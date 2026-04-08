/*
Copyright 2026 Cloudaura sp. z o.o.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protocol

import (
	"testing"
)

// TestProtocolDetector_NewProtocolDetector verifies creation of a new detector.
func TestProtocolDetector_NewProtocolDetector(t *testing.T) {
	detector := NewProtocolDetector()
	if detector == nil {
		t.Fatal("NewProtocolDetector() returned nil")
	}
}

// TestProtocolDetector_Register verifies parser registration.
func TestProtocolDetector_Register(t *testing.T) {
	detector := NewProtocolDetector()
	parser := newMockParser(ProtocolMCP, true, 0.9)

	err := detector.Register(parser)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	parsers := detector.Parsers()
	if len(parsers) != 1 {
		t.Fatalf("Parsers() returned %d, want 1", len(parsers))
	}
	if parsers[0] != ProtocolMCP {
		t.Errorf("Parsers()[0] = %q, want %q", parsers[0], ProtocolMCP)
	}
}

// TestProtocolDetector_Register_Duplicate verifies duplicate name rejection.
func TestProtocolDetector_Register_Duplicate(t *testing.T) {
	detector := NewProtocolDetector()
	p1 := newMockParser(ProtocolMCP, true, 0.9)
	p2 := newMockParser(ProtocolMCP, true, 0.8)

	if err := detector.Register(p1); err != nil {
		t.Fatalf("First Register() error = %v", err)
	}

	err := detector.Register(p2)
	if err == nil {
		t.Fatal("Second Register() expected error for duplicate name, got nil")
	}
}

// TestProtocolDetector_Cascade_AnnotationHighestPriority verifies annotation detection
// returns confidence 1.0, overriding all heuristic detection.
func TestProtocolDetector_Cascade_AnnotationHighestPriority(t *testing.T) {
	detector := NewProtocolDetector()

	// Register MCP parser that detects via JSON-RPC (lower confidence)
	mcp := newMockParser(ProtocolMCP, true, 0.6)
	if err := detector.Register(mcp); err != nil {
		t.Fatalf("Register mcp: %v", err)
	}

	// Detect with explicit annotation — should override
	headers := map[string]string{}
	annotations := map[string]string{"panoptium.io/protocol": ProtocolMCP}

	result := detector.Detect(headers, "/some/path", "POST", annotations, nil)
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser with annotation")
	}
	if result.Parser.Name() != ProtocolMCP {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), ProtocolMCP)
	}
	if result.Confidence != 1.0 {
		t.Errorf("Confidence = %f, want 1.0", result.Confidence)
	}
	if result.Method != DetectionMethodAnnotation {
		t.Errorf("Method = %q, want %q", result.Method, DetectionMethodAnnotation)
	}
}

// TestProtocolDetector_Cascade_PathDetection verifies path-based detection
// returns confidence 0.9.
func TestProtocolDetector_Cascade_PathDetection(t *testing.T) {
	detector := NewProtocolDetector()

	gemini := newMockParser("gemini", false, 0) // Detect returns false by default
	if err := detector.Register(gemini); err != nil {
		t.Fatalf("Register gemini: %v", err)
	}

	// Register path pattern for Gemini
	detector.RegisterPathPattern("/v1beta/models/", "gemini")

	headers := map[string]string{}
	result := detector.Detect(headers, "/v1beta/models/gemini-pro/generateContent", "POST", nil, nil)

	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for Gemini path")
	}
	if result.Parser.Name() != "gemini" {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), "gemini")
	}
	if result.Confidence != 0.9 {
		t.Errorf("Confidence = %f, want 0.9", result.Confidence)
	}
	if result.Method != DetectionMethodPath {
		t.Errorf("Method = %q, want %q", result.Method, DetectionMethodPath)
	}
}

// TestProtocolDetector_Cascade_ContentTypeDetection verifies Content-Type-based detection
// returns confidence 0.7.
func TestProtocolDetector_Cascade_ContentTypeDetection(t *testing.T) {
	detector := NewProtocolDetector()

	mcp := newMockParser(ProtocolMCP, false, 0)
	if err := detector.Register(mcp); err != nil {
		t.Fatalf("Register mcp: %v", err)
	}

	// Register content type pattern
	detector.RegisterContentType("application/json-rpc", ProtocolMCP)

	headers := map[string]string{"Content-Type": "application/json-rpc"}
	result := detector.Detect(headers, "/unknown/path", "POST", nil, nil)

	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for Content-Type match")
	}
	if result.Parser.Name() != ProtocolMCP {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), ProtocolMCP)
	}
	if result.Confidence != 0.7 {
		t.Errorf("Confidence = %f, want 0.7", result.Confidence)
	}
	if result.Method != DetectionMethodContentType {
		t.Errorf("Method = %q, want %q", result.Method, DetectionMethodContentType)
	}
}

// TestProtocolDetector_Cascade_JSONRPCDetection verifies JSON-RPC method inspection
// returns confidence 0.6.
func TestProtocolDetector_Cascade_JSONRPCDetection(t *testing.T) {
	detector := NewProtocolDetector()

	mcp := newMockParser(ProtocolMCP, false, 0)
	if err := detector.Register(mcp); err != nil {
		t.Fatalf("Register mcp: %v", err)
	}

	// Register JSON-RPC methods for MCP
	detector.RegisterJSONRPCMethod("tools/list", ProtocolMCP)
	detector.RegisterJSONRPCMethod("tools/call", ProtocolMCP)
	detector.RegisterJSONRPCMethod("initialize", ProtocolMCP)

	headers := map[string]string{"Content-Type": "application/json"}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	result := detector.Detect(headers, "/rpc", "POST", nil, body)

	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for JSON-RPC method match")
	}
	if result.Parser.Name() != ProtocolMCP {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), ProtocolMCP)
	}
	if result.Confidence != 0.6 {
		t.Errorf("Confidence = %f, want 0.6", result.Confidence)
	}
	if result.Method != DetectionMethodJSONRPC {
		t.Errorf("Method = %q, want %q", result.Method, DetectionMethodJSONRPC)
	}
}

// TestProtocolDetector_Cascade_Fallback verifies fallback returns confidence 0.1
// when no parser matches.
func TestProtocolDetector_Cascade_Fallback(t *testing.T) {
	detector := NewProtocolDetector()

	// Register parsers that don't match
	mcp := newMockParser(ProtocolMCP, false, 0)
	if err := detector.Register(mcp); err != nil {
		t.Fatalf("Register mcp: %v", err)
	}

	headers := map[string]string{}
	result := detector.Detect(headers, "/unknown", "GET", nil, nil)

	if result.Parser != nil {
		t.Errorf("Detect() returned non-nil parser for fallback, got %q", result.Parser.Name())
	}
	if result.Confidence != 0.1 {
		t.Errorf("Confidence = %f, want 0.1 for fallback", result.Confidence)
	}
	if result.Method != DetectionMethodFallback {
		t.Errorf("Method = %q, want %q", result.Method, DetectionMethodFallback)
	}
}

// TestProtocolDetector_Cascade_PriorityOrder verifies the cascade stops at the
// highest confidence match: annotation > path > Content-Type > JSON-RPC > fallback.
func TestProtocolDetector_Cascade_PriorityOrder(t *testing.T) {
	detector := NewProtocolDetector()

	// Register two parsers: MCP and Gemini
	mcp := newMockParser(ProtocolMCP, false, 0)
	gemini := newMockParser("gemini", false, 0)
	if err := detector.Register(mcp); err != nil {
		t.Fatalf("Register mcp: %v", err)
	}
	if err := detector.Register(gemini); err != nil {
		t.Fatalf("Register gemini: %v", err)
	}

	// Register path that would match Gemini
	detector.RegisterPathPattern("/v1beta/models/", "gemini")
	// Also register JSON-RPC method that would match MCP
	detector.RegisterJSONRPCMethod("tools/list", ProtocolMCP)

	// When annotation says "mcp", annotation should win over path match for Gemini
	annotations := map[string]string{"panoptium.io/protocol": ProtocolMCP}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)

	result := detector.Detect(
		map[string]string{},
		"/v1beta/models/gemini-pro/generateContent", // path matches Gemini
		"POST",
		annotations, // annotation says MCP
		body,        // body matches MCP JSON-RPC
	)

	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser")
	}
	if result.Parser.Name() != ProtocolMCP {
		t.Errorf("Parser = %q, want %q (annotation should override path)", result.Parser.Name(), ProtocolMCP)
	}
	if result.Confidence != 1.0 {
		t.Errorf("Confidence = %f, want 1.0 (annotation)", result.Confidence)
	}
	if result.Method != DetectionMethodAnnotation {
		t.Errorf("Method = %q, want %q", result.Method, DetectionMethodAnnotation)
	}
}

// TestProtocolDetector_Cascade_PathBeatsJSONRPC verifies path detection (0.9) beats
// JSON-RPC detection (0.6) when both match.
func TestProtocolDetector_Cascade_PathBeatsJSONRPC(t *testing.T) {
	detector := NewProtocolDetector()

	a2a := newMockParser("a2a", false, 0)
	mcp := newMockParser(ProtocolMCP, false, 0)
	if err := detector.Register(a2a); err != nil {
		t.Fatalf("Register a2a: %v", err)
	}
	if err := detector.Register(mcp); err != nil {
		t.Fatalf("Register mcp: %v", err)
	}

	detector.RegisterPathPattern("/.well-known/agent-card.json", "a2a")
	detector.RegisterJSONRPCMethod("tools/list", ProtocolMCP)

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	result := detector.Detect(
		map[string]string{},
		"/.well-known/agent-card.json",
		"GET",
		nil,
		body,
	)

	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser")
	}
	if result.Parser.Name() != "a2a" {
		t.Errorf("Parser = %q, want %q (path should beat JSON-RPC)", result.Parser.Name(), "a2a")
	}
	if result.Confidence != 0.9 {
		t.Errorf("Confidence = %f, want 0.9 (path)", result.Confidence)
	}
}

// TestProtocolDetector_HighestConfidence_MultipleMatches verifies that when multiple
// parsers match via their Detect method, the one with the highest confidence is selected.
func TestProtocolDetector_HighestConfidence_MultipleMatches(t *testing.T) {
	detector := NewProtocolDetector()

	// Both parsers claim to handle via Detect(), but with different confidence
	low := newMockParser("low-conf", true, 0.5)
	high := newMockParser("high-conf", true, 0.8)

	if err := detector.Register(low); err != nil {
		t.Fatalf("Register low: %v", err)
	}
	if err := detector.Register(high); err != nil {
		t.Fatalf("Register high: %v", err)
	}

	// No annotation, path, content-type, or JSON-RPC matches — falls through to
	// parser's own Detect method
	result := detector.Detect(map[string]string{}, "/custom", "POST", nil, nil)

	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser")
	}
	if result.Parser.Name() != "high-conf" {
		t.Errorf("Parser = %q, want %q (highest confidence)", result.Parser.Name(), "high-conf")
	}
}

// TestProtocolDetector_Fallback_NoParser verifies fallback when no parser matches at all.
func TestProtocolDetector_Fallback_NoParser(t *testing.T) {
	detector := NewProtocolDetector()

	// Register a parser that can't handle anything
	noMatch := newMockParser("no-match", false, 0)
	if err := detector.Register(noMatch); err != nil {
		t.Fatalf("Register: %v", err)
	}

	result := detector.Detect(map[string]string{}, "/random", "GET", nil, nil)

	if result.Parser != nil {
		t.Errorf("Detect() returned parser %q, want nil for fallback", result.Parser.Name())
	}
	if result.Confidence != 0.1 {
		t.Errorf("Confidence = %f, want 0.1", result.Confidence)
	}
	if result.Method != DetectionMethodFallback {
		t.Errorf("Method = %q, want %q", result.Method, DetectionMethodFallback)
	}
}

// TestProtocolDetector_EmptyDetector verifies behavior with no registered parsers.
func TestProtocolDetector_EmptyDetector(t *testing.T) {
	detector := NewProtocolDetector()

	result := detector.Detect(map[string]string{}, "/v1/chat/completions", "POST", nil, nil)

	if result.Parser != nil {
		t.Errorf("Detect() returned non-nil parser on empty detector: %q", result.Parser.Name())
	}
	if result.Method != DetectionMethodFallback {
		t.Errorf("Method = %q, want %q", result.Method, DetectionMethodFallback)
	}
}

// TestProtocolDetector_Annotation_UnknownProtocol verifies that annotation with an
// unknown protocol name falls through to lower cascade levels.
func TestProtocolDetector_Annotation_UnknownProtocol(t *testing.T) {
	detector := NewProtocolDetector()

	mcp := newMockParser(ProtocolMCP, true, 0.6)
	if err := detector.Register(mcp); err != nil {
		t.Fatalf("Register mcp: %v", err)
	}

	// Annotation refers to "unknown" which has no registered parser
	annotations := map[string]string{"panoptium.io/protocol": "unknown"}
	result := detector.Detect(map[string]string{}, "/rpc", "POST", annotations, nil)

	// Should fall through and use parser's own Detect method
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser — should fall through to parser Detect()")
	}
	if result.Parser.Name() != ProtocolMCP {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), ProtocolMCP)
	}
	// Confidence should come from the parser's own Detect, not annotation
	if result.Confidence == 1.0 {
		t.Error("Confidence should not be 1.0 — annotation was for unknown protocol")
	}
}

// TestProtocolDetector_JSONRPCBatch verifies detection with batched JSON-RPC requests.
func TestProtocolDetector_JSONRPCBatch(t *testing.T) {
	detector := NewProtocolDetector()

	mcp := newMockParser(ProtocolMCP, false, 0)
	if err := detector.Register(mcp); err != nil {
		t.Fatalf("Register mcp: %v", err)
	}

	detector.RegisterJSONRPCMethod("tools/list", ProtocolMCP)
	detector.RegisterJSONRPCMethod("tools/call", ProtocolMCP)

	// Batched JSON-RPC: array of requests
	body := []byte(`[{"jsonrpc":"2.0","method":"tools/list","id":1},{"jsonrpc":"2.0","method":"tools/call","id":2}]`)
	result := detector.Detect(map[string]string{"Content-Type": "application/json"}, "/rpc", "POST", nil, body)

	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for batched JSON-RPC")
	}
	if result.Parser.Name() != ProtocolMCP {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), ProtocolMCP)
	}
	if result.Confidence != 0.6 {
		t.Errorf("Confidence = %f, want 0.6", result.Confidence)
	}
}
