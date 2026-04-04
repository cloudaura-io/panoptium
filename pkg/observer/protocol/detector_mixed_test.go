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
	"time"
)

// setupMixedDetector creates a ProtocolDetector with MCP, A2A, Gemini, OpenAI,
// and Anthropic parsers registered with their standard detection patterns.
func setupMixedDetector() *ProtocolDetector {
	detector := NewProtocolDetector()

	mcp := newMockParser("mcp", false, 0)
	a2a := newMockParser("a2a", false, 0)
	gemini := newMockParser("gemini", false, 0)
	openai := newMockParser("openai", false, 0)
	anthropic := newMockParser("anthropic", false, 0)

	detector.Register(mcp)
	detector.Register(a2a)
	detector.Register(gemini)
	detector.Register(openai)
	detector.Register(anthropic)

	// Path patterns
	detector.RegisterPathPattern("/.well-known/agent-card.json", "a2a")
	detector.RegisterPathPattern("/v1beta/models/", "gemini")
	detector.RegisterPathPattern("/v1/models/", "gemini")
	detector.RegisterPathPattern("/v1/chat/completions", "openai")
	detector.RegisterPathPattern("/v1/messages", "anthropic")

	// JSON-RPC methods for MCP
	detector.RegisterJSONRPCMethod("initialize", "mcp")
	detector.RegisterJSONRPCMethod("tools/list", "mcp")
	detector.RegisterJSONRPCMethod("tools/call", "mcp")
	detector.RegisterJSONRPCMethod("notifications/initialized", "mcp")

	// JSON-RPC methods for A2A
	detector.RegisterJSONRPCMethod("tasks/send", "a2a")
	detector.RegisterJSONRPCMethod("tasks/sendSubscribe", "a2a")
	detector.RegisterJSONRPCMethod("tasks/get", "a2a")

	return detector
}

// TestMixedDetect_MCP_ViaJSONRPC verifies MCP detection via JSON-RPC method field.
func TestMixedDetect_MCP_ViaJSONRPC(t *testing.T) {
	detector := setupMixedDetector()

	tests := []struct {
		name   string
		body   string
		method string
	}{
		{"initialize", `{"jsonrpc":"2.0","method":"initialize","id":1}`, "initialize"},
		{"tools/list", `{"jsonrpc":"2.0","method":"tools/list","id":2}`, "tools/list"},
		{"tools/call", `{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"fs_read"}}`, "tools/call"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(
				map[string]string{"Content-Type": "application/json"},
				"/rpc",
				"POST",
				nil,
				[]byte(tt.body),
			)
			if result.Parser == nil {
				t.Fatalf("Detect() returned nil parser for MCP %s", tt.name)
			}
			if result.Parser.Name() != "mcp" {
				t.Errorf("Parser = %q, want %q", result.Parser.Name(), "mcp")
			}
			if result.Confidence != ConfidenceJSONRPC {
				t.Errorf("Confidence = %f, want %f", result.Confidence, ConfidenceJSONRPC)
			}
		})
	}
}

// TestMixedDetect_A2A_AgentCard verifies A2A detection via /.well-known/agent-card.json path.
func TestMixedDetect_A2A_AgentCard(t *testing.T) {
	detector := setupMixedDetector()

	result := detector.Detect(
		map[string]string{},
		"/.well-known/agent-card.json",
		"GET",
		nil,
		nil,
	)
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for A2A Agent Card")
	}
	if result.Parser.Name() != "a2a" {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), "a2a")
	}
	if result.Confidence != ConfidencePath {
		t.Errorf("Confidence = %f, want %f", result.Confidence, ConfidencePath)
	}
}

// TestMixedDetect_A2A_TaskSend verifies A2A detection via tasks/send JSON-RPC method.
func TestMixedDetect_A2A_TaskSend(t *testing.T) {
	detector := setupMixedDetector()

	body := []byte(`{"jsonrpc":"2.0","method":"tasks/send","id":1,"params":{"task":{"description":"do something"}}}`)
	result := detector.Detect(
		map[string]string{"Content-Type": "application/json"},
		"/rpc",
		"POST",
		nil,
		body,
	)
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for A2A tasks/send")
	}
	if result.Parser.Name() != "a2a" {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), "a2a")
	}
}

// TestMixedDetect_Gemini_V1Beta verifies Gemini detection via /v1beta/models/* path.
func TestMixedDetect_Gemini_V1Beta(t *testing.T) {
	detector := setupMixedDetector()

	result := detector.Detect(
		map[string]string{"Content-Type": "application/json"},
		"/v1beta/models/gemini-pro/generateContent",
		"POST",
		nil,
		nil,
	)
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for Gemini v1beta")
	}
	if result.Parser.Name() != "gemini" {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), "gemini")
	}
	if result.Confidence != ConfidencePath {
		t.Errorf("Confidence = %f, want %f", result.Confidence, ConfidencePath)
	}
}

// TestMixedDetect_Gemini_V1 verifies Gemini detection via /v1/models/* path.
func TestMixedDetect_Gemini_V1(t *testing.T) {
	detector := setupMixedDetector()

	result := detector.Detect(
		map[string]string{},
		"/v1/models/gemini-1.5-flash/streamGenerateContent",
		"POST",
		nil,
		nil,
	)
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for Gemini v1")
	}
	if result.Parser.Name() != "gemini" {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), "gemini")
	}
}

// TestMixedDetect_OpenAI_StillRoutes verifies OpenAI traffic still routes correctly.
func TestMixedDetect_OpenAI_StillRoutes(t *testing.T) {
	detector := setupMixedDetector()

	result := detector.Detect(
		map[string]string{"Content-Type": "application/json"},
		"/v1/chat/completions",
		"POST",
		nil,
		nil,
	)
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for OpenAI")
	}
	if result.Parser.Name() != "openai" {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), "openai")
	}
	if result.Confidence != ConfidencePath {
		t.Errorf("Confidence = %f, want %f", result.Confidence, ConfidencePath)
	}
}

// TestMixedDetect_Anthropic_StillRoutes verifies Anthropic traffic still routes correctly.
func TestMixedDetect_Anthropic_StillRoutes(t *testing.T) {
	detector := setupMixedDetector()

	result := detector.Detect(
		map[string]string{"Content-Type": "application/json"},
		"/v1/messages",
		"POST",
		nil,
		nil,
	)
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser for Anthropic")
	}
	if result.Parser.Name() != "anthropic" {
		t.Errorf("Parser = %q, want %q", result.Parser.Name(), "anthropic")
	}
}

// TestMixedDetect_AnnotationOverridesPath verifies annotation overrides all heuristics.
func TestMixedDetect_AnnotationOverridesPath(t *testing.T) {
	detector := setupMixedDetector()

	// Path matches OpenAI, but annotation says MCP
	annotations := map[string]string{"panoptium.io/protocol": "mcp"}
	result := detector.Detect(
		map[string]string{},
		"/v1/chat/completions",
		"POST",
		annotations,
		nil,
	)
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser")
	}
	if result.Parser.Name() != "mcp" {
		t.Errorf("Parser = %q, want %q (annotation override)", result.Parser.Name(), "mcp")
	}
	if result.Confidence != ConfidenceAnnotation {
		t.Errorf("Confidence = %f, want %f", result.Confidence, ConfidenceAnnotation)
	}
}

// TestMixedDetect_AnnotationOverridesJSONRPC verifies annotation beats JSON-RPC detection.
func TestMixedDetect_AnnotationOverridesJSONRPC(t *testing.T) {
	detector := setupMixedDetector()

	// Body contains MCP JSON-RPC, but annotation says Gemini
	annotations := map[string]string{"panoptium.io/protocol": "gemini"}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1}`)
	result := detector.Detect(
		map[string]string{},
		"/rpc",
		"POST",
		annotations,
		body,
	)
	if result.Parser == nil {
		t.Fatal("Detect() returned nil parser")
	}
	if result.Parser.Name() != "gemini" {
		t.Errorf("Parser = %q, want %q (annotation override)", result.Parser.Name(), "gemini")
	}
}

// TestMixedDetect_Latency_SubMillisecond verifies detection completes in <1ms (NFR-1).
func TestMixedDetect_Latency_SubMillisecond(t *testing.T) {
	detector := setupMixedDetector()

	headers := map[string]string{"Content-Type": "application/json"}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"fs_read","arguments":{"path":"/etc/passwd"}}}`)

	// Run 1000 iterations to get a stable measurement
	start := time.Now()
	iterations := 1000
	for i := 0; i < iterations; i++ {
		detector.Detect(headers, "/rpc", "POST", nil, body)
	}
	elapsed := time.Since(start)

	avgPerDetection := elapsed / time.Duration(iterations)
	if avgPerDetection > time.Millisecond {
		t.Errorf("Average detection latency = %v, want <1ms", avgPerDetection)
	}
}

// TestMixedDetect_Latency_AnnotationFastPath verifies annotation detection is fast.
func TestMixedDetect_Latency_AnnotationFastPath(t *testing.T) {
	detector := setupMixedDetector()

	annotations := map[string]string{"panoptium.io/protocol": "mcp"}

	start := time.Now()
	iterations := 1000
	for i := 0; i < iterations; i++ {
		detector.Detect(map[string]string{}, "/rpc", "POST", annotations, nil)
	}
	elapsed := time.Since(start)

	avgPerDetection := elapsed / time.Duration(iterations)
	if avgPerDetection > time.Millisecond {
		t.Errorf("Average annotation detection latency = %v, want <1ms", avgPerDetection)
	}
}
