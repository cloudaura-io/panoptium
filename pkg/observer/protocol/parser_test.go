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
	"context"
	"testing"
)

const testMethodToolsCall = "tools/call"

// --- Mock ProtocolParser Implementation ---


// mockParser is a test double implementing ProtocolParser.
type mockParser struct {
	name        string
	canDetect   bool
	confidence  float32
	reqResult   *ParsedRequest
	reqErr      error
	respResult  *ParsedResponse
	respErr     error
	chunkResult *ParsedChunk
	chunkErr    error

	detectCalled int
	reqCalled    int
	respCalled   int
	chunkCalled  int
}

func newMockParser(name string, canDetect bool, confidence float32) *mockParser {
	return &mockParser{
		name:       name,
		canDetect:  canDetect,
		confidence: confidence,
	}
}

func (m *mockParser) Name() string { return m.name }

func (m *mockParser) Detect(headers map[string]string, path string, method string) (bool, float32) {
	m.detectCalled++
	return m.canDetect, m.confidence
}

func (m *mockParser) ProcessRequest(
	ctx context.Context, headers map[string]string, body []byte,
) (*ParsedRequest, error) {
	m.reqCalled++
	if m.reqErr != nil {
		return nil, m.reqErr
	}
	if m.reqResult != nil {
		return m.reqResult, nil
	}
	return &ParsedRequest{
		Protocol:    m.name,
		MessageType: "request",
	}, nil
}

func (m *mockParser) ProcessResponse(
	ctx context.Context, headers map[string]string, body []byte,
) (*ParsedResponse, error) {
	m.respCalled++
	if m.respErr != nil {
		return nil, m.respErr
	}
	if m.respResult != nil {
		return m.respResult, nil
	}
	return &ParsedResponse{
		Protocol:    m.name,
		MessageType: "response",
	}, nil
}

func (m *mockParser) ProcessStreamChunk(ctx context.Context, chunk []byte, state *StreamState) (*ParsedChunk, error) {
	m.chunkCalled++
	if m.chunkErr != nil {
		return nil, m.chunkErr
	}
	if m.chunkResult != nil {
		return m.chunkResult, nil
	}
	return &ParsedChunk{
		Protocol: m.name,
		Content:  string(chunk),
	}, nil
}

// TestProtocolParser_Detect verifies that Detect returns a boolean and confidence score.
func TestProtocolParser_Detect(t *testing.T) {
	parser := newMockParser("mcp", true, 0.9)
	canDetect, confidence := parser.Detect(
		map[string]string{"Content-Type": "application/json"},
		"/mcp/v1",
		"POST",
	)
	if !canDetect {
		t.Error("Detect() returned false, want true")
	}
	if confidence != 0.9 {
		t.Errorf("Detect() confidence = %f, want 0.9", confidence)
	}
	if parser.detectCalled != 1 {
		t.Errorf("Detect called %d times, want 1", parser.detectCalled)
	}
}

// TestProtocolParser_Detect_NoMatch verifies that Detect returns false for unmatched traffic.
func TestProtocolParser_Detect_NoMatch(t *testing.T) {
	parser := newMockParser("mcp", false, 0)
	canDetect, confidence := parser.Detect(
		map[string]string{},
		"/unknown",
		"GET",
	)
	if canDetect {
		t.Error("Detect() returned true for unmatched traffic, want false")
	}
	if confidence != 0 {
		t.Errorf("Detect() confidence = %f, want 0", confidence)
	}
}

// TestProtocolParser_ProcessRequest verifies request parsing returns a ParsedRequest.
func TestProtocolParser_ProcessRequest(t *testing.T) {
	parser := newMockParser("mcp", true, 1.0)
	ctx := context.Background()
	result, err := parser.ProcessRequest(ctx, map[string]string{}, []byte(`{"jsonrpc":"2.0"}`))
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessRequest() returned nil")
	}
	if result.Protocol != "mcp" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "mcp")
	}
	if result.MessageType != "request" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "request")
	}
}

// TestProtocolParser_ProcessResponse verifies response parsing returns a ParsedResponse.
func TestProtocolParser_ProcessResponse(t *testing.T) {
	parser := newMockParser("a2a", true, 1.0)
	ctx := context.Background()
	result, err := parser.ProcessResponse(ctx, map[string]string{}, []byte(`{"result":{}}`))
	if err != nil {
		t.Fatalf("ProcessResponse() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessResponse() returned nil")
	}
	if result.Protocol != "a2a" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "a2a")
	}
}

// TestProtocolParser_ProcessStreamChunk verifies chunk processing with state tracking.
func TestProtocolParser_ProcessStreamChunk(t *testing.T) {
	parser := newMockParser("gemini", true, 1.0)
	ctx := context.Background()
	state := NewStreamState("gemini")

	chunk1, err := parser.ProcessStreamChunk(ctx, []byte("chunk1"), state)
	if err != nil {
		t.Fatalf("ProcessStreamChunk() error = %v", err)
	}
	if chunk1 == nil {
		t.Fatal("ProcessStreamChunk() returned nil")
	}
	if chunk1.Content != "chunk1" {
		t.Errorf("Content = %q, want %q", chunk1.Content, "chunk1")
	}
	if chunk1.Protocol != "gemini" {
		t.Errorf("Protocol = %q, want %q", chunk1.Protocol, "gemini")
	}
}

// TestStreamState_NewStreamState verifies initial StreamState creation.
func TestStreamState_NewStreamState(t *testing.T) {
	state := NewStreamState("mcp")
	if state == nil {
		t.Fatal("NewStreamState() returned nil")
	}
	if state.Protocol != "mcp" {
		t.Errorf("Protocol = %q, want %q", state.Protocol, "mcp")
	}
	if state.Buffer != nil {
		t.Error("Buffer should be nil initially")
	}
	if state.PendingIDs == nil {
		t.Error("PendingIDs should be initialized (non-nil)")
	}
	if len(state.PendingIDs) != 0 {
		t.Errorf("PendingIDs length = %d, want 0", len(state.PendingIDs))
	}
	if state.Metadata == nil {
		t.Error("Metadata should be initialized (non-nil)")
	}
}

// TestStreamState_StatefulTracking verifies that StreamState maintains state across calls.
func TestStreamState_StatefulTracking(t *testing.T) {
	state := NewStreamState("mcp")

	// Simulate buffering a partial JSON payload
	state.Buffer = []byte(`{"jsonrpc":"2.0","method":"tools`)
	state.PendingIDs["req-1"] = testMethodToolsCall
	state.Metadata["chunk_count"] = "1"

	// Verify state is preserved
	if string(state.Buffer) != `{"jsonrpc":"2.0","method":"tools` {
		t.Errorf("Buffer = %q, want partial JSON", string(state.Buffer))
	}
	if state.PendingIDs["req-1"] != testMethodToolsCall {
		t.Errorf("PendingIDs[req-1] = %q, want %q", state.PendingIDs["req-1"], testMethodToolsCall)
	}
	if state.Metadata["chunk_count"] != "1" {
		t.Errorf("Metadata[chunk_count] = %q, want %q", state.Metadata["chunk_count"], "1")
	}

	// Simulate completing the buffer
	state.Buffer = append(state.Buffer, []byte(`/list"}`)...)
	state.Metadata["chunk_count"] = "2"

	if string(state.Buffer) != `{"jsonrpc":"2.0","method":"tools/list"}` {
		t.Errorf("Buffer = %q, want complete JSON", string(state.Buffer))
	}
	if state.Metadata["chunk_count"] != "2" {
		t.Errorf("Metadata[chunk_count] = %q, want %q", state.Metadata["chunk_count"], "2")
	}
}

// TestStreamState_MultipleRequestCorrelation verifies tracking multiple pending request IDs.
func TestStreamState_MultipleRequestCorrelation(t *testing.T) {
	state := NewStreamState("mcp")

	state.PendingIDs["1"] = "initialize"
	state.PendingIDs["2"] = "tools/list"
	state.PendingIDs["3"] = testMethodToolsCall

	if len(state.PendingIDs) != 3 {
		t.Fatalf("PendingIDs length = %d, want 3", len(state.PendingIDs))
	}

	// Simulate response received — remove correlated request
	delete(state.PendingIDs, "1")
	if len(state.PendingIDs) != 2 {
		t.Fatalf("PendingIDs length = %d after delete, want 2", len(state.PendingIDs))
	}
	if _, exists := state.PendingIDs["1"]; exists {
		t.Error("PendingIDs should not contain deleted key '1'")
	}
}
