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

package anthropic

import (
	"testing"
)

const (
	testContentHello = "Hello"
)

// --- Request Parsing Tests ---


// TestParseRequest_Basic verifies parsing a basic Anthropic messages API request.
func TestParseRequest_Basic(t *testing.T) {
	body := []byte(`{
		"model": "claude-3-opus-20240229",
		"messages": [
			{"role": "user", "content": "Hello, Claude!"}
		],
		"max_tokens": 1024,
		"stream": true
	}`)

	req, err := ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if req == nil {
		t.Fatal("ParseRequest() returned nil")
	}
	if req.Model != "claude-3-opus-20240229" {
		t.Errorf("Model = %q, want %q", req.Model, "claude-3-opus-20240229")
	}
	if len(req.Messages) != 1 {
		t.Fatalf("Messages count = %d, want 1", len(req.Messages))
	}
	if req.Messages[0].Role != "user" {
		t.Errorf("Messages[0].Role = %q, want %q", req.Messages[0].Role, "user")
	}
	if req.Messages[0].Content != "Hello, Claude!" {
		t.Errorf("Messages[0].Content = %q, want %q", req.Messages[0].Content, "Hello, Claude!")
	}
	if !req.Stream {
		t.Error("Stream = false, want true")
	}
	if req.MaxTokens != 1024 {
		t.Errorf("MaxTokens = %d, want 1024", req.MaxTokens)
	}
}

// TestParseRequest_NonStreaming verifies parsing with stream=false.
func TestParseRequest_NonStreaming(t *testing.T) {
	body := []byte(`{
		"model": "claude-3-sonnet-20240229",
		"messages": [{"role": "user", "content": "Hi"}],
		"max_tokens": 256
	}`)

	req, err := ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if req.Stream {
		t.Error("Stream = true, want false")
	}
}

// TestParseRequest_MultipleMessages verifies parsing with multiple messages.
func TestParseRequest_MultipleMessages(t *testing.T) {
	body := []byte(`{
		"model": "claude-3-opus-20240229",
		"messages": [
			{"role": "user", "content": "What is 2+2?"},
			{"role": "assistant", "content": "4"},
			{"role": "user", "content": "And 3+3?"}
		],
		"max_tokens": 100,
		"stream": true
	}`)

	req, err := ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if len(req.Messages) != 3 {
		t.Fatalf("Messages count = %d, want 3", len(req.Messages))
	}
}

// TestParseRequest_InvalidJSON verifies error on malformed JSON.
func TestParseRequest_InvalidJSON(t *testing.T) {
	body := []byte(`{invalid}`)

	_, err := ParseRequest(body)
	if err == nil {
		t.Fatal("ParseRequest() expected error for invalid JSON, got nil")
	}
}

// TestParseSSEEvent_ContentBlockDelta verifies parsing a content_block_delta event.
func TestParseSSEEvent_ContentBlockDelta(t *testing.T) {
	data := []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`)

	event, err := ParseSSEEvent("content_block_delta", data)
	if err != nil {
		t.Fatalf("ParseSSEEvent() error = %v", err)
	}
	if event == nil {
		t.Fatal("ParseSSEEvent() returned nil")
	}
	if event.Content != testContentHello {
		t.Errorf("Content = %q, want %q", event.Content, testContentHello)
	}
	if event.EventType != "content_block_delta" {
		t.Errorf("EventType = %q, want %q", event.EventType, "content_block_delta")
	}
	if event.Done {
		t.Error("Done = true, want false")
	}
}

// TestParseSSEEvent_MessageStop verifies parsing a message_stop event.
func TestParseSSEEvent_MessageStop(t *testing.T) {
	data := []byte(`{"type":"message_stop"}`)

	event, err := ParseSSEEvent("message_stop", data)
	if err != nil {
		t.Fatalf("ParseSSEEvent() error = %v", err)
	}
	if !event.Done {
		t.Error("Done = false, want true for message_stop")
	}
}

// TestParseSSEEvent_MessageDelta verifies parsing a message_delta event with stop_reason.
func TestParseSSEEvent_MessageDelta(t *testing.T) {
	data := []byte(
		`{"type":"message_delta","delta":{"stop_reason":"end_turn",` +
			`"stop_sequence":null},"usage":{"output_tokens":15}}`,
	)

	event, err := ParseSSEEvent("message_delta", data)
	if err != nil {
		t.Fatalf("ParseSSEEvent() error = %v", err)
	}
	if event.StopReason != "end_turn" {
		t.Errorf("StopReason = %q, want %q", event.StopReason, "end_turn")
	}
}

// TestParseSSEFrame_SingleEvent verifies parsing a frame with a single SSE event.
func TestParseSSEFrame_SingleEvent(t *testing.T) {
	frame := []byte(
		"event: content_block_delta\n" +
			`data: {"type":"content_block_delta","index":0,` +
			`"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n",
	)

	events, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("ParseSSEFrame() returned %d events, want 1", len(events))
	}
	if events[0].Content != testContentHello {
		t.Errorf("events[0].Content = %q, want %q", events[0].Content, testContentHello)
	}
}

// TestParseSSEFrame_MultipleEvents verifies parsing a frame with multiple SSE events.
func TestParseSSEFrame_MultipleEvents(t *testing.T) {
	frame := []byte(
		"event: content_block_delta\n" +
			`data: {"type":"content_block_delta","index":0,` +
			`"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n" +
			"event: content_block_delta\n" +
			`data: {"type":"content_block_delta","index":0,` +
			`"delta":{"type":"text_delta","text":" world"}}` + "\n\n",
	)

	events, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("ParseSSEFrame() returned %d events, want 2", len(events))
	}
	if events[0].Content != testContentHello {
		t.Errorf("events[0].Content = %q, want %q", events[0].Content, testContentHello)
	}
	if events[1].Content != " world" {
		t.Errorf("events[1].Content = %q, want %q", events[1].Content, " world")
	}
}

// TestParseSSEFrame_EmptyFrame verifies parsing an empty frame.
func TestParseSSEFrame_EmptyFrame(t *testing.T) {
	frame := []byte("")

	events, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(events) != 0 {
		t.Errorf("ParseSSEFrame() returned %d events for empty frame, want 0", len(events))
	}
}

// TestParseNonStreamingResponse verifies parsing a complete non-streaming response.
func TestParseNonStreamingResponse(t *testing.T) {
	body := []byte(`{
		"id": "msg_123",
		"type": "message",
		"role": "assistant",
		"model": "claude-3-opus-20240229",
		"content": [
			{
				"type": "text",
				"text": "Hello! How can I assist you today?"
			}
		],
		"stop_reason": "end_turn",
		"usage": {
			"input_tokens": 12,
			"output_tokens": 9
		}
	}`)

	resp, err := ParseNonStreamingResponse(body)
	if err != nil {
		t.Fatalf("ParseNonStreamingResponse() error = %v", err)
	}
	if resp == nil {
		t.Fatal("ParseNonStreamingResponse() returned nil")
	}
	if resp.Content != "Hello! How can I assist you today?" {
		t.Errorf("Content = %q, want %q", resp.Content, "Hello! How can I assist you today?")
	}
	if resp.Model != "claude-3-opus-20240229" {
		t.Errorf("Model = %q, want %q", resp.Model, "claude-3-opus-20240229")
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("StopReason = %q, want %q", resp.StopReason, "end_turn")
	}
	if resp.InputTokens != 12 {
		t.Errorf("InputTokens = %d, want 12", resp.InputTokens)
	}
	if resp.OutputTokens != 9 {
		t.Errorf("OutputTokens = %d, want 9", resp.OutputTokens)
	}
}

// TestParseRequest_ToolExtraction_SingleTool verifies extracting tools[].name
// from an Anthropic messages API request with a single tool.
func TestParseRequest_ToolExtraction_SingleTool(t *testing.T) {
	body := []byte(`{
		"model": "claude-3-opus-20240229",
		"messages": [{"role": "user", "content": "What is the weather?"}],
		"tools": [
			{
				"name": "get_weather",
				"description": "Get the current weather",
				"input_schema": {"type": "object", "properties": {"location": {"type": "string"}}}
			}
		],
		"max_tokens": 1024
	}`)

	req, err := ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if len(req.ToolNames) != 1 {
		t.Fatalf("ToolNames count = %d, want 1", len(req.ToolNames))
	}
	if req.ToolNames[0] != "get_weather" {
		t.Errorf("ToolNames[0] = %q, want %q", req.ToolNames[0], "get_weather")
	}
}

// TestParseRequest_ToolExtraction_MultipleTools verifies extracting multiple tool names.
func TestParseRequest_ToolExtraction_MultipleTools(t *testing.T) {
	body := []byte(`{
		"model": "claude-3-opus-20240229",
		"messages": [{"role": "user", "content": "Do tasks"}],
		"tools": [
			{"name": "get_weather", "description": "weather"},
			{"name": "dangerous_exec", "description": "exec"},
			{"name": "read_file", "description": "file"}
		],
		"max_tokens": 1024
	}`)

	req, err := ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if len(req.ToolNames) != 3 {
		t.Fatalf("ToolNames count = %d, want 3", len(req.ToolNames))
	}
	expected := []string{"get_weather", "dangerous_exec", "read_file"}
	for i, name := range expected {
		if req.ToolNames[i] != name {
			t.Errorf("ToolNames[%d] = %q, want %q", i, req.ToolNames[i], name)
		}
	}
}

// TestParseRequest_ToolExtraction_NoTools verifies that a request without tools returns empty list.
func TestParseRequest_ToolExtraction_NoTools(t *testing.T) {
	body := []byte(`{
		"model": "claude-3-opus-20240229",
		"messages": [{"role": "user", "content": "Hello"}],
		"max_tokens": 1024
	}`)

	req, err := ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if len(req.ToolNames) != 0 {
		t.Errorf("ToolNames count = %d, want 0", len(req.ToolNames))
	}
}
