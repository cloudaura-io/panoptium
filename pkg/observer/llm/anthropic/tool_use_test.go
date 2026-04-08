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

// TestParseSSEEvent_ContentBlockStart_ToolUse verifies that a content_block_start
// event with type "tool_use" captures the tool name and id.
func TestParseSSEEvent_ContentBlockStart_ToolUse(t *testing.T) {
	data := []byte(`{
		"type": "content_block_start",
		"index": 1,
		"content_block": {
			"type": "tool_use",
			"id": "toolu_01abc",
			"name": "get_weather",
			"input": {}
		}
	}`)

	event, err := ParseSSEEvent("content_block_start", data)
	if err != nil {
		t.Fatalf("ParseSSEEvent() error = %v", err)
	}
	if event.EventType != "content_block_start" {
		t.Errorf("EventType = %q, want 'content_block_start'", event.EventType)
	}
	if event.ToolUse == nil {
		t.Fatal("expected ToolUse to be set for tool_use content block")
	}
	if event.ToolUse.ID != "toolu_01abc" {
		t.Errorf("ToolUse.ID = %q, want 'toolu_01abc'", event.ToolUse.ID)
	}
	if event.ToolUse.Name != "get_weather" {
		t.Errorf("ToolUse.Name = %q, want 'get_weather'", event.ToolUse.Name)
	}
}

// TestParseSSEEvent_ContentBlockDelta_ToolArguments verifies that
// content_block_delta with input_json_delta accumulates tool arguments.
func TestParseSSEEvent_ContentBlockDelta_ToolArguments(t *testing.T) {
	data := []byte(`{
		"type": "content_block_delta",
		"index": 1,
		"delta": {
			"type": "input_json_delta",
			"partial_json": "{\"location\":"
		}
	}`)

	event, err := ParseSSEEvent("content_block_delta", data)
	if err != nil {
		t.Fatalf("ParseSSEEvent() error = %v", err)
	}
	// input_json_delta is for tool arguments, not text content
	if event.Content != "" {
		t.Errorf("Content should be empty for input_json_delta, got %q", event.Content)
	}
}

// TestParseSSEEvent_ContentBlockStop verifies that content_block_stop signals
// completion of a content block (including tool_use blocks).
func TestParseSSEEvent_ContentBlockStop(t *testing.T) {
	data := []byte(`{"type": "content_block_stop", "index": 1}`)

	event, err := ParseSSEEvent("content_block_stop", data)
	if err != nil {
		t.Fatalf("ParseSSEEvent() error = %v", err)
	}
	if event.EventType != "content_block_stop" {
		t.Errorf("EventType = %q, want 'content_block_stop'", event.EventType)
	}
	if event.ContentBlockStop != true {
		t.Error("expected ContentBlockStop to be true")
	}
}

// TestParseSSEFrame_ToolUseFlow verifies parsing a complete tool_use flow
// across multiple SSE events in a single frame.
func TestParseSSEFrame_ToolUseFlow(t *testing.T) {
	frame := []byte(
		"event: content_block_start\n" +
			`data: {"type":"content_block_start","index":1,` +
			`"content_block":{"type":"tool_use",` +
			`"id":"toolu_01abc","name":"bash","input":{}}}` + "\n\n" +
			"event: content_block_delta\n" +
			`data: {"type":"content_block_delta","index":1,` +
			`"delta":{"type":"input_json_delta",` +
			`"partial_json":"{\"cmd\":\"ls\"}"}}` + "\n\n" +
			"event: content_block_stop\n" +
			`data: {"type":"content_block_stop","index":1}` + "\n\n",
	)

	events, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// First event: content_block_start with tool_use
	if events[0].ToolUse == nil {
		t.Fatal("expected ToolUse in first event")
	}
	if events[0].ToolUse.Name != "bash" {
		t.Errorf("first event ToolUse.Name = %q, want 'bash'", events[0].ToolUse.Name)
	}
	if events[0].ToolUse.ID != "toolu_01abc" {
		t.Errorf("first event ToolUse.ID = %q, want 'toolu_01abc'", events[0].ToolUse.ID)
	}

	// Third event: content_block_stop
	if !events[2].ContentBlockStop {
		t.Error("expected ContentBlockStop in third event")
	}
}

// TestParseSSEEvent_ContentBlockStart_TextType verifies that text content blocks
// do NOT set ToolUse.
func TestParseSSEEvent_ContentBlockStart_TextType(t *testing.T) {
	data := []byte(`{
		"type": "content_block_start",
		"index": 0,
		"content_block": {
			"type": "text",
			"text": ""
		}
	}`)

	event, err := ParseSSEEvent("content_block_start", data)
	if err != nil {
		t.Fatalf("ParseSSEEvent() error = %v", err)
	}
	if event.ToolUse != nil {
		t.Error("expected ToolUse to be nil for text content block")
	}
}
