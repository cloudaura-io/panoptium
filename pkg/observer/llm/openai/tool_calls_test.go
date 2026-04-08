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

package openai

import (
	"fmt"
	"testing"
)

// TestParseSSEChunk_ToolCalls_SingleCall verifies parsing a chunk with
// delta.tool_calls containing a function call with name and empty arguments.
func TestParseSSEChunk_ToolCalls_SingleCall(t *testing.T) {
	data := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{
			"index": 0,
			"delta": {
				"tool_calls": [{
					"index": 0,
					"id": "call_abc123",
					"type": "function",
					"function": {
						"name": "get_weather",
						"arguments": ""
					}
				}]
			},
			"finish_reason": null
		}]
	}`)

	chunk, err := ParseSSEChunk(data)
	if err != nil {
		t.Fatalf("ParseSSEChunk() error = %v", err)
	}
	if len(chunk.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(chunk.ToolCalls))
	}
	tc := chunk.ToolCalls[0]
	if tc.Index != 0 {
		t.Errorf("expected Index=0, got %d", tc.Index)
	}
	if tc.ID != "call_abc123" {
		t.Errorf("expected ID='call_abc123', got %q", tc.ID)
	}
	if tc.FunctionName != testToolGetWeather {
		t.Errorf("expected FunctionName=%q, got %q", testToolGetWeather, tc.FunctionName)
	}
	if tc.FunctionArguments != "" {
		t.Errorf("expected empty FunctionArguments, got %q", tc.FunctionArguments)
	}
}

// TestParseSSEChunk_ToolCalls_NameFragmented verifies that tool call names
// can accumulate across multiple chunks (name may be fragmented).
func TestParseSSEChunk_ToolCalls_NameFragmented(t *testing.T) {
	// First chunk: partial name
	data1 := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{
			"index": 0,
			"delta": {
				"tool_calls": [{
					"index": 0,
					"id": "call_abc123",
					"type": "function",
					"function": {
						"name": "get_",
						"arguments": ""
					}
				}]
			},
			"finish_reason": null
		}]
	}`)

	chunk1, err := ParseSSEChunk(data1)
	if err != nil {
		t.Fatalf("ParseSSEChunk(chunk1) error = %v", err)
	}
	if len(chunk1.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call in chunk1, got %d", len(chunk1.ToolCalls))
	}
	if chunk1.ToolCalls[0].FunctionName != "get_" {
		t.Errorf("chunk1 FunctionName = %q, want 'get_'", chunk1.ToolCalls[0].FunctionName)
	}

	// Second chunk: rest of name (in practice, name fragments are concatenated by the accumulator)
	data2 := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{
			"index": 0,
			"delta": {
				"tool_calls": [{
					"index": 0,
					"function": {
						"name": "weather",
						"arguments": ""
					}
				}]
			},
			"finish_reason": null
		}]
	}`)

	chunk2, err := ParseSSEChunk(data2)
	if err != nil {
		t.Fatalf("ParseSSEChunk(chunk2) error = %v", err)
	}
	if len(chunk2.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call in chunk2, got %d", len(chunk2.ToolCalls))
	}
	if chunk2.ToolCalls[0].FunctionName != "weather" {
		t.Errorf("chunk2 FunctionName = %q, want 'weather'", chunk2.ToolCalls[0].FunctionName)
	}

	// Accumulation: get_ + weather = get_weather
	combined := chunk1.ToolCalls[0].FunctionName + chunk2.ToolCalls[0].FunctionName
	if combined != testToolGetWeather {
		t.Errorf("accumulated name = %q, want %q", combined, testToolGetWeather)
	}
}

// TestParseSSEChunk_ToolCalls_MultipleConcurrent verifies parsing multiple
// concurrent tool calls with different indices.
func TestParseSSEChunk_ToolCalls_MultipleConcurrent(t *testing.T) {
	data := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{
			"index": 0,
			"delta": {
				"tool_calls": [
					{
						"index": 0,
						"id": "call_abc",
						"type": "function",
						"function": {"name": "get_weather", "arguments": ""}
					},
					{
						"index": 1,
						"id": "call_def",
						"type": "function",
						"function": {"name": "get_time", "arguments": ""}
					}
				]
			},
			"finish_reason": null
		}]
	}`)

	chunk, err := ParseSSEChunk(data)
	if err != nil {
		t.Fatalf("ParseSSEChunk() error = %v", err)
	}
	if len(chunk.ToolCalls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d", len(chunk.ToolCalls))
	}
	if chunk.ToolCalls[0].FunctionName != testToolGetWeather {
		t.Errorf("ToolCalls[0].FunctionName = %q, want %q", chunk.ToolCalls[0].FunctionName, testToolGetWeather)
	}
	if chunk.ToolCalls[0].Index != 0 {
		t.Errorf("ToolCalls[0].Index = %d, want 0", chunk.ToolCalls[0].Index)
	}
	if chunk.ToolCalls[1].FunctionName != "get_time" {
		t.Errorf("ToolCalls[1].FunctionName = %q, want 'get_time'", chunk.ToolCalls[1].FunctionName)
	}
	if chunk.ToolCalls[1].Index != 1 {
		t.Errorf("ToolCalls[1].Index = %d, want 1", chunk.ToolCalls[1].Index)
	}
}

// TestParseSSEChunk_ToolCalls_FinishReasonToolCalls verifies that
// finish_reason "tool_calls" signals completion.
func TestParseSSEChunk_ToolCalls_FinishReasonToolCalls(t *testing.T) {
	data := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{
			"index": 0,
			"delta": {},
			"finish_reason": "tool_calls"
		}]
	}`)

	chunk, err := ParseSSEChunk(data)
	if err != nil {
		t.Fatalf("ParseSSEChunk() error = %v", err)
	}
	if chunk.FinishReason != "tool_calls" {
		t.Errorf("FinishReason = %q, want 'tool_calls'", chunk.FinishReason)
	}
}

// TestParseSSEChunk_NoToolCalls verifies that chunks without tool_calls
// return an empty ToolCalls slice.
func TestParseSSEChunk_NoToolCalls(t *testing.T) {
	data := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{
			"index": 0,
			"delta": {"content": "Hello world"},
			"finish_reason": null
		}]
	}`)

	chunk, err := ParseSSEChunk(data)
	if err != nil {
		t.Fatalf("ParseSSEChunk() error = %v", err)
	}
	if len(chunk.ToolCalls) != 0 {
		t.Errorf("expected 0 tool calls for content-only chunk, got %d", len(chunk.ToolCalls))
	}
	if chunk.Content != "Hello world" {
		t.Errorf("Content = %q, want 'Hello world'", chunk.Content)
	}
}

// TestParseSSEFrame_ToolCalls_FullFlow verifies parsing a complete tool call
// flow across multiple SSE events in a single frame.
func TestParseSSEFrame_ToolCalls_FullFlow(t *testing.T) {
	// First event: tool call with name
	event1 := `{"id":"chatcmpl-123","choices":[{"index":0,` +
		`"delta":{"tool_calls":[{"index":0,"id":"call_abc",` +
		`"type":"function","function":{"name":"bash",` +
		`"arguments":""}}]},"finish_reason":null}]}`
	// Second event: arguments
	event2 := `{"id":"chatcmpl-123","choices":[{"index":0,` +
		`"delta":{"tool_calls":[{"index":0,"function":` +
		`{"arguments":"{\"cmd\":"}}]},"finish_reason":null}]}`
	// Third event: finish_reason
	event3 := `{"id":"chatcmpl-123","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`

	frame := []byte(fmt.Sprintf("data: %s\n\ndata: %s\n\ndata: %s\n\n", event1, event2, event3))

	chunks, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}

	// First chunk should have tool call name
	if len(chunks[0].ToolCalls) != 1 {
		t.Fatalf("chunk 0: expected 1 tool call, got %d", len(chunks[0].ToolCalls))
	}
	if chunks[0].ToolCalls[0].FunctionName != "bash" {
		t.Errorf("chunk 0: FunctionName = %q, want 'bash'", chunks[0].ToolCalls[0].FunctionName)
	}

	// Second chunk should have arguments fragment
	if len(chunks[1].ToolCalls) != 1 {
		t.Fatalf("chunk 1: expected 1 tool call, got %d", len(chunks[1].ToolCalls))
	}
	if chunks[1].ToolCalls[0].FunctionArguments != `{"cmd":` {
		t.Errorf("chunk 1: FunctionArguments = %q, want '{\"cmd\":'", chunks[1].ToolCalls[0].FunctionArguments)
	}

	// Third chunk should have finish_reason
	if chunks[2].FinishReason != "tool_calls" {
		t.Errorf("chunk 2: FinishReason = %q, want 'tool_calls'", chunks[2].FinishReason)
	}
}
