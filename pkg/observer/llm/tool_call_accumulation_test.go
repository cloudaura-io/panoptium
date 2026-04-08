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

package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/observer"
)

// makeToolCallSSEData builds an SSE data line for a tool call chunk.
func makeToolCallSSEData(index int, id, name string) []byte {
	tc := map[string]interface{}{
		"index": index,
	}
	if id != "" {
		tc["id"] = id
		tc["type"] = "function"
	}
	fn := map[string]interface{}{}
	if name != "" {
		fn["name"] = name
	}
	fn["arguments"] = ""
	tc["function"] = fn

	chunk := map[string]interface{}{
		"id": "chatcmpl-test",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"delta": map[string]interface{}{
					"tool_calls": []interface{}{tc},
				},
				"finish_reason": nil,
			},
		},
	}
	data, _ := json.Marshal(chunk)
	return []byte(fmt.Sprintf("data: %s\n\n", data))
}

// makeFinishReasonSSEData builds an SSE data line with finish_reason.
func makeFinishReasonSSEData(reason string) []byte {
	chunk := map[string]interface{}{
		"id": "chatcmpl-test",
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"delta":         map[string]interface{}{},
				"finish_reason": reason,
			},
		},
	}
	data, _ := json.Marshal(chunk)
	return []byte(fmt.Sprintf("data: %s\n\n", data))
}

// TestAccumulateToolCalls_SingleTool verifies that ProcessResponseStream
// accumulates tool call names from parsed SSE chunks.
func TestAccumulateToolCalls_SingleTool(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	streamCtx := &observer.StreamContext{
		RequestID: "test-req-1",
		Protocol:  eventbus.ProtocolLLM,
		Provider:  "openai",
		StartTime: time.Now(),
		EventBus:  bus,
	}

	ctx := context.Background()

	// Send tool call with name "bash"
	err := obs.ProcessResponseStream(ctx, streamCtx, makeToolCallSSEData(0, "call_1", "bash"))
	if err != nil {
		t.Fatalf("ProcessResponseStream error: %v", err)
	}

	// Send finish_reason to complete the tool calls
	err = obs.ProcessResponseStream(ctx, streamCtx, makeFinishReasonSSEData("tool_calls"))
	if err != nil {
		t.Fatalf("ProcessResponseStream error: %v", err)
	}

	// Check accumulated tool calls
	if len(streamCtx.ResponseToolCalls) == 0 {
		t.Fatal("expected ResponseToolCalls to be populated")
	}

	found := false
	for _, tc := range streamCtx.ResponseToolCalls {
		if tc.Name == "bash" && tc.Complete {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected completed tool call 'bash' in ResponseToolCalls, got %+v", streamCtx.ResponseToolCalls)
	}
}

// TestAccumulateToolCalls_FragmentedName verifies that fragmented tool call
// names across chunks are assembled correctly before evaluation.
func TestAccumulateToolCalls_FragmentedName(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	streamCtx := &observer.StreamContext{
		RequestID: "test-req-2",
		Protocol:  eventbus.ProtocolLLM,
		Provider:  "openai",
		StartTime: time.Now(),
		EventBus:  bus,
	}

	ctx := context.Background()

	// Send partial name
	err := obs.ProcessResponseStream(ctx, streamCtx, makeToolCallSSEData(0, "call_1", "get_"))
	if err != nil {
		t.Fatalf("ProcessResponseStream error: %v", err)
	}

	// Send rest of name
	err = obs.ProcessResponseStream(ctx, streamCtx, makeToolCallSSEData(0, "", "weather"))
	if err != nil {
		t.Fatalf("ProcessResponseStream error: %v", err)
	}

	// Send finish_reason
	err = obs.ProcessResponseStream(ctx, streamCtx, makeFinishReasonSSEData("tool_calls"))
	if err != nil {
		t.Fatalf("ProcessResponseStream error: %v", err)
	}

	if len(streamCtx.ResponseToolCalls) == 0 {
		t.Fatal("expected ResponseToolCalls to be populated")
	}

	found := false
	for _, tc := range streamCtx.ResponseToolCalls {
		if tc.Name == "get_weather" && tc.Complete {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected assembled tool call name 'get_weather', got %+v", streamCtx.ResponseToolCalls)
	}
}

// TestAccumulateToolCalls_MultipleConcurrent verifies that multiple concurrent
// tool calls with different indices are tracked independently.
func TestAccumulateToolCalls_MultipleConcurrent(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	streamCtx := &observer.StreamContext{
		RequestID: "test-req-3",
		Protocol:  eventbus.ProtocolLLM,
		Provider:  "openai",
		StartTime: time.Now(),
		EventBus:  bus,
	}

	ctx := context.Background()

	// Send first tool call
	err := obs.ProcessResponseStream(ctx, streamCtx, makeToolCallSSEData(0, "call_1", "bash"))
	if err != nil {
		t.Fatalf("ProcessResponseStream error: %v", err)
	}

	// Send second tool call with different index
	err = obs.ProcessResponseStream(ctx, streamCtx, makeToolCallSSEData(1, "call_2", "read_file"))
	if err != nil {
		t.Fatalf("ProcessResponseStream error: %v", err)
	}

	// Send finish_reason
	err = obs.ProcessResponseStream(ctx, streamCtx, makeFinishReasonSSEData("tool_calls"))
	if err != nil {
		t.Fatalf("ProcessResponseStream error: %v", err)
	}

	if len(streamCtx.ResponseToolCalls) < 2 {
		t.Fatalf("expected at least 2 ResponseToolCalls, got %d", len(streamCtx.ResponseToolCalls))
	}

	names := make(map[string]bool)
	for _, tc := range streamCtx.ResponseToolCalls {
		if tc.Complete {
			names[tc.Name] = true
		}
	}
	if !names["bash"] {
		t.Error("expected completed tool call 'bash'")
	}
	if !names["read_file"] {
		t.Error("expected completed tool call 'read_file'")
	}
}
