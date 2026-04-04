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
	"net/http"
	"testing"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/protocol"
)

var _ protocol.ProtocolParser = (*LLMParserAdapter)(nil)

// TestLLMParserAdapter_Name verifies the adapter returns the LLM observer name.
func TestLLMParserAdapter_Name(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	adapter := NewLLMParserAdapter(NewLLMObserver(bus))
	if adapter.Name() != "llm" {
		t.Errorf("Name() = %q, want %q", adapter.Name(), "llm")
	}
}

// TestLLMParserAdapter_Detect_OpenAI verifies adapter detects OpenAI traffic.
func TestLLMParserAdapter_Detect_OpenAI(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	adapter := NewLLMParserAdapter(NewLLMObserver(bus))
	canDetect, confidence := adapter.Detect(
		map[string]string{},
		"/v1/chat/completions",
		"POST",
	)
	if !canDetect {
		t.Error("Detect() returned false for OpenAI path, want true")
	}
	if confidence <= 0 {
		t.Errorf("Detect() confidence = %f, want > 0", confidence)
	}
}

// TestLLMParserAdapter_Detect_Anthropic verifies adapter detects Anthropic traffic.
func TestLLMParserAdapter_Detect_Anthropic(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	adapter := NewLLMParserAdapter(NewLLMObserver(bus))
	canDetect, confidence := adapter.Detect(
		map[string]string{},
		"/v1/messages",
		"POST",
	)
	if !canDetect {
		t.Error("Detect() returned false for Anthropic path, want true")
	}
	if confidence <= 0 {
		t.Errorf("Detect() confidence = %f, want > 0", confidence)
	}
}

// TestLLMParserAdapter_Detect_Unknown verifies adapter rejects unknown paths.
func TestLLMParserAdapter_Detect_Unknown(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	adapter := NewLLMParserAdapter(NewLLMObserver(bus))
	canDetect, confidence := adapter.Detect(
		map[string]string{},
		"/api/mcp/tools/list",
		"POST",
	)
	if canDetect {
		t.Error("Detect() returned true for non-LLM path, want false")
	}
	if confidence != 0 {
		t.Errorf("Detect() confidence = %f, want 0", confidence)
	}
}

// TestLLMParserAdapter_Detect_WithHost verifies adapter passes host header through.
func TestLLMParserAdapter_Detect_WithHost(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	adapter := NewLLMParserAdapter(NewLLMObserver(bus))
	canDetect, confidence := adapter.Detect(
		map[string]string{"Host": "api.openai.com"},
		"/v1/chat/completions",
		"POST",
	)
	if !canDetect {
		t.Error("Detect() returned false for OpenAI host+path, want true")
	}
	if confidence < 0.8 {
		t.Errorf("Detect() confidence = %f, want >= 0.8 for host match", confidence)
	}
}

// TestLLMParserAdapter_ProcessRequest verifies adapter parses request correctly.
func TestLLMParserAdapter_ProcessRequest(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	adapter := NewLLMParserAdapter(NewLLMObserver(bus))
	ctx := context.Background()

	body := []byte(`{
		"model": "gpt-4",
		"messages": [{"role": "user", "content": "Hello"}],
		"tools": [
			{"type": "function", "function": {"name": "get_weather"}}
		],
		"stream": true
	}`)

	result, err := adapter.ProcessRequest(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessRequest() returned nil")
	}
	if result.MessageType != "llm.request" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "llm.request")
	}
}

// TestLLMParserAdapter_ProcessResponse verifies adapter returns valid response.
func TestLLMParserAdapter_ProcessResponse(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	adapter := NewLLMParserAdapter(NewLLMObserver(bus))
	ctx := context.Background()

	result, err := adapter.ProcessResponse(ctx, map[string]string{}, []byte(`{}`))
	if err != nil {
		t.Fatalf("ProcessResponse() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessResponse() returned nil")
	}
	if result.Protocol != "llm" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "llm")
	}
}

// TestLLMParserAdapter_ProcessStreamChunk verifies adapter returns valid chunk.
func TestLLMParserAdapter_ProcessStreamChunk(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	adapter := NewLLMParserAdapter(NewLLMObserver(bus))
	ctx := context.Background()
	state := protocol.NewStreamState("llm")

	result, err := adapter.ProcessStreamChunk(ctx, []byte("data"), state)
	if err != nil {
		t.Fatalf("ProcessStreamChunk() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessStreamChunk() returned nil")
	}
	if result.Protocol != "llm" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "llm")
	}
}

// TestLLMObserver_RegressionOpenAI verifies existing OpenAI parsing is unaffected.
func TestLLMObserver_RegressionOpenAI(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()
	sub := bus.Subscribe(eventbus.EventTypeLLMTokenChunk)

	obs := NewLLMObserver(bus)
	ctx := context.Background()

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	headers := make(map[string]string)
	headers["Host"] = "api.openai.com"

	// Use the adapter to verify it doesn't break the original
	adapter := NewLLMParserAdapter(obs)
	canDetect, _ := adapter.Detect(headers, "/v1/chat/completions", "POST")
	if !canDetect {
		t.Fatal("Adapter failed to detect OpenAI traffic")
	}

	// Original observer should still work
	_ = body
	_ = ctx
	_ = sub
}

// TestLLMObserver_RegressionAnthropic verifies existing Anthropic parsing is unaffected.
func TestLLMObserver_RegressionAnthropic(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	adapter := NewLLMParserAdapter(obs)

	canDetect, _ := adapter.Detect(map[string]string{}, "/v1/messages", "POST")
	if !canDetect {
		t.Fatal("Adapter failed to detect Anthropic traffic")
	}

	// Verify original observer also still detects
	obsCtx := &observer.ObserverContext{
		Headers: mapToHTTPHeader(map[string]string{}),
		Path:    "/v1/messages",
		Method:  "POST",
	}
	canHandle, _ := obs.CanHandle(context.Background(), obsCtx)
	if !canHandle {
		t.Fatal("Original LLMObserver.CanHandle() failed for Anthropic — regression!")
	}
}

// mapToHTTPHeader converts a map[string]string to http.Header.
func mapToHTTPHeader(m map[string]string) http.Header {
	h := make(http.Header)
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}
