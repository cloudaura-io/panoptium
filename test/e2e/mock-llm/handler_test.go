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

// Package main contains tests for the mock LLM server handlers.
package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// expectedTokens are the deterministic tokens the mock LLM returns.
var expectedTokens = []string{"Hello", " from", " mock", " LLM"}

// TestOpenAIStreamingResponse verifies that the OpenAI /v1/chat/completions
// handler returns a proper SSE streaming response with deterministic tokens.
func TestOpenAIStreamingResponse(t *testing.T) {
	handler := newOpenAIHandler()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify SSE content type
	ct := resp.Header.Get("Content-Type")
	if ct != "text/event-stream" {
		t.Fatalf("expected Content-Type text/event-stream, got %q", ct)
	}

	// Parse SSE events and extract token content
	scanner := bufio.NewScanner(resp.Body)
	var tokens []string
	var gotDone bool

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			gotDone = true
			continue
		}

		var chunk openAIChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			t.Fatalf("failed to parse SSE chunk: %v", err)
		}
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			tokens = append(tokens, chunk.Choices[0].Delta.Content)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	// Verify tokens
	if len(tokens) != len(expectedTokens) {
		t.Fatalf("expected %d tokens, got %d: %v", len(expectedTokens), len(tokens), tokens)
	}
	for i, tok := range tokens {
		if tok != expectedTokens[i] {
			t.Errorf("token %d: expected %q, got %q", i, expectedTokens[i], tok)
		}
	}

	// Verify [DONE] terminator
	if !gotDone {
		t.Error("expected [DONE] terminator in SSE stream")
	}
}

// TestOpenAIDoneTerminator verifies the [DONE] terminator and Content-Type header.
func TestOpenAIDoneTerminator(t *testing.T) {
	handler := newOpenAIHandler()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Verify Content-Type
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected Content-Type text/event-stream, got %q", ct)
	}

	// Verify the response ends with [DONE]
	scanner := bufio.NewScanner(resp.Body)
	var lastData string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			lastData = strings.TrimPrefix(line, "data: ")
		}
	}

	if lastData != "[DONE]" {
		t.Errorf("expected last data line to be [DONE], got %q", lastData)
	}
}

// TestAnthropicStreamingResponse verifies that the Anthropic /v1/messages
// handler returns proper SSE events with content_block_delta format.
func TestAnthropicStreamingResponse(t *testing.T) {
	handler := newAnthropicHandler()

	body := `{"model":"claude-3-opus","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected Content-Type text/event-stream, got %q", ct)
	}

	// Parse SSE events
	scanner := bufio.NewScanner(resp.Body)
	var tokens []string
	var gotMessageStop bool

	var currentEvent string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")

		if currentEvent == "content_block_delta" {
			var delta anthropicDelta
			if err := json.Unmarshal([]byte(data), &delta); err != nil {
				t.Fatalf("failed to parse content_block_delta: %v", err)
			}
			if delta.Delta.Text != "" {
				tokens = append(tokens, delta.Delta.Text)
			}
		}

		if currentEvent == "message_stop" {
			gotMessageStop = true
		}
	}

	// Verify tokens
	if len(tokens) != len(expectedTokens) {
		t.Fatalf("expected %d tokens, got %d: %v", len(expectedTokens), len(tokens), tokens)
	}
	for i, tok := range tokens {
		if tok != expectedTokens[i] {
			t.Errorf("token %d: expected %q, got %q", i, expectedTokens[i], tok)
		}
	}

	if !gotMessageStop {
		t.Error("expected message_stop event in SSE stream")
	}
}

// TestAnthropicMessageStopTerminator verifies the message_stop terminator event.
func TestAnthropicMessageStopTerminator(t *testing.T) {
	handler := newAnthropicHandler()

	body := `{"model":"claude-3-opus","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	var events []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			events = append(events, strings.TrimPrefix(line, "event: "))
		}
	}

	// Verify message_stop is the last event
	if len(events) == 0 {
		t.Fatal("no events found in response")
	}
	lastEvent := events[len(events)-1]
	if lastEvent != "message_stop" {
		t.Errorf("expected last event to be message_stop, got %q", lastEvent)
	}
}

// TestOpenAINonStreaming verifies that the OpenAI handler responds correctly
// for non-streaming requests.
func TestOpenAINonStreaming(t *testing.T) {
	handler := newOpenAIHandler()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var result openAINonStreamResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result.Choices) == 0 {
		t.Fatal("expected at least one choice in response")
	}

	expectedContent := strings.Join(expectedTokens, "")
	if result.Choices[0].Message.Content != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, result.Choices[0].Message.Content)
	}
}

// TestAnthropicNonStreaming verifies that the Anthropic handler responds correctly
// for non-streaming requests.
func TestAnthropicNonStreaming(t *testing.T) {
	handler := newAnthropicHandler()

	body := `{"model":"claude-3-opus","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var result anthropicNonStreamResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result.Content) == 0 {
		t.Fatal("expected at least one content block in response")
	}

	expectedContent := strings.Join(expectedTokens, "")
	if result.Content[0].Text != expectedContent {
		t.Errorf("expected text %q, got %q", expectedContent, result.Content[0].Text)
	}
}

// TestOpenAIToolCallStreaming verifies that when FORCE_TOOL_CALL is set,
// the OpenAI handler returns a tool_call SSE stream instead of text tokens.
func TestOpenAIToolCallStreaming(t *testing.T) {
	old := forceToolCall
	forceToolCall = "bash"
	defer func() { forceToolCall = old }()

	handler := newOpenAIHandler()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected Content-Type text/event-stream, got %q", ct)
	}

	scanner := bufio.NewScanner(resp.Body)
	var toolName string
	var gotFinishToolCalls bool
	var gotDone bool

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			gotDone = true
			continue
		}

		var chunk openAIToolCallChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			t.Fatalf("failed to parse SSE chunk: %v", err)
		}
		if len(chunk.Choices) > 0 {
			for _, tc := range chunk.Choices[0].Delta.ToolCalls {
				if tc.Function.Name != "" {
					toolName = tc.Function.Name
				}
			}
			if chunk.Choices[0].FinishReason == "tool_calls" {
				gotFinishToolCalls = true
			}
		}
	}

	if toolName != "bash" {
		t.Errorf("expected tool_call name %q, got %q", "bash", toolName)
	}
	if !gotFinishToolCalls {
		t.Error("expected finish_reason \"tool_calls\"")
	}
	if !gotDone {
		t.Error("expected [DONE] terminator")
	}
}

// TestOpenAIToolCallNonStreaming verifies that when FORCE_TOOL_CALL is set,
// the non-streaming handler returns a tool_call response.
func TestOpenAIToolCallNonStreaming(t *testing.T) {
	old := forceToolCall
	forceToolCall = "k8s_get_pod_logs"
	defer func() { forceToolCall = old }()

	handler := newOpenAIHandler()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var result openAIToolCallNonStreamResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result.Choices) == 0 {
		t.Fatal("expected at least one choice")
	}
	choice := result.Choices[0]
	if choice.FinishReason != "tool_calls" {
		t.Errorf("expected finish_reason %q, got %q", "tool_calls", choice.FinishReason)
	}
	if len(choice.Message.ToolCalls) == 0 {
		t.Fatal("expected at least one tool_call")
	}
	if choice.Message.ToolCalls[0].Function.Name != "k8s_get_pod_logs" {
		t.Errorf("expected tool name %q, got %q", "k8s_get_pod_logs", choice.Message.ToolCalls[0].Function.Name)
	}
}

// openAIChunk represents a chunk in an OpenAI SSE streaming response.
type openAIChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

// openAIToolCallChunk represents an SSE chunk containing tool_call deltas.
type openAIToolCallChunk struct {
	Choices []struct {
		Delta struct {
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

// openAIToolCallNonStreamResponse represents a non-streaming response with tool_calls.
type openAIToolCallNonStreamResponse struct {
	Choices []struct {
		Message struct {
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

// openAINonStreamResponse represents a non-streaming OpenAI response.
type openAINonStreamResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// anthropicDelta represents an Anthropic content_block_delta event.
type anthropicDelta struct {
	Delta struct {
		Text string `json:"text"`
	} `json:"delta"`
}

// anthropicNonStreamResponse represents a non-streaming Anthropic response.
type anthropicNonStreamResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}
