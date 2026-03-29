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

// Package main implements a mock LLM server for E2E testing.
// It handles OpenAI and Anthropic API endpoints with deterministic
// SSE streaming responses for verifiable test assertions.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// tokens are the deterministic tokens returned by the mock LLM.
var tokens = []string{"Hello", " from", " mock", " LLM"}

func main() {
	mux := http.NewServeMux()
	mux.Handle("/v1/chat/completions", newOpenAIHandler())
	mux.Handle("/v1/messages", newAnthropicHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	addr := ":8080"
	log.Printf("Mock LLM server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// llmRequest represents the common fields in OpenAI/Anthropic API requests.
type llmRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

// newOpenAIHandler returns an HTTP handler for OpenAI /v1/chat/completions.
func newOpenAIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req llmRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.Stream {
			handleOpenAIStreaming(w, req)
			return
		}

		handleOpenAINonStreaming(w, req)
	})
}

// handleOpenAIStreaming writes SSE streaming chunks in OpenAI format.
func handleOpenAIStreaming(w http.ResponseWriter, req llmRequest) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)

	for i, tok := range tokens {
		chunk := map[string]interface{}{
			"id":      fmt.Sprintf("chatcmpl-mock-%d", i),
			"object":  "chat.completion.chunk",
			"created": time.Now().Unix(),
			"model":   req.Model,
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"delta": map[string]string{
						"content": tok,
					},
					"finish_reason": nil,
				},
			},
		}

		data, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", data)
		if flusher != nil {
			flusher.Flush()
		}
	}

	// Send [DONE] terminator
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

// handleOpenAINonStreaming writes a single JSON response in OpenAI format.
func handleOpenAINonStreaming(w http.ResponseWriter, req llmRequest) {
	content := strings.Join(tokens, "")
	resp := map[string]interface{}{
		"id":      "chatcmpl-mock-non-stream",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   req.Model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     10,
			"completion_tokens": len(tokens),
			"total_tokens":      10 + len(tokens),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// newAnthropicHandler returns an HTTP handler for Anthropic /v1/messages.
func newAnthropicHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req llmRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.Stream {
			handleAnthropicStreaming(w, req)
			return
		}

		handleAnthropicNonStreaming(w, req)
	})
}

// handleAnthropicStreaming writes SSE streaming events in Anthropic format.
func handleAnthropicStreaming(w http.ResponseWriter, req llmRequest) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)

	// message_start event
	msgStart := map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id":    "msg-mock-001",
			"type":  "message",
			"role":  "assistant",
			"model": req.Model,
		},
	}
	data, _ := json.Marshal(msgStart)
	fmt.Fprintf(w, "event: message_start\ndata: %s\n\n", data)
	if flusher != nil {
		flusher.Flush()
	}

	// content_block_start event
	blockStart := map[string]interface{}{
		"type":          "content_block_start",
		"index":         0,
		"content_block": map[string]string{"type": "text", "text": ""},
	}
	data, _ = json.Marshal(blockStart)
	fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n", data)
	if flusher != nil {
		flusher.Flush()
	}

	// content_block_delta events with tokens
	for i, tok := range tokens {
		delta := map[string]interface{}{
			"type":  "content_block_delta",
			"index": i,
			"delta": map[string]string{
				"type": "text_delta",
				"text": tok,
			},
		}
		data, _ = json.Marshal(delta)
		fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", data)
		if flusher != nil {
			flusher.Flush()
		}
	}

	// content_block_stop event
	blockStop := map[string]interface{}{
		"type":  "content_block_stop",
		"index": 0,
	}
	data, _ = json.Marshal(blockStop)
	fmt.Fprintf(w, "event: content_block_stop\ndata: %s\n\n", data)
	if flusher != nil {
		flusher.Flush()
	}

	// message_delta event
	msgDelta := map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]string{
			"stop_reason": "end_turn",
		},
		"usage": map[string]int{
			"output_tokens": len(tokens),
		},
	}
	data, _ = json.Marshal(msgDelta)
	fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", data)
	if flusher != nil {
		flusher.Flush()
	}

	// message_stop event
	msgStop := map[string]interface{}{
		"type": "message_stop",
	}
	data, _ = json.Marshal(msgStop)
	fmt.Fprintf(w, "event: message_stop\ndata: %s\n\n", data)
	if flusher != nil {
		flusher.Flush()
	}
}

// handleAnthropicNonStreaming writes a single JSON response in Anthropic format.
func handleAnthropicNonStreaming(w http.ResponseWriter, req llmRequest) {
	content := strings.Join(tokens, "")
	resp := map[string]interface{}{
		"id":    "msg-mock-non-stream",
		"type":  "message",
		"role":  "assistant",
		"model": req.Model,
		"content": []map[string]string{
			{
				"type": "text",
				"text": content,
			},
		},
		"stop_reason": "end_turn",
		"usage": map[string]int{
			"input_tokens":  10,
			"output_tokens": len(tokens),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
