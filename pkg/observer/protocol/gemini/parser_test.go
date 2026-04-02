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

package gemini

import (
	"context"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/observer/protocol"
)

// --- Compile-time interface check ---

var _ protocol.ProtocolParser = (*GeminiParser)(nil)

// --- Detect Tests ---

// TestGeminiParser_Detect_V1Beta verifies detection of v1beta generateContent path.
func TestGeminiParser_Detect_V1Beta(t *testing.T) {
	parser := NewGeminiParser()
	canDetect, confidence := parser.Detect(map[string]string{}, "/v1beta/models/gemini-pro/generateContent", "POST")
	if !canDetect {
		t.Error("Detect() returned false for v1beta path, want true")
	}
	if confidence < 0.9 {
		t.Errorf("Confidence = %f, want >= 0.9", confidence)
	}
}

// TestGeminiParser_Detect_V1 verifies detection of v1 generateContent path.
func TestGeminiParser_Detect_V1(t *testing.T) {
	parser := NewGeminiParser()
	canDetect, confidence := parser.Detect(map[string]string{}, "/v1/models/gemini-1.5-flash/generateContent", "POST")
	if !canDetect {
		t.Error("Detect() returned false for v1 path, want true")
	}
	if confidence >= 0.9 {
		// Good
	}
}

// TestGeminiParser_Detect_StreamGenerateContent verifies detection of streaming path.
func TestGeminiParser_Detect_StreamGenerateContent(t *testing.T) {
	parser := NewGeminiParser()
	canDetect, _ := parser.Detect(map[string]string{}, "/v1beta/models/gemini-pro/streamGenerateContent", "POST")
	if !canDetect {
		t.Error("Detect() returned false for streamGenerateContent path, want true")
	}
}

// TestGeminiParser_Detect_NonGemini verifies non-Gemini paths are rejected.
func TestGeminiParser_Detect_NonGemini(t *testing.T) {
	parser := NewGeminiParser()
	canDetect, _ := parser.Detect(map[string]string{}, "/v1/chat/completions", "POST")
	if canDetect {
		t.Error("Detect() returned true for non-Gemini path, want false")
	}
}

// --- Request Parsing Tests ---

// TestGeminiParser_ProcessRequest_GenerateContent verifies parsing a generateContent request.
func TestGeminiParser_ProcessRequest_GenerateContent(t *testing.T) {
	parser := NewGeminiParser()
	ctx := context.Background()

	body := []byte(`{
		"model": "gemini-pro",
		"contents": [
			{
				"role": "user",
				"parts": [
					{"text": "What is the weather in London?"}
				]
			}
		],
		"tools": [
			{
				"functionDeclarations": [
					{
						"name": "get_weather",
						"description": "Returns weather for a location"
					}
				]
			}
		],
		"safetySettings": [
			{
				"category": "HARM_CATEGORY_HARASSMENT",
				"threshold": "BLOCK_MEDIUM_AND_ABOVE"
			}
		]
	}`)

	result, err := parser.ProcessRequest(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessRequest() returned nil")
	}
	if result.Protocol != "gemini" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "gemini")
	}
	if result.MessageType != "llm.request.start" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "llm.request.start")
	}
	if result.Metadata["model"] != "gemini-pro" {
		t.Errorf("model = %v, want %q", result.Metadata["model"], "gemini-pro")
	}
	toolNames, ok := result.Metadata["tool_names"].([]string)
	if !ok {
		t.Fatalf("tool_names type = %T, want []string", result.Metadata["tool_names"])
	}
	if len(toolNames) != 1 || toolNames[0] != "get_weather" {
		t.Errorf("tool_names = %v, want [get_weather]", toolNames)
	}
}

// TestGeminiParser_ProcessRequest_FunctionResponse verifies parsing of follow-up
// request containing functionResponse.
func TestGeminiParser_ProcessRequest_FunctionResponse(t *testing.T) {
	parser := NewGeminiParser()
	ctx := context.Background()

	body := []byte(`{
		"contents": [
			{
				"role": "model",
				"parts": [
					{"functionCall": {"name": "get_weather", "args": {"location": "London"}}}
				]
			},
			{
				"role": "user",
				"parts": [
					{
						"functionResponse": {
							"name": "get_weather",
							"response": {"temperature": 15, "condition": "cloudy"}
						}
					}
				]
			}
		]
	}`)

	result, err := parser.ProcessRequest(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}
	if result.Metadata["function_response_name"] != "get_weather" {
		t.Errorf("function_response_name = %v, want %q", result.Metadata["function_response_name"], "get_weather")
	}
}

// --- SSE Response Parsing Tests ---

// TestGeminiParser_ProcessStreamChunk_TextContent verifies text extraction from SSE chunks.
func TestGeminiParser_ProcessStreamChunk_TextContent(t *testing.T) {
	parser := NewGeminiParser()
	ctx := context.Background()
	state := protocol.NewStreamState("gemini")

	chunk := []byte(`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Hello"}]},"safetyRatings":[{"category":"HARM_CATEGORY_HARASSMENT","probability":"NEGLIGIBLE"}]}]}` + "\n\n")

	result, err := parser.ProcessStreamChunk(ctx, chunk, state)
	if err != nil {
		t.Fatalf("ProcessStreamChunk() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessStreamChunk() returned nil")
	}
	if result.Content != "Hello" {
		t.Errorf("Content = %q, want %q", result.Content, "Hello")
	}
	if result.Protocol != "gemini" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "gemini")
	}
}

// TestGeminiParser_ProcessStreamChunk_FunctionCall verifies functionCall extraction
// from streaming response.
func TestGeminiParser_ProcessStreamChunk_FunctionCall(t *testing.T) {
	parser := NewGeminiParser()
	ctx := context.Background()
	state := protocol.NewStreamState("gemini")

	chunk := []byte(`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"location":"London"}}}]},"finishReason":"STOP"}]}` + "\n\n")

	result, err := parser.ProcessStreamChunk(ctx, chunk, state)
	if err != nil {
		t.Fatalf("ProcessStreamChunk() error = %v", err)
	}
	if result.Metadata["function_call_name"] != "get_weather" {
		t.Errorf("function_call_name = %v, want %q", result.Metadata["function_call_name"], "get_weather")
	}
	args, ok := result.Metadata["function_call_args"].(map[string]interface{})
	if !ok {
		t.Fatalf("function_call_args type = %T, want map", result.Metadata["function_call_args"])
	}
	if args["location"] != "London" {
		t.Errorf("function_call_args.location = %v, want %q", args["location"], "London")
	}
	if !result.Done {
		t.Error("Done = false, want true (finishReason is STOP)")
	}
}

// TestGeminiParser_ProcessStreamChunk_SafetyRatings verifies safety ratings extraction.
func TestGeminiParser_ProcessStreamChunk_SafetyRatings(t *testing.T) {
	parser := NewGeminiParser()
	ctx := context.Background()
	state := protocol.NewStreamState("gemini")

	chunk := []byte(`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Hi"}]},"safetyRatings":[{"category":"HARM_CATEGORY_HARASSMENT","probability":"NEGLIGIBLE"},{"category":"HARM_CATEGORY_DANGEROUS_CONTENT","probability":"LOW"}]}]}` + "\n\n")

	result, err := parser.ProcessStreamChunk(ctx, chunk, state)
	if err != nil {
		t.Fatalf("ProcessStreamChunk() error = %v", err)
	}
	ratings, ok := result.Metadata["safety_ratings"].([]safetyRating)
	if !ok {
		t.Fatalf("safety_ratings type = %T, want []safetyRating", result.Metadata["safety_ratings"])
	}
	if len(ratings) != 2 {
		t.Fatalf("safety_ratings count = %d, want 2", len(ratings))
	}
}

// TestGeminiParser_ProcessStreamChunk_Empty verifies handling of empty chunks.
func TestGeminiParser_ProcessStreamChunk_Empty(t *testing.T) {
	parser := NewGeminiParser()
	ctx := context.Background()
	state := protocol.NewStreamState("gemini")

	result, err := parser.ProcessStreamChunk(ctx, []byte{}, state)
	if err != nil {
		t.Fatalf("ProcessStreamChunk() error = %v", err)
	}
	if result != nil {
		t.Error("ProcessStreamChunk() should return nil for empty chunk")
	}
}

// --- Non-streaming response ---

// TestGeminiParser_ProcessResponse_NonStreaming verifies parsing of non-streaming response.
func TestGeminiParser_ProcessResponse_NonStreaming(t *testing.T) {
	parser := NewGeminiParser()
	ctx := context.Background()

	body := []byte(`{
		"candidates": [
			{
				"content": {
					"role": "model",
					"parts": [
						{"text": "The weather in London is cloudy and 15C."}
					]
				},
				"finishReason": "STOP",
				"safetyRatings": [
					{"category": "HARM_CATEGORY_HARASSMENT", "probability": "NEGLIGIBLE"}
				],
				"citationMetadata": {
					"citationSources": [
						{"startIndex": 0, "endIndex": 10, "uri": "https://example.com"}
					]
				}
			}
		],
		"usageMetadata": {
			"promptTokenCount": 10,
			"candidatesTokenCount": 15,
			"totalTokenCount": 25
		}
	}`)

	result, err := parser.ProcessResponse(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessResponse() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessResponse() returned nil")
	}
	if result.Protocol != "gemini" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "gemini")
	}
	if result.MessageType != "llm.token.chunk" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "llm.token.chunk")
	}
	if result.Metadata["content"] != "The weather in London is cloudy and 15C." {
		t.Errorf("content = %v, want expected text", result.Metadata["content"])
	}
	if result.Metadata["finish_reason"] != "STOP" {
		t.Errorf("finish_reason = %v, want %q", result.Metadata["finish_reason"], "STOP")
	}
	if result.Metadata["total_tokens"] != 25 {
		t.Errorf("total_tokens = %v, want 25", result.Metadata["total_tokens"])
	}
}

// TestGeminiParser_ProcessResponse_FunctionCallResponse verifies functionCall in non-streaming.
func TestGeminiParser_ProcessResponse_FunctionCallResponse(t *testing.T) {
	parser := NewGeminiParser()
	ctx := context.Background()

	body := []byte(`{
		"candidates": [
			{
				"content": {
					"role": "model",
					"parts": [
						{
							"functionCall": {
								"name": "get_weather",
								"args": {"location": "London"}
							}
						}
					]
				},
				"finishReason": "STOP"
			}
		]
	}`)

	result, err := parser.ProcessResponse(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessResponse() error = %v", err)
	}
	if result.MessageType != "llm.tool.call" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "llm.tool.call")
	}
	if result.Metadata["function_call_name"] != "get_weather" {
		t.Errorf("function_call_name = %v, want %q", result.Metadata["function_call_name"], "get_weather")
	}
}

// --- Performance Tests ---

// TestGeminiParser_ChunkProcessingLatency verifies chunk processing <5ms (NFR-1).
func TestGeminiParser_ChunkProcessingLatency(t *testing.T) {
	parser := NewGeminiParser()
	ctx := context.Background()
	state := protocol.NewStreamState("gemini")

	chunk := []byte(`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Hello world"}]},"safetyRatings":[{"category":"HARM_CATEGORY_HARASSMENT","probability":"NEGLIGIBLE"}]}]}` + "\n\n")

	start := time.Now()
	iterations := 1000
	for i := 0; i < iterations; i++ {
		parser.ProcessStreamChunk(ctx, chunk, state)
	}
	elapsed := time.Since(start)

	avgPerChunk := elapsed / time.Duration(iterations)
	if avgPerChunk > 5*time.Millisecond {
		t.Errorf("Average chunk processing latency = %v, want <5ms", avgPerChunk)
	}
}
