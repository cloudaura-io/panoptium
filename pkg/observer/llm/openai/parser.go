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

// Package openai provides parsing logic for OpenAI API request and response formats.
package openai

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ChatCompletionRequest represents a parsed OpenAI chat completion request.
type ChatCompletionRequest struct {
	// Model is the model identifier (e.g., "gpt-4", "gpt-3.5-turbo").
	Model string

	// Messages contains the conversation messages.
	Messages []Message

	// Stream indicates whether streaming is enabled.
	Stream bool

	// ToolNames contains the function names extracted from the tools array.
	// Each entry corresponds to tools[i].function.name in the request.
	ToolNames []string

	// ToolChoice is the tool_choice value from the request (e.g., "auto", "none").
	ToolChoice string
}

// Message represents a single message in a chat completion request.
type Message struct {
	// Role is the message role (e.g., "system", "user", "assistant").
	Role string

	// Content is the message text content.
	Content string
}

// StreamChunk represents a parsed SSE chunk from a streaming response.
type StreamChunk struct {
	// ID is the chunk identifier.
	ID string

	// Content is the token text content from this chunk.
	Content string

	// FinishReason is set on the final chunk (e.g., "stop", "length", "tool_calls").
	FinishReason string

	// Done indicates this is the [DONE] sentinel.
	Done bool

	// ToolCalls contains incremental tool call deltas from this chunk.
	// Each entry corresponds to one tool_calls[i] in the delta.
	ToolCalls []ToolCallDelta
}

// ToolCallDelta represents an incremental tool call update from a streaming
// response chunk. Tool call data may be fragmented across multiple chunks.
type ToolCallDelta struct {
	// Index is the tool call index (for parallel tool calls).
	Index int

	// ID is the tool call identifier (set on the first chunk for this index).
	ID string

	// FunctionName is the function name fragment from this chunk.
	FunctionName string

	// FunctionArguments is the function arguments fragment from this chunk.
	FunctionArguments string
}

// ChatCompletionResponse represents a parsed non-streaming response.
type ChatCompletionResponse struct {
	// Content is the full response text.
	Content string

	// Model is the model used.
	Model string

	// FinishReason is the reason generation stopped.
	FinishReason string

	// TotalTokens is the total token count reported by the API.
	TotalTokens int

	// InputTokens is the prompt token count.
	InputTokens int

	// OutputTokens is the completion token count.
	OutputTokens int
}

// rawTool is the internal JSON structure for a single tool in the request.
type rawTool struct {
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

// rawRequest is the internal JSON structure for request deserialization.
type rawRequest struct {
	Model      string       `json:"model"`
	Messages   []rawMessage `json:"messages"`
	Stream     bool         `json:"stream"`
	Tools      []rawTool    `json:"tools"`
	ToolChoice interface{}  `json:"tool_choice"`
}

// rawMessage is the internal JSON structure for message deserialization.
type rawMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// rawToolCallDelta is the internal JSON structure for a tool call delta.
type rawToolCallDelta struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// rawChunk is the internal JSON structure for SSE chunk deserialization.
type rawChunk struct {
	ID      string `json:"id"`
	Choices []struct {
		Delta struct {
			Content   string             `json:"content"`
			ToolCalls []rawToolCallDelta `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

// rawResponse is the internal JSON structure for non-streaming response deserialization.
type rawResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// ParseRequest parses a raw JSON request body into a ChatCompletionRequest.
func ParseRequest(body []byte) (*ChatCompletionRequest, error) {
	var raw rawRequest
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	messages := make([]Message, len(raw.Messages))
	for i, m := range raw.Messages {
		messages[i] = Message(m)
	}

	// Extract tool names from tools array
	var toolNames []string
	for _, tool := range raw.Tools {
		if tool.Function.Name != "" {
			toolNames = append(toolNames, tool.Function.Name)
		}
	}

	// Extract tool_choice value
	var toolChoice string
	if raw.ToolChoice != nil {
		switch v := raw.ToolChoice.(type) {
		case string:
			toolChoice = v
		}
	}

	return &ChatCompletionRequest{
		Model:      raw.Model,
		Messages:   messages,
		Stream:     raw.Stream,
		ToolNames:  toolNames,
		ToolChoice: toolChoice,
	}, nil
}

// ParseSSEChunk parses a single SSE data payload (JSON) into a StreamChunk.
func ParseSSEChunk(data []byte) (*StreamChunk, error) {
	var raw rawChunk
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	chunk := &StreamChunk{
		ID: raw.ID,
	}

	if len(raw.Choices) > 0 {
		choice := raw.Choices[0]
		chunk.Content = choice.Delta.Content
		if choice.FinishReason != nil {
			chunk.FinishReason = *choice.FinishReason
		}

		// Extract tool call deltas
		for _, tc := range choice.Delta.ToolCalls {
			chunk.ToolCalls = append(chunk.ToolCalls, ToolCallDelta{
				Index:             tc.Index,
				ID:                tc.ID,
				FunctionName:      tc.Function.Name,
				FunctionArguments: tc.Function.Arguments,
			})
		}
	}

	return chunk, nil
}

// ParseSSEFrame parses a raw HTTP frame that may contain multiple SSE events.
// Each event is delimited by a blank line ("\n\n") and prefixed with "data: ".
// The special "data: [DONE]" marker indicates the end of the stream.
func ParseSSEFrame(frame []byte) ([]*StreamChunk, error) {
	if len(frame) == 0 {
		return nil, nil
	}

	var chunks []*StreamChunk

	// Split frame into individual SSE events by double newline
	events := bytes.Split(frame, []byte("\n\n"))

	for _, event := range events {
		event = bytes.TrimSpace(event)
		if len(event) == 0 {
			continue
		}

		// Extract the data payload from lines starting with "data: "
		lines := bytes.Split(event, []byte("\n"))
		for _, line := range lines {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data: ")) {
				continue
			}

			payload := bytes.TrimPrefix(line, []byte("data: "))

			// Check for [DONE] marker
			if strings.TrimSpace(string(payload)) == "[DONE]" {
				chunks = append(chunks, &StreamChunk{Done: true})
				continue
			}

			// Parse JSON chunk
			chunk, err := ParseSSEChunk(payload)
			if err != nil {
				return chunks, err
			}
			chunks = append(chunks, chunk)
		}
	}

	return chunks, nil
}

// ParseNonStreamingResponse parses a complete non-streaming response body.
func ParseNonStreamingResponse(body []byte) (*ChatCompletionResponse, error) {
	var raw rawResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	resp := &ChatCompletionResponse{
		Model:        raw.Model,
		TotalTokens:  raw.Usage.TotalTokens,
		InputTokens:  raw.Usage.PromptTokens,
		OutputTokens: raw.Usage.CompletionTokens,
	}

	if len(raw.Choices) > 0 {
		resp.Content = raw.Choices[0].Message.Content
		resp.FinishReason = raw.Choices[0].FinishReason
	}

	return resp, nil
}
