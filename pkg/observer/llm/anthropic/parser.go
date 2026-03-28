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

// Package anthropic provides parsing logic for Anthropic API request and response formats.
package anthropic

import (
	"bytes"
	"encoding/json"
)

// MessagesRequest represents a parsed Anthropic messages API request.
type MessagesRequest struct {
	// Model is the model identifier (e.g., "claude-3-opus-20240229").
	Model string

	// Messages contains the conversation messages.
	Messages []Message

	// Stream indicates whether streaming is enabled.
	Stream bool

	// MaxTokens is the maximum number of tokens to generate.
	MaxTokens int
}

// Message represents a single message in a messages API request.
type Message struct {
	// Role is the message role ("user" or "assistant").
	Role string

	// Content is the message text content.
	Content string
}

// StreamEvent represents a parsed SSE event from a streaming response.
type StreamEvent struct {
	// EventType is the SSE event type (e.g., "content_block_delta", "message_stop").
	EventType string

	// Content is the token text content (for content_block_delta events).
	Content string

	// Done indicates this is a terminal event (message_stop).
	Done bool

	// StopReason is the reason generation stopped (for message_stop/message_delta events).
	StopReason string
}

// MessagesResponse represents a parsed non-streaming Anthropic response.
type MessagesResponse struct {
	// Content is the full response text.
	Content string

	// Model is the model used.
	Model string

	// StopReason is the reason generation stopped.
	StopReason string

	// InputTokens is the input token count.
	InputTokens int

	// OutputTokens is the output token count.
	OutputTokens int
}

// rawRequest is the internal JSON structure for request deserialization.
type rawRequest struct {
	Model     string       `json:"model"`
	Messages  []rawMessage `json:"messages"`
	Stream    bool         `json:"stream"`
	MaxTokens int          `json:"max_tokens"`
}

// rawMessage is the internal JSON structure for message deserialization.
type rawMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// rawContentBlockDelta is the internal JSON structure for content_block_delta events.
type rawContentBlockDelta struct {
	Type  string `json:"type"`
	Delta struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"delta"`
}

// rawMessageDelta is the internal JSON structure for message_delta events.
type rawMessageDelta struct {
	Type  string `json:"type"`
	Delta struct {
		StopReason   string  `json:"stop_reason"`
		StopSequence *string `json:"stop_sequence"`
	} `json:"delta"`
}

// rawResponse is the internal JSON structure for non-streaming response deserialization.
type rawResponse struct {
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ParseRequest parses a raw JSON request body into a MessagesRequest.
func ParseRequest(body []byte) (*MessagesRequest, error) {
	var raw rawRequest
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	messages := make([]Message, len(raw.Messages))
	for i, m := range raw.Messages {
		messages[i] = Message{
			Role:    m.Role,
			Content: m.Content,
		}
	}

	return &MessagesRequest{
		Model:     raw.Model,
		Messages:  messages,
		Stream:    raw.Stream,
		MaxTokens: raw.MaxTokens,
	}, nil
}

// ParseSSEEvent parses a single SSE event (identified by event type and data payload)
// into a StreamEvent.
func ParseSSEEvent(eventType string, data []byte) (*StreamEvent, error) {
	event := &StreamEvent{
		EventType: eventType,
	}

	switch eventType {
	case "content_block_delta":
		var raw rawContentBlockDelta
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
		event.Content = raw.Delta.Text

	case "message_delta":
		var raw rawMessageDelta
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
		event.StopReason = raw.Delta.StopReason

	case "message_stop":
		event.Done = true
	}

	return event, nil
}

// ParseSSEFrame parses a raw HTTP frame that may contain multiple SSE events.
// Anthropic SSE format uses "event: <type>\ndata: <json>\n\n" pairs.
func ParseSSEFrame(frame []byte) ([]*StreamEvent, error) {
	if len(frame) == 0 {
		return nil, nil
	}

	var events []*StreamEvent

	// Split frame into individual SSE event blocks by double newline
	blocks := bytes.Split(frame, []byte("\n\n"))

	for _, block := range blocks {
		block = bytes.TrimSpace(block)
		if len(block) == 0 {
			continue
		}

		var eventType string
		var dataPayload []byte

		lines := bytes.Split(block, []byte("\n"))
		for _, line := range lines {
			line = bytes.TrimSpace(line)
			if bytes.HasPrefix(line, []byte("event: ")) {
				eventType = string(bytes.TrimPrefix(line, []byte("event: ")))
			} else if bytes.HasPrefix(line, []byte("data: ")) {
				dataPayload = bytes.TrimPrefix(line, []byte("data: "))
			}
		}

		if eventType == "" {
			continue
		}

		event, err := ParseSSEEvent(eventType, dataPayload)
		if err != nil {
			return events, err
		}
		events = append(events, event)
	}

	return events, nil
}

// ParseNonStreamingResponse parses a complete non-streaming response body.
func ParseNonStreamingResponse(body []byte) (*MessagesResponse, error) {
	var raw rawResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	resp := &MessagesResponse{
		Model:        raw.Model,
		StopReason:   raw.StopReason,
		InputTokens:  raw.Usage.InputTokens,
		OutputTokens: raw.Usage.OutputTokens,
	}

	// Concatenate all text content blocks
	for _, block := range raw.Content {
		if block.Type == "text" {
			resp.Content += block.Text
		}
	}

	return resp, nil
}
