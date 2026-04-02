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

// Package protocol provides the protocol detection framework and ProtocolParser
// interface for extensible, multi-protocol parsing in the Panoptium operator.
// Parsers implement this interface to handle MCP, A2A, Google Gemini, and other
// protocols flowing through the ExtProc pipeline.
package protocol

import "context"

// ProtocolParser defines the interface for protocol-specific parsers that
// detect and parse protocol messages flowing through the ExtProc pipeline.
// Each implementation handles a specific protocol (e.g., MCP, A2A, Gemini).
type ProtocolParser interface {
	// Name returns a unique identifier for this parser (e.g., "mcp", "a2a", "gemini").
	Name() string

	// Detect determines whether this parser can handle the given request based
	// on headers, path, and method. Returns whether it can handle the request
	// and a confidence score (0.0 to 1.0).
	Detect(headers map[string]string, path string, method string) (bool, float32)

	// ProcessRequest parses a request body into a structured protocol event.
	ProcessRequest(ctx context.Context, headers map[string]string, body []byte) (*ParsedRequest, error)

	// ProcessResponse parses a response body into a structured protocol event.
	ProcessResponse(ctx context.Context, headers map[string]string, body []byte) (*ParsedResponse, error)

	// ProcessStreamChunk parses a single SSE/streaming chunk with stateful
	// tracking across chunks via StreamState.
	ProcessStreamChunk(ctx context.Context, chunk []byte, state *StreamState) (*ParsedChunk, error)
}

// ParsedRequest represents a parsed protocol request.
type ParsedRequest struct {
	// Protocol identifies the protocol (e.g., "mcp", "a2a", "gemini").
	Protocol string

	// MessageType identifies the specific message type (e.g., "tools/call", "tasks/send").
	MessageType string

	// Method is the protocol-specific method name (e.g., JSON-RPC method).
	Method string

	// Metadata contains protocol-specific key-value metadata extracted from the request.
	Metadata map[string]interface{}
}

// ParsedResponse represents a parsed protocol response.
type ParsedResponse struct {
	// Protocol identifies the protocol.
	Protocol string

	// MessageType identifies the specific message type.
	MessageType string

	// Method is the protocol-specific method name.
	Method string

	// Metadata contains protocol-specific key-value metadata extracted from the response.
	Metadata map[string]interface{}
}

// ParsedChunk represents a parsed streaming chunk.
type ParsedChunk struct {
	// Protocol identifies the protocol.
	Protocol string

	// Content is the text content extracted from this chunk.
	Content string

	// Done indicates this is the final chunk in the stream.
	Done bool

	// Metadata contains protocol-specific key-value metadata extracted from the chunk.
	Metadata map[string]interface{}
}

// StreamState tracks parser-specific state across streaming chunks.
// It enables stateful processing of chunked SSE responses, including
// partial JSON buffering and JSON-RPC request ID correlation.
type StreamState struct {
	// Protocol identifies which parser owns this state.
	Protocol string

	// Buffer holds partial data that spans multiple chunks (e.g., incomplete JSON).
	Buffer []byte

	// PendingIDs maps JSON-RPC request IDs to their method names for
	// request-response correlation.
	PendingIDs map[string]string

	// Metadata contains arbitrary parser-specific state.
	Metadata map[string]string
}

// NewStreamState creates a new StreamState for the given protocol.
func NewStreamState(protocol string) *StreamState {
	return &StreamState{
		Protocol:   protocol,
		PendingIDs: make(map[string]string),
		Metadata:   make(map[string]string),
	}
}
