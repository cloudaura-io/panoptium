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

// Package mcp implements the ProtocolParser interface for the Model Context Protocol
// (MCP), parsing JSON-RPC 2.0 messages for tool operations, session initialization,
// and tool poisoning detection.
package mcp

import (
	"context"
	"errors"
	"sync"

	"github.com/panoptium/panoptium/pkg/observer/protocol"
)

// ToolInfo contains metadata about an MCP tool extracted from a tools/list response.
type ToolInfo struct {
	// Name is the tool's identifier.
	Name string

	// Description is the tool's human-readable description.
	Description string

	// InputSchema is the JSON Schema for the tool's input parameters.
	InputSchema map[string]interface{}
}

// MCPParser implements protocol.ProtocolParser for MCP JSON-RPC 2.0 messages.
type MCPParser struct {
	mu         sync.RWMutex
	pendingIDs map[string]string // JSON-RPC id -> method name
}

// NewMCPParser creates a new MCP parser.
func NewMCPParser() *MCPParser {
	return &MCPParser{
		pendingIDs: make(map[string]string),
	}
}

// Name returns the parser name.
func (p *MCPParser) Name() string {
	return "mcp"
}

// Detect returns whether this parser can handle the given request.
// MCP detection is primarily handled by the ProtocolDetector's JSON-RPC method
// inspection, so this returns false by default.
func (p *MCPParser) Detect(_ map[string]string, _ string, _ string) (bool, float32) {
	return false, 0
}

// TrackRequest registers a JSON-RPC request ID for later response correlation.
func (p *MCPParser) TrackRequest(id string, method string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pendingIDs[id] = method
}

// ProcessRequest parses a single MCP JSON-RPC request.
func (p *MCPParser) ProcessRequest(_ context.Context, _ map[string]string, _ []byte) (*protocol.ParsedRequest, error) {
	return nil, errors.New("not implemented")
}

// ProcessRequestBatch parses a batched array of MCP JSON-RPC requests.
func (p *MCPParser) ProcessRequestBatch(_ context.Context, _ map[string]string, _ []byte) ([]*protocol.ParsedRequest, error) {
	return nil, errors.New("not implemented")
}

// ProcessResponse parses an MCP JSON-RPC response.
func (p *MCPParser) ProcessResponse(_ context.Context, _ map[string]string, _ []byte) (*protocol.ParsedResponse, error) {
	return nil, errors.New("not implemented")
}

// ProcessStreamChunk is a no-op for MCP since MCP uses HTTP request-response,
// not streaming.
func (p *MCPParser) ProcessStreamChunk(_ context.Context, _ []byte, _ *protocol.StreamState) (*protocol.ParsedChunk, error) {
	return &protocol.ParsedChunk{
		Protocol: "mcp",
	}, nil
}
