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
//
// NOTE: Fully implemented and tested but not yet registered with the operator.
// Will be wired into the ExtProc pipeline to enable MCP-aware policy enforcement
// and tool poisoning detection.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

const (
	// parserName is the name of this parser.
	parserName = "mcp"

	// methodInitialize is the JSON-RPC method for session initialization.
	methodInitialize = "initialize"

	// methodToolsList is the JSON-RPC method for listing tools.
	methodToolsList = "tools/list"

	// methodToolsCall is the JSON-RPC method for calling a tool.
	methodToolsCall = "tools/call"

	// msgTypeSessionInit is the message type for session initialization.
	msgTypeSessionInit = "mcp.session.init"

	// msgTypeToolsList is the message type for tools list.
	msgTypeToolsList = "mcp.tools.list"
)

// MCPParser implements protocol.ProtocolParser for MCP JSON-RPC 2.0 messages.
type MCPParser struct {
	mu         sync.RWMutex
	pendingIDs map[string]string // JSON-RPC id (string) -> method name
}

// NewMCPParser creates a new MCP parser.
func NewMCPParser() *MCPParser {
	return &MCPParser{
		pendingIDs: make(map[string]string),
	}
}

// Name returns the parser name.
func (p *MCPParser) Name() string {
	return parserName
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

// lookupAndRemovePending retrieves and removes a pending request by ID.
func (p *MCPParser) lookupAndRemovePending(id string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	method, ok := p.pendingIDs[id]
	if ok {
		delete(p.pendingIDs, id)
	}
	return method, ok
}

// jsonrpcMessage is the internal JSON-RPC 2.0 message structure for deserialization.
type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonrpcError   `json:"error"`
}

// jsonrpcError represents a JSON-RPC 2.0 error object.
type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// initializeParams holds the parsed params of an initialize request.
type initializeParams struct {
	ProtocolVersion string      `json:"protocolVersion"`
	Capabilities    interface{} `json:"capabilities"`
	ClientInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"clientInfo"`
}

// toolsCallParams holds the parsed params of a tools/call request.
type toolsCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// toolsListResult holds the parsed result of a tools/list response.
type toolsListResult struct {
	Tools []rawToolInfo `json:"tools"`
}

// rawToolInfo is the JSON shape of an MCP tool in a tools/list response.
type rawToolInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// idToString normalizes a JSON-RPC id (which can be a number or string) to a string.
func idToString(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n float64
	if err := json.Unmarshal(raw, &n); err == nil {
		return fmt.Sprintf("%g", n)
	}
	return string(raw)
}

// ProcessRequest parses a single MCP JSON-RPC request body.
func (p *MCPParser) ProcessRequest(
	_ context.Context, _ map[string]string, body []byte,
) (*protocol.ParsedRequest, error) {
	if len(body) == 0 {
		return nil, errors.New("empty request body")
	}

	var msg jsonrpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC: %w", err)
	}

	id := idToString(msg.ID)

	// Track request ID for response correlation
	if id != "" && msg.Method != "" {
		p.TrackRequest(id, msg.Method)
	}

	result := &protocol.ParsedRequest{
		Protocol: parserName,
		Method:   msg.Method,
		Metadata: make(map[string]interface{}),
	}

	switch msg.Method {
	case methodInitialize:
		result.MessageType = msgTypeSessionInit
		if msg.Params != nil {
			var params initializeParams
			if err := json.Unmarshal(msg.Params, &params); err == nil {
				result.Metadata["protocol_version"] = params.ProtocolVersion
				result.Metadata["client_name"] = params.ClientInfo.Name
				result.Metadata["client_version"] = params.ClientInfo.Version
				result.Metadata["capabilities"] = params.Capabilities
			}
		}

	case methodToolsList:
		result.MessageType = msgTypeToolsList

	case methodToolsCall:
		result.MessageType = "mcp.tool.call"
		if msg.Params != nil {
			var params toolsCallParams
			if err := json.Unmarshal(msg.Params, &params); err == nil {
				result.Metadata["tool_name"] = params.Name
				result.Metadata["tool_arguments"] = params.Arguments
			}
		}

	default:
		// Unknown method — still return a result
		result.MessageType = "mcp.unknown"
	}

	result.Metadata["jsonrpc_id"] = id

	return result, nil
}

// ProcessRequestBatch parses a batched array of MCP JSON-RPC requests.
func (p *MCPParser) ProcessRequestBatch(
	ctx context.Context, headers map[string]string, body []byte,
) ([]*protocol.ParsedRequest, error) {
	if len(body) == 0 {
		return nil, errors.New("empty request body")
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(body, &messages); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC batch: %w", err)
	}

	results := make([]*protocol.ParsedRequest, 0, len(messages))
	for _, raw := range messages {
		result, err := p.ProcessRequest(ctx, headers, raw)
		if err != nil {
			return nil, fmt.Errorf("batch item error: %w", err)
		}
		results = append(results, result)
	}

	return results, nil
}

// ProcessResponse parses an MCP JSON-RPC response body, correlating it with a
// previously tracked request ID to determine the response type.
func (p *MCPParser) ProcessResponse(
	_ context.Context, _ map[string]string, body []byte,
) (*protocol.ParsedResponse, error) {
	if len(body) == 0 {
		return nil, errors.New("empty response body")
	}

	var msg jsonrpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC: %w", err)
	}

	id := idToString(msg.ID)

	// Correlate response with pending request
	method, found := p.lookupAndRemovePending(id)

	result := &protocol.ParsedResponse{
		Protocol: parserName,
		Method:   method,
		Metadata: make(map[string]interface{}),
	}

	result.Metadata["jsonrpc_id"] = id

	if msg.Error != nil {
		result.MessageType = "mcp.error"
		result.Metadata["error_code"] = msg.Error.Code
		result.Metadata["error_message"] = msg.Error.Message
		return result, nil
	}

	if !found {
		result.MessageType = "mcp.response"
		return result, nil
	}

	switch method {
	case methodInitialize:
		result.MessageType = msgTypeSessionInit

	case methodToolsList:
		result.MessageType = msgTypeToolsList
		if msg.Result != nil {
			var toolsResult toolsListResult
			if err := json.Unmarshal(msg.Result, &toolsResult); err == nil {
				tools := make([]ToolInfo, len(toolsResult.Tools))
				for i, t := range toolsResult.Tools {
					tools[i] = ToolInfo(t)
				}
				result.Metadata["tools"] = tools
			}
		}

	case methodToolsCall:
		result.MessageType = "mcp.tool.response"

	default:
		result.MessageType = "mcp.response"
	}

	return result, nil
}

// ProcessStreamChunk is a no-op for MCP since MCP uses HTTP request-response,
// not streaming.
func (p *MCPParser) ProcessStreamChunk(
	_ context.Context, _ []byte, _ *protocol.StreamState,
) (*protocol.ParsedChunk, error) {
	return &protocol.ParsedChunk{
		Protocol: parserName,
	}, nil
}
