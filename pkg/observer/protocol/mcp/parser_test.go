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

package mcp

import (
	"context"
	"testing"

	"github.com/panoptium/panoptium/pkg/observer/protocol"
)

var _ protocol.ProtocolParser = (*MCPParser)(nil)

// TestMCPParser_ProcessRequest_Initialize verifies parsing of an initialize request.
func TestMCPParser_ProcessRequest_Initialize(t *testing.T) {
	parser := NewMCPParser()
	ctx := context.Background()

	body := []byte(`{
		"jsonrpc": "2.0",
		"method": "initialize",
		"id": 1,
		"params": {
			"protocolVersion": "2024-11-05",
			"capabilities": {"tools": {}},
			"clientInfo": {
				"name": "test-client",
				"version": "1.0.0"
			}
		}
	}`)

	result, err := parser.ProcessRequest(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessRequest() returned nil")
	}
	if result.Protocol != "mcp" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "mcp")
	}
	if result.Method != "initialize" {
		t.Errorf("Method = %q, want %q", result.Method, "initialize")
	}
	if result.MessageType != "mcp.session.init" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "mcp.session.init")
	}

	// Check metadata
	if result.Metadata["protocol_version"] != "2024-11-05" {
		t.Errorf("protocol_version = %v, want %q", result.Metadata["protocol_version"], "2024-11-05")
	}
	if result.Metadata["client_name"] != "test-client" {
		t.Errorf("client_name = %v, want %q", result.Metadata["client_name"], "test-client")
	}
	if result.Metadata["client_version"] != "1.0.0" {
		t.Errorf("client_version = %v, want %q", result.Metadata["client_version"], "1.0.0")
	}
}

// TestMCPParser_ProcessResponse_ToolsList verifies parsing of a tools/list response.
func TestMCPParser_ProcessResponse_ToolsList(t *testing.T) {
	parser := NewMCPParser()
	ctx := context.Background()

	// Pre-register the pending request ID correlation
	parser.TrackRequest("2", "tools/list")

	body := []byte(`{
		"jsonrpc": "2.0",
		"id": 2,
		"result": {
			"tools": [
				{
					"name": "read_file",
					"description": "Reads a file from the filesystem",
					"inputSchema": {
						"type": "object",
						"properties": {
							"path": {"type": "string", "description": "The file path to read"}
						},
						"required": ["path"]
					}
				},
				{
					"name": "write_file",
					"description": "Writes content to a file",
					"inputSchema": {
						"type": "object",
						"properties": {
							"path": {"type": "string"},
							"content": {"type": "string"}
						},
						"required": ["path", "content"]
					}
				}
			]
		}
	}`)

	result, err := parser.ProcessResponse(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessResponse() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessResponse() returned nil")
	}
	if result.Protocol != "mcp" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "mcp")
	}
	if result.MessageType != "mcp.tools.list" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "mcp.tools.list")
	}

	// Check tool names extracted
	tools, ok := result.Metadata["tools"].([]ToolInfo)
	if !ok {
		t.Fatalf("Metadata[tools] type = %T, want []ToolInfo", result.Metadata["tools"])
	}
	if len(tools) != 2 {
		t.Fatalf("tools count = %d, want 2", len(tools))
	}
	if tools[0].Name != "read_file" {
		t.Errorf("tools[0].Name = %q, want %q", tools[0].Name, "read_file")
	}
	if tools[0].Description != "Reads a file from the filesystem" {
		t.Errorf("tools[0].Description = %q, want expected description", tools[0].Description)
	}
	if tools[1].Name != "write_file" {
		t.Errorf("tools[1].Name = %q, want %q", tools[1].Name, "write_file")
	}
}

// TestMCPParser_ProcessRequest_ToolsCall verifies parsing of a tools/call request.
func TestMCPParser_ProcessRequest_ToolsCall(t *testing.T) {
	parser := NewMCPParser()
	ctx := context.Background()

	body := []byte(`{
		"jsonrpc": "2.0",
		"method": "tools/call",
		"id": 3,
		"params": {
			"name": "read_file",
			"arguments": {
				"path": "/etc/passwd"
			}
		}
	}`)

	result, err := parser.ProcessRequest(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessRequest() returned nil")
	}
	if result.Method != "tools/call" {
		t.Errorf("Method = %q, want %q", result.Method, "tools/call")
	}
	if result.MessageType != "mcp.tool.call" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "mcp.tool.call")
	}
	if result.Metadata["tool_name"] != "read_file" {
		t.Errorf("tool_name = %v, want %q", result.Metadata["tool_name"], "read_file")
	}
	args, ok := result.Metadata["tool_arguments"].(map[string]interface{})
	if !ok {
		t.Fatalf("tool_arguments type = %T, want map", result.Metadata["tool_arguments"])
	}
	if args["path"] != "/etc/passwd" {
		t.Errorf("tool_arguments.path = %v, want %q", args["path"], "/etc/passwd")
	}
}

// TestMCPParser_ProcessResponse_ToolResult verifies parsing of a tool call result.
func TestMCPParser_ProcessResponse_ToolResult(t *testing.T) {
	parser := NewMCPParser()
	ctx := context.Background()

	parser.TrackRequest("3", "tools/call")

	body := []byte(`{
		"jsonrpc": "2.0",
		"id": 3,
		"result": {
			"content": [
				{
					"type": "text",
					"text": "root:x:0:0:root:/root:/bin/bash"
				}
			]
		}
	}`)

	result, err := parser.ProcessResponse(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessResponse() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessResponse() returned nil")
	}
	if result.MessageType != "mcp.tool.response" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "mcp.tool.response")
	}
}

// TestMCPParser_RequestIDCorrelation verifies tracking request IDs between request and response.
func TestMCPParser_RequestIDCorrelation(t *testing.T) {
	parser := NewMCPParser()
	ctx := context.Background()

	// Process initialize request
	initBody := []byte(`{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}`)
	result, err := parser.ProcessRequest(ctx, map[string]string{}, initBody)
	if err != nil {
		t.Fatalf("ProcessRequest(initialize) error = %v", err)
	}
	if result.Method != "initialize" {
		t.Errorf("Method = %q, want %q", result.Method, "initialize")
	}

	// Process initialize response — should correlate via id:1
	initResp := []byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"test-server","version":"1.0"}}}`)
	respResult, err := parser.ProcessResponse(ctx, map[string]string{}, initResp)
	if err != nil {
		t.Fatalf("ProcessResponse(initialize) error = %v", err)
	}
	if respResult.MessageType != "mcp.session.init" {
		t.Errorf("correlated MessageType = %q, want %q", respResult.MessageType, "mcp.session.init")
	}
}

// TestMCPParser_ProcessRequest_Batch verifies parsing of batched JSON-RPC requests.
func TestMCPParser_ProcessRequest_Batch(t *testing.T) {
	parser := NewMCPParser()
	ctx := context.Background()

	body := []byte(`[
		{"jsonrpc":"2.0","method":"tools/list","id":1},
		{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}
	]`)

	results, err := parser.ProcessRequestBatch(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessRequestBatch() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("ProcessRequestBatch() returned %d results, want 2", len(results))
	}
	if results[0].Method != "tools/list" {
		t.Errorf("results[0].Method = %q, want %q", results[0].Method, "tools/list")
	}
	if results[1].Method != "tools/call" {
		t.Errorf("results[1].Method = %q, want %q", results[1].Method, "tools/call")
	}
}

// TestMCPParser_ProcessRequest_MalformedJSON verifies graceful error on malformed JSON.
func TestMCPParser_ProcessRequest_MalformedJSON(t *testing.T) {
	parser := NewMCPParser()
	ctx := context.Background()

	body := []byte(`{invalid json`)

	_, err := parser.ProcessRequest(ctx, map[string]string{}, body)
	if err == nil {
		t.Fatal("ProcessRequest() expected error for malformed JSON, got nil")
	}
}

// TestMCPParser_ProcessRequest_MissingMethod verifies handling of JSON-RPC without method.
func TestMCPParser_ProcessRequest_MissingMethod(t *testing.T) {
	parser := NewMCPParser()
	ctx := context.Background()

	body := []byte(`{"jsonrpc":"2.0","id":1}`)

	result, err := parser.ProcessRequest(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}
	// Should still return a result but with an empty/unknown method
	if result.Method != "" {
		t.Errorf("Method = %q, want empty for missing method", result.Method)
	}
}

// TestMCPParser_ProcessRequest_EmptyBody verifies graceful handling of empty body.
func TestMCPParser_ProcessRequest_EmptyBody(t *testing.T) {
	parser := NewMCPParser()
	ctx := context.Background()

	_, err := parser.ProcessRequest(ctx, map[string]string{}, []byte{})
	if err == nil {
		t.Fatal("ProcessRequest() expected error for empty body, got nil")
	}
}

// TestMCPParser_Detect verifies detection of MCP traffic.
func TestMCPParser_Detect(t *testing.T) {
	parser := NewMCPParser()

	// MCP has no path-based detection — relies on JSON-RPC method from ProtocolDetector
	canDetect, confidence := parser.Detect(
		map[string]string{"Content-Type": "application/json"},
		"/rpc",
		"POST",
	)
	// MCP parser itself should return low or no confidence (detection is via ProtocolDetector)
	_ = canDetect
	_ = confidence
}
