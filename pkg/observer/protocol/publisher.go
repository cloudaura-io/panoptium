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

package protocol

import (
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// Protocol event type constants.
const (
	// MCP events
	EventTypeMCPSessionInit  = "mcp.session.init"
	EventTypeMCPToolsList    = "mcp.tools.list"
	EventTypeMCPToolCall     = "mcp.tool.call"
	EventTypeMCPToolResponse = "mcp.tool.response"

	// A2A events
	EventTypeA2AAgentDiscovered = "a2a.agent.discovered"
	EventTypeA2ATaskCreated     = "a2a.task.created"
	EventTypeA2ATaskUpdated     = "a2a.task.updated"
	EventTypeA2AMessageSent     = "a2a.message.sent"

	// Gemini events (compatible with existing LLM event schema)
	EventTypeGeminiRequestStart = "llm.request.start"
	EventTypeGeminiTokenChunk   = "llm.token.chunk"
	EventTypeGeminiToolCall     = "llm.tool.call"
)

// Protocol constants.
const (
	ProtocolMCP    = "mcp"
	ProtocolA2A    = "a2a"
	ProtocolGemini = "gemini"
)

// ProtocolEvent is emitted to the Event Bus for protocol-specific observations.
// It carries common fields plus protocol-specific metadata.
type ProtocolEvent struct {
	eventbus.BaseEvent

	// ProtocolVersion is the protocol version (e.g., "2024-11-05" for MCP).
	ProtocolVersion string

	// Metadata contains protocol-specific key-value metadata.
	Metadata map[string]interface{}
}

// ProtocolEventPublisher wraps an EventBus to emit typed ProtocolEvents.
type ProtocolEventPublisher struct {
	bus eventbus.EventBus
}

// NewProtocolEventPublisher creates a new publisher wrapping the given EventBus.
func NewProtocolEventPublisher(bus eventbus.EventBus) *ProtocolEventPublisher {
	return &ProtocolEventPublisher{bus: bus}
}

// EmitParsedRequest emits an event for a parsed protocol request.
func (p *ProtocolEventPublisher) EmitParsedRequest(
	proto string, requestID string,
	agentID eventbus.AgentIdentity, parsed *ParsedRequest,
) {
	if parsed == nil {
		return
	}

	event := &ProtocolEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:      parsed.MessageType,
			Time:      time.Now(),
			ReqID:     requestID,
			Proto:     proto,
			Prov:      proto,
			AgentInfo: agentID,
		},
		Metadata: parsed.Metadata,
	}

	p.bus.Emit(event)
}

// EmitParsedResponse emits an event for a parsed protocol response.
func (p *ProtocolEventPublisher) EmitParsedResponse(
	proto string, requestID string,
	agentID eventbus.AgentIdentity, parsed *ParsedResponse,
) {
	if parsed == nil {
		return
	}

	event := &ProtocolEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:      parsed.MessageType,
			Time:      time.Now(),
			ReqID:     requestID,
			Proto:     proto,
			Prov:      proto,
			AgentInfo: agentID,
		},
		Metadata: parsed.Metadata,
	}

	p.bus.Emit(event)
}

// EmitParsedChunk emits an event for a parsed streaming chunk.
func (p *ProtocolEventPublisher) EmitParsedChunk(
	proto string, requestID string,
	agentID eventbus.AgentIdentity, parsed *ParsedChunk,
) {
	if parsed == nil {
		return
	}

	eventType := "protocol.chunk"
	if parsed.Metadata != nil {
		if et, ok := parsed.Metadata["event_type"].(string); ok {
			eventType = et
		}
	}

	event := &ProtocolEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:      eventType,
			Time:      time.Now(),
			ReqID:     requestID,
			Proto:     proto,
			Prov:      proto,
			AgentInfo: agentID,
		},
		Metadata: parsed.Metadata,
	}

	p.bus.Emit(event)
}
