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
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// TestProtocolEventPublisher_EmitParsedRequest_MCP verifies MCP event emission.
func TestProtocolEventPublisher_EmitParsedRequest_MCP(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(EventTypeMCPToolCall)
	publisher := NewProtocolEventPublisher(bus)

	agentID := eventbus.AgentIdentity{
		ID:        "agent-1",
		PodName:   "test-pod",
		Namespace: "default",
	}

	parsed := &ParsedRequest{
		Protocol:    "mcp",
		MessageType: EventTypeMCPToolCall,
		Method:      "tools/call",
		Metadata: map[string]interface{}{
			"tool_name": "read_file",
			"tool_arguments": map[string]interface{}{
				"path": "/etc/passwd",
			},
		},
	}

	publisher.EmitParsedRequest("mcp", "req-1", agentID, parsed)

	select {
	case event := <-sub.Events():
		if event.EventType() != EventTypeMCPToolCall {
			t.Errorf("EventType = %q, want %q", event.EventType(), EventTypeMCPToolCall)
		}
		if event.Protocol() != "mcp" {
			t.Errorf("Protocol = %q, want %q", event.Protocol(), "mcp")
		}
		if event.RequestID() != "req-1" {
			t.Errorf("RequestID = %q, want %q", event.RequestID(), "req-1")
		}
		pe, ok := event.(*ProtocolEvent)
		if !ok {
			t.Fatalf("event type = %T, want *ProtocolEvent", event)
		}
		if pe.Metadata["tool_name"] != "read_file" {
			t.Errorf("tool_name = %v, want %q", pe.Metadata["tool_name"], "read_file")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for MCP event")
	}
}

// TestProtocolEventPublisher_EmitParsedResponse_A2A verifies A2A event emission.
func TestProtocolEventPublisher_EmitParsedResponse_A2A(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(EventTypeA2AAgentDiscovered)
	publisher := NewProtocolEventPublisher(bus)

	parsed := &ParsedResponse{
		Protocol:    "a2a",
		MessageType: EventTypeA2AAgentDiscovered,
		Metadata: map[string]interface{}{
			"agent_name": "WeatherAgent",
			"agent_url":  "https://weather.example.com/agent",
		},
	}

	publisher.EmitParsedResponse("a2a", "req-2", eventbus.AgentIdentity{}, parsed)

	select {
	case event := <-sub.Events():
		if event.EventType() != EventTypeA2AAgentDiscovered {
			t.Errorf("EventType = %q, want %q", event.EventType(), EventTypeA2AAgentDiscovered)
		}
		pe := event.(*ProtocolEvent)
		if pe.Metadata["agent_name"] != "WeatherAgent" {
			t.Errorf("agent_name = %v, want %q", pe.Metadata["agent_name"], "WeatherAgent")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for A2A event")
	}
}

// TestProtocolEventPublisher_EmitParsedRequest_Gemini verifies Gemini event emission
// compatible with existing LLM event schema.
func TestProtocolEventPublisher_EmitParsedRequest_Gemini(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(EventTypeGeminiRequestStart)
	publisher := NewProtocolEventPublisher(bus)

	parsed := &ParsedRequest{
		Protocol:    "gemini",
		MessageType: EventTypeGeminiRequestStart,
		Metadata: map[string]interface{}{
			"model":      "gemini-pro",
			"tool_names": []string{"get_weather"},
		},
	}

	publisher.EmitParsedRequest("gemini", "req-3", eventbus.AgentIdentity{}, parsed)

	select {
	case event := <-sub.Events():
		if event.EventType() != EventTypeGeminiRequestStart {
			t.Errorf("EventType = %q, want %q", event.EventType(), EventTypeGeminiRequestStart)
		}
		if event.Protocol() != "gemini" {
			t.Errorf("Protocol = %q, want %q", event.Protocol(), "gemini")
		}
		pe := event.(*ProtocolEvent)
		if pe.Metadata["model"] != "gemini-pro" {
			t.Errorf("model = %v, want %q", pe.Metadata["model"], "gemini-pro")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for Gemini event")
	}
}

// TestProtocolEventPublisher_CommonFields verifies common event fields are set.
func TestProtocolEventPublisher_CommonFields(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe()
	publisher := NewProtocolEventPublisher(bus)

	agentID := eventbus.AgentIdentity{
		ID:        "agent-1",
		PodName:   "test-pod",
		Namespace: "default",
		SourceIP:  "10.0.0.1",
	}

	parsed := &ParsedRequest{
		Protocol:    "mcp",
		MessageType: "mcp.session.init",
		Metadata:    map[string]interface{}{},
	}

	before := time.Now()
	publisher.EmitParsedRequest("mcp", "req-common", agentID, parsed)

	select {
	case event := <-sub.Events():
		if event.Timestamp().Before(before) {
			t.Error("event timestamp should be >= before")
		}
		if event.RequestID() != "req-common" {
			t.Errorf("RequestID = %q, want %q", event.RequestID(), "req-common")
		}
		if event.Identity().ID != "agent-1" {
			t.Errorf("Identity.ID = %q, want %q", event.Identity().ID, "agent-1")
		}
		if event.Identity().Namespace != "default" {
			t.Errorf("Identity.Namespace = %q, want %q", event.Identity().Namespace, "default")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}
}

// TestProtocolEventPublisher_NonBlocking verifies non-blocking emission (drop on full buffer).
func TestProtocolEventPublisher_NonBlocking(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	// Subscribe but don't read — buffer will fill up
	_ = bus.Subscribe(EventTypeMCPToolCall)

	publisher := NewProtocolEventPublisher(bus)
	parsed := &ParsedRequest{
		Protocol:    "mcp",
		MessageType: EventTypeMCPToolCall,
		Metadata:    map[string]interface{}{},
	}

	// Emit many events — should not block
	done := make(chan bool, 1)
	go func() {
		for i := 0; i < 1000; i++ {
			publisher.EmitParsedRequest("mcp", "req-overflow", eventbus.AgentIdentity{}, parsed)
		}
		done <- true
	}()

	select {
	case <-done:
		// Good — didn't block
	case <-time.After(1 * time.Second):
		t.Fatal("EmitParsedRequest blocked on full buffer — should be non-blocking")
	}
}

// TestProtocolEventPublisher_NilParsed verifies no panic on nil parsed data.
func TestProtocolEventPublisher_NilParsed(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	publisher := NewProtocolEventPublisher(bus)

	// These should not panic
	publisher.EmitParsedRequest("mcp", "req-nil", eventbus.AgentIdentity{}, nil)
	publisher.EmitParsedResponse("a2a", "req-nil", eventbus.AgentIdentity{}, nil)
	publisher.EmitParsedChunk("gemini", "req-nil", eventbus.AgentIdentity{}, nil)
}
