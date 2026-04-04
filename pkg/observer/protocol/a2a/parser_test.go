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

package a2a

import (
	"context"
	"testing"

	"github.com/panoptium/panoptium/pkg/observer/protocol"
)

var _ protocol.ProtocolParser = (*A2AParser)(nil)

// TestA2AParser_Detect_AgentCard verifies detection of Agent Card discovery path.
func TestA2AParser_Detect_AgentCard(t *testing.T) {
	parser := NewA2AParser()
	canDetect, confidence := parser.Detect(map[string]string{}, "/.well-known/agent-card.json", "GET")
	if !canDetect {
		t.Error("Detect() returned false for Agent Card path, want true")
	}
	if confidence < 0.9 {
		t.Errorf("Confidence = %f, want >= 0.9", confidence)
	}
}

// TestA2AParser_Detect_NonAgentCard verifies non-A2A paths are rejected.
func TestA2AParser_Detect_NonAgentCard(t *testing.T) {
	parser := NewA2AParser()
	canDetect, _ := parser.Detect(map[string]string{}, "/v1/chat/completions", "POST")
	if canDetect {
		t.Error("Detect() returned true for non-A2A path, want false")
	}
}

// TestA2AParser_ProcessResponse_AgentCard verifies parsing Agent Card JSON.
func TestA2AParser_ProcessResponse_AgentCard(t *testing.T) {
	parser := NewA2AParser()
	ctx := context.Background()

	body := []byte(`{
		"name": "WeatherAgent",
		"description": "An agent that provides weather information",
		"url": "https://weather.example.com/agent",
		"skills": [
			{
				"id": "get-weather",
				"name": "Get Weather",
				"description": "Returns current weather for a location"
			},
			{
				"id": "get-forecast",
				"name": "Get Forecast",
				"description": "Returns a multi-day forecast"
			}
		],
		"authentication": {
			"schemes": ["Bearer"]
		}
	}`)

	result, err := parser.ProcessResponse(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessResponse() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessResponse() returned nil")
	}
	if result.Protocol != "a2a" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "a2a")
	}
	if result.MessageType != "a2a.agent.discovered" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "a2a.agent.discovered")
	}
	if result.Metadata["agent_name"] != "WeatherAgent" {
		t.Errorf("agent_name = %v, want %q", result.Metadata["agent_name"], "WeatherAgent")
	}
	if result.Metadata["agent_url"] != "https://weather.example.com/agent" {
		t.Errorf("agent_url = %v, want URL", result.Metadata["agent_url"])
	}
	skills, ok := result.Metadata["skills"].([]Skill)
	if !ok {
		t.Fatalf("skills type = %T, want []Skill", result.Metadata["skills"])
	}
	if len(skills) != 2 {
		t.Fatalf("skills count = %d, want 2", len(skills))
	}
	if skills[0].ID != "get-weather" {
		t.Errorf("skills[0].ID = %q, want %q", skills[0].ID, "get-weather")
	}
	authSchemes, ok := result.Metadata["auth_schemes"].([]string)
	if !ok {
		t.Fatalf("auth_schemes type = %T, want []string", result.Metadata["auth_schemes"])
	}
	if len(authSchemes) != 1 || authSchemes[0] != "Bearer" {
		t.Errorf("auth_schemes = %v, want [Bearer]", authSchemes)
	}
}

// TestA2AParser_ProcessResponse_AgentCard_MalformedMissingFields verifies handling
// of malformed Agent Card (missing required fields falls through to JSON-RPC parsing).
func TestA2AParser_ProcessResponse_AgentCard_MalformedMissingFields(t *testing.T) {
	parser := NewA2AParser()
	ctx := context.Background()

	// Missing name and URL — should not be treated as Agent Card
	body := []byte(`{"description": "incomplete card"}`)
	result, err := parser.ProcessResponse(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessResponse() error = %v", err)
	}
	// Should fall through to generic response
	if result.MessageType == "a2a.agent.discovered" {
		t.Error("MessageType should not be a2a.agent.discovered for incomplete card")
	}
}

// TestA2AParser_ProcessRequest_TasksSend verifies parsing tasks/send request.
func TestA2AParser_ProcessRequest_TasksSend(t *testing.T) {
	parser := NewA2AParser()
	ctx := context.Background()

	body := []byte(`{
		"jsonrpc": "2.0",
		"method": "tasks/send",
		"id": "req-1",
		"params": {
			"id": "task-123",
			"description": "Get the weather in San Francisco",
			"skillId": "get-weather",
			"input": {
				"location": "San Francisco, CA"
			}
		}
	}`)

	result, err := parser.ProcessRequest(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}
	if result.MessageType != "a2a.task.created" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "a2a.task.created")
	}
	if result.Metadata["task_id"] != "task-123" {
		t.Errorf("task_id = %v, want %q", result.Metadata["task_id"], "task-123")
	}
	if result.Metadata["description"] != "Get the weather in San Francisco" {
		t.Errorf("description = %v, want expected text", result.Metadata["description"])
	}
	if result.Metadata["skill_id"] != "get-weather" {
		t.Errorf("skill_id = %v, want %q", result.Metadata["skill_id"], "get-weather")
	}
}

// TestA2AParser_ProcessRequest_TasksSendSubscribe verifies parsing tasks/sendSubscribe.
func TestA2AParser_ProcessRequest_TasksSendSubscribe(t *testing.T) {
	parser := NewA2AParser()
	ctx := context.Background()

	body := []byte(`{
		"jsonrpc": "2.0",
		"method": "tasks/sendSubscribe",
		"id": "req-2",
		"params": {
			"id": "task-456",
			"description": "Analyze the document",
			"skillId": "analyze"
		}
	}`)

	result, err := parser.ProcessRequest(ctx, map[string]string{}, body)
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}
	if result.MessageType != "a2a.task.created" {
		t.Errorf("MessageType = %q, want %q", result.MessageType, "a2a.task.created")
	}
	if result.Metadata["subscribe"] != true {
		t.Error("subscribe metadata should be true for sendSubscribe")
	}
}

// TestA2AParser_ProcessStreamChunk_TaskUpdate verifies SSE chunk parsing for task updates.
func TestA2AParser_ProcessStreamChunk_TaskUpdate(t *testing.T) {
	parser := NewA2AParser()
	ctx := context.Background()
	state := protocol.NewStreamState("a2a")

	chunk := []byte("data: {\"id\":\"task-123\",\"status\":\"completed\"}\n\n")
	result, err := parser.ProcessStreamChunk(ctx, chunk, state)
	if err != nil {
		t.Fatalf("ProcessStreamChunk() error = %v", err)
	}
	if result == nil {
		t.Fatal("ProcessStreamChunk() returned nil")
	}
	if result.Protocol != "a2a" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "a2a")
	}
	if result.Metadata["status"] != "completed" {
		t.Errorf("status = %v, want %q", result.Metadata["status"], "completed")
	}
	if result.Metadata["task_id"] != "task-123" {
		t.Errorf("task_id = %v, want %q", result.Metadata["task_id"], "task-123")
	}
}

// TestA2AParser_ProcessStreamChunk_Empty verifies handling of empty chunks.
func TestA2AParser_ProcessStreamChunk_Empty(t *testing.T) {
	parser := NewA2AParser()
	ctx := context.Background()
	state := protocol.NewStreamState("a2a")

	result, err := parser.ProcessStreamChunk(ctx, []byte{}, state)
	if err != nil {
		t.Fatalf("ProcessStreamChunk() error = %v", err)
	}
	if result != nil {
		t.Error("ProcessStreamChunk() should return nil for empty chunk")
	}
}

// TestA2AParser_ProcessRequest_EmptyBody verifies error on empty body.
func TestA2AParser_ProcessRequest_EmptyBody(t *testing.T) {
	parser := NewA2AParser()
	ctx := context.Background()

	_, err := parser.ProcessRequest(ctx, map[string]string{}, []byte{})
	if err == nil {
		t.Fatal("ProcessRequest() expected error for empty body, got nil")
	}
}

// TestA2AParser_ProcessRequest_MalformedJSON verifies error on malformed JSON.
func TestA2AParser_ProcessRequest_MalformedJSON(t *testing.T) {
	parser := NewA2AParser()
	ctx := context.Background()

	_, err := parser.ProcessRequest(ctx, map[string]string{}, []byte(`{invalid`))
	if err == nil {
		t.Fatal("ProcessRequest() expected error for malformed JSON, got nil")
	}
}
