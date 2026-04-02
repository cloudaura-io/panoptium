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

// Package a2a implements the ProtocolParser interface for the Agent-to-Agent (A2A)
// protocol, parsing JSON-RPC 2.0 messages for agent card discovery, task delegation,
// and inter-agent communication.
package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/panoptium/panoptium/pkg/observer/protocol"
	"github.com/panoptium/panoptium/pkg/threat"
)

// AgentCard represents a parsed A2A Agent Card.
type AgentCard struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	URL            string   `json:"url"`
	Skills         []Skill  `json:"skills"`
	Authentication *AuthInfo `json:"authentication,omitempty"`
}

// Skill represents a capability advertised in an Agent Card.
type Skill struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// AuthInfo represents authentication requirements from an Agent Card.
type AuthInfo struct {
	Schemes []string `json:"schemes"`
}

// TaskRequest represents a parsed A2A task request.
type TaskRequest struct {
	TaskID      string                 `json:"id,omitempty"`
	Description string                 `json:"description,omitempty"`
	SkillID     string                 `json:"skillId,omitempty"`
	Input       map[string]interface{} `json:"input,omitempty"`
}

// A2AParser implements protocol.ProtocolParser for A2A JSON-RPC 2.0 messages.
type A2AParser struct {
	mu            sync.RWMutex
	pendingIDs    map[string]string // JSON-RPC id -> method name
	threatMatcher threat.ThreatMatcher
}

// NewA2AParser creates a new A2A parser.
func NewA2AParser() *A2AParser {
	return &A2AParser{
		pendingIDs: make(map[string]string),
	}
}

// SetThreatMatcher sets the CRD-driven ThreatMatcher for threat detection.
func (p *A2AParser) SetThreatMatcher(matcher threat.ThreatMatcher) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.threatMatcher = matcher
}

// Name returns the parser name.
func (p *A2AParser) Name() string {
	return "a2a"
}

// Detect checks if the request matches A2A patterns.
func (p *A2AParser) Detect(headers map[string]string, path string, method string) (bool, float32) {
	// Agent Card discovery endpoint
	if strings.HasSuffix(path, "/.well-known/agent-card.json") && method == "GET" {
		return true, 0.9
	}
	return false, 0
}

// jsonrpcMessage is the internal JSON-RPC 2.0 message structure.
type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonrpcError   `json:"error"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

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

// ProcessRequest parses an A2A request.
func (p *A2AParser) ProcessRequest(ctx context.Context, headers map[string]string, body []byte) (*protocol.ParsedRequest, error) {
	if len(body) == 0 {
		return nil, errors.New("empty request body")
	}

	var msg jsonrpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC: %w", err)
	}

	id := idToString(msg.ID)
	if id != "" && msg.Method != "" {
		p.mu.Lock()
		p.pendingIDs[id] = msg.Method
		p.mu.Unlock()
	}

	result := &protocol.ParsedRequest{
		Protocol: "a2a",
		Method:   msg.Method,
		Metadata: make(map[string]interface{}),
	}

	switch msg.Method {
	case "tasks/send", "tasks/sendSubscribe":
		result.MessageType = "a2a.task.created"
		if msg.Params != nil {
			var taskReq TaskRequest
			if err := json.Unmarshal(msg.Params, &taskReq); err == nil {
				result.Metadata["task_id"] = taskReq.TaskID
				result.Metadata["description"] = taskReq.Description
				result.Metadata["skill_id"] = taskReq.SkillID
				result.Metadata["input"] = taskReq.Input
			}
		}
		if msg.Method == "tasks/sendSubscribe" {
			result.Metadata["subscribe"] = true
		}

	case "tasks/get":
		result.MessageType = "a2a.task.get"

	default:
		result.MessageType = "a2a.unknown"
	}

	result.Metadata["jsonrpc_id"] = id

	// Evaluate ThreatMatcher if set
	p.mu.RLock()
	matcher := p.threatMatcher
	p.mu.RUnlock()

	if matcher != nil {
		// Build content from task description for threat evaluation
		var content string
		if desc, ok := result.Metadata["description"].(string); ok {
			content = desc
		}
		if content != "" {
			matches, err := matcher.Match(ctx, threat.MatchInput{
				Protocol: "a2a",
				Target:   "message_content",
				Content:  content,
				Metadata: map[string]any{"method": msg.Method},
			})
			if err == nil && len(matches) > 0 {
				result.Metadata["threat_matches"] = matches
			}
		}
	}

	return result, nil
}

// ProcessResponse parses an A2A response.
// For Agent Card responses (non-JSON-RPC), it parses the card directly.
func (p *A2AParser) ProcessResponse(_ context.Context, headers map[string]string, body []byte) (*protocol.ParsedResponse, error) {
	if len(body) == 0 {
		return nil, errors.New("empty response body")
	}

	// Try to parse as Agent Card (plain JSON, not JSON-RPC)
	var card AgentCard
	if err := json.Unmarshal(body, &card); err == nil && card.Name != "" && card.URL != "" {
		result := &protocol.ParsedResponse{
			Protocol:    "a2a",
			MessageType: "a2a.agent.discovered",
			Metadata: map[string]interface{}{
				"agent_name":   card.Name,
				"agent_url":    card.URL,
				"description":  card.Description,
				"skills":       card.Skills,
			},
		}
		if card.Authentication != nil {
			result.Metadata["auth_schemes"] = card.Authentication.Schemes
		}
		return result, nil
	}

	// Try JSON-RPC response
	var msg jsonrpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid response: %w", err)
	}

	id := idToString(msg.ID)
	p.mu.Lock()
	method, found := p.pendingIDs[id]
	if found {
		delete(p.pendingIDs, id)
	}
	p.mu.Unlock()

	result := &protocol.ParsedResponse{
		Protocol: "a2a",
		Method:   method,
		Metadata: map[string]interface{}{"jsonrpc_id": id},
	}

	if msg.Error != nil {
		result.MessageType = "a2a.error"
		return result, nil
	}

	switch method {
	case "tasks/send", "tasks/sendSubscribe":
		result.MessageType = "a2a.task.updated"
	default:
		result.MessageType = "a2a.response"
	}

	return result, nil
}

// ProcessStreamChunk parses an SSE chunk from tasks/sendSubscribe responses.
func (p *A2AParser) ProcessStreamChunk(_ context.Context, chunk []byte, state *protocol.StreamState) (*protocol.ParsedChunk, error) {
	if len(chunk) == 0 {
		return nil, nil
	}

	result := &protocol.ParsedChunk{
		Protocol: "a2a",
		Metadata: make(map[string]interface{}),
	}

	// Parse SSE format: "data: <json>\n\n"
	lines := bytes.Split(chunk, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data: ")) {
			continue
		}
		payload := bytes.TrimPrefix(line, []byte("data: "))

		// Try to parse as task update
		var update map[string]interface{}
		if err := json.Unmarshal(payload, &update); err == nil {
			if status, ok := update["status"].(string); ok {
				result.Metadata["status"] = status
			}
			if taskID, ok := update["id"].(string); ok {
				result.Metadata["task_id"] = taskID
			}
			result.Content = string(payload)
		}
	}

	if result.Content != "" {
		result.Metadata["event_type"] = "a2a.task.updated"
	}

	return result, nil
}
