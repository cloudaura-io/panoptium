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

package extproc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
	"github.com/panoptium/panoptium/pkg/policy"
)

// toolOnlyDenyEvaluator denies tool_call events but allows llm_request events.
// This is needed because FR-2 dual emission evaluates llm_request first.
type toolOnlyDenyEvaluator struct {
	denyDecision   *policy.Decision
	lastToolEvent  *policy.PolicyEvent
	lastEvent      *policy.PolicyEvent
}

func (m *toolOnlyDenyEvaluator) Evaluate(event *policy.PolicyEvent) (*policy.Decision, error) {
	m.lastEvent = event
	if event.Subcategory == "tool_call" {
		m.lastToolEvent = event
		return m.denyDecision, nil
	}
	return policy.DefaultAllowDecision(), nil
}

func (m *toolOnlyDenyEvaluator) EvaluateAll(event *policy.PolicyEvent) (*policy.EvaluationResult, error) {
	d, err := m.Evaluate(event)
	if err != nil {
		return nil, err
	}
	result := &policy.EvaluationResult{}
	if d != nil && d.Matched {
		result.Decisions = []*policy.Decision{d}
	} else {
		result.DefaultAllow = true
	}
	return result, nil
}

// setupPolicyEventFieldsTest creates test infrastructure for policy event field tests.
func setupPolicyEventFieldsTest(t *testing.T, evaluator PolicyEvaluator) (*eventbus.SimpleBus, *identity.PodCache, *ExtProcServer) {
	t.Helper()

	bus := eventbus.NewSimpleBus()
	registry := observer.NewObserverRegistry()

	llmObs := llm.NewLLMObserver(bus)
	if err := registry.Register(llmObs, observer.ObserverConfig{
		Name:      "llm",
		Priority:  100,
		Protocol:  eventbus.ProtocolLLM,
		Providers: []string{eventbus.ProviderOpenAI, eventbus.ProviderAnthropic},
	}); err != nil {
		t.Fatalf("failed to register LLM observer: %v", err)
	}

	podCache := identity.NewPodCache()
	resolver := identity.NewResolver(podCache)

	srv := NewExtProcServer(registry, resolver, bus)
	srv.SetEnforcementMode(enforce.ModeEnforcing)
	if evaluator != nil {
		srv.SetPolicyEvaluator(evaluator)
	}

	return bus, podCache, srv
}

// makeOpenAIRequestBodyWithTools creates a JSON request body for an OpenAI chat completion
// with tool definitions in the request body.
func makeOpenAIRequestBodyWithTools(model string, stream bool, toolNames []string) []byte {
	tools := make([]map[string]interface{}, len(toolNames))
	for i, name := range toolNames {
		tools[i] = map[string]interface{}{
			"type": "function",
			"function": map[string]interface{}{
				"name":        name,
				"description": "Test tool " + name,
				"parameters": map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
		}
	}

	body := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": "Use the tool"},
		},
		"stream": stream,
		"tools":  tools,
	}
	data, _ := json.Marshal(body)
	return data
}

// sendHeadersAndBody sends request headers and a complete body to the ExtProc stream,
// receiving the response for each. Returns the body-phase response.
func sendHeadersAndBody(t *testing.T, stream extprocv3.ExternalProcessor_ProcessClient, headerKVs []string, body []byte) *extprocv3.ProcessingResponse {
	t.Helper()

	// Send request headers
	err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(headerKVs...),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	// Receive headers response
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive headers response: %v", err)
	}

	// Send request body (end_of_stream = true)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        body,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}

	// Receive body response
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive body response: %v", err)
	}

	return resp
}

// TestPolicyEventFields_ToolCallSubcategory verifies that when the request body
// contains tool definitions, the PolicyEvent Subcategory is set to "tool_call"
// (not "llm_request").
func TestPolicyEventFields_ToolCallSubcategory(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEventFieldsTest(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.100", identity.PodInfo{
		Name:      "tool-pod",
		Namespace: "default",
		UID:       "uid-tool-1",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"dangerous_exec", "read_file"})

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.100",
	}, body)

	// Verify the evaluator was called with tool_call subcategory
	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked")
	}
	if evaluator.lastEvent.Subcategory != "tool_call" {
		t.Errorf("expected Subcategory 'tool_call', got %q", evaluator.lastEvent.Subcategory)
	}
	if evaluator.lastEvent.Category != "protocol" {
		t.Errorf("expected Category 'protocol', got %q", evaluator.lastEvent.Category)
	}
}

// TestPolicyEventFields_LLMRequestSubcategory verifies that when the request body
// does NOT contain tool definitions, the PolicyEvent Subcategory is "llm_request".
func TestPolicyEventFields_LLMRequestSubcategory(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEventFieldsTest(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.101", identity.PodInfo{
		Name:      "notool-pod",
		Namespace: "default",
		UID:       "uid-notool-1",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBody("gpt-4", false) // no tools

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.101",
	}, body)

	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked")
	}
	if evaluator.lastEvent.Subcategory != "llm_request" {
		t.Errorf("expected Subcategory 'llm_request', got %q", evaluator.lastEvent.Subcategory)
	}
}

// TestPolicyEventFields_ToolNamePopulated verifies that Fields["toolName"]
// is populated per-tool — one PolicyEvent per declared tool, each with the
// individual tool name.
func TestPolicyEventFields_ToolNamePopulated(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEventFieldsTest(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.102", identity.PodInfo{
		Name:      "toolname-pod",
		Namespace: "default",
		UID:       "uid-toolname-1",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"dangerous_exec", "read_file"})

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.102",
	}, body)

	// FR-2 dual emission: 1 llm_request + 2 tool_call events = 3 total
	if len(evaluator.allEvents) != 3 {
		t.Fatalf("expected 3 PolicyEvents (1 llm_request + 2 tool_call), got %d", len(evaluator.allEvents))
	}

	// First event should be llm_request (FR-2)
	if evaluator.allEvents[0].Subcategory != "llm_request" {
		t.Errorf("expected first event Subcategory='llm_request', got %q", evaluator.allEvents[0].Subcategory)
	}

	// Second event should have toolName = "dangerous_exec"
	toolName := evaluator.allEvents[1].GetStringField("toolName")
	if toolName != "dangerous_exec" {
		t.Errorf("expected second event Fields[toolName]='dangerous_exec', got %q", toolName)
	}

	// Third event should have toolName = "read_file"
	toolName = evaluator.allEvents[2].GetStringField("toolName")
	if toolName != "read_file" {
		t.Errorf("expected third event Fields[toolName]='read_file', got %q", toolName)
	}
}

// TestPolicyEventFields_ToolNamesPopulated verifies that Fields["toolNames"]
// contains all parsed tool names from the request body.
func TestPolicyEventFields_ToolNamesPopulated(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEventFieldsTest(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.103", identity.PodInfo{
		Name:      "toolnames-pod",
		Namespace: "default",
		UID:       "uid-toolnames-1",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"dangerous_exec", "read_file", "write_file"})

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.103",
	}, body)

	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked")
	}

	// Fields["toolNames"] should contain all tool names as a comma-separated string
	toolNames := evaluator.lastEvent.GetStringField("toolNames")
	if !strings.Contains(toolNames, "dangerous_exec") {
		t.Errorf("expected toolNames to contain 'dangerous_exec', got %q", toolNames)
	}
	if !strings.Contains(toolNames, "read_file") {
		t.Errorf("expected toolNames to contain 'read_file', got %q", toolNames)
	}
	if !strings.Contains(toolNames, "write_file") {
		t.Errorf("expected toolNames to contain 'write_file', got %q", toolNames)
	}
}

// TestPolicyEventFields_ModelAndProvider verifies that Fields["model"] and
// Fields["provider"] are populated from the parsed request body.
func TestPolicyEventFields_ModelAndProvider(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEventFieldsTest(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.104", identity.PodInfo{
		Name:      "model-pod",
		Namespace: "default",
		UID:       "uid-model-1",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBody("gpt-4-turbo", false)

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.104",
	}, body)

	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked")
	}

	model := evaluator.lastEvent.GetStringField("model")
	if model != "gpt-4-turbo" {
		t.Errorf("expected Fields[model]='gpt-4-turbo', got %q", model)
	}

	provider := evaluator.lastEvent.GetStringField("provider")
	if provider != "openai" {
		t.Errorf("expected Fields[provider]='openai', got %q", provider)
	}
}

// TestPolicyEventFields_HeaderNotUsedForToolName verifies that the
// x-panoptium-tool-name header is NOT used to populate PolicyEvent fields.
// Tool names must come from trusted body parsing only.
func TestPolicyEventFields_HeaderNotUsedForToolName(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEventFieldsTest(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.105", identity.PodInfo{
		Name:      "header-pod",
		Namespace: "default",
		UID:       "uid-header-1",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Body has no tools, but header claims a tool name
	body := makeOpenAIRequestBody("gpt-4", false)

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.105",

		"x-panoptium-tool-name", "spoofed_tool",
	}, body)

	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked")
	}

	// Subcategory should be llm_request (no tools in body), not tool_call
	if evaluator.lastEvent.Subcategory != "llm_request" {
		t.Errorf("expected Subcategory 'llm_request' (header should be ignored), got %q", evaluator.lastEvent.Subcategory)
	}

	// Fields["toolName"] should be empty (not from header)
	toolName := evaluator.lastEvent.GetStringField("toolName")
	if toolName != "" {
		t.Errorf("expected empty toolName (header should not be used), got %q", toolName)
	}
}

// TestPolicyEventFields_DenyAfterBodyParsing verifies that a deny decision
// for a tool_call subcategory during body-phase evaluation strips the tool
// from the request body rather than blocking the entire request. When ALL
// tools are denied, the tools and tool_choice keys are removed.
func TestPolicyEventFields_DenyAfterBodyParsing(t *testing.T) {
	// Use a tool-only deny evaluator: denies tool_call events, allows llm_request.
	// With FR-2 dual emission, llm_request is evaluated first and must allow.
	evaluator := &toolOnlyDenyEvaluator{
		denyDecision: &policy.Decision{
			Action: policy.CompiledAction{
				Type: "deny",
				Parameters: map[string]string{
					"message":   "tool blocked",
					"signature": "PAN-SIG-0099",
				},
			},
			Matched:          true,
			MatchedRule:      "block-dangerous-tools",
			MatchedRuleIndex: 0,
			PolicyName:       "security-policy",
			PolicyNamespace:  "production",
		},
	}
	bus, podCache, srv := setupPolicyEventFieldsTest(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.106", identity.PodInfo{
		Name:      "deny-body-pod",
		Namespace: "production",
		UID:       "uid-deny-body-1",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"dangerous_exec"})

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.106",
	}, body)

	// Tool deny now strips instead of 403 — request should pass through
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through with tool stripping, got ImmediateResponse")
	}

	// Verify the forwarded body has the tool stripped (all tools denied
	// means tools key is removed entirely)
	bodyResp := resp.GetRequestBody()
	if bodyResp == nil {
		t.Fatal("expected RequestBody response")
	}
	streamedResp := bodyResp.GetResponse().GetBodyMutation().GetStreamedResponse()
	if streamedResp == nil {
		t.Fatal("expected StreamedResponse in body mutation")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(streamedResp.Body, &parsed); err != nil {
		t.Fatalf("forwarded body is not valid JSON: %v", err)
	}

	// All tools denied → tools key should be removed
	if _, exists := parsed["tools"]; exists {
		t.Error("expected 'tools' key to be removed when all tools are denied")
	}

	// Verify the evaluator received tool_call subcategory
	if evaluator.lastToolEvent == nil {
		t.Fatal("policy evaluator was not invoked for tool_call")
	}
	if evaluator.lastToolEvent.Subcategory != "tool_call" {
		t.Errorf("expected Subcategory 'tool_call', got %q", evaluator.lastToolEvent.Subcategory)
	}
	if evaluator.lastToolEvent.GetStringField("toolName") != "dangerous_exec" {
		t.Errorf("expected toolName 'dangerous_exec', got %q", evaluator.lastToolEvent.GetStringField("toolName"))
	}
}
