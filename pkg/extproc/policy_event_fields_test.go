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
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
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
		"x-request-id", "req-tool-subcat-1",
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
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
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
		"x-request-id", "req-notool-subcat-1",
	}, body)

	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked")
	}
	if evaluator.lastEvent.Subcategory != "llm_request" {
		t.Errorf("expected Subcategory 'llm_request', got %q", evaluator.lastEvent.Subcategory)
	}
}

// TestPolicyEventFields_ToolNamePopulated verifies that Fields["toolName"]
// is populated from the first parsed tool name in the request body.
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
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
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
		"x-request-id", "req-toolname-1",
	}, body)

	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked")
	}

	// Fields["toolName"] should be the first tool name
	toolName := evaluator.lastEvent.GetStringField("toolName")
	if toolName != "dangerous_exec" {
		t.Errorf("expected Fields[toolName]='dangerous_exec', got %q", toolName)
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
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
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
		"x-request-id", "req-toolnames-1",
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
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
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
		"x-request-id", "req-model-1",
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
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
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
		"x-request-id", "req-header-1",
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
// returned during body-phase evaluation produces an ImmediateResponse with 403.
func TestPolicyEventFields_DenyAfterBodyParsing(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: &policy.Decision{
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
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
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
		"x-request-id", "req-deny-body-1",
	}, body)

	// Should receive an ImmediateResponse with 403 from the body phase
	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse for deny decision after body parsing")
	}
	if ir.Status.Code != 403 {
		t.Errorf("expected status 403, got %d", ir.Status.Code)
	}

	// Verify the evaluator received tool_call subcategory
	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked")
	}
	if evaluator.lastEvent.Subcategory != "tool_call" {
		t.Errorf("expected Subcategory 'tool_call', got %q", evaluator.lastEvent.Subcategory)
	}
	if evaluator.lastEvent.GetStringField("toolName") != "dangerous_exec" {
		t.Errorf("expected toolName 'dangerous_exec', got %q", evaluator.lastEvent.GetStringField("toolName"))
	}
}
