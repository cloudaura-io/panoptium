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
	"testing"
	"time"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
	"github.com/panoptium/panoptium/pkg/policy"
)

// perToolMockEvaluator records all PolicyEvents it receives and returns
// tool-specific decisions based on a configured deny list.
type perToolMockEvaluator struct {
	// denyTools is the set of tool names that should produce a deny decision.
	denyTools map[string]bool

	// events records all PolicyEvents received.
	events []*policy.PolicyEvent

	// auditOnly controls whether deny decisions have AuditOnly set.
	auditOnly bool
}

func (m *perToolMockEvaluator) Evaluate(event *policy.PolicyEvent) (*policy.Decision, error) {
	m.events = append(m.events, event)

	toolName := event.GetStringField("toolName")
	if toolName != "" && m.denyTools[toolName] {
		return &policy.Decision{
			Action: policy.CompiledAction{
				Type:       v1alpha1.ActionTypeDeny,
				Parameters: map[string]string{"message": "tool " + toolName + " denied"},
			},
			Matched:          true,
			AuditOnly:        m.auditOnly,
			MatchedRule:      "deny-" + toolName,
			MatchedRuleIndex: 0,
			PolicyName:       "tool-policy",
			PolicyNamespace:  "default",
		}, nil
	}

	return policy.DefaultAllowDecision(), nil
}

func (m *perToolMockEvaluator) EvaluateAll(event *policy.PolicyEvent) (*policy.EvaluationResult, error) {
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

const subcategoryLLMRequest = "llm_request"

// setupPerToolTestComponents creates test infrastructure with a perToolMockEvaluator.
func setupPerToolTestComponents(
	t *testing.T, evaluator PolicyEvaluator,
) (*eventbus.SimpleBus, *identity.PodCache, *ExtProcServer) {
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

// TestPerToolEval_FiresOneEventPerTool verifies that evaluateRequestPolicy
// fires one PolicyEvent per declared tool (not one for all tools together).
func TestPerToolEval_FiresOneEventPerTool(t *testing.T) {
	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{},
	}
	bus, podCache, srv := setupPerToolTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.200", identity.PodInfo{
		Name:      "per-tool-pod",
		Namespace: "default",
		UID:       "uid-pt-1",
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

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file", "write_file"})

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.200",
	}, body)

	// FR-2: 1 llm_request + 3 tool_call events = 4 total
	if len(evaluator.events) != 4 {
		t.Fatalf("expected 4 PolicyEvents (1 llm_request + 3 tool_call), got %d", len(evaluator.events))
	}

	// First event is llm_request
	if evaluator.events[0].Subcategory != subcategoryLLMRequest {
		t.Errorf("expected first event Subcategory=%q, got %q", subcategoryLLMRequest, evaluator.events[0].Subcategory)
	}

	// Remaining 3 events should have a different toolName each
	seenTools := make(map[string]bool)
	for _, evt := range evaluator.events[1:] {
		toolName := evt.GetStringField("toolName")
		if toolName == "" {
			t.Error("expected non-empty toolName in PolicyEvent")
		}
		seenTools[toolName] = true
	}
	if !seenTools["bash"] {
		t.Error("expected PolicyEvent for tool 'bash'")
	}
	if !seenTools["read_file"] {
		t.Error("expected PolicyEvent for tool 'read_file'")
	}
	if !seenTools["write_file"] {
		t.Error("expected PolicyEvent for tool 'write_file'")
	}
}

// TestPerToolEval_DenyOneToolStripsIt verifies that denying one tool strips it
// from the request body but leaves other tools untouched.
func TestPerToolEval_DenyOneToolStripsIt(t *testing.T) {
	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{"bash": true},
	}
	bus, podCache, srv := setupPerToolTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.201", identity.PodInfo{
		Name:      "strip-one-pod",
		Namespace: "default",
		UID:       "uid-pt-2",
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

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file", "write_file"})

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.201",
	}, body)

	// Should NOT be a 403 — only the tool is stripped, request continues
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through with tool stripping, got ImmediateResponse")
	}

	// Verify the forwarded body has tools stripped
	bodyResp := resp.GetRequestBody()
	if bodyResp == nil {
		t.Fatal("expected RequestBody response")
	}
	mutation := bodyResp.GetResponse().GetBodyMutation()
	if mutation == nil {
		t.Fatal("expected body mutation in response")
	}
	streamedResp := mutation.GetStreamedResponse()
	if streamedResp == nil {
		t.Fatal("expected StreamedResponse in body mutation")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(streamedResp.Body, &parsed); err != nil {
		t.Fatalf("forwarded body is not valid JSON: %v", err)
	}

	tools, ok := parsed["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array in forwarded body")
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools after stripping 'bash', got %d", len(tools))
	}

	names := extractToolNamesFromParsed(t, tools)
	if contains(names, "bash") {
		t.Error("expected 'bash' to be stripped from forwarded body")
	}
	if !contains(names, "read_file") || !contains(names, "write_file") {
		t.Error("expected 'read_file' and 'write_file' to be preserved")
	}
}

// TestPerToolEval_DenyAllToolsRemovesToolsAndToolChoice verifies that when
// all tools are denied, the tools[] and tool_choice keys are removed entirely.
func TestPerToolEval_DenyAllToolsRemovesToolsAndToolChoice(t *testing.T) {
	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{"bash": true, "read_file": true},
	}
	bus, podCache, srv := setupPerToolTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.202", identity.PodInfo{
		Name:      "strip-all-pod",
		Namespace: "default",
		UID:       "uid-pt-3",
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

	body := makeOpenAIRequestBodyWithToolsAndChoice("gpt-4", false,
		[]string{"bash", "read_file"}, "auto")

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.202",
	}, body)

	// Should NOT be a 403 — request continues as plain chat
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through (plain chat), got ImmediateResponse")
	}

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

	if _, exists := parsed["tools"]; exists {
		t.Error("expected 'tools' key to be removed when all tools are denied")
	}
	if _, exists := parsed["tool_choice"]; exists {
		t.Error("expected 'tool_choice' key to be removed when all tools are denied")
	}

	// model and messages should still be present
	if parsed["model"] != testModelGPT4 {
		t.Errorf("expected model %q, got %v", testModelGPT4, parsed["model"])
	}
}

// TestPerToolEval_NoDenyLeavesBodyUnmodified verifies that when no tools are
// denied, the request body is forwarded as-is.
func TestPerToolEval_NoDenyLeavesBodyUnmodified(t *testing.T) {
	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{}, // nothing denied
	}
	bus, podCache, srv := setupPerToolTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.203", identity.PodInfo{
		Name:      "no-deny-pod",
		Namespace: "default",
		UID:       "uid-pt-4",
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

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file", "write_file"})

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.203",
	}, body)

	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through, got ImmediateResponse")
	}

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

	tools, ok := parsed["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array in forwarded body")
	}
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools (unchanged), got %d", len(tools))
	}
}

// TestPerToolEval_AuditModeDenyDoesNotStrip verifies that when a tool is
// denied in audit-only mode, it is NOT stripped from the request body.
func TestPerToolEval_AuditModeDenyDoesNotStrip(t *testing.T) {
	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{"bash": true},
		auditOnly: true,
	}
	bus, podCache, srv := setupPerToolTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.204", identity.PodInfo{
		Name:      "audit-strip-pod",
		Namespace: "default",
		UID:       "uid-pt-5",
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

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file", "write_file"})

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.204",
	}, body)

	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through in audit mode, got ImmediateResponse")
	}

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

	tools, ok := parsed["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array in forwarded body")
	}
	// All 3 tools should be preserved — audit mode does NOT strip
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools (audit mode should NOT strip), got %d", len(tools))
	}
}
