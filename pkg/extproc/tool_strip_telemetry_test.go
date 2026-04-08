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

// setupTelemetryTestComponents creates test infrastructure for telemetry tests.
func setupTelemetryTestComponents(
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

// TestToolStripEvent_EmittedOnStrip verifies that stripping a tool emits a
// ToolStrippedEvent to the event bus with the correct fields.
func TestToolStripEvent_EmittedOnStrip(t *testing.T) {
	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{"bash": true},
	}
	bus, podCache, srv := setupTelemetryTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.210", identity.PodInfo{
		Name:      "telemetry-pod",
		Namespace: "production",
		UID:       "uid-telem-1",
		Labels:    map[string]string{"app": "agent"},
	})

	// Subscribe to tool stripped events
	sub := bus.Subscribe(eventbus.EventTypeToolStripped)
	defer bus.Unsubscribe(sub)

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file"})

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.210",
	}, body)

	// Should receive a ToolStrippedEvent
	select {
	case evt := <-sub.Events():
		stripped, ok := evt.(*eventbus.ToolStrippedEvent)
		if !ok {
			t.Fatalf("expected ToolStrippedEvent, got %T", evt)
		}
		if stripped.ToolName != "bash" {
			t.Errorf("expected ToolName 'bash', got %q", stripped.ToolName)
		}
		if stripped.PolicyName != "tool-policy" {
			t.Errorf("expected PolicyName 'tool-policy', got %q", stripped.PolicyName)
		}
		if stripped.RuleName != "deny-bash" {
			t.Errorf("expected RuleName 'deny-bash', got %q", stripped.RuleName)
		}
		if stripped.Identity().Namespace != "production" {
			t.Errorf("expected Namespace 'production', got %q", stripped.Identity().Namespace)
		}
		if stripped.Identity().PodName != "telemetry-pod" {
			t.Errorf("expected PodName 'telemetry-pod', got %q", stripped.Identity().PodName)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ToolStrippedEvent")
	}
}

// TestToolStripEvent_MultipleToolsEmitMultipleEvents verifies that stripping
// multiple tools emits one ToolStrippedEvent per tool.
func TestToolStripEvent_MultipleToolsEmitMultipleEvents(t *testing.T) {
	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{"bash": true, "k8s_get_pod_logs": true},
	}
	bus, podCache, srv := setupTelemetryTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.211", identity.PodInfo{
		Name:      "multi-strip-pod",
		Namespace: "default",
		UID:       "uid-telem-2",
		Labels:    map[string]string{"app": "agent"},
	})

	sub := bus.Subscribe(eventbus.EventTypeToolStripped)
	defer bus.Unsubscribe(sub)

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file", "k8s_get_pod_logs"})

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.211",
	}, body)

	// Should receive 2 ToolStrippedEvents
	strippedTools := make(map[string]bool)
	for i := 0; i < 2; i++ {
		select {
		case evt := <-sub.Events():
			stripped, ok := evt.(*eventbus.ToolStrippedEvent)
			if !ok {
				t.Fatalf("expected ToolStrippedEvent, got %T", evt)
			}
			strippedTools[stripped.ToolName] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for ToolStrippedEvent %d/2", i+1)
		}
	}

	if !strippedTools["bash"] {
		t.Error("expected ToolStrippedEvent for 'bash'")
	}
	if !strippedTools["k8s_get_pod_logs"] {
		t.Error("expected ToolStrippedEvent for 'k8s_get_pod_logs'")
	}
}

// TestToolStripEvent_FieldsComplete verifies that all required fields are
// present in the ToolStrippedEvent.
func TestToolStripEvent_FieldsComplete(t *testing.T) {
	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{"dangerous_tool": true},
	}
	bus, podCache, srv := setupTelemetryTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.212", identity.PodInfo{
		Name:      "fields-pod",
		Namespace: "staging",
		UID:       "uid-telem-3",
		Labels:    map[string]string{"app": "agent"},
	})

	sub := bus.Subscribe(eventbus.EventTypeToolStripped)
	defer bus.Unsubscribe(sub)

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"dangerous_tool", "safe_tool"})

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.212",
	}, body)

	select {
	case evt := <-sub.Events():
		stripped, ok := evt.(*eventbus.ToolStrippedEvent)
		if !ok {
			t.Fatalf("expected ToolStrippedEvent, got %T", evt)
		}

		// Required fields per FR-3
		if stripped.ToolName == "" {
			t.Error("ToolName must not be empty")
		}
		if stripped.PolicyName == "" {
			t.Error("PolicyName must not be empty")
		}
		if stripped.RuleName == "" {
			t.Error("RuleName must not be empty")
		}
		if stripped.RequestID() == "" {
			t.Error("RequestID must not be empty")
		}
		if stripped.Timestamp().IsZero() {
			t.Error("Timestamp must not be zero")
		}
		if stripped.EventType() != eventbus.EventTypeToolStripped {
			t.Errorf("expected EventType %q, got %q", eventbus.EventTypeToolStripped, stripped.EventType())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ToolStrippedEvent")
	}
}

// TestToolStripMetric_IncrementedOnStrip verifies that the
// panoptium_tools_stripped_total counter increments when a tool is stripped.
func TestToolStripMetric_IncrementedOnStrip(t *testing.T) {
	// Reset the metric
	toolsStrippedTotal.Reset()

	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{"bash": true},
	}
	bus, podCache, srv := setupTelemetryTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.213", identity.PodInfo{
		Name:      "metric-pod",
		Namespace: "production",
		UID:       "uid-metric-1",
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

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file"})

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.213",
	}, body)

	counter, err := toolsStrippedTotal.GetMetricWithLabelValues("bash", "tool-policy", "production", "metric-pod")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues error: %v", err)
	}
	if got := getCounterValue(t, counter); got != 1 {
		t.Errorf("expected tools_stripped_total=1 for bash, got %f", got)
	}
}

// TestToolStripMetric_LabelsCorrect verifies that the metric labels include
// tool, policy, agent_namespace, and agent_pod.
func TestToolStripMetric_LabelsCorrect(t *testing.T) {
	toolsStrippedTotal.Reset()

	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{"k8s_get_pod_logs": true, "bash": true},
	}
	bus, podCache, srv := setupTelemetryTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.214", identity.PodInfo{
		Name:      "label-pod",
		Namespace: "staging",
		UID:       "uid-metric-2",
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

	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"k8s_get_pod_logs", "bash", "read_file"})

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.214",
	}, body)

	// Verify counter for each stripped tool
	tests := []struct {
		tool      string
		policy    string
		namespace string
		pod       string
	}{
		{"k8s_get_pod_logs", "tool-policy", "staging", "label-pod"},
		{"bash", "tool-policy", "staging", "label-pod"},
	}

	for _, tt := range tests {
		counter, err := toolsStrippedTotal.GetMetricWithLabelValues(tt.tool, tt.policy, tt.namespace, tt.pod)
		if err != nil {
			t.Fatalf("GetMetricWithLabelValues(%s) error: %v", tt.tool, err)
		}
		if got := getCounterValue(t, counter); got != 1 {
			t.Errorf("expected tools_stripped_total=1 for %s, got %f", tt.tool, got)
		}
	}
}

// denyLLMRequestEvaluator returns deny for llm_request subcategory.
// Used to test that non-tool_call deny still produces 403.
type denyLLMRequestEvaluator struct {
	lastEvent *policy.PolicyEvent
}

func (m *denyLLMRequestEvaluator) Evaluate(event *policy.PolicyEvent) (*policy.Decision, error) {
	m.lastEvent = event
	if event.Subcategory == subcategoryLLMRequest {
		return &policy.Decision{
			Action: policy.CompiledAction{
				Type:       v1alpha1.ActionTypeDeny,
				Parameters: map[string]string{"message": "request blocked"},
			},
			Matched:          true,
			MatchedRule:      "block-all",
			MatchedRuleIndex: 0,
			PolicyName:       "block-policy",
			PolicyNamespace:  "default",
		}, nil
	}
	return policy.DefaultAllowDecision(), nil
}

func (m *denyLLMRequestEvaluator) EvaluateAll(event *policy.PolicyEvent) (*policy.EvaluationResult, error) {
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

// TestNonToolDeny_StillBlocks verifies that deny on llm_request subcategory
// (non-tool requests) still returns 403, not tool stripping.
func TestNonToolDeny_StillBlocks(t *testing.T) {
	evaluator := &denyLLMRequestEvaluator{}
	bus, podCache, srv := setupTelemetryTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.215", identity.PodInfo{
		Name:      "block-pod",
		Namespace: "default",
		UID:       "uid-block-1",
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

	// No tools — llm_request subcategory
	body := makeOpenAIRequestBody("gpt-4", false)

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.215",
	}, body)

	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse 403 for non-tool deny")
	}
	if ir.Status.Code != 403 {
		t.Errorf("expected 403, got %d", ir.Status.Code)
	}
}
