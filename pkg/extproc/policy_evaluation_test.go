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

// mockPolicyEvaluator is a test double that returns a configurable Decision.
type mockPolicyEvaluator struct {
	decision  *policy.Decision
	err       error
	lastEvent *policy.PolicyEvent
	allEvents []*policy.PolicyEvent
}

func (m *mockPolicyEvaluator) Evaluate(event *policy.PolicyEvent) (*policy.Decision, error) {
	m.lastEvent = event
	m.allEvents = append(m.allEvents, event)
	return m.decision, m.err
}

// setupPolicyEvalTestComponents creates test infrastructure with a mock PolicyEvaluator.
func setupPolicyEvalTestComponents(t *testing.T, evaluator PolicyEvaluator) (*eventbus.SimpleBus, *identity.PodCache, *ExtProcServer) {
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

// TestPolicyEvaluation_InvokedAfterObserverParsing verifies that the policy
// evaluator is invoked during request body processing (after body parsing),
// receiving a PolicyEvent built from the parsed request context and agent identity.
func TestPolicyEvaluation_InvokedAfterObserverParsing(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	// Register an enrolled pod
	podCache.Set("10.0.0.50", identity.PodInfo{
		Name:      "agent-pod-1",
		Namespace: "production",
		UID:       "uid-abc-123",
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

	body := makeOpenAIRequestBody("gpt-4", false)

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.50",
	}, body)

	// Verify the evaluator was called
	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked during request processing")
	}
}

// TestPolicyEvaluation_EventContextExtraction verifies that the PolicyEvent
// passed to the evaluator contains correct agent identity, destination path,
// model, provider, and protocol fields extracted from the request body parsing.
func TestPolicyEvaluation_EventContextExtraction(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.60", identity.PodInfo{
		Name:      "test-agent",
		Namespace: "staging",
		UID:       "uid-def-456",
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

	body := makeOpenAIRequestBody("gpt-4", false)

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.60",
	}, body)

	event := evaluator.lastEvent
	if event == nil {
		t.Fatal("policy evaluator was not invoked")
	}

	// Verify agent identity fields
	if event.PodName != "test-agent" {
		t.Errorf("expected PodName 'test-agent', got %q", event.PodName)
	}
	if event.Namespace != "staging" {
		t.Errorf("expected Namespace 'staging', got %q", event.Namespace)
	}
	if event.PodLabels["app"] != "agent" {
		t.Errorf("expected PodLabels[app]='agent', got %q", event.PodLabels["app"])
	}

	// Verify request context fields
	if event.GetStringField("path") != "/v1/chat/completions" {
		t.Errorf("expected path '/v1/chat/completions', got %q", event.GetStringField("path"))
	}
	if event.GetStringField("method") != "POST" {
		t.Errorf("expected method 'POST', got %q", event.GetStringField("method"))
	}
	if event.GetStringField("host") != "api.openai.com" {
		t.Errorf("expected host 'api.openai.com', got %q", event.GetStringField("host"))
	}

	// Verify body-derived fields
	if event.GetStringField("model") != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %q", event.GetStringField("model"))
	}
	if event.GetStringField("provider") != "openai" {
		t.Errorf("expected provider 'openai', got %q", event.GetStringField("provider"))
	}

	// Verify category and subcategory
	if event.Category != "protocol" {
		t.Errorf("expected Category 'protocol', got %q", event.Category)
	}
	if event.Subcategory != "llm_request" {
		t.Errorf("expected Subcategory 'llm_request', got %q", event.Subcategory)
	}
}

// TestPolicyEvaluation_PassThroughWhenNoMatch verifies that when the policy
// evaluator returns a default allow decision (no rule matched), traffic passes
// through with no mutations.
func TestPolicyEvaluation_PassThroughWhenNoMatch(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.70", identity.PodInfo{
		Name:      "pass-pod",
		Namespace: "default",
		UID:       "uid-pass-1",
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

	body := makeOpenAIRequestBody("gpt-4", false)

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.70",
	}, body)

	// Should be a pass-through (no ImmediateResponse)
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through, got ImmediateResponse")
	}
	// Body-phase response should be RequestBody, not RequestHeaders
	if resp.GetRequestBody() == nil {
		t.Fatal("expected RequestBody response for pass-through")
	}
}

// TestPolicyEvaluation_DenyDecision verifies that when the policy evaluator
// returns a deny decision after body parsing, the ExtProc server returns an
// ImmediateResponse with status 403 and a structured JSON error body.
func TestPolicyEvaluation_DenyDecision(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: &policy.Decision{
			Action: policy.CompiledAction{
				Type: v1alpha1.ActionTypeDeny,
				Parameters: map[string]string{
					"message":   "tool call denied by policy",
					"signature": "PAN-SIG-0042",
				},
			},
			Matched:          true,
			MatchedRule:      "block-dangerous-tools",
			MatchedRuleIndex: 0,
			PolicyName:       "security-policy",
			PolicyNamespace:  "production",
		},
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.80", identity.PodInfo{
		Name:      "deny-pod",
		Namespace: "production",
		UID:       "uid-deny-1",
		Labels:    map[string]string{"app": "agent"},
	})

	// Subscribe to policy decision events
	sub := bus.Subscribe(eventbus.EventTypePolicyDecision)
	defer bus.Unsubscribe(sub)

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	reqBody := makeOpenAIRequestBody("gpt-4", false)

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.80",
	}, reqBody)

	// Should receive an ImmediateResponse with 403
	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse for deny decision")
	}
	if ir.Status.Code != 403 {
		t.Errorf("expected status 403, got %d", ir.Status.Code)
	}

	// Parse the structured JSON body
	var respBody enforce.ErrorResponse
	if err := json.Unmarshal(ir.Body, &respBody); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	if respBody.Error != "policy_violation" {
		t.Errorf("expected error 'policy_violation', got %q", respBody.Error)
	}
	if respBody.Rule != "production/security-policy/rule-0" {
		t.Errorf("expected rule 'production/security-policy/rule-0', got %q", respBody.Rule)
	}
	if respBody.Signature != "PAN-SIG-0042" {
		t.Errorf("expected signature 'PAN-SIG-0042', got %q", respBody.Signature)
	}
	if respBody.Message != "tool call denied by policy" {
		t.Errorf("expected message 'tool call denied by policy', got %q", respBody.Message)
	}

	// Verify policy.decision event was emitted
	select {
	case evt := <-sub.Events():
		if evt.EventType() != eventbus.EventTypePolicyDecision {
			t.Errorf("expected policy.decision event, got %q", evt.EventType())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for policy.decision event")
	}
}

// TestPolicyEvaluation_ThrottleDecision verifies that when the policy evaluator
// returns a throttle decision after body parsing, the ExtProc server returns an
// ImmediateResponse with status 429 and a Retry-After header.
func TestPolicyEvaluation_ThrottleDecision(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: &policy.Decision{
			Action: policy.CompiledAction{
				Type: v1alpha1.ActionTypeRateLimit,
				Parameters: map[string]string{
					"retryAfter": "30",
				},
			},
			Matched:          true,
			MatchedRule:      "rate-limit-api-calls",
			MatchedRuleIndex: 1,
			PolicyName:       "rate-policy",
			PolicyNamespace:  "production",
		},
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.90", identity.PodInfo{
		Name:      "throttle-pod",
		Namespace: "production",
		UID:       "uid-throttle-1",
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

	reqBody := makeOpenAIRequestBody("gpt-4", false)

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.90",
	}, reqBody)

	// Should receive an ImmediateResponse with 429
	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse for throttle decision")
	}
	if ir.Status.Code != 429 {
		t.Errorf("expected status 429, got %d", ir.Status.Code)
	}

	// Parse the structured JSON body
	var respBody enforce.ErrorResponse
	if err := json.Unmarshal(ir.Body, &respBody); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	if respBody.Error != "rate_limited" {
		t.Errorf("expected error 'rate_limited', got %q", respBody.Error)
	}
	if respBody.RetryAfter != 30 {
		t.Errorf("expected retry_after 30, got %d", respBody.RetryAfter)
	}

	// Verify Retry-After header is set
	if ir.Headers == nil || len(ir.Headers.SetHeaders) == 0 {
		t.Fatal("expected headers in response")
	}
	foundRetryAfter := false
	for _, h := range ir.Headers.SetHeaders {
		if h.Header.Key == "retry-after" {
			foundRetryAfter = true
			if string(h.Header.RawValue) != "30" {
				t.Errorf("expected Retry-After value '30', got %q", string(h.Header.RawValue))
			}
		}
	}
	if !foundRetryAfter {
		t.Error("expected Retry-After header in response")
	}
}

// TestPolicyEvaluation_AuditOnlyPassesThrough verifies that when the policy
// evaluator returns a deny decision with AuditOnly=true, the ExtProc server
// emits a policy.decision event but passes the request through (no blocking).
func TestPolicyEvaluation_AuditOnlyPassesThrough(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: &policy.Decision{
			Action: policy.CompiledAction{
				Type: v1alpha1.ActionTypeDeny,
				Parameters: map[string]string{
					"message":   "tool call denied by policy",
					"signature": "PAN-SIG-0099",
				},
			},
			Matched:          true,
			AuditOnly:        true,
			MatchedRule:      "block-dangerous-tools",
			MatchedRuleIndex: 0,
			PolicyName:       "audit-policy",
			PolicyNamespace:  "staging",
		},
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.81", identity.PodInfo{
		Name:      "audit-pod",
		Namespace: "staging",
		UID:       "uid-audit-1",
		Labels:    map[string]string{"app": "agent"},
	})

	// Subscribe to policy decision events to verify emission
	sub := bus.Subscribe(eventbus.EventTypePolicyDecision)
	defer bus.Unsubscribe(sub)

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	reqBody := makeOpenAIRequestBody("gpt-4", false)

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.81",
	}, reqBody)

	// Should pass through — no ImmediateResponse despite deny action
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through for audit-only deny decision, got ImmediateResponse")
	}
	if resp.GetRequestBody() == nil {
		t.Fatal("expected RequestBody response for audit-only pass-through")
	}

	// Verify policy.decision event was still emitted
	select {
	case evt := <-sub.Events():
		if evt.EventType() != eventbus.EventTypePolicyDecision {
			t.Errorf("expected policy.decision event, got %q", evt.EventType())
		}
		// Verify the action label includes the "audit:" prefix
		ee, ok := evt.(*eventbus.EnforcementEvent)
		if !ok {
			t.Fatal("expected EnforcementEvent type")
		}
		if ee.Action != "audit:deny" {
			t.Errorf("expected audit action label 'audit:deny', got %q", ee.Action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for policy.decision event — audit-only should still emit events")
	}
}

// TestPolicyEvaluation_GlobalAuditOverridesPerPolicyEnforcing verifies that when
// the server-level enforcement mode is "audit", even decisions from per-policy
// "enforcing" rules are treated as audit-only: the event is emitted with an
// "audit:" prefix in the action label, and traffic passes through without blocking.
func TestPolicyEvaluation_GlobalAuditOverridesPerPolicyEnforcing(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		decision: &policy.Decision{
			Action: policy.CompiledAction{
				Type: v1alpha1.ActionTypeDeny,
				Parameters: map[string]string{
					"message":   "tool call denied by policy",
					"signature": "PAN-SIG-0100",
				},
			},
			Matched:          true,
			AuditOnly:        false, // Per-policy mode is enforcing (no AuditOnly)
			MatchedRule:      "deny-tools",
			MatchedRuleIndex: 0,
			PolicyName:       "enforcing-policy",
			PolicyNamespace:  "production",
		},
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	// Override to audit mode (global) — this should override per-policy enforcing
	srv.SetEnforcementMode(enforce.ModeAudit)

	podCache.Set("10.0.0.82", identity.PodInfo{
		Name:      "global-audit-pod",
		Namespace: "production",
		UID:       "uid-gaud-1",
		Labels:    map[string]string{"app": "agent"},
	})

	// Subscribe to policy decision events to verify emission
	sub := bus.Subscribe(eventbus.EventTypePolicyDecision)
	defer bus.Unsubscribe(sub)

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	reqBody := makeOpenAIRequestBody("gpt-4", false)

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.82",
	}, reqBody)

	// Should pass through — global audit mode overrides per-policy enforcing
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through for global audit mode, got ImmediateResponse (deny was enforced)")
	}
	if resp.GetRequestBody() == nil {
		t.Fatal("expected RequestBody response for audit-mode pass-through")
	}

	// Verify policy.decision event was emitted with "audit:" prefix
	select {
	case evt := <-sub.Events():
		if evt.EventType() != eventbus.EventTypePolicyDecision {
			t.Errorf("expected policy.decision event, got %q", evt.EventType())
		}
		ee, ok := evt.(*eventbus.EnforcementEvent)
		if !ok {
			t.Fatal("expected EnforcementEvent type")
		}
		if ee.Action != "audit:deny" {
			t.Errorf("expected audit action label 'audit:deny', got %q", ee.Action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for policy.decision event")
	}
}

// TestPolicyEvaluation_NilEvaluator verifies that when no PolicyEvaluator is
// configured, the server passes through all requests without policy evaluation.
func TestPolicyEvaluation_NilEvaluator(t *testing.T) {
	bus, podCache, srv := setupPolicyEvalTestComponents(t, nil)
	defer bus.Close()

	podCache.Set("10.0.0.55", identity.PodInfo{
		Name:      "no-eval-pod",
		Namespace: "default",
		UID:       "uid-noeval-1",
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

	reqBody := makeOpenAIRequestBody("gpt-4", false)

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.55",
	}, reqBody)

	// Should pass through without blocking
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through when no evaluator is set")
	}
	if resp.GetRequestBody() == nil {
		t.Fatal("expected RequestBody response for pass-through")
	}
}
