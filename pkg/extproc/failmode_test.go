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
	"errors"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
	"github.com/panoptium/panoptium/pkg/policy"
)

// setupFailModeTestComponents creates test infrastructure with configurable failure mode.
func setupFailModeTestComponents(t *testing.T, evaluator PolicyEvaluator, failureMode enforce.FailureMode) (*eventbus.SimpleBus, *identity.PodCache, *ExtProcServer) {
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
	srv.SetFailureMode(failureMode)
	if evaluator != nil {
		srv.SetPolicyEvaluator(evaluator)
	}

	return bus, podCache, srv
}

// errorPolicyEvaluator always returns an error to simulate policy engine unavailability.
type errorPolicyEvaluator struct {
	err error
}

func (e *errorPolicyEvaluator) Evaluate(_ *policy.PolicyEvent) (*policy.Decision, error) {
	return nil, e.err
}

func (e *errorPolicyEvaluator) EvaluateAll(_ *policy.PolicyEvent) (*policy.EvaluationResult, error) {
	return nil, e.err
}

// TestFailOpen_PassThroughOnPolicyError verifies that in fail-open mode,
// when the policy evaluator returns an error, traffic passes through.
func TestFailOpen_PassThroughOnPolicyError(t *testing.T) {
	evaluator := &errorPolicyEvaluator{err: errors.New("policy engine unavailable")}
	bus, podCache, srv := setupFailModeTestComponents(t, evaluator, enforce.FailOpen)
	defer bus.Close()

	podCache.Set("10.0.0.100", identity.PodInfo{
		Name:      "failopen-pod",
		Namespace: "default",
		UID:       "uid-fo-1",
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
		"x-forwarded-for", "10.0.0.100",
	}, reqBody)

	// Fail-open: should pass through (no ImmediateResponse)
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through in fail-open mode, got ImmediateResponse")
	}
	if resp.GetRequestBody() == nil {
		t.Fatal("expected RequestBody response for fail-open pass-through")
	}
}

// TestFailOpen_EmitsBypassEvent verifies that in fail-open mode, an
// enforcement.bypass event is emitted to the Event Bus.
func TestFailOpen_EmitsBypassEvent(t *testing.T) {
	evaluator := &errorPolicyEvaluator{err: errors.New("evaluation timeout")}
	bus, podCache, srv := setupFailModeTestComponents(t, evaluator, enforce.FailOpen)
	defer bus.Close()

	podCache.Set("10.0.0.101", identity.PodInfo{
		Name:      "bypass-pod",
		Namespace: "default",
		UID:       "uid-bp-1",
		Labels:    map[string]string{"app": "agent"},
	})

	// Subscribe to bypass events
	sub := bus.Subscribe(eventbus.EventTypeEnforcementBypass)
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

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.101",
	}, reqBody)

	// Verify enforcement.bypass event was emitted
	select {
	case evt := <-sub.Events():
		if evt.EventType() != eventbus.EventTypeEnforcementBypass {
			t.Errorf("expected enforcement.bypass event, got %q", evt.EventType())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for enforcement.bypass event")
	}
}

// TestFailClosed_Returns503OnPolicyError verifies that in fail-closed mode,
// when the policy evaluator returns an error, the ExtProc server returns
// an ImmediateResponse with status 503.
func TestFailClosed_Returns503OnPolicyError(t *testing.T) {
	evaluator := &errorPolicyEvaluator{err: errors.New("policy engine unavailable")}
	bus, podCache, srv := setupFailModeTestComponents(t, evaluator, enforce.FailClosed)
	defer bus.Close()

	podCache.Set("10.0.0.102", identity.PodInfo{
		Name:      "failclosed-pod",
		Namespace: "default",
		UID:       "uid-fc-1",
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
		"x-forwarded-for", "10.0.0.102",
	}, reqBody)

	// Fail-closed: should return 503 ImmediateResponse
	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse in fail-closed mode")
	}
	if ir.Status.Code != 503 {
		t.Errorf("expected status 503, got %d", ir.Status.Code)
	}

	// Verify structured error body
	var respBody enforce.ErrorResponse
	if err := json.Unmarshal(ir.Body, &respBody); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	if respBody.Error != "service_unavailable" {
		t.Errorf("expected error 'service_unavailable', got %q", respBody.Error)
	}
}

// TestFailClosed_EmitsUnavailableEvent verifies that in fail-closed mode,
// an enforcement.unavailable event is emitted to the Event Bus.
func TestFailClosed_EmitsUnavailableEvent(t *testing.T) {
	evaluator := &errorPolicyEvaluator{err: errors.New("policy engine down")}
	bus, podCache, srv := setupFailModeTestComponents(t, evaluator, enforce.FailClosed)
	defer bus.Close()

	podCache.Set("10.0.0.103", identity.PodInfo{
		Name:      "unavailable-pod",
		Namespace: "default",
		UID:       "uid-ua-1",
		Labels:    map[string]string{"app": "agent"},
	})

	// Subscribe to unavailable events
	sub := bus.Subscribe(eventbus.EventTypeEnforcementUnavailable)
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

	sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.103",
	}, reqBody)

	// Verify enforcement.unavailable event was emitted
	select {
	case evt := <-sub.Events():
		if evt.EventType() != eventbus.EventTypeEnforcementUnavailable {
			t.Errorf("expected enforcement.unavailable event, got %q", evt.EventType())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for enforcement.unavailable event")
	}
}

// TestFailModeConstants verifies the FailureMode constants.
func TestFailModeConstants(t *testing.T) {
	if enforce.FailOpen != "open" {
		t.Errorf("expected FailOpen='open', got %q", enforce.FailOpen)
	}
	if enforce.FailClosed != "closed" {
		t.Errorf("expected FailClosed='closed', got %q", enforce.FailClosed)
	}
}

// TestDefaultFailModeIsOpen verifies the default failure mode is fail-open.
func TestDefaultFailModeIsOpen(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	podCache := identity.NewPodCache()
	resolver := identity.NewResolver(podCache)
	srv := NewExtProcServer(registry, resolver, bus)

	// The default should be fail-open
	if srv.failureMode != enforce.FailOpen {
		t.Errorf("expected default failure mode FailOpen, got %q", srv.failureMode)
	}
}
