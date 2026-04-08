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

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
)

// setupEnforcementTestComponents creates test infrastructure with configurable
// enforcement mode and PodCache entries.
func setupEnforcementTestComponents(
	t *testing.T, mode enforce.EnforcementMode,
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
	srv.SetEnforcementMode(mode)

	return bus, podCache, srv
}

// TestIdentityResolution_EnrolledPod verifies that ExtProc resolves agent
// identity from source IP via PodCache for enrolled pods. The identity
// must include pod_name, namespace, and pod_uid for correlation with
// Tetragon kernel events.
func TestIdentityResolution_EnrolledPod(t *testing.T) {
	bus, podCache, srv := setupEnforcementTestComponents(t, enforce.ModeEnforcing)
	defer bus.Close()

	// Register an enrolled pod in the PodCache
	podCache.Set("10.0.0.50", identity.PodInfo{
		Name:      "agent-pod-1",
		Namespace: "production",
		UID:       "uid-abc-123",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers with X-Forwarded-For to identify the source pod
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-forwarded-for", "10.0.0.50",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	// Should receive a pass-through response (not an ImmediateResponse)
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	if resp.GetImmediateResponse() != nil {
		t.Fatal("enrolled pod should NOT receive ImmediateResponse; expected pass-through")
	}
	if resp.GetRequestHeaders() == nil {
		t.Fatal("expected RequestHeaders response for enrolled pod")
	}

	// Send request body to trigger event emission
	reqBody := makeOpenAIRequestBody("gpt-4", false)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        reqBody,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}

	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive body response: %v", err)
	}

	// Verify that the emitted event carries the correct identity
	select {
	case evt := <-sub.Events():
		id := evt.Identity()
		if id.PodName != "agent-pod-1" {
			t.Errorf("expected pod_name 'agent-pod-1', got %q", id.PodName)
		}
		if id.Namespace != "production" {
			t.Errorf("expected namespace 'production', got %q", id.Namespace)
		}
		if id.PodUID != "uid-abc-123" {
			t.Errorf("expected pod_uid 'uid-abc-123', got %q", id.PodUID)
		}
		if id.Confidence != eventbus.ConfidenceHigh {
			t.Errorf("expected high confidence, got %q", id.Confidence)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for LLMRequestStart event")
	}
}

// TestIdentityResolution_UnknownSource_EnforcingMode verifies that in
// enforcing mode, requests from unknown source pods (source IP not in PodCache)
// pass through with degraded identity. Network admission is delegated to
// Kubernetes NetworkPolicy, not ExtProc.
func TestIdentityResolution_UnknownSource_EnforcingMode(t *testing.T) {
	bus, _, srv := setupEnforcementTestComponents(t, enforce.ModeEnforcing)
	defer bus.Close()

	// Do NOT register any pod in PodCache — the source IP is unknown

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers from unknown source pod
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-forwarded-for", "10.0.0.99",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Unknown source pods should pass through (no ImmediateResponse).
	// Network admission is handled by Kubernetes NetworkPolicy, not ExtProc.
	if resp.GetImmediateResponse() != nil {
		t.Fatal("unknown source pod should NOT receive ImmediateResponse; network admission is delegated to NetworkPolicy")
	}
	if resp.GetRequestHeaders() == nil {
		t.Fatal("expected RequestHeaders response (pass-through) for unknown source pod")
	}
}

// TestIdentityResolution_UnknownSource_AuditMode verifies that in audit mode,
// requests from unknown source pods pass through with degraded identity and
// NO enforcement.unknown_source event is emitted (that event type no longer
// exists -- network admission is delegated to Kubernetes NetworkPolicy).
func TestIdentityResolution_UnknownSource_AuditMode(t *testing.T) {
	bus, _, srv := setupEnforcementTestComponents(t, enforce.ModeAudit)
	defer bus.Close()

	// Do NOT register any pod in PodCache — the source IP is unknown

	// Subscribe to all events so we can verify no unknown_source event is emitted
	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers from unknown source pod
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-forwarded-for", "10.0.0.99",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Unknown source pods should pass through (no ImmediateResponse)
	if resp.GetImmediateResponse() != nil {
		t.Fatal("unknown source pod should NOT receive ImmediateResponse")
	}
	if resp.GetRequestHeaders() == nil {
		t.Fatal("expected RequestHeaders response (pass-through) for unknown source pod")
	}

	// Verify NO enforcement.unknown_source event was emitted
	select {
	case evt := <-sub.Events():
		t.Fatalf("expected no events during header processing, but got event type %q", evt.EventType())
	case <-time.After(200 * time.Millisecond):
		// Good — no event emitted
	}
}

// TestIdentityResolution_PodUIDCorrelation verifies that the agent identity
// in emitted events includes pod_uid for correlation with Tetragon events.
// This ensures the intent-action correlation engine can join gateway
// enforcement events and Tetragon kernel-level events using a common key.
func TestIdentityResolution_PodUIDCorrelation(t *testing.T) {
	bus, podCache, srv := setupEnforcementTestComponents(t, enforce.ModeEnforcing)
	defer bus.Close()

	podCache.Set("10.0.0.77", identity.PodInfo{
		Name:      "correlation-pod",
		Namespace: "test-ns",
		UID:       "uid-xyz-789",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-forwarded-for", "10.0.0.77",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive header response: %v", err)
	}

	reqBody := makeOpenAIRequestBody("gpt-4", false)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        reqBody,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}

	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive body response: %v", err)
	}

	// Verify the event identity carries pod_uid matching the PodCache entry
	select {
	case evt := <-sub.Events():
		id := evt.Identity()
		if id.PodUID != "uid-xyz-789" {
			t.Errorf("expected pod_uid 'uid-xyz-789', got %q", id.PodUID)
		}
		if id.PodName != "correlation-pod" {
			t.Errorf("expected pod_name 'correlation-pod', got %q", id.PodName)
		}
		if id.Namespace != "test-ns" {
			t.Errorf("expected namespace 'test-ns', got %q", id.Namespace)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for LLMRequestStart event")
	}
}
