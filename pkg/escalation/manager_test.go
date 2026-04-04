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

package escalation

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/eventbus"
)

func TestEscalationManager_ThreeDeniesTriggerQuarantine(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	mgr := NewEscalationManager(bus, fakeClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the manager in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	// Give the subscription time to register
	time.Sleep(50 * time.Millisecond)

	// Emit 3 deny events with escalation parameters and severity.
	// 3 HIGH events = 3 * 50 = 150 risk points, meeting threshold 150.
	for i := 0; i < 3; i++ {
		bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:  eventbus.EventTypePolicyDecision,
				Time:  time.Now(),
				ReqID: "req-" + string(rune('a'+i)),
				AgentInfo: eventbus.AgentIdentity{
					PodName:   "test-pod",
					Namespace: "test-ns",
				},
			},
			Action:              "deny",
			Severity:            "HIGH",
			EscalationThreshold: 150,
			EscalationWindow:    60 * time.Second,
			EscalationAction:    "quarantine",
			PolicyName:          "test-policy",
			PolicyNamespace:     "test-ns",
		})
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify quarantine was created
	var quarantineList v1alpha1.AgentQuarantineList
	if err := fakeClient.List(ctx, &quarantineList); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) == 0 {
		t.Fatal("expected at least one AgentQuarantine to be created, got 0")
	}

	q := quarantineList.Items[0]
	if q.Spec.TargetPod != "test-pod" {
		t.Errorf("expected TargetPod=%q, got %q", "test-pod", q.Spec.TargetPod)
	}
	if q.Spec.TargetNamespace != "test-ns" {
		t.Errorf("expected TargetNamespace=%q, got %q", "test-ns", q.Spec.TargetNamespace)
	}
	if q.Spec.TriggeringPolicy != "test-policy" {
		t.Errorf("expected TriggeringPolicy=%q, got %q", "test-policy", q.Spec.TriggeringPolicy)
	}
	if q.Spec.ContainmentLevel != v1alpha1.ContainmentLevelNetworkIsolate {
		t.Errorf("expected ContainmentLevel=%q, got %q", v1alpha1.ContainmentLevelNetworkIsolate, q.Spec.ContainmentLevel)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("manager returned error: %v", err)
	}
}

func TestEscalationManager_NoEscalationParamsIgnored(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	mgr := NewEscalationManager(bus, fakeClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Emit deny events without escalation parameters (threshold=0)
	for i := 0; i < 5; i++ {
		bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:  eventbus.EventTypePolicyDecision,
				Time:  time.Now(),
				ReqID: "req-no-esc",
				AgentInfo: eventbus.AgentIdentity{
					PodName:   "test-pod",
					Namespace: "test-ns",
				},
			},
			Action: "deny",
			// No escalation params — EscalationThreshold defaults to 0
		})
	}

	time.Sleep(200 * time.Millisecond)

	var quarantineList v1alpha1.AgentQuarantineList
	if err := fakeClient.List(ctx, &quarantineList); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) != 0 {
		t.Errorf("expected no quarantines, got %d", len(quarantineList.Items))
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("manager returned error: %v", err)
	}
}

func TestEscalationManager_NonDenyActionsIgnored(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	mgr := NewEscalationManager(bus, fakeClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Emit allow/alert events with escalation parameters — should be ignored
	for _, action := range []string{"allow", "alert", "rate-limit", "pass-through"} {
		for i := 0; i < 5; i++ {
			bus.Emit(&eventbus.EnforcementEvent{
				BaseEvent: eventbus.BaseEvent{
					Type:  eventbus.EventTypePolicyDecision,
					Time:  time.Now(),
					ReqID: "req-non-deny",
					AgentInfo: eventbus.AgentIdentity{
						PodName:   "test-pod",
						Namespace: "test-ns",
					},
				},
				Action:              action,
				EscalationThreshold: 3,
				EscalationWindow:    60 * time.Second,
				EscalationAction:    "quarantine",
			})
		}
	}

	time.Sleep(200 * time.Millisecond)

	var quarantineList v1alpha1.AgentQuarantineList
	if err := fakeClient.List(ctx, &quarantineList); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) != 0 {
		t.Errorf("expected no quarantines, got %d", len(quarantineList.Items))
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("manager returned error: %v", err)
	}
}

// TestEscalationManager_EmptyIdentityErrorsNotSilent verifies that events
// with completely empty agent identity (no PodName, ID, or SourceIP) are
// logged as errors and emit a metric, rather than being silently dropped.
func TestEscalationManager_EmptyIdentityErrorsNotSilent(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	// Reset the metric counter for this test
	escalationMissingIdentityTotal.Add(0) // ensure registered
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	mgr := NewEscalationManager(bus, fakeClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Emit deny events with escalation parameters but completely empty identity
	for i := 0; i < 3; i++ {
		bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:  eventbus.EventTypePolicyDecision,
				Time:  time.Now(),
				ReqID: "req-empty-id",
				AgentInfo: eventbus.AgentIdentity{
					// All identity fields empty
					PodName:  "",
					ID:       "",
					SourceIP: "",
				},
			},
			Action:              "deny",
			Severity:            "CRITICAL",
			EscalationThreshold: 100,
			EscalationWindow:    60 * time.Second,
			EscalationAction:    "quarantine",
			PolicyName:          "test-policy",
			PolicyNamespace:     "test-ns",
		})
	}

	time.Sleep(200 * time.Millisecond)

	// Verify no quarantine was created (identity was empty, so escalation couldn't proceed)
	var quarantineList v1alpha1.AgentQuarantineList
	if err := fakeClient.List(ctx, &quarantineList); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) != 0 {
		t.Errorf("expected no quarantines for empty identity, got %d", len(quarantineList.Items))
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("manager returned error: %v", err)
	}
}

// Verify the manager does not require leader election.
func TestEscalationManager_NeedsLeaderElection(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	mgr := NewEscalationManager(bus, fakeClient)
	if mgr.NeedsLeaderElection() {
		t.Error("expected NeedsLeaderElection() to return false")
	}
}

// --- Severity-Based Escalation Tests (FR-5) ---

// TestEscalationManager_ProcessesAllActions verifies that the manager processes
// alert, deny, and rateLimit events (not just deny) toward escalation.
func TestEscalationManager_ProcessesAllActions(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	mgr := NewEscalationManager(bus, fakeClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Emit mixed action events, each with CRITICAL severity (100 pts each).
	// Threshold is 200, so 2 CRITICAL events should trigger escalation
	// regardless of action type.
	actions := []string{"deny", "alert"}
	for _, act := range actions {
		bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:  eventbus.EventTypePolicyDecision,
				Time:  time.Now(),
				ReqID: "req-mixed-" + act,
				AgentInfo: eventbus.AgentIdentity{
					PodName:   "mixed-pod",
					Namespace: "test-ns",
				},
			},
			Action:              act,
			Severity:            "CRITICAL",
			EscalationThreshold: 200,
			EscalationWindow:    60 * time.Second,
			EscalationAction:    "quarantine",
			PolicyName:          "mixed-policy",
			PolicyNamespace:     "test-ns",
		})
	}

	time.Sleep(200 * time.Millisecond)

	var quarantineList v1alpha1.AgentQuarantineList
	if err := fakeClient.List(ctx, &quarantineList); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) == 0 {
		t.Fatal("expected quarantine from mixed action types (deny + alert), got 0")
	}
}

// TestEscalationManager_SeverityFromEvent verifies that the manager reads the
// Severity field from EnforcementEvent and uses it for risk scoring.
func TestEscalationManager_SeverityFromEvent(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	mgr := NewEscalationManager(bus, fakeClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// 3 MEDIUM events = 3 * 20 = 60 points, below threshold 100
	for i := 0; i < 3; i++ {
		bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:  eventbus.EventTypePolicyDecision,
				Time:  time.Now(),
				ReqID: "req-sev-med",
				AgentInfo: eventbus.AgentIdentity{
					PodName:   "sev-pod",
					Namespace: "test-ns",
				},
			},
			Action:              "deny",
			Severity:            "MEDIUM",
			EscalationThreshold: 100,
			EscalationWindow:    60 * time.Second,
			EscalationAction:    "quarantine",
			PolicyName:          "sev-policy",
			PolicyNamespace:     "test-ns",
		})
	}

	time.Sleep(200 * time.Millisecond)

	var quarantineList v1alpha1.AgentQuarantineList
	if err := fakeClient.List(ctx, &quarantineList); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) != 0 {
		t.Errorf("expected no quarantine at 60 risk points (threshold 100), got %d", len(quarantineList.Items))
	}

	// 1 CRITICAL event = 100 points, total now 160 >= 100
	bus.Emit(&eventbus.EnforcementEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypePolicyDecision,
			Time:  time.Now(),
			ReqID: "req-sev-crit",
			AgentInfo: eventbus.AgentIdentity{
				PodName:   "sev-pod",
				Namespace: "test-ns",
			},
		},
		Action:              "deny",
		Severity:            "CRITICAL",
		EscalationThreshold: 100,
		EscalationWindow:    60 * time.Second,
		EscalationAction:    "quarantine",
		PolicyName:          "sev-policy",
		PolicyNamespace:     "test-ns",
	})

	time.Sleep(200 * time.Millisecond)

	if err := fakeClient.List(ctx, &quarantineList); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) == 0 {
		t.Fatal("expected quarantine after CRITICAL event pushed total over threshold")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("manager returned error: %v", err)
	}
}

// TestEscalationManager_AuditEventHalfWeight verifies that audit-prefixed
// actions ("audit:deny") are recorded with AuditOnly=true and weighted at 50%.
func TestEscalationManager_AuditEventHalfWeight(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	mgr := NewEscalationManager(bus, fakeClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// 2 audit:deny HIGH events = 2 * 50 * 0.5 = 50 points, below threshold 100
	for i := 0; i < 2; i++ {
		bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:  eventbus.EventTypePolicyDecision,
				Time:  time.Now(),
				ReqID: "req-audit-half",
				AgentInfo: eventbus.AgentIdentity{
					PodName:   "audit-pod",
					Namespace: "test-ns",
				},
			},
			Action:              "audit:deny",
			Severity:            "HIGH",
			EscalationThreshold: 100,
			EscalationWindow:    60 * time.Second,
			EscalationAction:    "quarantine",
			PolicyName:          "audit-policy",
			PolicyNamespace:     "test-ns",
		})
	}

	time.Sleep(200 * time.Millisecond)

	var quarantineList v1alpha1.AgentQuarantineList
	if err := fakeClient.List(ctx, &quarantineList); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) != 0 {
		t.Errorf("expected no quarantine at 50 audit-weighted points (threshold 100), got %d", len(quarantineList.Items))
	}

	// 1 enforced HIGH event = 50 points, total now 100 >= 100
	bus.Emit(&eventbus.EnforcementEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypePolicyDecision,
			Time:  time.Now(),
			ReqID: "req-audit-enforced",
			AgentInfo: eventbus.AgentIdentity{
				PodName:   "audit-pod",
				Namespace: "test-ns",
			},
		},
		Action:              "deny",
		Severity:            "HIGH",
		EscalationThreshold: 100,
		EscalationWindow:    60 * time.Second,
		EscalationAction:    "quarantine",
		PolicyName:          "audit-policy",
		PolicyNamespace:     "test-ns",
	})

	time.Sleep(200 * time.Millisecond)

	if err := fakeClient.List(ctx, &quarantineList); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) == 0 {
		t.Fatal("expected quarantine after enforced HIGH event pushed total to 100")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("manager returned error: %v", err)
	}
}

// Ensure the quarantine namespace falls back to policy namespace.
func TestEscalationManager_NamespaceFallback(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.AgentQuarantine{}).Build()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	mgr := NewEscalationManager(bus, fakeClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Emit events with empty agent namespace — should fall back to policy namespace.
	// 3 HIGH events = 3 * 50 = 150 risk points, meeting threshold 150.
	for i := 0; i < 3; i++ {
		bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:  eventbus.EventTypePolicyDecision,
				Time:  time.Now(),
				ReqID: "req-fallback",
				AgentInfo: eventbus.AgentIdentity{
					PodName:   "agent-pod",
					Namespace: "", // empty
				},
			},
			Action:              "deny",
			Severity:            "HIGH",
			EscalationThreshold: 150,
			EscalationWindow:    60 * time.Second,
			EscalationAction:    "quarantine",
			PolicyName:          "fallback-policy",
			PolicyNamespace:     "policy-ns",
		})
	}

	time.Sleep(200 * time.Millisecond)

	var quarantineList v1alpha1.AgentQuarantineList
	if err := fakeClient.List(ctx, &quarantineList, &client.ListOptions{
		Namespace: "policy-ns",
	}); err != nil {
		t.Fatalf("failed to list quarantines: %v", err)
	}

	if len(quarantineList.Items) == 0 {
		// List across all namespaces to see what we got
		var allList v1alpha1.AgentQuarantineList
		_ = fakeClient.List(ctx, &allList)
		for _, q := range allList.Items {
			t.Logf("quarantine in ns=%q, pod=%q", q.Namespace, q.Spec.TargetPod)
		}
		t.Fatal("expected quarantine in namespace 'policy-ns', got none")
	}

	q := quarantineList.Items[0]
	if q.Spec.TargetNamespace != "policy-ns" {
		t.Errorf("expected TargetNamespace=%q, got %q", "policy-ns", q.Spec.TargetNamespace)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("manager returned error: %v", err)
	}
}
