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

package policy

import (
	"sync"
	"testing"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testPolicyDenyCurl = "deny-curl"

func makeTestPolicy(name, namespace string, priority int32) *v1alpha1.AgentPolicy {
	return &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        priority,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "test-rule",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "process_exec",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.processName == "curl"`},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}
}

// Test: OnAdd compiles and stores a policy
func TestPolicyCache_OnAdd(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	pol := makeTestPolicy(testPolicyDenyCurl, "default", 100)
	err := cache.OnAdd(pol)
	if err != nil {
		t.Fatalf("OnAdd: %v", err)
	}

	policies := cache.GetPolicies()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != testPolicyDenyCurl {
		t.Errorf("expected name deny-curl, got %q", policies[0].Name)
	}
}

// Test: OnUpdate recompiles only the changed policy
func TestPolicyCache_OnUpdate_RecompilesChangedOnly(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	pol1 := makeTestPolicy("pol-a", "default", 100)
	pol2 := makeTestPolicy("pol-b", "default", 200)

	_ = cache.OnAdd(pol1)
	_ = cache.OnAdd(pol2)

	// Update pol-a with a new rule
	pol1Updated := makeTestPolicy("pol-a", "default", 150)
	err := cache.OnUpdate(pol1, pol1Updated)
	if err != nil {
		t.Fatalf("OnUpdate: %v", err)
	}

	policies := cache.GetPolicies()
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}

	// Find pol-a and verify updated priority
	var found *CompiledPolicy
	for _, p := range policies {
		if p.Name == "pol-a" {
			found = p
			break
		}
	}
	if found == nil {
		t.Fatal("pol-a not found after update")
	}
	if found.Priority != 150 {
		t.Errorf("expected priority 150, got %d", found.Priority)
	}
}

// Test: OnDelete removes the policy
func TestPolicyCache_OnDelete(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	pol := makeTestPolicy("delete-me", "default", 100)
	_ = cache.OnAdd(pol)

	err := cache.OnDelete(pol)
	if err != nil {
		t.Fatalf("OnDelete: %v", err)
	}

	policies := cache.GetPolicies()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies after delete, got %d", len(policies))
	}
}

// Test: OnDelete with missing policy is a no-op
func TestPolicyCache_OnDelete_Missing(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	pol := makeTestPolicy("nonexistent", "default", 100)
	err := cache.OnDelete(pol)
	if err != nil {
		t.Fatalf("OnDelete of missing policy: %v", err)
	}

	policies := cache.GetPolicies()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policies))
	}
}

// Test: Atomic swap — readers see consistent snapshot
func TestPolicyCache_AtomicSwap(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	pol := makeTestPolicy("pol-1", "default", 100)
	_ = cache.OnAdd(pol)

	// Get policies before the update
	before := cache.GetPolicies()

	// Update the policy
	polUpdated := makeTestPolicy("pol-1", "default", 200)
	_ = cache.OnUpdate(pol, polUpdated)

	// The before slice should still be the old snapshot
	if before[0].Priority != 100 {
		t.Error("expected snapshot isolation: before should still show priority 100")
	}

	// New read should reflect the update
	after := cache.GetPolicies()
	if after[0].Priority != 200 {
		t.Errorf("expected priority 200 after update, got %d", after[0].Priority)
	}
}

// Test: Concurrent OnAdd/OnDelete/GetPolicies are safe
func TestPolicyCache_ConcurrentAccess(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			pol := makeTestPolicy("pol", "default", int32(n))
			pol.Name = "pol-concurrent"
			pol.Namespace = "default"
			_ = cache.OnAdd(pol)
			cache.GetPolicies()
			_ = cache.OnDelete(pol)
		}(i)
	}
	wg.Wait()
}

// Test: InvalidationCallback is called on Update
func TestPolicyCache_InvalidationCallback_OnUpdate(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	var callbackCalled bool
	var callbackPolicyKey string
	cache.SetInvalidationCallback(func(policyKey string) {
		callbackCalled = true
		callbackPolicyKey = policyKey
	})

	pol := makeTestPolicy("pol-x", "default", 100)
	_ = cache.OnAdd(pol)

	polUpdated := makeTestPolicy("pol-x", "default", 200)
	_ = cache.OnUpdate(pol, polUpdated)

	if !callbackCalled {
		t.Error("expected invalidation callback to be called on update")
	}
	if callbackPolicyKey != "default/pol-x" {
		t.Errorf("expected policy key default/pol-x, got %q", callbackPolicyKey)
	}
}

// Test: InvalidationCallback is called on Delete
func TestPolicyCache_InvalidationCallback_OnDelete(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	var callbackCalled bool
	cache.SetInvalidationCallback(func(policyKey string) {
		callbackCalled = true
	})

	pol := makeTestPolicy("pol-y", "ns-1", 100)
	_ = cache.OnAdd(pol)
	_ = cache.OnDelete(pol)

	if !callbackCalled {
		t.Error("expected invalidation callback to be called on delete")
	}
}

// Test: Compile error on add does not corrupt cache
func TestPolicyCache_OnAdd_CompileError(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	// Add a valid policy first
	goodPol := makeTestPolicy("good", "default", 100)
	_ = cache.OnAdd(goodPol)

	// Try adding a policy with an invalid trigger
	badPol := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bad",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        200,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "bad-rule",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "invalid_layer",
						EventSubcategory: "unknown_event",
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}

	err := cache.OnAdd(badPol)
	if err == nil {
		t.Fatal("expected error for invalid policy")
	}

	// The good policy should still be intact
	policies := cache.GetPolicies()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy (good), got %d", len(policies))
	}
	if policies[0].Name != "good" {
		t.Errorf("expected good policy, got %q", policies[0].Name)
	}
}

// Test: Multiple namespaces use distinct keys
func TestPolicyCache_MultipleNamespaces(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	pol1 := makeTestPolicy(testPolicyDenyCurl, "ns-a", 100)
	pol2 := makeTestPolicy(testPolicyDenyCurl, "ns-b", 200)

	_ = cache.OnAdd(pol1)
	_ = cache.OnAdd(pol2)

	policies := cache.GetPolicies()
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies from different namespaces, got %d", len(policies))
	}
}
