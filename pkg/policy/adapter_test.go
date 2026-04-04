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
	"time"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testRateLimitCounter is a simple in-memory rate limit counter for tests.
// It tracks per-key counts and checks against a dynamic limit.
type testRateLimitCounter struct {
	mu    sync.Mutex
	count map[string]int
}

func newTestRateLimitCounter() *testRateLimitCounter {
	return &testRateLimitCounter{count: make(map[string]int)}
}

func (c *testRateLimitCounter) IncrementAndCheck(key string, limit int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count[key]++
	return c.count[key] > limit
}

// TestEvaluatorAdapter_EmptyCache verifies that the adapter returns a default
// allow decision when the cache contains no policies.
func TestEvaluatorAdapter_EmptyCache(t *testing.T) {
	compiler := NewPolicyCompiler()
	cache := NewPolicyCache(compiler)
	resolver := NewPolicyCompositionResolver()
	adapter := NewEvaluatorAdapter(cache, resolver)

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Timestamp:   time.Now(),
		Namespace:   "default",
		PodName:     "test-pod",
		Fields:      map[string]interface{}{"toolName": "get_weather"},
	}

	decision, err := adapter.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision == nil {
		t.Fatal("Evaluate() returned nil decision")
	}
	if decision.Matched {
		t.Error("expected no match with empty cache")
	}
	if decision.Action.Type != "allow" {
		t.Errorf("expected default allow action, got %q", decision.Action.Type)
	}
}

// TestEvaluatorAdapter_DenyDecision verifies that the adapter returns a deny
// decision when a policy matches the event.
func TestEvaluatorAdapter_DenyDecision(t *testing.T) {
	compiler := NewPolicyCompiler()
	cache := NewPolicyCache(compiler)
	resolver := NewPolicyCompositionResolver()
	adapter := NewEvaluatorAdapter(cache, resolver)

	// Add a deny policy targeting tool_call events
	pol := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "block-dangerous",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "block-exec",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "protocol",
						EventSubcategory: "tool_call",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.toolName == "dangerous_exec"`},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}
	if err := cache.OnAdd(pol); err != nil {
		t.Fatalf("OnAdd() error = %v", err)
	}

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Timestamp:   time.Now(),
		Namespace:   "default",
		PodName:     "agent-pod",
		Fields:      map[string]interface{}{"toolName": "dangerous_exec"},
	}

	decision, err := adapter.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for deny policy")
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny action, got %q", decision.Action.Type)
	}
}

// TestEvaluatorAdapter_ConcurrentSafety verifies that the adapter is safe
// for concurrent evaluation by multiple goroutines.
func TestEvaluatorAdapter_ConcurrentSafety(t *testing.T) {
	compiler := NewPolicyCompiler()
	cache := NewPolicyCache(compiler)
	resolver := NewPolicyCompositionResolver()
	adapter := NewEvaluatorAdapter(cache, resolver)

	// Add a policy
	pol := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "concurrent-test",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "allow-all",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "protocol",
						EventSubcategory: "tool_call",
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAllow},
					Severity: v1alpha1.SeverityInfo,
				},
			},
		},
	}
	if err := cache.OnAdd(pol); err != nil {
		t.Fatalf("OnAdd() error = %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			event := &PolicyEvent{
				Category:    "protocol",
				Subcategory: "tool_call",
				Timestamp:   time.Now(),
				Namespace:   "default",
				PodName:     "agent-pod",
				Fields:      map[string]interface{}{"toolName": "safe_tool"},
			}
			_, err := adapter.Evaluate(event)
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent Evaluate() error: %v", err)
	}
}

// TestEvaluatorAdapter_CallsGetPoliciesAndResolver verifies that the adapter
// calls cache.GetPolicies() and passes the result to the resolver.
func TestEvaluatorAdapter_CallsGetPoliciesAndResolver(t *testing.T) {
	compiler := NewPolicyCompiler()
	cache := NewPolicyCache(compiler)
	resolver := NewPolicyCompositionResolver()
	adapter := NewEvaluatorAdapter(cache, resolver)

	// Initially empty cache — should get default allow
	event := &PolicyEvent{
		Category:    "llm",
		Subcategory: "llm_request",
		Timestamp:   time.Now(),
		Namespace:   "test-ns",
		PodName:     "test-pod",
		Fields:      map[string]interface{}{},
	}

	decision, err := adapter.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Matched {
		t.Error("expected no match with empty cache")
	}

	// Add policy and verify it gets picked up
	pol := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "llm-policy",
			Namespace: "test-ns",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        50,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "block-llm",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "llm",
						EventSubcategory: "llm_request",
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityMedium,
				},
			},
		},
	}
	if err := cache.OnAdd(pol); err != nil {
		t.Fatalf("OnAdd() error = %v", err)
	}

	decision, err = adapter.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Matched {
		t.Error("expected match after adding policy")
	}
}

// TestEvaluatorAdapter_RateLimiting verifies the end-to-end rate limiting flow:
// requests within the burst limit are allowed, and requests exceeding the
// limit are matched with a rateLimit action.
func TestEvaluatorAdapter_RateLimiting(t *testing.T) {
	compiler := NewPolicyCompiler()
	cache := NewPolicyCache(compiler)
	counter := newTestRateLimitCounter()
	resolver := NewPolicyCompositionResolverWithRateLimit(counter)
	adapter := NewEvaluatorAdapter(cache, resolver)

	// Add a rate limit policy
	pol := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rate-limit-test",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "throttle-rate-test",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "protocol",
						EventSubcategory: "tool_call",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.toolName == "rate_test"`},
					},
					Action: v1alpha1.Action{
						Type: v1alpha1.ActionTypeRateLimit,
						Parameters: map[string]string{
							"requestsPerMinute": "3",
							"burstSize":         "3",
						},
					},
					Severity: v1alpha1.SeverityMedium,
				},
			},
		},
	}
	if err := cache.OnAdd(pol); err != nil {
		t.Fatalf("OnAdd() error = %v", err)
	}

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Timestamp:   time.Now(),
		Namespace:   "default",
		PodName:     "agent-pod",
		Fields:      map[string]interface{}{"toolName": "rate_test"},
	}

	// First 3 requests: within burst limit, should be allowed
	for i := 1; i <= 3; i++ {
		decision, err := adapter.Evaluate(event)
		if err != nil {
			t.Fatalf("request %d: Evaluate() error = %v", i, err)
		}
		if decision.Matched {
			t.Errorf("request %d: expected no match (within rate limit), got matched with action %q", i, decision.Action.Type)
		}
		if decision.Action.Type != "allow" {
			t.Errorf("request %d: expected allow, got %q", i, decision.Action.Type)
		}
	}

	// 4th request: exceeds burst limit, should be rate limited
	decision, err := adapter.Evaluate(event)
	if err != nil {
		t.Fatalf("4th request: Evaluate() error = %v", err)
	}
	if !decision.Matched {
		t.Error("4th request: expected match (rate limit exceeded)")
	}
	if decision.Action.Type != v1alpha1.ActionTypeRateLimit {
		t.Errorf("4th request: expected rateLimit action, got %q", decision.Action.Type)
	}
}
