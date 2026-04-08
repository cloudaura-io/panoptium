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
	"net"
	"regexp"
	"testing"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPolicyComposition_DescendingPriorityOrdering(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "low-priority",
			Namespace: "default",
			Priority:  10,
			Rules: []*CompiledRule{
				{
					Name:         "low-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeAllow},
				},
			},
		},
		{
			Name:      "high-priority",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "high-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny (from high-priority policy), got %q", decision.Action.Type)
	}
	if decision.PolicyName != "high-priority" {
		t.Errorf("expected PolicyName=high-priority, got %q", decision.PolicyName)
	}
}

func TestPolicyComposition_FirstMatchWithinPolicy(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "test-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "first-rule",
					Index:        0,
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.processName", Operator: "==", Value: "curl"},
					},
				},
				{
					Name:         "second-rule",
					Index:        1,
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeAllow},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.MatchedRule != "first-rule" {
		t.Errorf("expected first-rule (first match), got %q", decision.MatchedRule)
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_NamespaceOverridesCluster(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	// Both policies use alert (non-terminal, same action) to test ordering
	// without deny-first interference.
	policies := []*CompiledPolicy{
		{
			Name:            "cluster-policy",
			Namespace:       "",
			Priority:        100,
			IsClusterScoped: true,
			Rules: []*CompiledRule{
				{
					Name:         "cluster-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
		{
			Name:            "namespace-policy",
			Namespace:       "default",
			Priority:        100, // same priority
			IsClusterScoped: false,
			Rules: []*CompiledRule{
				{
					Name:         "namespace-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	// Use EvaluateAll to verify ordering. The namespace-scoped policy
	// should sort before the cluster-scoped one at equal priority.
	result, err := resolver.EvaluateAll(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(result.Decisions))
	}
	if result.Decisions[0].PolicyName != "namespace-policy" {
		t.Errorf("expected namespace-policy first (namespace overrides cluster at equal priority), got %q",
			result.Decisions[0].PolicyName)
	}
}

func TestPolicyComposition_DenyFirstAtEqualPriority(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "deny-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
		{
			Name:      "allow-policy",
			Namespace: "default",
			Priority:  100, // same priority
			Rules: []*CompiledRule{
				{
					Name:         "allow-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeAllow},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// FR-3: deny-first semantics — at equal priority, deny beats allow.
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny (deny-first at equal priority, FR-3), got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_DeterministicEvaluation(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "policy-a",
			Namespace: "default",
			Priority:  50,
			Rules: []*CompiledRule{
				{
					Name:         "rule-a",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
		{
			Name:      "policy-b",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "rule-b",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	// Evaluate multiple times and verify same result
	for i := 0; i < 10; i++ {
		decision, err := resolver.Evaluate(policies, event)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if decision.Action.Type != v1alpha1.ActionTypeDeny {
			t.Errorf("iteration %d: expected deny, got %q", i, decision.Action.Type)
		}
		if decision.PolicyName != "policy-b" {
			t.Errorf("iteration %d: expected policy-b, got %q", i, decision.PolicyName)
		}
	}
}

func TestPolicyComposition_NoMatchDefaultAllow(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "network-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "network-rule",
					TriggerLayer: "network",
					TriggerEvent: "egress_attempt",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("expected no match (no kernel rule), got match")
	}
	if decision.Action.Type != v1alpha1.ActionTypeAllow {
		t.Errorf("expected default allow, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_EmptyPolicySet(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{},
	}

	decision, err := resolver.Evaluate([]*CompiledPolicy{}, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("expected no match with empty policy set")
	}
	if decision.Action.Type != v1alpha1.ActionTypeAllow {
		t.Errorf("expected default allow, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_PredicateEvaluation(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "test-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "regex-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.processName", Operator: "matches", Value: "^curl.*"},
					},
					CompiledRegexes: map[string]*regexp.Regexp{
						"^curl.*": regexp.MustCompile("^curl.*"),
					},
					CompiledGlobs: map[string]*GlobMatcher{},
					CompiledCIDRs: map[string]*net.IPNet{},
				},
			},
		},
	}

	// Matching event
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match on regex predicate")
	}

	// Non-matching event
	event2 := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "python"},
	}

	decision2, err := resolver.Evaluate(policies, event2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for python (regex ^curl.* doesn't match)")
	}
}

func TestPolicyComposition_TiebreakByPolicyName(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	// Two namespace-scoped policies with same priority
	policies := []*CompiledPolicy{
		{
			Name:      "zzz-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "zzz-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
		{
			Name:      "aaa-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "aaa-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionType("alert")},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With deny-first semantics (FR-3), deny beats alert at equal priority.
	// zzz-policy has deny, aaa-policy has alert — deny wins.
	if decision.PolicyName != "zzz-policy" {
		t.Errorf("expected zzz-policy (deny-first at equal priority), got %q", decision.PolicyName)
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny (deny-first), got %q", decision.Action.Type)
	}
}

// mockRateLimitCounter implements RateLimitCounter for testing.
type mockRateLimitCounter struct {
	count int
}

func (m *mockRateLimitCounter) IncrementAndCheck(key string, limit int) bool {
	m.count++
	return m.count > limit
}

func TestPolicyComposition_RateLimitWithinBurst(t *testing.T) {
	counter := &mockRateLimitCounter{}
	resolver := NewPolicyCompositionResolverWithRateLimit(counter)

	policies := []*CompiledPolicy{
		{
			Name:      "rate-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "throttle-rule",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: v1alpha1.ActionTypeRateLimit,
						Parameters: map[string]string{
							"burstSize":         "3",
							"requestsPerMinute": "3",
						},
					},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.toolName", Operator: "==", Value: "rate_test"},
					},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		Fields:      map[string]interface{}{"toolName": "rate_test"},
	}

	// First 3 requests should be allowed (within burst of 3)
	for i := 1; i <= 3; i++ {
		decision, err := resolver.Evaluate(policies, event)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		if decision.Matched {
			t.Errorf("request %d: expected no match (under rate limit), got matched with action %q", i, decision.Action.Type)
		}
		if decision.Action.Type != v1alpha1.ActionTypeAllow {
			t.Errorf("request %d: expected allow action, got %q", i, decision.Action.Type)
		}
	}

	// 4th request should be rate limited
	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("4th request: unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("4th request: expected match (rate limit exceeded)")
	}
	if decision.Action.Type != rateLimitCanonicalName {
		t.Errorf("4th request: expected rateLimit action, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_RateLimitWithoutCounter(t *testing.T) {
	// Without a counter, rateLimit decisions should be returned as-is
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "rate-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "throttle-rule",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: v1alpha1.ActionTypeRateLimit,
						Parameters: map[string]string{
							"burstSize":         "3",
							"requestsPerMinute": "3",
						},
					},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.toolName", Operator: "==", Value: "rate_test"},
					},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		Fields:      map[string]interface{}{"toolName": "rate_test"},
	}

	// Without counter, should always return matched rateLimit
	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match (no counter = rateLimit returned as-is)")
	}
	if decision.Action.Type != rateLimitCanonicalName {
		t.Errorf("expected rateLimit action, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_RateLimitNonMatchingEvent(t *testing.T) {
	counter := &mockRateLimitCounter{}
	resolver := NewPolicyCompositionResolverWithRateLimit(counter)

	policies := []*CompiledPolicy{
		{
			Name:      "rate-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "throttle-rule",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: v1alpha1.ActionTypeRateLimit,
						Parameters: map[string]string{
							"burstSize":         "3",
							"requestsPerMinute": "3",
						},
					},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.toolName", Operator: "==", Value: "rate_test"},
					},
				},
			},
		},
	}

	// Event with different tool name should not match at all
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		Fields:      map[string]interface{}{"toolName": "other_tool"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("expected no match for non-matching event")
	}
	if decision.Action.Type != v1alpha1.ActionTypeAllow {
		t.Errorf("expected default allow, got %q", decision.Action.Type)
	}
	// Counter should not have been touched
	if counter.count != 0 {
		t.Errorf("expected counter.count=0 (no rate limit check), got %d", counter.count)
	}
}

func TestPolicyComposition_NamespacedPolicy_DoesNotMatchPodInOtherNamespace(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "foo-policy",
			Namespace:       "foo",
			Priority:        100,
			IsClusterScoped: false,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	// Event is from namespace "bar" — policy in "foo" should NOT match
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "bar",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("namespaced policy in 'foo' should NOT match pod in namespace 'bar'")
	}
	if decision.Action.Type != v1alpha1.ActionTypeAllow {
		t.Errorf("expected default allow, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_NamespacedPolicy_MatchesPodInSameNamespace(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "foo-policy",
			Namespace:       "foo",
			Priority:        100,
			IsClusterScoped: false,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	// Event is from the same namespace "foo" — should match
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "foo",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("namespaced policy should match pod in same namespace")
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_NamespacedPolicy_EmptyTargetSelector_MatchesAllPodsInNamespace(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "wildcard-ns-policy",
			Namespace:       "production",
			Priority:        100,
			IsClusterScoped: false,
			TargetSelector:  nil, // empty selector = all pods
			Rules: []*CompiledRule{
				{
					Name:         "alert-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
	}

	// Pod in same namespace — should match
	eventSame := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "production",
		PodLabels:   map[string]string{"app": "anything"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, eventSame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("empty targetSelector + same namespace should match")
	}

	// Pod in different namespace — should NOT match
	eventOther := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "staging",
		PodLabels:   map[string]string{"app": "anything"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision2, err := resolver.Evaluate(policies, eventOther)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision2.Matched {
		t.Error("empty targetSelector on namespaced policy should NOT match pods in other namespace")
	}
}

func TestPolicyComposition_ClusterPolicy_EmptyTargetSelector_MatchesAllPods(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "global-policy",
			Namespace:       "",
			Priority:        100,
			IsClusterScoped: true,
			TargetSelector:  nil, // empty selector = all pods
			Rules: []*CompiledRule{
				{
					Name:         "alert-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
	}

	// Should match pods in any namespace
	for _, ns := range []string{"production", "staging", "default", ""} {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Namespace:   ns,
			Fields:      map[string]interface{}{"processName": "curl"},
		}

		decision, err := resolver.Evaluate(policies, event)
		if err != nil {
			t.Fatalf("unexpected error for ns %q: %v", ns, err)
		}
		if !decision.Matched {
			t.Errorf("cluster policy with empty targetSelector should match pod in namespace %q", ns)
		}
	}
}

func TestPolicyComposition_ClusterPolicy_WithSelector_MatchesAcrossNamespaces(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "global-labeled-policy",
			Namespace:       "",
			Priority:        100,
			IsClusterScoped: true,
			TargetSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "agents"},
			},
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	// Matching labels in different namespaces — cluster policy matches all
	for _, ns := range []string{"ns-a", "ns-b", "ns-c"} {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Namespace:   ns,
			PodLabels:   map[string]string{"tier": "agents"},
			Fields:      map[string]interface{}{"processName": "curl"},
		}

		decision, err := resolver.Evaluate(policies, event)
		if err != nil {
			t.Fatalf("unexpected error for ns %q: %v", ns, err)
		}
		if !decision.Matched {
			t.Errorf("cluster policy should match label-matching pod in namespace %q", ns)
		}
	}

	// Non-matching labels — should NOT match
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "ns-a",
		PodLabels:   map[string]string{"tier": "web"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("cluster policy should NOT match pod without matching labels")
	}
}

func TestEvaluateAll_ReturnsEvaluationResult(t *testing.T) {
	resolver := NewPolicyCompositionResolver()
	policies := []*CompiledPolicy{
		{
			Name:      "single-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}

	result, err := resolver.EvaluateAll(policies, event)
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}
	if len(result.Decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(result.Decisions))
	}
	if result.Decisions[0].Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("decision action = %q, want %q", result.Decisions[0].Action.Type, v1alpha1.ActionTypeDeny)
	}
}

func TestEvaluateAll_CollectsAllMatchingPolicies(t *testing.T) {
	resolver := NewPolicyCompositionResolver()
	policies := []*CompiledPolicy{
		{
			Name: "pol-100", Namespace: "default", Priority: 100,
			Rules: []*CompiledRule{
				{Name: "rule-a", TriggerLayer: "protocol", TriggerEvent: "tool_call",
					Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}},
			},
		},
		{
			Name: "pol-50", Namespace: "default", Priority: 50,
			Rules: []*CompiledRule{
				{Name: "rule-b", TriggerLayer: "protocol", TriggerEvent: "tool_call",
					Action: CompiledAction{Type: v1alpha1.ActionTypeAlert}},
			},
		},
		{
			Name: "pol-10", Namespace: "default", Priority: 10,
			Rules: []*CompiledRule{
				{Name: "rule-c", TriggerLayer: "protocol", TriggerEvent: "tool_call",
					Action: CompiledAction{Type: v1alpha1.ActionTypeAllow}},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}

	result, err := resolver.EvaluateAll(policies, event)
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}
	if len(result.Decisions) != 3 {
		t.Fatalf("expected 3 decisions (all priorities), got %d", len(result.Decisions))
	}
}

func TestEvaluateAll_PriorityAndDenyFirst(t *testing.T) {
	tests := []struct {
		name       string
		policies   []*CompiledPolicy
		wantAction v1alpha1.ActionType
		desc       string
	}{
		{
			name: "DenyFirstAtEqualPriority",
			policies: []*CompiledPolicy{
				{
					Name: "allow-pol", Namespace: "default", Priority: 100,
					Rules: []*CompiledRule{
						{Name: "allow-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
							Action: CompiledAction{Type: v1alpha1.ActionTypeAllow}},
					},
				},
				{
					Name: "deny-pol", Namespace: "default", Priority: 100,
					Rules: []*CompiledRule{
						{Name: "deny-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
							Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}},
					},
				},
			},
			wantAction: v1alpha1.ActionTypeDeny,
			desc:       "deny-first at equal priority",
		},
		{
			name: "HigherPriorityDenyWins",
			policies: []*CompiledPolicy{
				{
					Name: "high-deny", Namespace: "default", Priority: 200,
					Rules: []*CompiledRule{
						{Name: "deny-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
							Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}},
					},
				},
				{
					Name: "low-allow", Namespace: "default", Priority: 100,
					Rules: []*CompiledRule{
						{Name: "allow-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
							Action: CompiledAction{Type: v1alpha1.ActionTypeAllow}},
					},
				},
			},
			wantAction: v1alpha1.ActionTypeDeny,
			desc:       "higher priority deny wins",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver := NewPolicyCompositionResolver()
			event := &PolicyEvent{
				Category:    "llm",
				Subcategory: "llm_request",
				Namespace:   "default",
				Fields:      map[string]interface{}{},
			}

			result, err := resolver.EvaluateAll(tc.policies, event)
			if err != nil {
				t.Fatalf("EvaluateAll() error: %v", err)
			}

			effective := result.EffectiveAction()
			if effective.Type != tc.wantAction {
				t.Errorf("EffectiveAction().Type = %q, want %q (%s)",
					effective.Type, tc.wantAction, tc.desc)
			}
		})
	}
}

func TestEvaluateAll_HigherPriorityAllowWins(t *testing.T) {
	resolver := NewPolicyCompositionResolver()
	policies := []*CompiledPolicy{
		{
			Name: "high-allow", Namespace: "default", Priority: 200,
			Rules: []*CompiledRule{
				{Name: "allow-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
					Action: CompiledAction{Type: v1alpha1.ActionTypeAllow}},
			},
		},
		{
			Name: "low-deny", Namespace: "default", Priority: 100,
			Rules: []*CompiledRule{
				{Name: "deny-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
					Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "llm",
		Subcategory: "llm_request",
		Namespace:   "default",
		Fields:      map[string]interface{}{},
	}

	result, err := resolver.EvaluateAll(policies, event)
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}

	if len(result.Decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(result.Decisions))
	}

	// Higher priority allow (200) must beat lower priority deny (100).
	// Deny-first only applies within the same priority tier (FR-3).
	effective := result.EffectiveAction()
	if effective.Type != v1alpha1.ActionTypeAllow {
		t.Errorf("EffectiveAction().Type = %q, want %q (higher priority allow wins)",
			effective.Type, v1alpha1.ActionTypeAllow)
	}
}

func TestEvaluateAll_NonTerminalCollected(t *testing.T) {
	resolver := NewPolicyCompositionResolver()
	policies := []*CompiledPolicy{
		{
			Name: "alert-pol", Namespace: "default", Priority: 100,
			Rules: []*CompiledRule{
				{Name: "alert-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
					Action: CompiledAction{Type: v1alpha1.ActionTypeAlert}},
			},
		},
		{
			Name: "deny-pol", Namespace: "default", Priority: 100,
			Rules: []*CompiledRule{
				{Name: "deny-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
					Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "llm",
		Subcategory: "llm_request",
		Namespace:   "default",
		Fields:      map[string]interface{}{},
	}

	result, err := resolver.EvaluateAll(policies, event)
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}

	if len(result.Decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(result.Decisions))
	}

	nonTerminal := result.NonTerminalDecisions()
	if len(nonTerminal) != 1 {
		t.Errorf("expected 1 non-terminal decision, got %d", len(nonTerminal))
	}
}

func TestEvaluateAll_RateLimitClassified(t *testing.T) {
	resolver := NewPolicyCompositionResolver()
	policies := []*CompiledPolicy{
		{
			Name: "rate-pol", Namespace: "default", Priority: 100,
			Rules: []*CompiledRule{
				{Name: "rate-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
					Action: CompiledAction{Type: v1alpha1.ActionTypeRateLimit, Parameters: map[string]string{"burstSize": "10"}}},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "llm",
		Subcategory: "llm_request",
		Namespace:   "default",
		Fields:      map[string]interface{}{},
	}

	result, err := resolver.EvaluateAll(policies, event)
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}

	rateControl := result.RateControlDecisions()
	if len(rateControl) != 1 {
		t.Fatalf("expected 1 rate control decision, got %d", len(rateControl))
	}
}

func TestEvaluateAll_EmptyPolicies(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	event := &PolicyEvent{
		Category:    "llm",
		Subcategory: "llm_request",
		Namespace:   "default",
		Fields:      map[string]interface{}{},
	}

	result, err := resolver.EvaluateAll(nil, event)
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}

	if !result.DefaultAllow {
		t.Error("expected DefaultAllow=true for empty policies")
	}

	effective := result.EffectiveAction()
	if effective.Type != v1alpha1.ActionTypeAllow {
		t.Errorf("EffectiveAction().Type = %q, want %q", effective.Type, v1alpha1.ActionTypeAllow)
	}
}

func TestEvaluateAll_AuditModeFlagPreserved(t *testing.T) {
	resolver := NewPolicyCompositionResolver()
	policies := []*CompiledPolicy{
		{
			Name: "audit-pol", Namespace: "default", Priority: 100,
			EnforcementMode: v1alpha1.EnforcementModeAudit,
			Rules: []*CompiledRule{
				{Name: "deny-rule", TriggerLayer: "llm", TriggerEvent: "llm_request",
					Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "llm",
		Subcategory: "llm_request",
		Namespace:   "default",
		Fields:      map[string]interface{}{},
	}

	result, err := resolver.EvaluateAll(policies, event)
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}

	if len(result.Decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(result.Decisions))
	}
	if !result.Decisions[0].AuditOnly {
		t.Error("expected AuditOnly=true for audit-mode policy decision")
	}
}

// keyTrackingCounter records per-key call counts for testing groupBy behavior.
type keyTrackingCounter struct {
	counts map[string]int
}

func newKeyTrackingCounter() *keyTrackingCounter {
	return &keyTrackingCounter{counts: make(map[string]int)}
}

func (c *keyTrackingCounter) IncrementAndCheck(key string, limit int) bool {
	c.counts[key]++
	return c.counts[key] > limit
}

func TestRateLimitCheck_GroupByAgent(t *testing.T) {
	counter := newKeyTrackingCounter()
	resolver := NewPolicyCompositionResolverWithRateLimit(counter)

	policies := []*CompiledPolicy{
		{
			Name:      "agent-rate",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "agent-limit",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: v1alpha1.ActionTypeRateLimit,
						Parameters: map[string]string{
							"burstSize": "2",
							"groupBy":   "agent",
						},
					},
				},
			},
		},
	}

	// Two different tools from the same agent should share one counter
	event1 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		PodName:     "agent-pod-1",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		PodName:     "agent-pod-1",
		Fields:      map[string]interface{}{"toolName": "read_file"},
	}

	_, _ = resolver.Evaluate(policies, event1) // count 1
	_, _ = resolver.Evaluate(policies, event2) // count 2 (same agent key)

	// 3rd request from same agent should exceed limit=2
	decision, _ := resolver.Evaluate(policies, event1)
	if !decision.Matched {
		t.Error("expected rate limit exceeded for agent-based grouping after 3 requests")
	}

	// Verify both tools used the same counter key
	if len(counter.counts) != 1 {
		t.Errorf("expected 1 counter key (agent-based), got %d keys: %v", len(counter.counts), counter.counts)
	}
}

func TestRateLimitCheck_GroupByTool(t *testing.T) {
	counter := newKeyTrackingCounter()
	resolver := NewPolicyCompositionResolverWithRateLimit(counter)

	policies := []*CompiledPolicy{
		{
			Name:      "tool-rate",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "tool-limit",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: v1alpha1.ActionTypeRateLimit,
						Parameters: map[string]string{
							"burstSize": "2",
							"groupBy":   "tool",
						},
					},
				},
			},
		},
	}

	// Same agent, different tools should have independent counters
	eventBash := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		PodName:     "agent-pod-1",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}
	eventRead := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		PodName:     "agent-pod-1",
		Fields:      map[string]interface{}{"toolName": "read_file"},
	}

	_, _ = resolver.Evaluate(policies, eventBash) // bash count 1
	_, _ = resolver.Evaluate(policies, eventBash) // bash count 2
	_, _ = resolver.Evaluate(policies, eventRead) // read_file count 1

	// bash should now exceed limit
	bashDecision, _ := resolver.Evaluate(policies, eventBash)
	if !bashDecision.Matched {
		t.Error("expected rate limit exceeded for bash (3 > 2)")
	}

	// read_file should still be within limit
	readDecision, _ := resolver.Evaluate(policies, eventRead)
	if readDecision.Matched && readDecision.Action.Type == v1alpha1.ActionTypeRateLimit {
		t.Error("expected read_file to still be within limit (2 <= 2)")
	}

	// Verify two separate counter keys
	if len(counter.counts) != 2 {
		t.Errorf("expected 2 counter keys (tool-based), got %d keys: %v", len(counter.counts), counter.counts)
	}
}

func TestRateLimitCheck_GroupByAgentTool(t *testing.T) {
	counter := newKeyTrackingCounter()
	resolver := NewPolicyCompositionResolverWithRateLimit(counter)

	policies := []*CompiledPolicy{
		{
			Name:      "agenttool-rate",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "agenttool-limit",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: v1alpha1.ActionTypeRateLimit,
						Parameters: map[string]string{
							"burstSize": "1",
							"groupBy":   "agent+tool",
						},
					},
				},
			},
		},
	}

	// Same agent + same tool share a counter, different agent or tool is independent
	event1 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		PodName:     "agent-1",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		PodName:     "agent-2",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}

	_, _ = resolver.Evaluate(policies, event1) // agent-1/bash count 1

	// agent-1/bash should now exceed limit=1
	decision1, _ := resolver.Evaluate(policies, event1)
	if !decision1.Matched {
		t.Error("expected rate limit exceeded for agent-1/bash (2 > 1)")
	}

	// agent-2/bash should still be within limit (different agent)
	decision2, _ := resolver.Evaluate(policies, event2)
	if decision2.Matched && decision2.Action.Type == v1alpha1.ActionTypeRateLimit {
		t.Error("expected agent-2/bash to be within limit (independent counter)")
	}
}

func TestRateLimitCheck_DefaultGroupByAgent(t *testing.T) {
	counter := newKeyTrackingCounter()
	resolver := NewPolicyCompositionResolverWithRateLimit(counter)

	policies := []*CompiledPolicy{
		{
			Name:      "default-rate",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "default-limit",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: v1alpha1.ActionTypeRateLimit,
						Parameters: map[string]string{
							"burstSize": "2",
							// No groupBy — should default to "agent"
						},
					},
				},
			},
		},
	}

	// Different tools from same agent should share counter (agent-based default)
	event1 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		PodName:     "agent-pod",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		PodName:     "agent-pod",
		Fields:      map[string]interface{}{"toolName": "read_file"},
	}

	_, _ = resolver.Evaluate(policies, event1) // count 1
	_, _ = resolver.Evaluate(policies, event2) // count 2 (same agent key)

	// 3rd request should exceed limit
	decision, _ := resolver.Evaluate(policies, event1)
	if !decision.Matched {
		t.Error("expected rate limit exceeded with default agent-based grouping")
	}

	// Verify single counter key (agent-based)
	if len(counter.counts) != 1 {
		t.Errorf("expected 1 counter key (default agent grouping), got %d keys: %v", len(counter.counts), counter.counts)
	}
}
