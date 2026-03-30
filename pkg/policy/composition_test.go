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
					Action:       CompiledAction{Type: "allow"},
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
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != "deny" {
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
					Action:       CompiledAction{Type: "deny"},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.processName", Operator: "==", Value: "curl"},
					},
				},
				{
					Name:         "second-rule",
					Index:        1,
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "allow"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.MatchedRule != "first-rule" {
		t.Errorf("expected first-rule (first match), got %q", decision.MatchedRule)
	}
	if decision.Action.Type != "deny" {
		t.Errorf("expected deny, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_NamespaceOverridesCluster(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

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
					Action:       CompiledAction{Type: "deny"},
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
					Action:       CompiledAction{Type: "allow"},
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
	if decision.Action.Type != "allow" {
		t.Errorf("expected allow (namespace overrides cluster at equal priority), got %q", decision.Action.Type)
	}
	if decision.PolicyName != "namespace-policy" {
		t.Errorf("expected namespace-policy, got %q", decision.PolicyName)
	}
}

func TestPolicyComposition_ExplicitAllowOverridesDeny(t *testing.T) {
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
					Action:       CompiledAction{Type: "deny"},
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
					Action:       CompiledAction{Type: "allow"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != "allow" {
		t.Errorf("expected allow (explicit allow overrides deny at equal priority), got %q", decision.Action.Type)
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
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	// Evaluate multiple times and verify same result
	for i := 0; i < 10; i++ {
		decision, err := resolver.Evaluate(policies, event)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if decision.Action.Type != "deny" {
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
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("expected no match (no kernel rule), got match")
	}
	if decision.Action.Type != "allow" {
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
	if decision.Action.Type != "allow" {
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
					Action:       CompiledAction{Type: "deny"},
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
					Action:       CompiledAction{Type: "deny"},
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
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With same priority and both namespace-scoped, aaa-policy sorts first by name
	if decision.PolicyName != "aaa-policy" {
		t.Errorf("expected aaa-policy (alphabetical tiebreak), got %q", decision.PolicyName)
	}
}
