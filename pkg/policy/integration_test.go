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

func TestIntegration_FullPipeline_RegexPredicate(t *testing.T) {
	policy := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "regex-integration",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "deny-tmp-scripts",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "file_open",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.path.matches("^/tmp/.*\.sh$")`},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}

	tree := NewDecisionTree(compiled)

	// Matching event.
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"path": "/tmp/exploit.sh"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("Decision.Matched = false, want true for regex matching event")
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, v1alpha1.ActionTypeDeny)
	}
	if decision.MatchedRule != "deny-tmp-scripts" {
		t.Errorf("Decision.MatchedRule = %q, want %q", decision.MatchedRule, "deny-tmp-scripts")
	}

	// Non-matching event.
	eventNoMatch := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"path": "/home/user/safe.txt"},
	}
	decisionNoMatch, err := tree.Evaluate(eventNoMatch)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if decisionNoMatch.Matched {
		t.Error("Decision.Matched = true, want false for non-matching regex event")
	}
}

func TestIntegration_FullPipeline_GlobPredicate(t *testing.T) {
	policy := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "glob-integration",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "deny-etc-writes",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "file_write",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.path.glob("/etc/**")`},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityCritical,
				},
			},
		},
	}

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}

	tree := NewDecisionTree(compiled)

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_write",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"path": "/etc/shadow"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("Decision.Matched = false, want true for glob matching event")
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, v1alpha1.ActionTypeDeny)
	}
}

func TestIntegration_FullPipeline_CIDRPredicate(t *testing.T) {
	policy := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cidr-integration",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "alert-external-egress",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "network",
						EventSubcategory: "egress_attempt",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.destinationIP.inCIDR("10.0.0.0/8")`},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			},
		},
	}

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}

	tree := NewDecisionTree(compiled)

	event := &PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"destinationIP": "10.42.0.5"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("Decision.Matched = false, want true for CIDR matching event")
	}
	if decision.Action.Type != v1alpha1.ActionTypeAlert {
		t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, v1alpha1.ActionTypeAlert)
	}
}

func TestIntegration_FullPipeline_EqualityPredicate(t *testing.T) {
	policy := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "equality-integration",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "deny-curl",
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

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}

	tree := NewDecisionTree(compiled)

	// Matching event.
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"processName": "curl"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("Decision.Matched = false, want true for equality matching event")
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, v1alpha1.ActionTypeDeny)
	}

	// Non-matching event.
	eventNoMatch := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"processName": "python"},
	}
	decisionNoMatch, err := tree.Evaluate(eventNoMatch)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if decisionNoMatch.Matched {
		t.Error("Decision.Matched = true, want false for non-matching equality event")
	}
}

func TestIntegration_FullPipeline_NoMatchDefaultAllow(t *testing.T) {
	policy := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-match-integration",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "deny-curl",
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

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}

	tree := NewDecisionTree(compiled)

	// Send a completely different event type.
	event := &PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"destinationIP": "8.8.8.8"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for no-match scenario")
	}
	if decision.Action.Type != "allow" {
		t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, "allow")
	}
	if decision.MatchedRuleIndex != -1 {
		t.Errorf("Decision.MatchedRuleIndex = %d, want -1", decision.MatchedRuleIndex)
	}
	if decision.PolicyName != "no-match-integration" {
		t.Errorf("Decision.PolicyName = %q, want %q", decision.PolicyName, "no-match-integration")
	}
}

func TestIntegration_FullPipeline_MultiRuleFirstMatchWins(t *testing.T) {
	policy := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-rule-integration",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "deny-curl",
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
				{
					Name: "alert-all-exec",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "process_exec",
					},
					// No predicates: matches any process_exec event.
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityLow,
				},
			},
		},
	}

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}

	tree := NewDecisionTree(compiled)

	t.Run("curl matches first rule (deny)", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"processName": "curl"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if decision.MatchedRule != "deny-curl" {
			t.Errorf("Decision.MatchedRule = %q, want %q", decision.MatchedRule, "deny-curl")
		}
		if decision.Action.Type != v1alpha1.ActionTypeDeny {
			t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, v1alpha1.ActionTypeDeny)
		}
		if decision.MatchedRuleIndex != 0 {
			t.Errorf("Decision.MatchedRuleIndex = %d, want 0", decision.MatchedRuleIndex)
		}
	})

	t.Run("python skips first rule, matches second (alert)", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"processName": "python"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if decision.MatchedRule != "alert-all-exec" {
			t.Errorf("Decision.MatchedRule = %q, want %q", decision.MatchedRule, "alert-all-exec")
		}
		if decision.Action.Type != v1alpha1.ActionTypeAlert {
			t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, v1alpha1.ActionTypeAlert)
		}
		if decision.MatchedRuleIndex != 1 {
			t.Errorf("Decision.MatchedRuleIndex = %d, want 1", decision.MatchedRuleIndex)
		}
	})
}

func TestIntegration_ConcurrencySafety(t *testing.T) {
	policy := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "concurrency-test",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "deny-curl",
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
				{
					Name: "alert-all-exec",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "process_exec",
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityLow,
				},
			},
		},
	}

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}

	tree := NewDecisionTree(compiled)

	const goroutines = 100
	var wg sync.WaitGroup
	errors := make(chan error, goroutines)
	results := make(chan *Decision, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Alternate between matching and non-matching events.
			var event *PolicyEvent
			if idx%2 == 0 {
				event = &PolicyEvent{
					Category:    "kernel",
					Subcategory: "process_exec",
					Timestamp:   time.Now(),
					Fields:      map[string]interface{}{"processName": "curl"},
				}
			} else {
				event = &PolicyEvent{
					Category:    "kernel",
					Subcategory: "process_exec",
					Timestamp:   time.Now(),
					Fields:      map[string]interface{}{"processName": "python"},
				}
			}
			decision, err := tree.Evaluate(event)
			if err != nil {
				errors <- err
				return
			}
			results <- decision
		}(i)
	}

	wg.Wait()
	close(errors)
	close(results)

	// Check for errors.
	for err := range errors {
		t.Errorf("Concurrent Evaluate() returned error: %v", err)
	}

	// Verify correctness of all results.
	i := 0
	for decision := range results {
		if !decision.Matched {
			t.Errorf("Goroutine result: Decision.Matched = false, want true (all events should match some rule)")
		}
		i++
	}
	if i != goroutines {
		t.Errorf("Received %d results, want %d", i, goroutines)
	}
}
