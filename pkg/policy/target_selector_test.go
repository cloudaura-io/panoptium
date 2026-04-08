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
	"testing"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Test: Policy with TargetSelector={app:web} only matches events with PodLabels={app:web}.
func TestTargetSelector_MatchLabelsFiltering(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "web-policy",
			Namespace: "default",
			Priority:  100,
			TargetSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
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

	// Event from a pod that matches the selector
	matchingEvent := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		PodName:     "web-pod",
		PodLabels:   map[string]string{"app": "web", "version": "v1"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, matchingEvent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for event with matching PodLabels")
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny, got %q", decision.Action.Type)
	}

	// Event from a pod that does NOT match the selector
	nonMatchingEvent := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		PodName:     "api-pod",
		PodLabels:   map[string]string{"app": "api"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision2, err := resolver.Evaluate(policies, nonMatchingEvent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for event with non-matching PodLabels")
	}
	if decision2.Action.Type != v1alpha1.ActionTypeAllow {
		t.Errorf("expected default allow, got %q", decision2.Action.Type)
	}
}

// Test: Policy with empty TargetSelector matches all events.
func TestTargetSelector_EmptySelectorMatchesAll(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:           "catch-all-policy",
			Namespace:      "default",
			Priority:       100,
			TargetSelector: nil, // nil = matches all
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

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		PodName:     "any-pod",
		PodLabels:   map[string]string{"app": "anything"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match — empty TargetSelector should match all events")
	}

	// Also test with empty LabelSelector struct
	policies[0].TargetSelector = &metav1.LabelSelector{}
	decision2, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision2.Matched {
		t.Error("expected match — empty LabelSelector{} should match all events")
	}
}

// Test: MatchExpressions support (In, NotIn, Exists, DoesNotExist operators).
func TestTargetSelector_MatchExpressions(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	tests := []struct {
		name        string
		selector    *metav1.LabelSelector
		podLabels   map[string]string
		expectMatch bool
	}{
		{
			name: "In operator matches",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend", "backend"}},
				},
			},
			podLabels:   map[string]string{"tier": "frontend"},
			expectMatch: true,
		},
		{
			name: "In operator does not match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend", "backend"}},
				},
			},
			podLabels:   map[string]string{"tier": "database"},
			expectMatch: false,
		},
		{
			name: "NotIn operator matches",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"staging"}},
				},
			},
			podLabels:   map[string]string{"env": "production"},
			expectMatch: true,
		},
		{
			name: "NotIn operator does not match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"staging"}},
				},
			},
			podLabels:   map[string]string{"env": "staging"},
			expectMatch: false,
		},
		{
			name: "Exists operator matches",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "monitored", Operator: metav1.LabelSelectorOpExists},
				},
			},
			podLabels:   map[string]string{"monitored": "true"},
			expectMatch: true,
		},
		{
			name: "Exists operator does not match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "monitored", Operator: metav1.LabelSelectorOpExists},
				},
			},
			podLabels:   map[string]string{"app": "web"},
			expectMatch: false,
		},
		{
			name: "DoesNotExist operator matches",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "excluded", Operator: metav1.LabelSelectorOpDoesNotExist},
				},
			},
			podLabels:   map[string]string{"app": "web"},
			expectMatch: true,
		},
		{
			name: "DoesNotExist operator does not match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "excluded", Operator: metav1.LabelSelectorOpDoesNotExist},
				},
			},
			podLabels:   map[string]string{"excluded": "true"},
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies := []*CompiledPolicy{
				{
					Name:           "test-policy",
					Namespace:      "default",
					Priority:       100,
					TargetSelector: tt.selector,
					Rules: []*CompiledRule{
						{
							Name:         "test-rule",
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
				PodLabels:   tt.podLabels,
				Fields:      map[string]interface{}{},
			}

			decision, err := resolver.Evaluate(policies, event)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectMatch && !decision.Matched {
				t.Error("expected match, but no rule matched")
			}
			if !tt.expectMatch && decision.Matched {
				t.Error("expected no match, but got a match")
			}
		})
	}
}

// Test: Cluster-scoped policy without TargetSelector matches all namespaces.
func TestTargetSelector_ClusterPolicyNoSelectorMatchesAll(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "cluster-default",
			Namespace:       "",
			Priority:        50,
			IsClusterScoped: true,
			TargetSelector:  nil, // No selector — matches everything
			Rules: []*CompiledRule{
				{
					Name:         "cluster-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	// Event from namespace "production"
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "production",
		PodName:     "prod-pod",
		PodLabels:   map[string]string{"app": "api"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match — cluster policy without selector should match all namespaces")
	}
}

// Test: Mixed scenario — namespace policy with selector + cluster policy without selector.
func TestTargetSelector_MixedNamespaceAndCluster(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "cluster-default",
			Namespace:       "",
			Priority:        50,
			IsClusterScoped: true,
			TargetSelector:  nil, // matches all
			Rules: []*CompiledRule{
				{
					Name:         "cluster-alert",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
		{
			Name:      "ns-deny",
			Namespace: "default",
			Priority:  100,
			TargetSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			Rules: []*CompiledRule{
				{
					Name:         "ns-deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	// Event with matching labels — should match both, ns-deny wins due to higher priority
	matchingEvent := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		PodName:     "web-pod",
		PodLabels:   map[string]string{"app": "web"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, matchingEvent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny from ns-deny (higher priority), got %q", decision.Action.Type)
	}
	if decision.PolicyName != "ns-deny" {
		t.Errorf("expected ns-deny, got %q", decision.PolicyName)
	}

	// Event with non-matching labels — only cluster policy matches
	nonMatchingEvent := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		PodName:     "api-pod",
		PodLabels:   map[string]string{"app": "api"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision2, err := resolver.Evaluate(policies, nonMatchingEvent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision2.Matched {
		t.Error("expected match from cluster policy for non-matching ns labels")
	}
	if decision2.PolicyName != "cluster-default" {
		t.Errorf("expected cluster-default, got %q", decision2.PolicyName)
	}
	if decision2.Action.Type != "alert" {
		t.Errorf("expected alert from cluster policy, got %q", decision2.Action.Type)
	}
}
