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

package controller

import (
	"sort"
	"testing"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSortPoliciesByPriority verifies that policies are sorted in descending priority order.
func TestSortPoliciesByPriority(t *testing.T) {
	policies := []panoptiumiov1alpha1.AgentPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "low-priority"},
			Spec: panoptiumiov1alpha1.AgentPolicySpec{
				Priority: 10,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "high-priority"},
			Spec: panoptiumiov1alpha1.AgentPolicySpec{
				Priority: 500,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "medium-priority"},
			Spec: panoptiumiov1alpha1.AgentPolicySpec{
				Priority: 100,
			},
		},
	}

	SortPoliciesByPriority(policies)

	if policies[0].Name != "high-priority" {
		t.Errorf("policies[0].Name = %q, want %q", policies[0].Name, "high-priority")
	}
	if policies[1].Name != "medium-priority" {
		t.Errorf("policies[1].Name = %q, want %q", policies[1].Name, "medium-priority")
	}
	if policies[2].Name != "low-priority" {
		t.Errorf("policies[2].Name = %q, want %q", policies[2].Name, "low-priority")
	}
}

// TestDetectPriorityConflicts verifies conflict detection for overlapping policies.
func TestDetectPriorityConflicts(t *testing.T) {
	tests := []struct {
		name         string
		policies     []panoptiumiov1alpha1.AgentPolicy
		wantConflict bool
	}{
		{
			name: "no conflict different priorities",
			policies: []panoptiumiov1alpha1.AgentPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-a", Namespace: "default"},
					Spec: panoptiumiov1alpha1.AgentPolicySpec{
						Priority: 100,
						TargetSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "agent"},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-b", Namespace: "default"},
					Spec: panoptiumiov1alpha1.AgentPolicySpec{
						Priority: 200,
						TargetSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "agent"},
						},
					},
				},
			},
			wantConflict: false,
		},
		{
			name: "conflict same priority overlapping selector",
			policies: []panoptiumiov1alpha1.AgentPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-a", Namespace: "default"},
					Spec: panoptiumiov1alpha1.AgentPolicySpec{
						Priority: 100,
						TargetSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "agent"},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-b", Namespace: "default"},
					Spec: panoptiumiov1alpha1.AgentPolicySpec{
						Priority: 100,
						TargetSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "agent"},
						},
					},
				},
			},
			wantConflict: true,
		},
		{
			name: "no conflict same priority different selectors",
			policies: []panoptiumiov1alpha1.AgentPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-a", Namespace: "default"},
					Spec: panoptiumiov1alpha1.AgentPolicySpec{
						Priority: 100,
						TargetSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "agent-a"},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-b", Namespace: "default"},
					Spec: panoptiumiov1alpha1.AgentPolicySpec{
						Priority: 100,
						TargetSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "agent-b"},
						},
					},
				},
			},
			wantConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflicts := DetectPriorityConflicts(tt.policies)
			gotConflict := len(conflicts) > 0
			if gotConflict != tt.wantConflict {
				t.Errorf("DetectPriorityConflicts() conflict = %v, want %v", gotConflict, tt.wantConflict)
			}
		})
	}
}

// TestExtractTargetSelectorKeys verifies label key extraction from targetSelector.
func TestExtractTargetSelectorKeys(t *testing.T) {
	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app":  "agent",
			"tier": "backend",
		},
	}

	keys := ExtractTargetSelectorKeys(selector)
	sort.Strings(keys)

	if len(keys) != 2 {
		t.Fatalf("ExtractTargetSelectorKeys() returned %d keys, want 2", len(keys))
	}
	if keys[0] != "app=agent" {
		t.Errorf("keys[0] = %q, want %q", keys[0], "app=agent")
	}
	if keys[1] != "tier=backend" {
		t.Errorf("keys[1] = %q, want %q", keys[1], "tier=backend")
	}
}

// PriorityConflict represents a conflict between two policies at the same priority.
// (This type is expected to be defined in the production code.)
