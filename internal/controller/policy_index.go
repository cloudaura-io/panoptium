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
	"fmt"
	"sort"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PriorityConflict represents a conflict between two policies that have the same
// priority and overlapping target selectors.
type PriorityConflict struct {
	// PolicyA is the name of the first conflicting policy.
	PolicyA string

	// PolicyB is the name of the second conflicting policy.
	PolicyB string

	// Priority is the shared priority value.
	Priority int32

	// OverlappingLabels contains the label key=value pairs that overlap.
	OverlappingLabels []string
}

// SortPoliciesByPriority sorts policies in descending order by priority.
// Higher priority policies appear first in the slice.
func SortPoliciesByPriority(policies []panoptiumiov1alpha1.PanoptiumPolicy) {
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Spec.Priority > policies[j].Spec.Priority
	})
}

// DetectPriorityConflicts identifies policies with the same priority and
// overlapping target selectors. Returns a list of conflicts found.
func DetectPriorityConflicts(policies []panoptiumiov1alpha1.PanoptiumPolicy) []PriorityConflict {
	var conflicts []PriorityConflict

	for i := 0; i < len(policies); i++ {
		for j := i + 1; j < len(policies); j++ {
			if policies[i].Spec.Priority != policies[j].Spec.Priority {
				continue
			}

			overlap := findSelectorOverlap(
				policies[i].Spec.TargetSelector,
				policies[j].Spec.TargetSelector,
			)

			if len(overlap) > 0 {
				conflicts = append(conflicts, PriorityConflict{
					PolicyA:           policies[i].Name,
					PolicyB:           policies[j].Name,
					Priority:          policies[i].Spec.Priority,
					OverlappingLabels: overlap,
				})
			}
		}
	}

	return conflicts
}

// findSelectorOverlap returns the list of overlapping label key=value pairs
// between two label selectors. Only matchLabels are considered.
func findSelectorOverlap(a, b metav1.LabelSelector) []string {
	var overlap []string
	for k, v := range a.MatchLabels {
		if bv, ok := b.MatchLabels[k]; ok && bv == v {
			overlap = append(overlap, fmt.Sprintf("%s=%s", k, v))
		}
	}
	return overlap
}

// ExtractTargetSelectorKeys returns sorted label key=value strings from a LabelSelector.
// Used for indexing policies by their target selectors.
func ExtractTargetSelectorKeys(selector metav1.LabelSelector) []string {
	keys := make([]string, 0, len(selector.MatchLabels))
	for k, v := range selector.MatchLabels {
		keys = append(keys, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(keys)
	return keys
}
