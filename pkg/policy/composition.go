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
	"sort"
	"time"
)

// PolicyCompositionResolver evaluates multiple compiled policies against
// a single event, applying composition rules: priority ordering,
// namespace > cluster specificity, and explicit allow override.
type PolicyCompositionResolver struct{}

// NewPolicyCompositionResolver creates a new PolicyCompositionResolver.
func NewPolicyCompositionResolver() *PolicyCompositionResolver {
	return &PolicyCompositionResolver{}
}

// Evaluate evaluates the given event against all provided compiled policies
// using the composition rules defined in FR-6. Returns a Decision from the
// highest-priority matching policy/rule.
//
// Composition rules:
//   - Policies are sorted by descending priority.
//   - At equal priority, namespace-scoped policies beat cluster-scoped.
//   - At equal priority and scope, alphabetical policy name breaks ties.
//   - Within a policy, rules are evaluated top-to-bottom (first match wins).
//   - Across policies at equal priority, explicit "allow" overrides "deny".
//   - If no rule matches, a default "allow" decision is returned.
func (r *PolicyCompositionResolver) Evaluate(policies []*CompiledPolicy, event *PolicyEvent) (*Decision, error) {
	start := time.Now()

	if len(policies) == 0 {
		d := DefaultAllowDecision()
		d.EvaluationDuration = time.Since(start)
		return d, nil
	}

	// Sort policies by priority (descending), then namespace > cluster,
	// then alphabetical name.
	sorted := make([]*CompiledPolicy, len(policies))
	copy(sorted, policies)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority > sorted[j].Priority
		}
		// At equal priority: namespace-scoped beats cluster-scoped
		if sorted[i].IsClusterScoped != sorted[j].IsClusterScoped {
			return !sorted[i].IsClusterScoped
		}
		// At equal priority and scope: alphabetical name
		return sorted[i].Name < sorted[j].Name
	})

	// Group policies by priority level for allow-override logic
	var allTrace []PredicateTraceEntry

	// Evaluate each policy in sorted order using decision trees.
	// At equal priority, collect all matches and apply allow-override.
	type candidateDecision struct {
		decision *Decision
		policy   *CompiledPolicy
	}

	var matchPriority int32
	var candidates []candidateDecision
	hasMatch := false

	for _, pol := range sorted {
		if hasMatch && pol.Priority < matchPriority {
			// We already have match(es) at a higher priority — stop.
			break
		}

		dt := NewDecisionTree(pol)
		decision, err := dt.Evaluate(event)
		if err != nil {
			return nil, err
		}

		allTrace = append(allTrace, decision.PredicateTrace...)

		if decision.Matched {
			if !hasMatch {
				hasMatch = true
				matchPriority = pol.Priority
			}
			candidates = append(candidates, candidateDecision{
				decision: decision,
				policy:   pol,
			})
		}
	}

	if len(candidates) == 0 {
		d := DefaultAllowDecision()
		d.EvaluationDuration = time.Since(start)
		d.PredicateTrace = allTrace
		return d, nil
	}

	// If there's only one candidate, use it directly
	if len(candidates) == 1 {
		candidates[0].decision.EvaluationDuration = time.Since(start)
		candidates[0].decision.PredicateTrace = allTrace
		return candidates[0].decision, nil
	}

	// Multiple candidates at same priority — apply allow-override.
	// An explicit "allow" at equal priority overrides "deny".
	best := candidates[0].decision
	for _, c := range candidates {
		if c.decision.Action.Type == "allow" {
			best = c.decision
			break
		}
	}

	best.EvaluationDuration = time.Since(start)
	best.PredicateTrace = allTrace
	return best, nil
}
