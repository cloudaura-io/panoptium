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
	"strconv"
	"time"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

// RateLimitCounter is an interface for rate limit checking. Implementations
// atomically record an event and report whether the count for the given key
// exceeds the specified limit within a sliding time window.
type RateLimitCounter interface {
	// IncrementAndCheck records an event for key and returns true if the
	// count now exceeds limit.
	IncrementAndCheck(key string, limit int) bool
}

// PolicyCompositionResolver evaluates multiple compiled policies against
// a single event, applying composition rules: priority ordering,
// namespace > cluster specificity, and explicit allow override.
type PolicyCompositionResolver struct {
	// rateLimitCounter is the shared sliding window counter for rate limiting.
	// When nil, rateLimit action decisions are returned as-is (always match).
	rateLimitCounter RateLimitCounter
}

// NewPolicyCompositionResolver creates a new PolicyCompositionResolver.
func NewPolicyCompositionResolver() *PolicyCompositionResolver {
	return &PolicyCompositionResolver{}
}

// NewPolicyCompositionResolverWithRateLimit creates a new PolicyCompositionResolver
// with a shared RateLimitCounter for rate limit evaluation.
func NewPolicyCompositionResolverWithRateLimit(counter RateLimitCounter) *PolicyCompositionResolver {
	return &PolicyCompositionResolver{
		rateLimitCounter: counter,
	}
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

	// Filter policies by TargetSelector — only policies whose selector
	// matches the event's PodLabels are evaluated.
	policies = filterByTargetSelector(policies, event)

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
	var best *Decision
	if len(candidates) == 1 {
		best = candidates[0].decision
	} else {
		// Multiple candidates at same priority — apply allow-override.
		// An explicit "allow" at equal priority overrides "deny".
		best = candidates[0].decision
		for _, c := range candidates {
			if c.decision.Action.Type == "allow" {
				best = c.decision
				break
			}
		}
	}

	// Post-match rate limit check: if the matched rule has a rateLimit action
	// and we have a counter, check whether the rate limit is actually exceeded.
	// If under the limit, convert the decision to a pass-through (allow).
	if best.Action.Type == v1alpha1.ActionTypeRateLimit && r.rateLimitCounter != nil {
		best = r.applyRateLimitCheck(best, event)
	}

	best.EvaluationDuration = time.Since(start)
	best.PredicateTrace = allTrace
	return best, nil
}

// applyRateLimitCheck performs a post-match rate limit evaluation. It extracts
// the burstSize from the decision's action parameters, builds a counter key
// from the policy/rule name and event's toolName field, and atomically
// increments and checks the counter. If the count is within the burst limit,
// a default allow decision is returned (pass-through). If the count exceeds
// the limit, the original rate-limit decision is returned unchanged.
func (r *PolicyCompositionResolver) applyRateLimitCheck(decision *Decision, event *PolicyEvent) *Decision {
	// Extract burst limit from action parameters
	burstSize := 0
	if v, ok := decision.Action.Parameters["burstSize"]; ok {
		if parsed, err := strconv.Atoi(v); err == nil {
			burstSize = parsed
		}
	}
	// Fall back to requestsPerMinute if burstSize is not set
	if burstSize == 0 {
		if v, ok := decision.Action.Parameters["requestsPerMinute"]; ok {
			if parsed, err := strconv.Atoi(v); err == nil {
				burstSize = parsed
			}
		}
	}
	if burstSize == 0 {
		// No limit configured — pass through
		return DefaultAllowDecision()
	}

	// Build a counter key scoped to the policy+rule and the event's toolName.
	// This ensures different rules and different tools have independent counters.
	toolName := event.GetStringField("toolName")
	key := decision.PolicyName + "/" + decision.MatchedRule + "/" + toolName

	exceeded := r.rateLimitCounter.IncrementAndCheck(key, burstSize)
	if !exceeded {
		// Under the limit — allow the request
		return DefaultAllowDecision()
	}
	// Over the limit — return the original rateLimit decision (triggers 429)
	return decision
}

// filterByTargetSelector returns only the policies whose TargetSelector matches
// the event's PodLabels. Policies with a nil or empty TargetSelector match all pods.
func filterByTargetSelector(policies []*CompiledPolicy, event *PolicyEvent) []*CompiledPolicy {
	podLabels := labels.Set(event.PodLabels)
	filtered := make([]*CompiledPolicy, 0, len(policies))

	for _, pol := range policies {
		if matchesTargetSelector(pol, podLabels) {
			filtered = append(filtered, pol)
		}
	}
	return filtered
}

// matchesTargetSelector checks if a policy's TargetSelector matches the given labels.
// A nil or empty selector matches all labels (wildcard).
func matchesTargetSelector(pol *CompiledPolicy, podLabels labels.Set) bool {
	if pol.TargetSelector == nil {
		return true
	}
	if len(pol.TargetSelector.MatchLabels) == 0 && len(pol.TargetSelector.MatchExpressions) == 0 {
		return true
	}

	// Build a selector from the LabelSelector
	selector := labels.NewSelector()

	// Add MatchLabels requirements
	for key, value := range pol.TargetSelector.MatchLabels {
		req, err := labels.NewRequirement(key, selection.Equals, []string{value})
		if err != nil {
			// Invalid requirement — skip this policy (fail-closed)
			return false
		}
		selector = selector.Add(*req)
	}

	// Add MatchExpressions requirements
	for _, expr := range pol.TargetSelector.MatchExpressions {
		var op selection.Operator
		switch expr.Operator {
		case "In":
			op = selection.In
		case "NotIn":
			op = selection.NotIn
		case "Exists":
			op = selection.Exists
		case "DoesNotExist":
			op = selection.DoesNotExist
		default:
			// Unknown operator — fail-closed
			return false
		}
		req, err := labels.NewRequirement(expr.Key, op, expr.Values)
		if err != nil {
			return false
		}
		selector = selector.Add(*req)
	}

	return selector.Matches(podLabels)
}
