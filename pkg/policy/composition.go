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

// RateLimitCounter tracks event counts within sliding time windows.
type RateLimitCounter interface {
	// IncrementAndCheck records an event for key and returns true if the count exceeds limit.
	IncrementAndCheck(key string, limit int) bool
}

// PolicyCompositionResolver evaluates policies with deny-first semantics and priority ordering.
type PolicyCompositionResolver struct {
	// rateLimitCounter is the shared sliding window counter. Nil means rate limits always match.
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

// Evaluate returns the single winning decision from all policies using deny-first composition.
func (r *PolicyCompositionResolver) Evaluate(policies []*CompiledPolicy, event *PolicyEvent) (*Decision, error) {
	result, err := r.EvaluateAll(policies, event)
	if err != nil {
		return nil, err
	}

	if result.DefaultAllow || len(result.Decisions) == 0 {
		d := DefaultAllowDecision()
		d.EvaluationDuration = result.EvaluationDuration
		d.PredicateTrace = result.PredicateTrace
		return d, nil
	}

	// Find the best decision: terminal deny/quarantine at the highest
	// priority wins. At equal priority, deny beats allow (deny-first).
	var best *Decision
	for _, d := range result.Decisions {
		if d.Action.Type == v1alpha1.ActionTypeDeny || d.Action.Type == v1alpha1.ActionTypeQuarantine {
			best = d
			break // Decisions are sorted by priority, first deny wins
		}
	}

	// Check rate limit decisions
	if best == nil {
		for _, d := range result.Decisions {
			if d.Action.Type == v1alpha1.ActionTypeRateLimit {
				best = d
				break
			}
		}
	}

	// Fall back to the first matched decision
	if best == nil {
		best = result.Decisions[0]
	}

	best.EvaluationDuration = result.EvaluationDuration
	best.PredicateTrace = result.PredicateTrace
	return best, nil
}

// EvaluateAll evaluates the given event against ALL provided compiled policies
// and returns an EvaluationResult containing decisions from ALL matching
// policies across ALL priority tiers. This replaces the single-winner Evaluate
// for multi-phase evaluation with deny-first semantics.
//
// Unlike Evaluate, EvaluateAll does NOT stop at the first matching priority
// level. It evaluates every policy and collects all decisions.
func (r *PolicyCompositionResolver) EvaluateAll(
	policies []*CompiledPolicy, event *PolicyEvent,
) (*EvaluationResult, error) {
	start := time.Now()

	result := &EvaluationResult{}

	if len(policies) == 0 {
		result.DefaultAllow = true
		result.EvaluationDuration = time.Since(start)
		return result, nil
	}

	// Filter out disabled policies.
	policies = filterByEnforcementMode(policies)

	// Filter by target selector.
	policies = filterByTargetSelector(policies, event)

	if len(policies) == 0 {
		result.DefaultAllow = true
		result.EvaluationDuration = time.Since(start)
		return result, nil
	}

	// Sort policies by priority (descending), namespace > cluster, alphabetical.
	sorted := make([]*CompiledPolicy, len(policies))
	copy(sorted, policies)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority > sorted[j].Priority
		}
		if sorted[i].IsClusterScoped != sorted[j].IsClusterScoped {
			return !sorted[i].IsClusterScoped
		}
		return sorted[i].Name < sorted[j].Name
	})

	var allTrace []PredicateTraceEntry

	// Evaluate ALL policies (do not stop at first match).
	for _, pol := range sorted {
		dt := NewDecisionTree(pol)
		decision, err := dt.Evaluate(event)
		if err != nil {
			return nil, err
		}

		allTrace = append(allTrace, decision.PredicateTrace...)

		if decision.Matched {
			// Set AuditOnly flag if the source policy is in audit mode.
			if pol.EnforcementMode == v1alpha1.EnforcementModeAudit {
				decision.AuditOnly = true
			}

			// Set Priority from the source policy for priority-aware composition.
			decision.Priority = pol.Priority

			// Set Subcategory from event for action classification.
			decision.Subcategory = event.Subcategory

			// Set Severity from the matched rule.
			if decision.MatchedRuleIndex >= 0 && decision.MatchedRuleIndex < len(pol.Rules) {
				decision.Severity = string(pol.Rules[decision.MatchedRuleIndex].Severity)
			}

			// Post-match rate limit check.
			if decision.Action.Type == v1alpha1.ActionTypeRateLimit && r.rateLimitCounter != nil {
				decision = r.applyRateLimitCheck(decision, event)
			}

			result.Decisions = append(result.Decisions, decision)
		}
	}

	if len(result.Decisions) == 0 {
		result.DefaultAllow = true
	}

	result.PredicateTrace = allTrace
	result.EvaluationDuration = time.Since(start)
	return result, nil
}

// applyRateLimitCheck increments the counter keyed by groupBy and returns allow if under the limit.
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

	// Build counter key based on groupBy parameter
	groupBy := decision.Action.Parameters["groupBy"]
	if groupBy == "" {
		groupBy = "agent" // default
	}

	prefix := decision.PolicyName + "/" + decision.MatchedRule
	var key string

	switch groupBy {
	case "tool":
		toolName := event.GetStringField("toolName")
		key = prefix + "/" + toolName
	case "agent+tool":
		agentKey := rateLimitAgentKey(event)
		toolName := event.GetStringField("toolName")
		key = prefix + "/" + agentKey + "/" + toolName
	default: // "agent"
		agentKey := rateLimitAgentKey(event)
		key = prefix + "/" + agentKey
	}

	exceeded := r.rateLimitCounter.IncrementAndCheck(key, burstSize)
	if !exceeded {
		// Under the limit — allow the request
		return DefaultAllowDecision()
	}
	// Over the limit — return the original rateLimit decision (triggers 429)
	return decision
}

// rateLimitAgentKey returns the agent identity key for rate limiting.
// It uses PodName if available, falling back to sourceIP from event fields.
func rateLimitAgentKey(event *PolicyEvent) string {
	if event.PodName != "" {
		return event.PodName
	}
	return event.GetStringField("sourceIP")
}

// filterByEnforcementMode removes disabled policies from evaluation.
func filterByEnforcementMode(policies []*CompiledPolicy) []*CompiledPolicy {
	filtered := make([]*CompiledPolicy, 0, len(policies))
	for _, pol := range policies {
		if pol.EnforcementMode != v1alpha1.EnforcementModeDisabled {
			filtered = append(filtered, pol)
		}
	}
	return filtered
}

// filterByTargetSelector returns policies whose target selector and namespace scope match the event.
func filterByTargetSelector(policies []*CompiledPolicy, event *PolicyEvent) []*CompiledPolicy {
	podLabels := labels.Set(event.PodLabels)
	filtered := make([]*CompiledPolicy, 0, len(policies))

	for _, pol := range policies {
		// Namespace scoping: namespace-scoped policies only match pods
		// in their own namespace.
		if !pol.IsClusterScoped && pol.Namespace != event.Namespace {
			continue
		}

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
