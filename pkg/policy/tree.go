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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DecisionTree is the evaluation engine for a single CompiledPolicy.
// It evaluates events against rules using first-match semantics.
type DecisionTree struct {
	policy *CompiledPolicy
}

// NewDecisionTree creates a DecisionTree from a CompiledPolicy.
func NewDecisionTree(policy *CompiledPolicy) *DecisionTree {
	return &DecisionTree{policy: policy}
}

// Evaluate evaluates a PolicyEvent against the decision tree and returns
// a Decision. It uses first-match semantics: the first rule whose trigger
// and predicates match the event determines the decision. If no rule matches,
// a default "allow" decision is returned.
func (dt *DecisionTree) Evaluate(event *PolicyEvent) (*Decision, error) {
	start := time.Now()

	var trace []PredicateTraceEntry

	for _, rule := range dt.policy.Rules {
		// Check trigger match.
		if !dt.matchesTrigger(rule, event) {
			continue
		}

		// Check all predicates (AND logic).
		allMatched := true
		for _, pred := range rule.Predicates {
			predStart := time.Now()
			matched, evalErr := dt.evaluatePredicate(rule, &pred, event)
			entry := PredicateTraceEntry{
				RuleName:     rule.Name,
				PredicateCEL: pred.RawCEL,
				Matched:      matched,
				Duration:     time.Since(predStart),
			}
			if evalErr != nil {
				entry.Error = evalErr.Error()
			}
			trace = append(trace, entry)

			if !matched {
				allMatched = false
				break
			}
		}

		if allMatched {
			return &Decision{
				Action:             rule.Action,
				Matched:            true,
				MatchedRule:        rule.Name,
				MatchedRuleIndex:   rule.Index,
				PolicyName:         dt.policy.Name,
				PolicyNamespace:    dt.policy.Namespace,
				EvaluationDuration: time.Since(start),
				PredicateTrace:     trace,
			}, nil
		}
	}

	// No rule matched — return default allow.
	d := DefaultAllowDecision()
	d.PolicyName = dt.policy.Name
	d.PolicyNamespace = dt.policy.Namespace
	d.EvaluationDuration = time.Since(start)
	d.PredicateTrace = trace
	return d, nil
}

// matchesTrigger checks if an event matches a rule's trigger.
func (dt *DecisionTree) matchesTrigger(rule *CompiledRule, event *PolicyEvent) bool {
	if rule.TriggerLayer != event.Category {
		return false
	}
	if rule.TriggerEvent == "" {
		// Empty subcategory means match all events in this layer.
		return true
	}
	return rule.TriggerEvent == event.Subcategory
}

// evaluatePredicate evaluates a single compiled predicate against an event.
func (dt *DecisionTree) evaluatePredicate(rule *CompiledRule, pred *CompiledPredicate, event *PolicyEvent) (bool, error) {
	switch pred.Operator {
	case "==":
		return dt.evalEquality(pred, event)
	case "!=":
		matched, err := dt.evalEquality(pred, event)
		return !matched, err
	case ">":
		return dt.evalNumericComparison(pred, event, func(a, b float64) bool { return a > b })
	case "<":
		return dt.evalNumericComparison(pred, event, func(a, b float64) bool { return a < b })
	case "matches":
		return dt.evalRegex(rule, pred, event)
	case "glob":
		return dt.evalGlob(rule, pred, event)
	case "inCIDR":
		return dt.evalCIDR(rule, pred, event)
	case "raw":
		// Raw CEL expressions are passed through as-is; for now they match.
		return true, nil
	default:
		return false, fmt.Errorf("unknown predicate operator %q", pred.Operator)
	}
}

// evalEquality evaluates a string equality predicate.
func (dt *DecisionTree) evalEquality(pred *CompiledPredicate, event *PolicyEvent) (bool, error) {
	fieldValue := dt.resolveField(pred.FieldPath, event)
	return fmt.Sprint(fieldValue) == pred.Value, nil
}

// evalNumericComparison evaluates a numeric comparison predicate.
func (dt *DecisionTree) evalNumericComparison(pred *CompiledPredicate, event *PolicyEvent, cmp func(float64, float64) bool) (bool, error) {
	fieldValue := dt.resolveField(pred.FieldPath, event)
	var actual float64
	switch v := fieldValue.(type) {
	case int:
		actual = float64(v)
	case int64:
		actual = float64(v)
	case float64:
		actual = v
	default:
		return false, nil
	}

	expected, err := strconv.ParseFloat(pred.Value, 64)
	if err != nil {
		return false, fmt.Errorf("invalid numeric value %q: %w", pred.Value, err)
	}

	return cmp(actual, expected), nil
}

// evalRegex evaluates a regex predicate using pre-compiled patterns.
func (dt *DecisionTree) evalRegex(rule *CompiledRule, pred *CompiledPredicate, event *PolicyEvent) (bool, error) {
	re, ok := rule.CompiledRegexes[pred.Value]
	if !ok {
		return false, fmt.Errorf("pre-compiled regex not found for pattern %q", pred.Value)
	}
	fieldValue := dt.resolveField(pred.FieldPath, event)
	return re.MatchString(fmt.Sprint(fieldValue)), nil
}

// evalGlob evaluates a glob predicate using pre-compiled patterns.
func (dt *DecisionTree) evalGlob(rule *CompiledRule, pred *CompiledPredicate, event *PolicyEvent) (bool, error) {
	g, ok := rule.CompiledGlobs[pred.Value]
	if !ok {
		return false, fmt.Errorf("pre-compiled glob not found for pattern %q", pred.Value)
	}
	fieldValue := dt.resolveField(pred.FieldPath, event)
	return g.Match(fmt.Sprint(fieldValue)), nil
}

// evalCIDR evaluates a CIDR predicate using pre-compiled networks.
func (dt *DecisionTree) evalCIDR(rule *CompiledRule, pred *CompiledPredicate, event *PolicyEvent) (bool, error) {
	ipNet, ok := rule.CompiledCIDRs[pred.Value]
	if !ok {
		return false, fmt.Errorf("pre-compiled CIDR not found for %q", pred.Value)
	}
	fieldValue := dt.resolveField(pred.FieldPath, event)
	ip := net.ParseIP(fmt.Sprint(fieldValue))
	if ip == nil {
		return false, nil
	}
	return ipNet.Contains(ip), nil
}

// resolveField resolves a field path from a PolicyEvent.
// It strips the "event." prefix and looks up in the event's Fields map.
func (dt *DecisionTree) resolveField(path string, event *PolicyEvent) interface{} {
	// Strip "event." prefix if present.
	fieldName := strings.TrimPrefix(path, "event.")
	return event.GetField(fieldName)
}
