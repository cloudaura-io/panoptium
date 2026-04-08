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
	"time"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// PolicyEvent represents a runtime event to be evaluated against compiled policies.
// It provides a uniform interface for events from all trigger layers.
type PolicyEvent struct {
	// Category is the event trigger layer (kernel, network, protocol, llm, lifecycle).
	Category string

	// Subcategory is the event type within the layer (e.g., process_exec, egress_attempt).
	Subcategory string

	// Timestamp is when the event occurred.
	Timestamp time.Time

	// Namespace is the Kubernetes namespace of the source pod.
	Namespace string

	// PodName is the name of the source pod.
	PodName string

	// PodLabels contains the labels of the source pod.
	PodLabels map[string]string

	// Fields contains the event-specific data as key-value pairs.
	// Field paths use dot notation (e.g., "processName", "destinationIP", "path").
	Fields map[string]interface{}
}

// GetField retrieves a field value from the event by its path.
// Returns nil if the field does not exist.
func (e *PolicyEvent) GetField(path string) interface{} {
	if e.Fields == nil {
		return nil
	}
	return e.Fields[path]
}

// GetStringField retrieves a string field value from the event.
// Returns empty string if the field does not exist.
func (e *PolicyEvent) GetStringField(path string) string {
	v := e.GetField(path)
	switch s := v.(type) {
	case string:
		return s
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", s)
	}
}

// GetIntField retrieves an integer field value from the event.
// Returns 0 if the field does not exist or is not numeric.
func (e *PolicyEvent) GetIntField(path string) int {
	v := e.GetField(path)
	switch i := v.(type) {
	case int:
		return i
	case int64:
		return int(i)
	case float64:
		return int(i)
	default:
		return 0
	}
}

// ActionCategory classifies an action type for multi-phase evaluation.
type ActionCategory int

const (
	// ActionCategoryNonTerminal represents actions that are always executed
	// without blocking (alert, audit).
	ActionCategoryNonTerminal ActionCategory = iota

	// ActionCategoryMutating represents tool-strip actions (deny on tool_call).
	ActionCategoryMutating

	// ActionCategoryRateControl represents rate limit actions.
	ActionCategoryRateControl

	// ActionCategoryTerminal represents blocking actions (deny, quarantine on
	// non-tool-call events).
	ActionCategoryTerminal
)

// ClassifyAction returns the ActionCategory for the given action type and
// event subcategory. Deny on tool_call is mutating (strips the tool); deny
// on other subcategories is terminal (blocks the request).
func ClassifyAction(actionType v1alpha1.ActionType, subcategory string) ActionCategory {
	switch actionType {
	case v1alpha1.ActionTypeAlert:
		return ActionCategoryNonTerminal
	case v1alpha1.ActionTypeRateLimit:
		return ActionCategoryRateControl
	case v1alpha1.ActionTypeDeny:
		if subcategory == "tool_call" {
			return ActionCategoryMutating
		}
		return ActionCategoryTerminal
	case v1alpha1.ActionTypeQuarantine:
		return ActionCategoryTerminal
	case v1alpha1.ActionTypeAllow:
		return ActionCategoryNonTerminal
	default:
		return ActionCategoryNonTerminal
	}
}

// EvaluationResult collects decisions from ALL matching policies across ALL
// priority tiers. It replaces the single-winner Decision output for
// multi-phase evaluation with deny-first semantics.
type EvaluationResult struct {
	// Decisions contains all matched decisions across all policies.
	Decisions []*Decision

	// DefaultAllow is true when no rule matched (implicit allow).
	DefaultAllow bool

	// EvaluationDuration is how long the full evaluation took.
	EvaluationDuration time.Duration

	// PredicateTrace records the evaluation result of each predicate.
	PredicateTrace []PredicateTraceEntry
}

// EffectiveAction returns the winning action after priority-aware deny-first
// composition. Higher priority always wins. At equal priority, terminal
// deny/quarantine beats allow (deny-first). If no decisions exist, returns
// a default allow action.
//
// Decisions are expected to be sorted by descending priority (from EvaluateAll).
func (r *EvaluationResult) EffectiveAction() CompiledAction {
	if len(r.Decisions) == 0 || r.DefaultAllow {
		return CompiledAction{Type: v1alpha1.ActionTypeAllow}
	}

	// Walk decisions grouped by priority tier (highest first).
	// Within each tier, deny-first: if any terminal deny/quarantine exists, it wins.
	// An explicit allow at a higher tier beats deny at a lower tier.
	// Non-terminal actions (alert/audit) do not claim a tier — they are
	// always executed regardless and do not block lower-priority decisions.
	tierPriority := r.Decisions[0].Priority
	var tierHasTerminal bool
	var tierTerminal CompiledAction
	var tierHasRateLimit bool
	var tierRateLimit CompiledAction
	var tierHasAllow bool

	for _, d := range r.Decisions {
		if d.Priority != tierPriority {
			// Finished processing previous tier -- check if it produced a winner.
			if tierHasTerminal {
				return tierTerminal
			}
			if tierHasRateLimit {
				return tierRateLimit
			}
			if tierHasAllow {
				return CompiledAction{Type: v1alpha1.ActionTypeAllow}
			}
			// Move to next tier.
			tierPriority = d.Priority
			tierHasTerminal = false
			tierHasRateLimit = false
			tierHasAllow = false
		}

		cat := ClassifyAction(d.Action.Type, d.Subcategory)
		switch cat {
		case ActionCategoryTerminal:
			if !tierHasTerminal {
				tierHasTerminal = true
				tierTerminal = d.Action
			}
		case ActionCategoryRateControl:
			if !tierHasRateLimit {
				tierHasRateLimit = true
				tierRateLimit = d.Action
			}
		case ActionCategoryNonTerminal:
			if d.Action.Type == v1alpha1.ActionTypeAllow {
				tierHasAllow = true
			}
		}
	}

	// Check the last tier.
	if tierHasTerminal {
		return tierTerminal
	}
	if tierHasRateLimit {
		return tierRateLimit
	}

	// No terminal or rate control at any tier -- allow.
	return CompiledAction{Type: v1alpha1.ActionTypeAllow}
}

// TerminalDecisions returns all decisions classified as terminal (deny on
// non-tool-call, quarantine).
func (r *EvaluationResult) TerminalDecisions() []*Decision {
	var result []*Decision
	for _, d := range r.Decisions {
		if ClassifyAction(d.Action.Type, d.Subcategory) == ActionCategoryTerminal {
			result = append(result, d)
		}
	}
	return result
}

// NonTerminalDecisions returns all decisions classified as non-terminal
// (alert, audit, allow).
func (r *EvaluationResult) NonTerminalDecisions() []*Decision {
	var result []*Decision
	for _, d := range r.Decisions {
		if ClassifyAction(d.Action.Type, d.Subcategory) == ActionCategoryNonTerminal {
			result = append(result, d)
		}
	}
	return result
}

// MutatingDecisions returns all decisions classified as mutating (deny on
// tool_call -- tools to strip).
func (r *EvaluationResult) MutatingDecisions() []*Decision {
	var result []*Decision
	for _, d := range r.Decisions {
		if ClassifyAction(d.Action.Type, d.Subcategory) == ActionCategoryMutating {
			result = append(result, d)
		}
	}
	return result
}

// RateControlDecisions returns all decisions classified as rate control.
func (r *EvaluationResult) RateControlDecisions() []*Decision {
	var result []*Decision
	for _, d := range r.Decisions {
		if ClassifyAction(d.Action.Type, d.Subcategory) == ActionCategoryRateControl {
			result = append(result, d)
		}
	}
	return result
}

// HasDeny returns true if any decision is a terminal deny or quarantine.
// Mutating denies (deny on tool_call, which only strip tools) are excluded.
func (r *EvaluationResult) HasDeny() bool {
	for _, d := range r.Decisions {
		if ClassifyAction(d.Action.Type, d.Subcategory) == ActionCategoryTerminal {
			return true
		}
	}
	return false
}

// Decision represents the outcome of evaluating a PolicyEvent against compiled policies.
type Decision struct {
	// Action is the action type to take.
	Action CompiledAction

	// Matched indicates whether any rule matched the event.
	Matched bool

	// Subcategory is the event subcategory that produced this decision
	// (e.g., "tool_call", "llm_request"). Used for action classification.
	Subcategory string

	// Priority is the priority of the source policy that produced this
	// decision. Used by EffectiveAction() to implement priority-aware
	// deny-first composition: higher priority wins; deny-first only
	// applies within the same priority tier.
	Priority int32

	// Severity is the severity level from the matched rule.
	Severity string

	// AuditOnly indicates that the decision came from a policy with
	// enforcementMode=audit. The action should be logged/emitted but not
	// actually enforced (e.g., a "deny" in audit mode is recorded but the
	// request is allowed through).
	AuditOnly bool

	// MatchedRule is the name of the first matched rule (empty if no match).
	MatchedRule string

	// MatchedRuleIndex is the index of the matched rule (-1 if no match).
	MatchedRuleIndex int

	// PolicyName is the name of the policy containing the matched rule.
	PolicyName string

	// PolicyNamespace is the namespace of the policy containing the matched rule.
	PolicyNamespace string

	// EvaluationDuration is how long the evaluation took.
	EvaluationDuration time.Duration

	// PredicateTrace records the evaluation result of each predicate.
	PredicateTrace []PredicateTraceEntry
}

// PredicateTraceEntry records the result of evaluating a single predicate.
type PredicateTraceEntry struct {
	// RuleName is the name of the rule this predicate belongs to.
	RuleName string

	// PredicateCEL is the original CEL expression.
	PredicateCEL string

	// Matched indicates whether this predicate matched.
	Matched bool

	// Error is any error that occurred during evaluation.
	Error string

	// Duration is how long this predicate evaluation took.
	Duration time.Duration
}

// DefaultAllowDecision returns a Decision with a default "allow" action.
func DefaultAllowDecision() *Decision {
	return &Decision{
		Action: CompiledAction{
			Type: v1alpha1.ActionTypeAllow,
		},
		Matched:          false,
		MatchedRule:      "",
		MatchedRuleIndex: -1,
	}
}
