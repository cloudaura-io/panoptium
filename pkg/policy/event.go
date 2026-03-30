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

import "time"

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
// Returns empty string if the field does not exist or is not a string.
func (e *PolicyEvent) GetStringField(path string) string {
	v := e.GetField(path)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// GetIntField retrieves an integer field value from the event.
// Returns 0 if the field does not exist or is not an int.
func (e *PolicyEvent) GetIntField(path string) int {
	v := e.GetField(path)
	if i, ok := v.(int); ok {
		return i
	}
	return 0
}

// Decision represents the outcome of evaluating a PolicyEvent against compiled policies.
type Decision struct {
	// Action is the action type to take.
	Action CompiledAction

	// Matched indicates whether any rule matched the event.
	Matched bool

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
			Type: "allow",
		},
		Matched:          false,
		MatchedRule:      "",
		MatchedRuleIndex: -1,
	}
}
