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

// Package predicate implements predicate evaluators for the Panoptium policy engine.
// Each evaluator matches a specific predicate type (string equality, numeric comparison,
// regex, glob, CIDR, rate limiting, temporal sequences, process ancestry) against
// runtime PolicyEvent fields.
package predicate

import (
	"fmt"
	"strings"

	"github.com/panoptium/panoptium/pkg/policy"
)

// PredicateEvaluator evaluates a single predicate against a PolicyEvent.
// Implementations are stateless matchers initialized from compiled predicate data.
type PredicateEvaluator interface {
	// Evaluate returns true if the predicate matches the given event.
	Evaluate(event *policy.PolicyEvent) (bool, error)
}

// StringMatchMode defines the type of string comparison to perform.
type StringMatchMode int

const (
	// MatchExact performs exact string equality comparison.
	MatchExact StringMatchMode = iota

	// MatchPrefix checks if the field value starts with the given prefix.
	MatchPrefix

	// MatchSuffix checks if the field value ends with the given suffix.
	MatchSuffix
)

// StringEqualityEvaluator evaluates string predicates including exact match,
// prefix, and suffix comparisons. Non-string field values are coerced to their
// string representation via fmt.Sprintf before comparison.
type StringEqualityEvaluator struct {
	// FieldPath is the event field to extract (e.g., "processName", "path").
	FieldPath string

	// Value is the string to compare against.
	Value string

	// Mode determines the type of string comparison (exact, prefix, suffix).
	Mode StringMatchMode

	// Negate inverts the match result when true (implements != semantics).
	Negate bool
}

// Evaluate checks whether the event field matches the configured string value.
func (e *StringEqualityEvaluator) Evaluate(event *policy.PolicyEvent) (bool, error) {
	fieldValue := extractField(e.FieldPath, event)
	if fieldValue == nil {
		if e.Negate {
			return true, nil
		}
		return false, nil
	}

	str := coerceToString(fieldValue)

	var matched bool
	switch e.Mode {
	case MatchExact:
		matched = str == e.Value
	case MatchPrefix:
		matched = strings.HasPrefix(str, e.Value)
	case MatchSuffix:
		matched = strings.HasSuffix(str, e.Value)
	default:
		matched = str == e.Value
	}

	if e.Negate {
		return !matched, nil
	}
	return matched, nil
}

// NumericOp defines the type of numeric comparison to perform.
type NumericOp int

const (
	// OpEqual checks for numeric equality.
	OpEqual NumericOp = iota

	// OpNotEqual checks for numeric inequality.
	OpNotEqual

	// OpGreaterThan checks if the field value is strictly greater than the threshold.
	OpGreaterThan

	// OpLessThan checks if the field value is strictly less than the threshold.
	OpLessThan

	// OpGreaterThanOrEqual checks if the field value is greater than or equal to the threshold.
	OpGreaterThanOrEqual

	// OpLessThanOrEqual checks if the field value is less than or equal to the threshold.
	OpLessThanOrEqual

	// OpBetween checks if the field value is within [Value, UpperBound] inclusive.
	OpBetween
)

// NumericComparisonEvaluator evaluates numeric predicates including equality,
// greater-than, less-than, and between comparisons. It supports int, int64,
// and float64 field values.
type NumericComparisonEvaluator struct {
	// FieldPath is the event field to extract (e.g., "destinationPort", "tokenCount").
	FieldPath string

	// Op is the comparison operator.
	Op NumericOp

	// Value is the comparison threshold (or lower bound for OpBetween).
	Value float64

	// UpperBound is the upper bound for OpBetween comparisons (inclusive).
	UpperBound float64
}

// Evaluate checks whether the event field satisfies the numeric comparison.
func (e *NumericComparisonEvaluator) Evaluate(event *policy.PolicyEvent) (bool, error) {
	fieldValue := extractField(e.FieldPath, event)
	if fieldValue == nil {
		return false, nil
	}

	actual, ok := coerceToFloat64(fieldValue)
	if !ok {
		return false, nil
	}

	switch e.Op {
	case OpEqual:
		return actual == e.Value, nil
	case OpNotEqual:
		return actual != e.Value, nil
	case OpGreaterThan:
		return actual > e.Value, nil
	case OpLessThan:
		return actual < e.Value, nil
	case OpGreaterThanOrEqual:
		return actual >= e.Value, nil
	case OpLessThanOrEqual:
		return actual <= e.Value, nil
	case OpBetween:
		return actual >= e.Value && actual <= e.UpperBound, nil
	default:
		return false, fmt.Errorf("unknown numeric operator %d", e.Op)
	}
}

// FieldExtractor resolves dotted field paths from PolicyEvent structs.
// It provides a simple lookup into the event's Fields map.
type FieldExtractor struct{}

// Extract retrieves a field value from the event by its path.
// Returns nil if the field does not exist or the Fields map is nil.
func (f *FieldExtractor) Extract(path string, event *policy.PolicyEvent) interface{} {
	return extractField(path, event)
}

// extractField is a shared helper that resolves a field from a PolicyEvent.
func extractField(path string, event *policy.PolicyEvent) interface{} {
	if event == nil || event.Fields == nil {
		return nil
	}
	return event.Fields[path]
}

// coerceToString converts an arbitrary value to its string representation.
func coerceToString(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	default:
		return fmt.Sprintf("%v", s)
	}
}

// coerceToFloat64 converts a numeric value to float64.
// Returns (0, false) if the value is not a recognized numeric type.
func coerceToFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case int32:
		return float64(n), true
	case float32:
		return float64(n), true
	default:
		return 0, false
	}
}
