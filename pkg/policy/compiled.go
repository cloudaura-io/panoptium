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

// Package policy implements the Panoptium policy engine: compilation of
// PanoptiumPolicy CRD specs into optimized intermediate representations
// and evaluation of runtime events against compiled rules.
package policy

import (
	"net"
	"regexp"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledPolicy is the optimized intermediate representation of a PanoptiumPolicy
// CRD spec. It contains pre-compiled matchers and a decision tree for fast
// evaluation of runtime events.
type CompiledPolicy struct {
	// Name is the policy resource name.
	Name string

	// Namespace is the policy resource namespace (empty for cluster-scoped).
	Namespace string

	// Priority is the policy evaluation priority (higher = evaluated first).
	Priority int32

	// EnforcementMode controls whether actions are enforced, audited, or disabled.
	EnforcementMode v1alpha1.EnforcementMode

	// TargetSelector is the label selector for target pods.
	// Nil or empty selector matches all pods.
	TargetSelector *metav1.LabelSelector

	// Rules is the ordered list of compiled rules for decision tree evaluation.
	Rules []*CompiledRule

	// IsClusterScoped indicates whether this is a ClusterPanoptiumPolicy.
	IsClusterScoped bool
}

// CompiledRule is a single rule within a CompiledPolicy, containing pre-compiled
// matchers for efficient evaluation.
type CompiledRule struct {
	// Name is the human-readable rule identifier.
	Name string

	// Index is the rule's position within the policy (for deterministic ordering).
	Index int

	// TriggerLayer is the event category (kernel, network, protocol, llm, lifecycle).
	TriggerLayer string

	// TriggerEvent is the event subcategory (e.g., process_exec, egress_attempt).
	TriggerEvent string

	// Predicates contains the parsed predicate expressions for this rule.
	Predicates []CompiledPredicate

	// Action is the action configuration for this rule.
	Action CompiledAction

	// Severity is the severity level for this rule.
	Severity v1alpha1.Severity

	// CompiledRegexes contains pre-compiled regex patterns extracted from predicates.
	CompiledRegexes map[string]*regexp.Regexp

	// CompiledGlobs contains pre-compiled glob patterns extracted from predicates.
	CompiledGlobs map[string]*GlobMatcher

	// CompiledCIDRs contains pre-compiled CIDR networks extracted from predicates.
	CompiledCIDRs map[string]*net.IPNet
}

// CompiledPredicate represents a parsed predicate expression with extracted
// patterns and field references.
type CompiledPredicate struct {
	// RawCEL is the original CEL expression string.
	RawCEL string

	// FieldPath is the extracted event field path (e.g., "event.processName").
	FieldPath string

	// Operator is the comparison operator (e.g., "==", "!=", "matches", "glob", "inCIDR").
	Operator string

	// Value is the literal comparison value.
	Value string

	// Negate indicates whether the predicate result should be negated (NOT).
	Negate bool
}

// CompiledAction holds the action type and its parameters for a compiled rule.
type CompiledAction struct {
	// Type is the action type.
	Type v1alpha1.ActionType

	// Parameters contains action-specific configuration.
	Parameters map[string]string
}

// GlobMatcher wraps a glob pattern string for matching.
type GlobMatcher struct {
	// Pattern is the original glob pattern string.
	Pattern string
}

// Match checks if the given path matches this glob pattern.
func (g *GlobMatcher) Match(path string) bool {
	matched, _ := matchGlob(g.Pattern, path)
	return matched
}

// matchGlob provides simple glob matching supporting * and ** wildcards.
func matchGlob(pattern, path string) (bool, error) {
	return deepMatchGlob([]rune(pattern), []rune(path))
}

// deepMatchGlob recursively matches a glob pattern against a path.
func deepMatchGlob(pattern, str []rune) (bool, error) {
	for len(pattern) > 0 {
		switch {
		case len(pattern) >= 3 && string(pattern[:3]) == "**/":
			// ** matches zero or more path segments
			pattern = pattern[3:]
			for i := 0; i <= len(str); i++ {
				if ok, _ := deepMatchGlob(pattern, str[i:]); ok {
					return true, nil
				}
			}
			return false, nil
		case len(pattern) >= 2 && string(pattern[:2]) == "**":
			// ** at end of pattern matches everything
			return true, nil
		case pattern[0] == '*':
			// * matches any non-separator character sequence
			pattern = pattern[1:]
			for i := 0; i <= len(str); i++ {
				if i > 0 && str[i-1] == '/' {
					break
				}
				if ok, _ := deepMatchGlob(pattern, str[i:]); ok {
					return true, nil
				}
			}
			return false, nil
		case len(str) == 0:
			return false, nil
		case pattern[0] == '?':
			if str[0] == '/' {
				return false, nil
			}
			pattern = pattern[1:]
			str = str[1:]
		case pattern[0] == str[0]:
			pattern = pattern[1:]
			str = str[1:]
		default:
			return false, nil
		}
	}
	return len(str) == 0, nil
}
