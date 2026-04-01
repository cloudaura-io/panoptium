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
	"regexp"
	"strings"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// validActionTypes is the set of ActionTypes supported by the policy engine.
// Any ActionType not in this set will cause a CompilationError. This prevents
// unknown or removed action types (e.g., customWebhook) from silently passing
// through the compilation pipeline.
var validActionTypes = map[v1alpha1.ActionType]bool{
	v1alpha1.ActionTypeAllow:      true,
	v1alpha1.ActionTypeDeny:       true,
	v1alpha1.ActionTypeAlert:      true,
	v1alpha1.ActionTypeQuarantine: true,
	v1alpha1.ActionTypeRateLimit:  true,
}

// validTriggerLayers maps each trigger layer to its valid event subcategories.
var validTriggerLayers = map[string]map[string]bool{
	"kernel": {
		"file_open":      true,
		"file_write":     true,
		"file_delete":    true,
		"process_exec":   true,
		"process_fork":   true,
		"module_load":    true,
		"capability_use": true,
	},
	"network": {
		"egress_attempt":         true,
		"ingress_attempt":        true,
		"dns_query":              true,
		"dns_response":           true,
		"connection_established": true,
		"connection_closed":      true,
	},
	"protocol": {
		"tool_call":           true,
		"tool_response":       true,
		"message_send":        true,
		"message_receive":     true,
		"task_delegate":       true,
		"llm_request":         true,
		"llm_response":        true,
		"llm_response_chunk":  true,
	},
	"llm": {
		"prompt_submit":      true,
		"completion_receive": true,
		"tool_use_intent":    true,
		"function_call":      true,
		"token_stream":       true,
	},
	"lifecycle": {
		"pod_start":        true,
		"pod_stop":         true,
		"container_exec":   true,
		"agent_register":   true,
		"agent_deregister": true,
	},
}

// CompilationError represents a structured error from policy compilation.
type CompilationError struct {
	// PolicyName is the name of the policy that failed compilation.
	PolicyName string

	// RuleName is the name of the rule that caused the error (may be empty).
	RuleName string

	// RuleIndex is the index of the rule that caused the error.
	RuleIndex int

	// Field is the field path that caused the error.
	Field string

	// Message is a human-readable description of the error.
	Message string

	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *CompilationError) Error() string {
	if e.RuleName != "" {
		return fmt.Sprintf("compilation error in policy %q, rule %q (index %d), field %q: %s",
			e.PolicyName, e.RuleName, e.RuleIndex, e.Field, e.Message)
	}
	return fmt.Sprintf("compilation error in policy %q, field %q: %s",
		e.PolicyName, e.Field, e.Message)
}

// Unwrap returns the underlying cause error.
func (e *CompilationError) Unwrap() error {
	return e.Cause
}

// PolicyCompiler converts PanoptiumPolicy CRD specs into optimized CompiledPolicy
// intermediate representations with pre-compiled matchers.
type PolicyCompiler struct{}

// NewPolicyCompiler creates a new PolicyCompiler.
func NewPolicyCompiler() *PolicyCompiler {
	return &PolicyCompiler{}
}

// Compile converts a PanoptiumPolicy CRD into a CompiledPolicy with pre-compiled
// regex, glob, and CIDR matchers. Returns a CompilationError for invalid specs.
func (c *PolicyCompiler) Compile(policy *v1alpha1.PanoptiumPolicy) (*CompiledPolicy, error) {
	compiled := &CompiledPolicy{
		Name:            policy.Name,
		Namespace:       policy.Namespace,
		Priority:        policy.Spec.Priority,
		EnforcementMode: policy.Spec.EnforcementMode,
		TargetSelector:  &policy.Spec.TargetSelector,
		IsClusterScoped: false,
	}

	rules := make([]*CompiledRule, 0, len(policy.Spec.Rules))
	for i, rule := range policy.Spec.Rules {
		cr, err := c.compileRule(policy.Name, i, rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, cr)
	}
	compiled.Rules = rules

	return compiled, nil
}

// CompileCluster converts a ClusterPanoptiumPolicy CRD into a CompiledPolicy.
func (c *PolicyCompiler) CompileCluster(policy *v1alpha1.ClusterPanoptiumPolicy) (*CompiledPolicy, error) {
	compiled := &CompiledPolicy{
		Name:            policy.Name,
		Namespace:       "",
		Priority:        policy.Spec.Priority,
		EnforcementMode: policy.Spec.EnforcementMode,
		TargetSelector:  &policy.Spec.TargetSelector,
		IsClusterScoped: true,
	}

	rules := make([]*CompiledRule, 0, len(policy.Spec.Rules))
	for i, rule := range policy.Spec.Rules {
		cr, err := c.compileRule(policy.Name, i, rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, cr)
	}
	compiled.Rules = rules

	return compiled, nil
}

// compileRule compiles a single PolicyRule into a CompiledRule.
func (c *PolicyCompiler) compileRule(policyName string, index int, rule v1alpha1.PolicyRule) (*CompiledRule, error) {
	// Validate trigger layer and event.
	if err := c.validateTrigger(policyName, index, rule); err != nil {
		return nil, err
	}

	// Validate action type — reject unknown or unsupported types at compile time.
	if !validActionTypes[rule.Action.Type] {
		return nil, &CompilationError{
			PolicyName: policyName,
			RuleName:   rule.Name,
			RuleIndex:  index,
			Field:      "action.type",
			Message:    fmt.Sprintf("unsupported action type %q; valid types: allow, deny, alert, quarantine, rateLimit", rule.Action.Type),
		}
	}

	cr := &CompiledRule{
		Name:            rule.Name,
		Index:           index,
		TriggerLayer:    rule.Trigger.EventCategory,
		TriggerEvent:    rule.Trigger.EventSubcategory,
		Severity:        rule.Severity,
		CompiledRegexes: make(map[string]*regexp.Regexp),
		CompiledGlobs:   make(map[string]*GlobMatcher),
		CompiledCIDRs:   make(map[string]*net.IPNet),
		Action: CompiledAction{
			Type:       rule.Action.Type,
			Parameters: rule.Action.Parameters,
		},
	}

	// Compile predicates.
	predicates := make([]CompiledPredicate, 0, len(rule.Predicates))
	for _, pred := range rule.Predicates {
		cp, err := c.compilePredicate(policyName, rule.Name, index, pred, cr)
		if err != nil {
			return nil, err
		}
		predicates = append(predicates, cp)
	}
	cr.Predicates = predicates

	return cr, nil
}

// validateTrigger validates the trigger layer and event type.
func (c *PolicyCompiler) validateTrigger(policyName string, ruleIndex int, rule v1alpha1.PolicyRule) error {
	layer := rule.Trigger.EventCategory
	events, ok := validTriggerLayers[layer]
	if !ok {
		return &CompilationError{
			PolicyName: policyName,
			RuleName:   rule.Name,
			RuleIndex:  ruleIndex,
			Field:      "trigger.eventCategory",
			Message:    fmt.Sprintf("unknown trigger layer %q; valid layers: kernel, network, protocol, llm, lifecycle", layer),
		}
	}

	subcategory := rule.Trigger.EventSubcategory
	if subcategory != "" && !events[subcategory] {
		// Check if it's a glob pattern (contains *)
		if !strings.Contains(subcategory, "*") {
			return &CompilationError{
				PolicyName: policyName,
				RuleName:   rule.Name,
				RuleIndex:  ruleIndex,
				Field:      "trigger.eventSubcategory",
				Message:    fmt.Sprintf("unknown event subcategory %q for layer %q", subcategory, layer),
			}
		}
	}

	return nil
}

// compilePredicate parses a CEL expression predicate and extracts regex, glob,
// and CIDR patterns for pre-compilation.
func (c *PolicyCompiler) compilePredicate(policyName, ruleName string, ruleIndex int, pred v1alpha1.Predicate, cr *CompiledRule) (CompiledPredicate, error) {
	cp := CompiledPredicate{
		RawCEL: pred.CEL,
	}

	cel := pred.CEL

	// Detect compound expressions (&&, ||, ternary) that need full CEL compilation.
	// These cannot be decomposed into simple field/operator/value form.
	if isCompoundExpression(cel) {
		return c.compileCELPredicate(policyName, ruleName, ruleIndex, cel, cp)
	}

	// Extract and pre-compile regex patterns: event.field.matches("pattern")
	if idx := strings.Index(cel, ".matches(\""); idx >= 0 {
		fieldPath := cel[:idx]
		rest := cel[idx+len(".matches(\""):]
		endIdx := strings.Index(rest, "\")")
		if endIdx >= 0 {
			pattern := rest[:endIdx]
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return cp, &CompilationError{
					PolicyName: policyName,
					RuleName:   ruleName,
					RuleIndex:  ruleIndex,
					Field:      "predicates.cel",
					Message:    fmt.Sprintf("invalid regex pattern %q: %v", pattern, err),
					Cause:      err,
				}
			}
			cr.CompiledRegexes[pattern] = compiled
			cp.FieldPath = fieldPath
			cp.Operator = "matches"
			cp.Value = pattern
			return cp, nil
		}
	}

	// Extract and pre-compile glob patterns: event.field.glob("pattern")
	if idx := strings.Index(cel, ".glob(\""); idx >= 0 {
		fieldPath := cel[:idx]
		rest := cel[idx+len(".glob(\""):]
		endIdx := strings.Index(rest, "\")")
		if endIdx >= 0 {
			pattern := rest[:endIdx]
			cr.CompiledGlobs[pattern] = &GlobMatcher{Pattern: pattern}
			cp.FieldPath = fieldPath
			cp.Operator = "glob"
			cp.Value = pattern
			return cp, nil
		}
	}

	// Extract and pre-compile CIDR patterns: event.field.inCIDR("cidr")
	if idx := strings.Index(cel, ".inCIDR(\""); idx >= 0 {
		fieldPath := cel[:idx]
		rest := cel[idx+len(".inCIDR(\""):]
		endIdx := strings.Index(rest, "\")")
		if endIdx >= 0 {
			cidrStr := rest[:endIdx]
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				return cp, &CompilationError{
					PolicyName: policyName,
					RuleName:   ruleName,
					RuleIndex:  ruleIndex,
					Field:      "predicates.cel",
					Message:    fmt.Sprintf("invalid CIDR %q: %v", cidrStr, err),
					Cause:      err,
				}
			}
			cr.CompiledCIDRs[cidrStr] = ipNet
			cp.FieldPath = fieldPath
			cp.Operator = "inCIDR"
			cp.Value = cidrStr
			return cp, nil
		}
	}

	// Parse simple equality: event.field == "value" or event.field == 'value'
	if parts := strings.SplitN(cel, " == ", 2); len(parts) == 2 {
		cp.FieldPath = strings.TrimSpace(parts[0])
		cp.Operator = "=="
		cp.Value = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		return cp, nil
	}

	// Parse simple inequality: event.field != "value" or event.field != 'value'
	if parts := strings.SplitN(cel, " != ", 2); len(parts) == 2 {
		cp.FieldPath = strings.TrimSpace(parts[0])
		cp.Operator = "!="
		cp.Value = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		return cp, nil
	}

	// Parse greater-than: event.field > value
	if parts := strings.SplitN(cel, " > ", 2); len(parts) == 2 {
		cp.FieldPath = strings.TrimSpace(parts[0])
		cp.Operator = ">"
		cp.Value = strings.TrimSpace(parts[1])
		return cp, nil
	}

	// Parse less-than: event.field < value
	if parts := strings.SplitN(cel, " < ", 2); len(parts) == 2 {
		cp.FieldPath = strings.TrimSpace(parts[0])
		cp.Operator = "<"
		cp.Value = strings.TrimSpace(parts[1])
		return cp, nil
	}

	// Fallback: compile the expression with google/cel-go.
	// This handles any expression not matched by the simple parsers above
	// and validates syntax (eliminates silent "raw" pass-through).
	return c.compileCELPredicate(policyName, ruleName, ruleIndex, cel, cp)
}

// isCompoundExpression returns true if the CEL expression contains logical
// operators that indicate it cannot be decomposed into simple field/op/value.
func isCompoundExpression(expr string) bool {
	return strings.Contains(expr, " && ") || strings.Contains(expr, " || ") || strings.Contains(expr, " ? ")
}

// compileCELPredicate compiles an expression using google/cel-go and stores
// the compiled program in the CompiledPredicate.
func (c *PolicyCompiler) compileCELPredicate(policyName, ruleName string, ruleIndex int, expr string, cp CompiledPredicate) (CompiledPredicate, error) {
	celEnv, err := getCELEnv()
	if err != nil {
		return cp, &CompilationError{
			PolicyName: policyName,
			RuleName:   ruleName,
			RuleIndex:  ruleIndex,
			Field:      "predicates.cel",
			Message:    fmt.Sprintf("failed to initialize CEL environment: %v", err),
			Cause:      err,
		}
	}

	prg, err := compileCEL(celEnv, expr, policyName, ruleName, ruleIndex)
	if err != nil {
		return cp, err
	}

	cp.FieldPath = expr
	cp.Operator = "cel"
	cp.Value = expr
	cp.CELProgram = prg
	return cp, nil
}
