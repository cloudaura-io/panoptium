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
	"testing"
	"time"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Helper to create a policy with a single predicate.
func makePredicatePolicy(name, celExpr string) *v1alpha1.AgentPolicy {
	return &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "test-rule",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "protocol",
						EventSubcategory: "tool_call",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: celExpr},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}
}

// TestCEL_MatchAndNoMatch covers basic CEL predicate evaluation across
// multiple operator types using a table-driven approach.
func TestCEL_MatchAndNoMatch(t *testing.T) {
	tests := []struct {
		name          string
		policyName    string
		celExpr       string
		matchFields   map[string]interface{}
		noMatchFields map[string]interface{}
	}{
		{
			name:          "BasicEquality",
			policyName:    "equality",
			celExpr:       `event.toolName == "bash"`,
			matchFields:   map[string]interface{}{"toolName": "bash"},
			noMatchFields: map[string]interface{}{"toolName": "python"},
		},
		{
			name:          "Inequality",
			policyName:    "inequality",
			celExpr:       `event.toolName != "safe_tool"`,
			matchFields:   map[string]interface{}{"toolName": "bash"},
			noMatchFields: map[string]interface{}{"toolName": "safe_tool"},
		},
		{
			name:          "NumericComparison",
			policyName:    "numeric",
			celExpr:       `event.tokenCount > 1000`,
			matchFields:   map[string]interface{}{"tokenCount": 2000},
			noMatchFields: map[string]interface{}{"tokenCount": 500},
		},
		{
			name:       "MatchesFunction",
			policyName: "regex",
			celExpr:    `event.processName.matches(".*malicious.*")`,
			matchFields: map[string]interface{}{
				"processName": "run_malicious_script",
			},
			noMatchFields: map[string]interface{}{
				"processName": "safe_tool",
			},
		},
		{
			name:          "GlobFunction",
			policyName:    "glob-test",
			celExpr:       `event.path.glob("/etc/**")`,
			matchFields:   map[string]interface{}{"path": "/etc/passwd"},
			noMatchFields: map[string]interface{}{"path": "/var/log/syslog"},
		},
		{
			name:          "InCIDRFunction",
			policyName:    "cidr-test",
			celExpr:       `event.sourceIP.inCIDR("10.0.0.0/8")`,
			matchFields:   map[string]interface{}{"sourceIP": "10.1.2.3"},
			noMatchFields: map[string]interface{}{"sourceIP": "192.168.1.1"},
		},
	}

	compiler := NewPolicyCompiler()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol := makePredicatePolicy(tc.policyName, tc.celExpr)
			compiled, err := compiler.Compile(pol)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}

			dt := NewDecisionTree(compiled)

			// Should match
			matchEvent := &PolicyEvent{
				Category:    "protocol",
				Subcategory: "tool_call",
				Fields:      tc.matchFields,
			}
			decision, err := dt.Evaluate(matchEvent)
			if err != nil {
				t.Fatalf("Evaluate (match): %v", err)
			}
			if !decision.Matched {
				t.Errorf("expected match for %v", tc.matchFields)
			}

			// Should not match
			noMatchEvent := &PolicyEvent{
				Category:    "protocol",
				Subcategory: "tool_call",
				Fields:      tc.noMatchFields,
			}
			decision2, err := dt.Evaluate(noMatchEvent)
			if err != nil {
				t.Fatalf("Evaluate (no-match): %v", err)
			}
			if decision2.Matched {
				t.Errorf("expected no match for %v", tc.noMatchFields)
			}
		})
	}
}

// Test: Complex expression -- event.toolName == "bash" && event.model == "gpt-4".
func TestCEL_ComplexExpression(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("complex", `event.toolName == "bash" && event.model == "gpt-4"`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	// Both conditions match
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash", "model": "gpt-4"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for bash+gpt-4")
	}

	// Only one condition matches
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash", "model": "claude"},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for bash+claude")
	}
}

// Test: Invalid CEL expression returns CompilationError.
func TestCEL_InvalidExpressionReturnsError(t *testing.T) {
	compiler := NewPolicyCompiler()

	invalidExprs := []string{
		`event.toolName ===`,      // syntax error
		`gibberish not valid CEL`, // not valid CEL
		`event.unknown_func()`,    // unknown function
	}

	for _, expr := range invalidExprs {
		pol := makePredicatePolicy("invalid", expr)
		_, err := compiler.Compile(pol)
		if err == nil {
			t.Errorf("expected CompilationError for expression %q, got nil", expr)
		} else {
			// Verify it's a CompilationError
			if _, ok := err.(*CompilationError); !ok {
				t.Errorf("expected *CompilationError for expression %q, got %T: %v", expr, err, err)
			}
		}
	}
}

// Test: Single-quoted values -- event.toolName == 'bash'.
func TestCEL_SingleQuotedValues(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("single-quote", `event.toolName == 'bash'`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for single-quoted bash")
	}
}

// Benchmark: CEL evaluation should be <1ms per predicate.
func BenchmarkCEL_PredicateEvaluation(b *testing.B) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("bench", `event.toolName == "bash" && event.model == "gpt-4"`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash", "model": "gpt-4"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dt.Evaluate(event)
	}

	// Verify that per-evaluation time is < 1ms
	elapsed := b.Elapsed()
	perOp := elapsed / time.Duration(b.N)
	if perOp > 1*time.Millisecond {
		b.Errorf("CEL evaluation took %v per operation, expected <1ms", perOp)
	}
}
