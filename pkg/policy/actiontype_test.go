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
	"errors"
	"testing"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// --- ActionType Consistency Tests (FR-5) ---

// TestActionType_RateLimitCanonicalNameInAPI verifies that the API uses "rateLimit"
// as the canonical ActionType constant.
func TestActionType_RateLimitCanonicalNameInAPI(t *testing.T) {
	if string(v1alpha1.ActionTypeRateLimit) != "rateLimit" {
		t.Errorf("ActionTypeRateLimit = %q, want %q", v1alpha1.ActionTypeRateLimit, "rateLimit")
	}
}

// TestActionType_RateLimitCompilesAndEvaluates verifies that a policy rule with
// ActionType "rateLimit" compiles successfully and produces a decision with
// ActionType "rateLimit" throughout the pipeline.
func TestActionType_RateLimitCompilesAndEvaluates(t *testing.T) {
	policy := newTestPolicy("rate-consistency", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "rate-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "protocol",
				EventSubcategory: "tool_call",
			},
			Action: v1alpha1.Action{
				Type: v1alpha1.ActionTypeRateLimit,
				Parameters: map[string]string{
					"requestsPerMinute": "10",
					"burstSize":         "5",
				},
			},
			Severity: v1alpha1.SeverityMedium,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}

	if compiled.Rules[0].Action.Type != v1alpha1.ActionTypeRateLimit {
		t.Errorf("compiled action type = %q, want %q", compiled.Rules[0].Action.Type, v1alpha1.ActionTypeRateLimit)
	}

	// Evaluate and verify the decision carries the canonical name
	dt := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "test"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Fatal("expected match, got no match")
	}
	if decision.Action.Type != v1alpha1.ActionTypeRateLimit {
		t.Errorf("decision action type = %q, want %q", decision.Action.Type, v1alpha1.ActionTypeRateLimit)
	}
}

// TestActionType_UnknownTypeCausesCompilationError verifies that using an unknown
// ActionType in a PolicyRule causes a CompilationError at compile time, not a
// silent pass-through.
func TestActionType_UnknownTypeCausesCompilationError(t *testing.T) {
	unknownTypes := []v1alpha1.ActionType{
		"unknownAction",
		"mutate",
		"redirect",
		"throttle",
		"block",
		"suspend",
		"",
	}

	compiler := NewPolicyCompiler()

	for _, actionType := range unknownTypes {
		t.Run(string(actionType), func(t *testing.T) {
			policy := newTestPolicy("unknown-action-test", "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "bad-action-rule",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "process_exec",
					},
					Action: v1alpha1.Action{
						Type: actionType,
					},
					Severity: v1alpha1.SeverityHigh,
				},
			})

			_, err := compiler.Compile(policy)
			if err == nil {
				t.Fatalf("Compile() with ActionType %q should return error, got nil", actionType)
			}
			var compErr *CompilationError
			if !errors.As(err, &compErr) {
				t.Fatalf("expected *CompilationError, got %T: %v", err, err)
			}
			if compErr.Field != "action.type" {
				t.Errorf("CompilationError.Field = %q, want %q", compErr.Field, "action.type")
			}
		})
	}
}

// TestActionType_CustomWebhookRemoved verifies that customWebhook is no longer
// a valid ActionType in the API enum and causes a CompilationError.
func TestActionType_CustomWebhookRemoved(t *testing.T) {
	compiler := NewPolicyCompiler()
	policy := newTestPolicy("webhook-removed", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "webhook-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Action: v1alpha1.Action{
				Type: "customWebhook",
			},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	_, err := compiler.Compile(policy)
	if err == nil {
		t.Fatal("Compile() with ActionType 'customWebhook' should return error, got nil")
	}
	var compErr *CompilationError
	if !errors.As(err, &compErr) {
		t.Fatalf("expected *CompilationError, got %T: %v", err, err)
	}
}

// TestActionType_AllValidTypesCompile verifies that all supported ActionTypes
// compile successfully. This is the definitive set of allowed types.
func TestActionType_AllValidTypesCompile(t *testing.T) {
	validTypes := []v1alpha1.ActionType{
		v1alpha1.ActionTypeAllow,
		v1alpha1.ActionTypeDeny,
		v1alpha1.ActionTypeAlert,
		v1alpha1.ActionTypeQuarantine,
		v1alpha1.ActionTypeRateLimit,
	}

	compiler := NewPolicyCompiler()

	for _, actionType := range validTypes {
		t.Run(string(actionType), func(t *testing.T) {
			policy := newTestPolicy("valid-action-"+string(actionType), "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "valid-rule",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "process_exec",
					},
					Action: v1alpha1.Action{
						Type: actionType,
					},
					Severity: v1alpha1.SeverityHigh,
				},
			})

			_, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() with ActionType %q should succeed, got error: %v", actionType, err)
			}
		})
	}
}

// TestActionType_RateLimitBackwardCompatibility verifies that existing CRDs
// using "rateLimit" ActionType still compile successfully after the ActionType
// unification.
func TestActionType_RateLimitBackwardCompatibility(t *testing.T) {
	// Simulate an existing CRD that uses the string "rateLimit" directly
	policy := newTestPolicy("backward-compat", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "rate-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "protocol",
				EventSubcategory: "tool_call",
			},
			Action: v1alpha1.Action{
				Type: "rateLimit", // Direct string, simulating existing CRD
				Parameters: map[string]string{
					"requestsPerMinute": "60",
					"burstSize":         "10",
				},
			},
			Severity: v1alpha1.SeverityMedium,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() with 'rateLimit' should succeed (backward compatibility), got error: %v", err)
	}

	// Verify the compiled action type is the canonical name
	if compiled.Rules[0].Action.Type != v1alpha1.ActionTypeRateLimit {
		t.Errorf("compiled action type = %q, want %q", compiled.Rules[0].Action.Type, v1alpha1.ActionTypeRateLimit)
	}
}

// TestActionType_ClusterPolicyUnknownTypeCausesCompilationError verifies that
// ActionType validation also works for ClusterPanoptiumPolicy compilation.
func TestActionType_ClusterPolicyUnknownTypeCausesCompilationError(t *testing.T) {
	compiler := NewPolicyCompiler()
	clusterPolicy := &v1alpha1.ClusterPanoptiumPolicy{
		Spec: v1alpha1.ClusterPanoptiumPolicySpec{
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "bad-action-rule",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "process_exec",
					},
					Action: v1alpha1.Action{
						Type: "unknownAction",
					},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}
	clusterPolicy.Name = "cluster-unknown-action"

	_, err := compiler.CompileCluster(clusterPolicy)
	if err == nil {
		t.Fatal("CompileCluster() with unknown ActionType should return error, got nil")
	}
	var compErr *CompilationError
	if !errors.As(err, &compErr) {
		t.Fatalf("expected *CompilationError, got %T: %v", err, err)
	}
}

// TestActionType_ExtProcHandlesRateLimit verifies that the ExtProc enforcement
// decision handler uses the canonical "rateLimit" ActionType (v1alpha1.ActionTypeRateLimit)
// to produce a throttle/429 response.
func TestActionType_ExtProcHandlesRateLimit(t *testing.T) {
	// This is verified by the existing test TestPolicyEvaluation_ThrottleDecision
	// in policy_evaluation_test.go, which uses v1alpha1.ActionTypeRateLimit.
	// Here we verify the constant value matches what ExtProc switches on.
	if v1alpha1.ActionTypeRateLimit != "rateLimit" {
		t.Errorf("ActionTypeRateLimit = %q, ExtProc enforcement expects 'rateLimit'", v1alpha1.ActionTypeRateLimit)
	}
}
