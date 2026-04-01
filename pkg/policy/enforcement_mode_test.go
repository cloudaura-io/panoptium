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

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// Test: Policy with enforcementMode=disabled is skipped in evaluation.
func TestEnforcementMode_DisabledSkipped(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "disabled-policy",
			Namespace:       "default",
			Priority:        100,
			EnforcementMode: v1alpha1.EnforcementModeDisabled,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("expected no match — disabled policy should be skipped")
	}
	if decision.Action.Type != "allow" {
		t.Errorf("expected default allow, got %q", decision.Action.Type)
	}
}

// Test: Policy with enforcementMode=audit evaluates but Decision has AuditOnly=true.
func TestEnforcementMode_AuditSetsAuditOnly(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "audit-policy",
			Namespace:       "default",
			Priority:        100,
			EnforcementMode: v1alpha1.EnforcementModeAudit,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match — audit policy should still evaluate")
	}
	if decision.Action.Type != "deny" {
		t.Errorf("expected deny action, got %q", decision.Action.Type)
	}
	if !decision.AuditOnly {
		t.Error("expected AuditOnly=true for audit-mode policy")
	}
}

// Test: Policy with enforcementMode=enforcing evaluates normally without AuditOnly.
func TestEnforcementMode_EnforcingNormal(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "enforcing-policy",
			Namespace:       "default",
			Priority:        100,
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for enforcing policy")
	}
	if decision.Action.Type != "deny" {
		t.Errorf("expected deny, got %q", decision.Action.Type)
	}
	if decision.AuditOnly {
		t.Error("expected AuditOnly=false for enforcing policy")
	}
}

// Test: Global enforcement mode "audit" overrides per-policy "enforcing".
// When the global mode is audit, even enforcing policies produce AuditOnly decisions.
// Note: The global mode is applied at the ExtProc server layer, not in the resolver.
// This test verifies that the resolver correctly sets AuditOnly based on per-policy mode;
// the ExtProc-level override is tested in policy_evaluation_test.go.
func TestEnforcementMode_GlobalAuditOverridesPerPolicyEnforcing(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	// A policy with per-policy enforcing mode — at the resolver level,
	// this should NOT set AuditOnly (the global override is applied in ExtProc).
	policies := []*CompiledPolicy{
		{
			Name:            "enforcing-policy",
			Namespace:       "default",
			Priority:        100,
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for enforcing policy")
	}
	if decision.AuditOnly {
		t.Error("expected AuditOnly=false at resolver level (global override is in ExtProc)")
	}
}

// Test: Disabled policy with higher priority does not block lower-priority enforcing policy.
func TestEnforcementMode_DisabledDoesNotBlockLowerPriority(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "disabled-high",
			Namespace:       "default",
			Priority:        200,
			EnforcementMode: v1alpha1.EnforcementModeDisabled,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
		{
			Name:            "enforcing-low",
			Namespace:       "default",
			Priority:        100,
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Rules: []*CompiledRule{
				{
					Name:         "alert-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match from lower-priority enforcing policy")
	}
	if decision.PolicyName != "enforcing-low" {
		t.Errorf("expected enforcing-low, got %q", decision.PolicyName)
	}
}
