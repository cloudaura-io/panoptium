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

package action

import (
	"testing"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/policy"
)

func TestAllowExecutor_ProducesPermitDecision(t *testing.T) {
	exec := &AllowExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{
			Category:    "protocol",
			Subcategory: "tool_call",
			Fields:      map[string]interface{}{"toolName": "read_file"},
		},
		Rule: &policy.CompiledRule{
			Name:  "allow-read-file",
			Index: 0,
		},
		CompiledAction: policy.CompiledAction{
			Type: "allow",
		},
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Permitted {
		t.Error("expected Permitted=true for allow action")
	}
	if result.ActionType != "allow" {
		t.Errorf("expected ActionType=allow, got %q", result.ActionType)
	}
	if result.RuleName != "allow-read-file" {
		t.Errorf("expected RuleName=allow-read-file, got %q", result.RuleName)
	}
	if result.Annotations["audit"] != "allowed" {
		t.Error("expected audit annotation 'allowed'")
	}
}

func TestDenyExecutor_ProducesBlockDecision(t *testing.T) {
	exec := &DenyExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{
			Category:    "kernel",
			Subcategory: "file_write",
			Fields:      map[string]interface{}{"path": "/etc/shadow"},
		},
		Rule: &policy.CompiledRule{
			Name:  "block-etc-shadow",
			Index: 1,
		},
		CompiledAction: policy.CompiledAction{
			Type: "deny",
			Parameters: map[string]string{
				"message": "access denied by policy",
			},
		},
		PolicyName:      "security-policy",
		PolicyNamespace: "production",
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Permitted {
		t.Error("expected Permitted=false for deny action")
	}
	if result.ActionType != "deny" {
		t.Errorf("expected ActionType=deny, got %q", result.ActionType)
	}
	if result.RuleName != "block-etc-shadow" {
		t.Errorf("expected RuleName=block-etc-shadow, got %q", result.RuleName)
	}
	if result.PolicyReference != "production/security-policy" {
		t.Errorf("expected PolicyReference=production/security-policy, got %q", result.PolicyReference)
	}
	if result.Message != "access denied by policy" {
		t.Errorf("expected message 'access denied by policy', got %q", result.Message)
	}
}

func TestDenyExecutor_DefaultMessage(t *testing.T) {
	exec := &DenyExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{},
		Rule:  &policy.CompiledRule{Name: "test-rule"},
		CompiledAction: policy.CompiledAction{
			Type: "deny",
		},
		PolicyName: "my-policy",
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Message == "" {
		t.Error("expected non-empty default message for deny action")
	}
}

func TestThrottleExecutor_ProducesDelayDecision(t *testing.T) {
	exec := &ThrottleExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{
			Category:    "llm",
			Subcategory: "prompt_submit",
		},
		Rule: &policy.CompiledRule{Name: "rate-limit-prompts"},
		CompiledAction: policy.CompiledAction{
			Type: "throttle",
			Parameters: map[string]string{
				"retryAfter": "30",
			},
		},
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Permitted {
		t.Error("expected Permitted=false for throttle action")
	}
	if result.ActionType != "throttle" {
		t.Errorf("expected ActionType=throttle, got %q", result.ActionType)
	}
	if result.RetryAfterSeconds != 30 {
		t.Errorf("expected RetryAfterSeconds=30, got %d", result.RetryAfterSeconds)
	}
	if result.StatusCode != 429 {
		t.Errorf("expected StatusCode=429, got %d", result.StatusCode)
	}
}

func TestThrottleExecutor_DefaultRetryAfter(t *testing.T) {
	exec := &ThrottleExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{},
		Rule:  &policy.CompiledRule{Name: "test"},
		CompiledAction: policy.CompiledAction{
			Type: "throttle",
		},
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RetryAfterSeconds != 60 {
		t.Errorf("expected default RetryAfterSeconds=60, got %d", result.RetryAfterSeconds)
	}
}

func TestAlertExecutor_ProducesPermitWithAlert(t *testing.T) {
	exec := &AlertExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{
			Category:    "protocol",
			Subcategory: "tool_call",
			Fields:      map[string]interface{}{"toolName": "execute_command"},
		},
		Rule: &policy.CompiledRule{
			Name:  "alert-on-execute",
			Index: 2,
		},
		CompiledAction: policy.CompiledAction{
			Type: "alert",
			Parameters: map[string]string{
				"severity": "HIGH",
			},
		},
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Permitted {
		t.Error("expected Permitted=true for alert action (allows event through)")
	}
	if result.ActionType != "alert" {
		t.Errorf("expected ActionType=alert, got %q", result.ActionType)
	}
	if !result.AlertEmitted {
		t.Error("expected AlertEmitted=true")
	}
	if result.AlertSeverity != "HIGH" {
		t.Errorf("expected AlertSeverity=HIGH, got %q", result.AlertSeverity)
	}
}

func TestAlertExecutor_DefaultSeverity(t *testing.T) {
	exec := &AlertExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{},
		Rule:  &policy.CompiledRule{Name: "test"},
		CompiledAction: policy.CompiledAction{
			Type: "alert",
		},
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AlertSeverity != "MEDIUM" {
		t.Errorf("expected default AlertSeverity=MEDIUM, got %q", result.AlertSeverity)
	}
}

func TestQuarantineExecutor_ProducesIsolationDecision(t *testing.T) {
	exec := &QuarantineExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Namespace:   "production",
			PodName:     "agent-pod-1",
		},
		Rule: &policy.CompiledRule{
			Name:  "quarantine-malicious",
			Index: 0,
		},
		CompiledAction: policy.CompiledAction{
			Type: "quarantine",
			Parameters: map[string]string{
				"level":       "3",
				"denyNetwork": "true",
				"denyTools":   "true",
			},
		},
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Permitted {
		t.Error("expected Permitted=false for quarantine action")
	}
	if result.ActionType != "quarantine" {
		t.Errorf("expected ActionType=quarantine, got %q", result.ActionType)
	}
	if result.ContainmentLevel != 3 {
		t.Errorf("expected ContainmentLevel=3, got %d", result.ContainmentLevel)
	}
	if !result.DenyNetwork {
		t.Error("expected DenyNetwork=true")
	}
	if !result.DenyTools {
		t.Error("expected DenyTools=true")
	}
}

func TestQuarantineExecutor_DefaultContainmentLevel(t *testing.T) {
	exec := &QuarantineExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{},
		Rule:  &policy.CompiledRule{Name: "test"},
		CompiledAction: policy.CompiledAction{
			Type: "quarantine",
		},
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ContainmentLevel != 1 {
		t.Errorf("expected default ContainmentLevel=1, got %d", result.ContainmentLevel)
	}
}

func TestRedirectExecutor_ProducesRewrittenTarget(t *testing.T) {
	exec := &RedirectExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{
			Category:    "protocol",
			Subcategory: "tool_call",
			Fields: map[string]interface{}{
				"toolName": "execute_command",
				"target":   "https://api.example.com/run",
			},
		},
		Rule: &policy.CompiledRule{Name: "redirect-to-sandbox"},
		CompiledAction: policy.CompiledAction{
			Type: "redirect",
			Parameters: map[string]string{
				"target": "https://sandbox.example.com/run",
			},
		},
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Permitted {
		t.Error("expected Permitted=true for redirect (allows modified request)")
	}
	if result.ActionType != "redirect" {
		t.Errorf("expected ActionType=redirect, got %q", result.ActionType)
	}
	if result.RedirectTarget != "https://sandbox.example.com/run" {
		t.Errorf("expected RedirectTarget=https://sandbox.example.com/run, got %q", result.RedirectTarget)
	}
}

func TestMutateExecutor_ProducesModifiedFields(t *testing.T) {
	exec := &MutateExecutor{}
	ctx := &ActionContext{
		Event: &policy.PolicyEvent{
			Category:    "llm",
			Subcategory: "prompt_submit",
			Fields: map[string]interface{}{
				"prompt": "sensitive data here",
			},
		},
		Rule: &policy.CompiledRule{Name: "sanitize-prompt"},
		CompiledAction: policy.CompiledAction{
			Type: "mutate",
			Parameters: map[string]string{
				"stripFields":  "sensitiveArg",
				"injectPrefix": "[SAFETY] ",
			},
		},
	}

	result, err := exec.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Permitted {
		t.Error("expected Permitted=true for mutate (allows modified request)")
	}
	if result.ActionType != "mutate" {
		t.Errorf("expected ActionType=mutate, got %q", result.ActionType)
	}
	if len(result.Mutations) == 0 {
		t.Error("expected non-empty Mutations map")
	}
	if result.Mutations["stripFields"] != "sensitiveArg" {
		t.Errorf("expected stripFields mutation, got %v", result.Mutations)
	}
}

func TestActionExecutorRegistry_Dispatch(t *testing.T) {
	registry := NewActionExecutorRegistry()

	tests := []struct {
		actionType string
		expectType string
	}{
		{"allow", "allow"},
		{"deny", "deny"},
		{"throttle", "throttle"},
		{"alert", "alert"},
		{"quarantine", "quarantine"},
		{"redirect", "redirect"},
		{"mutate", "mutate"},
	}

	for _, tt := range tests {
		t.Run(tt.actionType, func(t *testing.T) {
			ctx := &ActionContext{
				Event: &policy.PolicyEvent{},
				Rule:  &policy.CompiledRule{Name: "test-rule"},
				CompiledAction: policy.CompiledAction{
					Type: v1alpha1.ActionType(tt.actionType),
				},
			}

			result, err := registry.Execute(tt.actionType, ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.ActionType != tt.expectType {
				t.Errorf("expected ActionType=%q, got %q", tt.expectType, result.ActionType)
			}
		})
	}
}

func TestActionExecutorRegistry_UnknownAction(t *testing.T) {
	registry := NewActionExecutorRegistry()

	ctx := &ActionContext{
		Event: &policy.PolicyEvent{},
		Rule:  &policy.CompiledRule{Name: "test"},
		CompiledAction: policy.CompiledAction{
			Type: "unknown",
		},
	}

	_, err := registry.Execute("unknown", ctx)
	if err == nil {
		t.Error("expected error for unknown action type, got nil")
	}
}
