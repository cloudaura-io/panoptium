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

func TestGetField_ExistingKey(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}
	got := e.GetField("processName")
	if got != "curl" {
		t.Errorf("GetField(\"processName\") = %v, want %q", got, "curl")
	}
}

func TestGetField_MissingKey(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}
	got := e.GetField("nonexistent")
	if got != nil {
		t.Errorf("GetField(\"nonexistent\") = %v, want nil", got)
	}
}

func TestGetField_NilFieldsMap(t *testing.T) {
	e := &PolicyEvent{
		Fields: nil,
	}
	got := e.GetField("anything")
	if got != nil {
		t.Errorf("GetField with nil Fields = %v, want nil", got)
	}
}

func TestGetStringField_StringValue(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}
	got := e.GetStringField("processName")
	if got != "curl" {
		t.Errorf("GetStringField(\"processName\") = %q, want %q", got, "curl")
	}
}

func TestGetStringField_NonStringValue(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"pid": 1234,
		},
	}
	got := e.GetStringField("pid")
	if got != "1234" {
		t.Errorf("GetStringField(\"pid\") = %q, want %q", got, "1234")
	}
}

func TestGetStringField_NilFieldsMap(t *testing.T) {
	e := &PolicyEvent{
		Fields: nil,
	}
	got := e.GetStringField("anything")
	if got != "" {
		t.Errorf("GetStringField with nil Fields = %q, want empty string", got)
	}
}

func TestGetIntField_IntValue(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"pid": 42,
		},
	}
	got := e.GetIntField("pid")
	if got != 42 {
		t.Errorf("GetIntField(\"pid\") = %d, want %d", got, 42)
	}
}

func TestGetIntField_Int64Value(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"bigPid": int64(999),
		},
	}
	got := e.GetIntField("bigPid")
	if got != 999 {
		t.Errorf("GetIntField(\"bigPid\") with int64 = %d, want 999", got)
	}
}

func TestGetIntField_Float64Value(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"score": float64(3.14),
		},
	}
	got := e.GetIntField("score")
	if got != 3 {
		t.Errorf("GetIntField(\"score\") with float64 = %d, want 3", got)
	}
}

func TestGetIntField_NonNumericValue(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"name": "not-a-number",
		},
	}
	got := e.GetIntField("name")
	if got != 0 {
		t.Errorf("GetIntField(\"name\") = %d, want 0", got)
	}
}

func TestGetIntField_NilFieldsMap(t *testing.T) {
	e := &PolicyEvent{
		Fields: nil,
	}
	got := e.GetIntField("anything")
	if got != 0 {
		t.Errorf("GetIntField with nil Fields = %d, want 0", got)
	}
}

func TestEvaluationResult_ActionClassification(t *testing.T) {
	result := &EvaluationResult{
		Decisions: []*Decision{
			{Action: CompiledAction{Type: "alert"}, Matched: true, MatchedRule: "alert-rule"},
			{
				Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}, Matched: true,
				MatchedRule: "deny-tool", PolicyName: "tool-deny",
			},
			{Action: CompiledAction{Type: "rateLimit"}, Matched: true, MatchedRule: "rate-rule"},
			{Action: CompiledAction{Type: "quarantine"}, Matched: true, MatchedRule: "quarantine-rule"},
		},
	}

	nonTerminal := result.NonTerminalDecisions()
	if len(nonTerminal) != 1 {
		t.Fatalf("NonTerminalDecisions() returned %d decisions, want 1", len(nonTerminal))
	}
	if nonTerminal[0].Action.Type != "alert" {
		t.Errorf("NonTerminalDecisions()[0].Action.Type = %q, want %q", nonTerminal[0].Action.Type, "alert")
	}

	terminal := result.TerminalDecisions()
	if len(terminal) != 2 {
		t.Fatalf("TerminalDecisions() returned %d decisions, want 2", len(terminal))
	}

	rateControl := result.RateControlDecisions()
	if len(rateControl) != 1 {
		t.Fatalf("RateControlDecisions() returned %d decisions, want 1", len(rateControl))
	}
	if rateControl[0].Action.Type != "rateLimit" {
		t.Errorf("RateControlDecisions()[0].Action.Type = %q, want %q", rateControl[0].Action.Type, "rateLimit")
	}
}

func TestEvaluationResult_Empty(t *testing.T) {
	result := &EvaluationResult{
		DefaultAllow: true,
	}
	effective := result.EffectiveAction()
	if effective.Type != v1alpha1.ActionTypeAllow {
		t.Errorf("EffectiveAction().Type = %q, want %q", effective.Type, v1alpha1.ActionTypeAllow)
	}
}

func TestEvaluationResult_DenyFirst(t *testing.T) {
	result := &EvaluationResult{
		Decisions: []*Decision{
			{Action: CompiledAction{Type: v1alpha1.ActionTypeAllow}, Matched: true, MatchedRule: "allow-rule"},
			{Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}, Matched: true, MatchedRule: "deny-rule"},
		},
	}
	effective := result.EffectiveAction()
	if effective.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("EffectiveAction().Type = %q, want %q (deny-first semantics)", effective.Type, v1alpha1.ActionTypeDeny)
	}
}

func TestEvaluationResult_CollectsAll(t *testing.T) {
	d1 := &Decision{Action: CompiledAction{Type: "alert"}, Matched: true, PolicyName: "pol-1"}
	d2 := &Decision{Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}, Matched: true, PolicyName: "pol-2"}
	d3 := &Decision{Action: CompiledAction{Type: v1alpha1.ActionTypeAllow}, Matched: true, PolicyName: "pol-3"}
	result := &EvaluationResult{
		Decisions: []*Decision{d1, d2, d3},
	}
	if len(result.Decisions) != 3 {
		t.Fatalf("Decisions has %d entries, want 3", len(result.Decisions))
	}
	if result.Decisions[0].PolicyName != "pol-1" {
		t.Errorf("Decisions[0].PolicyName = %q, want %q", result.Decisions[0].PolicyName, "pol-1")
	}
	if result.Decisions[1].PolicyName != "pol-2" {
		t.Errorf("Decisions[1].PolicyName = %q, want %q", result.Decisions[1].PolicyName, "pol-2")
	}
	if result.Decisions[2].PolicyName != "pol-3" {
		t.Errorf("Decisions[2].PolicyName = %q, want %q", result.Decisions[2].PolicyName, "pol-3")
	}
}

func TestEvaluationResult_HasDeny(t *testing.T) {
	result := &EvaluationResult{
		Decisions: []*Decision{
			{Action: CompiledAction{Type: v1alpha1.ActionTypeAllow}, Matched: true},
		},
	}
	if result.HasDeny() {
		t.Error("HasDeny() = true, want false (no deny decisions)")
	}

	result.Decisions = append(result.Decisions, &Decision{
		Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}, Matched: true,
	})
	if !result.HasDeny() {
		t.Error("HasDeny() = false, want true (has deny decision)")
	}
}

func TestEvaluationResult_MutatingDecisions(t *testing.T) {
	result := &EvaluationResult{
		Decisions: []*Decision{
			{
				Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}, Matched: true,
				MatchedRule: "deny-tool", Subcategory: "tool_call",
			},
			{
				Action: CompiledAction{Type: v1alpha1.ActionTypeDeny}, Matched: true,
				MatchedRule: "deny-request", Subcategory: "llm_request",
			},
			{Action: CompiledAction{Type: "alert"}, Matched: true, MatchedRule: "alert-rule", Subcategory: "tool_call"},
		},
	}
	mutating := result.MutatingDecisions()
	if len(mutating) != 1 {
		t.Fatalf("MutatingDecisions() returned %d decisions, want 1 (only deny on tool_call)", len(mutating))
	}
	if mutating[0].MatchedRule != "deny-tool" {
		t.Errorf("MutatingDecisions()[0].MatchedRule = %q, want %q", mutating[0].MatchedRule, "deny-tool")
	}
}

func TestDefaultAllowDecision_ReturnsAllowAction(t *testing.T) {
	d := DefaultAllowDecision()
	if d.Action.Type != v1alpha1.ActionTypeAllow {
		t.Errorf("DefaultAllowDecision().Action.Type = %q, want %q", d.Action.Type, v1alpha1.ActionTypeAllow)
	}
}

func TestDefaultAllowDecision_FieldValues(t *testing.T) {
	d := DefaultAllowDecision()
	if d.Matched {
		t.Error("DefaultAllowDecision().Matched = true, want false")
	}
	if d.MatchedRule != "" {
		t.Errorf("DefaultAllowDecision().MatchedRule = %q, want empty", d.MatchedRule)
	}
	if d.MatchedRuleIndex != -1 {
		t.Errorf("DefaultAllowDecision().MatchedRuleIndex = %d, want -1", d.MatchedRuleIndex)
	}
	if d.PolicyName != "" {
		t.Errorf("DefaultAllowDecision().PolicyName = %q, want empty", d.PolicyName)
	}
	if d.PolicyNamespace != "" {
		t.Errorf("DefaultAllowDecision().PolicyNamespace = %q, want empty", d.PolicyNamespace)
	}
	if d.Action.Parameters != nil {
		t.Errorf("DefaultAllowDecision().Action.Parameters = %v, want nil", d.Action.Parameters)
	}
}
