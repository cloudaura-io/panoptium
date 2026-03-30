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
)

func TestDecisionTree_RulesOrderedByPriority(t *testing.T) {
	// Create a compiled policy with rules that should be evaluated in index order.
	compiled := &CompiledPolicy{
		Name:      "priority-test",
		Namespace: "default",
		Priority:  100,
		Rules: []*CompiledRule{
			{
				Name:         "high-priority-rule",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeDeny,
				},
				Severity: v1alpha1.SeverityHigh,
			},
			{
				Name:         "low-priority-rule",
				Index:        1,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeAllow,
				},
				Severity: v1alpha1.SeverityLow,
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{},
	}

	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	// First matching rule (index 0, deny) should win.
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, v1alpha1.ActionTypeDeny)
	}
	if decision.MatchedRule != "high-priority-rule" {
		t.Errorf("Decision.MatchedRule = %q, want %q", decision.MatchedRule, "high-priority-rule")
	}
}

func TestDecisionTree_FirstMatchSemantics(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "first-match-test",
		Namespace: "default",
		Priority:  100,
		Rules: []*CompiledRule{
			{
				Name:         "rule-1-deny",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeDeny,
				},
				Severity: v1alpha1.SeverityHigh,
			},
			{
				Name:         "rule-2-alert",
				Index:        1,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeAlert,
				},
				Severity: v1alpha1.SeverityMedium,
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{},
	}

	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	// First match wins — rule-1-deny.
	if decision.MatchedRule != "rule-1-deny" {
		t.Errorf("Decision.MatchedRule = %q, want %q", decision.MatchedRule, "rule-1-deny")
	}
	if decision.MatchedRuleIndex != 0 {
		t.Errorf("Decision.MatchedRuleIndex = %d, want 0", decision.MatchedRuleIndex)
	}
}

func TestDecisionTree_DefaultAllow(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "no-match-test",
		Namespace: "default",
		Priority:  100,
		Rules: []*CompiledRule{
			{
				Name:         "kernel-only-rule",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeDeny,
				},
				Severity: v1alpha1.SeverityHigh,
			},
		},
	}

	tree := NewDecisionTree(compiled)
	// Send a network event that won't match the kernel rule.
	event := &PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{},
	}

	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for non-matching event")
	}
	if decision.Action.Type != "allow" {
		t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, "allow")
	}
	if decision.MatchedRuleIndex != -1 {
		t.Errorf("Decision.MatchedRuleIndex = %d, want -1", decision.MatchedRuleIndex)
	}
}

func TestDecisionTree_MixedTriggerTypes(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "mixed-trigger-test",
		Namespace: "default",
		Priority:  100,
		Rules: []*CompiledRule{
			{
				Name:         "kernel-rule",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeDeny,
				},
				Severity: v1alpha1.SeverityHigh,
			},
			{
				Name:         "network-rule",
				Index:        1,
				TriggerLayer: "network",
				TriggerEvent: "egress_attempt",
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeAlert,
				},
				Severity: v1alpha1.SeverityMedium,
			},
			{
				Name:         "llm-rule",
				Index:        2,
				TriggerLayer: "llm",
				TriggerEvent: "prompt_submit",
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeRateLimit,
				},
				Severity: v1alpha1.SeverityLow,
			},
		},
	}

	tree := NewDecisionTree(compiled)

	tests := []struct {
		name          string
		category      string
		subcategory   string
		wantAction    v1alpha1.ActionType
		wantRule      string
		wantRuleIndex int
		wantMatched   bool
	}{
		{
			name:          "kernel event matches kernel rule",
			category:      "kernel",
			subcategory:   "process_exec",
			wantAction:    v1alpha1.ActionTypeDeny,
			wantRule:      "kernel-rule",
			wantRuleIndex: 0,
			wantMatched:   true,
		},
		{
			name:          "network event matches network rule",
			category:      "network",
			subcategory:   "egress_attempt",
			wantAction:    v1alpha1.ActionTypeAlert,
			wantRule:      "network-rule",
			wantRuleIndex: 1,
			wantMatched:   true,
		},
		{
			name:          "llm event matches llm rule",
			category:      "llm",
			subcategory:   "prompt_submit",
			wantAction:    v1alpha1.ActionTypeRateLimit,
			wantRule:      "llm-rule",
			wantRuleIndex: 2,
			wantMatched:   true,
		},
		{
			name:          "protocol event matches no rule",
			category:      "protocol",
			subcategory:   "tool_call",
			wantAction:    "allow",
			wantRule:      "",
			wantRuleIndex: -1,
			wantMatched:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &PolicyEvent{
				Category:    tt.category,
				Subcategory: tt.subcategory,
				Timestamp:   time.Now(),
				Fields:      map[string]interface{}{},
			}
			decision, err := tree.Evaluate(event)
			if err != nil {
				t.Fatalf("Evaluate() unexpected error: %v", err)
			}
			if decision.Matched != tt.wantMatched {
				t.Errorf("Decision.Matched = %v, want %v", decision.Matched, tt.wantMatched)
			}
			if decision.Action.Type != tt.wantAction {
				t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, tt.wantAction)
			}
			if decision.MatchedRule != tt.wantRule {
				t.Errorf("Decision.MatchedRule = %q, want %q", decision.MatchedRule, tt.wantRule)
			}
			if decision.MatchedRuleIndex != tt.wantRuleIndex {
				t.Errorf("Decision.MatchedRuleIndex = %d, want %d", decision.MatchedRuleIndex, tt.wantRuleIndex)
			}
		})
	}
}

func TestDecisionTree_PredicateFiltering(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "predicate-test",
		Namespace: "default",
		Priority:  100,
		Rules: []*CompiledRule{
			{
				Name:         "deny-curl",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.processName == "curl"`,
						FieldPath: "event.processName",
						Operator:  "==",
						Value:     "curl",
					},
				},
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeDeny,
				},
				Severity: v1alpha1.SeverityHigh,
			},
			{
				Name:         "allow-all-exec",
				Index:        1,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Action: CompiledAction{
					Type: v1alpha1.ActionTypeAllow,
				},
				Severity: v1alpha1.SeverityLow,
			},
		},
	}

	tree := NewDecisionTree(compiled)

	// Event with processName=curl should hit deny-curl.
	curlEvent := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}
	decision, err := tree.Evaluate(curlEvent)
	if err != nil {
		t.Fatalf("Evaluate(curl) unexpected error: %v", err)
	}
	if decision.MatchedRule != "deny-curl" {
		t.Errorf("curl event: MatchedRule = %q, want %q", decision.MatchedRule, "deny-curl")
	}

	// Event with processName=ls should skip deny-curl and hit allow-all-exec.
	lsEvent := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"processName": "ls",
		},
	}
	decision, err = tree.Evaluate(lsEvent)
	if err != nil {
		t.Fatalf("Evaluate(ls) unexpected error: %v", err)
	}
	if decision.MatchedRule != "allow-all-exec" {
		t.Errorf("ls event: MatchedRule = %q, want %q", decision.MatchedRule, "allow-all-exec")
	}
}

func TestDecisionTree_EvaluationDuration(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "duration-test",
		Namespace: "default",
		Priority:  100,
		Rules: []*CompiledRule{
			{
				Name:         "rule-1",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity:     v1alpha1.SeverityHigh,
			},
		},
	}
	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if decision.EvaluationDuration <= 0 {
		t.Error("Decision.EvaluationDuration should be > 0")
	}
}

func TestDecisionTree_EmptyRules(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "empty-test",
		Namespace: "default",
		Priority:  100,
		Rules:     []*CompiledRule{},
	}
	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for empty rules")
	}
	if decision.Action.Type != "allow" {
		t.Errorf("Decision.Action.Type = %q, want %q", decision.Action.Type, "allow")
	}
}
