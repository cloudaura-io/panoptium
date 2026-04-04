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
	"net"
	"regexp"
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

func TestDecisionTree_InequalityOperator(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "neq-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "deny-not-python",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.processName != "python"`,
						FieldPath: "event.processName",
						Operator:  "!=",
						Value:     "python",
					},
				},
				Action:   CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity: v1alpha1.SeverityHigh,
			},
		},
	}

	tree := NewDecisionTree(compiled)

	t.Run("not equal returns true when field differs", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"processName": "curl"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true when field != value")
		}
		if decision.MatchedRule != "deny-not-python" {
			t.Errorf("Decision.MatchedRule = %q, want %q", decision.MatchedRule, "deny-not-python")
		}
	})

	t.Run("not equal returns false when field equals value", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"processName": "python"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if decision.Matched {
			t.Error("Decision.Matched = true, want false when field == value for != operator")
		}
	})
}

func TestDecisionTree_GreaterThanOperator(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "gt-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "alert-high-tokens",
				Index:        0,
				TriggerLayer: "llm",
				TriggerEvent: "completion_receive",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.tokenCount > 1000`,
						FieldPath: "event.tokenCount",
						Operator:  ">",
						Value:     "1000",
					},
				},
				Action:   CompiledAction{Type: v1alpha1.ActionTypeAlert},
				Severity: v1alpha1.SeverityMedium,
			},
		},
	}

	tree := NewDecisionTree(compiled)

	t.Run("greater than with int field value", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "llm",
			Subcategory: "completion_receive",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"tokenCount": 1500},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true for int > threshold")
		}
	})

	t.Run("greater than with float64 field value", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "llm",
			Subcategory: "completion_receive",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"tokenCount": float64(1500.5)},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true for float64 > threshold")
		}
	})

	t.Run("greater than returns false when below threshold", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "llm",
			Subcategory: "completion_receive",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"tokenCount": 500},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if decision.Matched {
			t.Error("Decision.Matched = true, want false for value < threshold")
		}
	})
}

func TestDecisionTree_LessThanOperator(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "lt-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "alert-low-latency",
				Index:        0,
				TriggerLayer: "llm",
				TriggerEvent: "completion_receive",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.latencyMs < 100`,
						FieldPath: "event.latencyMs",
						Operator:  "<",
						Value:     "100",
					},
				},
				Action:   CompiledAction{Type: v1alpha1.ActionTypeAlert},
				Severity: v1alpha1.SeverityLow,
			},
		},
	}

	tree := NewDecisionTree(compiled)

	t.Run("less than with int field value", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "llm",
			Subcategory: "completion_receive",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"latencyMs": 50},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true for int < threshold")
		}
	})

	t.Run("less than with float64 field value", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "llm",
			Subcategory: "completion_receive",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"latencyMs": float64(50.5)},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true for float64 < threshold")
		}
	})

	t.Run("less than returns false when above threshold", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "llm",
			Subcategory: "completion_receive",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"latencyMs": 200},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if decision.Matched {
			t.Error("Decision.Matched = true, want false for value > threshold")
		}
	})
}

func TestDecisionTree_RegexEvaluation(t *testing.T) {
	re := regexp.MustCompile(`^/tmp/.*\.sh$`)
	compiled := &CompiledPolicy{
		Name:      "regex-eval-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "deny-tmp-scripts",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "file_open",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.path.matches("^/tmp/.*\\.sh$")`,
						FieldPath: "event.path",
						Operator:  "matches",
						Value:     `^/tmp/.*\.sh$`,
					},
				},
				Action:          CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity:        v1alpha1.SeverityHigh,
				CompiledRegexes: map[string]*regexp.Regexp{`^/tmp/.*\.sh$`: re},
				CompiledGlobs:   map[string]*GlobMatcher{},
				CompiledCIDRs:   map[string]*net.IPNet{},
			},
		},
	}

	tree := NewDecisionTree(compiled)

	t.Run("regex matches", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "file_open",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"path": "/tmp/exploit.sh"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true for regex match")
		}
	})

	t.Run("regex does not match", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "file_open",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"path": "/home/user/script.py"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if decision.Matched {
			t.Error("Decision.Matched = true, want false for regex non-match")
		}
	})
}

func TestDecisionTree_GlobEvaluation(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "glob-eval-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "deny-etc-writes",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "file_write",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.path.glob("/etc/**")`,
						FieldPath: "event.path",
						Operator:  "glob",
						Value:     "/etc/**",
					},
				},
				Action:          CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity:        v1alpha1.SeverityHigh,
				CompiledRegexes: map[string]*regexp.Regexp{},
				CompiledGlobs:   map[string]*GlobMatcher{"/etc/**": {Pattern: "/etc/**"}},
				CompiledCIDRs:   map[string]*net.IPNet{},
			},
		},
	}

	tree := NewDecisionTree(compiled)

	t.Run("glob matches", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "file_write",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"path": "/etc/passwd"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true for glob match")
		}
	})

	t.Run("glob does not match", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "file_write",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"path": "/home/user/file.txt"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if decision.Matched {
			t.Error("Decision.Matched = true, want false for glob non-match")
		}
	})
}

func TestDecisionTree_CIDREvaluation(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	compiled := &CompiledPolicy{
		Name:      "cidr-eval-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "alert-internal-network",
				Index:        0,
				TriggerLayer: "network",
				TriggerEvent: "egress_attempt",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.destinationIP.inCIDR("10.0.0.0/8")`,
						FieldPath: "event.destinationIP",
						Operator:  "inCIDR",
						Value:     "10.0.0.0/8",
					},
				},
				Action:          CompiledAction{Type: v1alpha1.ActionTypeAlert},
				Severity:        v1alpha1.SeverityMedium,
				CompiledRegexes: map[string]*regexp.Regexp{},
				CompiledGlobs:   map[string]*GlobMatcher{},
				CompiledCIDRs:   map[string]*net.IPNet{"10.0.0.0/8": ipNet},
			},
		},
	}

	tree := NewDecisionTree(compiled)

	t.Run("CIDR matches", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "network",
			Subcategory: "egress_attempt",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"destinationIP": "10.1.2.3"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true for IP in CIDR")
		}
	})

	t.Run("CIDR does not match", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "network",
			Subcategory: "egress_attempt",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"destinationIP": "192.168.1.1"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if decision.Matched {
			t.Error("Decision.Matched = true, want false for IP not in CIDR")
		}
	})
}

// TestDecisionTree_RawOperatorRemoved verifies that the "raw" operator
// no longer exists and is treated as an unknown operator (returns error).
// This test replaces the previous TestDecisionTree_RawOperator which
// expected raw expressions to always match (security vulnerability).
func TestDecisionTree_RawOperatorRemoved(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "raw-op-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "raw-no-longer-matches",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `some.complex.cel.expression()`,
						FieldPath: "some.complex.cel.expression()",
						Operator:  "raw",
						Value:     "some.complex.cel.expression()",
					},
				},
				Action:   CompiledAction{Type: v1alpha1.ActionTypeAlert},
				Severity: v1alpha1.SeverityLow,
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"processName": "anything"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	// The "raw" operator is now treated as an unknown operator, so
	// the predicate fails to match and the rule is skipped.
	if decision.Matched {
		t.Error("raw operator should not match anymore (security fix)")
	}
}

func TestDecisionTree_UnknownOperator(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "unknown-op-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "rule-with-unknown-op",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.field ?? "value"`,
						FieldPath: "event.field",
						Operator:  "??",
						Value:     "value",
					},
				},
				Action:   CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity: v1alpha1.SeverityHigh,
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"field": "value"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	// Unknown operator should not match (returns false).
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for unknown operator")
	}
	// The trace should contain an error entry.
	found := false
	for _, entry := range decision.PredicateTrace {
		if entry.Error != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("PredicateTrace should contain an error entry for unknown operator")
	}
}

func TestDecisionTree_MultiPredicateAND(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "and-logic-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "deny-curl-to-external",
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
					{
						RawCEL:    `event.uid == "0"`,
						FieldPath: "event.uid",
						Operator:  "==",
						Value:     "0",
					},
				},
				Action:   CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity: v1alpha1.SeverityHigh,
			},
		},
	}

	tree := NewDecisionTree(compiled)

	t.Run("all predicates match (AND success)", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Timestamp:   time.Now(),
			Fields: map[string]interface{}{
				"processName": "curl",
				"uid":         "0",
			},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true when all predicates match")
		}
	})

	t.Run("one predicate fails (AND failure)", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Timestamp:   time.Now(),
			Fields: map[string]interface{}{
				"processName": "curl",
				"uid":         "1000",
			},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if decision.Matched {
			t.Error("Decision.Matched = true, want false when one predicate fails")
		}
	})
}

func TestDecisionTree_PredicateTracePopulated(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "trace-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "traced-rule",
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
					{
						RawCEL:    `event.uid == "0"`,
						FieldPath: "event.uid",
						Operator:  "==",
						Value:     "0",
					},
				},
				Action:   CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity: v1alpha1.SeverityHigh,
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"processName": "curl",
			"uid":         "0",
		},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if len(decision.PredicateTrace) != 2 {
		t.Fatalf("PredicateTrace length = %d, want 2", len(decision.PredicateTrace))
	}
	// First predicate trace entry.
	if decision.PredicateTrace[0].RuleName != "traced-rule" {
		t.Errorf("PredicateTrace[0].RuleName = %q, want %q", decision.PredicateTrace[0].RuleName, "traced-rule")
	}
	if decision.PredicateTrace[0].PredicateCEL != `event.processName == "curl"` {
		t.Errorf("PredicateTrace[0].PredicateCEL = %q, want %q", decision.PredicateTrace[0].PredicateCEL, `event.processName == "curl"`)
	}
	if !decision.PredicateTrace[0].Matched {
		t.Error("PredicateTrace[0].Matched = false, want true")
	}
	if decision.PredicateTrace[0].Duration <= 0 {
		t.Error("PredicateTrace[0].Duration should be > 0")
	}
	// Second predicate trace entry.
	if !decision.PredicateTrace[1].Matched {
		t.Error("PredicateTrace[1].Matched = false, want true")
	}
}

func TestDecisionTree_DecisionMetadata(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "metadata-policy",
		Namespace: "production",
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

	t.Run("PolicyName is set on Decision", func(t *testing.T) {
		if decision.PolicyName != "metadata-policy" {
			t.Errorf("Decision.PolicyName = %q, want %q", decision.PolicyName, "metadata-policy")
		}
	})

	t.Run("PolicyNamespace is set on Decision", func(t *testing.T) {
		if decision.PolicyNamespace != "production" {
			t.Errorf("Decision.PolicyNamespace = %q, want %q", decision.PolicyNamespace, "production")
		}
	})
}

func TestDecisionTree_EmptyTriggerEventMatchesAllSubcategories(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "empty-trigger-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "catch-all-kernel",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "", // Empty subcategory: match all kernel events.
				Action:       CompiledAction{Type: v1alpha1.ActionTypeAlert},
				Severity:     v1alpha1.SeverityLow,
			},
		},
	}

	tree := NewDecisionTree(compiled)

	subcategories := []string{"process_exec", "file_open", "file_write", "module_load"}
	for _, sub := range subcategories {
		t.Run("matches "+sub, func(t *testing.T) {
			event := &PolicyEvent{
				Category:    "kernel",
				Subcategory: sub,
				Timestamp:   time.Now(),
				Fields:      map[string]interface{}{},
			}
			decision, err := tree.Evaluate(event)
			if err != nil {
				t.Fatalf("Evaluate() unexpected error: %v", err)
			}
			if !decision.Matched {
				t.Errorf("Decision.Matched = false, want true for empty TriggerEvent with subcategory %q", sub)
			}
		})
	}
}

func TestDecisionTree_CIDRWithInvalidIP(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	compiled := &CompiledPolicy{
		Name:      "cidr-invalid-ip",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "cidr-rule",
				Index:        0,
				TriggerLayer: "network",
				TriggerEvent: "egress_attempt",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.destinationIP.inCIDR("10.0.0.0/8")`,
						FieldPath: "event.destinationIP",
						Operator:  "inCIDR",
						Value:     "10.0.0.0/8",
					},
				},
				Action:          CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity:        v1alpha1.SeverityHigh,
				CompiledRegexes: map[string]*regexp.Regexp{},
				CompiledGlobs:   map[string]*GlobMatcher{},
				CompiledCIDRs:   map[string]*net.IPNet{"10.0.0.0/8": ipNet},
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"destinationIP": "not-an-ip"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() should not return error for invalid IP, got: %v", err)
	}
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for invalid IP string")
	}
}

func TestDecisionTree_NumericOperatorWithNonNumericField(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "non-numeric-field",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "gt-rule",
				Index:        0,
				TriggerLayer: "llm",
				TriggerEvent: "completion_receive",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.tokenCount > 100`,
						FieldPath: "event.tokenCount",
						Operator:  ">",
						Value:     "100",
					},
				},
				Action:   CompiledAction{Type: v1alpha1.ActionTypeAlert},
				Severity: v1alpha1.SeverityMedium,
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "llm",
		Subcategory: "completion_receive",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"tokenCount": "not-a-number"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() should not return error for non-numeric field, got: %v", err)
	}
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for non-numeric field value")
	}
}

func TestDecisionTree_NumericOperatorWithInvalidPredicateValue(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "invalid-pred-value",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "bad-threshold",
				Index:        0,
				TriggerLayer: "llm",
				TriggerEvent: "completion_receive",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.tokenCount > abc`,
						FieldPath: "event.tokenCount",
						Operator:  ">",
						Value:     "abc",
					},
				},
				Action:   CompiledAction{Type: v1alpha1.ActionTypeAlert},
				Severity: v1alpha1.SeverityMedium,
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "llm",
		Subcategory: "completion_receive",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"tokenCount": 500},
	}
	decision, err := tree.Evaluate(event)
	// The error path: evalNumericComparison returns error when predicate value is invalid.
	// DecisionTree.Evaluate does not propagate evaluatePredicate errors as return errors;
	// it records them in the trace. Let's check what actually happens.
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	// The predicate should not match because parsing "abc" as float fails.
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for invalid predicate value")
	}
	// Check trace for error.
	found := false
	for _, entry := range decision.PredicateTrace {
		if entry.Error != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("PredicateTrace should contain an error for invalid numeric predicate value")
	}
}

func TestDecisionTree_MissingPrecompiledRegex(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "missing-regex",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "regex-rule",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.path.matches("^/tmp/.*$")`,
						FieldPath: "event.path",
						Operator:  "matches",
						Value:     "^/tmp/.*$",
					},
				},
				Action:          CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity:        v1alpha1.SeverityHigh,
				CompiledRegexes: map[string]*regexp.Regexp{}, // Empty — missing the pattern.
				CompiledGlobs:   map[string]*GlobMatcher{},
				CompiledCIDRs:   map[string]*net.IPNet{},
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"path": "/tmp/test.sh"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for missing pre-compiled regex")
	}
	// Check trace for error.
	found := false
	for _, entry := range decision.PredicateTrace {
		if entry.Error != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("PredicateTrace should contain an error for missing pre-compiled regex")
	}
}

func TestDecisionTree_MissingPrecompiledGlob(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "missing-glob",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "glob-rule",
				Index:        0,
				TriggerLayer: "kernel",
				TriggerEvent: "file_write",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.path.glob("/etc/**")`,
						FieldPath: "event.path",
						Operator:  "glob",
						Value:     "/etc/**",
					},
				},
				Action:          CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity:        v1alpha1.SeverityHigh,
				CompiledRegexes: map[string]*regexp.Regexp{},
				CompiledGlobs:   map[string]*GlobMatcher{}, // Empty — missing the pattern.
				CompiledCIDRs:   map[string]*net.IPNet{},
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_write",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"path": "/etc/passwd"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for missing pre-compiled glob")
	}
	found := false
	for _, entry := range decision.PredicateTrace {
		if entry.Error != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("PredicateTrace should contain an error for missing pre-compiled glob")
	}
}

func TestDecisionTree_MissingPrecompiledCIDR(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "missing-cidr",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "cidr-rule",
				Index:        0,
				TriggerLayer: "network",
				TriggerEvent: "egress_attempt",
				Predicates: []CompiledPredicate{
					{
						RawCEL:    `event.destinationIP.inCIDR("10.0.0.0/8")`,
						FieldPath: "event.destinationIP",
						Operator:  "inCIDR",
						Value:     "10.0.0.0/8",
					},
				},
				Action:          CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity:        v1alpha1.SeverityHigh,
				CompiledRegexes: map[string]*regexp.Regexp{},
				CompiledGlobs:   map[string]*GlobMatcher{},
				CompiledCIDRs:   map[string]*net.IPNet{}, // Empty — missing the CIDR.
			},
		},
	}

	tree := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"destinationIP": "10.1.2.3"},
	}
	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("Decision.Matched = true, want false for missing pre-compiled CIDR")
	}
	found := false
	for _, entry := range decision.PredicateTrace {
		if entry.Error != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("PredicateTrace should contain an error for missing pre-compiled CIDR")
	}
}

func TestDecisionTree_ResolveFieldStripPrefix(t *testing.T) {
	compiled := &CompiledPolicy{
		Name:      "resolve-field-test",
		Namespace: "default",
		Rules: []*CompiledRule{
			{
				Name:         "with-prefix",
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
				Action:   CompiledAction{Type: v1alpha1.ActionTypeDeny},
				Severity: v1alpha1.SeverityHigh,
			},
		},
	}

	tree := NewDecisionTree(compiled)

	t.Run("strips event. prefix and resolves field", func(t *testing.T) {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"processName": "curl"},
		}
		decision, err := tree.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true when event. prefix is stripped correctly")
		}
	})

	t.Run("works without event. prefix", func(t *testing.T) {
		// Build a compiled policy with FieldPath without "event." prefix.
		compiled2 := &CompiledPolicy{
			Name:      "no-prefix-test",
			Namespace: "default",
			Rules: []*CompiledRule{
				{
					Name:         "no-prefix",
					Index:        0,
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Predicates: []CompiledPredicate{
						{
							RawCEL:    `processName == "curl"`,
							FieldPath: "processName",
							Operator:  "==",
							Value:     "curl",
						},
					},
					Action:   CompiledAction{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		}
		tree2 := NewDecisionTree(compiled2)
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Timestamp:   time.Now(),
			Fields:      map[string]interface{}{"processName": "curl"},
		}
		decision, err := tree2.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate() unexpected error: %v", err)
		}
		if !decision.Matched {
			t.Error("Decision.Matched = false, want true when FieldPath has no event. prefix")
		}
	})
}
