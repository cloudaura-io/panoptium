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

package policy_test

import (
	"testing"
	"time"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/policy"
	"github.com/panoptium/panoptium/pkg/policy/action"
	"github.com/panoptium/panoptium/pkg/policy/predicate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const categoryKernel = "kernel"

func TestIntegration_CompileEvaluateDecisionTrace(t *testing.T) {
	pol := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trace-test",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "deny-curl-etc",
					Trigger: v1alpha1.Trigger{
						EventCategory:    categoryKernel,
						EventSubcategory: "process_exec",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.processName == "curl"`},
						{CEL: `event.path.glob("/etc/**")`},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}

	compiler := policy.NewPolicyCompiler()
	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	tree := policy.NewDecisionTree(compiled)

	event := &policy.PolicyEvent{
		Category:    categoryKernel,
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"processName": "curl",
			"path":        "/etc/passwd",
		},
	}

	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	if !decision.Matched {
		t.Fatal("expected Matched=true")
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny, got %q", decision.Action.Type)
	}
	if decision.EvaluationDuration == 0 {
		t.Error("expected non-zero EvaluationDuration")
	}
	if len(decision.PredicateTrace) < 2 {
		t.Errorf("expected at least 2 trace entries, got %d", len(decision.PredicateTrace))
	}
	for _, trace := range decision.PredicateTrace {
		if !trace.Matched {
			t.Errorf("expected all predicates matched, but %q did not", trace.PredicateCEL)
		}
	}
}

func TestIntegration_MultiPolicyComposition(t *testing.T) {
	compiler := policy.NewPolicyCompiler()

	denyPol := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-policy",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        200,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "deny-curl",
					Trigger: v1alpha1.Trigger{
						EventCategory:    categoryKernel,
						EventSubcategory: "process_exec",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.processName == "curl"`},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}

	allowPol := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-policy",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "allow-all",
					Trigger: v1alpha1.Trigger{
						EventCategory:    categoryKernel,
						EventSubcategory: "process_exec",
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAllow},
					Severity: v1alpha1.SeverityInfo,
				},
			},
		},
	}

	compiledDeny, err := compiler.Compile(denyPol)
	if err != nil {
		t.Fatalf("Compile deny: %v", err)
	}
	compiledAllow, err := compiler.Compile(allowPol)
	if err != nil {
		t.Fatalf("Compile allow: %v", err)
	}

	resolver := policy.NewPolicyCompositionResolver()

	event := &policy.PolicyEvent{
		Category:    categoryKernel,
		Subcategory: "process_exec",
		Namespace:   "default",
		PodLabels:   map[string]string{"app": "agent"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate([]*policy.CompiledPolicy{compiledDeny, compiledAllow}, event)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny from high-priority policy, got %q", decision.Action.Type)
	}
	if decision.PolicyName != "deny-policy" {
		t.Errorf("expected deny-policy, got %q", decision.PolicyName)
	}

	event2 := &policy.PolicyEvent{
		Category:    categoryKernel,
		Subcategory: "process_exec",
		Namespace:   "default",
		PodLabels:   map[string]string{"app": "agent"},
		Fields:      map[string]interface{}{"processName": "python"},
	}

	decision2, err := resolver.Evaluate([]*policy.CompiledPolicy{compiledDeny, compiledAllow}, event2)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if decision2.Action.Type != "allow" {
		t.Errorf("expected allow for python, got %q", decision2.Action.Type)
	}
}

func TestIntegration_RateLimitingAcrossEvaluations(t *testing.T) {
	counter := predicate.NewSlidingWindowCounter(5 * time.Second)
	eval := &predicate.RateLimitEvaluator{
		Counter:       counter,
		Limit:         3,
		GroupByField:  "agentID",
		AutoIncrement: true,
	}

	for i := 0; i < 2; i++ {
		event := &policy.PolicyEvent{
			Category:    "protocol",
			Subcategory: "tool_call",
			Fields: map[string]interface{}{
				"agentID":  "agent-1",
				"toolName": "execute_command",
			},
		}
		matched, err := eval.Evaluate(event)
		if err != nil {
			t.Fatalf("iteration %d: error: %v", i, err)
		}
		if matched {
			t.Errorf("iteration %d: expected false (below limit)", i)
		}
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID":  "agent-1",
			"toolName": "execute_command",
		},
	}
	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("third: error: %v", err)
	}
	if !matched {
		t.Error("expected true (at limit) on third evaluation")
	}
}

func TestIntegration_TemporalSequenceDetection(t *testing.T) {
	detector := predicate.NewTemporalSequenceDetector()

	events := []struct {
		category    string
		subcategory string
	}{
		{categoryKernel, "process_exec"},
		{categoryKernel, "file_write"},
		{"network", "egress_attempt"},
	}

	for _, e := range events {
		ev := &policy.PolicyEvent{
			Category:    e.category,
			Subcategory: e.subcategory,
			Timestamp:   time.Now(),
			Fields: map[string]interface{}{
				"agentID": "agent-1",
			},
		}
		detector.RecordEvent("agent-1", ev)
	}

	eval := &predicate.TemporalSequenceEvaluator{
		Detector:              detector,
		PrecededByCategory:    categoryKernel,
		PrecededBySubcategory: "file_write",
		Window:                5 * time.Second,
		SessionField:          "agentID",
	}

	checkEvent := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	matched, err := eval.Evaluate(checkEvent)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !matched {
		t.Error("expected true (file_write preceded egress_attempt)")
	}
}

func TestIntegration_EscalationChainRepeatedViolations(t *testing.T) {
	proc := action.NewEscalationProcessor([]action.EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 3, Window: 5 * time.Second},
	})

	registry := action.NewActionExecutorRegistry()

	for i := 0; i < 3; i++ {
		ctx := &action.ActionContext{
			Event: &policy.PolicyEvent{
				Category:    categoryKernel,
				Subcategory: "process_exec",
			},
			Rule: &policy.CompiledRule{Name: "deny-curl", Index: 0},
			CompiledAction: policy.CompiledAction{
				Type: "deny",
			},
			PolicyName: "security-policy",
		}

		result, err := registry.Execute("deny", ctx)
		if err != nil {
			t.Fatalf("execute deny %d: %v", i, err)
		}
		if result.Permitted {
			t.Errorf("deny %d: expected Permitted=false", i)
		}

		proc.RecordAction("agent-1", "deny")
	}

	escalated, toAction := proc.CheckEscalation("agent-1", "deny")
	if !escalated {
		t.Fatal("expected escalation after 3 denials")
	}
	if toAction != "quarantine" {
		t.Errorf("expected escalation to quarantine, got %q", toAction)
	}

	ctx := &action.ActionContext{
		Event: &policy.PolicyEvent{
			Category:    categoryKernel,
			Subcategory: "process_exec",
		},
		Rule: &policy.CompiledRule{Name: "deny-curl", Index: 0},
		CompiledAction: policy.CompiledAction{
			Type: "quarantine",
			Parameters: map[string]string{
				"level":       "3",
				"denyNetwork": "true",
			},
		},
		PolicyName: "security-policy",
	}

	result, err := registry.Execute("quarantine", ctx)
	if err != nil {
		t.Fatalf("execute quarantine: %v", err)
	}
	if result.Permitted {
		t.Error("quarantine: expected Permitted=false")
	}
	if result.ContainmentLevel != 3 {
		t.Errorf("expected ContainmentLevel=3, got %d", result.ContainmentLevel)
	}
}

func TestIntegration_DecisionEventPublished(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(eventbus.EventTypePolicyDecision)
	pub := policy.NewDecisionPublisher(bus)

	pol := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "publish-test",
			Namespace: "default",
		},
		Spec: v1alpha1.AgentPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "deny-curl",
					Trigger: v1alpha1.Trigger{
						EventCategory:    categoryKernel,
						EventSubcategory: "process_exec",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.processName == "curl"`},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}

	compiler := policy.NewPolicyCompiler()
	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	tree := policy.NewDecisionTree(compiled)

	event := &policy.PolicyEvent{
		Category:    categoryKernel,
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := tree.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	pub.Publish(decision, event)

	select {
	case ev := <-sub.Events():
		pde, ok := ev.(*policy.PolicyDecisionEvent)
		if !ok {
			t.Fatalf("expected *PolicyDecisionEvent, got %T", ev)
		}
		if !pde.Matched {
			t.Error("expected Matched=true")
		}
		if pde.MatchedRule != "deny-curl" {
			t.Errorf("expected MatchedRule=deny-curl, got %q", pde.MatchedRule)
		}
		if string(pde.ActionTaken) != "deny" {
			t.Errorf("expected ActionTaken=deny, got %q", pde.ActionTaken)
		}
		if pde.TriggerCategory != categoryKernel {
			t.Errorf("expected TriggerCategory=kernel, got %q", pde.TriggerCategory)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for policy.decision event")
	}
}
