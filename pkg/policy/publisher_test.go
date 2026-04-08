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
	"github.com/panoptium/panoptium/pkg/eventbus"
)

func TestDecisionPublisher_EmitsMatchedRuleEvent(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(eventbus.EventTypePolicyDecision)

	pub := NewDecisionPublisher(bus)

	decision := &Decision{
		Action:             CompiledAction{Type: v1alpha1.ActionTypeDeny},
		Matched:            true,
		MatchedRule:        "block-curl",
		MatchedRuleIndex:   0,
		PolicyName:         "security-policy",
		PolicyNamespace:    "production",
		EvaluationDuration: 2 * time.Millisecond,
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}

	pub.Publish(decision, event)

	select {
	case ev := <-sub.Events():
		pde, ok := ev.(*PolicyDecisionEvent)
		if !ok {
			t.Fatalf("expected *PolicyDecisionEvent, got %T", ev)
		}
		if pde.MatchedRule != "block-curl" {
			t.Errorf("expected MatchedRule=block-curl, got %q", pde.MatchedRule)
		}
		if string(pde.ActionTaken) != string(v1alpha1.ActionTypeDeny) {
			t.Errorf("expected ActionTaken=deny, got %q", pde.ActionTaken)
		}
		if pde.TriggerCategory != "kernel" {
			t.Errorf("expected TriggerCategory=kernel, got %q", pde.TriggerCategory)
		}
		if pde.TriggerSubcategory != "process_exec" {
			t.Errorf("expected TriggerSubcategory=process_exec, got %q", pde.TriggerSubcategory)
		}
		if pde.PolicyName != "security-policy" {
			t.Errorf("expected PolicyName=security-policy, got %q", pde.PolicyName)
		}
		if pde.PolicyNamespace != "production" {
			t.Errorf("expected PolicyNamespace=production, got %q", pde.PolicyNamespace)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for policy.decision event")
	}
}

func TestDecisionPublisher_EmitsPredicateTrace(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(eventbus.EventTypePolicyDecision)

	pub := NewDecisionPublisher(bus)

	decision := &Decision{
		Action:      CompiledAction{Type: v1alpha1.ActionTypeDeny},
		Matched:     true,
		MatchedRule: "test-rule",
		PredicateTrace: []PredicateTraceEntry{
			{
				RuleName:     "test-rule",
				PredicateCEL: "event.processName == \"curl\"",
				Matched:      true,
				Duration:     1 * time.Millisecond,
			},
			{
				RuleName:     "test-rule",
				PredicateCEL: "event.path.glob(\"/etc/**\")",
				Matched:      false,
				Duration:     500 * time.Microsecond,
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
	}

	pub.Publish(decision, event)

	select {
	case ev := <-sub.Events():
		pde, ok := ev.(*PolicyDecisionEvent)
		if !ok {
			t.Fatalf("expected *PolicyDecisionEvent, got %T", ev)
		}
		if len(pde.PredicateTrace) != 2 {
			t.Fatalf("expected 2 trace entries, got %d", len(pde.PredicateTrace))
		}
		if !pde.PredicateTrace[0].Matched {
			t.Error("expected first trace entry matched=true")
		}
		if pde.PredicateTrace[1].Matched {
			t.Error("expected second trace entry matched=false")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestDecisionPublisher_EmitsNoMatchDefaultAllow(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(eventbus.EventTypePolicyDecision)

	pub := NewDecisionPublisher(bus)

	decision := DefaultAllowDecision()
	decision.PolicyName = "test-policy"

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
	}

	pub.Publish(decision, event)

	select {
	case ev := <-sub.Events():
		pde, ok := ev.(*PolicyDecisionEvent)
		if !ok {
			t.Fatalf("expected *PolicyDecisionEvent, got %T", ev)
		}
		if pde.Matched {
			t.Error("expected Matched=false for default allow")
		}
		if string(pde.ActionTaken) != "allow" {
			t.Errorf("expected ActionTaken=allow, got %q", pde.ActionTaken)
		}
		if pde.MatchedRule != "" {
			t.Errorf("expected empty MatchedRule, got %q", pde.MatchedRule)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestDecisionPublisher_NonBlockingEmission(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	// Subscribe but never read from the channel
	_ = bus.Subscribe(eventbus.EventTypePolicyDecision)

	pub := NewDecisionPublisher(bus)

	decision := &Decision{
		Action:      CompiledAction{Type: v1alpha1.ActionTypeDeny},
		Matched:     true,
		MatchedRule: "test",
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
	}

	// Fill the subscriber buffer
	for i := 0; i < 300; i++ {
		pub.Publish(decision, event)
	}

	// If we get here without blocking, the test passes.
	// The event bus uses non-blocking sends with drop-on-full semantics.
}
