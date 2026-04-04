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

package predicate

import (
	"sync"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/policy"
)

func TestTemporalSequenceDetector_PrecededBy_WithinDuration(t *testing.T) {
	det := NewTemporalSequenceDetector()

	// Record event A for agent-1
	eventA := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID":     "agent-1",
			"processName": "curl",
		},
	}
	det.RecordEvent("agent-1", eventA)

	// Create eval: event B must be precededBy event A (kernel.process_exec) within 5s
	eval := &TemporalSequenceEvaluator{
		Detector:              det,
		PrecededByCategory:    "kernel",
		PrecededBySubcategory: "process_exec",
		Window:                5 * time.Second,
		SessionField:          "agentID",
	}

	// Event B arrives within window
	eventB := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID":       "agent-1",
			"destinationIP": "10.0.0.1",
		},
	}

	matched, err := eval.Evaluate(eventB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected true (event A preceded event B within window), got false")
	}
}

func TestTemporalSequenceDetector_PrecededBy_OutsideDuration(t *testing.T) {
	det := NewTemporalSequenceDetector()

	// Record event A
	eventA := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now().Add(-200 * time.Millisecond),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}
	det.RecordEvent("agent-1", eventA)

	// Wait for window to expire
	time.Sleep(100 * time.Millisecond)

	eval := &TemporalSequenceEvaluator{
		Detector:              det,
		PrecededByCategory:    "kernel",
		PrecededBySubcategory: "process_exec",
		Window:                50 * time.Millisecond,
		SessionField:          "agentID",
	}

	eventB := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	matched, err := eval.Evaluate(eventB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (event A outside duration window), got true")
	}
}

func TestTemporalSequenceDetector_IsolatedSessions(t *testing.T) {
	det := NewTemporalSequenceDetector()

	// Record event A for agent-1 only
	eventA := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}
	det.RecordEvent("agent-1", eventA)

	eval := &TemporalSequenceEvaluator{
		Detector:              det,
		PrecededByCategory:    "kernel",
		PrecededBySubcategory: "process_exec",
		Window:                5 * time.Second,
		SessionField:          "agentID",
	}

	// Event B for agent-2 should NOT match (isolated session)
	eventB2 := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-2",
		},
	}

	matched, err := eval.Evaluate(eventB2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (agent-2 has no preceding event A), got true")
	}

	// Event B for agent-1 should match
	eventB1 := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	matched, err = eval.Evaluate(eventB1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected true (agent-1 has preceding event A), got false")
	}
}

func TestTemporalSequenceDetector_MultiStepSequence(t *testing.T) {
	det := NewTemporalSequenceDetector()

	// Sequence: A -> B -> C within cascading windows
	// Step 1: Record event A (process_exec)
	eventA := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}
	det.RecordEvent("agent-1", eventA)

	// Step 2: Record event B (file_write) preceded by A
	eventB := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_write",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}
	det.RecordEvent("agent-1", eventB)

	// Evaluator for: C must be precededBy B (file_write) within 5s
	evalBC := &TemporalSequenceEvaluator{
		Detector:              det,
		PrecededByCategory:    "kernel",
		PrecededBySubcategory: "file_write",
		Window:                5 * time.Second,
		SessionField:          "agentID",
	}

	// Evaluator for: C must also be preceded by A (process_exec) within 5s
	evalAC := &TemporalSequenceEvaluator{
		Detector:              det,
		PrecededByCategory:    "kernel",
		PrecededBySubcategory: "process_exec",
		Window:                5 * time.Second,
		SessionField:          "agentID",
	}

	eventC := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	matchedBC, err := evalBC.Evaluate(eventC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matchedBC {
		t.Error("expected true (B preceded C within window), got false")
	}

	matchedAC, err := evalAC.Evaluate(eventC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matchedAC {
		t.Error("expected true (A preceded C within window), got false")
	}
}

func TestTemporalSequenceDetector_GarbageCollection(t *testing.T) {
	det := NewTemporalSequenceDetector()

	// Record events with a short window
	eventA := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}
	det.RecordEvent("agent-1", eventA)

	// Wait for events to expire
	time.Sleep(150 * time.Millisecond)

	// Garbage collect with a short max age
	det.GarbageCollect(100 * time.Millisecond)

	// Verify events were cleaned up by checking with an evaluator
	eval := &TemporalSequenceEvaluator{
		Detector:              det,
		PrecededByCategory:    "kernel",
		PrecededBySubcategory: "process_exec",
		Window:                5 * time.Second, // large window, but events should be gone
		SessionField:          "agentID",
	}

	eventB := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Timestamp:   time.Now(),
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	matched, err := eval.Evaluate(eventB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (events garbage collected), got true")
	}
}

func TestTemporalSequenceDetector_ConcurrentAccess(t *testing.T) {
	det := NewTemporalSequenceDetector()

	var wg sync.WaitGroup
	wg.Add(3)

	// Goroutine 1: record events
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			ev := &policy.PolicyEvent{
				Category:    "kernel",
				Subcategory: "process_exec",
				Timestamp:   time.Now(),
				Fields: map[string]interface{}{
					"agentID": "agent-1",
				},
			}
			det.RecordEvent("agent-1", ev)
		}
	}()

	// Goroutine 2: record events for different session
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			ev := &policy.PolicyEvent{
				Category:    "network",
				Subcategory: "egress_attempt",
				Timestamp:   time.Now(),
				Fields: map[string]interface{}{
					"agentID": "agent-2",
				},
			}
			det.RecordEvent("agent-2", ev)
		}
	}()

	// Goroutine 3: evaluate
	go func() {
		defer wg.Done()
		eval := &TemporalSequenceEvaluator{
			Detector:              det,
			PrecededByCategory:    "kernel",
			PrecededBySubcategory: "process_exec",
			Window:                5 * time.Second,
			SessionField:          "agentID",
		}
		for i := 0; i < 50; i++ {
			ev := &policy.PolicyEvent{
				Category:    "network",
				Subcategory: "egress_attempt",
				Timestamp:   time.Now(),
				Fields: map[string]interface{}{
					"agentID": "agent-1",
				},
			}
			_, _ = eval.Evaluate(ev)
		}
	}()

	wg.Wait()
	// Test passes if no race conditions detected
}

func TestTemporalSequenceEvaluator_MissingSessionField(t *testing.T) {
	det := NewTemporalSequenceDetector()

	eval := &TemporalSequenceEvaluator{
		Detector:              det,
		PrecededByCategory:    "kernel",
		PrecededBySubcategory: "process_exec",
		Window:                5 * time.Second,
		SessionField:          "agentID",
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields:      map[string]interface{}{},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (missing session field), got true")
	}
}

func TestTemporalSequenceEvaluator_NoEventsRecorded(t *testing.T) {
	det := NewTemporalSequenceDetector()

	eval := &TemporalSequenceEvaluator{
		Detector:              det,
		PrecededByCategory:    "kernel",
		PrecededBySubcategory: "process_exec",
		Window:                5 * time.Second,
		SessionField:          "agentID",
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (no preceding events recorded), got true")
	}
}

func TestTemporalSequenceEvaluator_ImplementsInterface(t *testing.T) {
	det := NewTemporalSequenceDetector()
	var _ PredicateEvaluator = &TemporalSequenceEvaluator{
		Detector:              det,
		PrecededByCategory:    "kernel",
		PrecededBySubcategory: "process_exec",
		Window:                5 * time.Second,
		SessionField:          "agentID",
	}
}
