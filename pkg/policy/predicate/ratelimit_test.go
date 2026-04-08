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

func TestSlidingWindowCounter_Increment(t *testing.T) {
	c := NewSlidingWindowCounter(1 * time.Second)
	c.Increment("agent-1")
	if got := c.Count("agent-1"); got != 1 {
		t.Errorf("Count after single increment: got %d, want 1", got)
	}
}

func TestSlidingWindowCounter_MultipleIncrements(t *testing.T) {
	c := NewSlidingWindowCounter(1 * time.Second)
	c.Increment("agent-1")
	c.Increment("agent-1")
	c.Increment("agent-1")
	if got := c.Count("agent-1"); got != 3 {
		t.Errorf("Count after three increments: got %d, want 3", got)
	}
}

func TestSlidingWindowCounter_DecrementOverTime(t *testing.T) {
	window := 100 * time.Millisecond
	c := NewSlidingWindowCounter(window)
	c.Increment("agent-1")
	c.Increment("agent-1")

	// Wait for events to expire
	time.Sleep(150 * time.Millisecond)

	if got := c.Count("agent-1"); got != 0 {
		t.Errorf("Count after window expiry: got %d, want 0", got)
	}
}

func TestSlidingWindowCounter_PartialExpiry(t *testing.T) {
	window := 200 * time.Millisecond
	c := NewSlidingWindowCounter(window)

	// Add first event
	c.Increment("agent-1")

	// Wait 120ms, add second event
	time.Sleep(120 * time.Millisecond)
	c.Increment("agent-1")

	// At this point: first event ~120ms old, second ~0ms old
	// Wait 100ms more — first event is now ~220ms old (expired), second is ~100ms old (still valid)
	time.Sleep(100 * time.Millisecond)

	if got := c.Count("agent-1"); got != 1 {
		t.Errorf("Count after partial expiry: got %d, want 1", got)
	}
}

func TestSlidingWindowCounter_GroupByPartitioning(t *testing.T) {
	c := NewSlidingWindowCounter(1 * time.Second)
	c.Increment("agent-1")
	c.Increment("agent-1")
	c.Increment("agent-2")

	if got := c.Count("agent-1"); got != 2 {
		t.Errorf("Count for agent-1: got %d, want 2", got)
	}
	if got := c.Count("agent-2"); got != 1 {
		t.Errorf("Count for agent-2: got %d, want 1", got)
	}
	if got := c.Count("agent-3"); got != 0 {
		t.Errorf("Count for non-existent agent-3: got %d, want 0", got)
	}
}

func TestSlidingWindowCounter_ConcurrentIncrements(t *testing.T) {
	c := NewSlidingWindowCounter(5 * time.Second)
	const goroutines = 10
	const incrementsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				c.Increment("shared-key")
			}
		}()
	}
	wg.Wait()

	expected := goroutines * incrementsPerGoroutine
	if got := c.Count("shared-key"); got != expected {
		t.Errorf("Count after concurrent increments: got %d, want %d", got, expected)
	}
}

func TestSlidingWindowCounter_ConcurrentIncrementsDifferentKeys(t *testing.T) {
	c := NewSlidingWindowCounter(5 * time.Second)

	var wg sync.WaitGroup
	wg.Add(3)
	for _, key := range []string{"a", "b", "c"} {
		go func(k string) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				c.Increment(k)
			}
		}(key)
	}
	wg.Wait()

	for _, key := range []string{"a", "b", "c"} {
		if got := c.Count(key); got != 50 {
			t.Errorf("Count for key %q: got %d, want 50", key, got)
		}
	}
}

func TestSlidingWindowCounter_WindowExpiry_AllEntriesExpired(t *testing.T) {
	window := 50 * time.Millisecond
	c := NewSlidingWindowCounter(window)

	c.Increment("key1")
	c.Increment("key1")
	c.Increment("key2")

	time.Sleep(80 * time.Millisecond)

	if got := c.Count("key1"); got != 0 {
		t.Errorf("Count for key1 after full expiry: got %d, want 0", got)
	}
	if got := c.Count("key2"); got != 0 {
		t.Errorf("Count for key2 after full expiry: got %d, want 0", got)
	}
}

func TestSlidingWindowCounter_Cleanup(t *testing.T) {
	window := 50 * time.Millisecond
	c := NewSlidingWindowCounter(window)

	c.Increment("key1")
	c.Increment("key2")

	time.Sleep(80 * time.Millisecond)

	// Cleanup should remove expired entries
	c.Cleanup()

	// After cleanup, counts should be 0
	if got := c.Count("key1"); got != 0 {
		t.Errorf("Count for key1 after cleanup: got %d, want 0", got)
	}
}

func TestRateLimitEvaluator_BelowLimit(t *testing.T) {
	counter := NewSlidingWindowCounter(1 * time.Second)
	eval := &RateLimitEvaluator{
		Counter:      counter,
		Limit:        5,
		GroupByField: "agentID",
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	// Record 3 events (below limit of 5)
	counter.Increment("agent-1")
	counter.Increment("agent-1")
	counter.Increment("agent-1")

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Rate limit NOT exceeded -> should return false (no violation)
	if matched {
		t.Error("expected false (below limit), got true")
	}
}

func TestRateLimitEvaluator_AtLimit(t *testing.T) {
	counter := NewSlidingWindowCounter(1 * time.Second)
	eval := &RateLimitEvaluator{
		Counter:      counter,
		Limit:        3,
		GroupByField: "agentID",
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	// Record exactly 3 events (at limit of 3)
	counter.Increment("agent-1")
	counter.Increment("agent-1")
	counter.Increment("agent-1")

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Rate limit exceeded (count >= limit) -> should return true (violation)
	if !matched {
		t.Error("expected true (at limit), got false")
	}
}

func TestRateLimitEvaluator_ExceedsLimit(t *testing.T) {
	counter := NewSlidingWindowCounter(1 * time.Second)
	eval := &RateLimitEvaluator{
		Counter:      counter,
		Limit:        2,
		GroupByField: "agentID",
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	counter.Increment("agent-1")
	counter.Increment("agent-1")
	counter.Increment("agent-1")

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected true (exceeds limit), got false")
	}
}

func TestRateLimitEvaluator_GroupByPartitioning(t *testing.T) {
	counter := NewSlidingWindowCounter(1 * time.Second)
	eval := &RateLimitEvaluator{
		Counter:      counter,
		Limit:        2,
		GroupByField: "agentID",
	}

	eventAgent1 := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	eventAgent2 := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID": "agent-2",
		},
	}

	// Agent-1 exceeds limit, agent-2 does not
	counter.Increment("agent-1")
	counter.Increment("agent-1")
	counter.Increment("agent-1")
	counter.Increment("agent-2")

	matched1, err := eval.Evaluate(eventAgent1)
	if err != nil {
		t.Fatalf("unexpected error for agent-1: %v", err)
	}
	if !matched1 {
		t.Error("expected true for agent-1 (exceeds limit), got false")
	}

	matched2, err := eval.Evaluate(eventAgent2)
	if err != nil {
		t.Fatalf("unexpected error for agent-2: %v", err)
	}
	if matched2 {
		t.Error("expected false for agent-2 (below limit), got true")
	}
}

func TestRateLimitEvaluator_GroupByToolName(t *testing.T) {
	counter := NewSlidingWindowCounter(1 * time.Second)
	eval := &RateLimitEvaluator{
		Counter:      counter,
		Limit:        2,
		GroupByField: "toolName",
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"toolName": "execute_command",
		},
	}

	counter.Increment("execute_command")
	counter.Increment("execute_command")

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected true (at limit), got false")
	}
}

func TestRateLimitEvaluator_MissingGroupByField(t *testing.T) {
	counter := NewSlidingWindowCounter(1 * time.Second)
	eval := &RateLimitEvaluator{
		Counter:      counter,
		Limit:        2,
		GroupByField: "agentID",
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Missing field -> cannot group -> should return false
	if matched {
		t.Error("expected false (missing groupBy field), got true")
	}
}

func TestRateLimitEvaluator_WindowExpiry(t *testing.T) {
	window := 100 * time.Millisecond
	counter := NewSlidingWindowCounter(window)
	eval := &RateLimitEvaluator{
		Counter:      counter,
		Limit:        2,
		GroupByField: "agentID",
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	counter.Increment("agent-1")
	counter.Increment("agent-1")
	counter.Increment("agent-1")

	// Should be exceeded now
	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected true before window expiry, got false")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	matched, err = eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error after expiry: %v", err)
	}
	if matched {
		t.Error("expected false after window expiry, got true")
	}
}

func TestRateLimitEvaluator_MultipleOverlappingWindows(t *testing.T) {
	// Two evaluators with different windows
	shortCounter := NewSlidingWindowCounter(100 * time.Millisecond)
	longCounter := NewSlidingWindowCounter(1 * time.Second)

	evalShort := &RateLimitEvaluator{
		Counter:      shortCounter,
		Limit:        2,
		GroupByField: "agentID",
	}

	evalLong := &RateLimitEvaluator{
		Counter:      longCounter,
		Limit:        5,
		GroupByField: "agentID",
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	// Record 3 events in both counters
	for i := 0; i < 3; i++ {
		shortCounter.Increment("agent-1")
		longCounter.Increment("agent-1")
	}

	// Short window: 3 >= 2 -> exceeded
	matchedShort, err := evalShort.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matchedShort {
		t.Error("short window: expected true (3 >= 2), got false")
	}

	// Long window: 3 < 5 -> not exceeded
	matchedLong, err := evalLong.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matchedLong {
		t.Error("long window: expected false (3 < 5), got true")
	}
}

func TestRateLimitEvaluator_ImplementsInterface(t *testing.T) {
	counter := NewSlidingWindowCounter(1 * time.Second)
	var _ PredicateEvaluator = &RateLimitEvaluator{
		Counter:      counter,
		Limit:        5,
		GroupByField: "agentID",
	}
}

func TestRateLimitEvaluator_IncrementAndEvaluate(t *testing.T) {
	counter := NewSlidingWindowCounter(1 * time.Second)
	eval := &RateLimitEvaluator{
		Counter:       counter,
		Limit:         3,
		GroupByField:  "agentID",
		AutoIncrement: true,
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID": "agent-1",
		},
	}

	// First two evaluations: below limit
	for i := 0; i < 2; i++ {
		matched, err := eval.Evaluate(event)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if matched {
			t.Errorf("iteration %d: expected false (below limit), got true", i)
		}
	}

	// Third evaluation: at limit
	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("third evaluation: unexpected error: %v", err)
	}
	if !matched {
		t.Error("third evaluation: expected true (at limit), got false")
	}
}

// TestRateLimitEvaluator_GroupByField verifies that the evaluator uses the
// configured GroupByField to partition counters. Different GroupByField values
// produce independent counting behavior for the same events.
func TestRateLimitEvaluator_GroupByField(t *testing.T) {
	// Counter shared between two evaluators with different GroupByField
	counter := NewSlidingWindowCounter(1 * time.Second)

	evalByAgent := &RateLimitEvaluator{
		Counter:       counter,
		Limit:         2,
		GroupByField:  "agentID",
		AutoIncrement: true,
	}

	evalByTool := &RateLimitEvaluator{
		Counter:       counter,
		Limit:         2,
		GroupByField:  "toolName",
		AutoIncrement: true,
	}

	// Event with both fields
	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"agentID":  "agent-1",
			"toolName": "bash",
		},
	}

	// Evaluate twice with agent-based evaluator: counter key = "agent-1"
	_, _ = evalByAgent.Evaluate(event)
	matched, _ := evalByAgent.Evaluate(event)
	if !matched {
		t.Error("agent-based evaluator: expected true (count 2 >= limit 2)")
	}

	// Tool-based evaluator uses "bash" as key — should start from 0
	// since it's a different key namespace
	matched, _ = evalByTool.Evaluate(event)
	// "bash" count is now 1 (first time this key is used)
	if matched {
		t.Error("tool-based evaluator: expected false (count 1 < limit 2)")
	}
}

func TestSlidingWindowCounter_ConcurrentCountAndIncrement(t *testing.T) {
	c := NewSlidingWindowCounter(5 * time.Second)

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: increment
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			c.Increment("key")
		}
	}()

	// Goroutine 2: count
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = c.Count("key")
		}
	}()

	wg.Wait()

	// Final count should be 100
	if got := c.Count("key"); got != 100 {
		t.Errorf("Count after concurrent ops: got %d, want 100", got)
	}
}
