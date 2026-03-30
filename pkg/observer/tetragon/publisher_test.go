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

package tetragon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// testBus is a minimal EventBus implementation for testing.
type testBus struct {
	mu     sync.Mutex
	events []eventbus.Event
	closed bool
}

func newTestBus() *testBus {
	return &testBus{}
}

func (b *testBus) Subscribe(eventTypes ...string) *eventbus.Subscription {
	return eventbus.NewSubscription(eventTypes, eventbus.EventFilter{}, 256)
}

func (b *testBus) SubscribeWithFilter(filter eventbus.EventFilter, eventTypes ...string) *eventbus.Subscription {
	return eventbus.NewSubscription(eventTypes, filter, 256)
}

func (b *testBus) Unsubscribe(sub *eventbus.Subscription) {}

func (b *testBus) Emit(event eventbus.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event)
}

func (b *testBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
}

func (b *testBus) emittedEvents() []eventbus.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([]eventbus.Event, len(b.events))
	copy(result, b.events)
	return result
}

func TestPublisherPipeline(t *testing.T) {
	bus := newTestBus()
	translator := NewTranslator()

	pub := NewPublisher(bus, translator, PublisherConfig{
		Workers: 2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pub.Start(ctx)

	// Feed events through the pipeline.
	rawEvents := []*RawEvent{
		{Type: EventTypeProcessExec, ProcessPID: 100, ProcessComm: "proc1", Namespace: "default", PodName: "pod1", Timestamp: 1000000000},
		{Type: EventTypeProcessKprobe, ProcessPID: 200, ProcessComm: "proc2", KprobeFunc: "sys_openat", Namespace: "default", PodName: "pod2", Timestamp: 2000000000},
		{Type: EventTypeProcessKprobe, ProcessPID: 300, ProcessComm: "proc3", KprobeFunc: "sys_connect", Namespace: "default", PodName: "pod3", Timestamp: 3000000000},
	}

	for _, evt := range rawEvents {
		pub.Submit(evt)
	}

	// Wait for events to be processed.
	deadline := time.After(2 * time.Second)
	for {
		events := bus.emittedEvents()
		if len(events) >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for events; got %d, want 3", len(bus.emittedEvents()))
		case <-time.After(10 * time.Millisecond):
		}
	}

	events := bus.emittedEvents()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// Events may arrive in any order with multiple workers.
	typeSet := make(map[string]bool)
	for _, evt := range events {
		typeSet[evt.EventType()] = true
	}
	for _, expected := range []string{"syscall.execve", "syscall.openat", "syscall.connect"} {
		if !typeSet[expected] {
			t.Errorf("expected event type %q in results", expected)
		}
	}
}

func TestPublisherBackpressure(t *testing.T) {
	bus := newTestBus()
	translator := NewTranslator()

	// Very small channel to trigger backpressure.
	pub := NewPublisher(bus, translator, PublisherConfig{
		Workers:       1,
		ChannelBuffer: 1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pub.Start(ctx)

	// Submit many events rapidly.
	for i := 0; i < 100; i++ {
		pub.Submit(&RawEvent{
			Type:        EventTypeProcessExec,
			ProcessPID:  uint32(i),
			ProcessComm: "fast-proc",
			Namespace:   "default",
			PodName:     "stress-pod",
			Timestamp:   uint64(i) * 1000000000,
		})
	}

	// Wait a bit for processing.
	time.Sleep(200 * time.Millisecond)

	metrics := pub.Metrics()
	// Some events should have been dropped due to backpressure.
	processed := metrics.EventsProcessed.Load()
	dropped := metrics.EventsDropped.Load()

	// At least some events should have been processed.
	if processed == 0 {
		t.Error("expected at least some events to be processed")
	}

	// With buffer=1 and 100 rapid submits, some should be dropped.
	if dropped == 0 {
		t.Logf("warning: expected some drops with buffer=1 and 100 rapid submits (processed=%d)", processed)
	}
}

func TestPublisherMetrics(t *testing.T) {
	bus := newTestBus()
	translator := NewTranslator()

	pub := NewPublisher(bus, translator, PublisherConfig{
		Workers: 1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pub.Start(ctx)

	pub.Submit(&RawEvent{
		Type:        EventTypeProcessExec,
		ProcessPID:  42,
		ProcessComm: "test",
		Namespace:   "default",
		PodName:     "test-pod",
		Timestamp:   1000000000,
	})

	// Also submit an unknown event that should be skipped.
	pub.Submit(&RawEvent{
		Type:        "unknown_type",
		ProcessPID:  43,
		ProcessComm: "unknown",
		Timestamp:   2000000000,
	})

	// Wait for processing.
	time.Sleep(200 * time.Millisecond)

	metrics := pub.Metrics()
	if metrics.EventsProcessed.Load() < 1 {
		t.Error("expected at least 1 event processed")
	}
	if metrics.EventsPublished.Load() < 1 {
		t.Error("expected at least 1 event published to bus")
	}
}

func TestPublisherStop(t *testing.T) {
	bus := newTestBus()
	translator := NewTranslator()

	pub := NewPublisher(bus, translator, PublisherConfig{
		Workers: 2,
	})

	ctx, cancel := context.WithCancel(context.Background())

	pub.Start(ctx)

	// Submit some events.
	pub.Submit(&RawEvent{
		Type:        EventTypeProcessExec,
		ProcessPID:  1,
		ProcessComm: "test",
		Namespace:   "default",
		PodName:     "pod",
		Timestamp:   1000000000,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()

	// Stop should complete without hanging.
	done := make(chan struct{})
	go func() {
		pub.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("publisher did not stop within timeout")
	}
}

func TestPublisherSkipsUnknownEvents(t *testing.T) {
	bus := newTestBus()
	translator := NewTranslator()

	pub := NewPublisher(bus, translator, PublisherConfig{
		Workers: 1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pub.Start(ctx)

	// Submit unknown event.
	pub.Submit(&RawEvent{
		Type:        "completely_unknown",
		ProcessPID:  999,
		ProcessComm: "unknown",
		Timestamp:   1000000000,
	})

	// Submit valid event after.
	pub.Submit(&RawEvent{
		Type:        EventTypeProcessExec,
		ProcessPID:  1,
		ProcessComm: "valid",
		Namespace:   "default",
		PodName:     "pod",
		Timestamp:   2000000000,
	})

	// Wait for processing.
	deadline := time.After(2 * time.Second)
	for {
		events := bus.emittedEvents()
		if len(events) >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for events")
		case <-time.After(10 * time.Millisecond):
		}
	}

	events := bus.emittedEvents()
	// Only the valid event should be published.
	if len(events) != 1 {
		t.Errorf("expected 1 event (unknown skipped), got %d", len(events))
	}
	if events[0].EventType() != "syscall.execve" {
		t.Errorf("expected syscall.execve, got %q", events[0].EventType())
	}
}
