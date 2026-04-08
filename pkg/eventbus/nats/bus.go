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

package nats

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

const (
	// subjectPrefix is the base NATS subject prefix for all Panoptium events.
	subjectPrefix = "panoptium.events"

	// defaultSubscriberBufferSize matches the SimpleBus default.
	defaultSubscriberBufferSize = 256
)

// natsEventEnvelope is the JSON-serialized envelope for events on the wire.
// This bridges the Go Event interface with NATS messages until full protobuf
// migration is complete.
type natsEventEnvelope struct {
	EventType string                 `json:"event_type"`
	Timestamp time.Time              `json:"timestamp"`
	RequestID string                 `json:"request_id"`
	Protocol  string                 `json:"protocol"`
	Provider  string                 `json:"provider"`
	Namespace string                 `json:"namespace"`
	Identity  eventbus.AgentIdentity `json:"identity"`
	Data      json.RawMessage        `json:"data"`
}

// NATSBus implements the eventbus.EventBus interface using NATS as the
// transport layer. It supports typed event filtering by mapping event types
// to NATS subjects.
type NATSBus struct {
	mu          sync.RWMutex
	nc          *natsgo.Conn
	subscribers map[*eventbus.Subscription]*natsSubscription
	closed      bool
}

// natsSubscription tracks the NATS-side subscription(s) for an EventBus subscriber.
type natsSubscription struct {
	mu       sync.Mutex
	natsSubs []*natsgo.Subscription
	filter   eventbus.EventFilter
	closed   bool
}

// NewNATSBus creates a new NATSBus connected to the given NATS server URL.
func NewNATSBus(url string) (*NATSBus, error) {
	nc, err := natsgo.Connect(url,
		natsgo.MaxReconnects(-1),
		natsgo.ReconnectWait(100*time.Millisecond),
	)
	if err != nil {
		return nil, err
	}

	return &NATSBus{
		nc:          nc,
		subscribers: make(map[*eventbus.Subscription]*natsSubscription),
	}, nil
}

// Subscribe registers a subscriber for the specified event types.
// If no event types are provided, the subscriber receives all events.
// Returns nil if the bus is closed.
func (b *NATSBus) Subscribe(eventTypes ...string) *eventbus.Subscription {
	return b.SubscribeWithFilter(eventbus.EventFilter{}, eventTypes...)
}

// SubscribeWithFilter registers a subscriber with additional filtering criteria.
// Returns nil if the bus is closed.
func (b *NATSBus) SubscribeWithFilter(filter eventbus.EventFilter, eventTypes ...string) *eventbus.Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	sub := eventbus.NewSubscription(eventTypes, filter, defaultSubscriberBufferSize)

	// Determine NATS subjects to subscribe to
	subjects := b.resolveSubjects(eventTypes)

	ns := &natsSubscription{
		filter: filter,
	}

	for _, subject := range subjects {
		natsSub, err := b.nc.Subscribe(subject, func(msg *natsgo.Msg) {
			ns.mu.Lock()
			if ns.closed {
				ns.mu.Unlock()
				return
			}
			ns.mu.Unlock()

			evt, err := b.decodeEvent(msg.Data)
			if err != nil {
				return
			}

			// Apply filter
			if !b.matchesFilter(filter, evt) {
				return
			}

			// Non-blocking send with closed check
			ns.mu.Lock()
			if ns.closed {
				ns.mu.Unlock()
				return
			}
			select {
			case sub.Ch() <- evt:
			default:
				// Drop if subscriber buffer is full
			}
			ns.mu.Unlock()
		})
		if err != nil {
			// Clean up already-created subscriptions on error
			for _, s := range ns.natsSubs {
				_ = s.Unsubscribe()
			}
			return nil
		}
		ns.natsSubs = append(ns.natsSubs, natsSub)
	}

	b.subscribers[sub] = ns
	return sub
}

// Unsubscribe removes a subscriber from the bus.
// Safe to call multiple times and with nil.
func (b *NATSBus) Unsubscribe(sub *eventbus.Subscription) {
	if sub == nil {
		return
	}

	b.mu.Lock()
	ns, exists := b.subscribers[sub]
	if exists {
		delete(b.subscribers, sub)
	}
	b.mu.Unlock()

	if exists {
		ns.mu.Lock()
		ns.closed = true
		ns.mu.Unlock()
		for _, s := range ns.natsSubs {
			_ = s.Unsubscribe()
		}
		sub.Close()
	}
}

// Emit publishes an event to all matching subscribers via NATS.
// Non-blocking: if a subscriber's buffer is full, the event is dropped.
// Safe to call after Close (no-op).
func (b *NATSBus) Emit(event eventbus.Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed || b.nc == nil {
		return
	}

	subject := b.eventToSubject(event)
	data, err := b.encodeEvent(event)
	if err != nil {
		return
	}

	_ = b.nc.Publish(subject, data) // best-effort publish
}

// Close shuts down the event bus and closes all subscriber channels.
func (b *NATSBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	b.closed = true

	// Unsubscribe all NATS subscriptions and close subscriber channels
	for sub, ns := range b.subscribers {
		ns.mu.Lock()
		ns.closed = true
		ns.mu.Unlock()
		for _, s := range ns.natsSubs {
			_ = s.Unsubscribe()
		}
		sub.Close()
		delete(b.subscribers, sub)
	}

	if b.nc != nil {
		_ = b.nc.Drain()
		b.nc.Close()
	}
}

// resolveSubjects maps event types to NATS subjects.
// An empty list means "subscribe to all".
func (b *NATSBus) resolveSubjects(eventTypes []string) []string {
	if len(eventTypes) == 0 {
		return []string{subjectPrefix + ".>"}
	}

	subjects := make([]string, 0, len(eventTypes))
	for _, et := range eventTypes {
		// Convert event type like "llm.request.start" to subject
		// panoptium.events.*.llm.request.start (wildcard namespace)
		subjects = append(subjects, subjectPrefix+".*."+et)
	}
	return subjects
}

// eventToSubject converts an event to its NATS publish subject.
func (b *NATSBus) eventToSubject(event eventbus.Event) string {
	ns := event.Identity().Namespace
	if ns == "" {
		ns = "_"
	}
	return subjectPrefix + "." + ns + "." + event.EventType()
}

// encodeEvent serializes an event to JSON for NATS transport.
func (b *NATSBus) encodeEvent(event eventbus.Event) ([]byte, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}

	env := natsEventEnvelope{
		EventType: event.EventType(),
		Timestamp: event.Timestamp(),
		RequestID: event.RequestID(),
		Protocol:  event.Protocol(),
		Provider:  event.Provider(),
		Namespace: event.Identity().Namespace,
		Identity:  event.Identity(),
		Data:      data,
	}
	return json.Marshal(env)
}

// decodeEvent deserializes a NATS message into an Event.
func (b *NATSBus) decodeEvent(data []byte) (eventbus.Event, error) {
	var env natsEventEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}

	// Create a concrete event type based on the envelope
	switch {
	case strings.HasPrefix(env.EventType, "llm.request.start"):
		var evt eventbus.LLMRequestStartEvent
		if err := json.Unmarshal(env.Data, &evt); err != nil {
			return nil, err
		}
		return &evt, nil
	case strings.HasPrefix(env.EventType, "llm.token.chunk"):
		var evt eventbus.LLMTokenChunkEvent
		if err := json.Unmarshal(env.Data, &evt); err != nil {
			return nil, err
		}
		return &evt, nil
	case strings.HasPrefix(env.EventType, "llm.request.complete"):
		var evt eventbus.LLMRequestCompleteEvent
		if err := json.Unmarshal(env.Data, &evt); err != nil {
			return nil, err
		}
		return &evt, nil
	case strings.HasPrefix(env.EventType, "enforcement.") || strings.HasPrefix(env.EventType, "policy."):
		var evt eventbus.EnforcementEvent
		if err := json.Unmarshal(env.Data, &evt); err != nil {
			return nil, err
		}
		return &evt, nil
	default:
		// For unknown types, return a generic BaseEvent
		return &eventbus.BaseEvent{
			Type:      env.EventType,
			Time:      env.Timestamp,
			ReqID:     env.RequestID,
			Proto:     env.Protocol,
			Prov:      env.Provider,
			AgentInfo: env.Identity,
		}, nil
	}
}

// matchesFilter checks whether an event matches a subscription's filters.
func (b *NATSBus) matchesFilter(filter eventbus.EventFilter, event eventbus.Event) bool {
	if filter.Protocol != "" && event.Protocol() != filter.Protocol {
		return false
	}
	if filter.Provider != "" && event.Provider() != filter.Provider {
		return false
	}
	return true
}
