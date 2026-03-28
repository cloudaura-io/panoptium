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

package observer

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// ErrDuplicateObserver is returned when attempting to register an observer
// with a name that is already registered.
var ErrDuplicateObserver = errors.New("observer with this name is already registered")

// ErrNoMatchingObserver is returned when no registered observer can handle
// the given request context.
var ErrNoMatchingObserver = errors.New("no observer can handle this request")

// registeredObserver pairs a ProtocolObserver with its configuration.
type registeredObserver struct {
	observer ProtocolObserver
	config   ObserverConfig
}

// ObserverRegistry manages a set of ProtocolObservers and routes requests
// to the appropriate observer based on priority and confidence scoring.
type ObserverRegistry struct {
	mu        sync.RWMutex
	observers []registeredObserver
}

// NewObserverRegistry creates a new ObserverRegistry.
func NewObserverRegistry() *ObserverRegistry {
	return &ObserverRegistry{
		observers: make([]registeredObserver, 0),
	}
}

// Register adds a ProtocolObserver to the registry with the given configuration.
// Observers are maintained in sorted order by priority (lower number = higher priority).
// Returns ErrDuplicateObserver if an observer with the same name is already registered.
func (r *ObserverRegistry) Register(observer ProtocolObserver, config ObserverConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate name
	for _, entry := range r.observers {
		if entry.config.Name == config.Name {
			return ErrDuplicateObserver
		}
	}

	r.observers = append(r.observers, registeredObserver{
		observer: observer,
		config:   config,
	})

	// Sort by priority (lower number = higher priority)
	sort.Slice(r.observers, func(i, j int) bool {
		return r.observers[i].config.Priority < r.observers[j].config.Priority
	})

	return nil
}

// Unregister removes a ProtocolObserver from the registry by name.
// Returns false if no observer with the given name was found.
func (r *ObserverRegistry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, entry := range r.observers {
		if entry.config.Name == name {
			r.observers = append(r.observers[:i], r.observers[i+1:]...)
			return true
		}
	}

	return false
}

// SelectObserver finds the best matching observer for the given request context.
// All registered observers are consulted; the one with the highest confidence
// score that can handle the request is selected. When confidence scores are
// equal, the observer with higher priority (lower priority number) wins.
// Returns ErrNoMatchingObserver if no registered observer can handle the request.
func (r *ObserverRegistry) SelectObserver(ctx context.Context, req *ObserverContext) (ProtocolObserver, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestObserver ProtocolObserver
	var bestConfidence float32
	bestPriority := int(^uint(0) >> 1) // max int

	for _, entry := range r.observers {
		canHandle, confidence := entry.observer.CanHandle(ctx, req)
		if !canHandle {
			continue
		}

		// Select this observer if it has higher confidence, or equal confidence
		// with higher priority (lower priority number).
		if confidence > bestConfidence ||
			(confidence == bestConfidence && entry.config.Priority < bestPriority) {
			bestObserver = entry.observer
			bestConfidence = confidence
			bestPriority = entry.config.Priority
		}
	}

	if bestObserver == nil {
		return nil, ErrNoMatchingObserver
	}

	return bestObserver, nil
}

// Observers returns a list of all registered observer names, in priority order.
func (r *ObserverRegistry) Observers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, len(r.observers))
	for i, entry := range r.observers {
		names[i] = entry.config.Name
	}
	return names
}
