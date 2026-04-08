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
	"time"

	"github.com/panoptium/panoptium/pkg/policy"
)

// recordedEvent stores a previously observed event with its timestamp.
type recordedEvent struct {
	Category    string
	Subcategory string
	Timestamp   time.Time
}

// TemporalSequenceDetector tracks events per session (agent/session key)
// and supports temporal sequence detection via precededBy predicates.
// It is safe for concurrent use from multiple goroutines.
type TemporalSequenceDetector struct {
	mu       sync.RWMutex
	sessions map[string][]recordedEvent
}

// NewTemporalSequenceDetector creates a new TemporalSequenceDetector.
func NewTemporalSequenceDetector() *TemporalSequenceDetector {
	return &TemporalSequenceDetector{
		sessions: make(map[string][]recordedEvent),
	}
}

// RecordEvent records an observed event for the given session key.
// The event's category, subcategory, and timestamp are stored for
// later sequence matching.
func (d *TemporalSequenceDetector) RecordEvent(sessionKey string, event *policy.PolicyEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.sessions[sessionKey] = append(d.sessions[sessionKey], recordedEvent{
		Category:    event.Category,
		Subcategory: event.Subcategory,
		Timestamp:   event.Timestamp,
	})
}

// HasPrecedingEvent checks whether the given session has a recorded event
// matching the specified category and subcategory within the given window
// relative to the reference timestamp.
func (d *TemporalSequenceDetector) HasPrecedingEvent(
	sessionKey, category, subcategory string,
	window time.Duration, referenceTime time.Time,
) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	events, ok := d.sessions[sessionKey]
	if !ok {
		return false
	}

	cutoff := referenceTime.Add(-window)
	for _, ev := range events {
		if ev.Category == category && ev.Subcategory == subcategory {
			if !ev.Timestamp.Before(cutoff) && ev.Timestamp.Before(referenceTime) {
				return true
			}
			// Also handle events recorded at the exact same time or slightly after
			// (due to clock granularity) as valid if within window
			if ev.Timestamp.Equal(referenceTime) || (!ev.Timestamp.Before(cutoff) && !ev.Timestamp.After(referenceTime)) {
				return true
			}
		}
	}
	return false
}

// GarbageCollect removes all recorded events older than maxAge from all sessions.
// Sessions with no remaining events are removed entirely.
func (d *TemporalSequenceDetector) GarbageCollect(maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, events := range d.sessions {
		valid := events[:0]
		for _, ev := range events {
			if ev.Timestamp.After(cutoff) {
				valid = append(valid, ev)
			}
		}
		if len(valid) == 0 {
			delete(d.sessions, key)
		} else {
			d.sessions[key] = valid
		}
	}
}

// TemporalSequenceEvaluator evaluates precededBy temporal sequence predicates.
// It checks whether a preceding event of the specified type occurred within
// the configured window for the same session. Implements PredicateEvaluator.
type TemporalSequenceEvaluator struct {
	// Detector is the shared temporal sequence detector.
	Detector *TemporalSequenceDetector

	// PrecededByCategory is the event category that must have preceded.
	PrecededByCategory string

	// PrecededBySubcategory is the event subcategory that must have preceded.
	PrecededBySubcategory string

	// Window is the maximum duration between the preceding event and the
	// current event for the sequence to be considered valid.
	Window time.Duration

	// SessionField is the event field used to identify the session/agent
	// (e.g., "agentID").
	SessionField string
}

// Evaluate checks whether a preceding event matching the configured type
// occurred within the window for the same session as the given event.
// Returns false if the session field is missing from the event.
func (e *TemporalSequenceEvaluator) Evaluate(event *policy.PolicyEvent) (bool, error) {
	fieldValue := extractField(e.SessionField, event)
	if fieldValue == nil {
		return false, nil
	}

	sessionKey := coerceToString(fieldValue)

	referenceTime := event.Timestamp
	if referenceTime.IsZero() {
		referenceTime = time.Now()
	}

	return e.Detector.HasPrecedingEvent(
		sessionKey,
		e.PrecededByCategory,
		e.PrecededBySubcategory,
		e.Window,
		referenceTime,
	), nil
}
