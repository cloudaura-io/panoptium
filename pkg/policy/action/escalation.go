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

package action

import (
	"sync"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// EscalationLevel defines a single escalation rule: when the count of
// FromAction exceeds Threshold within Window, escalate to ToAction.
type EscalationLevel struct {
	// FromAction is the action type that triggers escalation when repeated.
	FromAction string

	// ToAction is the escalated action type.
	ToAction string

	// Threshold is the minimum number of FromAction occurrences within
	// the Window that triggers escalation.
	Threshold int

	// Window is the sliding time window for counting actions.
	Window time.Duration
}

// actionRecord stores a timestamped action for sliding window counting.
type actionRecord struct {
	Action    string
	Severity  string
	AuditOnly bool
	Timestamp time.Time
}

// EscalationProcessor tracks per-agent action history and determines
// when escalation should occur based on configured escalation levels.
// It is safe for concurrent use from multiple goroutines.
type EscalationProcessor struct {
	mu     sync.Mutex
	levels []EscalationLevel
	state  map[string][]actionRecord
}

// NewEscalationProcessor creates a new EscalationProcessor with the
// given escalation level definitions.
func NewEscalationProcessor(levels []EscalationLevel) *EscalationProcessor {
	return &EscalationProcessor{
		levels: levels,
		state:  make(map[string][]actionRecord),
	}
}

// SetLevels replaces the configured escalation levels. This allows dynamic
// reconfiguration as policy parameters arrive via events.
func (p *EscalationProcessor) SetLevels(levels []EscalationLevel) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.levels = levels
}

// RecordAction records an action occurrence for the given agent key.
func (p *EscalationProcessor) RecordAction(agentKey, actionType string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state[agentKey] = append(p.state[agentKey], actionRecord{
		Action:    actionType,
		Timestamp: time.Now(),
	})
}

// CheckEscalation checks whether the given action type for the given agent
// should be escalated based on the configured escalation levels. Returns
// (true, toAction) if escalation is triggered, or (false, "") if not.
func (p *EscalationProcessor) CheckEscalation(agentKey, currentAction string) (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	records, ok := p.state[agentKey]
	if !ok {
		return false, ""
	}

	now := time.Now()

	for _, level := range p.levels {
		if level.FromAction != currentAction {
			continue
		}

		cutoff := now.Add(-level.Window)
		count := 0
		for _, rec := range records {
			if rec.Action == level.FromAction && rec.Timestamp.After(cutoff) {
				count++
			}
		}

		if count >= level.Threshold {
			return true, level.ToAction
		}
	}

	return false, ""
}

// RecordSeverityAction records an action occurrence with severity and audit
// mode information for severity-based risk accumulation (FR-5).
func (p *EscalationProcessor) RecordSeverityAction(agentKey, actionType, severity string, auditOnly bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state[agentKey] = append(p.state[agentKey], actionRecord{
		Action:    actionType,
		Severity:  severity,
		AuditOnly: auditOnly,
		Timestamp: time.Now(),
	})
}

// CheckSeverityEscalation checks whether the accumulated severity-weighted
// risk for the given agent exceeds the escalation threshold. The threshold
// is reinterpreted as a risk point threshold (not a count).
//
// Risk scoring: each record contributes SeverityScore(severity) points,
// with audit-only records weighted at 50% (FR-5).
//
// Returns (true, toAction) if escalation is triggered, or (false, "") if not.
func (p *EscalationProcessor) CheckSeverityEscalation(agentKey string) (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	records, ok := p.state[agentKey]
	if !ok {
		return false, ""
	}

	now := time.Now()

	for _, level := range p.levels {
		cutoff := now.Add(-level.Window)
		totalRisk := 0

		for _, rec := range records {
			if rec.Timestamp.After(cutoff) {
				score := eventbus.SeverityScore(rec.Severity)
				if rec.AuditOnly {
					score = score / 2 // 50% weight for audit events
				}
				totalRisk += score
			}
		}

		if totalRisk >= level.Threshold {
			return true, level.ToAction
		}
	}

	return false, ""
}

// Cleanup removes expired action records across all agents.
// Records older than the largest configured window are removed.
func (p *EscalationProcessor) Cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Find the largest window
	var maxWindow time.Duration
	for _, level := range p.levels {
		if level.Window > maxWindow {
			maxWindow = level.Window
		}
	}

	if maxWindow == 0 {
		return
	}

	cutoff := time.Now().Add(-maxWindow)
	for key, records := range p.state {
		valid := records[:0]
		for _, rec := range records {
			if rec.Timestamp.After(cutoff) {
				valid = append(valid, rec)
			}
		}
		if len(valid) == 0 {
			delete(p.state, key)
		} else {
			p.state[key] = valid
		}
	}
}
