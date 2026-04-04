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
	"testing"
	"time"
)

func TestEscalationProcessor_DenyToQuarantine(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 3, Window: 5 * time.Second},
	})

	// Record 3 deny actions for agent-1
	proc.RecordAction("agent-1", "deny")
	proc.RecordAction("agent-1", "deny")
	proc.RecordAction("agent-1", "deny")

	escalated, toAction := proc.CheckEscalation("agent-1", "deny")
	if !escalated {
		t.Error("expected escalation after 3 denials, got false")
	}
	if toAction != "quarantine" {
		t.Errorf("expected escalation to quarantine, got %q", toAction)
	}
}

func TestEscalationProcessor_ThrottleToDeny(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "throttle", ToAction: "deny", Threshold: 5, Window: 10 * time.Second},
	})

	for i := 0; i < 5; i++ {
		proc.RecordAction("agent-1", "throttle")
	}

	escalated, toAction := proc.CheckEscalation("agent-1", "throttle")
	if !escalated {
		t.Error("expected escalation after 5 throttles, got false")
	}
	if toAction != "deny" {
		t.Errorf("expected escalation to deny, got %q", toAction)
	}
}

func TestEscalationProcessor_BelowThreshold(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 3, Window: 5 * time.Second},
	})

	proc.RecordAction("agent-1", "deny")
	proc.RecordAction("agent-1", "deny")

	escalated, _ := proc.CheckEscalation("agent-1", "deny")
	if escalated {
		t.Error("expected no escalation below threshold (2 < 3), got true")
	}
}

func TestEscalationProcessor_MultiLevelEscalation(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "throttle", ToAction: "deny", Threshold: 3, Window: 10 * time.Second},
		{FromAction: "deny", ToAction: "quarantine", Threshold: 2, Window: 10 * time.Second},
	})

	// First escalation: throttle -> deny
	for i := 0; i < 3; i++ {
		proc.RecordAction("agent-1", "throttle")
	}

	escalated, toAction := proc.CheckEscalation("agent-1", "throttle")
	if !escalated || toAction != "deny" {
		t.Errorf("expected throttle->deny escalation, got escalated=%v toAction=%q", escalated, toAction)
	}

	// Now record deny actions
	proc.RecordAction("agent-1", "deny")
	proc.RecordAction("agent-1", "deny")

	escalated2, toAction2 := proc.CheckEscalation("agent-1", "deny")
	if !escalated2 || toAction2 != "quarantine" {
		t.Errorf("expected deny->quarantine escalation, got escalated=%v toAction=%q", escalated2, toAction2)
	}
}

func TestEscalationProcessor_PerAgentState(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 3, Window: 5 * time.Second},
	})

	// Agent-1 hits threshold
	for i := 0; i < 3; i++ {
		proc.RecordAction("agent-1", "deny")
	}
	// Agent-2 does not
	proc.RecordAction("agent-2", "deny")

	escalated1, _ := proc.CheckEscalation("agent-1", "deny")
	if !escalated1 {
		t.Error("expected escalation for agent-1")
	}

	escalated2, _ := proc.CheckEscalation("agent-2", "deny")
	if escalated2 {
		t.Error("expected no escalation for agent-2 (below threshold)")
	}
}

func TestEscalationProcessor_WindowExpiry(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 3, Window: 100 * time.Millisecond},
	})

	for i := 0; i < 3; i++ {
		proc.RecordAction("agent-1", "deny")
	}

	// Should escalate now
	escalated, _ := proc.CheckEscalation("agent-1", "deny")
	if !escalated {
		t.Error("expected escalation before window expiry")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	escalated2, _ := proc.CheckEscalation("agent-1", "deny")
	if escalated2 {
		t.Error("expected no escalation after window expiry (de-escalation)")
	}
}

func TestEscalationProcessor_Cooldown(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 3, Window: 100 * time.Millisecond},
	})

	// Trigger escalation
	for i := 0; i < 3; i++ {
		proc.RecordAction("agent-1", "deny")
	}

	escalated, _ := proc.CheckEscalation("agent-1", "deny")
	if !escalated {
		t.Error("expected escalation")
	}

	// Wait for cooldown (window expiry acts as cooldown)
	time.Sleep(150 * time.Millisecond)

	// After cooldown, new actions below threshold should not escalate
	proc.RecordAction("agent-1", "deny")
	escalated2, _ := proc.CheckEscalation("agent-1", "deny")
	if escalated2 {
		t.Error("expected no escalation after cooldown with only 1 action")
	}
}

func TestEscalationProcessor_NoMatchingEscalation(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 3, Window: 5 * time.Second},
	})

	// Record allow actions (no escalation defined for allow)
	proc.RecordAction("agent-1", "allow")
	proc.RecordAction("agent-1", "allow")
	proc.RecordAction("agent-1", "allow")

	escalated, _ := proc.CheckEscalation("agent-1", "allow")
	if escalated {
		t.Error("expected no escalation for action type without escalation rule")
	}
}

func TestEscalationProcessor_Cleanup(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 3, Window: 50 * time.Millisecond},
	})

	for i := 0; i < 3; i++ {
		proc.RecordAction("agent-1", "deny")
	}
	proc.RecordAction("agent-2", "deny")

	// Wait for window to expire
	time.Sleep(80 * time.Millisecond)

	proc.Cleanup()

	// After cleanup, all expired records should be removed
	escalated, _ := proc.CheckEscalation("agent-1", "deny")
	if escalated {
		t.Error("expected no escalation after cleanup removed expired records")
	}
}

func TestEscalationProcessor_CleanupEmptyLevels(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{})
	proc.RecordAction("agent-1", "deny")
	proc.Cleanup() // Should not panic with empty levels
}

func TestEscalationProcessor_SeverityRisk(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 100, Window: 5 * time.Second},
	})

	// 3 MEDIUM events = 3 * 20 = 60 points, below threshold 100
	proc.RecordSeverityAction("agent-1", "deny", "MEDIUM", false)
	proc.RecordSeverityAction("agent-1", "deny", "MEDIUM", false)
	proc.RecordSeverityAction("agent-1", "deny", "MEDIUM", false)

	escalated, _ := proc.CheckSeverityEscalation("agent-1")
	if escalated {
		t.Error("expected no escalation at 60 risk points (threshold 100)")
	}
}

func TestEscalationProcessor_SeverityRisk_CriticalTriggers(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 100, Window: 5 * time.Second},
	})

	// 1 CRITICAL (100) + 1 INFO (0) = 100 points, meets threshold
	proc.RecordSeverityAction("agent-1", "deny", "CRITICAL", false)
	proc.RecordSeverityAction("agent-1", "deny", "INFO", false)

	escalated, toAction := proc.CheckSeverityEscalation("agent-1")
	if !escalated {
		t.Error("expected escalation at 100 risk points (threshold 100)")
	}
	if toAction != "quarantine" {
		t.Errorf("expected quarantine, got %q", toAction)
	}
}

func TestEscalationProcessor_AuditWeight(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 100, Window: 5 * time.Second},
	})

	// 2 HIGH audit events = 2 * 50 * 0.5 = 50 points
	proc.RecordSeverityAction("agent-1", "deny", "HIGH", true)
	proc.RecordSeverityAction("agent-1", "deny", "HIGH", true)

	escalated, _ := proc.CheckSeverityEscalation("agent-1")
	if escalated {
		t.Error("expected no escalation at 50 risk points (threshold 100)")
	}

	// 1 more HIGH enforced event = 50 pts, total now 100
	proc.RecordSeverityAction("agent-1", "deny", "HIGH", false)

	escalated, _ = proc.CheckSeverityEscalation("agent-1")
	if !escalated {
		t.Error("expected escalation at 100 risk points (threshold 100)")
	}
}

func TestEscalationProcessor_SeverityRisk_WindowExpiry(t *testing.T) {
	proc := NewEscalationProcessor([]EscalationLevel{
		{FromAction: "deny", ToAction: "quarantine", Threshold: 100, Window: 100 * time.Millisecond},
	})

	proc.RecordSeverityAction("agent-1", "deny", "CRITICAL", false)

	escalated, _ := proc.CheckSeverityEscalation("agent-1")
	if !escalated {
		t.Error("expected escalation before window expiry")
	}

	time.Sleep(150 * time.Millisecond)

	escalated, _ = proc.CheckSeverityEscalation("agent-1")
	if escalated {
		t.Error("expected no escalation after window expiry")
	}
}
