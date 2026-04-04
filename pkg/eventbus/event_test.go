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

package eventbus

import (
	"testing"
	"time"
)

// TestBaseEvent_GetEventType verifies that BaseEvent returns the correct event type.
func TestBaseEvent_GetEventType(t *testing.T) {
	e := BaseEvent{
		Type:      EventTypeLLMRequestStart,
		Time:      time.Now(),
		ReqID:     "req-123",
		Proto:     ProtocolLLM,
		Prov:      ProviderOpenAI,
		AgentInfo: AgentIdentity{},
	}
	if got := e.EventType(); got != EventTypeLLMRequestStart {
		t.Errorf("EventType() = %q, want %q", got, EventTypeLLMRequestStart)
	}
}

// TestBaseEvent_Timestamp verifies that BaseEvent returns the correct timestamp.
func TestBaseEvent_Timestamp(t *testing.T) {
	now := time.Now()
	e := BaseEvent{
		Type: EventTypeLLMTokenChunk,
		Time: now,
	}
	if got := e.Timestamp(); !got.Equal(now) {
		t.Errorf("Timestamp() = %v, want %v", got, now)
	}
}

// TestBaseEvent_RequestID verifies that BaseEvent returns the correct request ID.
func TestBaseEvent_RequestID(t *testing.T) {
	e := BaseEvent{
		Type:  EventTypeLLMRequestComplete,
		ReqID: "req-456",
	}
	if got := e.RequestID(); got != "req-456" {
		t.Errorf("RequestID() = %q, want %q", got, "req-456")
	}
}

// TestBaseEvent_Protocol verifies that BaseEvent returns the correct protocol.
func TestBaseEvent_Protocol(t *testing.T) {
	e := BaseEvent{
		Proto: ProtocolLLM,
	}
	if got := e.Protocol(); got != ProtocolLLM {
		t.Errorf("Protocol() = %q, want %q", got, ProtocolLLM)
	}
}

// TestBaseEvent_Provider verifies that BaseEvent returns the correct provider.
func TestBaseEvent_Provider(t *testing.T) {
	e := BaseEvent{
		Prov: ProviderAnthropic,
	}
	if got := e.Provider(); got != ProviderAnthropic {
		t.Errorf("Provider() = %q, want %q", got, ProviderAnthropic)
	}
}

// TestBaseEvent_Identity verifies that BaseEvent returns the correct AgentIdentity.
func TestBaseEvent_Identity(t *testing.T) {
	identity := AgentIdentity{
		ID:         "agent-summarizer",
		SourceIP:   "10.0.0.5",
		Confidence: ConfidenceHigh,
		PodName:    "summarizer-pod-abc",
		PodUID:     "uid-abc-123",
		Namespace:  "default",
		Labels:     map[string]string{"app": "summarizer"},
	}
	e := BaseEvent{
		AgentInfo: identity,
	}
	got := e.Identity()
	if got.ID != identity.ID {
		t.Errorf("Identity().ID = %q, want %q", got.ID, identity.ID)
	}
	if got.SourceIP != identity.SourceIP {
		t.Errorf("Identity().SourceIP = %q, want %q", got.SourceIP, identity.SourceIP)
	}
	if got.PodUID != identity.PodUID {
		t.Errorf("Identity().PodUID = %q, want %q", got.PodUID, identity.PodUID)
	}
	if got.Confidence != identity.Confidence {
		t.Errorf("Identity().Confidence = %q, want %q", got.Confidence, identity.Confidence)
	}
	if got.PodName != identity.PodName {
		t.Errorf("Identity().PodName = %q, want %q", got.PodName, identity.PodName)
	}
	if got.Namespace != identity.Namespace {
		t.Errorf("Identity().Namespace = %q, want %q", got.Namespace, identity.Namespace)
	}
	if got.Labels["app"] != "summarizer" {
		t.Errorf("Identity().Labels[app] = %q, want %q", got.Labels["app"], "summarizer")
	}
}

// TestAgentIdentity_Defaults verifies that a zero-value AgentIdentity has empty fields.
func TestAgentIdentity_Defaults(t *testing.T) {
	identity := AgentIdentity{}
	if identity.ID != "" {
		t.Errorf("expected empty ID, got %q", identity.ID)
	}
	if identity.Confidence != "" {
		t.Errorf("expected empty Confidence, got %q", identity.Confidence)
	}
	if identity.Labels != nil {
		t.Errorf("expected nil Labels, got %v", identity.Labels)
	}
}

// TestLLMRequestStartEvent verifies that LLMRequestStartEvent has proper type and identity.
func TestLLMRequestStartEvent(t *testing.T) {
	now := time.Now()
	identity := AgentIdentity{
		ID:         "agent-chat",
		Confidence: ConfidenceMedium,
	}
	e := &LLMRequestStartEvent{
		BaseEvent: BaseEvent{
			Type:      EventTypeLLMRequestStart,
			Time:      now,
			ReqID:     "req-start-1",
			Proto:     ProtocolLLM,
			Prov:      ProviderOpenAI,
			AgentInfo: identity,
		},
		Model:    "gpt-4",
		Messages: []string{"Hello, world!"},
		Stream:   true,
	}
	if e.EventType() != EventTypeLLMRequestStart {
		t.Errorf("EventType() = %q, want %q", e.EventType(), EventTypeLLMRequestStart)
	}
	if e.Model != "gpt-4" {
		t.Errorf("Model = %q, want %q", e.Model, "gpt-4")
	}
	if !e.Stream {
		t.Error("Stream should be true")
	}
	if e.Identity().ID != "agent-chat" {
		t.Errorf("Identity().ID = %q, want %q", e.Identity().ID, "agent-chat")
	}
	if e.Identity().Confidence != ConfidenceMedium {
		t.Errorf("Identity().Confidence = %q, want %q", e.Identity().Confidence, ConfidenceMedium)
	}
}

// TestLLMTokenChunkEvent verifies that LLMTokenChunkEvent has proper type and identity.
func TestLLMTokenChunkEvent(t *testing.T) {
	identity := AgentIdentity{
		ID:         "agent-coder",
		Confidence: ConfidenceHigh,
		PodName:    "coder-pod-xyz",
		Namespace:  "production",
	}
	e := &LLMTokenChunkEvent{
		BaseEvent: BaseEvent{
			Type:      EventTypeLLMTokenChunk,
			Time:      time.Now(),
			ReqID:     "req-chunk-1",
			Proto:     ProtocolLLM,
			Prov:      ProviderAnthropic,
			AgentInfo: identity,
		},
		Content:    "Hello",
		TokenIndex: 0,
	}
	if e.EventType() != EventTypeLLMTokenChunk {
		t.Errorf("EventType() = %q, want %q", e.EventType(), EventTypeLLMTokenChunk)
	}
	if e.Content != "Hello" {
		t.Errorf("Content = %q, want %q", e.Content, "Hello")
	}
	if e.TokenIndex != 0 {
		t.Errorf("TokenIndex = %d, want 0", e.TokenIndex)
	}
	if e.Identity().PodName != "coder-pod-xyz" {
		t.Errorf("Identity().PodName = %q, want %q", e.Identity().PodName, "coder-pod-xyz")
	}
}

// TestLLMRequestCompleteEvent verifies that LLMRequestCompleteEvent has metrics and identity.
func TestLLMRequestCompleteEvent(t *testing.T) {
	identity := AgentIdentity{
		ID:         "agent-analyst",
		SourceIP:   "10.0.1.10",
		Confidence: ConfidenceLow,
	}
	e := &LLMRequestCompleteEvent{
		BaseEvent: BaseEvent{
			Type:      EventTypeLLMRequestComplete,
			Time:      time.Now(),
			ReqID:     "req-complete-1",
			Proto:     ProtocolLLM,
			Prov:      ProviderOpenAI,
			AgentInfo: identity,
		},
		TotalTokens:  150,
		TTFT:         100 * time.Millisecond,
		Duration:     2 * time.Second,
		TokensPerSec: 75.0,
		FinishReason: "stop",
		InputTokens:  50,
		OutputTokens: 100,
	}
	if e.EventType() != EventTypeLLMRequestComplete {
		t.Errorf("EventType() = %q, want %q", e.EventType(), EventTypeLLMRequestComplete)
	}
	if e.TotalTokens != 150 {
		t.Errorf("TotalTokens = %d, want 150", e.TotalTokens)
	}
	if e.TTFT != 100*time.Millisecond {
		t.Errorf("TTFT = %v, want 100ms", e.TTFT)
	}
	if e.Duration != 2*time.Second {
		t.Errorf("Duration = %v, want 2s", e.Duration)
	}
	if e.TokensPerSec != 75.0 {
		t.Errorf("TokensPerSec = %f, want 75.0", e.TokensPerSec)
	}
	if e.Identity().Confidence != ConfidenceLow {
		t.Errorf("Identity().Confidence = %q, want %q", e.Identity().Confidence, ConfidenceLow)
	}
}

func TestEnforcementEvent_SeverityField(t *testing.T) {
	e := &EnforcementEvent{
		BaseEvent: BaseEvent{
			Type: EventTypePolicyDecision,
			Time: time.Now(),
		},
		Action:   "deny",
		Severity: "HIGH",
	}
	if e.Severity != "HIGH" {
		t.Errorf("EnforcementEvent.Severity = %q, want %q", e.Severity, "HIGH")
	}
}

func TestSeverityScore(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"INFO", 0},
		{"LOW", 5},
		{"MEDIUM", 20},
		{"HIGH", 50},
		{"CRITICAL", 100},
		{"", 0},
		{"unknown", 0},
	}
	for _, tc := range tests {
		got := SeverityScore(tc.severity)
		if got != tc.want {
			t.Errorf("SeverityScore(%q) = %d, want %d", tc.severity, got, tc.want)
		}
	}
}

// TestEventTypeConstants verifies the event type string constants are distinct.
func TestEventTypeConstants(t *testing.T) {
	types := []string{
		EventTypeLLMRequestStart,
		EventTypeLLMTokenChunk,
		EventTypeLLMRequestComplete,
	}
	seen := make(map[string]bool)
	for _, typ := range types {
		if typ == "" {
			t.Error("event type constant should not be empty")
		}
		if seen[typ] {
			t.Errorf("duplicate event type constant: %q", typ)
		}
		seen[typ] = true
	}
}

// TestProtocolConstants verifies protocol constants are distinct.
func TestProtocolConstants(t *testing.T) {
	if ProtocolLLM == "" {
		t.Error("ProtocolLLM should not be empty")
	}
}

// TestProviderConstants verifies provider constants are distinct.
func TestProviderConstants(t *testing.T) {
	if ProviderOpenAI == ProviderAnthropic {
		t.Error("ProviderOpenAI and ProviderAnthropic should be distinct")
	}
	if ProviderOpenAI == "" {
		t.Error("ProviderOpenAI should not be empty")
	}
	if ProviderAnthropic == "" {
		t.Error("ProviderAnthropic should not be empty")
	}
}

// TestConfidenceConstants verifies confidence level constants.
func TestConfidenceConstants(t *testing.T) {
	levels := []string{ConfidenceHigh, ConfidenceMedium, ConfidenceLow}
	seen := make(map[string]bool)
	for _, level := range levels {
		if level == "" {
			t.Error("confidence constant should not be empty")
		}
		if seen[level] {
			t.Errorf("duplicate confidence constant: %q", level)
		}
		seen[level] = true
	}
}

// TestAuthTypeConstants verifies auth type constants.
func TestAuthTypeConstants(t *testing.T) {
	if AuthTypeJWT == AuthTypeSourceIP {
		t.Error("AuthTypeJWT and AuthTypeSourceIP should be distinct")
	}
}
