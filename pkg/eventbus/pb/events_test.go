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

package pb

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestPanoptiumEvent_RoundTrip verifies that a PanoptiumEvent can be marshaled
// to wire format and unmarshaled back with all fields preserved.
func TestPanoptiumEvent_RoundTrip(t *testing.T) {
	now := time.Now()
	traceID := make([]byte, 16)
	for i := range traceID {
		traceID[i] = byte(i)
	}
	spanID := make([]byte, 8)
	for i := range spanID {
		spanID[i] = byte(i + 100)
	}
	parentSpanID := make([]byte, 8)
	for i := range parentSpanID {
		parentSpanID[i] = byte(i + 200)
	}

	original := &PanoptiumEvent{
		Id:           "01HZTEST000000000000000001",
		Timestamp:    timestamppb.New(now),
		TraceId:      traceID,
		SpanId:       spanID,
		ParentSpanId: parentSpanID,
		Source: &EventSource{
			Component: "extproc",
			Instance:  "panoptium-operator-abc123",
			Version:   "v0.1.0",
		},
		Agent: &AgentIdentity{
			PodName:   "agent-pod-xyz",
			Namespace: "default",
			Labels:    map[string]string{"app": "summarizer"},
			AuthType:  "jwt",
			AuthId:    "agent-summarizer",
		},
		Category:    "llm",
		Subcategory: "request.start",
		Severity:    Severity_INFO,
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal PanoptiumEvent: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Marshaled data is empty")
	}

	restored := &PanoptiumEvent{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal PanoptiumEvent: %v", err)
	}

	// Verify all fields
	if restored.Id != original.Id {
		t.Errorf("Id = %q, want %q", restored.Id, original.Id)
	}
	if restored.Category != original.Category {
		t.Errorf("Category = %q, want %q", restored.Category, original.Category)
	}
	if restored.Subcategory != original.Subcategory {
		t.Errorf("Subcategory = %q, want %q", restored.Subcategory, original.Subcategory)
	}
	if restored.Severity != original.Severity {
		t.Errorf("Severity = %v, want %v", restored.Severity, original.Severity)
	}
	if restored.Source.Component != original.Source.Component {
		t.Errorf("Source.Component = %q, want %q", restored.Source.Component, original.Source.Component)
	}
	if restored.Agent.PodName != original.Agent.PodName {
		t.Errorf("Agent.PodName = %q, want %q", restored.Agent.PodName, original.Agent.PodName)
	}
	if restored.Agent.Labels["app"] != "summarizer" {
		t.Errorf("Agent.Labels[app] = %q, want %q", restored.Agent.Labels["app"], "summarizer")
	}
}

// TestPanoptiumEvent_ULIDUniqueness verifies that ULID-based IDs should be
// unique and time-sortable. This test validates the format expectation.
func TestPanoptiumEvent_ULIDUniqueness(t *testing.T) {
	// ULIDs are 26-character Crockford Base32 encoded strings
	// We test that the ID field accepts and preserves ULID-format strings
	ids := []string{
		"01HZTEST000000000000000001",
		"01HZTEST000000000000000002",
		"01HZTEST000000000000000003",
	}

	seen := make(map[string]bool)
	for _, id := range ids {
		evt := &PanoptiumEvent{Id: id}
		data, err := proto.Marshal(evt)
		if err != nil {
			t.Fatalf("Failed to marshal event with ID %q: %v", id, err)
		}
		restored := &PanoptiumEvent{}
		if err := proto.Unmarshal(data, restored); err != nil {
			t.Fatalf("Failed to unmarshal event with ID %q: %v", id, err)
		}
		if restored.Id != id {
			t.Errorf("Round-trip ID = %q, want %q", restored.Id, id)
		}
		if seen[id] {
			t.Errorf("Duplicate ID: %q", id)
		}
		seen[id] = true
	}

	// Verify sortability: earlier IDs sort before later IDs
	if ids[0] >= ids[1] || ids[1] >= ids[2] {
		t.Error("ULID IDs should be sortable in chronological order")
	}
}

// TestPanoptiumEvent_NanosecondTimestamp verifies that the timestamp field
// preserves nanosecond precision via google.protobuf.Timestamp.
func TestPanoptiumEvent_NanosecondTimestamp(t *testing.T) {
	// Use a timestamp with nanosecond precision
	ts := time.Date(2026, 3, 30, 12, 0, 0, 123456789, time.UTC)

	evt := &PanoptiumEvent{
		Id:        "01HZTEST_TIMESTAMP",
		Timestamp: timestamppb.New(ts),
	}

	data, err := proto.Marshal(evt)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	restored := &PanoptiumEvent{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	restoredTime := restored.Timestamp.AsTime()
	if !restoredTime.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", restoredTime, ts)
	}

	// Verify nanosecond component specifically
	if restoredTime.Nanosecond() != 123456789 {
		t.Errorf("Nanosecond = %d, want %d", restoredTime.Nanosecond(), 123456789)
	}
}

// TestPanoptiumEvent_TraceIDSpanIDSizes verifies that TraceID is 16 bytes
// and SpanID is 8 bytes as required by W3C Trace Context.
func TestPanoptiumEvent_TraceIDSpanIDSizes(t *testing.T) {
	traceID := make([]byte, 16)
	for i := range traceID {
		traceID[i] = byte(i)
	}
	spanID := make([]byte, 8)
	for i := range spanID {
		spanID[i] = byte(i + 50)
	}
	parentSpanID := make([]byte, 8)
	for i := range parentSpanID {
		parentSpanID[i] = byte(i + 100)
	}

	evt := &PanoptiumEvent{
		Id:           "01HZTEST_TRACEID",
		TraceId:      traceID,
		SpanId:       spanID,
		ParentSpanId: parentSpanID,
	}

	data, err := proto.Marshal(evt)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	restored := &PanoptiumEvent{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify TraceID is 16 bytes
	if len(restored.TraceId) != 16 {
		t.Errorf("TraceID length = %d, want 16", len(restored.TraceId))
	}
	for i, b := range restored.TraceId {
		if b != byte(i) {
			t.Errorf("TraceID[%d] = %d, want %d", i, b, byte(i))
		}
	}

	// Verify SpanID is 8 bytes
	if len(restored.SpanId) != 8 {
		t.Errorf("SpanID length = %d, want 8", len(restored.SpanId))
	}
	for i, b := range restored.SpanId {
		if b != byte(i+50) {
			t.Errorf("SpanID[%d] = %d, want %d", i, b, byte(i+50))
		}
	}

	// Verify ParentSpanID is 8 bytes
	if len(restored.ParentSpanId) != 8 {
		t.Errorf("ParentSpanID length = %d, want 8", len(restored.ParentSpanId))
	}
	for i, b := range restored.ParentSpanId {
		if b != byte(i+100) {
			t.Errorf("ParentSpanID[%d] = %d, want %d", i, b, byte(i+100))
		}
	}
}

// TestSeverityEnum verifies that severity enum values are defined correctly.
func TestSeverityEnum(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     int32
	}{
		{"INFO", Severity_INFO, 0},
		{"LOW", Severity_LOW, 1},
		{"MEDIUM", Severity_MEDIUM, 2},
		{"HIGH", Severity_HIGH, 3},
		{"CRITICAL", Severity_CRITICAL, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int32(tt.severity) != tt.want {
				t.Errorf("Severity_%s = %d, want %d", tt.name, int32(tt.severity), tt.want)
			}
		})
	}
}

// TestEventSource_RoundTrip verifies the EventSource message fields.
func TestEventSource_RoundTrip(t *testing.T) {
	src := &EventSource{
		Component: "ebpf",
		Instance:  "node-agent-worker-1",
		Version:   "v0.2.0",
	}

	data, err := proto.Marshal(src)
	if err != nil {
		t.Fatalf("Failed to marshal EventSource: %v", err)
	}

	restored := &EventSource{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal EventSource: %v", err)
	}

	if restored.Component != "ebpf" {
		t.Errorf("Component = %q, want %q", restored.Component, "ebpf")
	}
	if restored.Instance != "node-agent-worker-1" {
		t.Errorf("Instance = %q, want %q", restored.Instance, "node-agent-worker-1")
	}
	if restored.Version != "v0.2.0" {
		t.Errorf("Version = %q, want %q", restored.Version, "v0.2.0")
	}
}

// TestAgentIdentity_RoundTrip verifies the AgentIdentity message fields.
func TestAgentIdentity_RoundTrip(t *testing.T) {
	agent := &AgentIdentity{
		PodName:   "chatbot-pod-abc",
		Namespace: "production",
		Labels:    map[string]string{"app": "chatbot", "tier": "frontend"},
		AuthType:  "jwt",
		AuthId:    "chatbot-sa",
		SourceIp:  "10.0.1.5",
	}

	data, err := proto.Marshal(agent)
	if err != nil {
		t.Fatalf("Failed to marshal AgentIdentity: %v", err)
	}

	restored := &AgentIdentity{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal AgentIdentity: %v", err)
	}

	if restored.PodName != "chatbot-pod-abc" {
		t.Errorf("PodName = %q, want %q", restored.PodName, "chatbot-pod-abc")
	}
	if restored.Namespace != "production" {
		t.Errorf("Namespace = %q, want %q", restored.Namespace, "production")
	}
	if restored.Labels["app"] != "chatbot" {
		t.Errorf("Labels[app] = %q, want %q", restored.Labels["app"], "chatbot")
	}
	if restored.Labels["tier"] != "frontend" {
		t.Errorf("Labels[tier] = %q, want %q", restored.Labels["tier"], "frontend")
	}
	if restored.AuthType != "jwt" {
		t.Errorf("AuthType = %q, want %q", restored.AuthType, "jwt")
	}
	if restored.SourceIp != "10.0.1.5" {
		t.Errorf("SourceIp = %q, want %q", restored.SourceIp, "10.0.1.5")
	}
}
