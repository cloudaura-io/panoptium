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
	"net/http"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// --- Mock Observer Implementation ---

// mockObserver is a test double implementing ProtocolObserver.
type mockObserver struct {
	name       string
	canHandle  bool
	confidence float32
	handleErr  error
	processErr error
	finalErr   error

	// Track calls for verification
	canHandleCalled       int
	processRequestCalled  int
	processResponseCalled int
	finalizeCalled        int
	lastObserverCtx       *ObserverContext
	lastStreamCtx         *StreamContext
	lastResponseBody      []byte
	lastFinalizeErr       error
}

func newMockObserver(name string, canHandle bool, confidence float32) *mockObserver {
	return &mockObserver{
		name:       name,
		canHandle:  canHandle,
		confidence: confidence,
	}
}

func (m *mockObserver) Name() string { return m.name }

func (m *mockObserver) CanHandle(_ context.Context, req *ObserverContext) (bool, float32) {
	m.canHandleCalled++
	m.lastObserverCtx = req
	return m.canHandle, m.confidence
}

func (m *mockObserver) ProcessRequestStream(_ context.Context, req *ObserverContext) (*StreamContext, error) {
	m.processRequestCalled++
	m.lastObserverCtx = req
	if m.handleErr != nil {
		return nil, m.handleErr
	}
	return &StreamContext{
		RequestID: req.RequestID,
		Protocol:  "llm",
		Provider:  m.name,
		StartTime: time.Now(),
	}, nil
}

func (m *mockObserver) ProcessResponseStream(_ context.Context, streamCtx *StreamContext, body []byte) error {
	m.processResponseCalled++
	m.lastStreamCtx = streamCtx
	m.lastResponseBody = body
	return m.processErr
}

func (m *mockObserver) Finalize(_ context.Context, streamCtx *StreamContext, err error) error {
	m.finalizeCalled++
	m.lastStreamCtx = streamCtx
	m.lastFinalizeErr = err
	return m.finalErr
}

// --- ProtocolObserver Interface Contract Tests ---

// TestProtocolObserver_Name verifies that observers return their unique name.
func TestProtocolObserver_Name(t *testing.T) {
	obs := newMockObserver("test-observer", false, 0)
	if got := obs.Name(); got != "test-observer" {
		t.Errorf("Name() = %q, want %q", got, "test-observer")
	}
}

// TestProtocolObserver_CanHandle verifies that CanHandle returns a boolean and confidence score.
func TestProtocolObserver_CanHandle(t *testing.T) {
	obs := newMockObserver("test-observer", true, 0.9)
	ctx := context.Background()
	req := &ObserverContext{
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-123",
	}

	canHandle, confidence := obs.CanHandle(ctx, req)
	if !canHandle {
		t.Error("CanHandle() returned false, want true")
	}
	if confidence != 0.9 {
		t.Errorf("CanHandle() confidence = %f, want 0.9", confidence)
	}
	if obs.canHandleCalled != 1 {
		t.Errorf("CanHandle called %d times, want 1", obs.canHandleCalled)
	}
}

// TestProtocolObserver_CanHandle_Negative verifies that CanHandle correctly rejects unmatched requests.
func TestProtocolObserver_CanHandle_Negative(t *testing.T) {
	obs := newMockObserver("test-observer", false, 0)
	ctx := context.Background()
	req := &ObserverContext{
		Path:      "/unknown/path",
		Method:    "GET",
		RequestID: "req-456",
	}

	canHandle, confidence := obs.CanHandle(ctx, req)
	if canHandle {
		t.Error("CanHandle() returned true for unmatched request, want false")
	}
	if confidence != 0 {
		t.Errorf("CanHandle() confidence = %f, want 0", confidence)
	}
}

// TestProtocolObserver_ProcessRequestStream verifies that a request is processed and a StreamContext is returned.
func TestProtocolObserver_ProcessRequestStream(t *testing.T) {
	obs := newMockObserver("test-observer", true, 1.0)
	ctx := context.Background()
	req := &ObserverContext{
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-789",
	}

	streamCtx, err := obs.ProcessRequestStream(ctx, req)
	if err != nil {
		t.Fatalf("ProcessRequestStream() error = %v", err)
	}
	if streamCtx == nil {
		t.Fatal("ProcessRequestStream() returned nil StreamContext")
	}
	if streamCtx.RequestID != "req-789" {
		t.Errorf("StreamContext.RequestID = %q, want %q", streamCtx.RequestID, "req-789")
	}
	if obs.processRequestCalled != 1 {
		t.Errorf("ProcessRequestStream called %d times, want 1", obs.processRequestCalled)
	}
}

// TestProtocolObserver_ProcessRequestStream_Error verifies error propagation.
func TestProtocolObserver_ProcessRequestStream_Error(t *testing.T) {
	obs := newMockObserver("test-observer", true, 1.0)
	obs.handleErr = errors.New("parse error")
	ctx := context.Background()
	req := &ObserverContext{RequestID: "req-err"}

	streamCtx, err := obs.ProcessRequestStream(ctx, req)
	if err == nil {
		t.Fatal("ProcessRequestStream() expected error, got nil")
	}
	if streamCtx != nil {
		t.Error("ProcessRequestStream() should return nil StreamContext on error")
	}
}

// TestProtocolObserver_ProcessResponseStream verifies that response body chunks are processed.
func TestProtocolObserver_ProcessResponseStream(t *testing.T) {
	obs := newMockObserver("test-observer", true, 1.0)
	ctx := context.Background()
	streamCtx := &StreamContext{RequestID: "req-resp"}
	body := []byte(`data: {"choices":[{"delta":{"content":"Hello"}}]}`)

	err := obs.ProcessResponseStream(ctx, streamCtx, body)
	if err != nil {
		t.Fatalf("ProcessResponseStream() error = %v", err)
	}
	if obs.processResponseCalled != 1 {
		t.Errorf("ProcessResponseStream called %d times, want 1", obs.processResponseCalled)
	}
	if string(obs.lastResponseBody) != string(body) {
		t.Errorf("received body = %q, want %q", string(obs.lastResponseBody), string(body))
	}
}

// TestProtocolObserver_Finalize verifies that finalization emits completion events.
func TestProtocolObserver_Finalize(t *testing.T) {
	obs := newMockObserver("test-observer", true, 1.0)
	ctx := context.Background()
	streamCtx := &StreamContext{RequestID: "req-final"}

	err := obs.Finalize(ctx, streamCtx, nil)
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if obs.finalizeCalled != 1 {
		t.Errorf("Finalize called %d times, want 1", obs.finalizeCalled)
	}
}

// TestProtocolObserver_Finalize_WithUpstreamError verifies that Finalize receives the upstream error.
func TestProtocolObserver_Finalize_WithUpstreamError(t *testing.T) {
	obs := newMockObserver("test-observer", true, 1.0)
	ctx := context.Background()
	streamCtx := &StreamContext{RequestID: "req-final-err"}
	upstreamErr := errors.New("stream interrupted")

	err := obs.Finalize(ctx, streamCtx, upstreamErr)
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if obs.lastFinalizeErr != upstreamErr {
		t.Errorf("Finalize received error = %v, want %v", obs.lastFinalizeErr, upstreamErr)
	}
}

// --- ObserverContext Tests ---

// TestObserverContext_Fields verifies that ObserverContext fields are properly set.
func TestObserverContext_Fields(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Panoptium-Agent-Id", "agent-1")

	ctx := &ObserverContext{
		Headers:   headers,
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-ctx-1",
		Body:      []byte(`{"model":"gpt-4"}`),
	}

	if ctx.Path != "/v1/chat/completions" {
		t.Errorf("Path = %q, want %q", ctx.Path, "/v1/chat/completions")
	}
	if ctx.Method != "POST" {
		t.Errorf("Method = %q, want %q", ctx.Method, "POST")
	}
	if ctx.RequestID != "req-ctx-1" {
		t.Errorf("RequestID = %q, want %q", ctx.RequestID, "req-ctx-1")
	}
	if ctx.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type header = %q, want %q", ctx.Headers.Get("Content-Type"), "application/json")
	}
	if string(ctx.Body) != `{"model":"gpt-4"}` {
		t.Errorf("Body = %q, want %q", string(ctx.Body), `{"model":"gpt-4"}`)
	}
}

// --- StreamContext Tests ---

// TestStreamContext_Fields verifies that StreamContext fields are properly set.
func TestStreamContext_Fields(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	now := time.Now()
	sCtx := &StreamContext{
		RequestID: "req-stream-1",
		Protocol:  "llm",
		Provider:  "openai",
		StartTime: now,
		EventBus:  bus,
		AgentIdentity: eventbus.AgentIdentity{
			ID:         "agent-test",
			SourceIP:   "10.0.0.1",
			AuthType:   eventbus.AuthTypeJWT,
			Confidence: eventbus.ConfidenceHigh,
			PodName:    "test-pod",
			Namespace:  "default",
		},
		Model:      "gpt-4",
		Stream:     true,
		TokenCount: 0,
	}

	if sCtx.RequestID != "req-stream-1" {
		t.Errorf("RequestID = %q, want %q", sCtx.RequestID, "req-stream-1")
	}
	if sCtx.Protocol != "llm" {
		t.Errorf("Protocol = %q, want %q", sCtx.Protocol, "llm")
	}
	if sCtx.Provider != "openai" {
		t.Errorf("Provider = %q, want %q", sCtx.Provider, "openai")
	}
	if sCtx.AgentIdentity.ID != "agent-test" {
		t.Errorf("AgentIdentity.ID = %q, want %q", sCtx.AgentIdentity.ID, "agent-test")
	}
	if !sCtx.Stream {
		t.Error("Stream = false, want true")
	}
}

// --- ObserverRegistry Tests ---

// TestNewObserverRegistry verifies that a new registry can be created.
func TestNewObserverRegistry(t *testing.T) {
	registry := NewObserverRegistry()
	if registry == nil {
		t.Fatal("NewObserverRegistry() returned nil")
	}
}

// TestRegistry_Register verifies that observers can be registered.
func TestRegistry_Register(t *testing.T) {
	registry := NewObserverRegistry()
	obs := newMockObserver("llm-openai", true, 1.0)

	err := registry.Register(obs, ObserverConfig{
		Name:      "llm-openai",
		Priority:  10,
		Protocol:  "llm",
		Providers: []string{"openai"},
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	observers := registry.Observers()
	if len(observers) != 1 {
		t.Fatalf("Observers() returned %d observers, want 1", len(observers))
	}
	if observers[0] != "llm-openai" {
		t.Errorf("Observers()[0] = %q, want %q", observers[0], "llm-openai")
	}
}

// TestRegistry_Register_PriorityOrdering verifies that observers are ordered by priority.
func TestRegistry_Register_PriorityOrdering(t *testing.T) {
	registry := NewObserverRegistry()

	// Register in non-priority order
	obs3 := newMockObserver("observer-low", false, 0)
	obs1 := newMockObserver("observer-high", false, 0)
	obs2 := newMockObserver("observer-mid", false, 0)

	if err := registry.Register(obs3, ObserverConfig{Name: "observer-low", Priority: 30}); err != nil {
		t.Fatalf("Register low-priority: %v", err)
	}
	if err := registry.Register(obs1, ObserverConfig{Name: "observer-high", Priority: 10}); err != nil {
		t.Fatalf("Register high-priority: %v", err)
	}
	if err := registry.Register(obs2, ObserverConfig{Name: "observer-mid", Priority: 20}); err != nil {
		t.Fatalf("Register mid-priority: %v", err)
	}

	observers := registry.Observers()
	if len(observers) != 3 {
		t.Fatalf("Observers() returned %d observers, want 3", len(observers))
	}

	// Should be sorted by priority (lowest number = highest priority)
	expected := []string{"observer-high", "observer-mid", "observer-low"}
	for i, name := range expected {
		if observers[i] != name {
			t.Errorf("Observers()[%d] = %q, want %q", i, observers[i], name)
		}
	}
}

// TestRegistry_Register_DuplicateName verifies that duplicate observer names are rejected.
func TestRegistry_Register_DuplicateName(t *testing.T) {
	registry := NewObserverRegistry()
	obs1 := newMockObserver("llm-openai", true, 1.0)
	obs2 := newMockObserver("llm-openai", true, 0.8)

	err := registry.Register(obs1, ObserverConfig{Name: "llm-openai", Priority: 10})
	if err != nil {
		t.Fatalf("First Register() error = %v", err)
	}

	err = registry.Register(obs2, ObserverConfig{Name: "llm-openai", Priority: 20})
	if !errors.Is(err, ErrDuplicateObserver) {
		t.Errorf("Second Register() error = %v, want ErrDuplicateObserver", err)
	}

	// Original observer should still be registered
	observers := registry.Observers()
	if len(observers) != 1 {
		t.Fatalf("Observers() returned %d observers, want 1 (original still registered)", len(observers))
	}
}

// TestRegistry_Unregister verifies that observers can be removed by name.
func TestRegistry_Unregister(t *testing.T) {
	registry := NewObserverRegistry()
	obs := newMockObserver("llm-openai", true, 1.0)

	if err := registry.Register(obs, ObserverConfig{Name: "llm-openai", Priority: 10}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	removed := registry.Unregister("llm-openai")
	if !removed {
		t.Error("Unregister() returned false, want true")
	}

	observers := registry.Observers()
	if len(observers) != 0 {
		t.Errorf("Observers() returned %d observers after Unregister, want 0", len(observers))
	}
}

// TestRegistry_Unregister_NotFound verifies that Unregister returns false for unknown names.
func TestRegistry_Unregister_NotFound(t *testing.T) {
	registry := NewObserverRegistry()

	removed := registry.Unregister("nonexistent")
	if removed {
		t.Error("Unregister() returned true for nonexistent observer, want false")
	}
}

// TestRegistry_Unregister_CanRegisterAfterUnregister verifies re-registration after unregister.
func TestRegistry_Unregister_CanRegisterAfterUnregister(t *testing.T) {
	registry := NewObserverRegistry()
	obs1 := newMockObserver("llm-openai", true, 1.0)
	obs2 := newMockObserver("llm-openai", true, 0.9)

	if err := registry.Register(obs1, ObserverConfig{Name: "llm-openai", Priority: 10}); err != nil {
		t.Fatalf("First Register() error = %v", err)
	}

	registry.Unregister("llm-openai")

	// Should be able to register with the same name again
	err := registry.Register(obs2, ObserverConfig{Name: "llm-openai", Priority: 20})
	if err != nil {
		t.Fatalf("Re-Register() error = %v", err)
	}

	observers := registry.Observers()
	if len(observers) != 1 {
		t.Fatalf("Observers() returned %d observers, want 1", len(observers))
	}
}

// TestRegistry_SelectObserver_ByConfidence verifies confidence-based observer selection.
func TestRegistry_SelectObserver_ByConfidence(t *testing.T) {
	registry := NewObserverRegistry()

	// Register two observers that both can handle the request
	obsLow := newMockObserver("observer-low-conf", true, 0.5)
	obsHigh := newMockObserver("observer-high-conf", true, 0.9)

	if err := registry.Register(obsLow, ObserverConfig{Name: "observer-low-conf", Priority: 10}); err != nil {
		t.Fatalf("Register low-confidence: %v", err)
	}
	if err := registry.Register(obsHigh, ObserverConfig{Name: "observer-high-conf", Priority: 20}); err != nil {
		t.Fatalf("Register high-confidence: %v", err)
	}

	ctx := context.Background()
	req := &ObserverContext{
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-select",
	}

	selected, err := registry.SelectObserver(ctx, req)
	if err != nil {
		t.Fatalf("SelectObserver() error = %v", err)
	}
	if selected == nil {
		t.Fatal("SelectObserver() returned nil")
	}
	// The observer with the highest confidence should be selected
	if selected.Name() != "observer-high-conf" {
		t.Errorf("SelectObserver() selected %q, want %q", selected.Name(), "observer-high-conf")
	}
}

// TestRegistry_SelectObserver_PriorityBreaksTie verifies that priority breaks confidence ties.
func TestRegistry_SelectObserver_PriorityBreaksTie(t *testing.T) {
	registry := NewObserverRegistry()

	// Both observers have the same confidence, but different priorities
	obs1 := newMockObserver("observer-high-pri", true, 0.8)
	obs2 := newMockObserver("observer-low-pri", true, 0.8)

	if err := registry.Register(obs1, ObserverConfig{Name: "observer-high-pri", Priority: 10}); err != nil {
		t.Fatalf("Register high-priority: %v", err)
	}
	if err := registry.Register(obs2, ObserverConfig{Name: "observer-low-pri", Priority: 20}); err != nil {
		t.Fatalf("Register low-priority: %v", err)
	}

	ctx := context.Background()
	req := &ObserverContext{
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-tie",
	}

	selected, err := registry.SelectObserver(ctx, req)
	if err != nil {
		t.Fatalf("SelectObserver() error = %v", err)
	}
	// Priority should break the tie — lower priority number wins
	if selected.Name() != "observer-high-pri" {
		t.Errorf("SelectObserver() selected %q, want %q (higher priority)", selected.Name(), "observer-high-pri")
	}
}

// TestRegistry_SelectObserver_OnlyMatchingObservers verifies that non-matching observers are skipped.
func TestRegistry_SelectObserver_OnlyMatchingObservers(t *testing.T) {
	registry := NewObserverRegistry()

	obsNoMatch := newMockObserver("no-match", false, 0)
	obsMatch := newMockObserver("match", true, 0.7)

	if err := registry.Register(obsNoMatch, ObserverConfig{Name: "no-match", Priority: 10}); err != nil {
		t.Fatalf("Register no-match: %v", err)
	}
	if err := registry.Register(obsMatch, ObserverConfig{Name: "match", Priority: 20}); err != nil {
		t.Fatalf("Register match: %v", err)
	}

	ctx := context.Background()
	req := &ObserverContext{
		Path:      "/v1/messages",
		Method:    "POST",
		RequestID: "req-only-match",
	}

	selected, err := registry.SelectObserver(ctx, req)
	if err != nil {
		t.Fatalf("SelectObserver() error = %v", err)
	}
	if selected.Name() != "match" {
		t.Errorf("SelectObserver() selected %q, want %q", selected.Name(), "match")
	}

	// Verify both observers were consulted
	if obsNoMatch.canHandleCalled != 1 {
		t.Errorf("no-match observer: CanHandle called %d times, want 1", obsNoMatch.canHandleCalled)
	}
	if obsMatch.canHandleCalled != 1 {
		t.Errorf("match observer: CanHandle called %d times, want 1", obsMatch.canHandleCalled)
	}
}

// TestRegistry_SelectObserver_NoMatch verifies that ErrNoMatchingObserver is returned when no observer matches.
func TestRegistry_SelectObserver_NoMatch(t *testing.T) {
	registry := NewObserverRegistry()

	obs := newMockObserver("no-match", false, 0)
	if err := registry.Register(obs, ObserverConfig{Name: "no-match", Priority: 10}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	ctx := context.Background()
	req := &ObserverContext{
		Path:      "/unknown/path",
		Method:    "POST",
		RequestID: "req-no-match",
	}

	selected, err := registry.SelectObserver(ctx, req)
	if !errors.Is(err, ErrNoMatchingObserver) {
		t.Errorf("SelectObserver() error = %v, want ErrNoMatchingObserver", err)
	}
	if selected != nil {
		t.Errorf("SelectObserver() returned non-nil observer on no-match: %q", selected.Name())
	}
}

// TestRegistry_SelectObserver_EmptyRegistry verifies ErrNoMatchingObserver on empty registry.
func TestRegistry_SelectObserver_EmptyRegistry(t *testing.T) {
	registry := NewObserverRegistry()

	ctx := context.Background()
	req := &ObserverContext{
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-empty",
	}

	selected, err := registry.SelectObserver(ctx, req)
	if !errors.Is(err, ErrNoMatchingObserver) {
		t.Errorf("SelectObserver() error = %v, want ErrNoMatchingObserver", err)
	}
	if selected != nil {
		t.Error("SelectObserver() returned non-nil observer on empty registry")
	}
}

// TestObserverConfig_Fields verifies that ObserverConfig fields are properly set.
func TestObserverConfig_Fields(t *testing.T) {
	config := ObserverConfig{
		Name:      "llm-openai",
		Priority:  10,
		Protocol:  "llm",
		Providers: []string{"openai", "azure-openai"},
	}

	if config.Name != "llm-openai" {
		t.Errorf("Name = %q, want %q", config.Name, "llm-openai")
	}
	if config.Priority != 10 {
		t.Errorf("Priority = %d, want 10", config.Priority)
	}
	if config.Protocol != "llm" {
		t.Errorf("Protocol = %q, want %q", config.Protocol, "llm")
	}
	if len(config.Providers) != 2 {
		t.Fatalf("Providers has %d items, want 2", len(config.Providers))
	}
}
