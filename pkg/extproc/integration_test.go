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

package extproc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/google/uuid"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
)

const (
	testModelGPT4           = "gpt-4"
	testAgentSummarizerName = "agent-summarizer"
)

// setupIntegrationComponents creates the full component stack for integration
// testing: event bus, observer registry with LLM observer, pod IP cache with
// pre-populated entries, identity resolver, and ExtProc server. It returns all
// components along with a gRPC client connected to an in-process server.
func setupIntegrationComponents(t *testing.T) (
	bus *eventbus.SimpleBus,
	podCache *identity.PodCache,
	client extprocv3.ExternalProcessorClient,
	cleanup func(),
) {
	t.Helper()

	bus = eventbus.NewSimpleBus()
	registry := observer.NewObserverRegistry()

	llmObs := llm.NewLLMObserver(bus)
	if err := registry.Register(llmObs, observer.ObserverConfig{
		Name:      "llm",
		Priority:  100,
		Protocol:  eventbus.ProtocolLLM,
		Providers: []string{eventbus.ProviderOpenAI, eventbus.ProviderAnthropic},
	}); err != nil {
		t.Fatalf("failed to register LLM observer: %v", err)
	}

	podCache = identity.NewPodCache()
	resolver := identity.NewResolver(podCache)

	srv := NewExtProcServer(registry, resolver, bus)
	client, cleanup = startTestServer(t, srv)

	return bus, podCache, client, cleanup
}

// collectEvents subscribes to the event bus and collects events until a timeout
// is reached or the expected count is reached, whichever comes first.
func collectEvents(sub *eventbus.Subscription, expectedCount int, timeout time.Duration) []eventbus.Event {
	var events []eventbus.Event
	deadline := time.After(timeout)
	for {
		select {
		case evt, ok := <-sub.Events():
			if !ok {
				return events
			}
			events = append(events, evt)
			if len(events) >= expectedCount {
				return events
			}
		case <-deadline:
			return events
		}
	}
}

// sendOpenAIStreamingRequest sends a complete OpenAI streaming request sequence
// through the ExtProc stream: request headers, request body, response headers,
// response body chunks with SSE data, and end-of-stream marker. It returns the
// number of response body chunks sent (excluding the [DONE] marker).
func sendOpenAIStreamingRequest(
	t *testing.T,
	stream extprocv3.ExternalProcessor_ProcessClient,
	sourceIP, model string,
	tokenContents []string,
) {
	t.Helper()

	// 1. Send request headers
	// Identity is resolved via X-Forwarded-For -> PodCache lookup (K8s-native).
	// The old x-panoptium-agent-id / x-panoptium-auth-type headers are no longer
	// used for identity resolution.
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-forwarded-for", sourceIP,
				),
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive response for request headers: %v", err)
	}

	// 2. Send request body
	reqBody := makeOpenAIRequestBody(model, true)
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        reqBody,
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive response for request body: %v", err)
	}

	// 3. Send response headers
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "text/event-stream",
				),
			},
		},
	}); err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive response for response headers: %v", err)
	}

	// 4. Send response body chunks
	for i, content := range tokenContents {
		isLast := i == len(tokenContents)-1
		if err := stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        makeOpenAISSEChunk(content),
					EndOfStream: isLast,
				},
			},
		}); err != nil {
			t.Fatalf("failed to send response body chunk %d: %v", i, err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatalf("failed to receive response for body chunk %d: %v", i, err)
		}
	}

	// 5. Close the stream
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("failed to close send: %v", err)
	}
}

// TestIntegration_OpenAIStreamingWithEnrolledPod verifies the full end-to-end
// flow for an OpenAI streaming request with K8s-native pod identity:
// request headers with X-Forwarded-For → PodCache lookup → LLMRequestStart event,
// streaming SSE response chunks → LLMTokenChunk events in order,
// end-of-stream → LLMRequestComplete with metrics and agent identity.
func TestIntegration_OpenAIStreamingWithEnrolledPod(t *testing.T) {
	bus, podCache, client, cleanup := setupIntegrationComponents(t)
	defer cleanup()

	// Pre-populate the PodCache with the enrolled pod
	podCache.Set("10.0.0.1", identity.PodInfo{
		Name:           testAgentSummarizerName,
		Namespace:      "ai-agents",
		UID:            "uid-summarizer-123",
		Labels:         map[string]string{"app": "summarizer"},
		ServiceAccount: "summarizer-sa",
	})

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	tokens := []string{"Hello", " from", " the", " AI", " assistant"}
	sendOpenAIStreamingRequest(t, stream, "10.0.0.1", testModelGPT4, tokens)

	// Expect: 1 LLMRequestStart + 5 LLMTokenChunk + 1 LLMRequestComplete = 7 events
	events := collectEvents(sub, 7, 5*time.Second)

	// Verify LLMRequestStart
	var startEvts []*eventbus.LLMRequestStartEvent
	var chunkEvts []*eventbus.LLMTokenChunkEvent
	var completeEvts []*eventbus.LLMRequestCompleteEvent

	for _, evt := range events {
		switch e := evt.(type) {
		case *eventbus.LLMRequestStartEvent:
			startEvts = append(startEvts, e)
		case *eventbus.LLMTokenChunkEvent:
			chunkEvts = append(chunkEvts, e)
		case *eventbus.LLMRequestCompleteEvent:
			completeEvts = append(completeEvts, e)
		}
	}

	// Verify LLMRequestStart event
	if len(startEvts) != 1 {
		t.Fatalf("expected 1 LLMRequestStart event, got %d", len(startEvts))
	}
	start := startEvts[0]
	if _, parseErr := uuid.Parse(start.RequestID()); parseErr != nil {
		t.Errorf("LLMRequestStart.RequestID %q is not a valid UUID: %v", start.RequestID(), parseErr)
	}
	streamRequestID := start.RequestID() // capture for cross-event consistency checks
	if start.Protocol() != eventbus.ProtocolLLM {
		t.Errorf("LLMRequestStart.Protocol = %q, want %q", start.Protocol(), eventbus.ProtocolLLM)
	}
	if start.Provider() != eventbus.ProviderOpenAI {
		t.Errorf("LLMRequestStart.Provider = %q, want %q", start.Provider(), eventbus.ProviderOpenAI)
	}
	if start.Model != testModelGPT4 {
		t.Errorf("LLMRequestStart.Model = %q, want %q", start.Model, testModelGPT4)
	}
	if !start.Stream {
		t.Error("LLMRequestStart.Stream = false, want true")
	}

	// Verify agent identity on start event (resolved via PodCache)
	agentInfo := start.Identity()
	if agentInfo.ID != testAgentSummarizerName {
		t.Errorf("AgentIdentity.ID = %q, want %q", agentInfo.ID, testAgentSummarizerName)
	}
	if agentInfo.PodName != testAgentSummarizerName {
		t.Errorf("AgentIdentity.PodName = %q, want %q", agentInfo.PodName, testAgentSummarizerName)
	}
	if agentInfo.Namespace != "ai-agents" {
		t.Errorf("AgentIdentity.Namespace = %q, want %q", agentInfo.Namespace, "ai-agents")
	}
	if agentInfo.Confidence != eventbus.ConfidenceHigh {
		t.Errorf("AgentIdentity.Confidence = %q, want %q", agentInfo.Confidence, eventbus.ConfidenceHigh)
	}

	// Verify LLMTokenChunk events — correct count, order, and identity
	if len(chunkEvts) != 5 {
		t.Fatalf("expected 5 LLMTokenChunk events, got %d", len(chunkEvts))
	}
	for i, chunk := range chunkEvts {
		if chunk.Content != tokens[i] {
			t.Errorf("LLMTokenChunk[%d].Content = %q, want %q", i, chunk.Content, tokens[i])
		}
		if chunk.TokenIndex != i {
			t.Errorf("LLMTokenChunk[%d].TokenIndex = %d, want %d", i, chunk.TokenIndex, i)
		}
		if chunk.RequestID() != streamRequestID {
			t.Errorf("LLMTokenChunk[%d].RequestID = %q, want %q (same as start event)", i, chunk.RequestID(), streamRequestID)
		}
		if chunk.Provider() != eventbus.ProviderOpenAI {
			t.Errorf("LLMTokenChunk[%d].Provider = %q, want %q", i, chunk.Provider(), eventbus.ProviderOpenAI)
		}
		chunkIdentity := chunk.Identity()
		if chunkIdentity.ID != testAgentSummarizerName {
			t.Errorf("LLMTokenChunk[%d].Identity.ID = %q, want %q", i, chunkIdentity.ID, testAgentSummarizerName)
		}
		if chunkIdentity.Confidence != eventbus.ConfidenceHigh {
			t.Errorf("LLMTokenChunk[%d].Identity.Confidence = %q, want %q", i, chunkIdentity.Confidence, eventbus.ConfidenceHigh)
		}
	}

	// Verify LLMRequestComplete event
	if len(completeEvts) != 1 {
		t.Fatalf("expected 1 LLMRequestComplete event, got %d", len(completeEvts))
	}
	complete := completeEvts[0]
	if complete.OutputTokens != 5 {
		t.Errorf("LLMRequestComplete.OutputTokens = %d, want 5", complete.OutputTokens)
	}
	if complete.Duration <= 0 {
		t.Error("LLMRequestComplete.Duration should be > 0")
	}
	if complete.RequestID() != streamRequestID {
		t.Errorf("LLMRequestComplete.RequestID = %q, want %q (same as start event)", complete.RequestID(), streamRequestID)
	}
	completeIdentity := complete.Identity()
	if completeIdentity.ID != testAgentSummarizerName {
		t.Errorf("LLMRequestComplete.Identity.ID = %q, want %q", completeIdentity.ID, testAgentSummarizerName)
	}
	if completeIdentity.Confidence != eventbus.ConfidenceHigh {
		t.Errorf("LLMRequestComplete.Identity.Confidence = %q, want %q", completeIdentity.Confidence, eventbus.ConfidenceHigh)
	}
}

// TestIntegration_OpenAIMultiEventSSEFrame verifies that multi-event SSE frames
// (multiple data: lines in a single HTTP frame) are correctly parsed and produce
// individual LLMTokenChunk events.
func TestIntegration_OpenAIMultiEventSSEFrame(t *testing.T) {
	bus, _, client, cleanup := setupIntegrationComponents(t)
	defer cleanup()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers and body
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
				),
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody(testModelGPT4, true),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	// Send response headers
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(":status", "200", "content-type", "text/event-stream"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	// Build a multi-event SSE frame: two data: lines in one HTTP frame
	chunk1JSON, _ := json.Marshal(map[string]interface{}{
		"id":      "chatcmpl-multi",
		"choices": []map[string]interface{}{{"delta": map[string]string{"content": "Hello"}, "finish_reason": nil}},
	})
	chunk2JSON, _ := json.Marshal(map[string]interface{}{
		"id":      "chatcmpl-multi",
		"choices": []map[string]interface{}{{"delta": map[string]string{"content": " World"}, "finish_reason": nil}},
	})
	multiEventFrame := fmt.Sprintf("data: %s\n\ndata: %s\n\n", chunk1JSON, chunk2JSON)

	// Send the multi-event frame as a single response body chunk
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        []byte(multiEventFrame),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send multi-event response body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	_ = stream.CloseSend()

	// Expect: 1 LLMRequestStart + 2 LLMTokenChunk + 1 LLMRequestComplete = 4
	events := collectEvents(sub, 4, 5*time.Second)

	var chunkEvts []*eventbus.LLMTokenChunkEvent
	for _, evt := range events {
		if chunk, ok := evt.(*eventbus.LLMTokenChunkEvent); ok {
			chunkEvts = append(chunkEvts, chunk)
		}
	}

	if len(chunkEvts) != 2 {
		t.Fatalf("expected 2 LLMTokenChunk events from multi-event frame, got %d", len(chunkEvts))
	}
	if chunkEvts[0].Content != "Hello" {
		t.Errorf("chunk[0].Content = %q, want %q", chunkEvts[0].Content, "Hello")
	}
	if chunkEvts[1].Content != " World" {
		t.Errorf("chunk[1].Content = %q, want %q", chunkEvts[1].Content, " World")
	}
	if chunkEvts[0].TokenIndex != 0 {
		t.Errorf("chunk[0].TokenIndex = %d, want 0", chunkEvts[0].TokenIndex)
	}
	if chunkEvts[1].TokenIndex != 1 {
		t.Errorf("chunk[1].TokenIndex = %d, want 1", chunkEvts[1].TokenIndex)
	}
}

// TestIntegration_AnthropicStreamingRequest verifies the full end-to-end flow
// for an Anthropic streaming request, including the SSE event format with
// event: and data: pairs.
func TestIntegration_AnthropicStreamingRequest(t *testing.T) {
	bus, _, client, cleanup := setupIntegrationComponents(t)
	defer cleanup()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers for Anthropic
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/messages",
					":method", "POST",
					"host", "api.anthropic.com",
					"content-type", "application/json",
				),
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	// Send Anthropic request body
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeAnthropicRequestBody("claude-3-opus-20240229", true),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	// Send response headers
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(":status", "200", "content-type", "text/event-stream"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	// Send Anthropic SSE response chunks
	anthropicTokens := []string{"Kubernetes", " is", " amazing"}
	for i, token := range anthropicTokens {
		deltaJSON, _ := json.Marshal(map[string]interface{}{
			"type": "content_block_delta",
			"delta": map[string]string{
				"type": "text_delta",
				"text": token,
			},
		})
		sseFrame := fmt.Sprintf("event: content_block_delta\ndata: %s\n\n", deltaJSON)

		isLast := i == len(anthropicTokens)-1
		if err := stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        []byte(sseFrame),
					EndOfStream: isLast,
				},
			},
		}); err != nil {
			t.Fatalf("failed to send response body chunk %d: %v", i, err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatalf("failed to recv: %v", err)
		}
	}

	_ = stream.CloseSend()

	// Expect: 1 LLMRequestStart + 3 LLMTokenChunk + 1 LLMRequestComplete = 5
	events := collectEvents(sub, 5, 5*time.Second)

	var startEvts []*eventbus.LLMRequestStartEvent
	var chunkEvts []*eventbus.LLMTokenChunkEvent
	var completeEvts []*eventbus.LLMRequestCompleteEvent

	for _, evt := range events {
		switch e := evt.(type) {
		case *eventbus.LLMRequestStartEvent:
			startEvts = append(startEvts, e)
		case *eventbus.LLMTokenChunkEvent:
			chunkEvts = append(chunkEvts, e)
		case *eventbus.LLMRequestCompleteEvent:
			completeEvts = append(completeEvts, e)
		}
	}

	// Verify Anthropic-specific parsing
	if len(startEvts) != 1 {
		t.Fatalf("expected 1 LLMRequestStart event, got %d", len(startEvts))
	}
	if startEvts[0].Provider() != eventbus.ProviderAnthropic {
		t.Errorf("Provider = %q, want %q", startEvts[0].Provider(), eventbus.ProviderAnthropic)
	}
	if startEvts[0].Model != "claude-3-opus-20240229" {
		t.Errorf("Model = %q, want %q", startEvts[0].Model, "claude-3-opus-20240229")
	}

	if len(chunkEvts) != 3 {
		t.Fatalf("expected 3 LLMTokenChunk events, got %d", len(chunkEvts))
	}
	for i, chunk := range chunkEvts {
		if chunk.Content != anthropicTokens[i] {
			t.Errorf("chunk[%d].Content = %q, want %q", i, chunk.Content, anthropicTokens[i])
		}
		if chunk.Provider() != eventbus.ProviderAnthropic {
			t.Errorf("chunk[%d].Provider = %q, want %q", i, chunk.Provider(), eventbus.ProviderAnthropic)
		}
	}

	if len(completeEvts) != 1 {
		t.Fatalf("expected 1 LLMRequestComplete event, got %d", len(completeEvts))
	}
	if completeEvts[0].OutputTokens != 3 {
		t.Errorf("OutputTokens = %d, want 3", completeEvts[0].OutputTokens)
	}
}

// TestIntegration_EnrolledPodIdentityWithPodCache verifies that when an enrolled
// pod's source IP is in the PodCache, the identity is resolved with high
// confidence including pod name, namespace, and labels.
func TestIntegration_EnrolledPodIdentityWithPodCache(t *testing.T) {
	bus, podCache, client, cleanup := setupIntegrationComponents(t)
	defer cleanup()

	// Pre-populate the pod IP cache (simulating a Kubernetes Informer having
	// observed the pod)
	podCache.Set("10.0.5.42", identity.PodInfo{
		Name:           "agent-pod-abc",
		Namespace:      "ml-workloads",
		UID:            "uid-pod-abc",
		Labels:         map[string]string{"app": "summarizer", "team": "ai"},
		ServiceAccount: "summarizer-sa",
	})

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request with X-Forwarded-For for K8s-native identity resolution
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-forwarded-for", "10.0.5.42",
				),
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	// Send request body to trigger event
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody(testModelGPT4, false),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	_ = stream.CloseSend()

	// Verify the event has high confidence with resolved pod info
	select {
	case evt := <-sub.Events():
		agentInfo := evt.Identity()
		if agentInfo.Confidence != eventbus.ConfidenceHigh {
			t.Errorf("Confidence = %q, want %q", agentInfo.Confidence, eventbus.ConfidenceHigh)
		}
		if agentInfo.ID != "agent-pod-abc" {
			t.Errorf("ID = %q, want %q", agentInfo.ID, "agent-pod-abc")
		}
		if agentInfo.PodName != "agent-pod-abc" {
			t.Errorf("PodName = %q, want %q", agentInfo.PodName, "agent-pod-abc")
		}
		if agentInfo.Namespace != "ml-workloads" {
			t.Errorf("Namespace = %q, want %q", agentInfo.Namespace, "ml-workloads")
		}
		if agentInfo.Labels["app"] != "summarizer" {
			t.Errorf("Labels[app] = %q, want %q", agentInfo.Labels["app"], "summarizer")
		}
		if agentInfo.Labels["team"] != "ai" {
			t.Errorf("Labels[team] = %q, want %q", agentInfo.Labels["team"], "ai")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for LLMRequestStart event")
	}
}

// TestIntegration_NoIdentityHeaders verifies that when no x-panoptium-* headers
// are present, the system gracefully falls back to an unknown identity with low
// confidence.
func TestIntegration_NoIdentityHeaders(t *testing.T) {
	bus, _, client, cleanup := setupIntegrationComponents(t)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers WITHOUT any x-panoptium-* headers
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
				),
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	// Send request body
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody(testModelGPT4, false),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	_ = stream.CloseSend()

	// Verify event has low confidence with empty identity fields
	select {
	case evt := <-sub.Events():
		agentInfo := evt.Identity()
		if agentInfo.Confidence != eventbus.ConfidenceLow {
			t.Errorf("Confidence = %q, want %q", agentInfo.Confidence, eventbus.ConfidenceLow)
		}
		if agentInfo.ID != "" {
			t.Errorf("ID = %q, want empty string", agentInfo.ID)
		}
		if agentInfo.PodName != "" {
			t.Errorf("PodName = %q, want empty string", agentInfo.PodName)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for LLMRequestStart event")
	}
}

// TestIntegration_ConcurrentStreamsFromDifferentAgents verifies that multiple
// concurrent ExtProc streams from different agents produce independent event
// streams with correct agent attribution. Each agent's events must carry the
// correct agent identity, and events from different agents must not be mixed.
func TestIntegration_ConcurrentStreamsFromDifferentAgents(t *testing.T) {
	bus, podCache, client, cleanup := setupIntegrationComponents(t)
	defer cleanup()

	// Pre-populate PodCache with enrolled pods
	podCache.Set("10.0.0.1", identity.PodInfo{
		Name:      "agent-alpha",
		Namespace: "default",
	})
	podCache.Set("10.0.0.2", identity.PodInfo{
		Name:      "agent-beta",
		Namespace: "default",
	})
	podCache.Set("10.0.0.3", identity.PodInfo{
		Name:      "agent-gamma",
		Namespace: "default",
	})

	// Subscribe to all events
	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	agents := []struct {
		podName  string
		sourceIP string
		model    string
		tokens   []string
	}{
		{
			podName:  "agent-alpha",
			sourceIP: "10.0.0.1",
			model:    testModelGPT4,
			tokens:   []string{"Alpha", " response", " here"},
		},
		{
			podName:  "agent-beta",
			sourceIP: "10.0.0.2",
			model:    "gpt-3.5-turbo",
			tokens:   []string{"Beta", " answering"},
		},
		{
			podName:  "agent-gamma",
			sourceIP: "10.0.0.3",
			model:    testModelGPT4,
			tokens:   []string{"Gamma", " data", " output", " done"},
		},
	}

	// Launch all streams concurrently
	var wg sync.WaitGroup
	for _, ag := range agents {
		wg.Add(1)
		go func(agent struct {
			podName  string
			sourceIP string
			model    string
			tokens   []string
		}) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			stream, err := client.Process(ctx)
			if err != nil {
				t.Errorf("agent %s: failed to open stream: %v", agent.podName, err)
				return
			}

			sendOpenAIStreamingRequest(
				t, stream,
				agent.sourceIP, agent.model,
				agent.tokens,
			)
		}(ag)
	}

	wg.Wait()

	// Total expected events: sum over agents of (1 start + len(tokens) chunks + 1 complete)
	// Alpha: 1+3+1=5, Beta: 1+2+1=4, Gamma: 1+4+1=6 => 15 total
	events := collectEvents(sub, 15, 10*time.Second)

	// Group events by agent identity (pod name). Request IDs are server-generated
	// UUIDs so we can't predict them; grouping by identity is the correct approach.
	eventsByAgent := make(map[string][]eventbus.Event)
	for _, evt := range events {
		agentID := evt.Identity().ID
		if agentID == "" {
			agentID = evt.Identity().SourceIP
		}
		eventsByAgent[agentID] = append(eventsByAgent[agentID], evt)
	}

	// Verify each agent's events
	for _, ag := range agents {
		agentEvents, ok := eventsByAgent[ag.podName]
		if !ok {
			t.Errorf("no events found for agent %s", ag.podName)
			continue
		}

		var starts, chunks, completes int
		for _, evt := range agentEvents {
			// Verify all events carry correct agent identity (resolved via PodCache)
			agentInfo := evt.Identity()
			if agentInfo.ID != ag.podName {
				t.Errorf("agent %s: event Identity.ID = %q, want %q", ag.podName, agentInfo.ID, ag.podName)
			}

			switch evt.EventType() {
			case eventbus.EventTypeLLMRequestStart:
				starts++
			case eventbus.EventTypeLLMTokenChunk:
				chunks++
			case eventbus.EventTypeLLMRequestComplete:
				completes++
			}
		}

		if starts != 1 {
			t.Errorf("agent %s: expected 1 LLMRequestStart, got %d", ag.podName, starts)
		}
		if chunks != len(ag.tokens) {
			t.Errorf("agent %s: expected %d LLMTokenChunk events, got %d", ag.podName, len(ag.tokens), chunks)
		}
		if completes != 1 {
			t.Errorf("agent %s: expected 1 LLMRequestComplete, got %d", ag.podName, completes)
		}
	}
}
