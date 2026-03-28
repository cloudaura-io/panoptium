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

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
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
	agentID, clientIP, authType, requestID, model string,
	tokenContents []string,
) {
	t.Helper()

	// 1. Send request headers
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-panoptium-agent-id", agentID,
					"x-panoptium-client-ip", clientIP,
					"x-panoptium-auth-type", authType,
					"x-panoptium-request-id", requestID,
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

// TestIntegration_OpenAIStreamingWithJWTIdentity verifies the full end-to-end
// flow for an OpenAI streaming request with JWT-based agent identity:
// request headers with x-panoptium-agent-id → LLMRequestStart event,
// streaming SSE response chunks → LLMTokenChunk events in order,
// end-of-stream → LLMRequestComplete with metrics and agent identity.
func TestIntegration_OpenAIStreamingWithJWTIdentity(t *testing.T) {
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

	tokens := []string{"Hello", " from", " the", " AI", " assistant"}
	sendOpenAIStreamingRequest(t, stream, "agent-summarizer", "10.0.0.1", "jwt", "req-openai-1", "gpt-4", tokens)

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
	if start.RequestID() != "req-openai-1" {
		t.Errorf("LLMRequestStart.RequestID = %q, want %q", start.RequestID(), "req-openai-1")
	}
	if start.Protocol() != eventbus.ProtocolLLM {
		t.Errorf("LLMRequestStart.Protocol = %q, want %q", start.Protocol(), eventbus.ProtocolLLM)
	}
	if start.Provider() != eventbus.ProviderOpenAI {
		t.Errorf("LLMRequestStart.Provider = %q, want %q", start.Provider(), eventbus.ProviderOpenAI)
	}
	if start.Model != "gpt-4" {
		t.Errorf("LLMRequestStart.Model = %q, want %q", start.Model, "gpt-4")
	}
	if !start.Stream {
		t.Error("LLMRequestStart.Stream = false, want true")
	}

	// Verify agent identity on start event
	agentInfo := start.Identity()
	if agentInfo.ID != "agent-summarizer" {
		t.Errorf("AgentIdentity.ID = %q, want %q", agentInfo.ID, "agent-summarizer")
	}
	if agentInfo.AuthType != eventbus.AuthTypeJWT {
		t.Errorf("AgentIdentity.AuthType = %q, want %q", agentInfo.AuthType, eventbus.AuthTypeJWT)
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
		if chunk.RequestID() != "req-openai-1" {
			t.Errorf("LLMTokenChunk[%d].RequestID = %q, want %q", i, chunk.RequestID(), "req-openai-1")
		}
		if chunk.Provider() != eventbus.ProviderOpenAI {
			t.Errorf("LLMTokenChunk[%d].Provider = %q, want %q", i, chunk.Provider(), eventbus.ProviderOpenAI)
		}
		chunkIdentity := chunk.Identity()
		if chunkIdentity.ID != "agent-summarizer" {
			t.Errorf("LLMTokenChunk[%d].Identity.ID = %q, want %q", i, chunkIdentity.ID, "agent-summarizer")
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
	if complete.RequestID() != "req-openai-1" {
		t.Errorf("LLMRequestComplete.RequestID = %q, want %q", complete.RequestID(), "req-openai-1")
	}
	completeIdentity := complete.Identity()
	if completeIdentity.ID != "agent-summarizer" {
		t.Errorf("LLMRequestComplete.Identity.ID = %q, want %q", completeIdentity.ID, "agent-summarizer")
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
					"x-panoptium-agent-id", "agent-multi-sse",
					"x-panoptium-auth-type", "jwt",
					"x-panoptium-request-id", "req-multi-sse",
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
				Body:        makeOpenAIRequestBody("gpt-4", true),
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

	stream.CloseSend()

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
					"x-panoptium-agent-id", "agent-claude",
					"x-panoptium-auth-type", "jwt",
					"x-panoptium-request-id", "req-anthropic-1",
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

	stream.CloseSend()

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

// TestIntegration_SourceIPIdentityWithPodCache verifies that when an agent
// authenticates via source-ip, the pod IP cache is consulted to resolve the
// pod name, namespace, and labels into the AgentIdentity with medium confidence.
func TestIntegration_SourceIPIdentityWithPodCache(t *testing.T) {
	bus, podCache, client, cleanup := setupIntegrationComponents(t)
	defer cleanup()

	// Pre-populate the pod IP cache (simulating a Kubernetes Informer having
	// observed the pod)
	podCache.Set("10.0.5.42", identity.PodInfo{
		Name:           "agent-pod-abc",
		Namespace:      "ml-workloads",
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

	// Send request with source-ip auth type
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-agent-id", "pod:10.0.5.42",
					"x-panoptium-client-ip", "10.0.5.42",
					"x-panoptium-auth-type", "source-ip",
					"x-panoptium-request-id", "req-podcache-1",
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
				Body:        makeOpenAIRequestBody("gpt-4", false),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	stream.CloseSend()

	// Verify the event has medium confidence with resolved pod info
	select {
	case evt := <-sub.Events():
		agentInfo := evt.Identity()
		if agentInfo.Confidence != eventbus.ConfidenceMedium {
			t.Errorf("Confidence = %q, want %q", agentInfo.Confidence, eventbus.ConfidenceMedium)
		}
		if agentInfo.ID != "pod:10.0.5.42" {
			t.Errorf("ID = %q, want %q", agentInfo.ID, "pod:10.0.5.42")
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
		if agentInfo.AuthType != eventbus.AuthTypeSourceIP {
			t.Errorf("AuthType = %q, want %q", agentInfo.AuthType, eventbus.AuthTypeSourceIP)
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
				Body:        makeOpenAIRequestBody("gpt-4", false),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to recv: %v", err)
	}

	stream.CloseSend()

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
		if agentInfo.AuthType != "" {
			t.Errorf("AuthType = %q, want empty string", agentInfo.AuthType)
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
	bus, _, client, cleanup := setupIntegrationComponents(t)
	defer cleanup()

	// Subscribe to all events
	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	agents := []struct {
		agentID   string
		clientIP  string
		requestID string
		model     string
		tokens    []string
	}{
		{
			agentID:   "agent-alpha",
			clientIP:  "10.0.0.1",
			requestID: "req-alpha-1",
			model:     "gpt-4",
			tokens:    []string{"Alpha", " response", " here"},
		},
		{
			agentID:   "agent-beta",
			clientIP:  "10.0.0.2",
			requestID: "req-beta-1",
			model:     "gpt-3.5-turbo",
			tokens:    []string{"Beta", " answering"},
		},
		{
			agentID:   "agent-gamma",
			clientIP:  "10.0.0.3",
			requestID: "req-gamma-1",
			model:     "gpt-4",
			tokens:    []string{"Gamma", " data", " output", " done"},
		},
	}

	// Launch all streams concurrently
	var wg sync.WaitGroup
	for _, ag := range agents {
		wg.Add(1)
		go func(agent struct {
			agentID   string
			clientIP  string
			requestID string
			model     string
			tokens    []string
		}) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			stream, err := client.Process(ctx)
			if err != nil {
				t.Errorf("agent %s: failed to open stream: %v", agent.agentID, err)
				return
			}

			sendOpenAIStreamingRequest(
				t, stream,
				agent.agentID, agent.clientIP, "jwt", agent.requestID, agent.model,
				agent.tokens,
			)
		}(ag)
	}

	wg.Wait()

	// Total expected events: sum over agents of (1 start + len(tokens) chunks + 1 complete)
	// Alpha: 1+3+1=5, Beta: 1+2+1=4, Gamma: 1+4+1=6 => 15 total
	events := collectEvents(sub, 15, 10*time.Second)

	// Group events by request ID
	eventsByReqID := make(map[string][]eventbus.Event)
	for _, evt := range events {
		eventsByReqID[evt.RequestID()] = append(eventsByReqID[evt.RequestID()], evt)
	}

	// Verify each agent's events
	for _, ag := range agents {
		agentEvents, ok := eventsByReqID[ag.requestID]
		if !ok {
			t.Errorf("no events found for agent %s (requestID=%s)", ag.agentID, ag.requestID)
			continue
		}

		var starts, chunks, completes int
		for _, evt := range agentEvents {
			// Verify all events carry correct agent identity
			agentInfo := evt.Identity()
			if agentInfo.ID != ag.agentID {
				t.Errorf("agent %s: event Identity.ID = %q, want %q", ag.agentID, agentInfo.ID, ag.agentID)
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
			t.Errorf("agent %s: expected 1 LLMRequestStart, got %d", ag.agentID, starts)
		}
		if chunks != len(ag.tokens) {
			t.Errorf("agent %s: expected %d LLMTokenChunk events, got %d", ag.agentID, len(ag.tokens), chunks)
		}
		if completes != 1 {
			t.Errorf("agent %s: expected 1 LLMRequestComplete, got %d", ag.agentID, completes)
		}
	}
}
