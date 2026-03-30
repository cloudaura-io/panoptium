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
	"io"
	"net"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
)

// startTestServer creates and starts a test gRPC server with the given ExtProcServer,
// returning a client and cleanup function.
func startTestServer(t *testing.T, srv *ExtProcServer) (extprocv3.ExternalProcessorClient, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(grpcServer, srv)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			// Server stopped, expected during cleanup
		}
	}()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		grpcServer.Stop()
		t.Fatalf("failed to dial: %v", err)
	}

	client := extprocv3.NewExternalProcessorClient(conn)

	cleanup := func() {
		conn.Close()
		grpcServer.Stop()
	}

	return client, cleanup
}

// makeHeaderMap creates a HeaderMap proto from key-value pairs.
func makeHeaderMap(kvs ...string) *corev3.HeaderMap {
	if len(kvs)%2 != 0 {
		panic("makeHeaderMap requires even number of arguments")
	}

	headers := make([]*corev3.HeaderValue, 0, len(kvs)/2)
	for i := 0; i < len(kvs); i += 2 {
		headers = append(headers, &corev3.HeaderValue{
			Key:   kvs[i],
			Value: kvs[i+1],
		})
	}

	return &corev3.HeaderMap{Headers: headers}
}

// makeOpenAIRequestBody creates a JSON request body for an OpenAI chat completion.
func makeOpenAIRequestBody(model string, stream bool) []byte {
	body := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": "Hello, what is Go?"},
		},
		"stream": stream,
	}
	data, _ := json.Marshal(body)
	return data
}

// makeOpenAISSEChunk creates an SSE-formatted OpenAI streaming chunk.
func makeOpenAISSEChunk(content string) []byte {
	chunk := map[string]interface{}{
		"id": "chatcmpl-test",
		"choices": []map[string]interface{}{
			{
				"delta": map[string]string{
					"content": content,
				},
				"finish_reason": nil,
			},
		},
	}
	data, _ := json.Marshal(chunk)
	return []byte(fmt.Sprintf("data: %s\n\n", data))
}

// makeOpenAISSEDone creates the [DONE] SSE sentinel.
func makeOpenAISSEDone() []byte {
	return []byte("data: [DONE]\n\n")
}

// makeAnthropicRequestBody creates a JSON request body for an Anthropic messages API call.
func makeAnthropicRequestBody(model string, stream bool) []byte {
	body := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": "Tell me about Kubernetes"},
		},
		"stream":     stream,
		"max_tokens": 1024,
	}
	data, _ := json.Marshal(body)
	return data
}

// setupTestComponents creates all the common test infrastructure.
func setupTestComponents(t *testing.T) (*eventbus.SimpleBus, *observer.ObserverRegistry, *identity.Resolver, *ExtProcServer) {
	t.Helper()

	bus := eventbus.NewSimpleBus()
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

	podCache := identity.NewPodCache()
	resolver := identity.NewResolver(podCache)

	srv := NewExtProcServer(registry, resolver, bus)

	return bus, registry, resolver, srv
}

// TestProcess_BidirectionalStream verifies the ExtProc server handles
// a full bidirectional stream lifecycle: request headers, request body,
// response headers, response body chunks, and end-of-stream.
func TestProcess_BidirectionalStream(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// 1. Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-panoptium-agent-id", "agent-test",
					"x-panoptium-client-ip", "10.0.0.1",
					"x-panoptium-auth-type", "jwt",
					"x-panoptium-request-id", "req-stream-1",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	// Receive response for request headers
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response for request headers: %v", err)
	}
	if resp.GetRequestHeaders() == nil {
		t.Fatal("expected RequestHeaders response, got something else")
	}

	// 2. Send request body
	reqBody := makeOpenAIRequestBody("gpt-4", true)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        reqBody,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}

	// Receive response for request body
	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response for request body: %v", err)
	}
	if resp.GetRequestBody() == nil {
		t.Fatal("expected RequestBody response, got something else")
	}

	// 3. Send response headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "text/event-stream",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}

	// Receive response for response headers
	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response for response headers: %v", err)
	}
	if resp.GetResponseHeaders() == nil {
		t.Fatal("expected ResponseHeaders response, got something else")
	}

	// 4. Send response body chunks
	chunks := []string{"Hello", " world", "!"}
	for i, content := range chunks {
		err = stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        makeOpenAISSEChunk(content),
					EndOfStream: i == len(chunks)-1,
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to send response body chunk %d: %v", i, err)
		}

		resp, err = stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive response for body chunk %d: %v", i, err)
		}
		if resp.GetResponseBody() == nil {
			t.Fatalf("expected ResponseBody response for chunk %d, got something else", i)
		}
	}

	// Close the send side
	err = stream.CloseSend()
	if err != nil {
		t.Fatalf("failed to close send: %v", err)
	}

	// Drain events from bus
	var events []eventbus.Event
	timeout := time.After(2 * time.Second)
	for {
		select {
		case evt, ok := <-sub.Events():
			if !ok {
				goto done
			}
			events = append(events, evt)
		case <-timeout:
			goto done
		}
	}
done:

	// Verify we got LLMRequestStart event
	var foundStart bool
	for _, evt := range events {
		if evt.EventType() == eventbus.EventTypeLLMRequestStart {
			foundStart = true
			if evt.RequestID() != "req-stream-1" {
				t.Errorf("LLMRequestStart RequestID = %q, want %q", evt.RequestID(), "req-stream-1")
			}
		}
	}
	if !foundStart {
		t.Error("expected LLMRequestStart event, but none found")
	}

	// Verify we got token chunk events
	var tokenChunks int
	for _, evt := range events {
		if evt.EventType() == eventbus.EventTypeLLMTokenChunk {
			tokenChunks++
		}
	}
	if tokenChunks != 3 {
		t.Errorf("expected 3 LLMTokenChunk events, got %d", tokenChunks)
	}

	// Verify we got completion event
	var foundComplete bool
	for _, evt := range events {
		if evt.EventType() == eventbus.EventTypeLLMRequestComplete {
			foundComplete = true
			completeEvt, ok := evt.(*eventbus.LLMRequestCompleteEvent)
			if !ok {
				t.Error("LLMRequestComplete event is not *LLMRequestCompleteEvent")
				continue
			}
			if completeEvt.OutputTokens != 3 {
				t.Errorf("OutputTokens = %d, want 3", completeEvt.OutputTokens)
			}
		}
	}
	if !foundComplete {
		t.Error("expected LLMRequestComplete event, but none found")
	}
}

// TestProcess_RequestHeaderExtraction verifies that request headers are correctly
// extracted and delegated to the ObserverRegistry for observer selection.
func TestProcess_RequestHeaderExtraction(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers for OpenAI
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-panoptium-agent-id", "test-agent",
					"x-panoptium-auth-type", "jwt",
					"x-panoptium-request-id", "req-header-test",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	// Receive response
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}
	if resp.GetRequestHeaders() == nil {
		t.Fatal("expected RequestHeaders response")
	}

	// Send request body
	reqBody := makeOpenAIRequestBody("gpt-4", true)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        reqBody,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}

	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Close and check event
	stream.CloseSend()

	select {
	case evt := <-sub.Events():
		startEvt, ok := evt.(*eventbus.LLMRequestStartEvent)
		if !ok {
			t.Fatal("expected *LLMRequestStartEvent")
		}
		if startEvt.Protocol() != eventbus.ProtocolLLM {
			t.Errorf("Protocol = %q, want %q", startEvt.Protocol(), eventbus.ProtocolLLM)
		}
		if startEvt.Provider() != eventbus.ProviderOpenAI {
			t.Errorf("Provider = %q, want %q", startEvt.Provider(), eventbus.ProviderOpenAI)
		}
		if startEvt.Model != "gpt-4" {
			t.Errorf("Model = %q, want %q", startEvt.Model, "gpt-4")
		}
		if !startEvt.Stream {
			t.Error("Stream = false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for LLMRequestStart event")
	}
}

// TestProcess_AgentIdentityExtraction verifies that agent identity is correctly
// resolved via PodCache lookup from X-Forwarded-For header and included in
// all emitted events.
func TestProcess_AgentIdentityExtraction(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	registry := observer.NewObserverRegistry()

	llmObs := llm.NewLLMObserver(bus)
	registry.Register(llmObs, observer.ObserverConfig{
		Name:     "llm",
		Priority: 100,
	})

	podCache := identity.NewPodCache()
	podCache.Set("10.0.1.5", identity.PodInfo{
		Name:      "agent-pod-xyz",
		Namespace: "ai-workloads",
		UID:       "uid-xyz",
		Labels:    map[string]string{"app": "analyzer"},
	})
	resolver := identity.NewResolver(podCache)

	srv := NewExtProcServer(registry, resolver, bus)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	tests := []struct {
		name           string
		sourceIP       string
		wantConfidence string
		wantID         string
		wantPodName    string
	}{
		{
			name:           "Enrolled pod gives high confidence",
			sourceIP:       "10.0.1.5",
			wantConfidence: eventbus.ConfidenceHigh,
			wantID:         "agent-pod-xyz",
			wantPodName:    "agent-pod-xyz",
		},
		{
			name:           "Unenrolled pod gives low confidence",
			sourceIP:       "10.0.2.99",
			wantConfidence: eventbus.ConfidenceLow,
			wantID:         "",
			wantPodName:    "",
		},
		{
			name:           "No source IP gives low confidence",
			sourceIP:       "",
			wantConfidence: eventbus.ConfidenceLow,
			wantID:         "",
			wantPodName:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			stream, err := client.Process(ctx)
			if err != nil {
				t.Fatalf("failed to open stream: %v", err)
			}

			reqID := "req-identity-" + tt.name
			headers := []string{
				":path", "/v1/chat/completions",
				":method", "POST",
				"host", "api.openai.com",
				"x-panoptium-request-id", reqID,
			}
			if tt.sourceIP != "" {
				headers = append(headers, "x-forwarded-for", tt.sourceIP)
			}
			err = stream.Send(&extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_RequestHeaders{
					RequestHeaders: &extprocv3.HttpHeaders{
						Headers: makeHeaderMap(headers...),
					},
				},
			})
			if err != nil {
				t.Fatalf("failed to send request headers: %v", err)
			}

			_, err = stream.Recv()
			if err != nil {
				t.Fatalf("failed to receive response: %v", err)
			}

			// Send request body to trigger LLMRequestStart event
			err = stream.Send(&extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_RequestBody{
					RequestBody: &extprocv3.HttpBody{
						Body:        makeOpenAIRequestBody("gpt-4", false),
						EndOfStream: true,
					},
				},
			})
			if err != nil {
				t.Fatalf("failed to send request body: %v", err)
			}
			_, err = stream.Recv()
			if err != nil {
				t.Fatalf("failed to receive response: %v", err)
			}

			stream.CloseSend()

			// Check the emitted event's agent identity
			select {
			case evt := <-sub.Events():
				agentInfo := evt.Identity()
				if agentInfo.Confidence != tt.wantConfidence {
					t.Errorf("Confidence = %q, want %q", agentInfo.Confidence, tt.wantConfidence)
				}
				if agentInfo.ID != tt.wantID {
					t.Errorf("ID = %q, want %q", agentInfo.ID, tt.wantID)
				}
				if agentInfo.PodName != tt.wantPodName {
					t.Errorf("PodName = %q, want %q", agentInfo.PodName, tt.wantPodName)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for event")
			}

			// Drain remaining events from this stream
			drainTimeout := time.After(500 * time.Millisecond)
			for {
				select {
				case <-sub.Events():
				case <-drainTimeout:
					goto nextTest
				}
			}
		nextTest:
		})
	}
}

// TestProcess_StreamedRequestBodyAssembly verifies that streamed request body
// chunks are correctly assembled and parsed.
func TestProcess_StreamedRequestBodyAssembly(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-agent-id", "agent-body-test",
					"x-panoptium-auth-type", "jwt",
					"x-panoptium-request-id", "req-body-assembly",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Split the request body into multiple chunks
	fullBody := makeOpenAIRequestBody("gpt-4-turbo", true)
	mid := len(fullBody) / 2

	// First chunk (not end of stream)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        fullBody[:mid],
				EndOfStream: false,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send first body chunk: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response for first chunk: %v", err)
	}

	// Second chunk (end of stream)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        fullBody[mid:],
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send second body chunk: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response for second chunk: %v", err)
	}

	stream.CloseSend()

	// Verify the assembled body was correctly parsed
	select {
	case evt := <-sub.Events():
		startEvt, ok := evt.(*eventbus.LLMRequestStartEvent)
		if !ok {
			t.Fatal("expected *LLMRequestStartEvent")
		}
		if startEvt.Model != "gpt-4-turbo" {
			t.Errorf("Model = %q, want %q", startEvt.Model, "gpt-4-turbo")
		}
		if !startEvt.Stream {
			t.Error("Stream = false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for LLMRequestStart event")
	}
}

// TestProcess_StreamedResponseBody verifies that streamed response body chunks
// (raw HTTP frames containing SSE data) are correctly parsed and emitted as
// LLMTokenChunk events.
func TestProcess_StreamedResponseBody(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMTokenChunk)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-agent-id", "agent-response",
					"x-panoptium-auth-type", "jwt",
					"x-panoptium-request-id", "req-response-1",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send request body
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send response headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "text/event-stream",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send multiple response body chunks with SSE data
	tokens := []string{"Go", " is", " a", " programming", " language"}
	for i, token := range tokens {
		isLast := i == len(tokens)-1
		var body []byte
		if isLast {
			body = append(makeOpenAISSEChunk(token), makeOpenAISSEDone()...)
		} else {
			body = makeOpenAISSEChunk(token)
		}

		err = stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        body,
					EndOfStream: isLast,
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to send response body chunk %d: %v", i, err)
		}
		_, err = stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive response for chunk %d: %v", i, err)
		}
	}

	stream.CloseSend()

	// Collect token chunk events
	var tokenContents []string
	timeout := time.After(2 * time.Second)
	for {
		select {
		case evt, ok := <-sub.Events():
			if !ok {
				goto verify
			}
			chunkEvt, ok := evt.(*eventbus.LLMTokenChunkEvent)
			if !ok {
				continue
			}
			tokenContents = append(tokenContents, chunkEvt.Content)
			if len(tokenContents) >= len(tokens) {
				goto verify
			}
		case <-timeout:
			goto verify
		}
	}
verify:

	if len(tokenContents) != len(tokens) {
		t.Fatalf("expected %d token chunks, got %d: %v", len(tokens), len(tokenContents), tokenContents)
	}

	for i, want := range tokens {
		if tokenContents[i] != want {
			t.Errorf("token[%d] = %q, want %q", i, tokenContents[i], want)
		}
	}
}

// TestProcess_PassiveMode verifies that all ProcessingResponse messages
// returned by the server have no header mutations, body responses echo
// data verbatim via BodyMutation (passive echo), and header responses
// remain empty.
func TestProcess_PassiveMode(t *testing.T) {
	_, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Test request headers response is empty (no mutations)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-passive",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Verify request headers response has no mutations
	headersResp := resp.GetRequestHeaders()
	if headersResp == nil {
		t.Fatal("expected RequestHeaders response")
	}
	if headersResp.GetResponse() != nil {
		commonResp := headersResp.GetResponse()
		if commonResp.GetHeaderMutation() != nil {
			t.Error("expected no header mutations in passive mode")
		}
		if commonResp.GetBodyMutation() != nil {
			t.Error("expected no body mutations in passive mode")
		}
	}

	// Test request body response echoes body verbatim (passive echo)
	reqBody := makeOpenAIRequestBody("gpt-4", true)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        reqBody,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	bodyResp := resp.GetRequestBody()
	if bodyResp == nil {
		t.Fatal("expected RequestBody response")
	}
	// In passive echo mode, body is echoed via BodyMutation (no content modification)
	commonResp := bodyResp.GetResponse()
	if commonResp == nil {
		t.Fatal("expected CommonResponse with BodyMutation for body echo")
	}
	if commonResp.GetHeaderMutation() != nil {
		t.Error("expected no header mutations in passive mode for body")
	}
	if commonResp.GetBodyMutation() == nil {
		t.Fatal("expected BodyMutation for body echo, got nil")
	}
	// Verify StreamedResponse variant is used (required by AgentGateway streaming mode)
	reqStreamedResp := commonResp.GetBodyMutation().GetStreamedResponse()
	if reqStreamedResp == nil {
		t.Fatal("expected BodyMutation_StreamedResponse for body echo, got different variant")
	}
	if string(reqStreamedResp.GetBody()) != string(reqBody) {
		t.Error("expected body to be echoed verbatim via StreamedResponse")
	}

	// Test response headers response is empty
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "text/event-stream",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	respHeaders := resp.GetResponseHeaders()
	if respHeaders == nil {
		t.Fatal("expected ResponseHeaders response")
	}
	if respHeaders.GetResponse() != nil {
		respCommon := respHeaders.GetResponse()
		if respCommon.GetHeaderMutation() != nil {
			t.Error("expected no header mutations in passive mode for response headers")
		}
	}

	// Test response body echoes body verbatim (passive echo)
	sseChunk := makeOpenAISSEChunk("test")
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        sseChunk,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response body: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	respBody := resp.GetResponseBody()
	if respBody == nil {
		t.Fatal("expected ResponseBody response")
	}
	// In passive echo mode, response body is echoed via BodyMutation
	respCommon := respBody.GetResponse()
	if respCommon == nil {
		t.Fatal("expected CommonResponse with BodyMutation for response body echo")
	}
	if respCommon.GetBodyMutation() == nil {
		t.Fatal("expected BodyMutation for response body echo, got nil")
	}
	// Verify StreamedResponse variant is used (required by AgentGateway streaming mode)
	respStreamedResp := respCommon.GetBodyMutation().GetStreamedResponse()
	if respStreamedResp == nil {
		t.Fatal("expected BodyMutation_StreamedResponse for response body echo, got different variant")
	}
	if string(respStreamedResp.GetBody()) != string(sseChunk) {
		t.Error("expected response body to be echoed verbatim via StreamedResponse")
	}

	// Verify no dynamic metadata or mode override
	if resp.GetDynamicMetadata() != nil {
		t.Error("expected no dynamic metadata in passive mode")
	}
	if resp.GetModeOverride() != nil {
		t.Error("expected no mode override in passive mode")
	}

	stream.CloseSend()
}

// TestProcess_EndOfStreamComplete verifies that when the stream ends,
// an LLMRequestComplete event is emitted with correct aggregated metrics
// and the correct agent identity (resolved via PodCache).
func TestProcess_EndOfStreamComplete(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	registry := observer.NewObserverRegistry()
	llmObs := llm.NewLLMObserver(bus)
	registry.Register(llmObs, observer.ObserverConfig{
		Name:     "llm",
		Priority: 100,
	})
	podCache := identity.NewPodCache()
	podCache.Set("10.0.0.99", identity.PodInfo{
		Name:      "agent-complete-test",
		Namespace: "default",
	})
	resolver := identity.NewResolver(podCache)
	srv := NewExtProcServer(registry, resolver, bus)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestComplete)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Full request lifecycle with K8s-native identity via X-Forwarded-For
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-forwarded-for", "10.0.0.99",
					"x-panoptium-request-id", "req-complete-1",
				),
			},
		},
	})
	stream.Recv()

	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	stream.Recv()

	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(":status", "200", "content-type", "text/event-stream"),
			},
		},
	})
	stream.Recv()

	// Send 5 token chunks
	for i := 0; i < 5; i++ {
		isLast := i == 4
		var body []byte
		if isLast {
			body = append(makeOpenAISSEChunk(fmt.Sprintf("token%d", i)), makeOpenAISSEDone()...)
		} else {
			body = makeOpenAISSEChunk(fmt.Sprintf("token%d", i))
		}
		stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        body,
					EndOfStream: isLast,
				},
			},
		})
		stream.Recv()
	}

	stream.CloseSend()

	// Wait for the complete event
	select {
	case evt := <-sub.Events():
		completeEvt, ok := evt.(*eventbus.LLMRequestCompleteEvent)
		if !ok {
			t.Fatal("expected *LLMRequestCompleteEvent")
		}
		if completeEvt.OutputTokens != 5 {
			t.Errorf("OutputTokens = %d, want 5", completeEvt.OutputTokens)
		}
		if completeEvt.Duration <= 0 {
			t.Error("Duration should be positive")
		}
		if completeEvt.RequestID() != "req-complete-1" {
			t.Errorf("RequestID = %q, want %q", completeEvt.RequestID(), "req-complete-1")
		}
		// Verify agent identity is present
		agentInfo := completeEvt.Identity()
		if agentInfo.ID != "agent-complete-test" {
			t.Errorf("AgentIdentity.ID = %q, want %q", agentInfo.ID, "agent-complete-test")
		}
		if agentInfo.Confidence != eventbus.ConfidenceHigh {
			t.Errorf("AgentIdentity.Confidence = %q, want %q", agentInfo.Confidence, eventbus.ConfidenceHigh)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for LLMRequestComplete event")
	}
}

// TestProcess_ConcurrentStreams verifies that multiple simultaneous
// bidirectional streams from different agents are handled independently,
// with correct agent attribution for each stream.
func TestProcess_ConcurrentStreams(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	registry := observer.NewObserverRegistry()
	llmObs := llm.NewLLMObserver(bus)
	registry.Register(llmObs, observer.ObserverConfig{
		Name:     "llm",
		Priority: 100,
	})
	podCache := identity.NewPodCache()

	numStreams := 5
	// Pre-populate PodCache with entries for each concurrent agent
	for i := 0; i < numStreams; i++ {
		ip := fmt.Sprintf("10.0.10.%d", i)
		podCache.Set(ip, identity.PodInfo{
			Name:      fmt.Sprintf("agent-%d", i),
			Namespace: "default",
		})
	}

	resolver := identity.NewResolver(podCache)
	srv := NewExtProcServer(registry, resolver, bus)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestComplete)
	defer bus.Unsubscribe(sub)

	var wg sync.WaitGroup
	wg.Add(numStreams)

	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			stream, err := client.Process(ctx)
			if err != nil {
				t.Errorf("stream %d: failed to open: %v", idx, err)
				return
			}

			sourceIP := fmt.Sprintf("10.0.10.%d", idx)
			reqID := fmt.Sprintf("req-concurrent-%d", idx)

			// Request headers with X-Forwarded-For for PodCache identity resolution
			err = stream.Send(&extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_RequestHeaders{
					RequestHeaders: &extprocv3.HttpHeaders{
						Headers: makeHeaderMap(
							":path", "/v1/chat/completions",
							":method", "POST",
							"host", "api.openai.com",
							"x-forwarded-for", sourceIP,
							"x-panoptium-request-id", reqID,
						),
					},
				},
			})
			if err != nil {
				t.Errorf("stream %d: send headers: %v", idx, err)
				return
			}
			if _, err := stream.Recv(); err != nil {
				t.Errorf("stream %d: recv headers: %v", idx, err)
				return
			}

			// Request body
			err = stream.Send(&extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_RequestBody{
					RequestBody: &extprocv3.HttpBody{
						Body:        makeOpenAIRequestBody("gpt-4", true),
						EndOfStream: true,
					},
				},
			})
			if err != nil {
				t.Errorf("stream %d: send body: %v", idx, err)
				return
			}
			if _, err := stream.Recv(); err != nil {
				t.Errorf("stream %d: recv body: %v", idx, err)
				return
			}

			// Response headers
			err = stream.Send(&extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &extprocv3.HttpHeaders{
						Headers: makeHeaderMap(":status", "200", "content-type", "text/event-stream"),
					},
				},
			})
			if err != nil {
				t.Errorf("stream %d: send resp headers: %v", idx, err)
				return
			}
			if _, err := stream.Recv(); err != nil {
				t.Errorf("stream %d: recv resp headers: %v", idx, err)
				return
			}

			// Response body with tokens
			tokenCount := idx + 1 // vary tokens per stream
			for j := 0; j < tokenCount; j++ {
				isLast := j == tokenCount-1
				var body []byte
				if isLast {
					body = append(makeOpenAISSEChunk(fmt.Sprintf("tok%d", j)), makeOpenAISSEDone()...)
				} else {
					body = makeOpenAISSEChunk(fmt.Sprintf("tok%d", j))
				}
				err = stream.Send(&extprocv3.ProcessingRequest{
					Request: &extprocv3.ProcessingRequest_ResponseBody{
						ResponseBody: &extprocv3.HttpBody{
							Body:        body,
							EndOfStream: isLast,
						},
					},
				})
				if err != nil {
					t.Errorf("stream %d: send response chunk %d: %v", idx, j, err)
					return
				}
				if _, err := stream.Recv(); err != nil {
					t.Errorf("stream %d: recv response chunk %d: %v", idx, j, err)
					return
				}
			}

			stream.CloseSend()
		}(i)
	}

	wg.Wait()

	// Collect all completion events
	completeEvents := make(map[string]*eventbus.LLMRequestCompleteEvent)
	timeout := time.After(5 * time.Second)
	for len(completeEvents) < numStreams {
		select {
		case evt := <-sub.Events():
			completeEvt, ok := evt.(*eventbus.LLMRequestCompleteEvent)
			if !ok {
				continue
			}
			completeEvents[completeEvt.RequestID()] = completeEvt
		case <-timeout:
			t.Fatalf("timed out waiting for completion events, got %d of %d", len(completeEvents), numStreams)
		}
	}

	// Verify each stream produced the correct event
	for i := 0; i < numStreams; i++ {
		reqID := fmt.Sprintf("req-concurrent-%d", i)
		evt, ok := completeEvents[reqID]
		if !ok {
			t.Errorf("missing completion event for %s", reqID)
			continue
		}

		expectedTokens := i + 1
		if evt.OutputTokens != expectedTokens {
			t.Errorf("stream %d: OutputTokens = %d, want %d", i, evt.OutputTokens, expectedTokens)
		}

		wantAgent := fmt.Sprintf("agent-%d", i)
		if evt.Identity().ID != wantAgent {
			t.Errorf("stream %d: AgentID = %q, want %q", i, evt.Identity().ID, wantAgent)
		}
	}
}

// TestProcess_MetricsComputation verifies that per-request metrics (TTFT,
// tokens per second, total tokens) are correctly computed.
func TestProcess_MetricsComputation(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestComplete)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Request headers
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-agent-id", "agent-metrics",
					"x-panoptium-auth-type", "jwt",
					"x-panoptium-request-id", "req-metrics-1",
				),
			},
		},
	})
	stream.Recv()

	// Request body
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	stream.Recv()

	// Response headers
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(":status", "200", "content-type", "text/event-stream"),
			},
		},
	})
	stream.Recv()

	// Send 3 tokens with small delays to make TTFT measurable
	for i := 0; i < 3; i++ {
		isLast := i == 2
		var body []byte
		if isLast {
			body = append(makeOpenAISSEChunk(fmt.Sprintf("w%d", i)), makeOpenAISSEDone()...)
		} else {
			body = makeOpenAISSEChunk(fmt.Sprintf("w%d", i))
		}
		stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        body,
					EndOfStream: isLast,
				},
			},
		})
		stream.Recv()
	}

	stream.CloseSend()

	select {
	case evt := <-sub.Events():
		completeEvt, ok := evt.(*eventbus.LLMRequestCompleteEvent)
		if !ok {
			t.Fatal("expected *LLMRequestCompleteEvent")
		}

		if completeEvt.OutputTokens != 3 {
			t.Errorf("OutputTokens = %d, want 3", completeEvt.OutputTokens)
		}

		// TTFT should be non-negative (it represents time from request start to first token)
		if completeEvt.TTFT < 0 {
			t.Errorf("TTFT = %v, should be non-negative", completeEvt.TTFT)
		}

		// Duration should be positive
		if completeEvt.Duration <= 0 {
			t.Errorf("Duration = %v, should be positive", completeEvt.Duration)
		}

		// TokensPerSec should be positive
		if completeEvt.TokensPerSec <= 0 {
			t.Errorf("TokensPerSec = %f, should be positive", completeEvt.TokensPerSec)
		}

	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for LLMRequestComplete event")
	}
}

// TestProcess_UnknownObserver verifies that when no observer can handle
// the request (unknown path/host), the server logs and passes through
// without failing.
func TestProcess_UnknownObserver(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers with an unknown path
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/unknown/api/endpoint",
					":method", "POST",
					"host", "unknown.example.com",
					"x-panoptium-request-id", "req-unknown",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	// The server should still respond (not error)
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("server should not error for unknown observer: %v", err)
	}
	if resp.GetRequestHeaders() == nil {
		t.Fatal("expected RequestHeaders response even for unknown observer")
	}

	// Send request body — should still succeed
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        []byte(`{"some": "data"}`),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("server should not error for unknown observer body: %v", err)
	}
	if resp.GetRequestBody() == nil {
		t.Fatal("expected RequestBody response even for unknown observer")
	}

	// Send response headers — should still succeed
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(":status", "200"),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("server should not error for unknown observer response headers: %v", err)
	}
	if resp.GetResponseHeaders() == nil {
		t.Fatal("expected ResponseHeaders response even for unknown observer")
	}

	// Send response body — should still succeed
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        []byte(`some response`),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response body: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("server should not error for unknown observer response body: %v", err)
	}
	if resp.GetResponseBody() == nil {
		t.Fatal("expected ResponseBody response even for unknown observer")
	}

	stream.CloseSend()

	// No events should be emitted for unknown observers
	select {
	case evt := <-sub.Events():
		t.Errorf("no events should be emitted for unknown observer, got: %s", evt.EventType())
	case <-time.After(500 * time.Millisecond):
		// Expected: no events
	}
}

// TestProcess_MultiEventSSEFrame verifies that when a single HTTP frame
// contains multiple SSE events, they are all correctly parsed and emitted.
func TestProcess_MultiEventSSEFrame(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMTokenChunk)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Request headers
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-multi-sse",
				),
			},
		},
	})
	stream.Recv()

	// Request body
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	stream.Recv()

	// Response headers
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(":status", "200", "content-type", "text/event-stream"),
			},
		},
	})
	stream.Recv()

	// Send a single frame with multiple SSE events
	multiFrame := append(
		append(makeOpenAISSEChunk("multi"), makeOpenAISSEChunk("event")...),
		makeOpenAISSEChunk("frame")...,
	)

	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        multiFrame,
				EndOfStream: true,
			},
		},
	})
	stream.Recv()

	stream.CloseSend()

	// Verify all three token events were emitted
	var tokens []string
	timeout := time.After(2 * time.Second)
	for len(tokens) < 3 {
		select {
		case evt := <-sub.Events():
			chunkEvt, ok := evt.(*eventbus.LLMTokenChunkEvent)
			if ok {
				tokens = append(tokens, chunkEvt.Content)
			}
		case <-timeout:
			t.Fatalf("timed out: expected 3 tokens from multi-event frame, got %d: %v", len(tokens), tokens)
		}
	}

	expected := []string{"multi", "event", "frame"}
	for i, want := range expected {
		if tokens[i] != want {
			t.Errorf("token[%d] = %q, want %q", i, tokens[i], want)
		}
	}
}

// TestProcess_StreamEndTriggersFinalize verifies that when the client closes
// the stream (io.EOF), the Finalize method is called on the observer.
func TestProcess_StreamEndTriggersFinalize(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestComplete)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Minimal stream with request headers, body, and one response chunk
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-finalize",
				),
			},
		},
	})
	stream.Recv()

	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	stream.Recv()

	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(":status", "200", "content-type", "text/event-stream"),
			},
		},
	})
	stream.Recv()

	// Send a single chunk with end of stream
	body := append(makeOpenAISSEChunk("final"), makeOpenAISSEDone()...)
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        body,
				EndOfStream: true,
			},
		},
	})
	stream.Recv()

	// Explicitly close the stream
	stream.CloseSend()

	// Wait to receive a trailing EOF
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}

	// Verify Finalize was called (LLMRequestComplete emitted)
	select {
	case evt := <-sub.Events():
		completeEvt, ok := evt.(*eventbus.LLMRequestCompleteEvent)
		if !ok {
			t.Fatal("expected *LLMRequestCompleteEvent")
		}
		if completeEvt.OutputTokens != 1 {
			t.Errorf("OutputTokens = %d, want 1", completeEvt.OutputTokens)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for LLMRequestComplete — Finalize may not have been called")
	}
}

// TestProcess_AnthropicProvider verifies that the ExtProc server correctly
// handles Anthropic-format requests and streaming responses.
func TestProcess_AnthropicProvider(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Request headers for Anthropic
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/messages",
					":method", "POST",
					"host", "api.anthropic.com",
					"x-panoptium-agent-id", "agent-anthropic",
					"x-panoptium-auth-type", "jwt",
					"x-panoptium-request-id", "req-anthropic-1",
				),
			},
		},
	})
	stream.Recv()

	// Request body
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeAnthropicRequestBody("claude-3-opus-20240229", true),
				EndOfStream: true,
			},
		},
	})
	stream.Recv()

	// Response headers
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(":status", "200", "content-type", "text/event-stream"),
			},
		},
	})
	stream.Recv()

	// Anthropic SSE events
	anthropicChunk := func(text string) []byte {
		data := fmt.Sprintf(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"%s"}}`, text)
		return []byte(fmt.Sprintf("event: content_block_delta\ndata: %s\n\n", data))
	}

	anthropicStop := func() []byte {
		return []byte("event: message_stop\ndata: {}\n\n")
	}

	// Send Anthropic streaming chunks
	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        anthropicChunk("Kubernetes"),
				EndOfStream: false,
			},
		},
	})
	stream.Recv()

	stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        append(anthropicChunk(" is"), anthropicStop()...),
				EndOfStream: true,
			},
		},
	})
	stream.Recv()

	stream.CloseSend()

	// Collect events
	var events []eventbus.Event
	timeout := time.After(2 * time.Second)
	for {
		select {
		case evt, ok := <-sub.Events():
			if !ok {
				goto checkAnthropicEvents
			}
			events = append(events, evt)
		case <-timeout:
			goto checkAnthropicEvents
		}
	}
checkAnthropicEvents:

	// Check for start event
	var foundAnthropicStart bool
	for _, evt := range events {
		if evt.EventType() == eventbus.EventTypeLLMRequestStart {
			foundAnthropicStart = true
			if evt.Provider() != eventbus.ProviderAnthropic {
				t.Errorf("Provider = %q, want %q", evt.Provider(), eventbus.ProviderAnthropic)
			}
		}
	}
	if !foundAnthropicStart {
		t.Error("expected LLMRequestStart event for Anthropic")
	}

	// Check token chunks
	var anthropicTokenCount int
	for _, evt := range events {
		if evt.EventType() == eventbus.EventTypeLLMTokenChunk {
			anthropicTokenCount++
		}
	}
	if anthropicTokenCount != 2 {
		t.Errorf("expected 2 Anthropic token chunks, got %d", anthropicTokenCount)
	}
}

// TestProcess_RequestBodyEchoesViaBodyMutation verifies that handleRequestBody
// returns a BodyResponse with BodyMutation containing the echoed body data,
// rather than an empty BodyResponse.
func TestProcess_RequestBodyEchoesViaBodyMutation(t *testing.T) {
	_, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-body-echo-1",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send request body
	reqBody := makeOpenAIRequestBody("gpt-4", true)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        reqBody,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Verify the response echoes body data via BodyMutation
	bodyResp := resp.GetRequestBody()
	if bodyResp == nil {
		t.Fatal("expected RequestBody response")
	}

	commonResp := bodyResp.GetResponse()
	if commonResp == nil {
		t.Fatal("expected CommonResponse in RequestBody response, got nil (empty BodyResponse)")
	}

	bodyMutation := commonResp.GetBodyMutation()
	if bodyMutation == nil {
		t.Fatal("expected BodyMutation in CommonResponse, got nil")
	}

	echoedBody := bodyMutation.GetStreamedResponse().GetBody()
	if len(echoedBody) == 0 {
		t.Fatal("expected echoed body data, got empty")
	}

	if string(echoedBody) != string(reqBody) {
		t.Errorf("echoed body = %q, want %q", string(echoedBody), string(reqBody))
	}

	stream.CloseSend()
}

// TestProcess_ResponseBodyEchoesViaBodyMutation verifies that handleResponseBody
// returns a BodyResponse with BodyMutation containing the echoed body data,
// rather than an empty BodyResponse.
func TestProcess_ResponseBodyEchoesViaBodyMutation(t *testing.T) {
	_, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-resp-echo-1",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send request body
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send response headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "text/event-stream",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send response body
	sseChunk := makeOpenAISSEChunk("Hello")
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        sseChunk,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response body: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Verify the response echoes body data via BodyMutation
	bodyResp := resp.GetResponseBody()
	if bodyResp == nil {
		t.Fatal("expected ResponseBody response")
	}

	commonResp := bodyResp.GetResponse()
	if commonResp == nil {
		t.Fatal("expected CommonResponse in ResponseBody response, got nil (empty BodyResponse)")
	}

	bodyMutation := commonResp.GetBodyMutation()
	if bodyMutation == nil {
		t.Fatal("expected BodyMutation in CommonResponse, got nil")
	}

	echoedBody := bodyMutation.GetStreamedResponse().GetBody()
	if len(echoedBody) == 0 {
		t.Fatal("expected echoed body data, got empty")
	}

	if string(echoedBody) != string(sseChunk) {
		t.Errorf("echoed body = %q, want %q", string(echoedBody), string(sseChunk))
	}

	stream.CloseSend()
}

// TestProcess_MultiChunkRequestBodyEchoesIndividually verifies that when the
// request body arrives in multiple chunks, each chunk is echoed individually
// via BodyMutation.
func TestProcess_MultiChunkRequestBodyEchoesIndividually(t *testing.T) {
	_, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-multi-chunk-1",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Split body into 3 chunks
	fullBody := makeOpenAIRequestBody("gpt-4", true)
	chunkSize := len(fullBody) / 3
	chunks := [][]byte{
		fullBody[:chunkSize],
		fullBody[chunkSize : 2*chunkSize],
		fullBody[2*chunkSize:],
	}

	for i, chunk := range chunks {
		isLast := i == len(chunks)-1
		err = stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_RequestBody{
				RequestBody: &extprocv3.HttpBody{
					Body:        chunk,
					EndOfStream: isLast,
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to send request body chunk %d: %v", i, err)
		}

		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive response for chunk %d: %v", i, err)
		}

		bodyResp := resp.GetRequestBody()
		if bodyResp == nil {
			t.Fatalf("chunk %d: expected RequestBody response", i)
		}

		commonResp := bodyResp.GetResponse()
		if commonResp == nil {
			t.Fatalf("chunk %d: expected CommonResponse in RequestBody response, got nil (empty BodyResponse)", i)
		}

		bodyMutation := commonResp.GetBodyMutation()
		if bodyMutation == nil {
			t.Fatalf("chunk %d: expected BodyMutation in CommonResponse, got nil", i)
		}

		echoedBody := bodyMutation.GetStreamedResponse().GetBody()
		if string(echoedBody) != string(chunk) {
			t.Errorf("chunk %d: echoed body = %q, want %q", i, string(echoedBody), string(chunk))
		}
	}

	stream.CloseSend()
}

// TestProcess_MultiChunkResponseBodyEchoesWithTokenParsing verifies that
// each response body chunk (containing SSE frames) is both echoed via
// BodyMutation and parsed for token observation.
func TestProcess_MultiChunkResponseBodyEchoesWithTokenParsing(t *testing.T) {
	bus, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMTokenChunk)
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-agent-id", "agent-echo-tokens",
					"x-panoptium-auth-type", "jwt",
					"x-panoptium-request-id", "req-echo-tokens-1",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send request body
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send response headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "text/event-stream",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send multiple response body chunks with SSE data
	sseChunks := [][]byte{
		makeOpenAISSEChunk("Hello"),
		makeOpenAISSEChunk(" world"),
		append(makeOpenAISSEChunk("!"), makeOpenAISSEDone()...),
	}

	for i, chunk := range sseChunks {
		isLast := i == len(sseChunks)-1
		err = stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        chunk,
					EndOfStream: isLast,
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to send response body chunk %d: %v", i, err)
		}

		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive response for chunk %d: %v", i, err)
		}

		// Verify body is echoed
		bodyResp := resp.GetResponseBody()
		if bodyResp == nil {
			t.Fatalf("chunk %d: expected ResponseBody response", i)
		}

		commonResp := bodyResp.GetResponse()
		if commonResp == nil {
			t.Fatalf("chunk %d: expected CommonResponse in ResponseBody response, got nil (empty BodyResponse)", i)
		}

		bodyMutation := commonResp.GetBodyMutation()
		if bodyMutation == nil {
			t.Fatalf("chunk %d: expected BodyMutation in CommonResponse, got nil", i)
		}

		echoedBody := bodyMutation.GetStreamedResponse().GetBody()
		if string(echoedBody) != string(chunk) {
			t.Errorf("chunk %d: echoed body = %q, want %q", i, string(echoedBody), string(chunk))
		}
	}

	stream.CloseSend()

	// Verify token parsing still works alongside echoing
	var tokenCount int
	timeout := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-sub.Events():
			if !ok {
				goto verifyTokens
			}
			tokenCount++
			if tokenCount >= 3 {
				goto verifyTokens
			}
		case <-timeout:
			goto verifyTokens
		}
	}
verifyTokens:
	if tokenCount != 3 {
		t.Errorf("expected 3 token chunk events, got %d", tokenCount)
	}
}

// TestProcess_EndOfStreamOnlyOnFinalChunk verifies that when multiple
// response body chunks are echoed, the BodyMutation data includes
// each chunk's body correctly, and the echo behavior is consistent
// regardless of the EndOfStream flag value in the request.
func TestProcess_EndOfStreamOnlyOnFinalChunk(t *testing.T) {
	_, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-eos-test-1",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send request body
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send response headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "text/event-stream",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}
	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send 3 response body chunks: first two with EndOfStream=false, last with EndOfStream=true
	type chunkTest struct {
		body        []byte
		endOfStream bool
	}
	chunks := []chunkTest{
		{body: makeOpenAISSEChunk("token1"), endOfStream: false},
		{body: makeOpenAISSEChunk("token2"), endOfStream: false},
		{body: append(makeOpenAISSEChunk("token3"), makeOpenAISSEDone()...), endOfStream: true},
	}

	for i, ct := range chunks {
		err = stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        ct.body,
					EndOfStream: ct.endOfStream,
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to send response body chunk %d: %v", i, err)
		}

		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("failed to receive response for chunk %d: %v", i, err)
		}

		bodyResp := resp.GetResponseBody()
		if bodyResp == nil {
			t.Fatalf("chunk %d: expected ResponseBody response", i)
		}

		commonResp := bodyResp.GetResponse()
		if commonResp == nil {
			t.Fatalf("chunk %d: expected CommonResponse, got nil (empty BodyResponse)", i)
		}

		bodyMutation := commonResp.GetBodyMutation()
		if bodyMutation == nil {
			t.Fatalf("chunk %d: expected BodyMutation, got nil", i)
		}

		// Each chunk should echo the exact body data sent
		echoedBody := bodyMutation.GetStreamedResponse().GetBody()
		if string(echoedBody) != string(ct.body) {
			t.Errorf("chunk %d: echoed body does not match sent body", i)
		}
	}

	stream.CloseSend()
}

// TestRequestBody_UsesStreamedResponse verifies that handleRequestBody returns
// BodyMutation_StreamedResponse (not BodyMutation_Body) with the correct body
// data and EndOfStream flag. AgentGateway requires this variant for streaming mode.
func TestRequestBody_UsesStreamedResponse(t *testing.T) {
	_, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-streamed-variant",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive headers response: %v", err)
	}

	// Send request body with EndOfStream=true
	reqBody := makeOpenAIRequestBody("gpt-4", true)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        reqBody,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive body response: %v", err)
	}

	bodyResp := resp.GetRequestBody()
	if bodyResp == nil {
		t.Fatal("expected RequestBody response")
	}

	commonResp := bodyResp.GetResponse()
	if commonResp == nil {
		t.Fatal("expected CommonResponse")
	}

	bodyMutation := commonResp.GetBodyMutation()
	if bodyMutation == nil {
		t.Fatal("expected BodyMutation, got nil")
	}

	// Assert the mutation is BodyMutation_StreamedResponse, NOT BodyMutation_Body
	streamedResp, ok := bodyMutation.Mutation.(*extprocv3.BodyMutation_StreamedResponse)
	if !ok {
		t.Fatalf("expected BodyMutation_StreamedResponse, got %T", bodyMutation.Mutation)
	}

	if streamedResp.StreamedResponse == nil {
		t.Fatal("StreamedResponse is nil")
	}

	if string(streamedResp.StreamedResponse.Body) != string(reqBody) {
		t.Error("StreamedResponse.Body does not match sent body")
	}

	if !streamedResp.StreamedResponse.EndOfStream {
		t.Error("StreamedResponse.EndOfStream should be true for final chunk")
	}

	stream.CloseSend()
}

// TestResponseBody_UsesStreamedResponse verifies that handleResponseBody returns
// BodyMutation_StreamedResponse (not BodyMutation_Body) with the correct body
// data and EndOfStream flag. AgentGateway requires this variant for streaming mode.
func TestResponseBody_UsesStreamedResponse(t *testing.T) {
	_, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-resp-streamed",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive headers response: %v", err)
	}

	// Send request body
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive body response: %v", err)
	}

	// Send response headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "text/event-stream",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive response headers response: %v", err)
	}

	// Send response body with EndOfStream=true
	sseChunk := makeOpenAISSEChunk("hello")
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        sseChunk,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response body: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response body response: %v", err)
	}

	respBody := resp.GetResponseBody()
	if respBody == nil {
		t.Fatal("expected ResponseBody response")
	}

	commonResp := respBody.GetResponse()
	if commonResp == nil {
		t.Fatal("expected CommonResponse")
	}

	bodyMutation := commonResp.GetBodyMutation()
	if bodyMutation == nil {
		t.Fatal("expected BodyMutation, got nil")
	}

	// Assert the mutation is BodyMutation_StreamedResponse, NOT BodyMutation_Body
	streamedResp, ok := bodyMutation.Mutation.(*extprocv3.BodyMutation_StreamedResponse)
	if !ok {
		t.Fatalf("expected BodyMutation_StreamedResponse, got %T", bodyMutation.Mutation)
	}

	if streamedResp.StreamedResponse == nil {
		t.Fatal("StreamedResponse is nil")
	}

	if string(streamedResp.StreamedResponse.Body) != string(sseChunk) {
		t.Error("StreamedResponse.Body does not match sent body")
	}

	if !streamedResp.StreamedResponse.EndOfStream {
		t.Error("StreamedResponse.EndOfStream should be true for final chunk")
	}

	stream.CloseSend()
}

// TestMultiChunkBody_StreamedResponseEndOfStream verifies that multi-chunk body
// processing uses StreamedBodyResponse with correct EndOfStream flags: false for
// intermediate chunks and true for the final chunk.
func TestMultiChunkBody_StreamedResponseEndOfStream(t *testing.T) {
	_, _, _, srv := setupTestComponents(t)
	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-panoptium-request-id", "req-multichunk-streamed",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive headers response: %v", err)
	}

	// Send request body
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        makeOpenAIRequestBody("gpt-4", true),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request body: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive body response: %v", err)
	}

	// Send response headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "text/event-stream",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive response headers response: %v", err)
	}

	// Send multiple response body chunks
	chunks := []struct {
		body        []byte
		endOfStream bool
	}{
		{makeOpenAISSEChunk("Hello"), false},
		{makeOpenAISSEChunk(" world"), false},
		{makeOpenAISSEChunk("!"), true},
	}

	for i, chunk := range chunks {
		err = stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        chunk.body,
					EndOfStream: chunk.endOfStream,
				},
			},
		})
		if err != nil {
			t.Fatalf("chunk %d: failed to send: %v", i, err)
		}

		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("chunk %d: failed to receive: %v", i, err)
		}

		respBody := resp.GetResponseBody()
		if respBody == nil {
			t.Fatalf("chunk %d: expected ResponseBody response", i)
		}

		commonResp := respBody.GetResponse()
		if commonResp == nil {
			t.Fatalf("chunk %d: expected CommonResponse", i)
		}

		bodyMutation := commonResp.GetBodyMutation()
		if bodyMutation == nil {
			t.Fatalf("chunk %d: expected BodyMutation", i)
		}

		// Assert BodyMutation_StreamedResponse for each chunk
		streamedResp, ok := bodyMutation.Mutation.(*extprocv3.BodyMutation_StreamedResponse)
		if !ok {
			t.Fatalf("chunk %d: expected BodyMutation_StreamedResponse, got %T", i, bodyMutation.Mutation)
		}

		if streamedResp.StreamedResponse == nil {
			t.Fatalf("chunk %d: StreamedResponse is nil", i)
		}

		if string(streamedResp.StreamedResponse.Body) != string(chunk.body) {
			t.Errorf("chunk %d: body mismatch", i)
		}

		if streamedResp.StreamedResponse.EndOfStream != chunk.endOfStream {
			t.Errorf("chunk %d: EndOfStream = %v, want %v", i, streamedResp.StreamedResponse.EndOfStream, chunk.endOfStream)
		}
	}

	stream.CloseSend()
}
