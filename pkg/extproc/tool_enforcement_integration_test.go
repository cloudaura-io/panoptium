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
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
)

// setupIntegrationTestComponents creates test infrastructure for integration tests.
func setupIntegrationTestComponents(t *testing.T, evaluator PolicyEvaluator) (*eventbus.SimpleBus, *identity.PodCache, *ExtProcServer) {
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
	srv.SetEnforcementMode(enforce.ModeEnforcing)
	if evaluator != nil {
		srv.SetPolicyEvaluator(evaluator)
	}

	return bus, podCache, srv
}

// TestIntegration_RequestPath_StripOneOfThreeTools verifies the full ExtProc flow:
// request with 3 tools, 1 banned → forwarded body has 2 tools, request proceeds.
func TestIntegration_RequestPath_StripOneOfThreeTools(t *testing.T) {
	evaluator := &perToolMockEvaluator{
		denyTools: map[string]bool{"k8s_get_pod_logs": true},
	}
	bus, podCache, srv := setupIntegrationTestComponents(t, evaluator)
	defer bus.Close()

	// Subscribe to tool stripped events
	stripSub := bus.Subscribe(eventbus.EventTypeToolStripped)
	defer bus.Unsubscribe(stripSub)

	// Subscribe to policy decision events
	decisionSub := bus.Subscribe(eventbus.EventTypePolicyDecision)
	defer bus.Unsubscribe(decisionSub)

	podCache.Set("10.0.0.230", identity.PodInfo{
		Name:      "integration-pod",
		Namespace: "production",
		UID:       "uid-integ-1",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	body := makeOpenAIRequestBodyWithTools("gpt-4", true,
		[]string{"k8s_get_resources", "k8s_get_pod_logs", "k8s_apply"})

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.230",
	}, body)

	// Should NOT be blocked (tool stripping, not 403)
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through with tool stripping, got ImmediateResponse")
	}

	// Verify the forwarded body has exactly 2 tools
	bodyResp := resp.GetRequestBody()
	if bodyResp == nil {
		t.Fatal("expected RequestBody response")
	}
	streamedResp := bodyResp.GetResponse().GetBodyMutation().GetStreamedResponse()
	if streamedResp == nil {
		t.Fatal("expected StreamedResponse")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(streamedResp.Body, &parsed); err != nil {
		t.Fatalf("forwarded body is not valid JSON: %v", err)
	}

	tools, ok := parsed["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array in forwarded body")
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools after stripping, got %d", len(tools))
	}

	names := extractToolNamesFromParsed(t, tools)
	if contains(names, "k8s_get_pod_logs") {
		t.Error("expected k8s_get_pod_logs to be stripped")
	}
	if !contains(names, "k8s_get_resources") {
		t.Error("expected k8s_get_resources to be preserved")
	}
	if !contains(names, "k8s_apply") {
		t.Error("expected k8s_apply to be preserved")
	}

	// Verify ToolStrippedEvent was emitted
	select {
	case evt := <-stripSub.Events():
		stripped, ok := evt.(*eventbus.ToolStrippedEvent)
		if !ok {
			t.Fatalf("expected ToolStrippedEvent, got %T", evt)
		}
		if stripped.ToolName != "k8s_get_pod_logs" {
			t.Errorf("expected stripped tool 'k8s_get_pod_logs', got %q", stripped.ToolName)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ToolStrippedEvent")
	}

	// Verify policy.decision event was emitted
	select {
	case evt := <-decisionSub.Events():
		ee, ok := evt.(*eventbus.EnforcementEvent)
		if !ok {
			t.Fatalf("expected EnforcementEvent, got %T", evt)
		}
		if ee.Action != "deny" {
			t.Errorf("expected action 'deny', got %q", ee.Action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for policy.decision event")
	}
}

// TestIntegration_ResponsePath_BannedToolCall403 verifies the full ExtProc flow:
// response with tool_calls for a banned tool → 403 ImmediateResponse.
func TestIntegration_ResponsePath_BannedToolCall403(t *testing.T) {
	evaluator := &responseToolEvaluator{
		denyTools: map[string]bool{"bash": true},
	}
	bus, podCache, srv := setupIntegrationTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.231", identity.PodInfo{
		Name:      "resp-integ-pod",
		Namespace: "default",
		UID:       "uid-integ-2",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request through (no request-path deny for these tools)
	sendFullRequestAndGetResponseStream(t, stream, []string{"bash", "read_file"})

	// Send response with tool_call for "bash"
	toolCallSSE := makeToolCallResponseSSE("bash")
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        toolCallSSE,
				EndOfStream: false,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send tool call response: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Send finish_reason to complete tool calls
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        makeFinishReasonSSE(),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		// Expected: server may have already sent ImmediateResponse
		t.Logf("send after enforcement may fail: %v", err)
	}

	// Check for 403 on first or second response
	if ir := resp.GetImmediateResponse(); ir != nil {
		if ir.Status.Code != 403 {
			t.Errorf("expected 403, got %d", ir.Status.Code)
		}
		return
	}

	// Check second response
	resp2, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive second response: %v", err)
	}
	ir := resp2.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse 403 for banned response tool_call")
	}
	if ir.Status.Code != 403 {
		t.Errorf("expected 403, got %d", ir.Status.Code)
	}
}

// TestIntegration_ResponsePath_AllowedToolCallPassThrough verifies the full
// ExtProc flow: response with tool_calls for an allowed tool → normal pass-through.
func TestIntegration_ResponsePath_AllowedToolCallPassThrough(t *testing.T) {
	evaluator := &responseToolEvaluator{
		denyTools: map[string]bool{"bash": true},
	}
	bus, podCache, srv := setupIntegrationTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.232", identity.PodInfo{
		Name:      "allowed-integ-pod",
		Namespace: "default",
		UID:       "uid-integ-3",
		Labels:    map[string]string{"app": "agent"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	sendFullRequestAndGetResponseStream(t, stream, []string{"read_file"})

	// Send response with tool_call for "read_file" (allowed)
	toolCallSSE := makeToolCallResponseSSE("read_file")
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        toolCallSSE,
				EndOfStream: false,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send tool call response: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Should pass through
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through for allowed tool_call, got ImmediateResponse")
	}
	if resp.GetResponseBody() == nil {
		t.Fatal("expected ResponseBody for allowed tool_call")
	}

	// Send finish_reason + end of stream
	finishSSE := makeFinishReasonSSE()
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        finishSSE,
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send finish: %v", err)
	}

	resp2, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive finish response: %v", err)
	}

	// Should also pass through
	if resp2.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through on finish, got ImmediateResponse")
	}
}

// sendFullRequestAndGetResponseStream_WithIP sends request and response headers
// through the stream, ready for response body chunks. Uses the given IP.
func sendFullRequestAndGetResponseStream_WithIP(t *testing.T, stream extprocv3.ExternalProcessor_ProcessClient, toolNames []string, ip string) {
	t.Helper()

	err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-forwarded-for", ip,
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

	body := makeOpenAIRequestBodyWithTools("gpt-4", true, toolNames)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        body,
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
}

// Ensure makeToolCallResponseSSE and makeFinishReasonSSE are defined (they are
// already in response_tool_enforcement_test.go). We use _ to suppress unused
// warnings if the helpers are already available.
var _ = fmt.Sprintf
