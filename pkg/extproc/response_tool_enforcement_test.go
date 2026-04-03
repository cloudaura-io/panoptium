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

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
	"github.com/panoptium/panoptium/pkg/policy"
)

// responseToolEvaluator evaluates tool_call subcategory events from the
// response path. Returns deny for banned tools.
type responseToolEvaluator struct {
	denyTools map[string]bool
	events    []*policy.PolicyEvent
}

func (m *responseToolEvaluator) Evaluate(event *policy.PolicyEvent) (*policy.Decision, error) {
	m.events = append(m.events, event)

	toolName := event.GetStringField("toolName")
	if event.Subcategory == "tool_call" && toolName != "" && m.denyTools[toolName] {
		return &policy.Decision{
			Action: policy.CompiledAction{
				Type:       v1alpha1.ActionTypeDeny,
				Parameters: map[string]string{"message": "tool " + toolName + " denied in response"},
			},
			Matched:          true,
			MatchedRule:      "deny-response-" + toolName,
			MatchedRuleIndex: 0,
			PolicyName:       "response-tool-policy",
			PolicyNamespace:  "default",
		}, nil
	}
	return policy.DefaultAllowDecision(), nil
}

func (m *responseToolEvaluator) EvaluateAll(event *policy.PolicyEvent) (*policy.EvaluationResult, error) {
	d, err := m.Evaluate(event)
	if err != nil {
		return nil, err
	}
	result := &policy.EvaluationResult{}
	if d != nil && d.Matched {
		result.Decisions = []*policy.Decision{d}
	} else {
		result.DefaultAllow = true
	}
	return result, nil
}

func setupResponseToolTestComponents(t *testing.T, evaluator PolicyEvaluator) (*eventbus.SimpleBus, *identity.PodCache, *ExtProcServer) {
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

// makeToolCallResponseSSE builds an SSE response with a tool_call for the given tool name.
func makeToolCallResponseSSE(toolName string) []byte {
	chunk := map[string]interface{}{
		"id": "chatcmpl-test",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"delta": map[string]interface{}{
					"tool_calls": []map[string]interface{}{
						{
							"index": 0,
							"id":    "call_test_123",
							"type":  "function",
							"function": map[string]interface{}{
								"name":      toolName,
								"arguments": "",
							},
						},
					},
				},
				"finish_reason": nil,
			},
		},
	}
	data, _ := json.Marshal(chunk)
	return []byte(fmt.Sprintf("data: %s\n\n", data))
}

// makeFinishReasonSSE builds an SSE response with finish_reason "tool_calls".
func makeFinishReasonSSE() []byte {
	chunk := map[string]interface{}{
		"id": "chatcmpl-test",
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"delta":         map[string]interface{}{},
				"finish_reason": "tool_calls",
			},
		},
	}
	data, _ := json.Marshal(chunk)
	return []byte(fmt.Sprintf("data: %s\n\n", data))
}

// sendFullRequestAndGetResponseStream sends request headers + body, then
// response headers, returns the stream ready for response body chunks.
func sendFullRequestAndGetResponseStream(t *testing.T, stream extprocv3.ExternalProcessor_ProcessClient, toolNames []string) {
	t.Helper()

	// Send request headers
	err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"content-type", "application/json",
					"x-forwarded-for", "10.0.0.220",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	// Receive headers response
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive headers response: %v", err)
	}

	// Send request body with tools
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

	// Receive body response
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

	// Receive response headers response
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("failed to receive response headers response: %v", err)
	}
}

// TestResponseToolEnforcement_DenyReturns403 verifies that when a banned tool
// call is detected in the response stream, an ImmediateResponse with 403 is returned.
func TestResponseToolEnforcement_DenyReturns403(t *testing.T) {
	evaluator := &responseToolEvaluator{
		denyTools: map[string]bool{"bash": true},
	}
	bus, podCache, srv := setupResponseToolTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.220", identity.PodInfo{
		Name:      "resp-tool-pod",
		Namespace: "default",
		UID:       "uid-resp-1",
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

	sendFullRequestAndGetResponseStream(t, stream, []string{"bash", "read_file"})

	// Send response with tool_call for "bash" (banned)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        makeToolCallResponseSSE("bash"),
				EndOfStream: false,
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

	// Send finish_reason to complete
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        makeFinishReasonSSE(),
				EndOfStream: true,
			},
		},
	})
	if err != nil {
		// May fail if server already closed stream — that's OK
		t.Logf("send after enforcement may fail: %v", err)
	}

	// First response chunk passes through (name accumulated but tool not yet complete)
	// The enforcement should happen when finish_reason marks completion
	if resp.GetImmediateResponse() != nil {
		// If we got 403 on first chunk, that's valid too — tool name was complete
		ir := resp.GetImmediateResponse()
		if ir.Status.Code != 403 {
			t.Errorf("expected 403, got %d", ir.Status.Code)
		}
		return // Test passes
	}

	// If first chunk passed through, the enforcement should happen on the
	// finish_reason chunk
	resp2, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive second response: %v", err)
	}

	ir := resp2.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse 403 for banned tool_call in response")
	}
	if ir.Status.Code != 403 {
		t.Errorf("expected 403, got %d", ir.Status.Code)
	}
}

// TestResponseToolEnforcement_AllowedToolPassesThrough verifies that tool calls
// for allowed tools pass through normally.
func TestResponseToolEnforcement_AllowedToolPassesThrough(t *testing.T) {
	evaluator := &responseToolEvaluator{
		denyTools: map[string]bool{"bash": true},
	}
	bus, podCache, srv := setupResponseToolTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.220", identity.PodInfo{
		Name:      "resp-allow-pod",
		Namespace: "default",
		UID:       "uid-resp-2",
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
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        makeToolCallResponseSSE("read_file"),
				EndOfStream: false,
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

	// Should pass through — no ImmediateResponse
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through for allowed tool, got ImmediateResponse")
	}
	if resp.GetResponseBody() == nil {
		t.Fatal("expected ResponseBody response")
	}
}

// TestResponseToolEnforcement_AuditDoesNotBlock verifies that audit-mode
// deny on response tool calls does not block.
func TestResponseToolEnforcement_AuditDoesNotBlock(t *testing.T) {
	evaluator := &responseToolEvaluator{
		denyTools: map[string]bool{"bash": true},
	}
	bus, podCache, srv := setupResponseToolTestComponents(t, evaluator)
	defer bus.Close()

	// Set audit mode
	srv.SetEnforcementMode(enforce.ModeAudit)

	podCache.Set("10.0.0.220", identity.PodInfo{
		Name:      "resp-audit-pod",
		Namespace: "default",
		UID:       "uid-resp-3",
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

	sendFullRequestAndGetResponseStream(t, stream, []string{"bash"})

	// Send response with tool_call for "bash" (denied but audit mode)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        makeToolCallResponseSSE("bash"),
				EndOfStream: false,
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

	// Audit mode — should pass through
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through in audit mode, got ImmediateResponse")
	}
	if resp.GetResponseBody() == nil {
		t.Fatal("expected ResponseBody response")
	}
}
