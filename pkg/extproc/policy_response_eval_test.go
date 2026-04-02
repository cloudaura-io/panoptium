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
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/policy"
)

// conditionalPolicyEvaluator returns different decisions based on the event category.
type conditionalPolicyEvaluator struct {
	requestDecision  *policy.Decision
	responseDecision *policy.Decision
	lastEvent        *policy.PolicyEvent
}

func (m *conditionalPolicyEvaluator) Evaluate(event *policy.PolicyEvent) (*policy.Decision, error) {
	m.lastEvent = event
	if event.Subcategory == "llm_response" || event.Subcategory == "llm_response_chunk" {
		return m.responseDecision, nil
	}
	return m.requestDecision, nil
}

// sendFullRequestSequence sends request headers and body to establish a stream
// and returns after receiving the body response. This helper sets up the stream
// so response-path tests can send response headers/body.
func sendFullRequestSequence(t *testing.T, stream extprocv3.ExternalProcessor_ProcessClient) {
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
					"x-forwarded-for", "10.0.0.50",
					"x-request-id", "req-resp-eval-1",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request headers: %v", err)
	}

	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive header response: %v", err)
	}

	// Send request body
	reqBody := makeOpenAIRequestBody("gpt-4", false)
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
		t.Fatalf("failed to receive body response: %v", err)
	}

	// Send response headers
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":status", "200",
					"content-type", "application/json",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send response headers: %v", err)
	}

	_, err = stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response headers response: %v", err)
	}
}

// TestResponsePolicyEvaluation_BufferedBody verifies that policy evaluation
// is invoked on response body chunks with a PolicyEvent containing response
// context (subcategory=llm_response, body content).
func TestResponsePolicyEvaluation_BufferedBody(t *testing.T) {
	evaluator := &conditionalPolicyEvaluator{
		requestDecision:  policy.DefaultAllowDecision(),
		responseDecision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.50", identity.PodInfo{
		Name:      "resp-eval-pod",
		Namespace: "default",
		UID:       "uid-resp-1",
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	sendFullRequestSequence(t, stream)

	// Send response body
	responseBody := []byte(`{"choices":[{"message":{"content":"Hello, Go is a programming language."}}]}`)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        responseBody,
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

	// Verify the evaluator was called with response context
	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked for response body")
	}
	if evaluator.lastEvent.Subcategory != "llm_response" && evaluator.lastEvent.Subcategory != "llm_response_chunk" {
		t.Errorf("expected response subcategory, got %q", evaluator.lastEvent.Subcategory)
	}

	// Should pass through (allow)
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through for allowed response")
	}
}

// TestResponsePolicyEvaluation_SSEStreamChunks verifies that each SSE chunk
// in a streaming response is individually evaluated against response-path rules.
func TestResponsePolicyEvaluation_SSEStreamChunks(t *testing.T) {
	evaluator := &conditionalPolicyEvaluator{
		requestDecision:  policy.DefaultAllowDecision(),
		responseDecision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.50", identity.PodInfo{
		Name:      "sse-eval-pod",
		Namespace: "default",
		UID:       "uid-sse-1",
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	sendFullRequestSequence(t, stream)

	// Send first SSE chunk (not end of stream)
	chunk1 := []byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n")
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        chunk1,
				EndOfStream: false,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send SSE chunk 1: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive chunk 1 response: %v", err)
	}

	// Should pass through
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through for SSE chunk 1")
	}

	// Verify evaluator was called
	if evaluator.lastEvent == nil {
		t.Fatal("policy evaluator was not invoked for SSE chunk")
	}
}

// TestResponsePolicyEvaluation_MidStreamEnforcement verifies that when a
// response-path policy violation is detected mid-stream, the server returns
// an ImmediateResponse to terminate the stream.
func TestResponsePolicyEvaluation_MidStreamEnforcement(t *testing.T) {
	evaluator := &conditionalPolicyEvaluator{
		requestDecision: policy.DefaultAllowDecision(),
		responseDecision: &policy.Decision{
			Action: policy.CompiledAction{
				Type: v1alpha1.ActionTypeDeny,
				Parameters: map[string]string{
					"message":   "content policy violation detected in response",
					"signature": "PAN-SIG-0099",
				},
			},
			Matched:          true,
			MatchedRule:      "block-sensitive-output",
			MatchedRuleIndex: 0,
			PolicyName:       "output-policy",
			PolicyNamespace:  "default",
		},
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.50", identity.PodInfo{
		Name:      "midstream-pod",
		Namespace: "default",
		UID:       "uid-midstream-1",
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
	})

	sub := bus.Subscribe(eventbus.EventTypePolicyDecision)
	defer bus.Unsubscribe(sub)

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	sendFullRequestSequence(t, stream)

	// Send response body that triggers content policy violation
	responseBody := []byte(`{"choices":[{"message":{"content":"Here is sensitive data: SSN 123-45-6789"}}]}`)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        responseBody,
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

	// Should receive ImmediateResponse with 403 for mid-stream enforcement
	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse for mid-stream content policy violation")
	}
	if ir.Status.Code != 403 {
		t.Errorf("expected status 403, got %d", ir.Status.Code)
	}

	var body enforce.ErrorResponse
	if err := json.Unmarshal(ir.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	if body.Error != "policy_violation" {
		t.Errorf("expected error 'policy_violation', got %q", body.Error)
	}
	if body.Signature != "PAN-SIG-0099" {
		t.Errorf("expected signature 'PAN-SIG-0099', got %q", body.Signature)
	}

	// Verify policy.decision event was emitted
	select {
	case evt := <-sub.Events():
		if evt.EventType() != eventbus.EventTypePolicyDecision {
			t.Errorf("expected policy.decision event, got %q", evt.EventType())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for policy.decision event")
	}
}

// TestResponsePolicyEvaluation_PassThroughNoMatch verifies that when no
// response-path rules match, the response body passes through unchanged.
func TestResponsePolicyEvaluation_PassThroughNoMatch(t *testing.T) {
	evaluator := &conditionalPolicyEvaluator{
		requestDecision:  policy.DefaultAllowDecision(),
		responseDecision: policy.DefaultAllowDecision(),
	}
	bus, podCache, srv := setupPolicyEvalTestComponents(t, evaluator)
	defer bus.Close()

	podCache.Set("10.0.0.50", identity.PodInfo{
		Name:      "pass-resp-pod",
		Namespace: "default",
		UID:       "uid-pass-resp-1",
		Labels:    map[string]string{"panoptium.io/monitored": "true"},
	})

	client, cleanup := startTestServer(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	sendFullRequestSequence(t, stream)

	// Send response body
	responseBody := []byte(`{"choices":[{"message":{"content":"Safe response content"}}]}`)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        responseBody,
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

	// Should pass through (no ImmediateResponse)
	if resp.GetImmediateResponse() != nil {
		t.Fatal("expected pass-through for response with no matching rules")
	}

	// Verify the response body is echoed back via StreamedResponse
	rb := resp.GetResponseBody()
	if rb == nil {
		t.Fatal("expected ResponseBody in response")
	}
}
