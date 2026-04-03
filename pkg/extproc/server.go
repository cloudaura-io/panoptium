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

// Package extproc implements an Envoy External Processing (ExtProc) gRPC server
// that observes LLM token streams flowing through AgentGateway and enforces
// policy decisions including deny, throttle, modify, and suspend actions.
package extproc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/google/uuid"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/policy"
)

// PolicyEvaluator is the interface used by the ExtProc server to evaluate
// request events against compiled policies. It decouples the ExtProc server
// from the policy engine implementation, enabling testability via mock
// evaluators and supporting composition resolvers in production.
type PolicyEvaluator interface {
	// Evaluate evaluates a PolicyEvent against the active policy set and
	// returns a Decision indicating the action to take.
	Evaluate(event *policy.PolicyEvent) (*policy.Decision, error)
}

// ExtProcServer implements the Envoy ExternalProcessor gRPC service.
// It observes LLM traffic flowing through AgentGateway, resolves agent
// identity via PodCache, evaluates policy rules, and enforces decisions
// (deny, throttle, modify, suspend) based on the configured enforcement mode.
type ExtProcServer struct {
	extprocv3.UnimplementedExternalProcessorServer

	registry        *observer.ObserverRegistry
	resolver        *identity.Resolver
	bus             eventbus.EventBus
	enforcementMode enforce.EnforcementMode
	failureMode     enforce.FailureMode
	policyEvaluator PolicyEvaluator
}

// NewExtProcServer creates a new ExtProcServer with the given dependencies.
// The default enforcement mode is audit (observe-only, no blocking).
// The default failure mode is fail-open (pass traffic on engine errors).
func NewExtProcServer(registry *observer.ObserverRegistry, resolver *identity.Resolver, bus eventbus.EventBus) *ExtProcServer {
	return &ExtProcServer{
		registry:        registry,
		resolver:        resolver,
		bus:             bus,
		enforcementMode: enforce.ModeAudit,
		failureMode:     enforce.FailOpen,
	}
}

// SetEnforcementMode configures the enforcement behavior for this server.
// In ModeEnforcing, policy decisions are actively enforced (deny, throttle).
// In ModeAudit, all traffic passes through with warning events emitted.
// Network admission (blocking unknown sources) is delegated to Kubernetes
// NetworkPolicy, not ExtProc.
func (s *ExtProcServer) SetEnforcementMode(mode enforce.EnforcementMode) {
	s.enforcementMode = mode
}

// SetFailureMode configures the failure behavior when the policy engine
// is unavailable or returns an error. In FailOpen mode, traffic passes
// through with warning events. In FailClosed mode, 503 is returned.
func (s *ExtProcServer) SetFailureMode(mode enforce.FailureMode) {
	s.failureMode = mode
}

// SetPolicyEvaluator configures the policy evaluator used for request-path
// and response-path policy enforcement. When nil, no policy evaluation is
// performed and all traffic passes through (observation-only mode).
func (s *ExtProcServer) SetPolicyEvaluator(evaluator PolicyEvaluator) {
	s.policyEvaluator = evaluator
}

// streamState tracks the per-stream state for an active ExtProc bidirectional stream.
type streamState struct {
	// requestID is the server-generated correlation ID for this stream.
	// Generated once at the start of Process() using uuid.New().String().
	// Never read from client headers (trust inversion prevention).
	requestID string

	// obs is the selected ProtocolObserver for this stream (nil if no match).
	obs observer.ProtocolObserver

	// streamCtx is the observer's StreamContext, tracking request lifecycle.
	streamCtx *observer.StreamContext

	// obsCtx is the ObserverContext built from request headers.
	obsCtx *observer.ObserverContext

	// requestBody accumulates streamed request body chunks.
	requestBody []byte

	// requestBodyComplete indicates the request body has been fully received.
	requestBodyComplete bool

	// requestBodyModified indicates the request body was modified (e.g., tools stripped).
	// When true, intermediate chunks are echoed as empty and the full modified body
	// is sent on the final chunk.
	requestBodyModified bool

	// startEventEmitted indicates the LLMRequestStart event has been emitted.
	startEventEmitted bool

	// evaluatedToolCallCount tracks how many response tool calls have already
	// been evaluated against policy, to avoid re-evaluating the same tool call.
	evaluatedToolCallCount int
}

// Process implements the ExternalProcessor bidirectional streaming RPC.
// For each ProcessingRequest received, it performs passive observation
// (extracting headers, body, tokens) and returns an empty ProcessingResponse
// (no mutations). When the stream ends, it finalizes metrics via the observer.
func (s *ExtProcServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	logger := log.FromContext(stream.Context()).WithName("extproc")

	RecordStreamStart()
	defer RecordStreamEnd()

	// Generate a server-side request ID per gRPC stream. Each stream
	// corresponds to exactly one HTTP request, making the stream boundary
	// a natural and non-spoofable correlation unit. Client-provided
	// headers (x-request-id, etc.) are never used for correlation.
	state := &streamState{
		requestID: uuid.New().String(),
	}

	for {
		req, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Stream ended normally — finalize if we have an active observer
				s.finalizeStream(stream.Context(), state)
				return nil
			}
			// Stream error — finalize with the error
			s.finalizeStream(stream.Context(), state)
			return err
		}

		var resp *extprocv3.ProcessingResponse

		switch r := req.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			resp = s.handleRequestHeaders(stream.Context(), state, r.RequestHeaders, logger)

		case *extprocv3.ProcessingRequest_RequestBody:
			resp = s.handleRequestBody(stream.Context(), state, r.RequestBody, logger)

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			resp = s.handleResponseHeaders(state, r.ResponseHeaders)

		case *extprocv3.ProcessingRequest_ResponseBody:
			resp = s.handleResponseBody(stream.Context(), state, r.ResponseBody, logger)

		case *extprocv3.ProcessingRequest_RequestTrailers:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestTrailers{
					RequestTrailers: &extprocv3.TrailersResponse{},
				},
			}

		case *extprocv3.ProcessingRequest_ResponseTrailers:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseTrailers{
					ResponseTrailers: &extprocv3.TrailersResponse{},
				},
			}

		default:
			logger.V(1).Info("unknown request type, ignoring")
			continue
		}

		if err := stream.Send(resp); err != nil {
			s.finalizeStream(stream.Context(), state)
			return err
		}
	}
}

// handleRequestHeaders processes incoming request headers, selects an observer,
// resolves agent identity via PodCache, and builds the initial ObserverContext.
// Unknown source IPs proceed with degraded identity; network admission is
// delegated to Kubernetes NetworkPolicy.
func (s *ExtProcServer) handleRequestHeaders(ctx context.Context, state *streamState, headers *extprocv3.HttpHeaders, logger interface{ Info(string, ...interface{}) }) *extprocv3.ProcessingResponse {
	httpHeaders := envoyHeadersToHTTP(headers.GetHeaders())

	path := httpHeaders.Get(":path")
	method := httpHeaders.Get(":method")
	// Request ID is exclusively server-generated per gRPC stream — never
	// read from client headers. Client-provided x-request-id is spoofable
	// (same trust boundary as identity headers per ADR-003).
	requestID := state.requestID

	// Resolve agent identity from source IP via PodCache.
	// Identity is derived exclusively from X-Forwarded-For -> PodCache lookup.
	agentIdentity := s.resolver.Resolve(httpHeaders)

	// PodCache miss: log a warning and proceed with degraded identity.
	// Network admission (blocking unknown sources) is delegated to Kubernetes
	// NetworkPolicy, which enforces at the kernel/CNI level. ExtProc focuses
	// exclusively on semantic/protocol-level enforcement (tool authorization,
	// rate limiting, threat signatures, content inspection).
	if agentIdentity.Confidence == eventbus.ConfidenceLow && agentIdentity.SourceIP != "" {
		if l, ok := logger.(interface {
			Info(string, ...interface{})
		}); ok {
			l.Info("PodCache miss, proceeding with degraded identity",
				"sourceIP", agentIdentity.SourceIP, "requestID", requestID)
		}
	}

	// Build observer context
	state.obsCtx = &observer.ObserverContext{
		Headers:   httpHeaders,
		Path:      path,
		Method:    method,
		RequestID: requestID,
	}

	// Select observer from registry
	obs, err := s.registry.SelectObserver(ctx, state.obsCtx)
	if err != nil {
		if errors.Is(err, observer.ErrNoMatchingObserver) {
			// No observer matches — log and pass through
			if l, ok := logger.(interface {
				Info(string, ...interface{})
			}); ok {
				l.Info("no matching observer for request", "path", path, "requestID", requestID)
			}
		}
		// No observer — all subsequent calls will be pass-through
		state.obs = nil
	} else {
		state.obs = obs
	}

	// Store agent identity for later use
	state.streamCtx = &observer.StreamContext{
		RequestID:     requestID,
		AgentIdentity: agentIdentity,
		EventBus:      s.bus,
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{},
		},
		ModeOverride: &extprocfilterv3.ProcessingMode{
			RequestBodyMode:  extprocfilterv3.ProcessingMode_BUFFERED,
			ResponseBodyMode: extprocfilterv3.ProcessingMode_STREAMED,
		},
	}
}

// handleRequestBody processes incoming request body chunks. It accumulates
// streamed body data and, when the body is complete, delegates to the observer
// for parsing and emits the LLMRequestStart event.
func (s *ExtProcServer) handleRequestBody(ctx context.Context, state *streamState, body *extprocv3.HttpBody, logger interface{ Info(string, ...interface{}) }) *extprocv3.ProcessingResponse {
	// Accumulate body chunks
	state.requestBody = append(state.requestBody, body.GetBody()...)

	if body.GetEndOfStream() {
		state.requestBodyComplete = true
	}

	// When body is complete and we have an observer, process the request
	if state.requestBodyComplete && state.obs != nil && !state.startEventEmitted {
		state.obsCtx.Body = state.requestBody

		streamCtx, err := state.obs.ProcessRequestStream(ctx, state.obsCtx)
		if err != nil {
			if l, ok := logger.(interface {
				Info(string, ...interface{})
			}); ok {
				l.Info("error processing request stream", "error", err)
			}
			RecordParseError(state.streamCtx.Provider, "request")
		}

		if streamCtx != nil {
			// Preserve the agent identity from the headers phase
			streamCtx.AgentIdentity = state.streamCtx.AgentIdentity
			streamCtx.RequestID = state.streamCtx.RequestID
			state.streamCtx = streamCtx

			// Record the request metric
			RecordRequest(streamCtx.Provider)

			// Emit LLMRequestStart event
			s.emitRequestStartEvent(state)
			state.startEventEmitted = true
		}

		// Policy evaluation: evaluate request against active policies
		// This runs after body parsing so we have model, provider, and tool names.
		if s.policyEvaluator != nil && state.streamCtx != nil {
			resp := s.evaluateRequestPolicy(state, logger)
			if resp != nil {
				return resp
			}
		}
	}

	// Echo body back via StreamedBodyResponse — AgentGateway operates in
	// streaming mode and rejects BodyMutation_Body variant.
	//
	// AgentGateway concatenates Body bytes from ALL chunk responses into the
	// final request body. Two cases:
	//
	// 1. Body NOT modified (no tool stripping): echo each raw chunk as-is.
	// 2. Body WAS modified (tools stripped): send empty bytes for intermediate
	//    chunks, then send the full modified body on the final chunk.
	var echoBody []byte
	eos := body.GetEndOfStream()

	if state.requestBodyModified {
		// Body was modified by tool stripping — hold intermediate chunks,
		// send full modified body only on the final chunk.
		if eos {
			echoBody = state.requestBody
		}
		// else: empty body for intermediate chunks
	} else {
		// Body unmodified — echo each raw chunk as-is.
		echoBody = body.GetBody()
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{
					BodyMutation: &extprocv3.BodyMutation{
						Mutation: &extprocv3.BodyMutation_StreamedResponse{
							StreamedResponse: &extprocv3.StreamedBodyResponse{
								Body:        echoBody,
								EndOfStream: eos,
							},
						},
					},
				},
			},
		},
	}
}

// handleResponseHeaders processes response headers. Currently used only for
// logging/observation — no mutations are applied.
func (s *ExtProcServer) handleResponseHeaders(_ *streamState, _ *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{},
		},
	}
}

// handleResponseBody processes response body chunks. Each chunk is delegated
// to the observer for SSE/token parsing.
func (s *ExtProcServer) handleResponseBody(ctx context.Context, state *streamState, body *extprocv3.HttpBody, logger interface{ Info(string, ...interface{}) }) *extprocv3.ProcessingResponse {
	if state.obs != nil && state.streamCtx != nil {
		prevTokenCount := state.streamCtx.TokenCount
		if err := state.obs.ProcessResponseStream(ctx, state.streamCtx, body.GetBody()); err != nil {
			if l, ok := logger.(interface {
				Info(string, ...interface{})
			}); ok {
				l.Info("error processing response stream", "error", err)
			}
			RecordParseError(state.streamCtx.Provider, "response")
		}
		// Record any new tokens observed in this chunk
		newTokens := state.streamCtx.TokenCount - prevTokenCount
		if newTokens > 0 {
			RecordTokensObserved(state.streamCtx.Provider, newTokens)
		}
	}

	// Response-path tool_call enforcement: check for newly completed tool calls
	// in the response stream and evaluate against policy.
	if s.policyEvaluator != nil && state.streamCtx != nil {
		resp := s.evaluateResponseToolCalls(ctx, state, logger)
		if resp != nil {
			return resp
		}
	}

	// Response-path policy evaluation: evaluate each response chunk
	if s.policyEvaluator != nil && state.streamCtx != nil {
		subcategory := "llm_response_chunk"
		if body.GetEndOfStream() {
			subcategory = "llm_response"
		}

		policyEvent := &policy.PolicyEvent{
			Category:    "protocol",
			Subcategory: subcategory,
			Timestamp:   time.Now(),
			Namespace:   state.streamCtx.AgentIdentity.Namespace,
			PodName:     state.streamCtx.AgentIdentity.PodName,
			PodLabels:   state.streamCtx.AgentIdentity.Labels,
			Fields: map[string]interface{}{
				"responseBody": string(body.GetBody()),
				"endOfStream":  body.GetEndOfStream(),
				"requestID":    state.streamCtx.RequestID,
			},
		}

		decision, err := s.policyEvaluator.Evaluate(policyEvent)
		if err != nil {
			resp := s.handleEvaluationError(err, state.streamCtx.AgentIdentity, state.streamCtx.RequestID, logger)
			if resp != nil {
				s.finalizeStream(ctx, state)
				return resp
			}
			// fail-open: fall through to pass-through
		} else if decision != nil && decision.Matched {
			resp := s.applyEnforcementDecision(decision, state.streamCtx.AgentIdentity, state.streamCtx.RequestID)
			if resp != nil {
				// Mid-stream enforcement: stop streaming and return enforcement response
				s.finalizeStream(ctx, state)
				return resp
			}
		}
	}

	// If this is the end of stream for the response body, finalize
	if body.GetEndOfStream() {
		s.finalizeStream(ctx, state)
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{
					BodyMutation: &extprocv3.BodyMutation{
						Mutation: &extprocv3.BodyMutation_StreamedResponse{
							StreamedResponse: &extprocv3.StreamedBodyResponse{
								Body:        body.GetBody(),
								EndOfStream: body.GetEndOfStream(),
							},
						},
					},
				},
			},
		},
	}
}

// finalizeStream calls the observer's Finalize method to emit completion events.
// It is safe to call multiple times — subsequent calls are no-ops.
func (s *ExtProcServer) finalizeStream(ctx context.Context, state *streamState) {
	if state.obs == nil || state.streamCtx == nil {
		return
	}

	obs := state.obs
	streamCtx := state.streamCtx

	// Nil out to prevent double-finalize
	state.obs = nil

	obs.Finalize(ctx, streamCtx, nil)
}

// emitRequestStartEvent publishes an LLMRequestStart event using data
// from the stream state.
func (s *ExtProcServer) emitRequestStartEvent(state *streamState) {
	if state.streamCtx == nil {
		return
	}

	s.bus.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:      eventbus.EventTypeLLMRequestStart,
			Time:      state.streamCtx.StartTime,
			ReqID:     state.streamCtx.RequestID,
			Proto:     state.streamCtx.Protocol,
			Prov:      state.streamCtx.Provider,
			AgentInfo: state.streamCtx.AgentIdentity,
		},
		Model:  state.streamCtx.Model,
		Stream: state.streamCtx.Stream,
	})
}

// evaluateRequestPolicy builds PolicyEvents from the parsed StreamContext
// and evaluates them against active policies. For requests with tool
// declarations, each tool is evaluated independently — deny decisions
// result in tool stripping (removing banned tools from the request body)
// rather than blocking the entire request.
//
// Returns an ImmediateResponse if a non-tool-call decision requires
// blocking (deny/throttle on llm_request subcategory), nil for pass-through.
//
// The PolicyEvent is populated with body-derived fields (model, provider,
// toolName, toolNames) rather than agent-controlled headers, ensuring
// policy decisions are based on trusted data.
func (s *ExtProcServer) evaluateRequestPolicy(state *streamState, logger interface{ Info(string, ...interface{}) }) *extprocv3.ProcessingResponse {
	sc := state.streamCtx
	agentIdentity := sc.AgentIdentity
	requestID := sc.RequestID

	// Build common fields from trusted body-parsed data
	baseFields := map[string]interface{}{
		"path":      state.obsCtx.Path,
		"method":    state.obsCtx.Method,
		"requestID": requestID,
		"sourceIP":  agentIdentity.SourceIP,
		"model":     sc.Model,
		"provider":  sc.Provider,
	}

	// Host from headers (infrastructure, not agent-controlled)
	host := state.obsCtx.Headers.Get("host")
	if host == "" {
		host = state.obsCtx.Headers.Get(":authority")
	}
	baseFields["host"] = host

	// For requests with tool declarations, evaluate per-tool
	if len(sc.ToolNames) > 0 {
		return s.evaluatePerToolPolicy(state, baseFields, logger)
	}

	// Non-tool request: single evaluation with llm_request subcategory
	baseFields["toolName"] = ""
	baseFields["toolNames"] = ""

	policyEvent := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "llm_request",
		Timestamp:   time.Now(),
		Namespace:   agentIdentity.Namespace,
		PodName:     agentIdentity.PodName,
		PodLabels:   agentIdentity.Labels,
		Fields:      baseFields,
	}

	decision, err := s.policyEvaluator.Evaluate(policyEvent)
	if err != nil {
		resp := s.handleEvaluationError(err, agentIdentity, requestID, logger)
		if resp != nil {
			return resp
		}
		return nil
	}

	if decision != nil && decision.Matched {
		resp := s.applyEnforcementDecision(decision, agentIdentity, requestID)
		if resp != nil {
			return resp
		}
	}

	return nil
}

// evaluatePerToolPolicy evaluates policy for each tool declared in the request
// independently. Tools that receive a deny decision (in enforcing mode) are
// collected and stripped from the request body. Audit-only denials are logged
// but do not strip. Non-deny decisions (throttle, etc.) are applied immediately.
func (s *ExtProcServer) evaluatePerToolPolicy(state *streamState, baseFields map[string]interface{}, logger interface{ Info(string, ...interface{}) }) *extprocv3.ProcessingResponse {
	sc := state.streamCtx
	agentIdentity := sc.AgentIdentity
	requestID := sc.RequestID

	var bannedTools []string

	for _, toolName := range sc.ToolNames {
		// Build per-tool fields (copy base fields and set tool-specific ones)
		fields := make(map[string]interface{}, len(baseFields)+2)
		for k, v := range baseFields {
			fields[k] = v
		}
		fields["toolName"] = toolName
		fields["toolNames"] = strings.Join(sc.ToolNames, ",")

		policyEvent := &policy.PolicyEvent{
			Category:    "protocol",
			Subcategory: "tool_call",
			Timestamp:   time.Now(),
			Namespace:   agentIdentity.Namespace,
			PodName:     agentIdentity.PodName,
			PodLabels:   agentIdentity.Labels,
			Fields:      fields,
		}

		decision, err := s.policyEvaluator.Evaluate(policyEvent)
		if err != nil {
			resp := s.handleEvaluationError(err, agentIdentity, requestID, logger)
			if resp != nil {
				return resp
			}
			// fail-open: continue to next tool
			continue
		}

		if decision == nil || !decision.Matched {
			continue
		}

		// Apply global audit mode override
		if s.enforcementMode == enforce.ModeAudit {
			decision.AuditOnly = true
		}

		// For deny actions: collect for stripping (only in enforcing mode)
		if decision.Action.Type == v1alpha1.ActionTypeDeny {
			// Emit the policy decision event (for both audit and enforcing)
			s.emitPerToolDecisionEvent(decision, agentIdentity, requestID, toolName)

			if !decision.AuditOnly {
				bannedTools = append(bannedTools, toolName)

				// Emit ToolStrippedEvent to event bus
				s.bus.Emit(&eventbus.ToolStrippedEvent{
					BaseEvent: eventbus.BaseEvent{
						Type:      eventbus.EventTypeToolStripped,
						Time:      time.Now(),
						ReqID:     requestID,
						AgentInfo: agentIdentity,
					},
					ToolName:   toolName,
					PolicyName: decision.PolicyName,
					RuleName:   decision.MatchedRule,
				})

				// Increment Prometheus metric
				RecordToolStripped(toolName, decision.PolicyName, agentIdentity.Namespace, agentIdentity.PodName)

				if l, ok := logger.(interface {
					Info(string, ...interface{})
				}); ok {
					l.Info("tool stripped by policy",
						"tool", toolName,
						"policy", decision.PolicyName,
						"rule", decision.MatchedRule,
						"requestID", requestID,
					)
				}
			} else {
				if l, ok := logger.(interface {
					Info(string, ...interface{})
				}); ok {
					l.Info("tool deny (audit-only, not stripped)",
						"tool", toolName,
						"policy", decision.PolicyName,
						"rule", decision.MatchedRule,
						"requestID", requestID,
					)
				}
			}
			continue
		}

		// For non-deny actions (throttle, etc.): apply immediately
		resp := s.applyEnforcementDecision(decision, agentIdentity, requestID)
		if resp != nil {
			return resp
		}
	}

	// Strip banned tools from the request body
	if len(bannedTools) > 0 {
		modified, err := stripToolsFromBody(state.requestBody, bannedTools)
		if err != nil {
			if l, ok := logger.(interface {
				Info(string, ...interface{})
			}); ok {
				l.Info("failed to strip tools from request body",
					"error", err,
					"requestID", requestID,
				)
			}
			// On strip failure, forward original body
			return nil
		}
		state.requestBody = modified
		state.requestBodyModified = true
	}

	return nil
}

// emitPerToolDecisionEvent emits a policy.decision event for a per-tool
// deny decision, including tool name in the reason.
func (s *ExtProcServer) emitPerToolDecisionEvent(decision *policy.Decision, agentIdentity eventbus.AgentIdentity, requestID, toolName string) {
	ruleRef := formatRuleReference(decision.PolicyNamespace, decision.PolicyName, decision.MatchedRuleIndex)

	actionLabel := string(decision.Action.Type)
	if decision.AuditOnly {
		actionLabel = "audit:" + actionLabel
	}

	s.bus.Emit(&eventbus.EnforcementEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:      eventbus.EventTypePolicyDecision,
			Time:      time.Now(),
			ReqID:     requestID,
			AgentInfo: agentIdentity,
		},
		Reason:          fmt.Sprintf("tool %q stripped by policy rule: %s", toolName, ruleRef),
		Action:          actionLabel,
		PolicyName:      decision.PolicyName,
		PolicyNamespace: decision.PolicyNamespace,
	})
}

// evaluateResponseToolCalls checks the StreamContext for newly completed
// tool calls in the response stream and evaluates each against the policy
// engine. Returns an ImmediateResponse if a tool call should be blocked.
func (s *ExtProcServer) evaluateResponseToolCalls(ctx context.Context, state *streamState, logger interface{ Info(string, ...interface{}) }) *extprocv3.ProcessingResponse {
	sc := state.streamCtx
	if sc == nil {
		return nil
	}

	// Check for new completed tool calls since last evaluation
	for i := state.evaluatedToolCallCount; i < len(sc.ResponseToolCalls); i++ {
		tc := sc.ResponseToolCalls[i]
		if !tc.Complete || tc.Name == "" {
			continue
		}

		// Mark as evaluated
		state.evaluatedToolCallCount = i + 1

		// Build PolicyEvent for the response-path tool call
		policyEvent := &policy.PolicyEvent{
			Category:    "protocol",
			Subcategory: "tool_call",
			Timestamp:   time.Now(),
			Namespace:   sc.AgentIdentity.Namespace,
			PodName:     sc.AgentIdentity.PodName,
			PodLabels:   sc.AgentIdentity.Labels,
			Fields: map[string]interface{}{
				"toolName":  tc.Name,
				"requestID": sc.RequestID,
				"direction": "response",
			},
		}

		decision, err := s.policyEvaluator.Evaluate(policyEvent)
		if err != nil {
			resp := s.handleEvaluationError(err, sc.AgentIdentity, sc.RequestID, logger)
			if resp != nil {
				s.finalizeStream(ctx, state)
				return resp
			}
			continue
		}

		if decision == nil || !decision.Matched {
			continue
		}

		resp := s.applyEnforcementDecision(decision, sc.AgentIdentity, sc.RequestID)
		if resp != nil {
			s.finalizeStream(ctx, state)
			return resp
		}
	}

	return nil
}

// handleEvaluationError handles policy evaluation errors based on the
// configured failure mode. In fail-open mode, it emits a warning event
// and returns nil (pass-through). In fail-closed mode, it emits an error
// event and returns a 503 ImmediateResponse.
func (s *ExtProcServer) handleEvaluationError(err error, agentIdentity eventbus.AgentIdentity, requestID string, logger interface{ Info(string, ...interface{}) }) *extprocv3.ProcessingResponse {
	switch s.failureMode {
	case enforce.FailClosed:
		if l, ok := logger.(interface {
			Info(string, ...interface{})
		}); ok {
			l.Info("policy evaluation error (fail-closed: returning 503)",
				"error", err, "requestID", requestID)
		}
		s.bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:      eventbus.EventTypeEnforcementUnavailable,
				Time:      time.Now(),
				ReqID:     requestID,
				AgentInfo: agentIdentity,
			},
			Reason: fmt.Sprintf("policy engine error: %v", err),
			Action: "block",
		})
		return enforce.NewServiceUnavailableResponse(
			fmt.Sprintf("policy engine unavailable: %v", err),
		)

	default: // FailOpen
		if l, ok := logger.(interface {
			Info(string, ...interface{})
		}); ok {
			l.Info("policy evaluation error (fail-open: passing through)",
				"error", err, "requestID", requestID)
		}
		s.bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:      eventbus.EventTypeEnforcementBypass,
				Time:      time.Now(),
				ReqID:     requestID,
				AgentInfo: agentIdentity,
			},
			Reason: fmt.Sprintf("policy engine error: %v", err),
			Action: "pass-through",
		})
		return nil
	}
}

// applyEnforcementDecision routes a matched policy decision to the appropriate
// enforcement action and returns an ExtProc ProcessingResponse. It also emits
// a policy.decision event to the Event Bus. Returns nil if the decision is an
// allow action (pass-through).
//
// Global enforcement mode takes precedence: if the server-level mode is "audit",
// all decisions are treated as audit-only regardless of per-policy enforcement mode.
func (s *ExtProcServer) applyEnforcementDecision(decision *policy.Decision, agentIdentity eventbus.AgentIdentity, requestID string) *extprocv3.ProcessingResponse {
	// Global audit mode override: when the server is in audit mode, force all
	// decisions to audit-only, even if the per-policy mode is "enforcing".
	if s.enforcementMode == enforce.ModeAudit {
		decision.AuditOnly = true
	}

	ruleRef := formatRuleReference(decision.PolicyNamespace, decision.PolicyName, decision.MatchedRuleIndex)
	signature := decision.Action.Parameters["signature"]
	message := decision.Action.Parameters["message"]

	// Parse escalation parameters from the policy action (if present)
	var escalationThreshold int
	var escalationWindow time.Duration
	var escalationAction string
	if v, ok := decision.Action.Parameters["escalationThreshold"]; ok {
		if parsed, err := strconv.Atoi(v); err == nil {
			escalationThreshold = parsed
		}
	}
	if v, ok := decision.Action.Parameters["escalationWindow"]; ok {
		if parsed, err := strconv.Atoi(v); err == nil {
			escalationWindow = time.Duration(parsed) * time.Second
		}
	}
	if v, ok := decision.Action.Parameters["escalationAction"]; ok {
		escalationAction = v
	}

	// Determine the action label for the event. For audit-only decisions,
	// prefix with "audit:" to distinguish from enforced actions.
	actionLabel := string(decision.Action.Type)
	if decision.AuditOnly {
		actionLabel = "audit:" + actionLabel
	}

	// Emit policy.decision event for all matched decisions
	s.bus.Emit(&eventbus.EnforcementEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:      eventbus.EventTypePolicyDecision,
			Time:      time.Now(),
			ReqID:     requestID,
			AgentInfo: agentIdentity,
		},
		Reason:              fmt.Sprintf("policy rule matched: %s", ruleRef),
		Action:              actionLabel,
		EscalationThreshold: escalationThreshold,
		EscalationWindow:    escalationWindow,
		EscalationAction:    escalationAction,
		PolicyName:          decision.PolicyName,
		PolicyNamespace:     decision.PolicyNamespace,
	})

	// Audit-only decisions: the event was emitted above, but the action is
	// not enforced — pass through as if it were an allow.
	if decision.AuditOnly {
		log.Log.Info("policy decision (audit-only, not enforced)",
			"action", string(decision.Action.Type),
			"rule", ruleRef,
			"agent", agentIdentity.PodName,
			"namespace", agentIdentity.Namespace,
			"requestID", requestID,
		)
		return nil
	}

	switch decision.Action.Type {
	case v1alpha1.ActionTypeDeny:
		if message == "" {
			message = fmt.Sprintf("denied by policy rule %q", decision.MatchedRule)
		}
		return enforce.NewDenyResponse(ruleRef, signature, message)

	case v1alpha1.ActionTypeRateLimit:
		retryAfter := 60 // default
		if v, ok := decision.Action.Parameters["retryAfter"]; ok {
			if parsed, err := strconv.Atoi(v); err == nil {
				retryAfter = parsed
			}
		}
		return enforce.NewThrottleResponse(ruleRef, signature, retryAfter)

	case v1alpha1.ActionTypeAllow:
		// Explicit allow — pass through
		return nil

	default:
		// Unknown or unhandled action type — pass through
		return nil
	}
}

// formatRuleReference formats a policy rule reference as
// "<namespace>/<policy-name>/rule-<index>" or "<policy-name>/rule-<index>".
func formatRuleReference(namespace, policyName string, ruleIndex int) string {
	ruleSuffix := fmt.Sprintf("rule-%d", ruleIndex)
	if namespace != "" {
		return fmt.Sprintf("%s/%s/%s", namespace, policyName, ruleSuffix)
	}
	return fmt.Sprintf("%s/%s", policyName, ruleSuffix)
}

// envoyHeadersToHTTP converts Envoy's HeaderMap proto to a standard http.Header.
// All header keys are stored in their canonical HTTP form.
func envoyHeadersToHTTP(headerMap *corev3.HeaderMap) http.Header {
	if headerMap == nil {
		return http.Header{}
	}

	h := make(http.Header, len(headerMap.GetHeaders()))
	for _, hv := range headerMap.GetHeaders() {
		key := hv.GetKey()
		value := hv.GetValue()
		if len(hv.GetRawValue()) > 0 {
			value = string(hv.GetRawValue())
		}
		h.Add(key, value)
	}
	return h
}
