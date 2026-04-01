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
// In ModeEnforcing, un-enrolled pods are rejected and policy decisions are
// actively enforced. In ModeAudit, all traffic passes through with warning
// events emitted.
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

	// startEventEmitted indicates the LLMRequestStart event has been emitted.
	startEventEmitted bool
}

// Process implements the ExternalProcessor bidirectional streaming RPC.
// For each ProcessingRequest received, it performs passive observation
// (extracting headers, body, tokens) and returns an empty ProcessingResponse
// (no mutations). When the stream ends, it finalizes metrics via the observer.
func (s *ExtProcServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	logger := log.FromContext(stream.Context()).WithName("extproc")

	RecordStreamStart()
	defer RecordStreamEnd()

	state := &streamState{}

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
// resolves agent identity via PodCache, enforces un-enrolled pod policy,
// and builds the initial ObserverContext.
func (s *ExtProcServer) handleRequestHeaders(ctx context.Context, state *streamState, headers *extprocv3.HttpHeaders, logger interface{ Info(string, ...interface{}) }) *extprocv3.ProcessingResponse {
	httpHeaders := envoyHeadersToHTTP(headers.GetHeaders())

	path := httpHeaders.Get(":path")
	method := httpHeaders.Get(":method")
	requestID := httpHeaders.Get("x-panoptium-request-id")

	// Resolve agent identity from source IP via PodCache
	agentIdentity := s.resolver.Resolve(httpHeaders)

	// If no identity was resolved, use x-panoptium-agent-id header as weak ID
	// (for escalation tracking; confidence remains low)
	if agentIdentity.ID == "" && agentIdentity.PodName == "" {
		if agentID := httpHeaders.Get("x-panoptium-agent-id"); agentID != "" {
			agentIdentity.ID = agentID
		}
	}

	// Check for un-enrolled pods (source IP not found in PodCache)
	if agentIdentity.Confidence == eventbus.ConfidenceLow && agentIdentity.SourceIP != "" {
		if s.enforcementMode == enforce.ModeEnforcing {
			// Enforcing mode: reject un-enrolled pod requests with 403
			if l, ok := logger.(interface {
				Info(string, ...interface{})
			}); ok {
				l.Info("rejecting request from un-enrolled pod",
					"sourceIP", agentIdentity.SourceIP, "requestID", requestID)
			}
			return enforce.NewUnenrolledDenyResponse(agentIdentity.SourceIP)
		}

		// Audit mode: pass through but emit warning event
		if l, ok := logger.(interface {
			Info(string, ...interface{})
		}); ok {
			l.Info("request from un-enrolled pod (audit mode, passing through)",
				"sourceIP", agentIdentity.SourceIP, "requestID", requestID)
		}
		s.bus.Emit(&eventbus.EnforcementEvent{
			BaseEvent: eventbus.BaseEvent{
				Type:      eventbus.EventTypeEnforcementUnenrolled,
				Time:      time.Now(),
				ReqID:     requestID,
				AgentInfo: agentIdentity,
			},
			Reason:   "un-enrolled pod",
			SourceIP: agentIdentity.SourceIP,
			Action:   "pass-through",
		})
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

	// Echo original body back via StreamedBodyResponse — AgentGateway
	// operates in streaming mode and rejects BodyMutation_Body variant.
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{
					BodyMutation: &extprocv3.BodyMutation{
						Mutation: &extprocv3.BodyMutation_StreamedResponse{
							StreamedResponse: &extprocv3.StreamedBodyResponse{
								Body:        state.requestBody,
								EndOfStream: true,
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

// evaluateRequestPolicy builds a PolicyEvent from the parsed StreamContext
// and evaluates it against active policies. Returns an ImmediateResponse
// if the decision requires blocking (deny/throttle), nil for pass-through.
//
// The PolicyEvent is populated with body-derived fields (model, provider,
// toolName, toolNames) rather than agent-controlled headers, ensuring
// policy decisions are based on trusted data.
func (s *ExtProcServer) evaluateRequestPolicy(state *streamState, logger interface{ Info(string, ...interface{}) }) *extprocv3.ProcessingResponse {
	sc := state.streamCtx
	agentIdentity := sc.AgentIdentity
	requestID := sc.RequestID

	// Determine subcategory based on parsed tool names
	subcategory := "llm_request"
	if len(sc.ToolNames) > 0 {
		subcategory = "tool_call"
	}

	// Build fields from trusted body-parsed data
	fields := map[string]interface{}{
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
	fields["host"] = host

	// Tool names from body parsing (trusted)
	if len(sc.ToolNames) > 0 {
		fields["toolName"] = sc.ToolNames[0]
		fields["toolNames"] = strings.Join(sc.ToolNames, ",")
	}

	policyEvent := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: subcategory,
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
		// fail-open: fall through to pass-through
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
