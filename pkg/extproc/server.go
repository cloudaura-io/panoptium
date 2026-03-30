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
	"io"
	"net/http"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
)

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
}

// NewExtProcServer creates a new ExtProcServer with the given dependencies.
// The default enforcement mode is audit (observe-only, no blocking).
func NewExtProcServer(registry *observer.ObserverRegistry, resolver *identity.Resolver, bus eventbus.EventBus) *ExtProcServer {
	return &ExtProcServer{
		registry:        registry,
		resolver:        resolver,
		bus:             bus,
		enforcementMode: enforce.ModeAudit,
	}
}

// SetEnforcementMode configures the enforcement behavior for this server.
// In ModeEnforcing, un-enrolled pods are rejected and policy decisions are
// actively enforced. In ModeAudit, all traffic passes through with warning
// events emitted.
func (s *ExtProcServer) SetEnforcementMode(mode enforce.EnforcementMode) {
	s.enforcementMode = mode
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
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{
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
