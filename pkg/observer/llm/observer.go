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

// Package llm implements the ProtocolObserver interface for LLM protocol traffic,
// supporting OpenAI and Anthropic providers.
package llm

import (
	"context"
	"strings"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm/anthropic"
	"github.com/panoptium/panoptium/pkg/observer/llm/openai"
)

const (
	// observerName is the name returned by the observer.
	observerName = "llm"

	// providerOpenAI identifies OpenAI as the LLM provider.
	providerOpenAI = "openai"

	// providerAnthropic identifies Anthropic as the LLM provider.
	providerAnthropic = "anthropic"

	// confidencePathOnly is the confidence score when only the path matches.
	confidencePathOnly float32 = 0.6

	// confidencePathAndHost is the confidence score when both path and host match.
	confidencePathAndHost float32 = 0.9
)

// knownPaths maps URL path prefixes to their provider identification.
var knownPaths = map[string]string{
	"/v1/chat/completions": providerOpenAI,
	"/chat/completions":    providerOpenAI,
	"/v1/messages":         providerAnthropic,
	"/messages":            providerAnthropic,
}

// knownHosts maps host patterns to their provider identification.
var knownHosts = map[string]string{
	"api.openai.com":    providerOpenAI,
	"api.anthropic.com": providerAnthropic,
}

// LLMObserver implements the observer.ProtocolObserver interface for LLM traffic.
// It delegates provider-specific parsing to OpenAI and Anthropic parsers.
type LLMObserver struct {
	bus eventbus.EventBus
}

// NewLLMObserver creates a new LLMObserver with the given event bus.
func NewLLMObserver(bus eventbus.EventBus) *LLMObserver {
	return &LLMObserver{bus: bus}
}

// Name returns the observer identifier.
func (o *LLMObserver) Name() string {
	return observerName
}

// CanHandle determines whether this observer can handle the request by
// checking the path and host against known LLM provider patterns.
// Returns true and a confidence score (0.6 for path-only, 0.9 for path+host).
func (o *LLMObserver) CanHandle(_ context.Context, req *observer.ObserverContext) (bool, float32) {
	provider := o.detectProvider(req)
	if provider == "" {
		return false, 0
	}

	// Check if the host also matches for higher confidence
	host := req.Headers.Get("Host")
	if host != "" {
		if hostProvider, ok := knownHosts[host]; ok && hostProvider == provider {
			return true, confidencePathAndHost
		}
	}

	return true, confidencePathOnly
}

// ProcessRequestStream parses the LLM request and emits a start event.
func (o *LLMObserver) ProcessRequestStream(
	_ context.Context, req *observer.ObserverContext,
) (*observer.StreamContext, error) {
	provider := o.detectProvider(req)

	streamCtx := &observer.StreamContext{
		RequestID: req.RequestID,
		Protocol:  eventbus.ProtocolLLM,
		Provider:  provider,
		StartTime: time.Now(),
		EventBus:  o.bus,
	}

	switch provider {
	case providerOpenAI:
		if len(req.Body) > 0 {
			parsed, err := openai.ParseRequest(req.Body)
			if err != nil {
				return streamCtx, nil // Continue even if parsing fails
			}
			streamCtx.Model = parsed.Model
			streamCtx.Stream = parsed.Stream
			streamCtx.RequestBody = req.Body
			streamCtx.ToolNames = parsed.ToolNames
		}
	case providerAnthropic:
		if len(req.Body) > 0 {
			parsed, err := anthropic.ParseRequest(req.Body)
			if err != nil {
				return streamCtx, nil
			}
			streamCtx.Model = parsed.Model
			streamCtx.Stream = parsed.Stream
			streamCtx.RequestBody = req.Body
			streamCtx.ToolNames = parsed.ToolNames
		}
	}

	return streamCtx, nil
}

// ProcessResponseStream handles a response body chunk, parsing SSE data
// and emitting token chunk events.
func (o *LLMObserver) ProcessResponseStream(_ context.Context, streamCtx *observer.StreamContext, body []byte) error {
	switch streamCtx.Provider {
	case providerOpenAI:
		chunks, err := openai.ParseSSEFrame(body)
		if err != nil {
			return err
		}
		for _, chunk := range chunks {
			if chunk.Done {
				continue
			}
			if chunk.Content != "" {
				streamCtx.TokenCount++
				if streamCtx.FirstTokenTime.IsZero() {
					streamCtx.FirstTokenTime = time.Now()
				}
				o.bus.Emit(&eventbus.LLMTokenChunkEvent{
					BaseEvent: eventbus.BaseEvent{
						Type:      eventbus.EventTypeLLMTokenChunk,
						Time:      time.Now(),
						ReqID:     streamCtx.RequestID,
						Proto:     streamCtx.Protocol,
						Prov:      streamCtx.Provider,
						AgentInfo: streamCtx.AgentIdentity,
					},
					Content:    chunk.Content,
					TokenIndex: streamCtx.TokenCount - 1,
				})
			}

			// Accumulate tool call deltas
			for _, tc := range chunk.ToolCalls {
				accumulateToolCallDelta(streamCtx, tc.Index, tc.ID, tc.FunctionName)
			}

			// Mark tool calls as complete when finish_reason is "tool_calls"
			if chunk.FinishReason == "tool_calls" {
				for i := range streamCtx.ResponseToolCalls {
					streamCtx.ResponseToolCalls[i].Complete = true
				}
			}
		}
	case providerAnthropic:
		events, err := anthropic.ParseSSEFrame(body)
		if err != nil {
			return err
		}
		for _, event := range events {
			if event.Done {
				continue
			}
			if event.Content != "" {
				streamCtx.TokenCount++
				if streamCtx.FirstTokenTime.IsZero() {
					streamCtx.FirstTokenTime = time.Now()
				}
				o.bus.Emit(&eventbus.LLMTokenChunkEvent{
					BaseEvent: eventbus.BaseEvent{
						Type:      eventbus.EventTypeLLMTokenChunk,
						Time:      time.Now(),
						ReqID:     streamCtx.RequestID,
						Proto:     streamCtx.Protocol,
						Prov:      streamCtx.Provider,
						AgentInfo: streamCtx.AgentIdentity,
					},
					Content:    event.Content,
					TokenIndex: streamCtx.TokenCount - 1,
				})
			}

			// Accumulate Anthropic tool_use blocks
			if event.ToolUse != nil {
				// content_block_start with tool_use: add new entry
				streamCtx.ResponseToolCalls = append(streamCtx.ResponseToolCalls, observer.ResponseToolCall{
					Index: len(streamCtx.ResponseToolCalls),
					ID:    event.ToolUse.ID,
					Name:  event.ToolUse.Name,
				})
			}

			// content_block_stop: mark the last tool_use as complete
			if event.ContentBlockStop && len(streamCtx.ResponseToolCalls) > 0 {
				last := len(streamCtx.ResponseToolCalls) - 1
				if !streamCtx.ResponseToolCalls[last].Complete {
					streamCtx.ResponseToolCalls[last].Complete = true
				}
			}
		}
	}

	return nil
}

// Finalize emits a completion event with aggregated metrics.
func (o *LLMObserver) Finalize(_ context.Context, streamCtx *observer.StreamContext, err error) error {
	duration := time.Since(streamCtx.StartTime)

	var ttft time.Duration
	if !streamCtx.FirstTokenTime.IsZero() {
		ttft = streamCtx.FirstTokenTime.Sub(streamCtx.StartTime)
	}

	var tokensPerSec float64
	if duration.Seconds() > 0 && streamCtx.TokenCount > 0 {
		tokensPerSec = float64(streamCtx.TokenCount) / duration.Seconds()
	}

	o.bus.Emit(&eventbus.LLMRequestCompleteEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:      eventbus.EventTypeLLMRequestComplete,
			Time:      time.Now(),
			ReqID:     streamCtx.RequestID,
			Proto:     streamCtx.Protocol,
			Prov:      streamCtx.Provider,
			AgentInfo: streamCtx.AgentIdentity,
		},
		OutputTokens: streamCtx.TokenCount,
		TTFT:         ttft,
		Duration:     duration,
		TokensPerSec: tokensPerSec,
	})

	return nil
}

// accumulateToolCallDelta accumulates a tool call delta into the StreamContext's
// ResponseToolCalls. Names are concatenated across chunks for the same index.
func accumulateToolCallDelta(streamCtx *observer.StreamContext, index int, id, nameFrag string) {
	// Find existing entry for this index
	for i := range streamCtx.ResponseToolCalls {
		if streamCtx.ResponseToolCalls[i].Index == index {
			// Accumulate name fragment
			streamCtx.ResponseToolCalls[i].Name += nameFrag
			if id != "" {
				streamCtx.ResponseToolCalls[i].ID = id
			}
			return
		}
	}

	// New tool call index — create entry
	streamCtx.ResponseToolCalls = append(streamCtx.ResponseToolCalls, observer.ResponseToolCall{
		Index: index,
		ID:    id,
		Name:  nameFrag,
	})
}

// detectProvider determines the LLM provider from the request path.
func (o *LLMObserver) detectProvider(req *observer.ObserverContext) string {
	for pathPrefix, provider := range knownPaths {
		if strings.HasPrefix(req.Path, pathPrefix) {
			return provider
		}
	}
	return ""
}
