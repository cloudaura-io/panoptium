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

// Package eventbus provides an in-memory event bus for publishing and subscribing
// to LLM observation events within the Panoptium operator.
package eventbus

import "time"

// Event type constants identify the kind of event being published.
const (
	// EventTypeLLMRequestStart is emitted when a new LLM request is observed.
	EventTypeLLMRequestStart = "llm.request.start"

	// EventTypeLLMTokenChunk is emitted for each token/chunk in a streaming response.
	EventTypeLLMTokenChunk = "llm.token.chunk"

	// EventTypeLLMRequestComplete is emitted when the response stream ends.
	EventTypeLLMRequestComplete = "llm.request.complete"

	// EventTypeEnforcementUnenrolled is emitted when a request from an un-enrolled pod
	// is observed in audit mode (passed through with warning).
	EventTypeEnforcementUnenrolled = "enforcement.unenrolled"

	// EventTypeEnforcementBypass is emitted when the policy engine is unavailable
	// and fail-open mode passes traffic through.
	EventTypeEnforcementBypass = "enforcement.bypass"

	// EventTypeEnforcementUnavailable is emitted when fail-closed mode rejects
	// traffic due to policy engine unavailability.
	EventTypeEnforcementUnavailable = "enforcement.unavailable"

	// EventTypePolicyDecision is emitted when a policy evaluation produces a
	// match (deny, throttle, modify, suspend).
	EventTypePolicyDecision = "policy.decision"
)

// Protocol constants identify the protocol of the observed traffic.
const (
	// ProtocolLLM represents LLM (Large Language Model) protocol traffic.
	ProtocolLLM = "llm"
)

// Provider constants identify the LLM provider.
const (
	// ProviderOpenAI represents OpenAI API traffic.
	ProviderOpenAI = "openai"

	// ProviderAnthropic represents Anthropic API traffic.
	ProviderAnthropic = "anthropic"
)

// Auth type constants identify how the agent was authenticated.
const (
	// AuthTypeJWT indicates the agent was authenticated via JWT token.
	AuthTypeJWT = "jwt"

	// AuthTypeSourceIP indicates the agent was identified by source IP.
	AuthTypeSourceIP = "source-ip"
)

// Confidence level constants indicate the reliability of agent identity resolution.
const (
	// ConfidenceHigh indicates identity was resolved via JWT (most reliable).
	ConfidenceHigh = "high"

	// ConfidenceMedium indicates identity was resolved via pod IP lookup.
	ConfidenceMedium = "medium"

	// ConfidenceLow indicates identity is based on raw source IP only.
	ConfidenceLow = "low"
)

// Event is the interface that all events published on the bus must implement.
type Event interface {
	// EventType returns the type identifier for this event.
	EventType() string

	// Timestamp returns when this event was created.
	Timestamp() time.Time

	// RequestID returns the unique request correlation ID.
	RequestID() string

	// Protocol returns the protocol of the observed traffic.
	Protocol() string

	// Provider returns the LLM provider identifier.
	Provider() string

	// Identity returns the agent identity associated with this event.
	Identity() AgentIdentity
}

// AgentIdentity contains information about the agent that initiated the request.
type AgentIdentity struct {
	// ID is the primary agent identifier (pod name from PodCache).
	ID string

	// SourceIP is the source pod IP for Kubernetes resolution.
	SourceIP string

	// Confidence indicates the reliability of the identity resolution.
	// "high" = resolved from PodCache with full metadata
	// "medium" = partially resolved
	// "low" = unknown / unenrolled pod
	Confidence string

	// PodName is the resolved Kubernetes pod name.
	PodName string

	// PodUID is the Kubernetes pod UID for unambiguous pod identification.
	PodUID string

	// Namespace is the Kubernetes namespace of the agent pod.
	Namespace string

	// Labels contains the Kubernetes labels of the agent pod.
	Labels map[string]string
}

// BaseEvent provides a common implementation of the Event interface.
type BaseEvent struct {
	// Type is the event type identifier.
	Type string

	// Time is when this event was created.
	Time time.Time

	// ReqID is the unique request correlation ID.
	ReqID string

	// Proto is the protocol of the observed traffic.
	Proto string

	// Prov is the LLM provider identifier.
	Prov string

	// AgentInfo contains the agent identity for this event.
	AgentInfo AgentIdentity
}

// EventType returns the type identifier for this event.
func (e *BaseEvent) EventType() string { return e.Type }

// Timestamp returns when this event was created.
func (e *BaseEvent) Timestamp() time.Time { return e.Time }

// RequestID returns the unique request correlation ID.
func (e *BaseEvent) RequestID() string { return e.ReqID }

// Protocol returns the protocol of the observed traffic.
func (e *BaseEvent) Protocol() string { return e.Proto }

// Provider returns the LLM provider identifier.
func (e *BaseEvent) Provider() string { return e.Prov }

// Identity returns the agent identity associated with this event.
func (e *BaseEvent) Identity() AgentIdentity { return e.AgentInfo }

// LLMRequestStartEvent is emitted when a new LLM request is observed.
// It contains the request metadata, model, messages, and agent identity.
type LLMRequestStartEvent struct {
	BaseEvent

	// Model is the LLM model being called (e.g., "gpt-4", "claude-3").
	Model string

	// Messages contains the prompt content.
	Messages []string

	// Stream indicates whether the request uses streaming mode.
	Stream bool
}

// LLMTokenChunkEvent is emitted for each token/chunk in a streaming response.
type LLMTokenChunkEvent struct {
	BaseEvent

	// Content is the token text content.
	Content string

	// TokenIndex is the sequential index of this token in the stream.
	TokenIndex int
}

// LLMRequestCompleteEvent is emitted when the response stream ends.
// It contains aggregated metrics for the completed request.
type LLMRequestCompleteEvent struct {
	BaseEvent

	// TotalTokens is the total number of tokens (input + output).
	TotalTokens int

	// InputTokens is the number of input/prompt tokens.
	InputTokens int

	// OutputTokens is the number of output/completion tokens.
	OutputTokens int

	// TTFT is the time-to-first-token duration.
	TTFT time.Duration

	// Duration is the total request duration.
	Duration time.Duration

	// TokensPerSec is the output tokens per second rate.
	TokensPerSec float64

	// FinishReason is the reason the response ended (e.g., "stop", "length").
	FinishReason string
}

// EnforcementEvent is emitted for enforcement-related occurrences such as
// un-enrolled pod access, policy bypass, and policy decisions.
type EnforcementEvent struct {
	BaseEvent

	// Reason describes why this enforcement event was generated.
	Reason string

	// SourceIP is the source IP that triggered the event.
	SourceIP string

	// Action is the enforcement action taken (e.g., "deny", "pass-through").
	Action string
}
