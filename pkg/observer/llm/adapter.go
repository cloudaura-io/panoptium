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

package llm

import (
	"context"
	"net/http"

	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/protocol"
)

// LLMParserAdapter adapts the existing LLMObserver to the ProtocolParser interface,
// enabling it to participate in the ProtocolDetector's detection cascade alongside
// new protocol parsers (MCP, A2A, Gemini). The adapter delegates detection to the
// underlying LLMObserver's CanHandle method and wraps its processing methods.
type LLMParserAdapter struct {
	observer *LLMObserver
}

// NewLLMParserAdapter creates a ProtocolParser adapter wrapping the given LLMObserver.
func NewLLMParserAdapter(obs *LLMObserver) *LLMParserAdapter {
	return &LLMParserAdapter{observer: obs}
}

// Name returns the adapter's name.
func (a *LLMParserAdapter) Name() string {
	return a.observer.Name()
}

// Detect delegates to LLMObserver.CanHandle, converting the flat header map
// to an http.Header for the existing CanHandle signature.
func (a *LLMParserAdapter) Detect(headers map[string]string, path string, method string) (bool, float32) {
	httpHeaders := http.Header{}
	for k, v := range headers {
		httpHeaders.Set(k, v)
	}

	req := &observer.ObserverContext{
		Headers: httpHeaders,
		Path:    path,
		Method:  method,
	}

	return a.observer.CanHandle(context.Background(), req)
}

// ProcessRequest delegates to LLMObserver.ProcessRequestStream.
func (a *LLMParserAdapter) ProcessRequest(ctx context.Context, headers map[string]string, body []byte) (*protocol.ParsedRequest, error) {
	httpHeaders := http.Header{}
	for k, v := range headers {
		httpHeaders.Set(k, v)
	}

	req := &observer.ObserverContext{
		Headers: httpHeaders,
		Body:    body,
	}

	streamCtx, err := a.observer.ProcessRequestStream(ctx, req)
	if err != nil {
		return nil, err
	}

	return &protocol.ParsedRequest{
		Protocol:    streamCtx.Protocol,
		MessageType: "llm.request",
		Metadata: map[string]interface{}{
			"model":      streamCtx.Model,
			"stream":     streamCtx.Stream,
			"provider":   streamCtx.Provider,
			"tool_names": streamCtx.ToolNames,
		},
	}, nil
}

// ProcessResponse is a no-op for the LLM adapter since LLM streaming responses
// are handled via ProcessResponseStream on the underlying observer.
func (a *LLMParserAdapter) ProcessResponse(_ context.Context, _ map[string]string, _ []byte) (*protocol.ParsedResponse, error) {
	return &protocol.ParsedResponse{
		Protocol:    "llm",
		MessageType: "llm.response",
	}, nil
}

// ProcessStreamChunk is a no-op for the LLM adapter since LLM stream processing
// is handled by the existing ProtocolObserver pipeline (ProcessResponseStream).
func (a *LLMParserAdapter) ProcessStreamChunk(_ context.Context, _ []byte, _ *protocol.StreamState) (*protocol.ParsedChunk, error) {
	return &protocol.ParsedChunk{
		Protocol: "llm",
	}, nil
}
