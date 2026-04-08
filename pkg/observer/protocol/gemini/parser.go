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

// Package gemini implements the ProtocolParser interface for the Google Gemini API,
// parsing generateContent requests and SSE streaming responses with functionCall
// extraction.
//
// NOTE: Fully implemented and tested but not yet registered with the operator.
// Will be wired into the ExtProc pipeline to enable Gemini-aware policy
// enforcement alongside OpenAI and Anthropic support.
package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/panoptium/panoptium/pkg/observer/protocol"
	"github.com/panoptium/panoptium/pkg/threat"
)

const (
	// parserName is the name of this parser.
	parserName = "gemini"
)

// GeminiParser implements protocol.ProtocolParser for Google Gemini API messages.
type GeminiParser struct {
	mu            sync.RWMutex
	threatMatcher threat.ThreatMatcher
}

// NewGeminiParser creates a new Gemini parser.
func NewGeminiParser() *GeminiParser {
	return &GeminiParser{}
}

// SetThreatMatcher sets the CRD-driven ThreatMatcher for threat detection.
func (p *GeminiParser) SetThreatMatcher(matcher threat.ThreatMatcher) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.threatMatcher = matcher
}

// Name returns the parser name.
func (p *GeminiParser) Name() string {
	return parserName
}

// Detect checks if the request matches Gemini API path patterns.
func (p *GeminiParser) Detect(headers map[string]string, path string, method string) (bool, float32) {
	if strings.Contains(path, "/models/") &&
		(strings.HasSuffix(path, "/generateContent") || strings.HasSuffix(path, "/streamGenerateContent")) {
		if strings.HasPrefix(path, "/v1beta/") || strings.HasPrefix(path, "/v1/") {
			return true, 0.9
		}
	}
	return false, 0
}

// --- Request types ---

type generateContentRequest struct {
	Contents       []content       `json:"contents"`
	Tools          []toolDef       `json:"tools,omitempty"`
	SafetySettings []safetySetting `json:"safetySettings,omitempty"`
	Model          string          `json:"model,omitempty"`
}

type content struct {
	Role  string `json:"role"`
	Parts []part `json:"parts"`
}

type part struct {
	Text             string            `json:"text,omitempty"`
	FunctionCall     *functionCall     `json:"functionCall,omitempty"`
	FunctionResponse *functionResponse `json:"functionResponse,omitempty"`
}

type functionCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}

type functionResponse struct {
	Name     string                 `json:"name"`
	Response map[string]interface{} `json:"response"`
}

type toolDef struct {
	FunctionDeclarations []functionDecl `json:"functionDeclarations,omitempty"`
}

type functionDecl struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type safetySetting struct {
	Category  string `json:"category"`
	Threshold string `json:"threshold"`
}

// --- Response types ---

type generateContentResponse struct {
	Candidates    []candidate    `json:"candidates"`
	UsageMetadata *usageMetadata `json:"usageMetadata,omitempty"`
}

type candidate struct {
	Content          content        `json:"content"`
	FinishReason     string         `json:"finishReason,omitempty"`
	SafetyRatings    []safetyRating `json:"safetyRatings,omitempty"`
	CitationMetadata *citationMeta  `json:"citationMetadata,omitempty"`
}

type safetyRating struct {
	Category    string `json:"category"`
	Probability string `json:"probability"`
}

type citationMeta struct {
	Citations []citation `json:"citationSources"`
}

type citation struct {
	StartIndex int    `json:"startIndex"`
	EndIndex   int    `json:"endIndex"`
	URI        string `json:"uri"`
}

type usageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// ProcessRequest parses a Gemini generateContent request.
func (p *GeminiParser) ProcessRequest(
	ctx context.Context, headers map[string]string, body []byte,
) (*protocol.ParsedRequest, error) {
	if len(body) == 0 {
		return nil, errors.New("empty request body")
	}

	var req generateContentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("invalid Gemini request: %w", err)
	}

	result := &protocol.ParsedRequest{
		Protocol:    parserName,
		MessageType: "llm.request.start",
		Metadata:    make(map[string]interface{}),
	}

	result.Metadata["model"] = req.Model

	// Extract tool declarations
	var toolNames []string
	for _, tool := range req.Tools {
		for _, fn := range tool.FunctionDeclarations {
			toolNames = append(toolNames, fn.Name)
		}
	}
	if len(toolNames) > 0 {
		result.Metadata["tool_names"] = toolNames
	}

	// Extract safety settings
	if len(req.SafetySettings) > 0 {
		result.Metadata["safety_settings"] = req.SafetySettings
	}

	// Check for functionResponse in contents (follow-up tool result)
	for _, c := range req.Contents {
		for _, pt := range c.Parts {
			if pt.FunctionResponse != nil {
				result.Metadata["function_response_name"] = pt.FunctionResponse.Name
				result.Metadata["function_response"] = pt.FunctionResponse.Response
			}
		}
	}

	// Evaluate ThreatMatcher if set
	p.mu.RLock()
	matcher := p.threatMatcher
	p.mu.RUnlock()

	if matcher != nil {
		// Build content from all text parts for threat evaluation
		var allText string
		for _, c := range req.Contents {
			for _, pt := range c.Parts {
				if pt.Text != "" {
					allText += pt.Text + " "
				}
			}
		}
		if allText != "" {
			matches, err := matcher.Match(ctx, threat.MatchInput{
				Protocol: parserName,
				Target:   "message_content",
				Content:  allText,
				Metadata: map[string]any{"model": req.Model},
			})
			if err == nil && len(matches) > 0 {
				result.Metadata["threat_matches"] = matches
			}
		}
	}

	return result, nil
}

// ProcessResponse parses a non-streaming Gemini generateContent response.
func (p *GeminiParser) ProcessResponse(
	_ context.Context, headers map[string]string, body []byte,
) (*protocol.ParsedResponse, error) {
	if len(body) == 0 {
		return nil, errors.New("empty response body")
	}

	var resp generateContentResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("invalid Gemini response: %w", err)
	}

	result := &protocol.ParsedResponse{
		Protocol: parserName,
		Metadata: make(map[string]interface{}),
	}

	if len(resp.Candidates) > 0 {
		cand := resp.Candidates[0]

		// Extract text content
		var textContent string
		for _, pt := range cand.Content.Parts {
			if pt.Text != "" {
				textContent += pt.Text
			}
		}
		if textContent != "" {
			result.MessageType = "llm.token.chunk"
			result.Metadata["content"] = textContent
		}

		// Extract functionCall
		for _, pt := range cand.Content.Parts {
			if pt.FunctionCall != nil {
				result.MessageType = "llm.tool.call"
				result.Metadata["function_call_name"] = pt.FunctionCall.Name
				result.Metadata["function_call_args"] = pt.FunctionCall.Args
			}
		}

		// Safety ratings
		if len(cand.SafetyRatings) > 0 {
			result.Metadata["safety_ratings"] = cand.SafetyRatings
		}

		// Citation metadata
		if cand.CitationMetadata != nil {
			result.Metadata["citations"] = cand.CitationMetadata.Citations
		}

		if cand.FinishReason != "" {
			result.Metadata["finish_reason"] = cand.FinishReason
		}
	}

	if result.MessageType == "" {
		result.MessageType = "llm.response"
	}

	// Usage metadata
	if resp.UsageMetadata != nil {
		result.Metadata["prompt_tokens"] = resp.UsageMetadata.PromptTokenCount
		result.Metadata["candidates_tokens"] = resp.UsageMetadata.CandidatesTokenCount
		result.Metadata["total_tokens"] = resp.UsageMetadata.TotalTokenCount
	}

	return result, nil
}

// ProcessStreamChunk parses an SSE chunk from a streaming Gemini response.
func (p *GeminiParser) ProcessStreamChunk(
	_ context.Context, chunk []byte, state *protocol.StreamState,
) (*protocol.ParsedChunk, error) {
	if len(chunk) == 0 {
		return nil, nil
	}

	result := &protocol.ParsedChunk{
		Protocol: parserName,
		Metadata: make(map[string]interface{}),
	}

	// Parse SSE: "data: <json>\n\n"
	lines := bytes.Split(chunk, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data: ")) {
			continue
		}
		payload := bytes.TrimPrefix(line, []byte("data: "))

		var resp generateContentResponse
		if err := json.Unmarshal(payload, &resp); err != nil {
			continue
		}

		if len(resp.Candidates) > 0 {
			cand := resp.Candidates[0]
			for _, pt := range cand.Content.Parts {
				if pt.Text != "" {
					result.Content += pt.Text
				}
				if pt.FunctionCall != nil {
					result.Metadata["function_call_name"] = pt.FunctionCall.Name
					result.Metadata["function_call_args"] = pt.FunctionCall.Args
				}
			}

			if len(cand.SafetyRatings) > 0 {
				result.Metadata["safety_ratings"] = cand.SafetyRatings
			}

			if cand.FinishReason != "" {
				result.Metadata["finish_reason"] = cand.FinishReason
				result.Done = true
			}
		}
	}

	return result, nil
}
