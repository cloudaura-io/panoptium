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

// Package threat provides CRD-driven threat signature matching for protocol
// parsers. It replaces hardcoded attack patterns with a compiled, thread-safe
// registry of signatures loaded from PanoptiumThreatSignature CRD resources.
package threat

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sync"
)

// ThreatMatcher evaluates content against compiled threat signatures.
type ThreatMatcher interface {
	// Match evaluates all signatures against the given content.
	// Returns matched signatures with scores.
	Match(ctx context.Context, input MatchInput) ([]MatchResult, error)
}

// MatchInput describes the content to evaluate against threat signatures.
type MatchInput struct {
	// Protocol is the protocol being analyzed ("mcp", "a2a", "gemini", "openai", "anthropic").
	Protocol string

	// Target is where the content came from ("tool_description", "tool_args", "message_content", "body").
	Target string

	// Content is the text to evaluate.
	Content string

	// Headers are the request headers for context.
	Headers map[string]string

	// Metadata contains protocol-specific metadata (tool name, method, etc.).
	Metadata map[string]any
}

// MatchResult describes a matched threat signature with its scoring details.
type MatchResult struct {
	// SignatureName is the name of the matched signature.
	SignatureName string

	// Category is the attack category (e.g., "prompt_injection", "data_exfiltration").
	Category string

	// Severity is the severity level ("critical", "high", "medium", "low", "info").
	Severity string

	// Score is the composite score (0.0-1.0) from all matched indicators.
	Score float64

	// Indicators lists which sub-rules matched.
	Indicators []string

	// MitreAtlas is the MITRE ATLAS reference if present.
	MitreAtlas string
}

// SignatureDefinition describes a threat signature for compilation into the registry.
type SignatureDefinition struct {
	// Name is the unique name of the signature (from CRD metadata.name).
	Name string

	// Protocols lists the protocols this signature applies to (empty = all).
	Protocols []string

	// Category is the attack category for grouping and policy matching.
	Category string

	// Severity is the severity level.
	Severity string

	// MitreAtlas is an optional MITRE ATLAS reference.
	MitreAtlas string

	// Description is a human-readable description of what this signature detects.
	Description string

	// Patterns defines regex-based detection patterns with weights.
	Patterns []PatternDef

	// Entropy defines entropy-based detection configuration.
	Entropy *EntropyDef

	// Base64 defines base64 payload detection configuration.
	Base64 *Base64Def

	// CELExpressions defines CEL-based detection rules.
	CELExpressions []CELDef
}

// PatternDef defines a regex pattern with weight and target.
type PatternDef struct {
	// Regex is the regular expression pattern.
	Regex string

	// Weight is the score weight (0.0-1.0) for this pattern.
	Weight float64

	// Target is where to apply this pattern ("tool_description", "tool_args", "message_content", "body").
	Target string
}

// EntropyDef defines entropy-based detection configuration.
type EntropyDef struct {
	// Enabled indicates whether entropy analysis is active.
	Enabled bool

	// Threshold is the Shannon entropy threshold above which content is flagged.
	Threshold float64

	// Target is where to apply entropy analysis.
	Target string
}

// Base64Def defines base64 payload detection configuration.
type Base64Def struct {
	// Enabled indicates whether base64 detection is active.
	Enabled bool

	// MinLength is the minimum base64 string length to flag.
	MinLength int

	// Target is where to apply base64 detection.
	Target string
}

// CELDef defines a CEL expression for complex detection rules.
type CELDef struct {
	// Expression is the CEL expression to evaluate.
	Expression string

	// Weight is the score weight (0.0-1.0) for this expression.
	Weight float64
}

// compiledSignature holds a compiled signature with precompiled regexps.
type compiledSignature struct {
	def      SignatureDefinition
	patterns []compiledPattern
}

// compiledPattern holds a precompiled regexp with its weight and target.
type compiledPattern struct {
	re     *regexp.Regexp
	weight float64
	target string
}

// CompiledSignatureRegistry implements ThreatMatcher with a thread-safe
// registry of compiled signatures.
type CompiledSignatureRegistry struct {
	mu         sync.RWMutex
	signatures map[string]*compiledSignature
}

// NewCompiledSignatureRegistry creates a new empty registry.
func NewCompiledSignatureRegistry() *CompiledSignatureRegistry {
	return &CompiledSignatureRegistry{
		signatures: make(map[string]*compiledSignature),
	}
}

// AddSignature compiles and adds a signature to the registry.
// Returns an error if any regex pattern fails to compile.
func (r *CompiledSignatureRegistry) AddSignature(def SignatureDefinition) error {
	compiled := &compiledSignature{
		def:      def,
		patterns: make([]compiledPattern, 0, len(def.Patterns)),
	}

	for _, pd := range def.Patterns {
		re, err := regexp.Compile(pd.Regex)
		if err != nil {
			return fmt.Errorf("invalid regex in signature %q pattern %q: %w", def.Name, pd.Regex, err)
		}
		compiled.patterns = append(compiled.patterns, compiledPattern{
			re:     re,
			weight: pd.Weight,
			target: pd.Target,
		})
	}

	r.mu.Lock()
	r.signatures[def.Name] = compiled
	r.mu.Unlock()

	return nil
}

// RemoveSignature removes a signature from the registry by name.
func (r *CompiledSignatureRegistry) RemoveSignature(name string) {
	r.mu.Lock()
	delete(r.signatures, name)
	r.mu.Unlock()
}

// Match evaluates all compiled signatures against the given input.
// It filters by protocol and target, then evaluates regex patterns.
func (r *CompiledSignatureRegistry) Match(_ context.Context, input MatchInput) ([]MatchResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []MatchResult

	for _, sig := range r.signatures {
		// Protocol filtering: skip if signature specifies protocols and input doesn't match
		if len(sig.def.Protocols) > 0 && !containsString(sig.def.Protocols, input.Protocol) {
			continue
		}

		var indicators []string
		var scores []float64

		// Evaluate regex patterns
		for _, cp := range sig.patterns {
			// Target filtering: skip if pattern target doesn't match input target
			if cp.target != "" && cp.target != input.Target {
				continue
			}

			if cp.re.MatchString(input.Content) {
				indicators = append(indicators, cp.re.String())
				scores = append(scores, cp.weight)
			}
		}

		// Evaluate entropy detection
		if sig.def.Entropy != nil && sig.def.Entropy.Enabled {
			ed := NewEntropyDetector(sig.def.Entropy.Threshold, sig.def.Entropy.Target)
			result := ed.Evaluate(input.Target, input.Content)
			if result.Flagged {
				indicators = append(indicators, "high_entropy")
				// Scale entropy score based on how far above threshold
				entropyScore := math.Min((result.Entropy-sig.def.Entropy.Threshold)/2.0, 1.0)
				scores = append(scores, entropyScore)
			}
		}

		// Evaluate base64 detection
		if sig.def.Base64 != nil && sig.def.Base64.Enabled {
			bd := NewBase64Detector(sig.def.Base64.MinLength, sig.def.Base64.Target)
			result := bd.Evaluate(input.Target, input.Content)
			if result.Flagged {
				indicators = append(indicators, "base64_payload")
				scores = append(scores, 0.6) // Standard weight for base64 detection
			}
		}

		// Only produce a result if at least one indicator matched
		if len(indicators) == 0 {
			continue
		}

		compositeScore := computeCompositeScore(scores)

		results = append(results, MatchResult{
			SignatureName: sig.def.Name,
			Category:      sig.def.Category,
			Severity:      sig.def.Severity,
			Score:         compositeScore,
			Indicators:    indicators,
			MitreAtlas:    sig.def.MitreAtlas,
		})
	}

	return results, nil
}

// SignatureCount returns the number of compiled signatures in the registry.
func (r *CompiledSignatureRegistry) SignatureCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.signatures)
}

// computeCompositeScore computes a composite score from individual scores.
// Uses max-of-all strategy with a small boost for multiple indicators.
func computeCompositeScore(scores []float64) float64 {
	if len(scores) == 0 {
		return 0
	}

	var maxScore float64
	for _, s := range scores {
		if s > maxScore {
			maxScore = s
		}
	}

	// Add a small boost (up to 0.1) for multiple indicators
	multiIndicatorBoost := math.Min(float64(len(scores)-1)*0.05, 0.1)

	result := maxScore + multiIndicatorBoost
	if result > 1.0 {
		result = 1.0
	}
	return result
}

// containsString checks if a string slice contains a value.
func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
