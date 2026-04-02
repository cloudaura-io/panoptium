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

package mcp

import (
	"context"
	"encoding/base64"
	"math"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/panoptium/panoptium/pkg/threat"
)

// Sensitivity levels for tool poisoning detection.
const (
	// SensitivityLow only flags high-confidence matches.
	SensitivityLow = "low"

	// SensitivityMedium is the default sensitivity level.
	SensitivityMedium = "medium"

	// SensitivityHigh flags all anomalies.
	SensitivityHigh = "high"
)

// PoisoningResult contains the results of tool poisoning analysis.
type PoisoningResult struct {
	// Score is the composite poisoning score (0.0-1.0).
	Score float32

	// Indicators lists the matched poisoning patterns.
	Indicators []string
}

// injectionPattern defines a known injection pattern with its regex and weight.
type injectionPattern struct {
	name    string
	pattern *regexp.Regexp
	weight  float32
}

// knownInjectionPatterns contains all known tool description injection patterns.
var knownInjectionPatterns = []injectionPattern{
	{
		name:    "ignore_instructions",
		pattern: regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`),
		weight:  0.9,
	},
	{
		name:    "role_confusion",
		pattern: regexp.MustCompile(`(?i)you\s+are\s+now\b`),
		weight:  0.9,
	},
	{
		name:    "delimiter_injection_xml",
		pattern: regexp.MustCompile(`(?i)</(tool_description|system|instructions|prompt)>`),
		weight:  0.85,
	},
	{
		name:    "delimiter_injection_open",
		pattern: regexp.MustCompile(`(?i)<(system|instructions|prompt)>`),
		weight:  0.85,
	},
	{
		name:    "system_prompt_ref",
		pattern: regexp.MustCompile(`(?i)system\s+prompt`),
		weight:  0.4,
	},
	{
		name:    "output_exfiltrate",
		pattern: regexp.MustCompile(`(?i)(output|print|display|reveal|show)\s+(all\s+)?(system\s+)?(secrets?|keys?|passwords?|credentials?|tokens?)`),
		weight:  0.85,
	},
	{
		name:    "instruction_override",
		pattern: regexp.MustCompile(`(?i)(disregard|forget|override)\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|constraints?)`),
		weight:  0.9,
	},
}

// ToolPoisoningDetector analyzes MCP tool descriptions for poisoning indicators
// including injection patterns, high entropy, base64 payloads, and description
// deviations from known-good metadata. When a ThreatMatcher is set, it delegates
// detection to CRD-driven signatures while maintaining backward compatibility.
type ToolPoisoningDetector struct {
	sensitivity string

	mu               sync.RWMutex
	knownGood        map[string]string // tool name -> known-good description
	threatMatcher    threat.ThreatMatcher
	lastMatchResults []threat.MatchResult
}

// NewToolPoisoningDetector creates a new detector with the given sensitivity level.
func NewToolPoisoningDetector(sensitivity string) *ToolPoisoningDetector {
	if sensitivity != SensitivityLow && sensitivity != SensitivityMedium && sensitivity != SensitivityHigh {
		sensitivity = SensitivityMedium
	}
	return &ToolPoisoningDetector{
		sensitivity: sensitivity,
		knownGood:   make(map[string]string),
	}
}

// SetThreatMatcher sets the CRD-driven ThreatMatcher for delegation.
// When set, Analyze delegates to the ThreatMatcher for primary detection.
func (d *ToolPoisoningDetector) SetThreatMatcher(matcher threat.ThreatMatcher) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.threatMatcher = matcher
}

// LastMatchResults returns the MatchResults from the most recent Analyze call
// when a ThreatMatcher is configured. Returns nil if no ThreatMatcher is set
// or no match occurred.
func (d *ToolPoisoningDetector) LastMatchResults() []threat.MatchResult {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastMatchResults
}

// SetKnownGood registers a known-good description for a tool (from ConfigMap).
func (d *ToolPoisoningDetector) SetKnownGood(toolName, description string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.knownGood[toolName] = description
}

// Analyze performs composite poisoning analysis on a tool description.
// Returns a PoisoningResult with a score (0.0-1.0) and matched indicators.
// When a ThreatMatcher is set, delegates to CRD-driven signatures.
func (d *ToolPoisoningDetector) Analyze(toolName, description string) PoisoningResult {
	d.mu.RLock()
	matcher := d.threatMatcher
	d.mu.RUnlock()

	// Delegate to ThreatMatcher when available
	if matcher != nil {
		return d.analyzeWithThreatMatcher(matcher, toolName, description)
	}

	return d.analyzeWithHardcoded(toolName, description)
}

// analyzeWithThreatMatcher delegates detection to the CRD-driven ThreatMatcher.
func (d *ToolPoisoningDetector) analyzeWithThreatMatcher(matcher threat.ThreatMatcher, toolName, description string) PoisoningResult {
	results, err := matcher.Match(context.Background(), threat.MatchInput{
		Protocol: "mcp",
		Target:   "tool_description",
		Content:  description,
		Metadata: map[string]any{"tool_name": toolName},
	})
	if err != nil {
		// Fall back to hardcoded on error
		return d.analyzeWithHardcoded(toolName, description)
	}

	// Store match results for later retrieval
	d.mu.Lock()
	d.lastMatchResults = results
	d.mu.Unlock()

	if len(results) == 0 {
		return PoisoningResult{Score: 0}
	}

	// Convert MatchResults to PoisoningResult (backward-compatible)
	var indicators []string
	var maxScore float64
	for _, r := range results {
		indicators = append(indicators, r.Indicators...)
		if r.Score > maxScore {
			maxScore = r.Score
		}
	}

	return PoisoningResult{
		Score:      float32(maxScore),
		Indicators: indicators,
	}
}

// analyzeWithHardcoded performs the original hardcoded pattern detection.
func (d *ToolPoisoningDetector) analyzeWithHardcoded(toolName, description string) PoisoningResult {
	var indicators []string
	var scores []float32

	// 1. Pattern matching — always run regardless of sensitivity
	for _, pat := range knownInjectionPatterns {
		if pat.pattern.MatchString(description) {
			indicators = append(indicators, pat.name)
			scores = append(scores, pat.weight)
		}
	}

	// 2. Base64 payload detection
	if detectBase64Payload(description) {
		indicators = append(indicators, "base64_payload")
		scores = append(scores, 0.6)
	}

	// 3. Entropy analysis (sensitivity-dependent threshold)
	entropyThreshold := d.entropyThreshold()
	entropy := ShannonEntropy(description)
	if entropy > entropyThreshold && len(description) > 50 {
		indicators = append(indicators, "high_entropy")
		// Scale entropy score: the higher above threshold, the more suspicious
		entropyScore := float32(math.Min(float64((entropy-entropyThreshold)/2.0), 1.0))
		scores = append(scores, entropyScore)
	}

	// 4. Diff comparison against known-good
	d.mu.RLock()
	knownDesc, hasKnown := d.knownGood[toolName]
	d.mu.RUnlock()

	if hasKnown && description != knownDesc {
		// Calculate similarity ratio
		similarity := stringSimilarity(knownDesc, description)
		if similarity < 0.8 {
			indicators = append(indicators, "description_deviation")
			deviationScore := float32(1.0-similarity) * 0.7
			scores = append(scores, deviationScore)
		}
	}

	// Compute composite score
	compositeScore := computeCompositeScore(scores)

	// Apply sensitivity scaling
	compositeScore = d.applySensitivity(compositeScore)

	return PoisoningResult{
		Score:      compositeScore,
		Indicators: indicators,
	}
}

// entropyThreshold returns the entropy threshold based on sensitivity.
func (d *ToolPoisoningDetector) entropyThreshold() float64 {
	switch d.sensitivity {
	case SensitivityLow:
		return 5.5
	case SensitivityHigh:
		return 4.0
	default: // medium
		return 4.5
	}
}

// applySensitivity adjusts the score based on sensitivity level.
func (d *ToolPoisoningDetector) applySensitivity(score float32) float32 {
	switch d.sensitivity {
	case SensitivityLow:
		// Only report high-confidence scores
		if score < 0.6 {
			score *= 0.5
		}
	case SensitivityHigh:
		// Amplify all anomalies
		if score > 0.1 {
			score = float32(math.Min(float64(score*1.3), 1.0))
		}
	}
	return score
}

// computeCompositeScore computes a composite score from individual scores.
// Uses max-of-all strategy with a small boost for multiple indicators.
func computeCompositeScore(scores []float32) float32 {
	if len(scores) == 0 {
		return 0
	}

	var maxScore float32
	var sum float32
	for _, s := range scores {
		if s > maxScore {
			maxScore = s
		}
		sum += s
	}

	// Add a small boost (up to 0.1) for multiple indicators
	multiIndicatorBoost := float32(math.Min(float64(len(scores)-1)*0.05, 0.1))

	result := maxScore + multiIndicatorBoost
	if result > 1.0 {
		result = 1.0
	}
	return result
}

// ShannonEntropy computes the Shannon entropy of a string in bits per character.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// detectBase64Payload checks if the description contains what appears to be
// base64-encoded content (long runs of base64-alphabet characters).
func detectBase64Payload(text string) bool {
	// Look for long base64 strings (>20 chars) that are valid base64
	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	matches := base64Pattern.FindAllString(text, -1)

	for _, match := range matches {
		// Try to decode — if it decodes to valid UTF-8, it's suspicious
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err == nil && utf8.Valid(decoded) && len(decoded) > 10 {
			return true
		}
		// Also try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(match)
		if err == nil && utf8.Valid(decoded) && len(decoded) > 10 {
			return true
		}
	}

	return false
}

// stringSimilarity computes a simple Jaccard-like word overlap similarity (0.0-1.0).
func stringSimilarity(a, b string) float64 {
	wordsA := strings.Fields(strings.ToLower(a))
	wordsB := strings.Fields(strings.ToLower(b))

	if len(wordsA) == 0 && len(wordsB) == 0 {
		return 1.0
	}

	setA := make(map[string]bool, len(wordsA))
	for _, w := range wordsA {
		setA[w] = true
	}

	setB := make(map[string]bool, len(wordsB))
	for _, w := range wordsB {
		setB[w] = true
	}

	// Intersection
	var intersection int
	for w := range setA {
		if setB[w] {
			intersection++
		}
	}

	// Union
	union := make(map[string]bool)
	for w := range setA {
		union[w] = true
	}
	for w := range setB {
		union[w] = true
	}

	if len(union) == 0 {
		return 1.0
	}

	return float64(intersection) / float64(len(union))
}
