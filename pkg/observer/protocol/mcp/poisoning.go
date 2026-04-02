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
	"sync"

	"github.com/panoptium/panoptium/pkg/threat"
)

// Sensitivity levels for tool poisoning detection.
// Retained for API compatibility; detection is now fully driven by CRD-based
// threat signatures via the ThreatMatcher interface.
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

// ToolPoisoningDetector analyzes MCP tool descriptions for poisoning indicators
// by delegating to CRD-driven threat signatures via the ThreatMatcher interface.
// All detection logic is defined by PanoptiumThreatSignature CRDs; there are no
// hardcoded patterns.
type ToolPoisoningDetector struct {
	sensitivity string

	mu               sync.RWMutex
	threatMatcher    threat.ThreatMatcher
	lastMatchResults []threat.MatchResult
}

// NewToolPoisoningDetector creates a new detector with the given sensitivity level.
// The sensitivity parameter is retained for API compatibility but detection is
// fully driven by the ThreatMatcher. Call SetThreatMatcher to enable detection.
func NewToolPoisoningDetector(sensitivity string) *ToolPoisoningDetector {
	if sensitivity != SensitivityLow && sensitivity != SensitivityMedium && sensitivity != SensitivityHigh {
		sensitivity = SensitivityMedium
	}
	return &ToolPoisoningDetector{
		sensitivity: sensitivity,
	}
}

// SetThreatMatcher sets the CRD-driven ThreatMatcher for detection.
// Detection only works when a ThreatMatcher is configured.
func (d *ToolPoisoningDetector) SetThreatMatcher(matcher threat.ThreatMatcher) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.threatMatcher = matcher
}

// LastMatchResults returns the MatchResults from the most recent Analyze call.
// Returns nil if no ThreatMatcher is set or no match occurred.
func (d *ToolPoisoningDetector) LastMatchResults() []threat.MatchResult {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastMatchResults
}

// Analyze performs poisoning analysis on a tool description by delegating to the
// configured ThreatMatcher. Returns a zero-score result if no ThreatMatcher is set.
func (d *ToolPoisoningDetector) Analyze(toolName, description string) PoisoningResult {
	d.mu.RLock()
	matcher := d.threatMatcher
	d.mu.RUnlock()

	if matcher == nil {
		return PoisoningResult{Score: 0}
	}

	results, err := matcher.Match(context.Background(), threat.MatchInput{
		Protocol: "mcp",
		Target:   "tool_description",
		Content:  description,
		Metadata: map[string]any{"tool_name": toolName},
	})
	if err != nil {
		return PoisoningResult{Score: 0}
	}

	// Store match results for later retrieval
	d.mu.Lock()
	d.lastMatchResults = results
	d.mu.Unlock()

	if len(results) == 0 {
		return PoisoningResult{Score: 0}
	}

	// Convert MatchResults to PoisoningResult
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
