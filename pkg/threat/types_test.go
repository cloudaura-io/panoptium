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

package threat

import (
	"testing"
)

// TestSignatureDefinition_Fields verifies SignatureDefinition carries all spec fields.
func TestSignatureDefinition_Fields(t *testing.T) {
	sd := SignatureDefinition{
		Name:        "mcp-ignore-instructions",
		Protocols:   []string{"mcp"},
		Category:    "prompt_injection",
		Severity:    "critical",
		MitreAtlas:  "AML.T0051.001",
		Description: "Detects prompt injection attempts",
		Patterns: []PatternDef{
			{
				Regex:  `(?i)ignore\s+previous`,
				Weight: 0.9,
				Target: "tool_description",
			},
		},
		Entropy: &EntropyDef{
			Enabled:   true,
			Threshold: 4.5,
			Target:    "tool_description",
		},
		Base64: &Base64Def{
			Enabled:   true,
			MinLength: 20,
			Target:    "tool_description",
		},
		CELExpressions: []CELDef{
			{
				Expression: `size(content) > 2000`,
				Weight:     0.8,
			},
		},
	}

	if sd.Name != "mcp-ignore-instructions" {
		t.Errorf("Name = %q, want %q", sd.Name, "mcp-ignore-instructions")
	}
	if len(sd.Protocols) != 1 || sd.Protocols[0] != "mcp" {
		t.Errorf("Protocols = %v, want [mcp]", sd.Protocols)
	}
	if sd.Category != "prompt_injection" {
		t.Errorf("Category = %q, want %q", sd.Category, "prompt_injection")
	}
	if sd.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", sd.Severity, "critical")
	}
	if sd.MitreAtlas != "AML.T0051.001" {
		t.Errorf("MitreAtlas = %q, want %q", sd.MitreAtlas, "AML.T0051.001")
	}
	if sd.Description != "Detects prompt injection attempts" {
		t.Errorf("Description = %q, want %q", sd.Description, "Detects prompt injection attempts")
	}
	if len(sd.Patterns) != 1 {
		t.Fatalf("Patterns length = %d, want 1", len(sd.Patterns))
	}
	if sd.Patterns[0].Weight != 0.9 {
		t.Errorf("Pattern weight = %f, want 0.9", sd.Patterns[0].Weight)
	}
	if sd.Entropy == nil || !sd.Entropy.Enabled {
		t.Error("Entropy should be enabled")
	}
	if sd.Base64 == nil || !sd.Base64.Enabled {
		t.Error("Base64 should be enabled")
	}
	if len(sd.CELExpressions) != 1 {
		t.Fatalf("CELExpressions length = %d, want 1", len(sd.CELExpressions))
	}
}

// TestPatternDef_ValidTargets verifies valid target values.
func TestPatternDef_ValidTargets(t *testing.T) {
	validTargets := []string{"tool_description", "tool_args", "message_content", "body"}
	for _, target := range validTargets {
		pd := PatternDef{
			Regex:  `test`,
			Weight: 0.5,
			Target: target,
		}
		if pd.Target != target {
			t.Errorf("Target = %q, want %q", pd.Target, target)
		}
	}
}

// TestEntropyDef_Defaults verifies entropy definition defaults.
func TestEntropyDef_Defaults(t *testing.T) {
	ed := EntropyDef{
		Enabled:   true,
		Threshold: 4.5,
		Target:    "tool_description",
	}
	if !ed.Enabled {
		t.Error("Enabled should be true")
	}
	if ed.Threshold != 4.5 {
		t.Errorf("Threshold = %f, want 4.5", ed.Threshold)
	}
}

// TestBase64Def_Defaults verifies base64 definition defaults.
func TestBase64Def_Defaults(t *testing.T) {
	bd := Base64Def{
		Enabled:   true,
		MinLength: 20,
		Target:    "tool_description",
	}
	if !bd.Enabled {
		t.Error("Enabled should be true")
	}
	if bd.MinLength != 20 {
		t.Errorf("MinLength = %d, want 20", bd.MinLength)
	}
}

// TestCELDef_Fields verifies CEL definition fields.
func TestCELDef_Fields(t *testing.T) {
	cd := CELDef{
		Expression: `size(content) > 2000 && shannon_entropy(content) > 4.5`,
		Weight:     0.8,
	}
	if cd.Expression == "" {
		t.Error("Expression should not be empty")
	}
	if cd.Weight != 0.8 {
		t.Errorf("Weight = %f, want 0.8", cd.Weight)
	}
}
