/*
Copyright 2026.

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

package threat_test

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/threat"
)

func TestSignatureDefinitionFromCRD_Full(t *testing.T) {
	sig := &v1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "prompt-injection-ignore-previous"},
		Spec: v1alpha1.ThreatSignatureSpec{
			Protocols:   []string{"anthropic", "openai"},
			Category:    "prompt_injection",
			Severity:    v1alpha1.SeverityHigh,
			MitreAtlas:  "AML.T0051.001",
			Description: "Classic ignore-previous prompt-injection attempt",
			Detection: v1alpha1.DetectionSpec{
				Patterns: []v1alpha1.PatternRule{
					{Regex: `(?i)ignore\s+previous`, Weight: 0.9, Target: "message_content"},
					{Regex: `(?i)disregard\s+all`, Weight: 0.8, Target: "message_content"},
				},
				Entropy: &v1alpha1.EntropyRule{
					Enabled:   true,
					Threshold: 4.5,
					Target:    "message_content",
				},
				Base64: &v1alpha1.Base64Rule{
					Enabled:   true,
					MinLength: 24,
					Target:    "tool_args",
				},
				CEL: []v1alpha1.CELRule{
					{Expression: `content.size() > 2000`, Weight: 0.2},
					{Expression: `metadata.tool_name == "system_override"`, Weight: 1.0},
				},
			},
		},
	}

	def := threat.SignatureDefinitionFromCRD(sig)

	if def.Name != "prompt-injection-ignore-previous" {
		t.Errorf("Name = %q, want prompt-injection-ignore-previous", def.Name)
	}
	if def.Category != "prompt_injection" {
		t.Errorf("Category = %q, want prompt_injection", def.Category)
	}
	if def.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", def.Severity)
	}
	if def.MitreAtlas != "AML.T0051.001" {
		t.Errorf("MitreAtlas = %q, want AML.T0051.001", def.MitreAtlas)
	}
	if def.Description != "Classic ignore-previous prompt-injection attempt" {
		t.Errorf("Description = %q, got unexpected value", def.Description)
	}
	wantProtos := []string{"anthropic", "openai"}
	if !reflect.DeepEqual(def.Protocols, wantProtos) {
		t.Errorf("Protocols = %v, want %v", def.Protocols, wantProtos)
	}

	if got := len(def.Patterns); got != 2 {
		t.Fatalf("len(Patterns) = %d, want 2", got)
	}
	wantPat0 := threat.PatternDef{Regex: `(?i)ignore\s+previous`, Weight: 0.9, Target: "message_content"}
	if def.Patterns[0] != wantPat0 {
		t.Errorf("Patterns[0] = %+v, want %+v", def.Patterns[0], wantPat0)
	}

	if def.Entropy == nil {
		t.Fatal("Entropy = nil, want non-nil")
	}
	wantEntropy := threat.EntropyDef{Enabled: true, Threshold: 4.5, Target: "message_content"}
	if *def.Entropy != wantEntropy {
		t.Errorf("Entropy = %+v, want %+v", *def.Entropy, wantEntropy)
	}

	if def.Base64 == nil {
		t.Fatal("Base64 = nil, want non-nil")
	}
	wantBase64 := threat.Base64Def{Enabled: true, MinLength: 24, Target: "tool_args"}
	if *def.Base64 != wantBase64 {
		t.Errorf("Base64 = %+v, want %+v", *def.Base64, wantBase64)
	}

	if got := len(def.CELExpressions); got != 2 {
		t.Fatalf("len(CELExpressions) = %d, want 2", got)
	}
	if def.CELExpressions[0].Expression != `content.size() > 2000` {
		t.Errorf("CELExpressions[0].Expression = %q", def.CELExpressions[0].Expression)
	}
	if def.CELExpressions[1].Weight != 1.0 {
		t.Errorf("CELExpressions[1].Weight = %v, want 1.0", def.CELExpressions[1].Weight)
	}
}

func TestSignatureDefinitionFromCRD_Minimal(t *testing.T) {
	sig := &v1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "minimal"},
		Spec: v1alpha1.ThreatSignatureSpec{
			Category:    "data_exfiltration",
			Severity:    v1alpha1.SeverityMedium,
			Description: "minimal signature",
			Detection: v1alpha1.DetectionSpec{
				Patterns: []v1alpha1.PatternRule{
					{Regex: `secret`, Weight: 1.0, Target: "body"},
				},
			},
		},
	}

	def := threat.SignatureDefinitionFromCRD(sig)

	if def.Name != "minimal" {
		t.Errorf("Name = %q, want minimal", def.Name)
	}
	if def.Entropy != nil {
		t.Errorf("Entropy = %+v, want nil", def.Entropy)
	}
	if def.Base64 != nil {
		t.Errorf("Base64 = %+v, want nil", def.Base64)
	}
	if len(def.CELExpressions) != 0 {
		t.Errorf("len(CELExpressions) = %d, want 0", len(def.CELExpressions))
	}
	if len(def.Protocols) != 0 {
		t.Errorf("len(Protocols) = %d, want 0", len(def.Protocols))
	}
	if len(def.Patterns) != 1 {
		t.Fatalf("len(Patterns) = %d, want 1", len(def.Patterns))
	}
}

func TestSignatureDefinitionFromCRD_NilInput(t *testing.T) {
	def := threat.SignatureDefinitionFromCRD(nil)
	if def.Name != "" {
		t.Errorf("Name = %q, want empty", def.Name)
	}
	if len(def.Patterns) != 0 {
		t.Errorf("len(Patterns) = %d, want 0", len(def.Patterns))
	}
}

func TestSignatureDefinitionFromCRD_RoundTripsThroughRegistry(t *testing.T) {
	sig := &v1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "roundtrip"},
		Spec: v1alpha1.ThreatSignatureSpec{
			Category:    "prompt_injection",
			Severity:    v1alpha1.SeverityHigh,
			Description: "roundtrip test",
			Detection: v1alpha1.DetectionSpec{
				Patterns: []v1alpha1.PatternRule{
					{Regex: `(?i)ignore previous`, Weight: 1.0, Target: "message_content"},
				},
			},
		},
	}

	registry := threat.NewCompiledSignatureRegistry()
	if err := registry.AddSignature(threat.SignatureDefinitionFromCRD(sig)); err != nil {
		t.Fatalf("AddSignature: %v", err)
	}
	if got := registry.SignatureCount(); got != 1 {
		t.Errorf("SignatureCount = %d, want 1", got)
	}
}
