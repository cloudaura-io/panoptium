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

package predicate

import (
	"testing"

	"github.com/panoptium/panoptium/pkg/policy"
)

// --- String Equality Evaluator Tests ---

func TestStringEqualityEvaluator_ExactMatch(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "processName",
		Value:     "curl",
		Mode:      MatchExact,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for processName == 'curl'")
	}
}

func TestStringEqualityEvaluator_ExactMatch_NoMatch(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "processName",
		Value:     "curl",
		Mode:      MatchExact,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"processName": "wget",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for processName == 'curl' when value is 'wget'")
	}
}

func TestStringEqualityEvaluator_MissingField(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "processName",
		Value:     "curl",
		Mode:      MatchExact,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match when field is missing")
	}
}

func TestStringEqualityEvaluator_NilFields(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "processName",
		Value:     "curl",
		Mode:      MatchExact,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match when Fields map is nil")
	}
}

// --- String Prefix Evaluator Tests ---

func TestStringEqualityEvaluator_Prefix(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "path",
		Value:     "/etc/",
		Mode:      MatchPrefix,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/etc/passwd",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for path prefix '/etc/'")
	}
}

func TestStringEqualityEvaluator_Prefix_NoMatch(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "path",
		Value:     "/etc/",
		Mode:      MatchPrefix,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/tmp/file.txt",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for path not starting with '/etc/'")
	}
}

// --- String Suffix Evaluator Tests ---

func TestStringEqualityEvaluator_Suffix(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "path",
		Value:     ".conf",
		Mode:      MatchSuffix,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/etc/nginx/nginx.conf",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for path suffix '.conf'")
	}
}

func TestStringEqualityEvaluator_Suffix_NoMatch(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "path",
		Value:     ".conf",
		Mode:      MatchSuffix,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/etc/nginx/nginx.log",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for path not ending with '.conf'")
	}
}

// --- Integer Comparison Evaluator Tests ---

func TestNumericComparisonEvaluator_Equal(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "destinationPort",
		Op:        OpEqual,
		Value:     443,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationPort": 443,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for destinationPort == 443")
	}
}

func TestNumericComparisonEvaluator_Equal_NoMatch(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "destinationPort",
		Op:        OpEqual,
		Value:     443,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationPort": 80,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for destinationPort == 443 when value is 80")
	}
}

func TestNumericComparisonEvaluator_GreaterThan(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "destinationPort",
		Op:        OpGreaterThan,
		Value:     1024,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationPort": 8080,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for destinationPort > 1024 when value is 8080")
	}
}

func TestNumericComparisonEvaluator_GreaterThan_Equal_NoMatch(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "destinationPort",
		Op:        OpGreaterThan,
		Value:     1024,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationPort": 1024,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for destinationPort > 1024 when value is exactly 1024")
	}
}

func TestNumericComparisonEvaluator_LessThan(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "tokenCount",
		Op:        OpLessThan,
		Value:     100,
	}

	event := &policy.PolicyEvent{
		Category:    "llm",
		Subcategory: "completion_receive",
		Fields: map[string]interface{}{
			"tokenCount": 50,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for tokenCount < 100 when value is 50")
	}
}

func TestNumericComparisonEvaluator_Between(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "tokenCount",
		Op:        OpBetween,
		Value:     100,
		UpperBound: 500,
	}

	event := &policy.PolicyEvent{
		Category:    "llm",
		Subcategory: "completion_receive",
		Fields: map[string]interface{}{
			"tokenCount": 250,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for tokenCount between 100 and 500 when value is 250")
	}
}

func TestNumericComparisonEvaluator_Between_BelowRange(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "tokenCount",
		Op:        OpBetween,
		Value:     100,
		UpperBound: 500,
	}

	event := &policy.PolicyEvent{
		Category:    "llm",
		Subcategory: "completion_receive",
		Fields: map[string]interface{}{
			"tokenCount": 50,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for tokenCount between 100 and 500 when value is 50")
	}
}

func TestNumericComparisonEvaluator_Between_AboveRange(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "tokenCount",
		Op:        OpBetween,
		Value:     100,
		UpperBound: 500,
	}

	event := &policy.PolicyEvent{
		Category:    "llm",
		Subcategory: "completion_receive",
		Fields: map[string]interface{}{
			"tokenCount": 600,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for tokenCount between 100 and 500 when value is 600")
	}
}

func TestNumericComparisonEvaluator_Int64Value(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "requestSize",
		Op:        OpGreaterThan,
		Value:     1024,
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"requestSize": int64(2048),
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for requestSize > 1024 when value is int64(2048)")
	}
}

func TestNumericComparisonEvaluator_Float64Value(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "confidence",
		Op:        OpGreaterThan,
		Value:     0.5,
	}

	event := &policy.PolicyEvent{
		Category:    "llm",
		Subcategory: "completion_receive",
		Fields: map[string]interface{}{
			"confidence": 0.9,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for confidence > 0.5 when value is 0.9")
	}
}

func TestNumericComparisonEvaluator_NonNumericField(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "processName",
		Op:        OpGreaterThan,
		Value:     100,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for non-numeric field")
	}
}

func TestNumericComparisonEvaluator_MissingField(t *testing.T) {
	eval := &NumericComparisonEvaluator{
		FieldPath: "destinationPort",
		Op:        OpEqual,
		Value:     443,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields:      map[string]interface{}{},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match when field is missing")
	}
}

// --- String Inequality (Negation) Tests ---

func TestStringEqualityEvaluator_ExactMatch_Negated(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "processName",
		Value:     "curl",
		Mode:      MatchExact,
		Negate:    true,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for negated processName == 'curl' when value is 'curl'")
	}
}

func TestStringEqualityEvaluator_ExactMatch_Negated_DifferentValue(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "processName",
		Value:     "curl",
		Mode:      MatchExact,
		Negate:    true,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"processName": "wget",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for negated processName == 'curl' when value is 'wget'")
	}
}

// --- Field Extraction from Different Event Types ---

func TestFieldExtractor_KernelEvent(t *testing.T) {
	extractor := &FieldExtractor{}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path":        "/etc/shadow",
			"processName": "cat",
			"pid":         1234,
		},
	}

	val := extractor.Extract("path", event)
	if val != "/etc/shadow" {
		t.Errorf("expected '/etc/shadow', got %v", val)
	}

	val = extractor.Extract("processName", event)
	if val != "cat" {
		t.Errorf("expected 'cat', got %v", val)
	}

	val = extractor.Extract("pid", event)
	if val != 1234 {
		t.Errorf("expected 1234, got %v", val)
	}
}

func TestFieldExtractor_NetworkEvent(t *testing.T) {
	extractor := &FieldExtractor{}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationIP":   "10.0.0.1",
			"destinationPort": 443,
			"protocol":        "TCP",
		},
	}

	val := extractor.Extract("destinationIP", event)
	if val != "10.0.0.1" {
		t.Errorf("expected '10.0.0.1', got %v", val)
	}

	val = extractor.Extract("destinationPort", event)
	if val != 443 {
		t.Errorf("expected 443, got %v", val)
	}
}

func TestFieldExtractor_ProtocolEvent(t *testing.T) {
	extractor := &FieldExtractor{}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"toolName":     "read_file",
			"arguments":    `{"path": "/etc/passwd"}`,
			"requestSize":  int64(256),
		},
	}

	val := extractor.Extract("toolName", event)
	if val != "read_file" {
		t.Errorf("expected 'read_file', got %v", val)
	}
}

func TestFieldExtractor_LLMEvent(t *testing.T) {
	extractor := &FieldExtractor{}

	event := &policy.PolicyEvent{
		Category:    "llm",
		Subcategory: "prompt_submit",
		Fields: map[string]interface{}{
			"tokenCount": 150,
			"model":      "gpt-4",
			"provider":   "openai",
		},
	}

	val := extractor.Extract("tokenCount", event)
	if val != 150 {
		t.Errorf("expected 150, got %v", val)
	}

	val = extractor.Extract("model", event)
	if val != "gpt-4" {
		t.Errorf("expected 'gpt-4', got %v", val)
	}
}

func TestFieldExtractor_LifecycleEvent(t *testing.T) {
	extractor := &FieldExtractor{}

	event := &policy.PolicyEvent{
		Category:    "lifecycle",
		Subcategory: "pod_start",
		Fields: map[string]interface{}{
			"containerName": "agent-worker",
			"image":         "myrepo/agent:v1",
		},
	}

	val := extractor.Extract("containerName", event)
	if val != "agent-worker" {
		t.Errorf("expected 'agent-worker', got %v", val)
	}
}

func TestFieldExtractor_MissingField(t *testing.T) {
	extractor := &FieldExtractor{}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{},
	}

	val := extractor.Extract("nonexistent", event)
	if val != nil {
		t.Errorf("expected nil for missing field, got %v", val)
	}
}

func TestFieldExtractor_NilFields(t *testing.T) {
	extractor := &FieldExtractor{}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
	}

	val := extractor.Extract("processName", event)
	if val != nil {
		t.Errorf("expected nil for nil Fields map, got %v", val)
	}
}

// --- PredicateEvaluator Interface Compliance ---

func TestStringEqualityEvaluator_ImplementsInterface(t *testing.T) {
	var _ PredicateEvaluator = (*StringEqualityEvaluator)(nil)
}

func TestNumericComparisonEvaluator_ImplementsInterface(t *testing.T) {
	var _ PredicateEvaluator = (*NumericComparisonEvaluator)(nil)
}

// --- Tool Name Equality (Protocol Layer) ---

func TestStringEqualityEvaluator_ToolName(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "toolName",
		Value:     "execute_command",
		Mode:      MatchExact,
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"toolName": "execute_command",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for toolName == 'execute_command'")
	}
}

// --- Non-String Field Coercion to String ---

func TestStringEqualityEvaluator_NonStringFieldCoercion(t *testing.T) {
	eval := &StringEqualityEvaluator{
		FieldPath: "destinationPort",
		Value:     "443",
		Mode:      MatchExact,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationPort": 443,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match when int field 443 is coerced to string '443'")
	}
}
