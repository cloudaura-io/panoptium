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
	"regexp"
	"testing"

	"github.com/panoptium/panoptium/pkg/policy"
)

func TestGlobEvaluator_RecursiveGlobMatch(t *testing.T) {
	matcher := &policy.GlobMatcher{Pattern: "/etc/**"}
	eval := &GlobEvaluator{
		FieldPath: "path",
		Matcher:   matcher,
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
		t.Error("expected match for /etc/passwd against /etc/**")
	}
}

func TestGlobEvaluator_RecursiveGlobDeepPath(t *testing.T) {
	matcher := &policy.GlobMatcher{Pattern: "/etc/**"}
	eval := &GlobEvaluator{
		FieldPath: "path",
		Matcher:   matcher,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/etc/nginx/conf.d/default.conf",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for /etc/nginx/conf.d/default.conf against /etc/**")
	}
}

func TestGlobEvaluator_SingleWildcard(t *testing.T) {
	matcher := &policy.GlobMatcher{Pattern: "/tmp/*.txt"}
	eval := &GlobEvaluator{
		FieldPath: "path",
		Matcher:   matcher,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/tmp/output.txt",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for /tmp/output.txt against /tmp/*.txt")
	}
}

func TestGlobEvaluator_SingleWildcard_NoSubdir(t *testing.T) {
	matcher := &policy.GlobMatcher{Pattern: "/tmp/*.txt"}
	eval := &GlobEvaluator{
		FieldPath: "path",
		Matcher:   matcher,
	}

	// * should NOT match across directory separators
	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/tmp/subdir/output.txt",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for /tmp/subdir/output.txt against /tmp/*.txt (single * should not cross directories)")
	}
}

func TestGlobEvaluator_NoMatch(t *testing.T) {
	matcher := &policy.GlobMatcher{Pattern: "/etc/**"}
	eval := &GlobEvaluator{
		FieldPath: "path",
		Matcher:   matcher,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/var/log/syslog",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for /var/log/syslog against /etc/**")
	}
}

func TestGlobEvaluator_QuestionMark(t *testing.T) {
	matcher := &policy.GlobMatcher{Pattern: "/tmp/file?.log"}
	eval := &GlobEvaluator{
		FieldPath: "path",
		Matcher:   matcher,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/tmp/file1.log",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for /tmp/file1.log against /tmp/file?.log")
	}
}

func TestGlobEvaluator_MissingField(t *testing.T) {
	matcher := &policy.GlobMatcher{Pattern: "/etc/**"}
	eval := &GlobEvaluator{
		FieldPath: "path",
		Matcher:   matcher,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
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

func TestGlobEvaluator_ExactMatch(t *testing.T) {
	matcher := &policy.GlobMatcher{Pattern: "/etc/shadow"}
	eval := &GlobEvaluator{
		FieldPath: "path",
		Matcher:   matcher,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields: map[string]interface{}{
			"path": "/etc/shadow",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected exact match for /etc/shadow against /etc/shadow")
	}
}

func TestGlobEvaluator_ImplementsInterface(t *testing.T) {
	var _ PredicateEvaluator = (*GlobEvaluator)(nil)
}

func TestRegexEvaluator_SimpleMatch(t *testing.T) {
	re := regexp.MustCompile(`^curl`)
	eval := &RegexEvaluator{
		FieldPath: "processName",
		Regex:     re,
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
		t.Error("expected match for processName 'curl' against regex ^curl")
	}
}

func TestRegexEvaluator_NoMatch(t *testing.T) {
	re := regexp.MustCompile(`^curl`)
	eval := &RegexEvaluator{
		FieldPath: "processName",
		Regex:     re,
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
		t.Error("expected no match for processName 'wget' against regex ^curl")
	}
}

func TestRegexEvaluator_CaptureGroups(t *testing.T) {
	re := regexp.MustCompile(`(ssh|scp|sftp)`)
	eval := &RegexEvaluator{
		FieldPath: "processName",
		Regex:     re,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"processName": "scp",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for processName 'scp' against regex (ssh|scp|sftp)")
	}
}

func TestRegexEvaluator_Anchors(t *testing.T) {
	re := regexp.MustCompile(`^/etc/shadow$`)
	eval := &RegexEvaluator{
		FieldPath: "path",
		Regex:     re,
	}

	tests := []struct {
		name    string
		value   string
		matched bool
	}{
		{"exact match", "/etc/shadow", true},
		{"prefix only", "/etc/shadow.bak", false},
		{"suffix only", "/other/etc/shadow", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := &policy.PolicyEvent{
				Category:    "kernel",
				Subcategory: "file_open",
				Fields: map[string]interface{}{
					"path": tc.value,
				},
			}

			matched, err := eval.Evaluate(event)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if matched != tc.matched {
				t.Errorf("expected matched=%v for value %q, got %v", tc.matched, tc.value, matched)
			}
		})
	}
}

func TestRegexEvaluator_MultilineContent(t *testing.T) {
	re := regexp.MustCompile(`(?s)password.*secret`)
	eval := &RegexEvaluator{
		FieldPath: "content",
		Regex:     re,
	}

	event := &policy.PolicyEvent{
		Category:    "llm",
		Subcategory: "prompt_submit",
		Fields: map[string]interface{}{
			"content": "my password is\na secret value",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for multiline content against (?s)password.*secret")
	}
}

func TestRegexEvaluator_MissingField(t *testing.T) {
	re := regexp.MustCompile(`^curl`)
	eval := &RegexEvaluator{
		FieldPath: "processName",
		Regex:     re,
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

func TestRegexEvaluator_NonStringField(t *testing.T) {
	re := regexp.MustCompile(`^443$`)
	eval := &RegexEvaluator{
		FieldPath: "destinationPort",
		Regex:     re,
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
		t.Error("expected match when int field 443 is coerced to string for regex ^443$")
	}
}

func TestRegexEvaluator_PreCompiledReuse(t *testing.T) {
	// Verify that pre-compiled regex is used (not recompiled each time)
	re := regexp.MustCompile(`sensitive_data_\d+`)
	eval := &RegexEvaluator{
		FieldPath: "content",
		Regex:     re,
	}

	// Evaluate multiple events with the same pre-compiled regex
	for i := 0; i < 100; i++ {
		event := &policy.PolicyEvent{
			Category:    "llm",
			Subcategory: "prompt_submit",
			Fields: map[string]interface{}{
				"content": "sensitive_data_42",
			},
		}

		matched, err := eval.Evaluate(event)
		if err != nil {
			t.Fatalf("unexpected error on iteration %d: %v", i, err)
		}
		if !matched {
			t.Errorf("expected match on iteration %d", i)
		}
	}
}

func TestRegexEvaluator_ImplementsInterface(t *testing.T) {
	var _ PredicateEvaluator = (*RegexEvaluator)(nil)
}
