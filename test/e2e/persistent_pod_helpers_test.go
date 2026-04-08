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

package e2e

import (
	"strings"
	"testing"
)

// TestPersistentPodNameGeneration verifies that createPersistentCurlPod
// generates RFC 1123-compliant pod names with the expected prefix.
func TestPersistentPodNameGeneration(t *testing.T) {
	// Verify the persistent pod name format used by the helper.
	// The name should start with "e2e-curl-" and contain a unique suffix.
	name := persistentCurlPodName("test-context")
	if !strings.HasPrefix(name, "e2e-curl-test-context-") {
		t.Errorf("expected name to start with 'e2e-curl-test-context-', got %q", name)
	}

	// Names should be RFC 1123 compliant (lowercase, alphanumeric + hyphens)
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			t.Errorf("pod name %q contains non-RFC-1123 character: %c", name, c)
		}
	}

	// Max length for pod names is 63 characters
	if len(name) > 63 {
		t.Errorf("pod name %q exceeds 63 character limit (len=%d)", name, len(name))
	}
}

// TestPersistentPodNameUniqueness verifies that subsequent calls produce
// different pod names.
func TestPersistentPodNameUniqueness(t *testing.T) {
	name1 := persistentCurlPodName("ctx")
	name2 := persistentCurlPodName("ctx")
	if name1 == name2 {
		t.Errorf("expected unique names, got identical: %q", name1)
	}
}

// TestBuildCurlExecArgs verifies that buildCurlExecArgs produces the expected
// kubectl exec command arguments for sending a tool call request through an
// existing persistent pod.
func TestBuildCurlExecArgs(t *testing.T) {
	args := buildCurlExecArgs("my-pod", "10.0.0.1", "dangerous_exec", nil)

	// Should start with "exec my-pod -n <namespace> --"
	if args[0] != "exec" {
		t.Errorf("expected first arg 'exec', got %q", args[0])
	}
	if args[1] != "my-pod" {
		t.Errorf("expected pod name 'my-pod', got %q", args[1])
	}

	// Should contain namespace flag
	found := false
	for i, a := range args {
		if a == "-n" && i+1 < len(args) && args[i+1] == namespace {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected namespace flag '-n %s' in args: %v", namespace, args)
	}

	// Should contain the gateway URL
	urlFound := false
	for _, a := range args {
		if strings.Contains(a, "10.0.0.1:8080") {
			urlFound = true
			break
		}
	}
	if !urlFound {
		t.Errorf("expected gateway URL with 10.0.0.1:8080 in args: %v", args)
	}

	// Should NOT contain agent-id header (identity is resolved via pod labels)
	for _, a := range args {
		if strings.Contains(a, "x-panoptium-agent-id") {
			t.Errorf("unexpected x-panoptium-agent-id header in args: %v", args)
			break
		}
	}

	// Should contain the tool name in the JSON payload
	payloadFound := false
	for _, a := range args {
		if strings.Contains(a, "dangerous_exec") {
			payloadFound = true
			break
		}
	}
	if !payloadFound {
		t.Errorf("expected tool name 'dangerous_exec' in payload args: %v", args)
	}
}

// TestBuildCurlExecArgsWithExtraHeaders verifies extra headers are included.
func TestBuildCurlExecArgsWithExtraHeaders(t *testing.T) {
	headers := map[string]string{
		"x-custom-header": "custom-value",
		"x-another":       "another-value",
	}
	args := buildCurlExecArgs("pod1", "10.0.0.1", "tool1", headers)

	customFound := false
	anotherFound := false
	for _, a := range args {
		if strings.Contains(a, "x-custom-header: custom-value") {
			customFound = true
		}
		if strings.Contains(a, "x-another: another-value") {
			anotherFound = true
		}
	}
	if !customFound {
		t.Errorf("expected x-custom-header in args: %v", args)
	}
	if !anotherFound {
		t.Errorf("expected x-another in args: %v", args)
	}
}

// TestParseExecResponse verifies the HTTP status code and body parsing from
// the kubectl exec curl output.
func TestParseExecResponse(t *testing.T) {
	tests := []struct {
		name           string
		output         string
		wantStatusCode int
		wantBody       string
		wantErr        bool
	}{
		{
			name: "standard 403 response",
			output: `{"error":"policy_violation","rule":"deny-exec","message":"blocked"}` +
				"\n---HTTP_STATUS_CODE:403---",
			wantStatusCode: 403,
			wantBody:       `{"error":"policy_violation","rule":"deny-exec","message":"blocked"}`,
			wantErr:        false,
		},
		{
			name:           "standard 200 response",
			output:         `{"model":"gpt-4","choices":[]}` + "\n---HTTP_STATUS_CODE:200---",
			wantStatusCode: 200,
			wantBody:       `{"model":"gpt-4","choices":[]}`,
			wantErr:        false,
		},
		{
			name:           "429 rate limited",
			output:         `{"error":"rate_limited","message":"exceeded","retry_after":30}` + "\n---HTTP_STATUS_CODE:429---",
			wantStatusCode: 429,
			wantBody:       `{"error":"rate_limited","message":"exceeded","retry_after":30}`,
			wantErr:        false,
		},
		{
			name:           "output without status code marker",
			output:         `some random output`,
			wantStatusCode: 0,
			wantBody:       `some random output`,
			wantErr:        false,
		},
		{
			name:           "empty output",
			output:         "",
			wantStatusCode: 0,
			wantBody:       "",
			wantErr:        false,
		},
		{
			name: "body with leading kubectl warnings",
			output: "W0402 warning message\n" +
				`{"error":"policy_violation","rule":"r1","message":"blocked"}` +
				"\n---HTTP_STATUS_CODE:403---",
			wantStatusCode: 403,
			wantBody:       `{"error":"policy_violation","rule":"r1","message":"blocked"}`,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusCode, body, err := parseExecResponse(tt.output)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if statusCode != tt.wantStatusCode {
				t.Errorf("statusCode = %d, want %d", statusCode, tt.wantStatusCode)
			}
			if body != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}
