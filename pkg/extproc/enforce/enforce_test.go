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

package enforce

import (
	"encoding/json"
	"testing"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

func TestNewImmediateResponse(t *testing.T) {
	resp := NewImmediateResponse(typev3.StatusCode_Forbidden, &ErrorResponse{
		Error:   "policy_violation",
		Rule:    "default/test-policy/rule-0",
		Message: "blocked by policy",
	})

	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse, got nil")
	}

	if ir.Status.Code != typev3.StatusCode_Forbidden {
		t.Errorf("expected status 403, got %d", ir.Status.Code)
	}

	var body ErrorResponse
	if err := json.Unmarshal(ir.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}

	if body.Error != "policy_violation" {
		t.Errorf("expected error type 'policy_violation', got %q", body.Error)
	}
	if body.Rule != "default/test-policy/rule-0" {
		t.Errorf("expected rule 'default/test-policy/rule-0', got %q", body.Rule)
	}
	if body.Message != "blocked by policy" {
		t.Errorf("expected message 'blocked by policy', got %q", body.Message)
	}

	// Verify content-type header is set
	if ir.Headers == nil || len(ir.Headers.SetHeaders) == 0 {
		t.Fatal("expected content-type header in response")
	}
	ctHeader := ir.Headers.SetHeaders[0]
	if ctHeader.Header.Key != "content-type" {
		t.Errorf("expected content-type header key, got %q", ctHeader.Header.Key)
	}
	if string(ctHeader.Header.RawValue) != "application/json" {
		t.Errorf("expected application/json, got %q", string(ctHeader.Header.RawValue))
	}
}

func TestNewDenyResponse(t *testing.T) {
	resp := NewDenyResponse("ns/policy/rule-0", "PAN-SIG-001", "tool call denied")

	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse, got nil")
	}
	if ir.Status.Code != typev3.StatusCode_Forbidden {
		t.Errorf("expected 403, got %d", ir.Status.Code)
	}

	var body ErrorResponse
	if err := json.Unmarshal(ir.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if body.Error != "policy_violation" {
		t.Errorf("expected 'policy_violation', got %q", body.Error)
	}
	if body.Signature != "PAN-SIG-001" {
		t.Errorf("expected signature 'PAN-SIG-001', got %q", body.Signature)
	}
}

func TestEnforcementModeConstants(t *testing.T) {
	if ModeEnforcing != "enforcing" {
		t.Errorf("expected ModeEnforcing='enforcing', got %q", ModeEnforcing)
	}
	if ModeAudit != "audit" {
		t.Errorf("expected ModeAudit='audit', got %q", ModeAudit)
	}
}
