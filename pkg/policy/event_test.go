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

package policy

import "testing"

// --- GetField Tests ---

func TestGetField_ExistingKey(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}
	got := e.GetField("processName")
	if got != "curl" {
		t.Errorf("GetField(\"processName\") = %v, want %q", got, "curl")
	}
}

func TestGetField_MissingKey(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}
	got := e.GetField("nonexistent")
	if got != nil {
		t.Errorf("GetField(\"nonexistent\") = %v, want nil", got)
	}
}

func TestGetField_NilFieldsMap(t *testing.T) {
	e := &PolicyEvent{
		Fields: nil,
	}
	got := e.GetField("anything")
	if got != nil {
		t.Errorf("GetField with nil Fields = %v, want nil", got)
	}
}

// --- GetStringField Tests ---

func TestGetStringField_StringValue(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"processName": "curl",
		},
	}
	got := e.GetStringField("processName")
	if got != "curl" {
		t.Errorf("GetStringField(\"processName\") = %q, want %q", got, "curl")
	}
}

func TestGetStringField_NonStringValue(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"pid": 1234,
		},
	}
	got := e.GetStringField("pid")
	if got != "" {
		t.Errorf("GetStringField(\"pid\") = %q, want empty string", got)
	}
}

func TestGetStringField_NilFieldsMap(t *testing.T) {
	e := &PolicyEvent{
		Fields: nil,
	}
	got := e.GetStringField("anything")
	if got != "" {
		t.Errorf("GetStringField with nil Fields = %q, want empty string", got)
	}
}

// --- GetIntField Tests ---

func TestGetIntField_IntValue(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"pid": 42,
		},
	}
	got := e.GetIntField("pid")
	if got != 42 {
		t.Errorf("GetIntField(\"pid\") = %d, want %d", got, 42)
	}
}

func TestGetIntField_Int64Value(t *testing.T) {
	// GetIntField only handles int type; int64 should return 0 per current implementation.
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"bigPid": int64(999),
		},
	}
	got := e.GetIntField("bigPid")
	if got != 0 {
		t.Errorf("GetIntField(\"bigPid\") with int64 = %d, want 0 (not handled by current impl)", got)
	}
}

func TestGetIntField_Float64Value(t *testing.T) {
	// GetIntField only handles int type; float64 should return 0 per current implementation.
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"score": float64(3.14),
		},
	}
	got := e.GetIntField("score")
	if got != 0 {
		t.Errorf("GetIntField(\"score\") with float64 = %d, want 0 (not handled by current impl)", got)
	}
}

func TestGetIntField_NonNumericValue(t *testing.T) {
	e := &PolicyEvent{
		Fields: map[string]interface{}{
			"name": "not-a-number",
		},
	}
	got := e.GetIntField("name")
	if got != 0 {
		t.Errorf("GetIntField(\"name\") = %d, want 0", got)
	}
}

func TestGetIntField_NilFieldsMap(t *testing.T) {
	e := &PolicyEvent{
		Fields: nil,
	}
	got := e.GetIntField("anything")
	if got != 0 {
		t.Errorf("GetIntField with nil Fields = %d, want 0", got)
	}
}

// --- DefaultAllowDecision Tests ---

func TestDefaultAllowDecision_ReturnsAllowAction(t *testing.T) {
	d := DefaultAllowDecision()
	if d.Action.Type != "allow" {
		t.Errorf("DefaultAllowDecision().Action.Type = %q, want %q", d.Action.Type, "allow")
	}
}

func TestDefaultAllowDecision_FieldValues(t *testing.T) {
	d := DefaultAllowDecision()
	if d.Matched {
		t.Error("DefaultAllowDecision().Matched = true, want false")
	}
	if d.MatchedRule != "" {
		t.Errorf("DefaultAllowDecision().MatchedRule = %q, want empty", d.MatchedRule)
	}
	if d.MatchedRuleIndex != -1 {
		t.Errorf("DefaultAllowDecision().MatchedRuleIndex = %d, want -1", d.MatchedRuleIndex)
	}
	if d.PolicyName != "" {
		t.Errorf("DefaultAllowDecision().PolicyName = %q, want empty", d.PolicyName)
	}
	if d.PolicyNamespace != "" {
		t.Errorf("DefaultAllowDecision().PolicyNamespace = %q, want empty", d.PolicyNamespace)
	}
	if d.Action.Parameters != nil {
		t.Errorf("DefaultAllowDecision().Action.Parameters = %v, want nil", d.Action.Parameters)
	}
}
