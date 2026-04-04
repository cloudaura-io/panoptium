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

func TestListMembershipEvaluator_InAllowlist(t *testing.T) {
	eval := &ListMembershipEvaluator{
		FieldPath: "toolName",
		Members:   map[string]struct{}{"read_file": {}, "list_dir": {}, "search": {}},
		Mode:      ListAllow,
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"toolName": "read_file",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for 'read_file' in allowlist")
	}
}

func TestListMembershipEvaluator_NotInAllowlist(t *testing.T) {
	eval := &ListMembershipEvaluator{
		FieldPath: "toolName",
		Members:   map[string]struct{}{"read_file": {}, "list_dir": {}, "search": {}},
		Mode:      ListAllow,
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
	if matched {
		t.Error("expected no match for 'execute_command' not in allowlist")
	}
}

func TestListMembershipEvaluator_InDenylist(t *testing.T) {
	eval := &ListMembershipEvaluator{
		FieldPath: "toolName",
		Members:   map[string]struct{}{"execute_command": {}, "write_file": {}, "delete_file": {}},
		Mode:      ListDeny,
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
		t.Error("expected match for 'execute_command' in denylist")
	}
}

func TestListMembershipEvaluator_NotInDenylist(t *testing.T) {
	eval := &ListMembershipEvaluator{
		FieldPath: "toolName",
		Members:   map[string]struct{}{"execute_command": {}, "write_file": {}, "delete_file": {}},
		Mode:      ListDeny,
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"toolName": "read_file",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for 'read_file' not in denylist")
	}
}

func TestListMembershipEvaluator_DestinationInList(t *testing.T) {
	eval := &ListMembershipEvaluator{
		FieldPath: "destinationHost",
		Members:   map[string]struct{}{"api.example.com": {}, "data.example.com": {}},
		Mode:      ListAllow,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationHost": "api.example.com",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for 'api.example.com' in destination list")
	}
}

func TestListMembershipEvaluator_EmptyList(t *testing.T) {
	eval := &ListMembershipEvaluator{
		FieldPath: "toolName",
		Members:   map[string]struct{}{},
		Mode:      ListAllow,
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields: map[string]interface{}{
			"toolName": "read_file",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match against empty list")
	}
}

func TestListMembershipEvaluator_MissingField(t *testing.T) {
	eval := &ListMembershipEvaluator{
		FieldPath: "toolName",
		Members:   map[string]struct{}{"read_file": {}},
		Mode:      ListAllow,
	}

	event := &policy.PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
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

func TestListMembershipEvaluator_ImplementsInterface(t *testing.T) {
	var _ PredicateEvaluator = (*ListMembershipEvaluator)(nil)
}

func TestConfigMapListResolver_ResolveEntries(t *testing.T) {
	resolver := &ConfigMapListResolver{
		Getter: func(namespace, name, key string) (string, error) {
			if namespace == "default" && name == "allowed-tools" && key == "tools" {
				return "read_file\nlist_dir\nsearch", nil
			}
			return "", &ConfigMapResolutionError{
				Namespace: namespace,
				Name:      name,
				Key:       key,
				Message:   "ConfigMap not found",
			}
		},
	}

	entries, err := resolver.Resolve("default", "allowed-tools", "tools")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]struct{}{
		"read_file": {},
		"list_dir":  {},
		"search":    {},
	}

	if len(entries) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(entries))
	}

	for k := range expected {
		if _, ok := entries[k]; !ok {
			t.Errorf("expected entry %q not found", k)
		}
	}
}

func TestConfigMapListResolver_MissingConfigMap(t *testing.T) {
	resolver := &ConfigMapListResolver{
		Getter: func(namespace, name, key string) (string, error) {
			return "", &ConfigMapResolutionError{
				Namespace: namespace,
				Name:      name,
				Key:       key,
				Message:   "ConfigMap not found",
			}
		},
	}

	_, err := resolver.Resolve("default", "missing-cm", "tools")
	if err == nil {
		t.Fatal("expected error for missing ConfigMap")
	}

	cmErr, ok := err.(*ConfigMapResolutionError)
	if !ok {
		t.Fatalf("expected *ConfigMapResolutionError, got %T", err)
	}

	if cmErr.Name != "missing-cm" {
		t.Errorf("expected Name 'missing-cm', got %q", cmErr.Name)
	}
}

func TestConfigMapListResolver_EmptyContent(t *testing.T) {
	resolver := &ConfigMapListResolver{
		Getter: func(namespace, name, key string) (string, error) {
			return "", nil
		},
	}

	entries, err := resolver.Resolve("default", "empty-cm", "tools")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty content, got %d", len(entries))
	}
}

func TestConfigMapListResolver_SkipsEmptyLines(t *testing.T) {
	resolver := &ConfigMapListResolver{
		Getter: func(namespace, name, key string) (string, error) {
			return "read_file\n\n\nlist_dir\n\n", nil
		},
	}

	entries, err := resolver.Resolve("default", "tools-cm", "tools")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries (skipping empty lines), got %d", len(entries))
	}
}

func TestConfigMapListResolver_TrimsWhitespace(t *testing.T) {
	resolver := &ConfigMapListResolver{
		Getter: func(namespace, name, key string) (string, error) {
			return "  read_file  \n  list_dir  ", nil
		},
	}

	entries, err := resolver.Resolve("default", "tools-cm", "tools")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := entries["read_file"]; !ok {
		t.Error("expected 'read_file' entry (trimmed)")
	}
	if _, ok := entries["list_dir"]; !ok {
		t.Error("expected 'list_dir' entry (trimmed)")
	}
}
