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
	"testing"
)

// TestMCPToolAuthorizer_AllowedToolPassesThrough verifies allowed tool passes through.
func TestMCPToolAuthorizer_AllowedToolPassesThrough(t *testing.T) {
	authorizer := NewMCPToolAuthorizer()
	authorizer.AddAllowPattern("read_file")
	authorizer.AddAllowPattern("write_file")

	result := authorizer.Authorize("read_file")
	if !result.Allowed {
		t.Error("Authorize(read_file) = denied, want allowed")
	}
	if result.ToolName != "read_file" {
		t.Errorf("ToolName = %q, want %q", result.ToolName, "read_file")
	}
}

// TestMCPToolAuthorizer_DeniedToolProducesDenyEvent verifies denied tool produces deny.
func TestMCPToolAuthorizer_DeniedToolProducesDenyEvent(t *testing.T) {
	authorizer := NewMCPToolAuthorizer()
	authorizer.AddAllowPattern("read_file")

	result := authorizer.Authorize("dangerous_exec")
	if result.Allowed {
		t.Error("Authorize(dangerous_exec) = allowed, want denied")
	}
	if result.ToolName != "dangerous_exec" {
		t.Errorf("ToolName = %q, want %q", result.ToolName, "dangerous_exec")
	}
	if result.Reason == "" {
		t.Error("Reason should not be empty for denied tool")
	}
}

// TestMCPToolAuthorizer_WildcardPattern verifies wildcard pattern matching.
func TestMCPToolAuthorizer_WildcardPattern(t *testing.T) {
	authorizer := NewMCPToolAuthorizer()
	authorizer.AddAllowPattern("fs_*")

	tests := []struct {
		tool    string
		allowed bool
	}{
		{"fs_read", true},
		{"fs_write", true},
		{"fs_delete", true},
		{"dangerous_exec", false},
		{"network_connect", false},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			result := authorizer.Authorize(tt.tool)
			if result.Allowed != tt.allowed {
				t.Errorf("Authorize(%q) = %v, want %v", tt.tool, result.Allowed, tt.allowed)
			}
		})
	}
}

// TestMCPToolAuthorizer_DenyPattern verifies explicit deny patterns override allow.
func TestMCPToolAuthorizer_DenyPattern(t *testing.T) {
	authorizer := NewMCPToolAuthorizer()
	authorizer.AddAllowPattern("fs_*")
	authorizer.AddDenyPattern("fs_delete")

	result := authorizer.Authorize("fs_read")
	if !result.Allowed {
		t.Error("Authorize(fs_read) = denied, want allowed")
	}

	result = authorizer.Authorize("fs_delete")
	if result.Allowed {
		t.Error("Authorize(fs_delete) = allowed, want denied (explicit deny)")
	}
}

// TestMCPToolAuthorizer_AllowAll verifies that "*" allows all tools.
func TestMCPToolAuthorizer_AllowAll(t *testing.T) {
	authorizer := NewMCPToolAuthorizer()
	authorizer.AddAllowPattern("*")

	result := authorizer.Authorize("anything_at_all")
	if !result.Allowed {
		t.Error("Authorize(*) = denied, want allowed for wildcard-all")
	}
}

// TestMCPToolAuthorizer_NoPatterns_DefaultDeny verifies default deny when no patterns configured.
func TestMCPToolAuthorizer_NoPatterns_DefaultDeny(t *testing.T) {
	authorizer := NewMCPToolAuthorizer()

	result := authorizer.Authorize("read_file")
	if result.Allowed {
		t.Error("Authorize with no patterns = allowed, want denied (default deny)")
	}
}

// TestMCPToolAuthorizer_MultipleAllowPatterns verifies multiple allow patterns.
func TestMCPToolAuthorizer_MultipleAllowPatterns(t *testing.T) {
	authorizer := NewMCPToolAuthorizer()
	authorizer.AddAllowPattern("fs_*")
	authorizer.AddAllowPattern("db_*")
	authorizer.AddAllowPattern("get_weather")

	tests := []struct {
		tool    string
		allowed bool
	}{
		{"fs_read", true},
		{"db_query", true},
		{"get_weather", true},
		{"exec_cmd", false},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			result := authorizer.Authorize(tt.tool)
			if result.Allowed != tt.allowed {
				t.Errorf("Authorize(%q) = %v, want %v", tt.tool, result.Allowed, tt.allowed)
			}
		})
	}
}
