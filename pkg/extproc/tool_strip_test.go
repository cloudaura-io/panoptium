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

package extproc

import (
	"encoding/json"
	"testing"
)

// TestStripToolsFromBody_RemovesSingleTool verifies that stripping a single tool
// from a multi-tool request removes only that tool and preserves the rest.
func TestStripToolsFromBody_RemovesSingleTool(t *testing.T) {
	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file", "write_file"})

	result, err := stripToolsFromBody(body, []string{"bash"})
	if err != nil {
		t.Fatalf("stripToolsFromBody returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	tools, ok := parsed["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array in result")
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools after strip, got %d", len(tools))
	}

	// Verify remaining tool names
	names := extractToolNamesFromParsed(t, tools)
	if contains(names, "bash") {
		t.Error("expected 'bash' to be stripped, but it is still present")
	}
	if !contains(names, "read_file") {
		t.Error("expected 'read_file' to be preserved")
	}
	if !contains(names, "write_file") {
		t.Error("expected 'write_file' to be preserved")
	}
}

// TestStripToolsFromBody_RemovesMultipleTools verifies that multiple tools
// can be stripped in a single call.
func TestStripToolsFromBody_RemovesMultipleTools(t *testing.T) {
	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file", "write_file", "k8s_get_pod_logs"})

	result, err := stripToolsFromBody(body, []string{"bash", "k8s_get_pod_logs"})
	if err != nil {
		t.Fatalf("stripToolsFromBody returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	tools, ok := parsed["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array in result")
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools after strip, got %d", len(tools))
	}

	names := extractToolNamesFromParsed(t, tools)
	if contains(names, "bash") {
		t.Error("expected 'bash' to be stripped")
	}
	if contains(names, "k8s_get_pod_logs") {
		t.Error("expected 'k8s_get_pod_logs' to be stripped")
	}
	if !contains(names, "read_file") {
		t.Error("expected 'read_file' to be preserved")
	}
	if !contains(names, "write_file") {
		t.Error("expected 'write_file' to be preserved")
	}
}

// TestStripToolsFromBody_RemovesAllTools verifies that when all tools are
// stripped, the tools key and tool_choice key are removed from the body.
func TestStripToolsFromBody_RemovesAllTools(t *testing.T) {
	// Build a body with tool_choice
	body := makeOpenAIRequestBodyWithToolsAndChoice("gpt-4", false,
		[]string{"bash", "read_file"}, "auto")

	result, err := stripToolsFromBody(body, []string{"bash", "read_file"})
	if err != nil {
		t.Fatalf("stripToolsFromBody returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	if _, exists := parsed["tools"]; exists {
		t.Error("expected 'tools' key to be removed when all tools are stripped")
	}
	if _, exists := parsed["tool_choice"]; exists {
		t.Error("expected 'tool_choice' key to be removed when all tools are stripped")
	}
}

// TestStripToolsFromBody_EmptyToolsArray verifies graceful handling of an
// empty tools array input.
func TestStripToolsFromBody_EmptyToolsArray(t *testing.T) {
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"tools":[]}`)

	result, err := stripToolsFromBody(body, []string{"bash"})
	if err != nil {
		t.Fatalf("stripToolsFromBody returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	// Empty tools array after stripping should result in tools key removal
	if _, exists := parsed["tools"]; exists {
		t.Error("expected 'tools' key to be removed when tools array is empty")
	}
}

// TestStripToolsFromBody_PreservesOtherFields verifies that all non-tool
// fields (model, messages, stream, etc.) are preserved unchanged.
func TestStripToolsFromBody_PreservesOtherFields(t *testing.T) {
	body := makeOpenAIRequestBodyWithTools("gpt-4-turbo", true, []string{"bash", "read_file"})

	result, err := stripToolsFromBody(body, []string{"bash"})
	if err != nil {
		t.Fatalf("stripToolsFromBody returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	if parsed["model"] != "gpt-4-turbo" {
		t.Errorf("expected model 'gpt-4-turbo', got %v", parsed["model"])
	}
	if parsed["stream"] != true {
		t.Errorf("expected stream true, got %v", parsed["stream"])
	}
	msgs, ok := parsed["messages"].([]interface{})
	if !ok || len(msgs) == 0 {
		t.Fatal("expected messages array to be preserved")
	}
}

// TestStripToolsFromBody_OutputIsValidJSON verifies that the output is always
// valid JSON.
func TestStripToolsFromBody_OutputIsValidJSON(t *testing.T) {
	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file", "write_file"})

	result, err := stripToolsFromBody(body, []string{"read_file"})
	if err != nil {
		t.Fatalf("stripToolsFromBody returned error: %v", err)
	}

	if !json.Valid(result) {
		t.Fatal("output is not valid JSON")
	}
}

// TestStripToolsFromBody_NoToolsInBody verifies that a body without a tools
// field is returned unchanged.
func TestStripToolsFromBody_NoToolsInBody(t *testing.T) {
	body := makeOpenAIRequestBody("gpt-4", false) // no tools

	result, err := stripToolsFromBody(body, []string{"bash"})
	if err != nil {
		t.Fatalf("stripToolsFromBody returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	// Should still have model, messages, etc.
	if parsed["model"] != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %v", parsed["model"])
	}
}

// TestStripToolsFromBody_EmptyBannedList verifies that an empty banned list
// leaves the body unmodified.
func TestStripToolsFromBody_EmptyBannedList(t *testing.T) {
	body := makeOpenAIRequestBodyWithTools("gpt-4", false, []string{"bash", "read_file"})

	result, err := stripToolsFromBody(body, []string{})
	if err != nil {
		t.Fatalf("stripToolsFromBody returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	tools, ok := parsed["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array in result")
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools (unchanged), got %d", len(tools))
	}
}

// makeOpenAIRequestBodyWithToolsAndChoice creates a JSON request body with
// tools and tool_choice fields.
func makeOpenAIRequestBodyWithToolsAndChoice(model string, stream bool, toolNames []string, toolChoice string) []byte {
	tools := make([]map[string]interface{}, len(toolNames))
	for i, name := range toolNames {
		tools[i] = map[string]interface{}{
			"type": "function",
			"function": map[string]interface{}{
				"name":        name,
				"description": "Test tool " + name,
				"parameters": map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
		}
	}

	body := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": "Use the tool"},
		},
		"stream":      stream,
		"tools":       tools,
		"tool_choice": toolChoice,
	}
	data, _ := json.Marshal(body)
	return data
}

// extractToolNamesFromParsed extracts tool function names from a parsed tools array.
func extractToolNamesFromParsed(t *testing.T, tools []interface{}) []string {
	t.Helper()
	var names []string
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]interface{})
		if !ok {
			continue
		}
		fn, ok := toolMap["function"].(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := fn["name"].(string); ok {
			names = append(names, name)
		}
	}
	return names
}

// contains checks if a string slice contains a given value.
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
