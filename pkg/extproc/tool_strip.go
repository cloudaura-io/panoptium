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

import "encoding/json"

// stripToolsFromBody removes banned tools from the request body's tools[] array.
// If all tools are stripped, the "tools" and "tool_choice" keys are removed
// entirely so the request becomes a plain chat completion.
//
// The function preserves all other request body fields (model, messages, stream,
// etc.) and returns valid JSON.
//
// If bannedTools is empty or the body contains no "tools" key, the original
// body is returned unchanged.
func stripToolsFromBody(body []byte, bannedTools []string) ([]byte, error) {
	if len(bannedTools) == 0 {
		return body, nil
	}

	// Build a set for O(1) lookup
	banned := make(map[string]bool, len(bannedTools))
	for _, name := range bannedTools {
		banned[name] = true
	}

	// Parse into generic map to preserve all fields
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	toolsRaw, exists := raw["tools"]
	if !exists {
		return body, nil
	}

	// Parse the tools array
	var tools []json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return nil, err
	}

	// Filter tools: keep only those not in the banned set
	var kept []json.RawMessage
	for _, toolRaw := range tools {
		name := extractToolName(toolRaw)
		if name != "" && banned[name] {
			continue // stripped
		}
		kept = append(kept, toolRaw)
	}

	// If all tools were stripped (or array was already empty), remove keys
	if len(kept) == 0 {
		delete(raw, "tools")
		delete(raw, "tool_choice")
	} else {
		keptBytes, err := json.Marshal(kept)
		if err != nil {
			return nil, err
		}
		raw["tools"] = keptBytes
	}

	return json.Marshal(raw)
}

// extractToolName extracts the function name from a raw tool JSON object.
// Supports both OpenAI format (tools[].function.name) and Anthropic format
// (tools[].name).
func extractToolName(toolRaw json.RawMessage) string {
	// Try OpenAI format: {"type": "function", "function": {"name": "..."}}
	var openAI struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := json.Unmarshal(toolRaw, &openAI); err == nil && openAI.Function.Name != "" {
		return openAI.Function.Name
	}

	// Try Anthropic format: {"name": "...", "input_schema": {...}}
	var anthropic struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(toolRaw, &anthropic); err == nil && anthropic.Name != "" {
		return anthropic.Name
	}

	return ""
}
