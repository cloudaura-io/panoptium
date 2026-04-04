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

package action

import (
	"testing"
)

func TestPathRewriter_RewritesDeniedPath(t *testing.T) {
	rewriter := &PathRewriter{
		SafePaths: map[string]string{
			"/etc/shadow": "/tmp/safe-shadow.txt",
			"/etc/passwd": "/tmp/safe-passwd.txt",
		},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
		RuleName:   "block-etc",
	}

	fields := map[string]string{
		"path": "/etc/shadow",
	}

	ok, err := rewriter.Apply(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected fallback to succeed")
	}
	if fields["path"] != "/tmp/safe-shadow.txt" {
		t.Errorf("expected path rewritten to /tmp/safe-shadow.txt, got %q", fields["path"])
	}
}

func TestPathRewriter_NoSafeAlternative(t *testing.T) {
	rewriter := &PathRewriter{
		SafePaths: map[string]string{
			"/etc/shadow": "/tmp/safe-shadow.txt",
		},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
	}

	fields := map[string]string{
		"path": "/etc/hostname",
	}

	ok, err := rewriter.Apply(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected fallback to fail (no safe path for /etc/hostname)")
	}
}

func TestArgumentSanitizer_StripsFields(t *testing.T) {
	sanitizer := &ArgumentSanitizer{
		FieldsToStrip: []string{"password", "apiKey", "secret"},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
	}

	fields := map[string]string{
		"command":  "curl https://api.example.com",
		"password": "secret123",
		"apiKey":   "sk-abc123",
	}

	ok, err := sanitizer.Apply(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected fallback to succeed")
	}
	if _, exists := fields["password"]; exists {
		t.Error("expected password field to be stripped")
	}
	if _, exists := fields["apiKey"]; exists {
		t.Error("expected apiKey field to be stripped")
	}
	if fields["command"] != "curl https://api.example.com" {
		t.Error("expected command field to remain unchanged")
	}
}

func TestArgumentSanitizer_NoSensitiveFields(t *testing.T) {
	sanitizer := &ArgumentSanitizer{
		FieldsToStrip: []string{"password", "apiKey"},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
	}

	fields := map[string]string{
		"command": "ls -la",
	}

	ok, err := sanitizer.Apply(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected fallback to succeed (no sensitive fields to strip = safe)")
	}
}

func TestProviderSubstituter_SubstitutesEndpoint(t *testing.T) {
	sub := &ProviderSubstituter{
		EndpointMap: map[string]string{
			"https://api.openai.com/v1":    "https://sandbox.openai.com/v1",
			"https://api.anthropic.com/v1": "https://sandbox.anthropic.com/v1",
		},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
	}

	fields := map[string]string{
		"endpoint": "https://api.openai.com/v1",
	}

	ok, err := sub.Apply(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected fallback to succeed")
	}
	if fields["endpoint"] != "https://sandbox.openai.com/v1" {
		t.Errorf("expected endpoint substituted to sandbox, got %q", fields["endpoint"])
	}
}

func TestProviderSubstituter_NoMapping(t *testing.T) {
	sub := &ProviderSubstituter{
		EndpointMap: map[string]string{
			"https://api.openai.com/v1": "https://sandbox.openai.com/v1",
		},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
	}

	fields := map[string]string{
		"endpoint": "https://unknown.provider.com/v1",
	}

	ok, err := sub.Apply(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected fallback to fail (no mapping for endpoint)")
	}
}

func TestFallbackEngine_SuccessConvertsToAllow(t *testing.T) {
	engine := &FallbackEngine{
		Fallbacks: []FallbackFunction{
			&PathRewriter{
				SafePaths: map[string]string{
					"/etc/shadow": "/tmp/safe.txt",
				},
			},
		},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
		RuleName:   "block-etc",
	}

	fields := map[string]string{
		"path": "/etc/shadow",
	}

	modified, err := engine.TryFallbacks(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified.Permitted {
		t.Error("expected Permitted=true after successful fallback")
	}
	if modified.Annotations["fallback_applied"] != "true" {
		t.Error("expected fallback_applied annotation")
	}
}

func TestFallbackEngine_FailurePreservesDeny(t *testing.T) {
	engine := &FallbackEngine{
		Fallbacks: []FallbackFunction{
			&PathRewriter{
				SafePaths: map[string]string{},
			},
		},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
		RuleName:   "block-etc",
	}

	fields := map[string]string{
		"path": "/etc/hostname",
	}

	modified, err := engine.TryFallbacks(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified.Permitted {
		t.Error("expected Permitted=false when all fallbacks fail")
	}
}

func TestFallbackEngine_PipelineOrder(t *testing.T) {
	engine := &FallbackEngine{
		Fallbacks: []FallbackFunction{
			// First: try path rewrite (will fail for /etc/hostname)
			&PathRewriter{
				SafePaths: map[string]string{},
			},
			// Second: try sanitizer (will succeed)
			&ArgumentSanitizer{
				FieldsToStrip: []string{"secret"},
			},
		},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
	}

	fields := map[string]string{
		"path":   "/etc/hostname",
		"secret": "sensitive-data",
	}

	modified, err := engine.TryFallbacks(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !modified.Permitted {
		t.Error("expected Permitted=true (second fallback succeeded)")
	}
	if _, exists := fields["secret"]; exists {
		t.Error("expected secret field stripped by sanitizer")
	}
}

func TestFallbackEngine_EmptyFallbackList(t *testing.T) {
	engine := &FallbackEngine{
		Fallbacks: []FallbackFunction{},
	}

	result := &ActionResult{
		ActionType: "deny",
		Permitted:  false,
	}

	fields := map[string]string{}

	modified, err := engine.TryFallbacks(result, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified.Permitted {
		t.Error("expected Permitted=false with no fallbacks")
	}
}
