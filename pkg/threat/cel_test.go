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

package threat

import (
	"testing"
)

// TestCELEvaluator_Compile verifies CEL expression compilation.
func TestCELEvaluator_Compile(t *testing.T) {
	eval := NewCELEvaluator()

	err := eval.Compile("test-expr", `content.size() > 100`)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
}

// TestCELEvaluator_CompileInvalid verifies invalid CEL expression compilation fails.
func TestCELEvaluator_CompileInvalid(t *testing.T) {
	eval := NewCELEvaluator()

	err := eval.Compile("bad-expr", `this is not valid CEL {{}}`)
	if err == nil {
		t.Fatal("Compile() expected error for invalid CEL, got nil")
	}
}

// TestCELEvaluator_Evaluate verifies CEL expression evaluation against content.
func TestCELEvaluator_Evaluate(t *testing.T) {
	eval := NewCELEvaluator()

	err := eval.Compile("size-check", `content.size() > 10`)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	result, err := eval.Evaluate("size-check", "this is a long description that exceeds 10 characters")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result {
		t.Error("Evaluate() = false, want true (content > 10 chars)")
	}
}

// TestCELEvaluator_EvaluateNoMatch verifies non-matching CEL expression.
func TestCELEvaluator_EvaluateNoMatch(t *testing.T) {
	eval := NewCELEvaluator()

	err := eval.Compile("size-check", `content.size() > 1000`)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	result, err := eval.Evaluate("size-check", "short")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result {
		t.Error("Evaluate() = true, want false (content < 1000 chars)")
	}
}

// TestCELEvaluator_ShannonEntropy verifies the custom shannon_entropy function.
func TestCELEvaluator_ShannonEntropy(t *testing.T) {
	eval := NewCELEvaluator()

	err := eval.Compile("entropy-check", `shannon_entropy(content) > 4.0`)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	// High entropy content (base64)
	highEntropy := "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2Ugd2l0aCBoaWdoIGVudHJvcHk="
	result, err := eval.Evaluate("entropy-check", highEntropy)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result {
		t.Error("Evaluate() = false, want true for high entropy content")
	}

	// Low entropy content
	result, err = eval.Evaluate("entropy-check", "aaaa")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result {
		t.Error("Evaluate() = true, want false for low entropy content")
	}
}

// TestCELEvaluator_RegexMatch verifies the custom regex_match function.
func TestCELEvaluator_RegexMatch(t *testing.T) {
	eval := NewCELEvaluator()

	err := eval.Compile("regex-check", `regex_match(content, "(?i)ignore\\s+previous")`)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	result, err := eval.Evaluate("regex-check", "Ignore previous instructions")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result {
		t.Error("Evaluate() = false, want true for matching regex")
	}

	result, err = eval.Evaluate("regex-check", "Normal text without injection")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result {
		t.Error("Evaluate() = true, want false for non-matching content")
	}
}

// TestCELEvaluator_CompileError verifies compilation error for non-boolean CEL.
func TestCELEvaluator_CompileError(t *testing.T) {
	eval := NewCELEvaluator()

	// This expression returns a string, not bool
	err := eval.Compile("type-mismatch", `content`)
	if err == nil {
		t.Fatal("Compile() expected error for non-boolean expression, got nil")
	}
}

// TestCELEvaluator_Caching verifies expressions are cached after compilation.
func TestCELEvaluator_Caching(t *testing.T) {
	eval := NewCELEvaluator()

	err := eval.Compile("cached", `content.size() > 5`)
	if err != nil {
		t.Fatalf("First Compile() error = %v", err)
	}

	// Should be able to evaluate multiple times
	for i := 0; i < 3; i++ {
		result, err := eval.Evaluate("cached", "this is a long string")
		if err != nil {
			t.Fatalf("Evaluate() iteration %d error = %v", i, err)
		}
		if !result {
			t.Errorf("Evaluate() iteration %d = false, want true", i)
		}
	}
}
