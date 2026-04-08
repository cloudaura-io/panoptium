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

// highEntropyBase64 is a base64-encoded string used across multiple tests.
const highEntropyBase64 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2Ugd2l0aCBoaWdoIGVudHJvcHk="

// TestShannonEntropy_Empty verifies entropy of empty string is 0.
func TestShannonEntropy_Empty(t *testing.T) {
	e := ShannonEntropy("")
	if e != 0 {
		t.Errorf("ShannonEntropy(\"\") = %f, want 0", e)
	}
}

// TestShannonEntropy_SingleChar verifies entropy of repeated single char is 0.
func TestShannonEntropy_SingleChar(t *testing.T) {
	e := ShannonEntropy("aaaa")
	if e != 0 {
		t.Errorf("ShannonEntropy(\"aaaa\") = %f, want 0", e)
	}
}

// TestShannonEntropy_HighEntropy verifies high entropy for base64-like content.
func TestShannonEntropy_HighEntropy(t *testing.T) {
	text := highEntropyBase64
	e := ShannonEntropy(text)
	if e < 4.0 {
		t.Errorf("ShannonEntropy(base64) = %f, want >= 4.0", e)
	}
}

// TestShannonEntropy_NormalText verifies normal English has moderate entropy.
func TestShannonEntropy_NormalText(t *testing.T) {
	text := "Reads a file from the filesystem given a path"
	e := ShannonEntropy(text)
	if e < 2.0 || e > 6.0 {
		t.Errorf("ShannonEntropy(normal text) = %f, want between 2.0-6.0", e)
	}
}

// TestEntropyDetector_Flagged verifies high-entropy content is flagged.
func TestEntropyDetector_Flagged(t *testing.T) {
	ed := NewEntropyDetector(4.5, "tool_description")

	// High entropy content (base64 encoded)
	text := highEntropyBase64
	result := ed.Evaluate("tool_description", text)
	if !result.Flagged {
		t.Error("EntropyDetector should flag high-entropy content")
	}
	if result.Entropy < 4.5 {
		t.Errorf("Entropy = %f, want >= 4.5", result.Entropy)
	}
}

// TestEntropyDetector_NotFlagged verifies normal content is not flagged.
func TestEntropyDetector_NotFlagged(t *testing.T) {
	ed := NewEntropyDetector(4.5, "tool_description")

	text := "Reads a file from the filesystem given a path"
	result := ed.Evaluate("tool_description", text)
	if result.Flagged {
		t.Errorf("EntropyDetector should not flag normal content, entropy = %f", result.Entropy)
	}
}

// TestEntropyDetector_TargetFiltering verifies target filtering.
func TestEntropyDetector_TargetFiltering(t *testing.T) {
	ed := NewEntropyDetector(4.5, "tool_description")

	// High entropy content but wrong target
	text := highEntropyBase64
	result := ed.Evaluate("message_content", text)
	if result.Flagged {
		t.Error("EntropyDetector should not flag for wrong target")
	}
}

// TestEntropyDetector_ConfigurableThreshold verifies per-signature threshold config.
func TestEntropyDetector_ConfigurableThreshold(t *testing.T) {
	// Very low threshold should flag almost everything
	ed := NewEntropyDetector(1.0, "tool_description")

	text := "This is normal text with some words"
	result := ed.Evaluate("tool_description", text)
	if !result.Flagged {
		t.Errorf("EntropyDetector with low threshold should flag normal text, entropy = %f", result.Entropy)
	}
}

// TestEntropyDetector_ShortTextNotFlagged verifies short text is not flagged.
func TestEntropyDetector_ShortTextNotFlagged(t *testing.T) {
	ed := NewEntropyDetector(4.5, "tool_description")

	// Short text should not be flagged even if technically high entropy
	text := "ab"
	result := ed.Evaluate("tool_description", text)
	if result.Flagged {
		t.Error("EntropyDetector should not flag very short text")
	}
}
