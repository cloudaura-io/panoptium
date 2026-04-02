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
	"math"
)

// EntropyResult holds the result of an entropy evaluation.
type EntropyResult struct {
	// Flagged indicates whether the content exceeded the entropy threshold.
	Flagged bool

	// Entropy is the computed Shannon entropy value.
	Entropy float64
}

// EntropyDetector evaluates content for high Shannon entropy which may indicate
// obfuscated or encoded malicious payloads.
type EntropyDetector struct {
	threshold float64
	target    string
}

// NewEntropyDetector creates a new entropy detector with the given threshold and target.
func NewEntropyDetector(threshold float64, target string) *EntropyDetector {
	return &EntropyDetector{
		threshold: threshold,
		target:    target,
	}
}

// Evaluate checks content entropy against the threshold.
// Short content (< 20 chars) is never flagged to avoid false positives.
func (ed *EntropyDetector) Evaluate(target, content string) EntropyResult {
	// Target filtering
	if ed.target != "" && ed.target != target {
		return EntropyResult{}
	}

	// Short text filter: avoid false positives on very short strings
	if len(content) < 20 {
		return EntropyResult{Entropy: ShannonEntropy(content)}
	}

	entropy := ShannonEntropy(content)
	return EntropyResult{
		Flagged: entropy > ed.threshold,
		Entropy: entropy,
	}
}

// ShannonEntropy computes the Shannon entropy of a string in bits per character.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
