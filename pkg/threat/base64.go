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
	"encoding/base64"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// Base64Result holds the result of a base64 payload detection.
type Base64Result struct {
	// Flagged indicates whether a suspicious base64 payload was detected.
	Flagged bool
}

// Base64Detector detects suspicious base64-encoded payloads in content.
type Base64Detector struct {
	minLength int
	target    string
	pattern   *regexp.Regexp
}

// NewBase64Detector creates a new base64 detector with the given minimum length and target.
func NewBase64Detector(minLength int, target string) *Base64Detector {
	return &Base64Detector{
		minLength: minLength,
		target:    target,
		pattern:   regexp.MustCompile(fmt.Sprintf(`[A-Za-z0-9+/]{%d,}={0,2}`, minLength)),
	}
}

// Evaluate checks content for base64-encoded payloads.
// A payload is flagged if it is at least minLength characters, decodes to valid UTF-8,
// and the decoded content is longer than 10 bytes.
func (bd *Base64Detector) Evaluate(target, content string) Base64Result {
	// Target filtering
	if bd.target != "" && bd.target != target {
		return Base64Result{}
	}

	matches := bd.pattern.FindAllString(content, -1)
	for _, match := range matches {
		// Try standard base64 decoding
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err == nil && utf8.Valid(decoded) && len(decoded) > 10 {
			return Base64Result{Flagged: true}
		}

		// Try URL-safe base64 decoding
		decoded, err = base64.URLEncoding.DecodeString(match)
		if err == nil && utf8.Valid(decoded) && len(decoded) > 10 {
			return Base64Result{Flagged: true}
		}
	}

	return Base64Result{}
}
