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

// ThreatSignatureSelector defines criteria for matching threat signatures
// in AgentPolicy rules. When multiple fields are specified, all must match
// (AND semantics). Within each field, any value can match (OR semantics).
type ThreatSignatureSelector struct {
	// Names matches specific threat signatures by name.
	Names []string

	// Categories matches signatures by attack category.
	Categories []string

	// Severities matches signatures by severity level.
	Severities []string
}

// PolicyMatcher evaluates whether a MatchResult satisfies a ThreatSignatureSelector.
type PolicyMatcher struct{}

// NewPolicyMatcher creates a new PolicyMatcher.
func NewPolicyMatcher() *PolicyMatcher {
	return &PolicyMatcher{}
}

// Matches returns true if the MatchResult satisfies all criteria in the selector.
// Empty selector matches nothing. When multiple fields are specified, all must match.
func (pm *PolicyMatcher) Matches(result MatchResult, selector ThreatSignatureSelector) bool {
	// Empty selector matches nothing
	if len(selector.Names) == 0 && len(selector.Categories) == 0 && len(selector.Severities) == 0 {
		return false
	}

	if len(selector.Names) > 0 {
		if !containsString(selector.Names, result.SignatureName) {
			return false
		}
	}

	if len(selector.Categories) > 0 {
		if !containsString(selector.Categories, result.Category) {
			return false
		}
	}

	if len(selector.Severities) > 0 {
		if !containsString(selector.Severities, result.Severity) {
			return false
		}
	}

	return true
}
