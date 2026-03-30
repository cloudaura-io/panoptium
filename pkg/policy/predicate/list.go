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
	"fmt"
	"strings"

	"github.com/panoptium/panoptium/pkg/policy"
)

// ListMode defines whether the list is an allowlist or denylist.
type ListMode int

const (
	// ListAllow means the field value must be IN the list to match.
	ListAllow ListMode = iota

	// ListDeny means the field value must be IN the list to match
	// (matching means the value is denied).
	ListDeny
)

// ListMembershipEvaluator evaluates list membership predicates using set-based
// O(1) lookups. It supports both allowlist and denylist semantics.
type ListMembershipEvaluator struct {
	// FieldPath is the event field to extract (e.g., "toolName", "destinationHost").
	FieldPath string

	// Members is the set of list entries for O(1) membership checks.
	Members map[string]struct{}

	// Mode determines whether this is an allowlist or denylist check.
	Mode ListMode
}

// Evaluate checks whether the event field value is a member of the configured list.
func (e *ListMembershipEvaluator) Evaluate(event *policy.PolicyEvent) (bool, error) {
	fieldValue := extractField(e.FieldPath, event)
	if fieldValue == nil {
		return false, nil
	}

	str := coerceToString(fieldValue)
	_, found := e.Members[str]
	return found, nil
}

// ConfigMapResolutionError represents a failure to resolve list entries
// from a Kubernetes ConfigMap reference.
type ConfigMapResolutionError struct {
	// Namespace is the ConfigMap namespace.
	Namespace string

	// Name is the ConfigMap name.
	Name string

	// Key is the ConfigMap data key.
	Key string

	// Message describes the error.
	Message string

	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *ConfigMapResolutionError) Error() string {
	return fmt.Sprintf("failed to resolve ConfigMap %s/%s key %q: %s",
		e.Namespace, e.Name, e.Key, e.Message)
}

// Unwrap returns the underlying cause error.
func (e *ConfigMapResolutionError) Unwrap() error {
	return e.Cause
}

// ConfigMapGetter is a function type that retrieves a ConfigMap data value.
// It takes namespace, name, and key, and returns the string data value.
type ConfigMapGetter func(namespace, name, key string) (string, error)

// ConfigMapListResolver fetches list entries from a Kubernetes ConfigMap
// at policy compilation time. Entries are newline-separated, with empty lines
// and surrounding whitespace stripped.
type ConfigMapListResolver struct {
	// Getter is the function used to fetch ConfigMap data.
	Getter ConfigMapGetter
}

// Resolve fetches the ConfigMap data and parses it into a membership set.
func (r *ConfigMapListResolver) Resolve(namespace, name, key string) (map[string]struct{}, error) {
	content, err := r.Getter(namespace, name, key)
	if err != nil {
		return nil, err
	}

	entries := make(map[string]struct{})
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			entries[trimmed] = struct{}{}
		}
	}

	return entries, nil
}
