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
	"net"

	"github.com/panoptium/panoptium/pkg/policy"
)

// CIDREvaluator evaluates CIDR range predicates against event fields.
// It uses a pre-parsed *net.IPNet to check whether an IP address from
// the event falls within the configured CIDR range.
type CIDREvaluator struct {
	// FieldPath is the event field to extract (e.g., "destinationIP").
	FieldPath string

	// IPNet is the pre-parsed CIDR network range.
	IPNet *net.IPNet
}

// Evaluate checks whether the event field's IP address is contained
// within the configured CIDR range.
func (e *CIDREvaluator) Evaluate(event *policy.PolicyEvent) (bool, error) {
	fieldValue := extractField(e.FieldPath, event)
	if fieldValue == nil {
		return false, nil
	}

	str := coerceToString(fieldValue)
	ip := net.ParseIP(str)
	if ip == nil {
		return false, nil
	}

	return e.IPNet.Contains(ip), nil
}
