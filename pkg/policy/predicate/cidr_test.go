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
	"testing"

	"github.com/panoptium/panoptium/pkg/policy"
)

func TestCIDREvaluator_IPv4_Match(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	eval := &CIDREvaluator{
		FieldPath: "destinationIP",
		IPNet:     ipNet,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationIP": "10.1.2.3",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for 10.1.2.3 in 10.0.0.0/8")
	}
}

func TestCIDREvaluator_IPv4_NoMatch(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	eval := &CIDREvaluator{
		FieldPath: "destinationIP",
		IPNet:     ipNet,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationIP": "192.168.1.1",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for 192.168.1.1 in 10.0.0.0/8")
	}
}

func TestCIDREvaluator_IPv4_Exact(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.1/32")
	eval := &CIDREvaluator{
		FieldPath: "destinationIP",
		IPNet:     ipNet,
	}

	tests := []struct {
		name    string
		ip      string
		matched bool
	}{
		{"exact match", "10.0.0.1", true},
		{"different ip", "10.0.0.2", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := &policy.PolicyEvent{
				Category:    "network",
				Subcategory: "egress_attempt",
				Fields: map[string]interface{}{
					"destinationIP": tc.ip,
				},
			}

			matched, err := eval.Evaluate(event)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if matched != tc.matched {
				t.Errorf("expected matched=%v for IP %s, got %v", tc.matched, tc.ip, matched)
			}
		})
	}
}

func TestCIDREvaluator_IPv6_Match(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("fd00::/8")
	eval := &CIDREvaluator{
		FieldPath: "destinationIP",
		IPNet:     ipNet,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationIP": "fd12:3456:789a::1",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected match for fd12:3456:789a::1 in fd00::/8")
	}
}

func TestCIDREvaluator_IPv6_NoMatch(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("fd00::/8")
	eval := &CIDREvaluator{
		FieldPath: "destinationIP",
		IPNet:     ipNet,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationIP": "2001:db8::1",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for 2001:db8::1 in fd00::/8")
	}
}

func TestCIDREvaluator_InvalidIP(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	eval := &CIDREvaluator{
		FieldPath: "destinationIP",
		IPNet:     ipNet,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields: map[string]interface{}{
			"destinationIP": "not-an-ip",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match for invalid IP string")
	}
}

func TestCIDREvaluator_MissingField(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	eval := &CIDREvaluator{
		FieldPath: "destinationIP",
		IPNet:     ipNet,
	}

	event := &policy.PolicyEvent{
		Category:    "network",
		Subcategory: "egress_attempt",
		Fields:      map[string]interface{}{},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected no match when field is missing")
	}
}

func TestCIDREvaluator_BoundaryAddresses(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	eval := &CIDREvaluator{
		FieldPath: "destinationIP",
		IPNet:     ipNet,
	}

	tests := []struct {
		name    string
		ip      string
		matched bool
	}{
		{"network address", "192.168.1.0", true},
		{"first host", "192.168.1.1", true},
		{"last host", "192.168.1.254", true},
		{"broadcast", "192.168.1.255", true},
		{"one above", "192.168.2.0", false},
		{"one below", "192.168.0.255", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := &policy.PolicyEvent{
				Category:    "network",
				Subcategory: "egress_attempt",
				Fields: map[string]interface{}{
					"destinationIP": tc.ip,
				},
			}

			matched, err := eval.Evaluate(event)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if matched != tc.matched {
				t.Errorf("expected matched=%v for IP %s, got %v", tc.matched, tc.ip, matched)
			}
		})
	}
}

func TestCIDREvaluator_ImplementsInterface(t *testing.T) {
	var _ PredicateEvaluator = (*CIDREvaluator)(nil)
}
