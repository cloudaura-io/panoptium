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

package identity

import (
	"net/http"
	"testing"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// TestResolveFromIP_EnrolledPod verifies that identity is resolved from PodCache
// with high confidence when the source IP matches an enrolled pod.
func TestResolveFromIP_EnrolledPod(t *testing.T) {
	cache := NewPodCache()
	cache.Set("10.0.1.10", PodInfo{
		Name:           "agent-pod-abc",
		Namespace:      "ai-agents",
		UID:            "uid-12345",
		Labels:         map[string]string{"app": "summarizer"},
		ServiceAccount: "summarizer-sa",
	})

	resolver := NewResolver(cache)
	identity := resolver.ResolveFromIP("10.0.1.10")

	if identity.ID != "agent-pod-abc" {
		t.Errorf("ID = %q, want %q", identity.ID, "agent-pod-abc")
	}
	if identity.SourceIP != "10.0.1.10" {
		t.Errorf("SourceIP = %q, want %q", identity.SourceIP, "10.0.1.10")
	}
	if identity.PodName != "agent-pod-abc" {
		t.Errorf("PodName = %q, want %q", identity.PodName, "agent-pod-abc")
	}
	if identity.PodUID != "uid-12345" {
		t.Errorf("PodUID = %q, want %q", identity.PodUID, "uid-12345")
	}
	if identity.Namespace != "ai-agents" {
		t.Errorf("Namespace = %q, want %q", identity.Namespace, "ai-agents")
	}
	if identity.Labels["app"] != "summarizer" {
		t.Errorf("Labels[app] = %q, want %q", identity.Labels["app"], "summarizer")
	}
	if identity.Confidence != eventbus.ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", identity.Confidence, eventbus.ConfidenceHigh)
	}
}

// TestResolveFromIP_UnenrolledPod verifies that un-enrolled source IPs
// receive a degraded identity with low confidence.
func TestResolveFromIP_UnenrolledPod(t *testing.T) {
	cache := NewPodCache() // empty cache — no enrolled pods
	resolver := NewResolver(cache)

	identity := resolver.ResolveFromIP("10.0.2.20")

	if identity.ID != "" {
		t.Errorf("ID = %q, want empty string for unenrolled pod", identity.ID)
	}
	if identity.SourceIP != "10.0.2.20" {
		t.Errorf("SourceIP = %q, want %q", identity.SourceIP, "10.0.2.20")
	}
	if identity.PodName != "" {
		t.Errorf("PodName = %q, want empty string", identity.PodName)
	}
	if identity.PodUID != "" {
		t.Errorf("PodUID = %q, want empty string", identity.PodUID)
	}
	if identity.Confidence != eventbus.ConfidenceLow {
		t.Errorf("Confidence = %q, want %q", identity.Confidence, eventbus.ConfidenceLow)
	}
}

// TestResolveFromIP_EmptyIP verifies graceful handling when source IP is empty.
func TestResolveFromIP_EmptyIP(t *testing.T) {
	resolver := NewResolver(NewPodCache())

	identity := resolver.ResolveFromIP("")

	if identity.Confidence != eventbus.ConfidenceLow {
		t.Errorf("Confidence = %q, want %q for empty IP", identity.Confidence, eventbus.ConfidenceLow)
	}
}

// TestResolveFromIP_NilCache verifies graceful handling when cache is nil.
func TestResolveFromIP_NilCache(t *testing.T) {
	resolver := NewResolver(nil)

	identity := resolver.ResolveFromIP("10.0.0.1")

	if identity.Confidence != eventbus.ConfidenceLow {
		t.Errorf("Confidence = %q, want %q for nil cache", identity.Confidence, eventbus.ConfidenceLow)
	}
}

// TestResolve_HeaderBased verifies the HTTP header convenience method
// extracts source IP from X-Forwarded-For and resolves via PodCache.
func TestResolve_HeaderBased(t *testing.T) {
	cache := NewPodCache()
	cache.Set("10.0.5.50", PodInfo{
		Name:      "cached-pod",
		Namespace: "test-ns",
		UID:       "uid-99",
		Labels:    map[string]string{"tier": "backend"},
	})

	resolver := NewResolver(cache)

	headers := http.Header{}
	headers.Set("X-Forwarded-For", "10.0.5.50")
	headers.Set("X-Request-Id", "req-123")

	identity := resolver.Resolve(headers)

	if identity.PodName != "cached-pod" {
		t.Errorf("PodName = %q, want %q", identity.PodName, "cached-pod")
	}
	if identity.Confidence != eventbus.ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", identity.Confidence, eventbus.ConfidenceHigh)
	}
}

// TestResolve_NoIdentityHeaders verifies that when no identity-related
// headers are present, the resolver returns a low-confidence identity.
func TestResolve_NoIdentityHeaders(t *testing.T) {
	resolver := NewResolver(NewPodCache())

	headers := http.Header{}
	identity := resolver.Resolve(headers)

	if identity.Confidence != eventbus.ConfidenceLow {
		t.Errorf("Confidence = %q, want %q", identity.Confidence, eventbus.ConfidenceLow)
	}
}

// TestResolve_XPanoptiumHeadersNotUsed verifies that the old X-Panoptium-*
// identity headers are no longer used for identity resolution.
func TestResolve_XPanoptiumHeadersNotUsed(t *testing.T) {
	resolver := NewResolver(NewPodCache())

	// Set old headers that should be ignored
	headers := http.Header{}
	headers.Set("X-Panoptium-Agent-Id", "agent-spoofed")
	headers.Set("X-Panoptium-Client-Ip", "10.0.0.1")
	headers.Set("X-Panoptium-Auth-Type", "jwt")

	identity := resolver.Resolve(headers)

	// Should NOT use these headers for identity
	if identity.ID == "agent-spoofed" {
		t.Error("Resolver should not trust X-Panoptium-Agent-Id header")
	}
	if identity.Confidence == eventbus.ConfidenceHigh {
		t.Error("Resolver should not assign high confidence from spoofable headers")
	}
}

// TestPodCacheLabelSelectorFiltering verifies that the PodCache only watches
// pods with panoptium.io/monitored=true label.
func TestPodCacheLabelSelectorFiltering(t *testing.T) {
	if MonitoredLabelSelector != "panoptium.io/monitored=true" {
		t.Errorf("MonitoredLabelSelector = %q, want %q",
			MonitoredLabelSelector, "panoptium.io/monitored=true")
	}
}
