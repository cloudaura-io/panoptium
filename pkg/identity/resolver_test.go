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

// TestResolveIdentity_JWT verifies that identity is resolved from JWT auth type
// with high confidence when x-panoptium-agent-id is present with jwt auth type.
func TestResolveIdentity_JWT(t *testing.T) {
	resolver := NewResolver(nil) // no pod cache needed for JWT resolution

	headers := http.Header{}
	headers.Set(HeaderAgentID, "agent-summarizer")
	headers.Set(HeaderClientIP, "10.0.0.5")
	headers.Set(HeaderAuthType, "jwt")
	headers.Set(HeaderRequestID, "req-123")

	identity := resolver.Resolve(headers)

	if identity.ID != "agent-summarizer" {
		t.Errorf("ID = %q, want %q", identity.ID, "agent-summarizer")
	}
	if identity.SourceIP != "10.0.0.5" {
		t.Errorf("SourceIP = %q, want %q", identity.SourceIP, "10.0.0.5")
	}
	if identity.AuthType != eventbus.AuthTypeJWT {
		t.Errorf("AuthType = %q, want %q", identity.AuthType, eventbus.AuthTypeJWT)
	}
	if identity.Confidence != eventbus.ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", identity.Confidence, eventbus.ConfidenceHigh)
	}
}

// TestResolveIdentity_SourceIP_WithPodCache verifies cascading resolution:
// when auth type is source-ip, the resolver uses the pod IP cache to resolve
// pod name, namespace, and labels with medium confidence.
func TestResolveIdentity_SourceIP_WithPodCache(t *testing.T) {
	cache := NewPodCache()
	cache.Set("10.0.1.10", PodInfo{
		Name:           "agent-pod-abc",
		Namespace:      "ai-agents",
		Labels:         map[string]string{"app": "summarizer"},
		ServiceAccount: "summarizer-sa",
	})

	resolver := NewResolver(cache)

	headers := http.Header{}
	headers.Set(HeaderAgentID, "pod:10.0.1.10")
	headers.Set(HeaderClientIP, "10.0.1.10")
	headers.Set(HeaderAuthType, "source-ip")
	headers.Set(HeaderRequestID, "req-456")

	identity := resolver.Resolve(headers)

	if identity.ID != "pod:10.0.1.10" {
		t.Errorf("ID = %q, want %q", identity.ID, "pod:10.0.1.10")
	}
	if identity.SourceIP != "10.0.1.10" {
		t.Errorf("SourceIP = %q, want %q", identity.SourceIP, "10.0.1.10")
	}
	if identity.AuthType != eventbus.AuthTypeSourceIP {
		t.Errorf("AuthType = %q, want %q", identity.AuthType, eventbus.AuthTypeSourceIP)
	}
	if identity.Confidence != eventbus.ConfidenceMedium {
		t.Errorf("Confidence = %q, want %q", identity.Confidence, eventbus.ConfidenceMedium)
	}
	if identity.PodName != "agent-pod-abc" {
		t.Errorf("PodName = %q, want %q", identity.PodName, "agent-pod-abc")
	}
	if identity.Namespace != "ai-agents" {
		t.Errorf("Namespace = %q, want %q", identity.Namespace, "ai-agents")
	}
	if identity.Labels["app"] != "summarizer" {
		t.Errorf("Labels[app] = %q, want %q", identity.Labels["app"], "summarizer")
	}
}

// TestResolveIdentity_SourceIP_CacheMiss verifies that when the pod IP is not
// in the cache, the resolver falls back to low confidence with raw IP only.
func TestResolveIdentity_SourceIP_CacheMiss(t *testing.T) {
	cache := NewPodCache() // empty cache
	resolver := NewResolver(cache)

	headers := http.Header{}
	headers.Set(HeaderAgentID, "pod:10.0.2.20")
	headers.Set(HeaderClientIP, "10.0.2.20")
	headers.Set(HeaderAuthType, "source-ip")
	headers.Set(HeaderRequestID, "req-789")

	identity := resolver.Resolve(headers)

	if identity.ID != "pod:10.0.2.20" {
		t.Errorf("ID = %q, want %q", identity.ID, "pod:10.0.2.20")
	}
	if identity.SourceIP != "10.0.2.20" {
		t.Errorf("SourceIP = %q, want %q", identity.SourceIP, "10.0.2.20")
	}
	if identity.AuthType != eventbus.AuthTypeSourceIP {
		t.Errorf("AuthType = %q, want %q", identity.AuthType, eventbus.AuthTypeSourceIP)
	}
	if identity.Confidence != eventbus.ConfidenceLow {
		t.Errorf("Confidence = %q, want %q", identity.Confidence, eventbus.ConfidenceLow)
	}
	if identity.PodName != "" {
		t.Errorf("PodName = %q, want empty string", identity.PodName)
	}
}

// TestResolveIdentity_CascadingResolution verifies the full cascading order:
// 1. JWT (high confidence) takes precedence
// 2. Pod lookup from cache (medium confidence)
// 3. Raw IP fallback (low confidence)
func TestResolveIdentity_CascadingResolution(t *testing.T) {
	cache := NewPodCache()
	cache.Set("10.0.3.30", PodInfo{
		Name:      "known-pod",
		Namespace: "default",
	})

	resolver := NewResolver(cache)

	tests := []struct {
		name     string
		headers  http.Header
		wantConf string
		wantPod  string
	}{
		{
			name: "JWT auth gives high confidence",
			headers: func() http.Header {
				h := http.Header{}
				h.Set(HeaderAgentID, "jwt-agent")
				h.Set(HeaderClientIP, "10.0.3.30")
				h.Set(HeaderAuthType, "jwt")
				return h
			}(),
			wantConf: eventbus.ConfidenceHigh,
			wantPod:  "",
		},
		{
			name: "Source-IP with cache hit gives medium confidence",
			headers: func() http.Header {
				h := http.Header{}
				h.Set(HeaderAgentID, "pod:10.0.3.30")
				h.Set(HeaderClientIP, "10.0.3.30")
				h.Set(HeaderAuthType, "source-ip")
				return h
			}(),
			wantConf: eventbus.ConfidenceMedium,
			wantPod:  "known-pod",
		},
		{
			name: "Source-IP with cache miss gives low confidence",
			headers: func() http.Header {
				h := http.Header{}
				h.Set(HeaderAgentID, "pod:10.0.4.40")
				h.Set(HeaderClientIP, "10.0.4.40")
				h.Set(HeaderAuthType, "source-ip")
				return h
			}(),
			wantConf: eventbus.ConfidenceLow,
			wantPod:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := resolver.Resolve(tt.headers)
			if identity.Confidence != tt.wantConf {
				t.Errorf("Confidence = %q, want %q", identity.Confidence, tt.wantConf)
			}
			if identity.PodName != tt.wantPod {
				t.Errorf("PodName = %q, want %q", identity.PodName, tt.wantPod)
			}
		})
	}
}

// TestResolveIdentity_MissingHeaders verifies that when no x-panoptium-*
// headers are present, the resolver returns an unknown identity.
func TestResolveIdentity_MissingHeaders(t *testing.T) {
	resolver := NewResolver(nil)

	headers := http.Header{}
	// No x-panoptium-* headers set

	identity := resolver.Resolve(headers)

	if identity.ID != "" {
		t.Errorf("ID = %q, want empty string", identity.ID)
	}
	if identity.AuthType != "" {
		t.Errorf("AuthType = %q, want empty string", identity.AuthType)
	}
	if identity.Confidence != eventbus.ConfidenceLow {
		t.Errorf("Confidence = %q, want %q", identity.Confidence, eventbus.ConfidenceLow)
	}
}

// TestResolveIdentity_PartialHeaders verifies graceful handling when only
// some x-panoptium-* headers are present.
func TestResolveIdentity_PartialHeaders(t *testing.T) {
	resolver := NewResolver(nil)

	headers := http.Header{}
	headers.Set(HeaderAgentID, "partial-agent")
	// No auth type, no client IP

	identity := resolver.Resolve(headers)

	if identity.ID != "partial-agent" {
		t.Errorf("ID = %q, want %q", identity.ID, "partial-agent")
	}
	if identity.Confidence != eventbus.ConfidenceLow {
		t.Errorf("Confidence = %q, want %q for missing auth type", identity.Confidence, eventbus.ConfidenceLow)
	}
}

// TestResolveIdentity_ConfidenceLevels verifies the three confidence levels
// are correctly assigned based on auth type and resolution success.
func TestResolveIdentity_ConfidenceLevels(t *testing.T) {
	cache := NewPodCache()
	cache.Set("10.0.5.50", PodInfo{
		Name:      "cached-pod",
		Namespace: "test-ns",
		Labels:    map[string]string{"tier": "backend"},
	})

	resolver := NewResolver(cache)

	// High confidence: JWT
	jwtHeaders := http.Header{}
	jwtHeaders.Set(HeaderAgentID, "jwt-user")
	jwtHeaders.Set(HeaderAuthType, "jwt")
	jwtIdentity := resolver.Resolve(jwtHeaders)
	if jwtIdentity.Confidence != eventbus.ConfidenceHigh {
		t.Errorf("JWT Confidence = %q, want %q", jwtIdentity.Confidence, eventbus.ConfidenceHigh)
	}

	// Medium confidence: source-ip with pod resolved
	podHeaders := http.Header{}
	podHeaders.Set(HeaderAgentID, "pod:10.0.5.50")
	podHeaders.Set(HeaderClientIP, "10.0.5.50")
	podHeaders.Set(HeaderAuthType, "source-ip")
	podIdentity := resolver.Resolve(podHeaders)
	if podIdentity.Confidence != eventbus.ConfidenceMedium {
		t.Errorf("Pod-resolved Confidence = %q, want %q", podIdentity.Confidence, eventbus.ConfidenceMedium)
	}

	// Low confidence: source-ip without pod resolved
	ipHeaders := http.Header{}
	ipHeaders.Set(HeaderAgentID, "pod:10.0.9.99")
	ipHeaders.Set(HeaderClientIP, "10.0.9.99")
	ipHeaders.Set(HeaderAuthType, "source-ip")
	ipIdentity := resolver.Resolve(ipHeaders)
	if ipIdentity.Confidence != eventbus.ConfidenceLow {
		t.Errorf("IP-only Confidence = %q, want %q", ipIdentity.Confidence, eventbus.ConfidenceLow)
	}
}
