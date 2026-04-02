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

// Package identity provides agent identity resolution for the Panoptium operator.
// Identity is resolved from the source pod IP via a Kubernetes-backed PodCache
// filtered to only enrolled pods (panoptium.io/monitored=true).
package identity

import (
	"net/http"

	"github.com/panoptium/panoptium/pkg/eventbus"
)


// Resolver resolves agent identity from the source pod IP via the PodCache.
// The PodCache is filtered by panoptium.io/monitored=true, so only enrolled
// pods are resolvable. Un-enrolled source IPs receive a degraded identity
// with low confidence.
type Resolver struct {
	cache *PodCache
}

// NewResolver creates a new Resolver with the given pod IP cache.
// The cache may be nil if pod resolution is not available.
func NewResolver(cache *PodCache) *Resolver {
	return &Resolver{cache: cache}
}

// ResolveFromIP resolves agent identity from the given source IP address.
// This is the primary identity resolution path for K8s-native identity.
//
// Resolution logic:
//  1. Look up the source IP in the filtered PodCache
//  2. If found: return identity with high confidence (1.0) including pod metadata
//  3. If not found: return degraded identity with low confidence (0.0)
func (r *Resolver) ResolveFromIP(sourceIP string) eventbus.AgentIdentity {
	if sourceIP == "" || r.cache == nil {
		recordResolution("ip", "unknown")
		return eventbus.AgentIdentity{
			SourceIP:   sourceIP,
			Confidence: eventbus.ConfidenceLow,
		}
	}

	podInfo, ok := r.cache.Get(sourceIP)
	if ok {
		recordResolution("pod", "success")
		return eventbus.AgentIdentity{
			ID:         podInfo.Name,
			SourceIP:   sourceIP,
			PodName:    podInfo.Name,
			Namespace:  podInfo.Namespace,
			PodUID:     podInfo.UID,
			Labels:     podInfo.Labels,
			Confidence: eventbus.ConfidenceHigh,
		}
	}

	// Source IP not in PodCache — pod is not enrolled
	recordResolution("ip", "unenrolled")
	return eventbus.AgentIdentity{
		SourceIP:   sourceIP,
		Confidence: eventbus.ConfidenceLow,
	}
}

// Resolve extracts agent identity from the source IP found in HTTP headers.
// This is a convenience wrapper around ResolveFromIP that extracts the
// client IP from the request context or X-Forwarded-For header.
//
// NOTE: X-Panoptium-Agent-Id, X-Panoptium-Client-Ip, and X-Panoptium-Auth-Type
// headers are no longer used for identity resolution (removed per FR-9).
// Only X-Panoptium-Request-Id is retained as a correlation/tracing header.
func (r *Resolver) Resolve(headers http.Header) eventbus.AgentIdentity {
	// Extract source IP from standard forwarding headers
	sourceIP := headers.Get("X-Forwarded-For")
	if sourceIP == "" {
		sourceIP = headers.Get("X-Real-Ip")
	}

	return r.ResolveFromIP(sourceIP)
}
