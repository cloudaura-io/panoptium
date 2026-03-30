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

// Package cgroup provides cgroup ID to Kubernetes pod identity resolution
// for the Panoptium observer. It serves as a supplementary enrichment layer
// for cases where Tetragon metadata is insufficient (e.g., short-lived
// containers, custom cgroup hierarchies).
package cgroup

import (
	"container/list"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
)

// PodIdentity contains the resolved Kubernetes pod identity for a cgroup.
type PodIdentity struct {
	// PodName is the Kubernetes pod name.
	PodName string

	// Namespace is the Kubernetes namespace.
	Namespace string

	// ContainerID is the container runtime ID (e.g., containerd://...).
	ContainerID string

	// Labels contains the Kubernetes labels of the pod.
	Labels map[string]string
}

// PodInformer is an interface for resolving container IDs to pod identities.
// In production this is backed by a Kubernetes informer cache.
type PodInformer interface {
	// GetPodByContainerID resolves a container ID to its pod identity.
	// Returns nil if the container ID is not found.
	GetPodByContainerID(containerID string) *PodIdentity
}

// lruEntry holds a cached cgroup-to-pod resolution with LRU tracking.
type lruEntry struct {
	key      uint64
	identity *PodIdentity
}

// CacheMetrics tracks cache performance counters.
type CacheMetrics struct {
	// Hits counts cache hits.
	Hits atomic.Int64
	// Misses counts cache misses.
	Misses atomic.Int64
}

// CgroupResolver maps cgroup IDs to Kubernetes pod identities.
// It uses a two-step resolution: cgroup ID -> container ID (via cgroup filesystem)
// and container ID -> pod identity (via Kubernetes informer cache).
// The cache uses an O(1) LRU eviction policy.
type CgroupResolver struct {
	mu sync.RWMutex

	// lruList maintains entries in access order (front = most recent).
	lruList *list.List

	// cache maps cgroup IDs to LRU list elements for O(1) lookup and eviction.
	cache map[uint64]*list.Element

	// containerMap maps cgroup IDs to container IDs (populated from cgroup fs).
	containerMap map[uint64]string

	// informer provides container ID -> pod identity resolution.
	informer PodInformer

	// maxCacheSize is the maximum number of entries in the LRU cache.
	maxCacheSize int

	// cgroupBasePath is the base path for the cgroup filesystem.
	cgroupBasePath string

	// metrics tracks cache hit/miss counters.
	metrics CacheMetrics
}

// ResolverOption configures the CgroupResolver.
type ResolverOption func(*CgroupResolver)

// WithMaxCacheSize sets the maximum LRU cache size.
func WithMaxCacheSize(size int) ResolverOption {
	return func(r *CgroupResolver) {
		r.maxCacheSize = size
	}
}

// WithCgroupBasePath sets the cgroup filesystem base path.
func WithCgroupBasePath(path string) ResolverOption {
	return func(r *CgroupResolver) {
		r.cgroupBasePath = path
	}
}

// NewCgroupResolver creates a new CgroupResolver with the given PodInformer.
func NewCgroupResolver(informer PodInformer, opts ...ResolverOption) *CgroupResolver {
	r := &CgroupResolver{
		lruList:        list.New(),
		cache:          make(map[uint64]*list.Element),
		containerMap:   make(map[uint64]string),
		informer:       informer,
		maxCacheSize:   4096,
		cgroupBasePath: "/sys/fs/cgroup",
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolve maps a cgroup ID to a PodIdentity.
// Returns nil if the cgroup ID cannot be resolved to a known pod.
// Cached lookups are O(1) via LRU.
func (r *CgroupResolver) Resolve(cgroupID uint64) *PodIdentity {
	// Fast path: check cache with read lock.
	r.mu.RLock()
	if elem, ok := r.cache[cgroupID]; ok {
		r.mu.RUnlock()
		// Promote to front requires write lock.
		r.mu.Lock()
		r.lruList.MoveToFront(elem)
		r.mu.Unlock()
		r.metrics.Hits.Add(1)
		return elem.Value.(*lruEntry).identity
	}
	r.mu.RUnlock()

	// Slow path: resolve from container map and informer.
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock.
	if elem, ok := r.cache[cgroupID]; ok {
		r.lruList.MoveToFront(elem)
		r.metrics.Hits.Add(1)
		return elem.Value.(*lruEntry).identity
	}

	r.metrics.Misses.Add(1)

	// Step 1: cgroup ID -> container ID.
	containerID, ok := r.containerMap[cgroupID]
	if !ok {
		return nil
	}

	// Step 2: container ID -> pod identity.
	if r.informer == nil {
		return nil
	}

	identity := r.informer.GetPodByContainerID(containerID)
	if identity == nil {
		return nil
	}

	// Cache the result with O(1) LRU eviction.
	r.evictIfNeeded()
	entry := &lruEntry{key: cgroupID, identity: identity}
	elem := r.lruList.PushFront(entry)
	r.cache[cgroupID] = elem

	return identity
}

// RegisterContainer maps a cgroup ID to a container ID.
// Called when a new container is detected (e.g., from pod informer events).
func (r *CgroupResolver) RegisterContainer(cgroupID uint64, containerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.containerMap[cgroupID] = containerID
	slog.Debug("registered container",
		"cgroup_id", cgroupID,
		"container_id", containerID,
	)
}

// UnregisterContainer removes a cgroup ID mapping.
// Called when a container/pod is deleted.
func (r *CgroupResolver) UnregisterContainer(cgroupID uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.containerMap, cgroupID)
	if elem, ok := r.cache[cgroupID]; ok {
		r.lruList.Remove(elem)
		delete(r.cache, cgroupID)
	}
}

// CacheSize returns the current number of entries in the cache.
func (r *CgroupResolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

// CacheMetricsSnapshot returns the current cache hit/miss counters.
func (r *CgroupResolver) CacheMetricsSnapshot() *CacheMetrics {
	return &r.metrics
}

// evictIfNeeded removes the least recently used cache entry if at capacity.
// Must be called with r.mu held. O(1) operation.
func (r *CgroupResolver) evictIfNeeded() {
	if len(r.cache) < r.maxCacheSize {
		return
	}

	// Remove the least recently used entry (back of list).
	back := r.lruList.Back()
	if back == nil {
		return
	}

	entry := back.Value.(*lruEntry)
	r.lruList.Remove(back)
	delete(r.cache, entry.key)
	slog.Debug("evicted cache entry",
		"cgroup_id", entry.key,
	)
}

// String returns a human-readable summary of the resolver state.
func (r *CgroupResolver) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return fmt.Sprintf("CgroupResolver{cache=%d, containers=%d, max=%d}",
		len(r.cache), len(r.containerMap), r.maxCacheSize)
}
