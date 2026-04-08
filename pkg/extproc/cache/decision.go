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

// Package cache implements a three-tier policy decision cache for the
// Panoptium ExtProc enforcement layer. The cache accelerates policy
// evaluation by storing and reusing decisions based on AgentSentry's
// validity model: universal (global), task-scoped (session), and
// once (per-invocation, never cached).
package cache

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panoptium/panoptium/pkg/policy"
)

// CacheTier identifies the caching tier for a policy decision.
type CacheTier int

const (
	// TierUniversal caches decisions that apply globally regardless of
	// context. Entries are cached until the relevant AgentPolicy is
	// updated or the TTL expires.
	TierUniversal CacheTier = iota

	// TierTaskScoped caches decisions tied to a specific agent session
	// or task. Entries are invalidated when the session ends.
	TierTaskScoped

	// TierOnce indicates per-invocation evaluation. Lookups always
	// return a cache miss and stores are no-ops.
	TierOnce
)

// String returns the human-readable name of the cache tier.
func (t CacheTier) String() string {
	switch t {
	case TierUniversal:
		return "universal"
	case TierTaskScoped:
		return "task-scoped"
	case TierOnce:
		return "once"
	default:
		return fmt.Sprintf("unknown(%d)", int(t))
	}
}

// SelectTier maps a policy rule annotation string to a CacheTier.
// Unknown or empty annotations default to TierUniversal.
func SelectTier(annotation string) CacheTier {
	switch annotation {
	case "universal", "":
		return TierUniversal
	case "task-scoped":
		return TierTaskScoped
	case "once":
		return TierOnce
	default:
		return TierUniversal
	}
}

// CacheKey uniquely identifies a cached decision entry.
type CacheKey struct {
	// Tool is the tool or action identifier (e.g., "curl", "read_file").
	Tool string

	// Action is the action verb (e.g., "execute", "read", "write").
	Action string

	// PolicyKey is the policy reference key (e.g., "default/deny-curl").
	PolicyKey string

	// SessionID is the agent session identifier (used for task-scoped tier).
	SessionID string
}

// universalKey returns a string key for the universal tier map.
func (k CacheKey) universalKey() string {
	return k.Tool + "|" + k.Action + "|" + k.PolicyKey
}

// taskScopedKey returns a string key for the task-scoped tier map.
func (k CacheKey) taskScopedKey() string {
	return k.SessionID + "|" + k.Tool + "|" + k.Action + "|" + k.PolicyKey
}

// cacheEntry wraps a cached Decision with metadata.
type cacheEntry struct {
	decision      *policy.Decision
	policyKey     string
	policyVersion string
	storedAt      time.Time
	expiresAt     time.Time
}

// CacheConfig holds configuration for the PolicyDecisionCache.
type CacheConfig struct {
	// UniversalTTL is the time-to-live for universal tier entries.
	UniversalTTL time.Duration

	// TaskScopedTTL is the time-to-live for task-scoped tier entries.
	TaskScopedTTL time.Duration

	// CleanupInterval is how often the background cleanup runs.
	CleanupInterval time.Duration
}

// DefaultCacheConfig returns a CacheConfig with sensible defaults.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		UniversalTTL:    10 * time.Minute,
		TaskScopedTTL:   30 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	}
}

// CacheStats holds cache hit/miss counters.
type CacheStats struct {
	Hits   int64
	Misses int64
}

// PolicyDecisionCache is a three-tier decision cache that accelerates
// policy evaluation by reusing previous decisions. It is safe for
// concurrent access from multiple goroutines.
type PolicyDecisionCache struct {
	cfg CacheConfig

	// Universal tier: sync.Map for lock-free concurrent access.
	universal sync.Map

	// Task-scoped tier: mutex-protected map of session -> entries.
	taskMu   sync.RWMutex
	taskData map[string]map[string]*cacheEntry

	// Stats counters (atomic for lock-free reads).
	hits   atomic.Int64
	misses atomic.Int64

	// Cleanup goroutine lifecycle.
	stopCh chan struct{}
	stopWg sync.WaitGroup
}

// NewPolicyDecisionCache creates a new three-tier decision cache with
// the given configuration and starts the background cleanup goroutine.
func NewPolicyDecisionCache(cfg CacheConfig) *PolicyDecisionCache {
	c := &PolicyDecisionCache{
		cfg:      cfg,
		taskData: make(map[string]map[string]*cacheEntry),
		stopCh:   make(chan struct{}),
	}
	c.stopWg.Add(1)
	go c.cleanupLoop()
	return c
}

// Stop shuts down the background cleanup goroutine and waits for it
// to finish.
func (c *PolicyDecisionCache) Stop() {
	close(c.stopCh)
	c.stopWg.Wait()
}

// Store stores a decision in the specified cache tier. For TierOnce,
// the store is a no-op.
func (c *PolicyDecisionCache) Store(
	key CacheKey, tier CacheTier,
	decision *policy.Decision,
	policyKey, policyVersion string,
) {
	if tier == TierOnce {
		return
	}

	now := time.Now()
	entry := &cacheEntry{
		decision:      decision,
		policyKey:     policyKey,
		policyVersion: policyVersion,
		storedAt:      now,
	}

	switch tier {
	case TierUniversal:
		entry.expiresAt = now.Add(c.cfg.UniversalTTL)
		c.universal.Store(key.universalKey(), entry)

	case TierTaskScoped:
		entry.expiresAt = now.Add(c.cfg.TaskScopedTTL)
		c.taskMu.Lock()
		sessMap, ok := c.taskData[key.SessionID]
		if !ok {
			sessMap = make(map[string]*cacheEntry)
			c.taskData[key.SessionID] = sessMap
		}
		sessMap[key.taskScopedKey()] = entry
		c.taskMu.Unlock()
	}
}

// Lookup retrieves a cached decision for the given key and tier.
// For TierOnce, it always returns (nil, false).
func (c *PolicyDecisionCache) Lookup(key CacheKey, tier CacheTier) (*policy.Decision, bool) {
	if tier == TierOnce {
		c.misses.Add(1)
		return nil, false
	}

	switch tier {
	case TierUniversal:
		v, ok := c.universal.Load(key.universalKey())
		if !ok {
			c.misses.Add(1)
			return nil, false
		}
		entry := v.(*cacheEntry)
		if time.Now().After(entry.expiresAt) {
			c.universal.Delete(key.universalKey())
			c.misses.Add(1)
			return nil, false
		}
		c.hits.Add(1)
		return entry.decision, true

	case TierTaskScoped:
		c.taskMu.RLock()
		sessMap, ok := c.taskData[key.SessionID]
		if !ok {
			c.taskMu.RUnlock()
			c.misses.Add(1)
			return nil, false
		}
		entry, ok := sessMap[key.taskScopedKey()]
		c.taskMu.RUnlock()
		if !ok {
			c.misses.Add(1)
			return nil, false
		}
		if time.Now().After(entry.expiresAt) {
			c.misses.Add(1)
			return nil, false
		}
		c.hits.Add(1)
		return entry.decision, true
	}

	c.misses.Add(1)
	return nil, false
}

// InvalidatePolicy removes all cached entries (universal and task-scoped)
// that were stored for the given policy key (e.g., "default/deny-curl").
func (c *PolicyDecisionCache) InvalidatePolicy(policyKey string) {
	// Purge universal tier
	c.universal.Range(func(key, value any) bool {
		entry := value.(*cacheEntry)
		if entry.policyKey == policyKey {
			c.universal.Delete(key)
		}
		return true
	})

	// Purge task-scoped tier
	c.taskMu.Lock()
	for sessID, sessMap := range c.taskData {
		for k, entry := range sessMap {
			if entry.policyKey == policyKey {
				delete(sessMap, k)
			}
		}
		if len(sessMap) == 0 {
			delete(c.taskData, sessID)
		}
	}
	c.taskMu.Unlock()
}

// InvalidateSession removes all task-scoped cache entries for the
// given session ID.
func (c *PolicyDecisionCache) InvalidateSession(sessionID string) {
	c.taskMu.Lock()
	delete(c.taskData, sessionID)
	c.taskMu.Unlock()
}

// GetEntryVersion returns the policy resource version stored with the
// cache entry for the given key and tier. Returns ("", false) if the
// entry does not exist.
func (c *PolicyDecisionCache) GetEntryVersion(key CacheKey, tier CacheTier) (string, bool) {
	switch tier {
	case TierUniversal:
		v, ok := c.universal.Load(key.universalKey())
		if !ok {
			return "", false
		}
		entry := v.(*cacheEntry)
		if time.Now().After(entry.expiresAt) {
			return "", false
		}
		return entry.policyVersion, true

	case TierTaskScoped:
		c.taskMu.RLock()
		sessMap, ok := c.taskData[key.SessionID]
		if !ok {
			c.taskMu.RUnlock()
			return "", false
		}
		entry, ok := sessMap[key.taskScopedKey()]
		c.taskMu.RUnlock()
		if !ok {
			return "", false
		}
		if time.Now().After(entry.expiresAt) {
			return "", false
		}
		return entry.policyVersion, true
	}

	return "", false
}

// Flush removes all entries from all cache tiers.
func (c *PolicyDecisionCache) Flush() {
	// Clear universal tier
	c.universal.Range(func(key, _ any) bool {
		c.universal.Delete(key)
		return true
	})

	// Clear task-scoped tier
	c.taskMu.Lock()
	c.taskData = make(map[string]map[string]*cacheEntry)
	c.taskMu.Unlock()
}

// Stats returns a snapshot of the cache hit/miss counters.
func (c *PolicyDecisionCache) Stats() CacheStats {
	return CacheStats{
		Hits:   c.hits.Load(),
		Misses: c.misses.Load(),
	}
}

// cleanupLoop periodically removes expired entries from all tiers.
func (c *PolicyDecisionCache) cleanupLoop() {
	defer c.stopWg.Done()

	ticker := time.NewTicker(c.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired entries from all tiers.
func (c *PolicyDecisionCache) cleanupExpired() {
	now := time.Now()

	// Clean universal tier
	c.universal.Range(func(key, value any) bool {
		entry := value.(*cacheEntry)
		if now.After(entry.expiresAt) {
			c.universal.Delete(key)
		}
		return true
	})

	// Clean task-scoped tier
	c.taskMu.Lock()
	for sessID, sessMap := range c.taskData {
		for k, entry := range sessMap {
			if now.After(entry.expiresAt) {
				delete(sessMap, k)
			}
		}
		if len(sessMap) == 0 {
			delete(c.taskData, sessID)
		}
	}
	c.taskMu.Unlock()
}
