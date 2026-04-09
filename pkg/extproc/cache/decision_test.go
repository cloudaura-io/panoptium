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

package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/policy"
)

func TestUniversalTier_StoreAndRetrieve(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	decision := &policy.Decision{
		Matched:     true,
		MatchedRule: "test-rule",
		Action: policy.CompiledAction{
			Type:       "deny",
			Parameters: map[string]string{"signature": "PAN-SIG-001"},
		},
		PolicyName:      "deny-curl",
		PolicyNamespace: "default",
	}

	key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}
	c.Store(key, TierUniversal, decision, "default/deny-curl", "v1")

	got, hit := c.Lookup(key, TierUniversal)
	if !hit {
		t.Fatal("expected cache hit for universal tier, got miss")
	}
	if got.MatchedRule != "test-rule" {
		t.Errorf("expected MatchedRule 'test-rule', got %q", got.MatchedRule)
	}
	if got.PolicyName != "deny-curl" {
		t.Errorf("expected PolicyName 'deny-curl', got %q", got.PolicyName)
	}
	if got.Action.Parameters["signature"] != "PAN-SIG-001" {
		t.Errorf("expected signature PAN-SIG-001, got %q", got.Action.Parameters["signature"])
	}
}

func TestUniversalTier_CacheMissForUnknownKey(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "unknown-tool", Action: "execute"}
	_, hit := c.Lookup(key, TierUniversal)
	if hit {
		t.Fatal("expected cache miss for unknown key, got hit")
	}
}

func TestUniversalTier_TTLExpiration(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.UniversalTTL = 50 * time.Millisecond
	cfg.CleanupInterval = 10 * time.Millisecond
	c := NewPolicyDecisionCache(cfg)
	defer c.Stop()

	decision := &policy.Decision{
		Matched:     true,
		MatchedRule: "ttl-rule",
		Action:      policy.CompiledAction{Type: "deny"},
	}

	key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}
	c.Store(key, TierUniversal, decision, "default/deny-curl", "v1")

	// Should be a hit immediately
	_, hit := c.Lookup(key, TierUniversal)
	if !hit {
		t.Fatal("expected cache hit before TTL expiry")
	}

	// Wait for TTL expiry
	time.Sleep(100 * time.Millisecond)

	// Should be a miss after TTL
	_, hit = c.Lookup(key, TierUniversal)
	if hit {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestUniversalTier_OverwriteExistingEntry(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}

	d1 := &policy.Decision{Matched: true, MatchedRule: "rule-v1", Action: policy.CompiledAction{Type: "deny"}}
	c.Store(key, TierUniversal, d1, "default/deny-curl", "v1")

	d2 := &policy.Decision{Matched: true, MatchedRule: "rule-v2", Action: policy.CompiledAction{Type: "allow"}}
	c.Store(key, TierUniversal, d2, "default/deny-curl", "v2")

	got, hit := c.Lookup(key, TierUniversal)
	if !hit {
		t.Fatal("expected cache hit after overwrite")
	}
	if got.MatchedRule != "rule-v2" {
		t.Errorf("expected MatchedRule 'rule-v2' after overwrite, got %q", got.MatchedRule)
	}
}

func TestTaskScopedTier_StoreAndRetrieve(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	decision := &policy.Decision{
		Matched:     true,
		MatchedRule: "session-rule",
		Action:      policy.CompiledAction{Type: "deny"},
	}

	key := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-abc-123"}
	c.Store(key, TierTaskScoped, decision, "default/deny-curl", "v1")

	got, hit := c.Lookup(key, TierTaskScoped)
	if !hit {
		t.Fatal("expected cache hit for task-scoped tier, got miss")
	}
	if got.MatchedRule != "session-rule" {
		t.Errorf("expected MatchedRule 'session-rule', got %q", got.MatchedRule)
	}
}

func TestTaskScopedTier_DifferentSessionsAreSeparate(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d1 := &policy.Decision{Matched: true, MatchedRule: "rule-session-1", Action: policy.CompiledAction{Type: "deny"}}
	d2 := &policy.Decision{Matched: true, MatchedRule: "rule-session-2", Action: policy.CompiledAction{Type: "allow"}}

	key1 := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-1"}
	key2 := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-2"}

	c.Store(key1, TierTaskScoped, d1, "default/deny-curl", "v1")
	c.Store(key2, TierTaskScoped, d2, "default/deny-curl", "v1")

	got1, hit1 := c.Lookup(key1, TierTaskScoped)
	got2, hit2 := c.Lookup(key2, TierTaskScoped)

	if !hit1 || !hit2 {
		t.Fatal("expected cache hits for both sessions")
	}
	if got1.MatchedRule != "rule-session-1" {
		t.Errorf("expected session-1 rule, got %q", got1.MatchedRule)
	}
	if got2.MatchedRule != "rule-session-2" {
		t.Errorf("expected session-2 rule, got %q", got2.MatchedRule)
	}
}

func TestTaskScopedTier_InvalidateOnSessionEnd(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d := &policy.Decision{Matched: true, MatchedRule: "session-rule", Action: policy.CompiledAction{Type: "deny"}}

	key := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-end-test"}
	c.Store(key, TierTaskScoped, d, "default/deny-curl", "v1")

	// Verify hit before invalidation
	_, hit := c.Lookup(key, TierTaskScoped)
	if !hit {
		t.Fatal("expected cache hit before session end")
	}

	// End the session
	c.InvalidateSession("session-end-test")

	// Should miss after session invalidation
	_, hit = c.Lookup(key, TierTaskScoped)
	if hit {
		t.Fatal("expected cache miss after session end")
	}
}

func TestTaskScopedTier_InvalidateSessionOnlyAffectsTargetSession(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d1 := &policy.Decision{Matched: true, MatchedRule: "keep-rule", Action: policy.CompiledAction{Type: "deny"}}
	d2 := &policy.Decision{Matched: true, MatchedRule: "evict-rule", Action: policy.CompiledAction{Type: "deny"}}

	key1 := CacheKey{Tool: "curl", Action: "execute", SessionID: "keep-session"}
	key2 := CacheKey{Tool: "curl", Action: "execute", SessionID: "evict-session"}

	c.Store(key1, TierTaskScoped, d1, "default/deny-curl", "v1")
	c.Store(key2, TierTaskScoped, d2, "default/deny-curl", "v1")

	// Invalidate only evict-session
	c.InvalidateSession("evict-session")

	// keep-session should still be a hit
	_, hit := c.Lookup(key1, TierTaskScoped)
	if !hit {
		t.Fatal("expected cache hit for keep-session after invalidating evict-session")
	}

	// evict-session should be a miss
	_, hit = c.Lookup(key2, TierTaskScoped)
	if hit {
		t.Fatal("expected cache miss for evict-session after invalidation")
	}
}

func TestOnceTier_AlwaysReturnsCacheMiss(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	decision := &policy.Decision{
		Matched:     true,
		MatchedRule: "once-rule",
		Action:      policy.CompiledAction{Type: "deny"},
	}

	key := CacheKey{Tool: "curl", Action: "execute"}

	// Store should succeed without error but lookup always misses
	c.Store(key, TierOnce, decision, "default/deny-curl", "v1")

	_, hit := c.Lookup(key, TierOnce)
	if hit {
		t.Fatal("expected cache miss for once tier, got hit")
	}
}

func TestOnceTier_MultipleStoresStillMiss(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute"}

	for i := 0; i < 5; i++ {
		d := &policy.Decision{Matched: true, MatchedRule: "once-rule", Action: policy.CompiledAction{Type: "deny"}}
		c.Store(key, TierOnce, d, "default/deny-curl", "v1")

		_, hit := c.Lookup(key, TierOnce)
		if hit {
			t.Fatalf("expected cache miss for once tier on iteration %d", i)
		}
	}
}

func TestCacheTierSelection_UniversalForGlobalRules(t *testing.T) {
	tier := SelectTier("universal")
	if tier != TierUniversal {
		t.Errorf("expected TierUniversal for 'universal' annotation, got %v", tier)
	}
}

func TestCacheTierSelection_TaskScopedForSessionRules(t *testing.T) {
	tier := SelectTier("task-scoped")
	if tier != TierTaskScoped {
		t.Errorf("expected TierTaskScoped for 'task-scoped' annotation, got %v", tier)
	}
}

func TestCacheTierSelection_OnceForPerInvocationRules(t *testing.T) {
	tier := SelectTier("once")
	if tier != TierOnce {
		t.Errorf("expected TierOnce for 'once' annotation, got %v", tier)
	}
}

func TestCacheTierSelection_DefaultIsUniversal(t *testing.T) {
	tier := SelectTier("")
	if tier != TierUniversal {
		t.Errorf("expected TierUniversal for empty annotation, got %v", tier)
	}
}

func TestCacheTierSelection_UnknownDefaultsToUniversal(t *testing.T) {
	tier := SelectTier("unknown-tier")
	if tier != TierUniversal {
		t.Errorf("expected TierUniversal for unknown annotation, got %v", tier)
	}
}

func TestConcurrentCacheAccess_UniversalTier(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent writes
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}
			d := &policy.Decision{Matched: true, MatchedRule: "concurrent-rule", Action: policy.CompiledAction{Type: "deny"}}
			c.Store(key, TierUniversal, d, "default/deny-curl", "v1")
		}()
	}

	// Concurrent reads
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}
			c.Lookup(key, TierUniversal)
		}()
	}

	wg.Wait()
}

func TestConcurrentCacheAccess_MixedTiers(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	var wg sync.WaitGroup
	iterations := 50

	for i := 0; i < iterations; i++ {
		wg.Add(3)

		// Universal tier operations
		go func() {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol"}
			d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}
			c.Store(key, TierUniversal, d, "default/pol", "v1")
			c.Lookup(key, TierUniversal)
		}()

		// Task-scoped tier operations
		go func() {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-concurrent"}
			d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}
			c.Store(key, TierTaskScoped, d, "default/pol", "v1")
			c.Lookup(key, TierTaskScoped)
		}()

		// Invalidation operations
		go func() {
			defer wg.Done()
			c.InvalidatePolicy("default/pol")
			c.InvalidateSession("session-concurrent")
		}()
	}

	wg.Wait()
}

func TestConcurrentCacheAccess_StoreAndInvalidate(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	var wg sync.WaitGroup

	// Concurrent stores and invalidations should not panic
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol"}
			d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}
			c.Store(key, TierUniversal, d, "default/pol", "v1")
		}()
		go func() {
			defer wg.Done()
			c.InvalidatePolicy("default/pol")
		}()
	}

	wg.Wait()
}

func TestInvalidatePolicy_UniversalTierEvictsMatchingEntries(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d := &policy.Decision{Matched: true, MatchedRule: "rule-a", Action: policy.CompiledAction{Type: "deny"}}

	key1 := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol-a"}
	key2 := CacheKey{Tool: "wget", Action: "execute", PolicyKey: "default/pol-a"}
	key3 := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol-b"}

	c.Store(key1, TierUniversal, d, "default/pol-a", "v1")
	c.Store(key2, TierUniversal, d, "default/pol-a", "v1")
	c.Store(key3, TierUniversal, d, "default/pol-b", "v1")

	// Invalidate pol-a
	c.InvalidatePolicy("default/pol-a")

	// pol-a entries should be evicted
	_, hit1 := c.Lookup(key1, TierUniversal)
	_, hit2 := c.Lookup(key2, TierUniversal)
	if hit1 || hit2 {
		t.Fatal("expected pol-a entries to be evicted after InvalidatePolicy")
	}

	// pol-b entry should remain
	_, hit3 := c.Lookup(key3, TierUniversal)
	if !hit3 {
		t.Fatal("expected pol-b entry to remain after InvalidatePolicy for pol-a")
	}
}

func TestInvalidatePolicy_PartialInvalidation(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	dA := &policy.Decision{Matched: true, MatchedRule: "rule-a", Action: policy.CompiledAction{Type: "deny"}}
	dB := &policy.Decision{Matched: true, MatchedRule: "rule-b", Action: policy.CompiledAction{Type: "allow"}}

	keyA := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol-a"}
	keyB := CacheKey{Tool: "wget", Action: "execute", PolicyKey: "default/pol-b"}

	c.Store(keyA, TierUniversal, dA, "default/pol-a", "v1")
	c.Store(keyB, TierUniversal, dB, "default/pol-b", "v1")

	// Invalidate only pol-a
	c.InvalidatePolicy("default/pol-a")

	_, hitA := c.Lookup(keyA, TierUniversal)
	if hitA {
		t.Fatal("expected pol-a to be evicted")
	}

	got, hitB := c.Lookup(keyB, TierUniversal)
	if !hitB {
		t.Fatal("expected pol-b to remain")
	}
	if got.MatchedRule != "rule-b" {
		t.Errorf("expected remaining entry to be rule-b, got %q", got.MatchedRule)
	}
}

func TestInvalidatePolicy_DeleteFlushesAllEntriesForPolicy(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}

	// Store entries in both universal and task-scoped tiers for the same policy
	uniKey := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/del-pol"}
	taskKey := CacheKey{Tool: "curl", Action: "execute", SessionID: "sess-1", PolicyKey: "default/del-pol"}

	c.Store(uniKey, TierUniversal, d, "default/del-pol", "v1")
	c.Store(taskKey, TierTaskScoped, d, "default/del-pol", "v1")

	// Invalidate simulates a policy deletion
	c.InvalidatePolicy("default/del-pol")

	_, hitUni := c.Lookup(uniKey, TierUniversal)
	_, hitTask := c.Lookup(taskKey, TierTaskScoped)
	if hitUni || hitTask {
		t.Fatal("expected all entries for deleted policy to be flushed")
	}
}

func TestInvalidatePolicy_VersionTracking(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/versioned-pol"}

	// Store with version v1
	d1 := &policy.Decision{Matched: true, MatchedRule: "rule-v1", Action: policy.CompiledAction{Type: "deny"}}
	c.Store(key, TierUniversal, d1, "default/versioned-pol", "v1")

	// Check version is v1
	version, ok := c.GetEntryVersion(key, TierUniversal)
	if !ok {
		t.Fatal("expected to find entry version")
	}
	if version != "v1" {
		t.Errorf("expected version v1, got %q", version)
	}

	// Invalidate and re-store with version v2
	c.InvalidatePolicy("default/versioned-pol")
	d2 := &policy.Decision{Matched: true, MatchedRule: "rule-v2", Action: policy.CompiledAction{Type: "allow"}}
	c.Store(key, TierUniversal, d2, "default/versioned-pol", "v2")

	// Check version is now v2
	version, ok = c.GetEntryVersion(key, TierUniversal)
	if !ok {
		t.Fatal("expected to find entry version after re-store")
	}
	if version != "v2" {
		t.Errorf("expected version v2 after re-store, got %q", version)
	}
}

func TestInvalidatePolicy_TaskScopedAlsoEvicted(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}

	key1 := CacheKey{Tool: "curl", Action: "execute", SessionID: "sess-a", PolicyKey: "default/pol-x"}
	key2 := CacheKey{Tool: "wget", Action: "execute", SessionID: "sess-b", PolicyKey: "default/pol-x"}
	key3 := CacheKey{Tool: "curl", Action: "execute", SessionID: "sess-a", PolicyKey: "default/pol-y"}

	c.Store(key1, TierTaskScoped, d, "default/pol-x", "v1")
	c.Store(key2, TierTaskScoped, d, "default/pol-x", "v1")
	c.Store(key3, TierTaskScoped, d, "default/pol-y", "v1")

	// Invalidate pol-x should evict task-scoped entries too
	c.InvalidatePolicy("default/pol-x")

	_, hit1 := c.Lookup(key1, TierTaskScoped)
	_, hit2 := c.Lookup(key2, TierTaskScoped)
	if hit1 || hit2 {
		t.Fatal("expected pol-x task-scoped entries to be evicted")
	}

	_, hit3 := c.Lookup(key3, TierTaskScoped)
	if !hit3 {
		t.Fatal("expected pol-y task-scoped entry to remain")
	}
}

func TestCacheTier_String(t *testing.T) {
	tests := []struct {
		tier CacheTier
		want string
	}{
		{TierUniversal, "universal"},
		{TierTaskScoped, "task-scoped"},
		{TierOnce, "once"},
		{CacheTier(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.tier.String(); got != tt.want {
			t.Errorf("CacheTier(%d).String() = %q, want %q", int(tt.tier), got, tt.want)
		}
	}
}

func TestGetEntryVersion_MissingKey(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "nonexistent", Action: "execute", PolicyKey: "default/pol"}
	_, ok := c.GetEntryVersion(key, TierUniversal)
	if ok {
		t.Fatal("expected no version for missing key")
	}
}

func TestGetEntryVersion_TaskScoped(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute", SessionID: "sess-v", PolicyKey: "default/pol"}
	d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}
	c.Store(key, TierTaskScoped, d, "default/pol", "v3")

	version, ok := c.GetEntryVersion(key, TierTaskScoped)
	if !ok {
		t.Fatal("expected to find task-scoped entry version")
	}
	if version != "v3" {
		t.Errorf("expected version v3, got %q", version)
	}
}

func TestGetEntryVersion_TaskScoped_MissingSession(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute", SessionID: "no-such-session", PolicyKey: "default/pol"}
	_, ok := c.GetEntryVersion(key, TierTaskScoped)
	if ok {
		t.Fatal("expected no version for missing session")
	}
}

func TestGetEntryVersion_TaskScoped_MissingKey(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	// Store one entry to create the session
	key1 := CacheKey{Tool: "curl", Action: "execute", SessionID: "sess-exists", PolicyKey: "default/pol"}
	d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}
	c.Store(key1, TierTaskScoped, d, "default/pol", "v1")

	// Look up a different key in the same session
	key2 := CacheKey{Tool: "wget", Action: "execute", SessionID: "sess-exists", PolicyKey: "default/pol"}
	_, ok := c.GetEntryVersion(key2, TierTaskScoped)
	if ok {
		t.Fatal("expected no version for missing key within existing session")
	}
}

func TestGetEntryVersion_OnceTier(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute"}
	_, ok := c.GetEntryVersion(key, TierOnce)
	if ok {
		t.Fatal("expected no version for once tier")
	}
}

func TestCacheStats_TracksHitsAndMisses(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol"}
	d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}

	// Miss
	c.Lookup(key, TierUniversal)

	// Store, then hit
	c.Store(key, TierUniversal, d, "default/pol", "v1")
	c.Lookup(key, TierUniversal)
	c.Lookup(key, TierUniversal)

	stats := c.Stats()
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
}

func TestFlush_ClearsAllTiers(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}

	uniKey := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol"}
	taskKey := CacheKey{Tool: "curl", Action: "execute", SessionID: "sess-1"}

	c.Store(uniKey, TierUniversal, d, "default/pol", "v1")
	c.Store(taskKey, TierTaskScoped, d, "default/pol", "v1")

	c.Flush()

	_, hit1 := c.Lookup(uniKey, TierUniversal)
	_, hit2 := c.Lookup(taskKey, TierTaskScoped)

	if hit1 || hit2 {
		t.Fatal("expected all tiers to be empty after flush")
	}
}
