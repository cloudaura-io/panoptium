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

package policy

import (
	"fmt"
	"sync"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// PolicyCache maintains a thread-safe cache of compiled policies, designed
// to be driven by a Kubernetes informer. It supports atomic swap of individual
// policies on CRD Add/Update/Delete events, and an invalidation callback for
// propagating changes to stateful components (rate limiters, temporal detectors).
//
// The cache is safe for concurrent read and write access. Readers get a snapshot
// slice that is not affected by subsequent writes.
type PolicyCache struct {
	mu       sync.RWMutex
	compiler *PolicyCompiler

	// policies maps "namespace/name" -> *CompiledPolicy
	policies map[string]*CompiledPolicy

	// snapshot is an immutable slice rebuilt on mutation.
	// Readers get a reference to this slice without holding the lock.
	snapshot []*CompiledPolicy

	// invalidationCallback is called when a policy is updated or deleted.
	// It receives the policy key ("namespace/name") to allow stateful
	// components like rate limiters and temporal detectors to clear
	// relevant state.
	invalidationCallback func(policyKey string)
}

// NewPolicyCache creates a new PolicyCache with the given compiler.
func NewPolicyCache(compiler *PolicyCompiler) *PolicyCache {
	return &PolicyCache{
		compiler: compiler,
		policies: make(map[string]*CompiledPolicy),
	}
}

// SetInvalidationCallback sets a callback that is invoked when a policy
// is updated or deleted. This enables propagation to rate limiter and
// temporal sequence state that may need to be cleared.
func (c *PolicyCache) SetInvalidationCallback(cb func(policyKey string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidationCallback = cb
}

// GetPolicies returns a snapshot of all currently compiled policies.
// The returned slice is immutable and safe to use without synchronization.
func (c *PolicyCache) GetPolicies() []*CompiledPolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snapshot
}

// OnAdd compiles and adds a new PanoptiumPolicy to the cache.
// Returns an error if compilation fails; the cache is not modified on error.
func (c *PolicyCache) OnAdd(pol *v1alpha1.PanoptiumPolicy) error {
	compiled, err := c.compiler.Compile(pol)
	if err != nil {
		return fmt.Errorf("compile policy %s/%s: %w", pol.Namespace, pol.Name, err)
	}

	key := policyKey(pol.Namespace, pol.Name)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.policies[key] = compiled
	c.rebuildSnapshotLocked()
	return nil
}

// OnAddCluster compiles and adds a ClusterPanoptiumPolicy to the cache.
// Returns an error if compilation fails; the cache is not modified on error.
func (c *PolicyCache) OnAddCluster(pol *v1alpha1.ClusterPanoptiumPolicy) error {
	compiled, err := c.compiler.CompileCluster(pol)
	if err != nil {
		return fmt.Errorf("compile cluster policy %s: %w", pol.Name, err)
	}

	key := policyKey("", pol.Name)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.policies[key] = compiled
	c.rebuildSnapshotLocked()
	return nil
}

// OnUpdate recompiles a policy that has changed. Only the changed policy is
// recompiled; other policies in the cache are unaffected.
// Returns an error if recompilation fails; the cache retains the old version.
func (c *PolicyCache) OnUpdate(oldPol, newPol *v1alpha1.PanoptiumPolicy) error {
	compiled, err := c.compiler.Compile(newPol)
	if err != nil {
		return fmt.Errorf("recompile policy %s/%s: %w", newPol.Namespace, newPol.Name, err)
	}

	key := policyKey(newPol.Namespace, newPol.Name)

	c.mu.Lock()
	c.policies[key] = compiled
	c.rebuildSnapshotLocked()
	cb := c.invalidationCallback
	c.mu.Unlock()

	if cb != nil {
		cb(key)
	}

	return nil
}

// OnDelete removes a policy from the cache.
func (c *PolicyCache) OnDelete(pol *v1alpha1.PanoptiumPolicy) error {
	key := policyKey(pol.Namespace, pol.Name)

	c.mu.Lock()
	_, existed := c.policies[key]
	delete(c.policies, key)
	c.rebuildSnapshotLocked()
	cb := c.invalidationCallback
	c.mu.Unlock()

	if existed && cb != nil {
		cb(key)
	}

	return nil
}

// OnDeleteCluster removes a ClusterPanoptiumPolicy from the cache.
func (c *PolicyCache) OnDeleteCluster(pol *v1alpha1.ClusterPanoptiumPolicy) error {
	key := policyKey("", pol.Name)

	c.mu.Lock()
	_, existed := c.policies[key]
	delete(c.policies, key)
	c.rebuildSnapshotLocked()
	cb := c.invalidationCallback
	c.mu.Unlock()

	if existed && cb != nil {
		cb(key)
	}

	return nil
}

// rebuildSnapshotLocked rebuilds the immutable snapshot slice from the
// current policies map. Must be called while holding the write lock.
func (c *PolicyCache) rebuildSnapshotLocked() {
	snap := make([]*CompiledPolicy, 0, len(c.policies))
	for _, p := range c.policies {
		snap = append(snap, p)
	}
	c.snapshot = snap
}

// policyKey returns the cache key for a policy: "namespace/name".
func policyKey(namespace, name string) string {
	if namespace != "" {
		return namespace + "/" + name
	}
	return name
}
