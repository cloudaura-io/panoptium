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

// EvaluatorAdapter bridges the PolicyCache and PolicyCompositionResolver,
// implementing the extproc.PolicyEvaluator interface. It fetches the current
// policy snapshot from the cache and delegates evaluation to the resolver.
//
// Thread safety: the adapter is safe for concurrent use because PolicyCache.GetPolicies()
// returns an immutable snapshot and the resolver is stateless.
type EvaluatorAdapter struct {
	cache    *PolicyCache
	resolver *PolicyCompositionResolver
}

// NewEvaluatorAdapter creates a new EvaluatorAdapter wrapping the given cache
// and composition resolver.
func NewEvaluatorAdapter(cache *PolicyCache, resolver *PolicyCompositionResolver) *EvaluatorAdapter {
	return &EvaluatorAdapter{
		cache:    cache,
		resolver: resolver,
	}
}

// Evaluate evaluates a PolicyEvent against the current compiled policy set.
// It fetches the latest policy snapshot from the cache and delegates to the
// composition resolver for priority-ordered evaluation.
func (a *EvaluatorAdapter) Evaluate(event *PolicyEvent) (*Decision, error) {
	policies := a.cache.GetPolicies()
	return a.resolver.Evaluate(policies, event)
}

// EvaluateAll evaluates a PolicyEvent against ALL policies in the current
// compiled policy set and returns an EvaluationResult containing decisions
// from all matching policies across all priority tiers.
func (a *EvaluatorAdapter) EvaluateAll(event *PolicyEvent) (*EvaluationResult, error) {
	policies := a.cache.GetPolicies()
	return a.resolver.EvaluateAll(policies, event)
}
