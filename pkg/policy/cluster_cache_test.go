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
	"reflect"
	"testing"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeTestClusterPolicy(name string, priority int32) *v1alpha1.AgentClusterPolicy {
	return &v1alpha1.AgentClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.AgentClusterPolicySpec{
			TargetSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        priority,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "test-rule",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "process_exec",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: `event.processName == "curl"`},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}
}

// Test: OnAddCluster compiles and stores a cluster-scoped policy in the cache.
func TestPolicyCache_OnAddCluster(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	pol := makeTestClusterPolicy("deny-curl-cluster", 100)
	err := cache.OnAddCluster(pol)
	if err != nil {
		t.Fatalf("OnAddCluster: %v", err)
	}

	policies := cache.GetPolicies()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "deny-curl-cluster" {
		t.Errorf("expected name deny-curl-cluster, got %q", policies[0].Name)
	}
	if !policies[0].IsClusterScoped {
		t.Error("expected IsClusterScoped=true for cluster policy")
	}
	if policies[0].Namespace != "" {
		t.Errorf("expected empty namespace for cluster policy, got %q", policies[0].Namespace)
	}
}

// Test: OnDeleteCluster removes a cluster-scoped policy from the cache.
func TestPolicyCache_OnDeleteCluster(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	pol := makeTestClusterPolicy("delete-cluster", 100)
	err := cache.OnAddCluster(pol)
	if err != nil {
		t.Fatalf("OnAddCluster: %v", err)
	}

	err = cache.OnDeleteCluster(pol)
	if err != nil {
		t.Fatalf("OnDeleteCluster: %v", err)
	}

	policies := cache.GetPolicies()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies after delete, got %d", len(policies))
	}
}

// Test: OnDeleteCluster with a missing policy is a no-op.
func TestPolicyCache_OnDeleteCluster_Missing(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	pol := makeTestClusterPolicy("nonexistent-cluster", 100)
	err := cache.OnDeleteCluster(pol)
	if err != nil {
		t.Fatalf("OnDeleteCluster of missing cluster policy: %v", err)
	}

	policies := cache.GetPolicies()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policies))
	}
}

// Test: Cluster and namespace policies coexist in cache.
func TestPolicyCache_ClusterAndNamespaceCoexist(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	nsPol := makeTestPolicy("ns-pol", "default", 100)
	clusterPol := makeTestClusterPolicy("cluster-pol", 200)

	if err := cache.OnAdd(nsPol); err != nil {
		t.Fatalf("OnAdd: %v", err)
	}
	if err := cache.OnAddCluster(clusterPol); err != nil {
		t.Fatalf("OnAddCluster: %v", err)
	}

	policies := cache.GetPolicies()
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}

	var foundNs, foundCluster bool
	for _, p := range policies {
		if p.Name == "ns-pol" && !p.IsClusterScoped {
			foundNs = true
		}
		if p.Name == "cluster-pol" && p.IsClusterScoped {
			foundCluster = true
		}
	}
	if !foundNs {
		t.Error("namespace policy not found in cache")
	}
	if !foundCluster {
		t.Error("cluster policy not found in cache")
	}
}

// Test: InvalidationCallback is called on OnDeleteCluster.
func TestPolicyCache_InvalidationCallback_OnDeleteCluster(t *testing.T) {
	cache := NewPolicyCache(NewPolicyCompiler())

	var callbackCalled bool
	var callbackKey string
	cache.SetInvalidationCallback(func(policyKey string) {
		callbackCalled = true
		callbackKey = policyKey
	})

	pol := makeTestClusterPolicy("cluster-cb", 100)
	_ = cache.OnAddCluster(pol)
	_ = cache.OnDeleteCluster(pol)

	if !callbackCalled {
		t.Error("expected invalidation callback to be called on cluster policy delete")
	}
	if callbackKey != "cluster-cb" {
		t.Errorf("expected key 'cluster-cb', got %q", callbackKey)
	}
}

// Test: Spec parity — AgentClusterPolicySpec fields match AgentPolicySpec fields.
func TestSpecParity_ClusterAndNamespaceFields(t *testing.T) {
	nsType := reflect.TypeOf(v1alpha1.AgentPolicySpec{})
	clusterType := reflect.TypeOf(v1alpha1.AgentClusterPolicySpec{})

	if nsType.NumField() != clusterType.NumField() {
		t.Errorf("field count mismatch: AgentPolicySpec has %d fields, AgentClusterPolicySpec has %d",
			nsType.NumField(), clusterType.NumField())
	}

	for i := 0; i < nsType.NumField(); i++ {
		nsField := nsType.Field(i)
		clusterField, found := clusterType.FieldByName(nsField.Name)
		if !found {
			t.Errorf("AgentClusterPolicySpec missing field %q", nsField.Name)
			continue
		}
		if nsField.Type != clusterField.Type {
			t.Errorf("type mismatch for field %q: AgentPolicySpec has %v, AgentClusterPolicySpec has %v",
				nsField.Name, nsField.Type, clusterField.Type)
		}
		nsTag := nsField.Tag.Get("json")
		clusterTag := clusterField.Tag.Get("json")
		if nsTag != clusterTag {
			t.Errorf("json tag mismatch for field %q: AgentPolicySpec has %q, AgentClusterPolicySpec has %q",
				nsField.Name, nsTag, clusterTag)
		}
	}
}

// Test: PolicyCompositionResolver evaluates both namespace and cluster policies.
func TestPolicyComposition_EvaluatesBothNamespaceAndCluster(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "ns-policy",
			Namespace:       "default",
			Priority:        50,
			IsClusterScoped: false,
			Rules: []*CompiledRule{
				{
					Name:         "ns-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
		{
			Name:            "cluster-policy",
			Namespace:       "",
			Priority:        100,
			IsClusterScoped: true,
			Rules: []*CompiledRule{
				{
					Name:         "cluster-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Cluster policy has higher priority (100 > 50), so it should win
	if decision.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("expected deny from cluster policy, got %q", decision.Action.Type)
	}
	if decision.PolicyName != "cluster-policy" {
		t.Errorf("expected cluster-policy, got %q", decision.PolicyName)
	}
}
