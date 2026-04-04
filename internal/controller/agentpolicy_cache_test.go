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

package controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/policy"
)

var _ = Describe("AgentPolicy Controller PolicyCache Integration", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When a PolicyCache is configured on the reconciler", func() {
		It("Should compile and cache the policy after creation", func() {
			pol := &panoptiumiov1alpha1.AgentPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cache-test-add",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.AgentPolicySpec{
					TargetSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "cache-test"},
					},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
					Priority:        100,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "test-rule",
							Trigger: panoptiumiov1alpha1.Trigger{
								EventCategory:    "protocol",
								EventSubcategory: "tool_call",
							},
							Predicates: []panoptiumiov1alpha1.Predicate{
								{CEL: `event.toolName == "dangerous_exec"`},
							},
							Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
							Severity: panoptiumiov1alpha1.SeverityHigh,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, pol)).Should(Succeed())

			// Wait for the reconciler to process it and update the cache
			Eventually(func() bool {
				for _, p := range testPolicyCache.GetPolicies() {
					if p.Name == "cache-test-add" {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue(),
				"PolicyCache should contain 'cache-test-add'")

			// Verify the cached policy structure
			for _, p := range testPolicyCache.GetPolicies() {
				if p.Name == "cache-test-add" {
					Expect(p.Rules).To(HaveLen(1))
					Expect(p.Rules[0].Name).To(Equal("test-rule"))
				}
			}
		})

		It("Should update the cached policy when the CRD is updated", func() {
			pol := &panoptiumiov1alpha1.AgentPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cache-test-update",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.AgentPolicySpec{
					TargetSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "cache-update"},
					},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
					Priority:        50,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "original-rule",
							Trigger: panoptiumiov1alpha1.Trigger{
								EventCategory:    "protocol",
								EventSubcategory: "tool_call",
							},
							Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeAllow},
							Severity: panoptiumiov1alpha1.SeverityInfo,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, pol)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "cache-test-update", Namespace: "default"}

			// Wait for initial cache entry
			Eventually(func() bool {
				for _, p := range testPolicyCache.GetPolicies() {
					if p.Name == "cache-test-update" {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			// Update the policy (retry on conflict since reconciler may update status concurrently)
			Eventually(func() error {
				updated := &panoptiumiov1alpha1.AgentPolicy{}
				if err := k8sClient.Get(ctx, lookupKey, updated); err != nil {
					return err
				}
				updated.Spec.Priority = 200
				return k8sClient.Update(ctx, updated)
			}, timeout, interval).Should(Succeed())

			// Wait for cache to reflect the update
			Eventually(func() int32 {
				for _, p := range testPolicyCache.GetPolicies() {
					if p.Name == "cache-test-update" {
						return p.Priority
					}
				}
				return -1
			}, timeout, interval).Should(Equal(int32(200)),
				"PolicyCache should reflect updated priority")
		})

		It("Should remove from cache when the CRD is deleted", func() {
			pol := &panoptiumiov1alpha1.AgentPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cache-test-delete",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.AgentPolicySpec{
					TargetSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "cache-delete"},
					},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
					Priority:        75,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "delete-rule",
							Trigger: panoptiumiov1alpha1.Trigger{
								EventCategory:    "protocol",
								EventSubcategory: "tool_call",
							},
							Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
							Severity: panoptiumiov1alpha1.SeverityMedium,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, pol)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "cache-test-delete", Namespace: "default"}

			// Wait for cache entry
			Eventually(func() bool {
				for _, p := range testPolicyCache.GetPolicies() {
					if p.Name == "cache-test-delete" {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			// Delete the policy
			toDelete := &panoptiumiov1alpha1.AgentPolicy{}
			Expect(k8sClient.Get(ctx, lookupKey, toDelete)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, toDelete)).Should(Succeed())

			// Wait for cache entry to be removed
			Eventually(func() bool {
				for _, p := range testPolicyCache.GetPolicies() {
					if p.Name == "cache-test-delete" {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeFalse(),
				"PolicyCache should not contain deleted policy")
		})
	})
})

// testPolicyCache is the shared PolicyCache used by the test suite.
// It is initialized in suite_test.go and passed to the AgentPolicyReconciler.
var testPolicyCache *policy.PolicyCache
