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
)

var _ = Describe("AgentClusterPolicy Controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When creating a AgentClusterPolicy", func() {
		It("Should set Ready condition to True and Enforcing to False for audit mode", func() {
			policy := &panoptiumiov1alpha1.AgentClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy-audit",
				},
				Spec: panoptiumiov1alpha1.AgentClusterPolicySpec{
					TargetSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "agent"},
					},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeAudit,
					Priority:        100,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "block-exec",
							Trigger: panoptiumiov1alpha1.Trigger{
								EventCategory:    "syscall",
								EventSubcategory: "execve",
							},
							Action: panoptiumiov1alpha1.Action{
								Type: panoptiumiov1alpha1.ActionTypeDeny,
							},
							Severity: panoptiumiov1alpha1.SeverityHigh,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-cluster-policy-audit"}
			createdPolicy := &panoptiumiov1alpha1.AgentClusterPolicy{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdPolicy)
				if err != nil {
					return false
				}
				for _, c := range createdPolicy.Status.Conditions {
					if c.Type == conditionTypeReady && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue(), "Ready condition should be True")

			Expect(createdPolicy.Status.RuleCount).Should(Equal(int32(1)))
			Expect(createdPolicy.Status.ObservedGeneration).Should(Equal(createdPolicy.Generation))
		})

		It("Should set Enforcing condition to True for enforcing mode", func() {
			policy := &panoptiumiov1alpha1.AgentClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy-enforcing",
				},
				Spec: panoptiumiov1alpha1.AgentClusterPolicySpec{
					TargetSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "agent-enforcing"},
					},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
					Priority:        200,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "deny-network",
							Trigger: panoptiumiov1alpha1.Trigger{
								EventCategory: "network",
							},
							Action: panoptiumiov1alpha1.Action{
								Type: panoptiumiov1alpha1.ActionTypeDeny,
							},
							Severity: panoptiumiov1alpha1.SeverityCritical,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-cluster-policy-enforcing"}
			createdPolicy := &panoptiumiov1alpha1.AgentClusterPolicy{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdPolicy)
				if err != nil {
					return false
				}
				for _, c := range createdPolicy.Status.Conditions {
					if c.Type == "Enforcing" && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue(), "Enforcing condition should be True")
		})

		It("Should set Degraded condition to True for empty targetSelector", func() {
			policy := &panoptiumiov1alpha1.AgentClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy-degraded",
				},
				Spec: panoptiumiov1alpha1.AgentClusterPolicySpec{
					TargetSelector:  metav1.LabelSelector{},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
					Priority:        100,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "rule-with-empty-selector",
							Trigger: panoptiumiov1alpha1.Trigger{
								EventCategory: "syscall",
							},
							Action: panoptiumiov1alpha1.Action{
								Type: panoptiumiov1alpha1.ActionTypeDeny,
							},
							Severity: panoptiumiov1alpha1.SeverityHigh,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-cluster-policy-degraded"}
			createdPolicy := &panoptiumiov1alpha1.AgentClusterPolicy{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdPolicy)
				if err != nil {
					return false
				}
				for _, c := range createdPolicy.Status.Conditions {
					if c.Type == "Degraded" && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue(), "Degraded condition should be True for empty selector")
		})

		It("Should update ruleCount and observedGeneration when spec changes", func() {
			policy := &panoptiumiov1alpha1.AgentClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy-update",
				},
				Spec: panoptiumiov1alpha1.AgentClusterPolicySpec{
					TargetSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "agent-update"},
					},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeAudit,
					Priority:        50,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "alert-network",
							Trigger: panoptiumiov1alpha1.Trigger{
								EventCategory: "network",
							},
							Action: panoptiumiov1alpha1.Action{
								Type: panoptiumiov1alpha1.ActionTypeAlert,
							},
							Severity: panoptiumiov1alpha1.SeverityMedium,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-cluster-policy-update"}
			createdPolicy := &panoptiumiov1alpha1.AgentClusterPolicy{}

			// Wait for initial reconcile
			Eventually(func() int64 {
				err := k8sClient.Get(ctx, lookupKey, createdPolicy)
				if err != nil {
					return 0
				}
				return createdPolicy.Status.ObservedGeneration
			}, timeout, interval).Should(Equal(int64(1)))

			Expect(createdPolicy.Status.RuleCount).Should(Equal(int32(1)))

			// Update the spec to add a new rule
			Expect(k8sClient.Get(ctx, lookupKey, createdPolicy)).Should(Succeed())
			createdPolicy.Spec.Rules = append(createdPolicy.Spec.Rules, panoptiumiov1alpha1.PolicyRule{
				Name: "new-rule",
				Trigger: panoptiumiov1alpha1.Trigger{
					EventCategory: "llm",
				},
				Action: panoptiumiov1alpha1.Action{
					Type: panoptiumiov1alpha1.ActionTypeAllow,
				},
				Severity: panoptiumiov1alpha1.SeverityLow,
			})
			Expect(k8sClient.Update(ctx, createdPolicy)).Should(Succeed())

			// Wait for updated observedGeneration
			Eventually(func() int64 {
				err := k8sClient.Get(ctx, lookupKey, createdPolicy)
				if err != nil {
					return 0
				}
				return createdPolicy.Status.ObservedGeneration
			}, timeout, interval).Should(Equal(int64(2)))

			Expect(createdPolicy.Status.RuleCount).Should(Equal(int32(2)))
		})

		It("Should handle deletion cleanly", func() {
			policy := &panoptiumiov1alpha1.AgentClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy-delete",
				},
				Spec: panoptiumiov1alpha1.AgentClusterPolicySpec{
					TargetSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "agent-del"},
					},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeAudit,
					Priority:        10,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "simple-rule",
							Trigger: panoptiumiov1alpha1.Trigger{
								EventCategory: "llm",
							},
							Action: panoptiumiov1alpha1.Action{
								Type: panoptiumiov1alpha1.ActionTypeAlert,
							},
							Severity: panoptiumiov1alpha1.SeverityInfo,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-cluster-policy-delete"}
			createdPolicy := &panoptiumiov1alpha1.AgentClusterPolicy{}

			// Wait for Ready
			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdPolicy)
				if err != nil {
					return false
				}
				for _, c := range createdPolicy.Status.Conditions {
					if c.Type == conditionTypeReady && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			// Delete
			Expect(k8sClient.Delete(ctx, createdPolicy)).Should(Succeed())

			// Verify it's gone
			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdPolicy)
				return err != nil
			}, timeout, interval).Should(BeTrue(), "Policy should be deleted")
		})
	})
})
