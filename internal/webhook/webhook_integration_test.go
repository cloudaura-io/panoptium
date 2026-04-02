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

package webhook

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

var _ = Describe("Webhook Integration", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	_ = timeout
	_ = interval

	Context("PanoptiumPolicy Validating Webhook", func() {
		It("Should accept a valid PanoptiumPolicy", func() {
			policy := &panoptiumiov1alpha1.PanoptiumPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-policy-integration",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
					TargetSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "agent"},
					},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
					Priority:        100,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "block-exec",
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

			// Verify it was actually created
			lookupKey := types.NamespacedName{Name: "valid-policy-integration", Namespace: "default"}
			createdPolicy := &panoptiumiov1alpha1.PanoptiumPolicy{}
			Expect(k8sClient.Get(ctx, lookupKey, createdPolicy)).Should(Succeed())
			Expect(createdPolicy.Spec.Priority).Should(Equal(int32(100)))
		})

		It("Should reject an invalid PanoptiumPolicy with priority=0", func() {
			policy := &panoptiumiov1alpha1.PanoptiumPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-policy-priority-zero",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
					TargetSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "agent"},
					},
					EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
					Priority:        0,
					Rules: []panoptiumiov1alpha1.PolicyRule{
						{
							Name: "some-rule",
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

			err := k8sClient.Create(ctx, policy)
			Expect(err).Should(HaveOccurred(), "Should reject PanoptiumPolicy with priority=0")
		})
	})
})
