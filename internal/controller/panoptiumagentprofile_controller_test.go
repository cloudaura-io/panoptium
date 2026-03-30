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

var _ = Describe("PanoptiumAgentProfile Controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When creating a PanoptiumAgentProfile", func() {
		It("Should set Ready condition to True", func() {
			profile := &panoptiumiov1alpha1.PanoptiumAgentProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile-ready",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumAgentProfileSpec{
					AgentSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "coding-assistant"},
					},
					AgentType: "coding-assistant",
					Baselines: panoptiumiov1alpha1.BaselineSpec{
						ExpectedToolCalls:    []string{"read_file", "write_file"},
						MaxRequestsPerMinute: 60,
					},
				},
			}

			Expect(k8sClient.Create(ctx, profile)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-profile-ready", Namespace: "default"}
			createdProfile := &panoptiumiov1alpha1.PanoptiumAgentProfile{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdProfile)
				if err != nil {
					return false
				}
				for _, c := range createdProfile.Status.Conditions {
					if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})

		It("Should set Learning condition when learningMode is true", func() {
			profile := &panoptiumiov1alpha1.PanoptiumAgentProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile-learning",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumAgentProfileSpec{
					AgentSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "learner"},
					},
					AgentType:    "data-analyst",
					LearningMode: true,
				},
			}

			Expect(k8sClient.Create(ctx, profile)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-profile-learning", Namespace: "default"}
			createdProfile := &panoptiumiov1alpha1.PanoptiumAgentProfile{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdProfile)
				if err != nil {
					return false
				}
				for _, c := range createdProfile.Status.Conditions {
					if c.Type == "Learning" && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			Expect(createdProfile.Status.BaselineHealth).Should(Equal("learning"))
		})

		It("Should update lastBaselineUpdate timestamp", func() {
			profile := &panoptiumiov1alpha1.PanoptiumAgentProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile-timestamp",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumAgentProfileSpec{
					AgentSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "timestamped"},
					},
					AgentType: "autonomous-agent",
					Baselines: panoptiumiov1alpha1.BaselineSpec{
						MaxRequestsPerMinute: 30,
					},
				},
			}

			Expect(k8sClient.Create(ctx, profile)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-profile-timestamp", Namespace: "default"}
			createdProfile := &panoptiumiov1alpha1.PanoptiumAgentProfile{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdProfile)
				if err != nil {
					return false
				}
				return createdProfile.Status.LastBaselineUpdate != nil
			}, timeout, interval).Should(BeTrue())
		})

		It("Should handle deletion cleanly", func() {
			profile := &panoptiumiov1alpha1.PanoptiumAgentProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile-delete",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumAgentProfileSpec{
					AgentSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "deletable"},
					},
					AgentType: "test-agent",
				},
			}

			Expect(k8sClient.Create(ctx, profile)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-profile-delete", Namespace: "default"}
			createdProfile := &panoptiumiov1alpha1.PanoptiumAgentProfile{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdProfile)
				if err != nil {
					return false
				}
				for _, c := range createdProfile.Status.Conditions {
					if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			Expect(k8sClient.Delete(ctx, createdProfile)).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdProfile)
				return err != nil
			}, timeout, interval).Should(BeTrue())
		})
	})
})
