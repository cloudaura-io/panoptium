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

var _ = Describe("PanoptiumQuarantine Controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When creating a PanoptiumQuarantine", func() {
		It("Should add finalizer and set Contained condition", func() {
			quarantine := &panoptiumiov1alpha1.PanoptiumQuarantine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-quarantine-basic",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumQuarantineSpec{
					TargetPod:        "suspicious-agent-pod",
					TargetNamespace:  "ai-agents",
					ContainmentLevel: panoptiumiov1alpha1.ContainmentLevelNetworkIsolate,
					Reason:           "Unusual network activity detected",
					TriggeringPolicy: "network-monitoring-policy",
				},
			}

			Expect(k8sClient.Create(ctx, quarantine)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-quarantine-basic", Namespace: "default"}
			createdQ := &panoptiumiov1alpha1.PanoptiumQuarantine{}

			// Verify finalizer is added
			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdQ)
				if err != nil {
					return false
				}
				for _, f := range createdQ.Finalizers {
					if f == panoptiumiov1alpha1.QuarantineCleanupFinalizer {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue(), "Finalizer should be added")

			// Verify Contained condition
			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdQ)
				if err != nil {
					return false
				}
				for _, c := range createdQ.Status.Conditions {
					if c.Type == "Contained" && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue(), "Contained condition should be True")
		})

		It("Should set containedAt timestamp on creation", func() {
			quarantine := &panoptiumiov1alpha1.PanoptiumQuarantine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-quarantine-timestamp",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumQuarantineSpec{
					TargetPod:        "timestamped-pod",
					TargetNamespace:  "test-ns",
					ContainmentLevel: panoptiumiov1alpha1.ContainmentLevelSyscallRestrict,
					Reason:           "Syscall anomaly",
				},
			}

			Expect(k8sClient.Create(ctx, quarantine)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-quarantine-timestamp", Namespace: "default"}
			createdQ := &panoptiumiov1alpha1.PanoptiumQuarantine{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdQ)
				if err != nil {
					return false
				}
				return createdQ.Status.ContainedAt != nil
			}, timeout, interval).Should(BeTrue(), "containedAt should be set")
		})

		It("Should run finalizer cleanup on deletion", func() {
			quarantine := &panoptiumiov1alpha1.PanoptiumQuarantine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-quarantine-delete",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumQuarantineSpec{
					TargetPod:        "deletable-pod",
					TargetNamespace:  "test-ns",
					ContainmentLevel: panoptiumiov1alpha1.ContainmentLevelFreeze,
					Reason:           "Test deletion",
				},
			}

			Expect(k8sClient.Create(ctx, quarantine)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-quarantine-delete", Namespace: "default"}
			createdQ := &panoptiumiov1alpha1.PanoptiumQuarantine{}

			// Wait for finalizer to be added
			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdQ)
				if err != nil {
					return false
				}
				for _, f := range createdQ.Finalizers {
					if f == panoptiumiov1alpha1.QuarantineCleanupFinalizer {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			// Delete
			Expect(k8sClient.Delete(ctx, createdQ)).Should(Succeed())

			// Verify it's gone (finalizer ran and was removed)
			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdQ)
				return err != nil
			}, timeout, interval).Should(BeTrue(), "Quarantine should be deleted after finalizer cleanup")
		})

		It("Should trigger auto-release after TTL", func() {
			quarantine := &panoptiumiov1alpha1.PanoptiumQuarantine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-quarantine-autorelease",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumQuarantineSpec{
					TargetPod:        "auto-release-pod",
					TargetNamespace:  "test-ns",
					ContainmentLevel: panoptiumiov1alpha1.ContainmentLevelNetworkIsolate,
					Reason:           "Auto-release test",
					Resolution: panoptiumiov1alpha1.ResolutionSpec{
						AutoRelease: true,
						TTLSeconds:  2, // Short TTL for testing
					},
				},
			}

			Expect(k8sClient.Create(ctx, quarantine)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-quarantine-autorelease", Namespace: "default"}
			createdQ := &panoptiumiov1alpha1.PanoptiumQuarantine{}

			// Verify initially contained
			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdQ)
				if err != nil {
					return false
				}
				for _, c := range createdQ.Status.Conditions {
					if c.Type == "Contained" && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			// Wait for auto-release after TTL (2 seconds + some buffer)
			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdQ)
				if err != nil {
					return false
				}
				for _, c := range createdQ.Status.Conditions {
					if c.Type == "Released" && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, time.Second*15, interval).Should(BeTrue(), "Should be auto-released after TTL")

			Expect(createdQ.Status.ReleasedAt).ShouldNot(BeNil())
		})
	})
})
