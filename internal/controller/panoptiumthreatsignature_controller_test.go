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

var _ = Describe("PanoptiumThreatSignature Controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When creating a PanoptiumThreatSignature", func() {
		It("Should set Ready and Active conditions to True for enabled signature", func() {
			sig := &panoptiumiov1alpha1.PanoptiumThreatSignature{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sig-ready",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumThreatSignatureSpec{
					SignatureID: "PAN-SIG-0001",
					Description: "Detect unauthorized file access",
					Severity:    panoptiumiov1alpha1.SeverityHigh,
					Enabled:     true,
					Patterns: []panoptiumiov1alpha1.DetectionPattern{
						{
							EventCategory: "syscall",
							Match:         "event.syscall == 'openat' && event.path.startsWith('/etc/shadow')",
						},
					},
					DetectionPoints: []string{"L3-ebpf"},
				},
			}

			Expect(k8sClient.Create(ctx, sig)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-sig-ready", Namespace: "default"}
			createdSig := &panoptiumiov1alpha1.PanoptiumThreatSignature{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdSig)
				if err != nil {
					return false
				}
				readyFound := false
				activeFound := false
				for _, c := range createdSig.Status.Conditions {
					if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
						readyFound = true
					}
					if c.Type == "Active" && c.Status == metav1.ConditionTrue {
						activeFound = true
					}
				}
				return readyFound && activeFound
			}, timeout, interval).Should(BeTrue())
		})

		It("Should set Active to False when disabled", func() {
			sig := &panoptiumiov1alpha1.PanoptiumThreatSignature{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sig-disabled",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumThreatSignatureSpec{
					SignatureID: "PAN-SIG-0002",
					Description: "Disabled signature",
					Severity:    panoptiumiov1alpha1.SeverityMedium,
					Enabled:     false,
					Patterns: []panoptiumiov1alpha1.DetectionPattern{
						{
							EventCategory: "network",
							Match:         "event.dst_port == 443",
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, sig)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-sig-disabled", Namespace: "default"}
			createdSig := &panoptiumiov1alpha1.PanoptiumThreatSignature{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdSig)
				if err != nil {
					return false
				}
				for _, c := range createdSig.Status.Conditions {
					if c.Type == "Active" && c.Status == metav1.ConditionFalse {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})

		It("Should initialize detectionCount to 0", func() {
			sig := &panoptiumiov1alpha1.PanoptiumThreatSignature{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sig-count",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumThreatSignatureSpec{
					SignatureID: "PAN-SIG-0003",
					Description: "Count test signature",
					Severity:    panoptiumiov1alpha1.SeverityLow,
					Enabled:     true,
					Patterns: []panoptiumiov1alpha1.DetectionPattern{
						{
							EventCategory: "llm",
							Match:         "event.tokens > 1000",
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, sig)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-sig-count", Namespace: "default"}
			createdSig := &panoptiumiov1alpha1.PanoptiumThreatSignature{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdSig)
				if err != nil {
					return false
				}
				return createdSig.Status.ObservedGeneration > 0
			}, timeout, interval).Should(BeTrue())

			Expect(createdSig.Status.DetectionCount).Should(Equal(int64(0)))
		})

		It("Should handle deletion cleanly", func() {
			sig := &panoptiumiov1alpha1.PanoptiumThreatSignature{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sig-delete",
					Namespace: "default",
				},
				Spec: panoptiumiov1alpha1.PanoptiumThreatSignatureSpec{
					SignatureID: "PAN-SIG-0004",
					Description: "Delete test signature",
					Severity:    panoptiumiov1alpha1.SeverityInfo,
					Enabled:     true,
					Patterns: []panoptiumiov1alpha1.DetectionPattern{
						{
							EventCategory: "syscall",
							Match:         "true",
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, sig)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-sig-delete", Namespace: "default"}
			createdSig := &panoptiumiov1alpha1.PanoptiumThreatSignature{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdSig)
				if err != nil {
					return false
				}
				for _, c := range createdSig.Status.Conditions {
					if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			Expect(k8sClient.Delete(ctx, createdSig)).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdSig)
				return err != nil
			}, timeout, interval).Should(BeTrue())
		})
	})
})
