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
		It("Should set Ready condition to True for valid signature", func() {
			sig := &panoptiumiov1alpha1.PanoptiumThreatSignature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-sig-ready",
				},
				Spec: panoptiumiov1alpha1.PanoptiumThreatSignatureSpec{
					Protocols:   []string{"mcp"},
					Category:    "prompt_injection",
					Severity:    panoptiumiov1alpha1.SeverityHigh,
					Description: "Detect prompt injection attempts",
					Detection: panoptiumiov1alpha1.DetectionSpec{
						Patterns: []panoptiumiov1alpha1.PatternRule{
							{
								Regex:  `(?i)ignore\s+previous\s+instructions`,
								Weight: 0.9,
								Target: "tool_description",
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, sig)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-sig-ready"}
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

			Expect(createdSig.Status.CompiledPatterns).Should(Equal(int32(1)))
		})

		It("Should set Ready to False for invalid regex", func() {
			sig := &panoptiumiov1alpha1.PanoptiumThreatSignature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-sig-invalid-regex",
				},
				Spec: panoptiumiov1alpha1.PanoptiumThreatSignatureSpec{
					Protocols:   []string{"mcp"},
					Category:    "prompt_injection",
					Severity:    panoptiumiov1alpha1.SeverityMedium,
					Description: "Invalid regex signature",
					Detection: panoptiumiov1alpha1.DetectionSpec{
						Patterns: []panoptiumiov1alpha1.PatternRule{
							{
								Regex:  `(?i)ignore\s+(`,
								Weight: 0.9,
								Target: "tool_description",
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, sig)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-sig-invalid-regex"}
			createdSig := &panoptiumiov1alpha1.PanoptiumThreatSignature{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdSig)
				if err != nil {
					return false
				}
				for _, c := range createdSig.Status.Conditions {
					if c.Type == "Ready" && c.Status == metav1.ConditionFalse && c.Reason == "CompilationFailed" {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})

		It("Should track ObservedGeneration", func() {
			sig := &panoptiumiov1alpha1.PanoptiumThreatSignature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-sig-generation",
				},
				Spec: panoptiumiov1alpha1.PanoptiumThreatSignatureSpec{
					Protocols:   []string{"mcp"},
					Category:    "data_exfiltration",
					Severity:    panoptiumiov1alpha1.SeverityLow,
					Description: "Generation test signature",
					Detection: panoptiumiov1alpha1.DetectionSpec{
						Patterns: []panoptiumiov1alpha1.PatternRule{
							{
								Regex:  `(?i)exfiltrate`,
								Weight: 0.8,
								Target: "body",
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, sig)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-sig-generation"}
			createdSig := &panoptiumiov1alpha1.PanoptiumThreatSignature{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, lookupKey, createdSig)
				if err != nil {
					return false
				}
				return createdSig.Status.ObservedGeneration > 0
			}, timeout, interval).Should(BeTrue())
		})

		It("Should handle deletion cleanly", func() {
			sig := &panoptiumiov1alpha1.PanoptiumThreatSignature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-sig-delete",
				},
				Spec: panoptiumiov1alpha1.PanoptiumThreatSignatureSpec{
					Protocols:   []string{"mcp"},
					Category:    "prompt_injection",
					Severity:    panoptiumiov1alpha1.SeverityInfo,
					Description: "Delete test signature",
					Detection: panoptiumiov1alpha1.DetectionSpec{
						Patterns: []panoptiumiov1alpha1.PatternRule{
							{
								Regex:  `(?i)test`,
								Weight: 0.5,
								Target: "body",
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, sig)).Should(Succeed())

			lookupKey := types.NamespacedName{Name: "test-sig-delete"}
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
