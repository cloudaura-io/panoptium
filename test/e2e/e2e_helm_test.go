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

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panoptium/panoptium/test/utils"
)

var _ = Describe("Helm Deployment E2E", Label("e2e-helm"), Ordered, func() {

	BeforeAll(func() {
		By("checking if the operator was deployed via Helm")
		cmd := exec.Command("helm", "list", "-n", namespace, "-o", "json")
		output, err := utils.Run(cmd)
		if err != nil || !strings.Contains(output, "panoptium") {
			Skip("operator not deployed via Helm")
		}
	})

	Context("Helm deployment health", func() {
		It("should have the operator deployment available and pod running", func() {
			By("verifying the operator deployment exists and is Available")
			verifyDeploymentAvailable := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment",
					"panoptium-controller-manager",
					"-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type==\"Available\")].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Deployment should have Available=True")
			}
			Eventually(verifyDeploymentAvailable, 60*time.Second, 5*time.Second).Should(Succeed())

			By("verifying the operator pod is Running and Ready")
			verifyPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods",
					"-l", "app.kubernetes.io/instance=panoptium,app.kubernetes.io/component=controller-manager",
					"-n", namespace,
					"-o", "jsonpath={.items[0].status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"))

				cmd = exec.Command("kubectl", "get", "pods",
					"-l", "app.kubernetes.io/instance=panoptium,app.kubernetes.io/component=controller-manager",
					"-n", namespace,
					"-o", "jsonpath={.items[0].status.conditions[?(@.type==\"Ready\")].status}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Operator pod should be Ready")
			}
			Eventually(verifyPodReady, 60*time.Second, 5*time.Second).Should(Succeed())
		})
	})

	Context("Webhook rejects invalid PanoptiumPolicy", func() {
		It("should reject a PanoptiumPolicy with priority 0", func() {
			By("applying an invalid PanoptiumPolicy with priority: 0")
			invalidYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumPolicy
metadata:
  name: e2e-helm-invalid-policy
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-helm-invalid
  enforcementMode: audit
  priority: 0
  rules:
    - name: invalid-rule
      trigger:
        eventCategory: syscall
        eventSubcategory: execve
      action:
        type: alert
      severity: LOW
`, namespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(invalidYAML)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "kubectl apply should fail for invalid PanoptiumPolicy")
			Expect(output).To(ContainSubstring("priority"),
				"Error should mention priority validation failure")
		})
	})

	Context("Webhook accepts valid PanoptiumPolicy", func() {
		const validPolicyName = "e2e-helm-valid-policy"

		It("should accept a valid PanoptiumPolicy", func() {
			By("applying a valid PanoptiumPolicy resource")
			validYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-helm-valid
  enforcementMode: audit
  priority: 100
  rules:
    - name: valid-rule
      trigger:
        eventCategory: syscall
        eventSubcategory: execve
      action:
        type: alert
      severity: LOW
`, validPolicyName, namespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(validYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "kubectl apply should succeed for valid PanoptiumPolicy")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "panoptiumpolicy", validPolicyName,
					"-n", namespace, "--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})
		})
	})

	Context("Helm upgrade changes replicas", func() {
		It("should scale the deployment to 2 replicas via helm upgrade", func() {
			By("upgrading the Helm release to set replicaCount=2")
			cmd := exec.Command("helm", "upgrade", "panoptium",
				"chart/panoptium/",
				"--namespace", namespace,
				"--reuse-values",
				"--set", "replicaCount=2")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm upgrade to 2 replicas should succeed")

			DeferCleanup(func() {
				cmd := exec.Command("helm", "upgrade", "panoptium",
					"chart/panoptium/",
					"--namespace", namespace,
					"--reuse-values",
					"--set", "replicaCount=1")
				_, _ = utils.Run(cmd)
			})

			By("verifying the deployment has 2 ready replicas")
			verifyReplicas := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment",
					"panoptium-controller-manager",
					"-n", namespace,
					"-o", "jsonpath={.status.readyReplicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("2"), "Deployment should have 2 ready replicas")
			}
			Eventually(verifyReplicas, 60*time.Second, 5*time.Second).Should(Succeed())
		})
	})
})
