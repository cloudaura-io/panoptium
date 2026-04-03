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

var _ = Describe("CRD Lifecycle E2E", Label("e2e-crd"), Ordered, func() {

	BeforeAll(func() {
		By("verifying panoptium operator is running")
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"))
		}
		Eventually(verifyControllerUp, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	Context("Namespaced CRD (AgentPolicy)", func() {
		const policyName = "e2e-smoke-policy"

		It("should create a AgentPolicy and reach Ready=True status", func() {
			By("applying a valid AgentPolicy resource")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-smoke
  enforcementMode: audit
  priority: 100
  rules:
    - name: smoke-rule
      trigger:
        eventCategory: kernel
        eventSubcategory: process_exec
      action:
        type: alert
      severity: LOW
`, policyName, namespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply AgentPolicy")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "agentpolicy", policyName,
					"-n", namespace, "--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("waiting for Ready=True status condition")
			verifyReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "agentpolicy", policyName,
					"-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "AgentPolicy should have Ready=True")
			}
			Eventually(verifyReady, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	Context("Cluster-scoped CRD (AgentClusterPolicy)", func() {
		const clusterPolicyName = "e2e-smoke-cluster-policy"

		It("should create a AgentClusterPolicy and reach Ready=True status", func() {
			By("applying a valid AgentClusterPolicy resource")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: AgentClusterPolicy
metadata:
  name: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-smoke-cluster
  enforcementMode: audit
  priority: 50
  rules:
    - name: cluster-smoke-rule
      trigger:
        eventCategory: network
        eventSubcategory: connection_established
      action:
        type: alert
      severity: MEDIUM
`, clusterPolicyName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply AgentClusterPolicy")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "agentclusterpolicy", clusterPolicyName,
					"--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("waiting for Ready=True status condition")
			verifyReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "agentclusterpolicy", clusterPolicyName,
					"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "AgentClusterPolicy should have Ready=True")
			}
			Eventually(verifyReady, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	Context("Finalizer behavior (AgentQuarantine)", func() {
		const quarantineName = "e2e-smoke-quarantine"

		It("should add finalizer, set Contained=True, and clean up on deletion", func() {
			By("applying a valid AgentQuarantine resource")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: AgentQuarantine
metadata:
  name: %s
  namespace: %s
spec:
  targetPod: fake-pod
  targetNamespace: %s
  containmentLevel: network-isolate
  reason: e2e smoke test quarantine
`, quarantineName, namespace, namespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply AgentQuarantine")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "agentquarantine", quarantineName,
					"-n", namespace, "--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("waiting for the quarantine-cleanup finalizer to be added")
			verifyFinalizer := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "agentquarantine", quarantineName,
					"-n", namespace,
					"-o", "jsonpath={.metadata.finalizers}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("panoptium.io/quarantine-cleanup"),
					"AgentQuarantine should have the quarantine-cleanup finalizer")
			}
			Eventually(verifyFinalizer, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for Contained=True status condition")
			verifyContained := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "agentquarantine", quarantineName,
					"-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type==\"Contained\")].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "AgentQuarantine should have Contained=True")
			}
			Eventually(verifyContained, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("deleting the AgentQuarantine resource")
			cmd = exec.Command("kubectl", "delete", "agentquarantine", quarantineName,
				"-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete AgentQuarantine")

			By("waiting for the resource to be fully removed")
			verifyGone := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "agentquarantine", quarantineName,
					"-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "AgentQuarantine should no longer exist")
			}
			Eventually(verifyGone, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})
