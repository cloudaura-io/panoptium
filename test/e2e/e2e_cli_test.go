/*
Copyright 2026.

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
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panoptium/panoptium/test/utils"
)

var _ = Describe("Panoptium CLI E2E", Label("e2e-cli"), Ordered, func() {
	var cliPath string

	BeforeAll(func() {
		By("building the panoptium CLI binary")
		cliBin := filepath.Join("..", "..", "bin", "panoptium-e2e")
		build := exec.Command("go", "build",
			"-o", cliBin,
			"../../cmd/panoptium")
		out, err := utils.Run(build)
		Expect(err).NotTo(HaveOccurred(), "go build: %s", out)

		absPath, err := filepath.Abs(cliBin)
		Expect(err).NotTo(HaveOccurred())
		cliPath = absPath

		By("verifying the panoptium operator is running")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.phase}")
			phase, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(phase).To(Equal("Running"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	Context("version subcommand", func() {
		It("prints build info in human format", func() {
			out, err := utils.Run(exec.Command(cliPath, "version"))
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("panoptium-cli"))
		})

		It("prints structured JSON", func() {
			out, err := utils.Run(exec.Command(cliPath, "version", "-o", "json"))
			Expect(err).NotTo(HaveOccurred())
			var info map[string]interface{}
			Expect(json.Unmarshal([]byte(out), &info)).To(Succeed())
			Expect(info).To(HaveKey("version"))
			Expect(info).To(HaveKey("platform"))
		})
	})

	Context("policy list", func() {
		const policyName = "e2e-cli-list-policy"

		BeforeAll(func() {
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-cli
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: r1
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'shell_exec'"
      action:
        type: deny
        parameters:
          message: "blocked"
      severity: HIGH
`, policyName, namespace)
			apply := exec.Command("kubectl", "apply", "-f", "-")
			apply.Stdin = strings.NewReader(yaml)
			_, err := utils.Run(apply)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			_, _ = utils.Run(exec.Command("kubectl", "delete", "agentpolicy", policyName, "-n", namespace, "--ignore-not-found"))
		})

		It("lists the created policy in human output", func() {
			Eventually(func(g Gomega) string {
				out, err := utils.Run(exec.Command(cliPath, "policy", "list", "-n", namespace))
				g.Expect(err).NotTo(HaveOccurred())
				return out
			}, 30*time.Second, 2*time.Second).Should(ContainSubstring(policyName))
		})

		It("lists the created policy in table output", func() {
			out, err := utils.Run(exec.Command(cliPath, "policy", "list", "-n", namespace, "-o", "table"))
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("NAME"))
			Expect(out).To(ContainSubstring(policyName))
		})

		It("shows the created policy with -o yaml", func() {
			out, err := utils.Run(exec.Command(cliPath, "policy", "show", policyName, "-n", namespace, "-o", "yaml"))
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("metadata:"))
			Expect(out).To(ContainSubstring(policyName))
		})

		It("errors cleanly when the name does not exist", func() {
			cmd := exec.Command(cliPath, "policy", "show", "never-created", "-n", namespace)
			err := cmd.Run()
			Expect(err).To(HaveOccurred(), "show of missing policy should fail")
		})
	})

	Context("policy validate offline", func() {
		It("validates a valid policy YAML without cluster contact", func() {
			yaml := `apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: cli-validate-ok
  namespace: default
spec:
  targetSelector:
    matchLabels:
      app: agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: r1
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'shell_exec'"
      action:
        type: deny
        parameters:
          message: "blocked"
      severity: HIGH
`
			cmd := exec.Command(cliPath, "policy", "validate", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			out, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "validate failed: %s", out)
			Expect(out).To(ContainSubstring("[ok]"))
		})

		It("returns non-zero on an invalid policy", func() {
			yaml := `apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: cli-validate-bad
  namespace: default
spec:
  targetSelector:
    matchLabels:
      app: agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: r1
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'shell_exec'"
      action:
        type: explode
      severity: HIGH
`
			cmd := exec.Command(cliPath, "policy", "validate", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			err := cmd.Run()
			Expect(err).To(HaveOccurred(), "expected non-zero exit for invalid policy")
		})
	})

	Context("quarantine list", func() {
		It("runs without error even if there are no quarantines", func() {
			out, err := utils.Run(exec.Command(cliPath, "quarantine", "list", "-A"))
			Expect(err).NotTo(HaveOccurred())
			_ = out // output may be "no quarantines found" or contain existing state
		})
	})

	Context("signature list", func() {
		It("lists whichever signatures are installed in the cluster", func() {
			out, err := utils.Run(exec.Command(cliPath, "signature", "list", "-o", "table"))
			Expect(err).NotTo(HaveOccurred())
			_ = out
		})
	})
})
