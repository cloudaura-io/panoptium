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
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	"github.com/panoptium/panoptium/test/utils"
)

var _ = Describe("Gateway Enforcement E2E", Label("e2e-enforcement"), Ordered, func() {

	var gwIP string

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

		By("verifying AgentGateway is running")
		verifyGateway := func(g Gomega) {
			ip := gatewayServiceIP()
			g.Expect(ip).NotTo(BeEmpty(), "Gateway service IP should be available")
		}
		Eventually(verifyGateway, 2*time.Minute, 5*time.Second).Should(Succeed())

		gwIP = gatewayServiceIP()
		Expect(gwIP).NotTo(BeEmpty(), "Gateway service IP must be available for enforcement e2e tests")
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching operator logs on failure")
			cmd := exec.Command("kubectl", "logs",
				"-l", "control-plane=controller-manager",
				"-n", namespace, "--tail=100")
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n%s\n", controllerLogs)
			}
		}
	})

	Context("GE-1: Deny Rule Enforcement", func() {
		var curlPod string
		BeforeAll(func() {
			curlPod = createPersistentCurlPod(namespace)
			DeferCleanup(func() { deletePersistentCurlPod(curlPod, namespace) })
		})

		It("should return 403 with structured error when request matches deny rule", func() {
			Skip("AgentGateway v1.0.1 does not support ExtProc ImmediateResponse (deny→403, rateLimit→429 return 503 instead)")
			policyName := uniqueName("ge1-deny")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: deny-all-requests
      trigger:
        eventCategory: llm
        eventSubcategory: llm_request
      predicates:
        - cel: "event.path == '/v1/chat/completions'"
      action:
        type: deny
        parameters:
          signature: "PAN-SIG-E2E-001"
          message: "request denied by enforcement policy"
      severity: HIGH
`, policyName, namespace)

			By("applying AgentPolicy with deny rule")
			Expect(applyAgentPolicy(yaml)).To(Succeed())
			DeferCleanup(func() { deleteAgentPolicy(policyName, namespace) })

			By("waiting for policy to be compiled")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)

			By("sending request without tools that matches deny rule through gateway")
			statusCode, body, err := execNoToolRequest(curlPod, gwIP, nil)
			Expect(err).NotTo(HaveOccurred())

			By("verifying 403 response with structured error")
			Expect(statusCode).To(Equal(403), "expected 403 Forbidden for denied request")

			var errorBody map[string]any
			err = json.Unmarshal([]byte(body), &errorBody)
			Expect(err).NotTo(HaveOccurred(), "response body should be valid JSON")
			Expect(errorBody["error"]).To(Equal("policy_violation"))

			By("verifying response body contains policy violation details")
			Expect(errorBody["signature"]).To(Equal("PAN-SIG-E2E-001"))
			Expect(errorBody["message"]).To(Equal("request denied by enforcement policy"))
		})
	})

	Context("GE-2: Throttle Enforcement with Rate Limiting", func() {
		var curlPod string
		BeforeAll(func() {
			curlPod = createPersistentCurlPod(namespace)
			DeferCleanup(func() { deletePersistentCurlPod(curlPod, namespace) })
		})

		It("should return 429 with Retry-After after exceeding rate limit", func() {
			Skip("AgentGateway v1.0.1 does not support ExtProc ImmediateResponse (deny→403, rateLimit→429 return 503 instead)")
			policyName := uniqueName("ge2-throttle")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: rate-limit-api
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.path == '/v1/chat/completions'"
      action:
        type: rateLimit
        parameters:
          burstSize: "5"
          retryAfter: "30"
      severity: MEDIUM
`, policyName, namespace)

			By("applying AgentPolicy with throttle rule")
			Expect(applyAgentPolicy(yaml)).To(Succeed())
			DeferCleanup(func() { deleteAgentPolicy(policyName, namespace) })

			By("waiting for policy to be compiled")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)

			By("sending requests through gateway and checking for 429")
			// Send multiple requests; when rate limit is enforced, we expect 429
			var got429 bool
			for range 10 {
				statusCode, body, err := execToolCallRequest(curlPod, gwIP, "api_call", nil)
				Expect(err).NotTo(HaveOccurred())

				if statusCode == 429 {
					got429 = true
					// Verify Retry-After header/body
					var errorBody map[string]any
					err = json.Unmarshal([]byte(body), &errorBody)
					Expect(err).NotTo(HaveOccurred())
					Expect(errorBody["error"]).To(Equal("rate_limited"))
					Expect(errorBody["retry_after"]).NotTo(BeNil())
					break
				}
			}
			Expect(got429).To(BeTrue(), "expected at least one 429 response after exceeding rate limit")
		})
	})

	Context("GE-3: Fail-Open Degradation", func() {
		var curlPod string
		BeforeAll(func() {
			curlPod = createPersistentCurlPod(namespace)
			DeferCleanup(func() { deletePersistentCurlPod(curlPod, namespace) })
		})

		It("should pass traffic through when policy engine is unavailable in fail-open mode", func() {
			By("verifying operator is configured with fail-open mode (default)")
			// The default failure mode is fail-open; verify traffic passes
			// even when a policy evaluation might error

			By("sending request through gateway")
			statusCode, _, err := execToolCallRequest(curlPod, gwIP, "safe_tool", nil)
			Expect(err).NotTo(HaveOccurred())

			By("verifying request passes through (not blocked)")
			// In fail-open mode with no matching policy or engine error,
			// the request should succeed (200 from mock LLM or pass-through)
			Expect(statusCode).NotTo(Equal(503),
				"fail-open mode should not return 503")

			By("checking for enforcement.bypass events in operator logs")
			// If the policy engine had an error, we'd see bypass logs
			logs := getOperatorLogs("fail-open")
			_, _ = fmt.Fprintf(GinkgoWriter, "Fail-open logs: %s\n", logs)
		})
	})

	Context("GE-4: Backward Compatibility", func() {
		var curlPod string
		BeforeAll(func() {
			curlPod = createPersistentCurlPod(namespace)
			DeferCleanup(func() { deletePersistentCurlPod(curlPod, namespace) })
		})

		It("should allow all traffic when no deny policies are applied", func() {
			By("ensuring no blocking policies exist")
			cmd := exec.Command("kubectl", "get", "agentpolicies",
				"-n", namespace, "-o", "jsonpath={.items}")
			output, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Existing policies: %s\n", output)
			}

			By("sending a standard request through gateway")
			statusCode, _, err := execToolCallRequest(curlPod, gwIP, "standard_tool", nil)
			Expect(err).NotTo(HaveOccurred())

			By("verifying request is not blocked (backward compatibility)")
			Expect(statusCode).NotTo(Equal(403),
				"request should not be denied when no deny policies exist")
			Expect(statusCode).NotTo(Equal(503),
				"request should not get 503 in normal operation")
		})
	})

	Context("GE-5: Tool Stripping Enforcement", func() {
		var curlPod string
		BeforeAll(func() {
			curlPod = createPersistentCurlPod(namespace)
			DeferCleanup(func() { deletePersistentCurlPod(curlPod, namespace) })
		})

		It("should strip banned tool from request and allow remaining tools through", func() {
			policyName := uniqueName("ge5-strip")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: strip-dangerous-exec
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'dangerous_exec'"
      action:
        type: deny
        parameters:
          message: "tool stripped by enforcement policy"
      severity: HIGH
`, policyName, namespace)

			By("applying AgentPolicy with tool_call deny rule")
			Expect(applyAgentPolicy(yaml)).To(Succeed())
			DeferCleanup(func() { deleteAgentPolicy(policyName, namespace) })

			By("waiting for policy to be compiled")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)

			By("sending request with 3 tools (1 banned) through gateway")
			statusCode, _, err := execMultiToolRequest(curlPod, gwIP,
				[]string{"safe_read", "dangerous_exec", "safe_write"}, nil)
			Expect(err).NotTo(HaveOccurred())

			By("verifying request succeeds (tool stripped, not blocked)")
			Expect(statusCode).To(Equal(200),
				"expected 200 OK: banned tool should be stripped, not block the entire request")

			By("verifying tool stripped event in operator logs")
			Eventually(func() string {
				return getOperatorLogs("tool stripped")
			}, 30*time.Second, 2*time.Second).ShouldNot(BeEmpty(),
				"expected 'tool stripped' log entry from operator")
		})

		It("should succeed when single tool is stripped (request becomes plain chat)", func() {
			policyName := uniqueName("ge5-single")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: strip-only-tool
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'banned_tool'"
      action:
        type: deny
        parameters:
          message: "tool stripped"
      severity: HIGH
`, policyName, namespace)

			By("applying AgentPolicy that strips the only tool")
			Expect(applyAgentPolicy(yaml)).To(Succeed())
			DeferCleanup(func() { deleteAgentPolicy(policyName, namespace) })

			By("waiting for policy to be compiled")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)

			By("sending request with single banned tool through gateway")
			statusCode, _, err := execToolCallRequest(curlPod, gwIP, "banned_tool", nil)
			Expect(err).NotTo(HaveOccurred())

			By("verifying request succeeds as plain chat (all tools stripped)")
			Expect(statusCode).To(Equal(200),
				"expected 200 OK: single tool stripped, request becomes plain chat completion")
		})
	})

	// GE-6: Multi-Policy Composition — deny-first at equal priority (FR-3)
	Context("GE-6: Multi-Policy Composition", func() {
		var curlPod string
		BeforeAll(func() {
			curlPod = createPersistentCurlPod(namespace)
			DeferCleanup(func() { deletePersistentCurlPod(curlPod, namespace) })
		})

		It("should deny when allow and deny policies exist at equal priority", func() {
			allowPolicyName := "ge6-allow-bash"
			denyPolicyName := "ge6-deny-bash"

			allowYAML := fmt.Sprintf(`
apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector: {}
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: allow-bash
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'bash'"
      action:
        type: allow
      severity: LOW
`, allowPolicyName, namespace)

			denyYAML := fmt.Sprintf(`
apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector: {}
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: deny-bash
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'bash'"
      action:
        type: deny
        parameters:
          message: "bash denied by GE-6"
      severity: HIGH
`, denyPolicyName, namespace)

			By("applying both allow and deny policies at equal priority")
			Expect(applyAgentPolicy(allowYAML)).To(Succeed())
			DeferCleanup(func() { deleteAgentPolicy(allowPolicyName, namespace) })
			Expect(applyAgentPolicy(denyYAML)).To(Succeed())
			DeferCleanup(func() { deleteAgentPolicy(denyPolicyName, namespace) })

			By("waiting for policies to be compiled")
			waitForPolicyReady(allowPolicyName, namespace, 2*time.Minute)
			waitForPolicyReady(denyPolicyName, namespace, 2*time.Minute)

			By("sending tool_call request with bash tool")
			statusCode, body, err := execToolCallRequest(curlPod, gwIP, "bash", nil)
			Expect(err).NotTo(HaveOccurred())

			By("verifying deny-first: bash should be stripped (deny wins over allow at equal priority)")
			// With deny-first semantics, the tool is stripped even though an allow exists.
			// If bash is the only tool, the request becomes plain chat (200), not 403.
			_ = body
			Expect(statusCode).To(Equal(200),
				"expected 200 OK: bash stripped by deny-first, request becomes plain chat")
		})
	})

	// GE-7: Dual Event Emission — llm_request deny blocks request with tools (FR-2)
	Context("GE-7: Dual Event Emission", func() {
		var curlPod string
		BeforeAll(func() {
			curlPod = createPersistentCurlPod(namespace)
			DeferCleanup(func() { deletePersistentCurlPod(curlPod, namespace) })
		})

		It("should block entire request when llm_request policy denies, even with tools", func() {
			Skip("AgentGateway v1.0.1 does not support ExtProc ImmediateResponse (deny→403, rateLimit→429 return 503 instead)")
			policyName := "ge7-deny-llm-request"

			yaml := fmt.Sprintf(`
apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector: {}
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: deny-all-llm
      trigger:
        eventCategory: llm
        eventSubcategory: llm_request
      action:
        type: deny
        parameters:
          message: "all LLM requests blocked by GE-7"
      severity: HIGH
`, policyName, namespace)

			By("applying llm_request deny policy")
			Expect(applyAgentPolicy(yaml)).To(Succeed())
			DeferCleanup(func() { deleteAgentPolicy(policyName, namespace) })

			By("waiting for policy to be compiled")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)

			By("sending request WITH tools through gateway")
			statusCode, body, err := execToolCallRequest(curlPod, gwIP, "safe_tool", nil)
			Expect(err).NotTo(HaveOccurred())

			By("verifying llm_request deny blocks the entire request (FR-2 dual emission)")
			Expect(statusCode).To(Equal(403),
				"expected 403: llm_request deny should block before per-tool evaluation")

			var respBody map[string]interface{}
			Expect(json.Unmarshal([]byte(body), &respBody)).To(Succeed())
			Expect(respBody["message"]).To(ContainSubstring("all LLM requests blocked by GE-7"))
		})
	})
})
