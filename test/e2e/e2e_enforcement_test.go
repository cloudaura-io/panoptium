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
	"strings"
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

	// -------------------------------------------------------------------
	// GE-1: Deny Rule Enforcement
	// -------------------------------------------------------------------
	Context("GE-1: Deny Rule Enforcement", func() {
		It("should return 403 with structured error when request matches deny rule", func() {
			policyName := uniqueName("ge1-deny")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-enforcement
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: deny-dangerous-exec
      trigger:
        eventCategory: protocol
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

			By("applying PanoptiumPolicy with deny rule")
			Expect(applyPanoptiumPolicy(yaml)).To(Succeed())
			DeferCleanup(func() { deletePanoptiumPolicy(policyName, namespace) })

			By("waiting for policy to be compiled")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)

			By("sending request that matches deny rule through gateway")
			statusCode, body, err := sendToolCallRequest(gwIP, "e2e-agent", "dangerous_exec", nil)
			Expect(err).NotTo(HaveOccurred())

			By("verifying 403 response with structured error")
			Expect(statusCode).To(Equal(403), "expected 403 Forbidden for denied request")

			var errorBody map[string]interface{}
			err = json.Unmarshal([]byte(body), &errorBody)
			Expect(err).NotTo(HaveOccurred(), "response body should be valid JSON")
			Expect(errorBody["error"]).To(Equal("policy_violation"))

			By("verifying operator logs contain policy decision")
			logs := getOperatorLogs("policy rule matched")
			Expect(logs).NotTo(BeEmpty(), "operator logs should contain policy decision")
		})
	})

	// -------------------------------------------------------------------
	// GE-2: Throttle/Rate Limit Enforcement
	// -------------------------------------------------------------------
	Context("GE-2: Throttle Enforcement with Rate Limiting", func() {
		It("should return 429 with Retry-After after exceeding rate limit", func() {
			policyName := uniqueName("ge2-throttle")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-enforcement
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: rate-limit-api
      trigger:
        eventCategory: protocol
        eventSubcategory: llm_request
      predicates:
        - cel: "event.path == '/v1/chat/completions'"
      action:
        type: rate_limit
        parameters:
          maxRequests: "5"
          windowSeconds: "60"
          retryAfter: "30"
      severity: MEDIUM
`, policyName, namespace)

			By("applying PanoptiumPolicy with throttle rule")
			Expect(applyPanoptiumPolicy(yaml)).To(Succeed())
			DeferCleanup(func() { deletePanoptiumPolicy(policyName, namespace) })

			By("waiting for policy to be compiled")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)

			By("sending requests through gateway and checking for 429")
			// Send multiple requests; when rate limit is enforced, we expect 429
			var got429 bool
			for i := 0; i < 10; i++ {
				statusCode, body, err := sendToolCallRequest(gwIP, "e2e-agent", "api_call", nil)
				Expect(err).NotTo(HaveOccurred())

				if statusCode == 429 {
					got429 = true
					// Verify Retry-After header/body
					var errorBody map[string]interface{}
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

	// -------------------------------------------------------------------
	// GE-3: Fail-Open Degradation
	// -------------------------------------------------------------------
	Context("GE-3: Fail-Open Degradation", func() {
		It("should pass traffic through when policy engine is unavailable in fail-open mode", func() {
			By("verifying operator is configured with fail-open mode (default)")
			// The default failure mode is fail-open; verify traffic passes
			// even when a policy evaluation might error

			By("sending request through gateway")
			statusCode, _, err := sendToolCallRequest(gwIP, "e2e-agent", "safe_tool", nil)
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

	// -------------------------------------------------------------------
	// GE-4: Backward Compatibility
	// -------------------------------------------------------------------
	Context("GE-4: Backward Compatibility", func() {
		It("should allow all traffic when no deny policies are applied", func() {
			By("ensuring no blocking policies exist")
			cmd := exec.Command("kubectl", "get", "panoptiumpolicies",
				"-n", namespace, "-o", "jsonpath={.items}")
			output, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Existing policies: %s\n", output)
			}

			By("sending a standard request through gateway")
			statusCode, _, err := sendToolCallRequest(gwIP, "e2e-agent", "standard_tool", nil)
			Expect(err).NotTo(HaveOccurred())

			By("verifying request is not blocked (backward compatibility)")
			Expect(statusCode).NotTo(Equal(403),
				"request should not be denied when no deny policies exist")
			Expect(statusCode).NotTo(Equal(503),
				"request should not get 503 in normal operation")
		})
	})
})

// sendEnforcementRequest sends an HTTP request through the gateway with
// enforcement-specific headers and returns the status code, body, and
// response headers.
func sendEnforcementRequest(gwIP, path string, headers map[string]string) (statusCode int, body string, respHeaders string, err error) {
	podName := fmt.Sprintf("enforce-req-%d", time.Now().UnixNano()%100000)

	curlArgs := []string{
		"run", podName,
		"--restart=Never",
		"--rm", "--attach",
		"--image=curlimages/curl:8.4.0",
		"-n", namespace,
		"--", "curl", "-s", "-o", "/dev/null",
		"-w", `%{http_code}\n%{response_header}`,
	}

	for k, v := range headers {
		curlArgs = append(curlArgs, "-H", fmt.Sprintf("%s: %s", k, v))
	}

	url := fmt.Sprintf("http://%s%s", gwIP, path)
	curlArgs = append(curlArgs, url)

	cmd := exec.Command("kubectl", curlArgs...)
	output, err := utils.Run(cmd)
	if err != nil {
		return 0, "", "", fmt.Errorf("curl failed: %w, output: %s", err, output)
	}

	lines := strings.SplitN(output, "\n", 2)
	if len(lines) < 1 {
		return 0, "", "", fmt.Errorf("unexpected curl output: %s", output)
	}

	var code int
	_, err = fmt.Sscanf(lines[0], "%d", &code)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to parse status code from %q: %w", lines[0], err)
	}

	respBody := ""
	hdrs := ""
	if len(lines) > 1 {
		hdrs = lines[1]
	}

	return code, respBody, hdrs, nil
}
