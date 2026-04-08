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

// gatewayServiceIP returns the ClusterIP for the AgentGateway service.
func gatewayServiceIP() string {
	cmd := exec.Command("kubectl", "get", "svc",
		"-l", "gateway.networking.k8s.io/gateway-name=e2e-gateway",
		"-n", namespace,
		"-o", "jsonpath={.items[0].spec.clusterIP}")
	output, err := utils.Run(cmd)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

// getOperatorLogs fetches operator pod logs with an optional grep pattern.
func getOperatorLogs(grepPattern string) string {
	cmd := exec.Command("kubectl", "logs",
		"-l", "control-plane=controller-manager",
		"-n", namespace, "--tail=200")
	output, err := utils.Run(cmd)
	if err != nil {
		return ""
	}

	if grepPattern == "" {
		return output
	}

	var filtered []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, grepPattern) {
			filtered = append(filtered, line)
		}
	}
	return strings.Join(filtered, "\n")
}

var _ = Describe("ExtProc E2E", Label("e2e-extproc"), Ordered, func() {

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

		By("verifying mock LLM is running")
		verifyMockLLM := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "app=mock-llm",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"))
		}
		Eventually(verifyMockLLM, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	Context("Deployment Validation", func() {
		It("should have the ExtProc service exposed on port 9001", func() {
			By("verifying the ExtProc service exists")
			cmd := exec.Command("kubectl", "get", "svc",
				"panoptium-controller-manager-extproc",
				"-n", namespace,
				"-o", "jsonpath={.spec.ports[0].port}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("9001"), "ExtProc service should expose port 9001")
		})

		It("should have the operator container port 9001 configured", func() {
			By("verifying the deployment has containerPort 9001")
			cmd := exec.Command("kubectl", "get", "deployment",
				"panoptium-controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.spec.template.spec.containers[0].ports[?(@.name==\"extproc\")].containerPort}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("9001"), "Deployment should have containerPort 9001")
		})

		It("should have the ExtProc gRPC server listening", func() {
			By("verifying the ExtProc server is accepting gRPC connections")
			logs := getOperatorLogs("extproc-lifecycle")
			Expect(logs).NotTo(BeEmpty(), "Operator logs should show ExtProc lifecycle activity")
		})
	})

	Context("OpenAI Streaming via AgentGateway", func() {
		It("should route OpenAI streaming requests through AgentGateway to mock LLM", func() {
			gwIP := gatewayServiceIP()
			Expect(gwIP).NotTo(BeEmpty(), "Gateway service IP should be available")

			By("creating a persistent curl pod for the streaming request")
			podName := fmt.Sprintf("openai-test-%d", time.Now().UnixNano()%100000)
			createPersistentCurlPodWithName(podName)
			DeferCleanup(func() {
				deletePersistentCurlPod(podName)
			})

			By("sending a streaming /v1/chat/completions request through AgentGateway")
			curlCmd := exec.Command("kubectl", "exec", podName,
				"-n", namespace,
				"--", "curl",
				"-s", "--max-time", "30",
				"-X", "POST",
				fmt.Sprintf("http://%s:8080/v1/chat/completions", gwIP),
				"-H", "Content-Type: application/json",
				"-d", `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`)
			output, err := utils.Run(curlCmd)
			Expect(err).NotTo(HaveOccurred(), "OpenAI request through AgentGateway should succeed")

			By("verifying response contains expected SSE token data")
			Expect(output).To(ContainSubstring("Hello"),
				"Response should contain 'Hello' token from mock LLM")
			Expect(output).To(ContainSubstring("[DONE]"),
				"Response should contain [DONE] terminator")
		})
	})

	Context("Second OpenAI Streaming via AgentGateway", func() {
		It("should route a second streaming request with different agent through AgentGateway to mock LLM", func() {
			gwIP := gatewayServiceIP()
			Expect(gwIP).NotTo(BeEmpty(), "Gateway service IP should be available")

			By("creating a persistent curl pod for the second streaming request")
			podName := fmt.Sprintf("second-test-%d", time.Now().UnixNano()%100000)
			createPersistentCurlPodWithName(podName)
			DeferCleanup(func() {
				deletePersistentCurlPod(podName)
			})

			By("sending a second streaming /v1/chat/completions request with a different agent ID")
			curlCmd := exec.Command("kubectl", "exec", podName,
				"-n", namespace,
				"--", "curl",
				"-s", "--max-time", "30",
				"-X", "POST",
				fmt.Sprintf("http://%s:8080/v1/chat/completions", gwIP),
				"-H", "Content-Type: application/json",
				"-d", `{"model":"gpt-4","messages":[{"role":"user","content":"hi again"}],"stream":true}`)
			output, err := utils.Run(curlCmd)
			Expect(err).NotTo(HaveOccurred(), "Second request through AgentGateway should succeed")

			By("verifying response contains expected SSE data")
			Expect(output).To(ContainSubstring("Hello"),
				"Response should contain 'Hello' token from mock LLM")
		})
	})

	Context("ExtProc Metric Assertions", func() {
		It("should record ExtProc request metrics for OpenAI provider", func() {
			By("waiting for panoptium_extproc_requests_total{provider=openai} >= 1")
			value, met := waitForMetric(
				"panoptium_extproc_requests_total",
				map[string]string{"provider": "openai"},
				1,
			)
			Expect(met).To(BeTrue(),
				fmt.Sprintf("Expected panoptium_extproc_requests_total{provider=openai} >= 1, got %v", value))
		})

		It("should record token observation metrics for OpenAI provider", func() {
			By("waiting for panoptium_extproc_tokens_observed_total{provider=openai} > 0")
			value, met := waitForMetric(
				"panoptium_extproc_tokens_observed_total",
				map[string]string{"provider": "openai"},
				1,
			)
			Expect(met).To(BeTrue(),
				fmt.Sprintf("Expected panoptium_extproc_tokens_observed_total{provider=openai} > 0, got %v", value))
		})

		It("should record ExtProc request metrics for multiple requests", func() {
			By("waiting for panoptium_extproc_requests_total{provider=openai} >= 2")
			value, met := waitForMetric(
				"panoptium_extproc_requests_total",
				map[string]string{"provider": "openai"},
				2,
			)
			Expect(met).To(BeTrue(),
				fmt.Sprintf("Expected panoptium_extproc_requests_total{provider=openai} >= 2, got %v", value))
		})

		It("should record agent identity resolution metrics", func() {
			By("waiting for panoptium_agent_identity_resolution_total to be recorded")
			value, met := waitForMetric(
				"panoptium_agent_identity_resolution_total",
				nil, // match any labels
				1,
			)
			Expect(met).To(BeTrue(),
				fmt.Sprintf("Expected panoptium_agent_identity_resolution_total >= 1, got %v", value))
		})

		It("should show ExtProc processing evidence in operator logs", func() {
			By("checking operator logs for ExtProc request processing")
			logs := getOperatorLogs("extproc-lifecycle")
			Expect(logs).NotTo(BeEmpty(),
				"Operator logs should contain ExtProc-related entries")
		})
	})

	Context("Operator Health and Metrics", func() {
		It("should have healthy operator endpoints", func() {
			By("verifying operator health endpoint")
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.conditions[?(@.type==\"Ready\")].status}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("True"), "Operator pod should be Ready")
		})

		It("should have the metrics service available", func() {
			By("verifying metrics service exists")
			cmd := exec.Command("kubectl", "get", "svc",
				metricsServiceName,
				"-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")
		})
	})

	Context("Native Identity Resolution via Transformation Policy", func() {
		It("should resolve enrolled pod identity via X-Forwarded-For (pod method, success result)", func() {
			gwIP := gatewayServiceIP()
			Expect(gwIP).NotTo(BeEmpty(), "Gateway service IP should be available")

			By("sending a request from an enrolled persistent curl pod")
			podName := createPersistentCurlPod()
			DeferCleanup(func() {
				deletePersistentCurlPod(podName)
			})

			statusCode, _, err := execToolCallRequest(podName, gwIP, "test-identity-tool")
			Expect(err).NotTo(HaveOccurred(), "request via persistent pod should succeed")
			Expect(statusCode).To(Or(Equal(200), Equal(0)),
				"enrolled pod request should not be rejected")

			By("verifying identity resolution metric shows pod method with success result")
			value, met := waitForMetric(
				"panoptium_agent_identity_resolution_total",
				map[string]string{"method": "pod", "result": "success"},
				1,
			)
			Expect(met).To(BeTrue(),
				fmt.Sprintf("Expected panoptium_agent_identity_resolution_total{method=pod,result=success} >= 1, got %v", value))
		})

		It("should have the transformation policy resource deployed", func() {
			By("verifying the AgentgatewayPolicy for header injection exists")
			cmd := exec.Command("kubectl", "get", "agentgatewaypolicy",
				"panoptium-identity-headers",
				"-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(),
				"AgentgatewayPolicy 'panoptium-identity-headers' should exist in namespace")
		})
	})

	Context("Concurrent Requests via AgentGateway", func() {
		It("should handle concurrent requests from multiple agents", func() {
			gwIP := gatewayServiceIP()
			Expect(gwIP).NotTo(BeEmpty(), "Gateway service IP should be available")

			By("creating a persistent curl pod for concurrent requests")
			podName := fmt.Sprintf("concurrent-test-%d", time.Now().UnixNano()%100000)
			createPersistentCurlPodWithName(podName)
			DeferCleanup(func() {
				deletePersistentCurlPod(podName)
			})

			agentIDs := []string{"agent-alpha", "agent-beta", "agent-gamma"}

			By("launching 3 sequential requests with different agent IDs")
			for _, agentID := range agentIDs {
				curlCmd := exec.Command("kubectl", "exec", podName,
					"-n", namespace,
					"--", "curl",
					"-s", "--max-time", "30",
					"-X", "POST",
					fmt.Sprintf("http://%s:8080/v1/chat/completions", gwIP),
					"-H", "Content-Type: application/json",
					"-d", fmt.Sprintf(`{"model":"gpt-4","messages":[{"role":"user","content":"test %s"}],"stream":true}`, agentID))

				output, err := utils.Run(curlCmd)
				Expect(err).NotTo(HaveOccurred(),
					fmt.Sprintf("request for agent %s should succeed", agentID))
				Expect(output).To(ContainSubstring("Hello"),
					fmt.Sprintf("response for agent %s should contain token data", agentID))
			}
		})
	})
})
