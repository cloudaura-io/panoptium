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
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	"github.com/panoptium/panoptium/test/utils"
)

// ---------------------------------------------------------------------------
// CRD Management Helpers
// ---------------------------------------------------------------------------

// applyAgentPolicy applies a AgentPolicy CRD from the given YAML spec
// via kubectl. The YAML must be a complete resource manifest.
func applyAgentPolicy(yamlSpec string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlSpec)
	_, err := utils.Run(cmd)
	return err
}

// applyAgentClusterPolicy applies a AgentClusterPolicy CRD from the
// given YAML spec via kubectl.
func applyAgentClusterPolicy(yamlSpec string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlSpec)
	_, err := utils.Run(cmd)
	return err
}

// deleteAgentPolicy deletes a namespaced AgentPolicy by name.
// Uses --ignore-not-found=true so it is safe to call on already-deleted resources.
func deleteAgentPolicy(name, ns string) {
	cmd := exec.Command("kubectl", "delete", "agentpolicy", name,
		"-n", ns, "--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}

// deleteAgentClusterPolicy deletes a cluster-scoped AgentClusterPolicy by name.
func deleteAgentClusterPolicy(name string) {
	cmd := exec.Command("kubectl", "delete", "agentclusterpolicy", name,
		"--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}

// ---------------------------------------------------------------------------
// Status Polling Helpers
// ---------------------------------------------------------------------------

// waitForPolicyReady polls the AgentPolicy status until Ready=True or the
// timeout expires. Uses Ginkgo Eventually for structured polling.
func waitForPolicyReady(name, ns string, timeout time.Duration) {
	By(fmt.Sprintf("waiting for AgentPolicy %s/%s to be Ready=True", ns, name))
	verifyReady := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "agentpolicy", name,
			"-n", ns,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"), "AgentPolicy should have Ready=True")
	}
	Eventually(verifyReady, timeout, 5*time.Second).Should(Succeed())
}

// waitForClusterPolicyReady polls the AgentClusterPolicy status until
// Ready=True or the timeout expires.
func waitForClusterPolicyReady(name string, timeout time.Duration) {
	By(fmt.Sprintf("waiting for AgentClusterPolicy %s to be Ready=True", name))
	verifyReady := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "agentclusterpolicy", name,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"), "AgentClusterPolicy should have Ready=True")
	}
	Eventually(verifyReady, timeout, 5*time.Second).Should(Succeed())
}

// ---------------------------------------------------------------------------
// Persistent Pod Lifecycle Helpers
// ---------------------------------------------------------------------------

// persistentCurlPodName generates a unique, RFC 1123-compliant pod name for a
// persistent curl pod. The contextName identifies the test context (e.g. "pe2",
// "ge1") to make debugging easier.
func persistentCurlPodName(contextName string) string {
	safe := strings.ReplaceAll(contextName, "_", "-")
	name := fmt.Sprintf("e2e-curl-%s-%d", safe, time.Now().UnixNano()%1000000)
	// Truncate to 63 characters (Kubernetes pod name limit)
	if len(name) > 63 {
		name = name[:63]
	}
	// Ensure it does not end with a hyphen
	name = strings.TrimRight(name, "-")
	return name
}

// createPersistentCurlPod creates a long-running curl pod that stays alive via
// "sleep 3600". It waits for the pod to reach Ready state before returning.
// Returns the pod name. Callers should defer deletePersistentCurlPod to clean up.
func createPersistentCurlPod(ns string) string {
	podName := persistentCurlPodName("ctx")
	return createPersistentCurlPodWithName(podName, ns)
}

// createPersistentCurlPodWithName creates a persistent curl pod with a specific name.
// It waits for the pod to reach Ready state before returning.
func createPersistentCurlPodWithName(podName, ns string) string {
	By(fmt.Sprintf("creating persistent curl pod %s", podName))
	cmd := exec.Command("kubectl", "run", podName,
		"--restart=Never",
		"--namespace", ns,
		"--labels=app=e2e-agent",
		"--image=curlimages/curl:7.78.0",
		"--", "sleep", "3600")
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		fmt.Sprintf("failed to create persistent curl pod %s", podName))

	By(fmt.Sprintf("waiting for persistent curl pod %s to be Ready", podName))
	waitCmd := exec.Command("kubectl", "wait", fmt.Sprintf("pod/%s", podName),
		"--for=condition=Ready",
		"--namespace", ns, "--timeout=120s")
	_, err = utils.Run(waitCmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		fmt.Sprintf("persistent curl pod %s did not become Ready", podName))

	return podName
}

// deletePersistentCurlPod deletes a persistent curl pod by name. Safe to call
// on already-deleted pods.
func deletePersistentCurlPod(podName, ns string) {
	By(fmt.Sprintf("deleting persistent curl pod %s", podName))
	cmd := exec.Command("kubectl", "delete", "pod", podName,
		"--namespace", ns, "--ignore-not-found=true", "--grace-period=0")
	_, _ = utils.Run(cmd)
}

// buildCurlExecArgs constructs the kubectl exec arguments for sending a tool
// call request through an existing persistent curl pod. This is a pure function
// that does not execute any commands, making it testable without a cluster.
func buildCurlExecArgs(podName, gwIP, agentID, toolName string, extraHeaders map[string]string) []string {
	payload := fmt.Sprintf(`{"model":"gpt-4","messages":[{"role":"user","content":"call tool"}],"tools":[{"type":"function","function":{"name":"%s","parameters":{}}}],"stream":false}`, toolName)

	args := []string{
		"exec", podName,
		"-n", namespace,
		"--", "curl",
		"-s", "--max-time", "30",
		"-w", "\n---HTTP_STATUS_CODE:%{http_code}---",
		"-X", "POST",
		fmt.Sprintf("http://%s:8080/v1/chat/completions", gwIP),
		"-H", "Content-Type: application/json",
	}

	for k, v := range extraHeaders {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}

	args = append(args, "-d", payload)
	return args
}

// parseExecResponse parses the HTTP status code and body from kubectl exec curl
// output. The curl -w flag appends a status code marker that this function
// extracts. This is a pure function for testability.
func parseExecResponse(output string) (statusCode int, body string, err error) {
	parts := strings.Split(output, "---HTTP_STATUS_CODE:")
	if len(parts) >= 2 {
		codeStr := strings.SplitN(parts[1], "---", 2)[0]
		codeStr = strings.TrimSpace(codeStr)
		code, parseErr := strconv.Atoi(codeStr)
		if parseErr == nil {
			statusCode = code
		}
		body = strings.TrimRight(parts[0], "\n")
	} else {
		body = output
	}

	// Strip kubectl warnings that precede the JSON body.
	if idx := strings.Index(body, "{"); idx > 0 {
		body = body[idx:]
	}

	return statusCode, body, nil
}

// execToolCallRequest sends a POST request through AgentGateway by executing
// curl inside an existing persistent pod via kubectl exec. This replaces
// sendToolCallRequest for PE and GE suites, eliminating pod scheduling overhead.
//
// Tool name identification is derived from the request body (tools[].function.name),
// not from HTTP headers. The x-panoptium-tool-name header is NOT sent because
// policy decisions must use trusted body-parsed data only (NFR-3: Security).
func execToolCallRequest(podName, gwIP, agentID, toolName string, extraHeaders map[string]string) (statusCode int, body string, err error) {
	args := buildCurlExecArgs(podName, gwIP, agentID, toolName, extraHeaders)
	cmd := exec.Command("kubectl", args...)
	output, execErr := utils.Run(cmd)
	if execErr != nil {
		return 0, "", fmt.Errorf("kubectl exec failed in pod %s: %w", podName, execErr)
	}

	return parseExecResponse(output)
}

// ---------------------------------------------------------------------------
// Structured Error Assertion
// ---------------------------------------------------------------------------

// structuredError represents the JSON error body returned by enforcement actions.
type structuredError struct {
	Error      string `json:"error"`
	Rule       string `json:"rule,omitempty"`
	Signature  string `json:"signature,omitempty"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// assertStructuredError parses the response body as a JSON structuredError and
// validates the error type and rule reference match the expected values.
// Returns an error if parsing or validation fails.
func assertStructuredError(body, expectedErrorType, expectedRuleRef string) error {
	body = strings.TrimSpace(body)
	if body == "" {
		return fmt.Errorf("response body is empty")
	}

	var se structuredError
	if err := json.Unmarshal([]byte(body), &se); err != nil {
		return fmt.Errorf("failed to parse JSON error response: %w (body: %q)", err, body)
	}

	if se.Error != expectedErrorType {
		return fmt.Errorf("expected error type %q, got %q", expectedErrorType, se.Error)
	}

	if expectedRuleRef != "" && se.Rule != expectedRuleRef {
		return fmt.Errorf("expected rule reference %q, got %q", expectedRuleRef, se.Rule)
	}

	if se.Message == "" {
		return fmt.Errorf("error message is empty")
	}

	return nil
}

// ---------------------------------------------------------------------------
// Operator Restart Count
// ---------------------------------------------------------------------------

// getOperatorRestartCount returns the total restart count for the operator
// controller-manager pod. Returns 0 if no restarts have occurred.
func getOperatorRestartCount() (int, error) {
	cmd := exec.Command("kubectl", "get", "pods",
		"-l", "control-plane=controller-manager",
		"-n", namespace,
		"-o", "jsonpath={.items[0].status.containerStatuses[0].restartCount}")
	output, err := utils.Run(cmd)
	if err != nil {
		return 0, fmt.Errorf("failed to get operator restart count: %w", err)
	}

	output = strings.TrimSpace(output)
	if output == "" {
		return 0, nil
	}

	count, err := strconv.Atoi(output)
	if err != nil {
		return 0, fmt.Errorf("failed to parse restart count %q: %w", output, err)
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Policy Status Helpers
// ---------------------------------------------------------------------------

// getPolicyRuleCount returns the ruleCount from the AgentPolicy status.
func getPolicyRuleCount(name, ns string) (int32, error) {
	cmd := exec.Command("kubectl", "get", "agentpolicy", name,
		"-n", ns,
		"-o", "jsonpath={.status.ruleCount}")
	output, err := utils.Run(cmd)
	if err != nil {
		return 0, err
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return 0, nil
	}
	count, err := strconv.ParseInt(output, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(count), nil
}

// getPolicyObservedGeneration returns the observedGeneration from the AgentPolicy status.
func getPolicyObservedGeneration(name, ns string) (int64, error) {
	cmd := exec.Command("kubectl", "get", "agentpolicy", name,
		"-n", ns,
		"-o", "jsonpath={.status.observedGeneration}")
	output, err := utils.Run(cmd)
	if err != nil {
		return 0, err
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return 0, nil
	}
	gen, err := strconv.ParseInt(output, 10, 64)
	if err != nil {
		return 0, err
	}
	return gen, nil
}

// ---------------------------------------------------------------------------
// Unique Name Generator
// ---------------------------------------------------------------------------

// uniqueName generates a unique resource name with the given prefix.
// Uses timestamp suffix to avoid conflicts with concurrent test runs.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1000000)
}

// ---------------------------------------------------------------------------
// Unit Tests for Helper Functions
// ---------------------------------------------------------------------------

func TestAssertStructuredError(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		errorType       string
		ruleRef         string
		expectErr       bool
		expectErrSubstr string
	}{
		{
			name:      "valid deny error",
			body:      `{"error":"policy_violation","rule":"deny-dangerous-tool","message":"tool_call to dangerous_exec is blocked by policy"}`,
			errorType: "policy_violation",
			ruleRef:   "deny-dangerous-tool",
			expectErr: false,
		},
		{
			name:      "valid rate_limited error",
			body:      `{"error":"rate_limited","rule":"rate-limit-rule","message":"rate limit exceeded","retry_after":30}`,
			errorType: "rate_limited",
			ruleRef:   "rate-limit-rule",
			expectErr: false,
		},
		{
			name:      "valid error with empty rule ref (not checked)",
			body:      `{"error":"policy_violation","rule":"some-rule","message":"blocked"}`,
			errorType: "policy_violation",
			ruleRef:   "",
			expectErr: false,
		},
		{
			name:            "wrong error type",
			body:            `{"error":"rate_limited","rule":"r1","message":"exceeded"}`,
			errorType:       "policy_violation",
			ruleRef:         "",
			expectErr:       true,
			expectErrSubstr: "expected error type",
		},
		{
			name:            "wrong rule reference",
			body:            `{"error":"policy_violation","rule":"wrong-rule","message":"blocked"}`,
			errorType:       "policy_violation",
			ruleRef:         "expected-rule",
			expectErr:       true,
			expectErrSubstr: "expected rule reference",
		},
		{
			name:            "empty body",
			body:            "",
			errorType:       "policy_violation",
			ruleRef:         "",
			expectErr:       true,
			expectErrSubstr: "empty",
		},
		{
			name:            "invalid JSON",
			body:            `not json at all`,
			errorType:       "policy_violation",
			ruleRef:         "",
			expectErr:       true,
			expectErrSubstr: "failed to parse JSON",
		},
		{
			name:            "missing message field",
			body:            `{"error":"policy_violation","rule":"r1","message":""}`,
			errorType:       "policy_violation",
			ruleRef:         "",
			expectErr:       true,
			expectErrSubstr: "message is empty",
		},
		{
			name:      "body with whitespace trimming",
			body:      `  {"error":"policy_violation","rule":"r1","message":"blocked"}  `,
			errorType: "policy_violation",
			ruleRef:   "r1",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := assertStructuredError(tt.body, tt.errorType, tt.ruleRef)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.expectErrSubstr != "" && !strings.Contains(err.Error(), tt.expectErrSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.expectErrSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestUniqueName(t *testing.T) {
	name1 := uniqueName("test-policy")
	name2 := uniqueName("test-policy")

	if !strings.HasPrefix(name1, "test-policy-") {
		t.Errorf("expected name to start with 'test-policy-', got %q", name1)
	}

	// Names should have the prefix
	if !strings.HasPrefix(name2, "test-policy-") {
		t.Errorf("expected name to start with 'test-policy-', got %q", name2)
	}
}

func TestStructuredErrorParsing(t *testing.T) {
	// Test that the structuredError struct correctly unmarshals JSON
	jsonBody := `{"error":"policy_violation","rule":"deny-exec","signature":"PAN-SIG-001","message":"blocked by policy","retry_after":60}`

	var se structuredError
	err := json.Unmarshal([]byte(jsonBody), &se)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if se.Error != "policy_violation" {
		t.Errorf("Error = %q, want %q", se.Error, "policy_violation")
	}
	if se.Rule != "deny-exec" {
		t.Errorf("Rule = %q, want %q", se.Rule, "deny-exec")
	}
	if se.Signature != "PAN-SIG-001" {
		t.Errorf("Signature = %q, want %q", se.Signature, "PAN-SIG-001")
	}
	if se.Message != "blocked by policy" {
		t.Errorf("Message = %q, want %q", se.Message, "blocked by policy")
	}
	if se.RetryAfter != 60 {
		t.Errorf("RetryAfter = %d, want %d", se.RetryAfter, 60)
	}
}
