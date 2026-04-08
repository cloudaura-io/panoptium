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

func applyAgentPolicy(yamlSpec string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlSpec)
	_, err := utils.Run(cmd)
	return err
}

func applyAgentClusterPolicy(yamlSpec string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlSpec)
	_, err := utils.Run(cmd)
	return err
}

// deleteAgentPolicy deletes a namespaced AgentPolicy by name.
// Uses --ignore-not-found=true so it is safe to call on already-deleted resources.
func deleteAgentPolicy(name string) {
	cmd := exec.Command("kubectl", "delete", "agentpolicy", name,
		"-n", namespace, "--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}

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
func waitForPolicyReady(name string) {
	const timeout = 2 * time.Minute
	By(fmt.Sprintf("waiting for AgentPolicy %s/%s to be Ready=True", namespace, name))
	verifyReady := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "agentpolicy", name,
			"-n", namespace,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"), "AgentPolicy should have Ready=True")
	}
	Eventually(verifyReady, timeout, 5*time.Second).Should(Succeed())
}

// waitForClusterPolicyReady polls until Ready=True or the timeout expires.
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

// persistentCurlPodName generates a unique, RFC 1123-compliant pod name.
// contextName identifies the test context (e.g. "pe2", "ge1").
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
func createPersistentCurlPod() string {
	podName := persistentCurlPodName("ctx")
	return createPersistentCurlPodWithName(podName)
}

// createPersistentCurlPodWithName creates a persistent curl pod with a specific name.
// It waits for the pod to reach Ready state before returning.
func createPersistentCurlPodWithName(podName string) string {
	By(fmt.Sprintf("creating persistent curl pod %s", podName))
	cmd := exec.Command("kubectl", "run", podName,
		"--restart=Never",
		"--namespace", namespace,
		"--labels=app=e2e-agent",
		"--image=curlimages/curl:7.78.0",
		"--", "sleep", "3600")
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		fmt.Sprintf("failed to create persistent curl pod %s", podName))

	By(fmt.Sprintf("waiting for persistent curl pod %s to be Ready", podName))
	waitCmd := exec.Command("kubectl", "wait", fmt.Sprintf("pod/%s", podName),
		"--for=condition=Ready",
		"--namespace", namespace, "--timeout=120s")
	_, err = utils.Run(waitCmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		fmt.Sprintf("persistent curl pod %s did not become Ready", podName))

	return podName
}

// deletePersistentCurlPod deletes a persistent curl pod by name. Safe to call
// on already-deleted pods.
func deletePersistentCurlPod(podName string) {
	By(fmt.Sprintf("deleting persistent curl pod %s", podName))
	cmd := exec.Command("kubectl", "delete", "pod", podName,
		"--namespace", namespace, "--ignore-not-found=true", "--grace-period=0")
	_, _ = utils.Run(cmd)
}

// buildCurlExecArgs constructs the kubectl exec arguments for sending a tool
// call request through an existing persistent curl pod. This is a pure function
// that does not execute any commands, making it testable without a cluster.
func buildCurlExecArgs(podName, gwIP, toolName string, extraHeaders map[string]string) []string {
	payload := fmt.Sprintf(
		`{"model":"gpt-4","messages":[{"role":"user","content":"call tool"}],`+
			`"tools":[{"type":"function","function":{"name":"%s","parameters":{}}}],"stream":false}`,
		toolName,
	)

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

// buildCurlExecArgsNoTools constructs kubectl exec arguments for sending a
// request WITHOUT tools through an existing persistent curl pod. Used to test
// llm_request subcategory policies (whole-request deny).
func buildCurlExecArgsNoTools(podName, gwIP string, extraHeaders map[string]string) []string {
	payload := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}],"stream":false}`

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

// buildCurlExecArgsMultiTool constructs kubectl exec arguments for sending a
// request with multiple tools through an existing persistent curl pod. Returns
// the full response body for inspection of tool stripping behavior.
func buildCurlExecArgsMultiTool(podName, gwIP string, toolNames []string, extraHeaders map[string]string) []string {
	toolsJSON := make([]string, 0, len(toolNames))
	for _, name := range toolNames {
		toolsJSON = append(toolsJSON,
			fmt.Sprintf(`{"type":"function","function":{"name":"%s","parameters":{}}}`, name))
	}
	payload := fmt.Sprintf(
		`{"model":"gpt-4","messages":[{"role":"user","content":"call tool"}],`+
			`"tools":[%s],"stream":false}`,
		strings.Join(toolsJSON, ","),
	)

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
func execToolCallRequest(
	podName, gwIP, toolName string,
) (statusCode int, body string, err error) {
	args := buildCurlExecArgs(podName, gwIP, toolName, nil)
	cmd := exec.Command("kubectl", args...)
	output, execErr := utils.Run(cmd)
	if execErr != nil {
		return 0, "", fmt.Errorf("kubectl exec failed in pod %s: %w", podName, execErr)
	}

	return parseExecResponse(output)
}

// execNoToolRequest sends a POST request WITHOUT tools through AgentGateway.
// Used to test llm_request subcategory policies that deny the entire request.
func execNoToolRequest(podName, gwIP string, extraHeaders map[string]string) (statusCode int, body string, err error) {
	args := buildCurlExecArgsNoTools(podName, gwIP, extraHeaders)
	cmd := exec.Command("kubectl", args...)
	output, execErr := utils.Run(cmd)
	if execErr != nil {
		return 0, "", fmt.Errorf("kubectl exec failed in pod %s: %w", podName, execErr)
	}

	return parseExecResponse(output)
}

// execMultiToolRequest sends a POST request with multiple tools through AgentGateway.
// Used to test tool stripping behavior where some tools are denied/stripped.
func execMultiToolRequest(
	podName, gwIP string, toolNames []string, extraHeaders map[string]string,
) (statusCode int, body string, err error) {
	args := buildCurlExecArgsMultiTool(podName, gwIP, toolNames, extraHeaders)
	cmd := exec.Command("kubectl", args...)
	output, execErr := utils.Run(cmd)
	if execErr != nil {
		return 0, "", fmt.Errorf("kubectl exec failed in pod %s: %w", podName, execErr)
	}

	return parseExecResponse(output)
}

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

// uniqueName generates a unique resource name with the given prefix.
// Uses timestamp suffix to avoid conflicts with concurrent test runs.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1000000)
}

// waitForExtProcReadyWithProbe is the testable core of the ExtProc readiness
// probe. It calls probeFn repeatedly until it returns a non-503 status code,
// or until the timeout expires. This allows unit tests to inject fake probes
// without requiring a live Kubernetes cluster.
func waitForExtProcReadyWithProbe(probeFn func() (int, error), timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		statusCode, err := probeFn()
		if err == nil && statusCode != 503 {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("waitForExtProcReady timed out after %v: last error: %w", timeout, err)
			}
			return fmt.Errorf("waitForExtProcReady timed out after %v: last status %d (expected non-503)", timeout, statusCode)
		}
		time.Sleep(interval)
	}
}

// waitForExtProcReady sends probe requests through the gateway via the
// persistent curl pod until the ExtProc gRPC path is ready (non-503 response).
// This should be called after kubectl wait --for=condition=Available to ensure
// the full gateway->ExtProc data path is established, not just the Kubernetes
// deployment status.
func waitForExtProcReady(curlPod, gwIP string) {
	By("probing gateway for ExtProc readiness (waiting for non-503)")
	probeFn := func() (int, error) {
		statusCode, _, err := execNoToolRequest(curlPod, gwIP, nil)
		return statusCode, err
	}
	err := waitForExtProcReadyWithProbe(probeFn, 60*time.Second, 2*time.Second)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		"ExtProc gRPC path did not become ready within 60s")
}

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
			name: "valid deny error",
			body: `{"error":"policy_violation","rule":"deny-dangerous-tool",` +
				`"message":"tool_call to dangerous_exec is blocked by policy"}`,
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

// TestWaitForExtProcReady_Timeout verifies that waitForExtProcReadyWithProbe
// returns an error when the probe function consistently returns 503 (indicating
// the ExtProc gRPC connection is not yet established).
func TestWaitForExtProcReady_Timeout(t *testing.T) {
	callCount := 0
	// Fake probe that always returns 503 (gateway not ready).
	fakeProbe := func() (int, error) {
		callCount++
		return 503, nil
	}

	// Use a very short timeout so the test completes quickly.
	err := waitForExtProcReadyWithProbe(fakeProbe, 200*time.Millisecond, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected error to contain 'timed out', got %q", err.Error())
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 probe calls, got %d", callCount)
	}
}

// TestWaitForExtProcReady_SuccessAfterRetry verifies that
// waitForExtProcReadyWithProbe returns nil once the probe returns a non-503
// status code, even after initial 503 responses.
func TestWaitForExtProcReady_SuccessAfterRetry(t *testing.T) {
	callCount := 0
	// Returns 503 twice, then 200 on the third call.
	fakeProbe := func() (int, error) {
		callCount++
		if callCount <= 2 {
			return 503, nil
		}
		return 200, nil
	}

	err := waitForExtProcReadyWithProbe(fakeProbe, 5*time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}
	if callCount != 3 {
		t.Errorf("expected 3 probe calls, got %d", callCount)
	}
}

func TestStructuredErrorParsing(t *testing.T) {
	// Test that the structuredError struct correctly unmarshals JSON
	jsonBody := `{"error":"policy_violation","rule":"deny-exec",` +
		`"signature":"PAN-SIG-001","message":"blocked by policy","retry_after":60}`

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
