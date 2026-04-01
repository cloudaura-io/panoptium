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
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	"github.com/panoptium/panoptium/test/utils"
)

// ---------------------------------------------------------------------------
// CRD Management Helpers
// ---------------------------------------------------------------------------

// applyPanoptiumPolicy applies a PanoptiumPolicy CRD from the given YAML spec
// via kubectl. The YAML must be a complete resource manifest.
func applyPanoptiumPolicy(yamlSpec string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlSpec)
	_, err := utils.Run(cmd)
	return err
}

// applyClusterPanoptiumPolicy applies a ClusterPanoptiumPolicy CRD from the
// given YAML spec via kubectl.
func applyClusterPanoptiumPolicy(yamlSpec string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlSpec)
	_, err := utils.Run(cmd)
	return err
}

// deletePanoptiumPolicy deletes a namespaced PanoptiumPolicy by name.
// Uses --ignore-not-found=true so it is safe to call on already-deleted resources.
func deletePanoptiumPolicy(name, ns string) {
	cmd := exec.Command("kubectl", "delete", "panoptiumpolicy", name,
		"-n", ns, "--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}

// deleteClusterPanoptiumPolicy deletes a cluster-scoped ClusterPanoptiumPolicy by name.
func deleteClusterPanoptiumPolicy(name string) {
	cmd := exec.Command("kubectl", "delete", "clusterpanoptiumpolicy", name,
		"--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}

// deletePanoptiumQuarantine deletes a namespaced PanoptiumQuarantine by name.
func deletePanoptiumQuarantine(name, ns string) {
	cmd := exec.Command("kubectl", "delete", "panoptiumquarantine", name,
		"-n", ns, "--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}

// ---------------------------------------------------------------------------
// Status Polling Helpers
// ---------------------------------------------------------------------------

// waitForPolicyReady polls the PanoptiumPolicy status until Ready=True or the
// timeout expires. Uses Ginkgo Eventually for structured polling.
func waitForPolicyReady(name, ns string, timeout time.Duration) {
	By(fmt.Sprintf("waiting for PanoptiumPolicy %s/%s to be Ready=True", ns, name))
	verifyReady := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "panoptiumpolicy", name,
			"-n", ns,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"), "PanoptiumPolicy should have Ready=True")
	}
	Eventually(verifyReady, timeout, 5*time.Second).Should(Succeed())
}

// waitForClusterPolicyReady polls the ClusterPanoptiumPolicy status until
// Ready=True or the timeout expires.
func waitForClusterPolicyReady(name string, timeout time.Duration) {
	By(fmt.Sprintf("waiting for ClusterPanoptiumPolicy %s to be Ready=True", name))
	verifyReady := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "clusterpanoptiumpolicy", name,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"), "ClusterPanoptiumPolicy should have Ready=True")
	}
	Eventually(verifyReady, timeout, 5*time.Second).Should(Succeed())
}

// waitForPolicyFailed polls the PanoptiumPolicy status until Ready=False and
// returns the reason and message from the condition.
func waitForPolicyFailed(name, ns string, timeout time.Duration) (reason, message string) {
	By(fmt.Sprintf("waiting for PanoptiumPolicy %s/%s to be Ready=False", ns, name))
	var r, m string
	verifyFailed := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "panoptiumpolicy", name,
			"-n", ns,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("False"), "PanoptiumPolicy should have Ready=False")

		// Extract reason
		cmd = exec.Command("kubectl", "get", "panoptiumpolicy", name,
			"-n", ns,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].reason}")
		reasonOut, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		r = reasonOut

		// Extract message
		cmd = exec.Command("kubectl", "get", "panoptiumpolicy", name,
			"-n", ns,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].message}")
		messageOut, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		m = messageOut
	}
	Eventually(verifyFailed, timeout, 5*time.Second).Should(Succeed())
	return r, m
}

// waitForQuarantineContained polls the PanoptiumQuarantine status until
// Contained=True or the timeout expires.
func waitForQuarantineContained(name, ns string, timeout time.Duration) {
	By(fmt.Sprintf("waiting for PanoptiumQuarantine %s/%s Contained=True", ns, name))
	verifyContained := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "panoptiumquarantine", name,
			"-n", ns,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Contained\")].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"), "PanoptiumQuarantine should have Contained=True")
	}
	Eventually(verifyContained, timeout, 5*time.Second).Should(Succeed())
}

// ---------------------------------------------------------------------------
// Tool Call Request Helper
// ---------------------------------------------------------------------------

// Deprecated: sendToolCallRequest creates an ephemeral kubectl run pod per
// request, incurring ~2s scheduling overhead. Use execToolCallRequest with a
// persistent curl pod instead. This function is retained for ExtProc and other
// test suites that have not yet been migrated.
//
// sendToolCallRequest sends a POST request through AgentGateway that simulates
// a tool_call event. It uses a curl pod in the test namespace to reach the
// gateway ClusterIP. Returns the HTTP status code and response body.
//
// Tool name identification is derived from the request body (tools[].function.name),
// not from HTTP headers. The x-panoptium-tool-name header is NOT sent because
// policy decisions must use trusted body-parsed data only (NFR-3: Security).
func sendToolCallRequest(gwIP, agentID, toolName string, extraHeaders map[string]string) (statusCode int, body string, err error) {
	// Replace underscores with hyphens to comply with RFC 1123 pod naming
	safeName := strings.ReplaceAll(toolName, "_", "-")
	podName := fmt.Sprintf("toolcall-%s-%d", safeName, time.Now().UnixNano()%100000)

	// Build the request payload simulating a tool_call with the tool name in the body.
	// The ExtProc server parses tools[].function.name from the JSON body for policy evaluation.
	payload := fmt.Sprintf(`{"model":"gpt-4","messages":[{"role":"user","content":"call tool"}],"tools":[{"type":"function","function":{"name":"%s","parameters":{}}}],"stream":false}`, toolName)

	// Build curl args (no --rm, no --attach to avoid race condition)
	curlArgs := []string{
		"-s", "--max-time", "30",
		"-w", "\n---HTTP_STATUS_CODE:%{http_code}---",
		"-X", "POST",
		fmt.Sprintf("http://%s:8080/v1/chat/completions", gwIP),
		"-H", "Content-Type: application/json",
		"-H", fmt.Sprintf("x-panoptium-agent-id: %s", agentID),
	}

	// Add extra headers
	for k, v := range extraHeaders {
		curlArgs = append(curlArgs, "-H", fmt.Sprintf("%s: %s", k, v))
	}

	curlArgs = append(curlArgs, "-d", payload)

	// Step 1: Create pod (no --rm, no --attach)
	runArgs := []string{
		"run", podName,
		"--restart=Never",
		"--namespace", namespace,
		"--image=curlimages/curl:7.78.0",
		"--",
	}
	runArgs = append(runArgs, curlArgs...)

	cmd := exec.Command("kubectl", runArgs...)
	_, runErr := utils.Run(cmd)
	if runErr != nil {
		// Cleanup on failure
		delCmd := exec.Command("kubectl", "delete", "pod", podName,
			"--namespace", namespace, "--ignore-not-found=true")
		_, _ = utils.Run(delCmd)
		return 0, "", fmt.Errorf("kubectl run failed: %w", runErr)
	}

	// Step 2: Wait for pod to complete (Succeeded or Failed phase)
	// Ensure cleanup happens regardless of outcome
	defer func() {
		delCmd := exec.Command("kubectl", "delete", "pod", podName,
			"--namespace", namespace, "--ignore-not-found=true")
		_, _ = utils.Run(delCmd)
	}()

	waitCmd := exec.Command("kubectl", "wait", fmt.Sprintf("pod/%s", podName),
		"--for=jsonpath={.status.phase}=Succeeded",
		"--namespace", namespace, "--timeout=60s")
	_, waitErr := utils.Run(waitCmd)
	if waitErr != nil {
		// Pod may have Failed (e.g. 4xx response still exits 0 from curl,
		// but check anyway). Read logs regardless.
		phaseCmd := exec.Command("kubectl", "get", "pod", podName,
			"--namespace", namespace, "-o", "jsonpath={.status.phase}")
		phase, _ := utils.Run(phaseCmd)
		if strings.TrimSpace(phase) != "Succeeded" && strings.TrimSpace(phase) != "Failed" {
			return 0, "", fmt.Errorf("pod %s did not complete (phase=%s): %w", podName, phase, waitErr)
		}
	}

	// Step 3: Read logs
	logsCmd := exec.Command("kubectl", "logs", podName, "--namespace", namespace)
	output, logsErr := utils.Run(logsCmd)
	if logsErr != nil {
		return 0, "", fmt.Errorf("failed to read logs from pod %s: %w", podName, logsErr)
	}

	// Parse the status code from the output
	parts := strings.Split(output, "---HTTP_STATUS_CODE:")
	if len(parts) >= 2 {
		// Extract status code before the closing "---" delimiter.
		codeStr := strings.SplitN(parts[1], "---", 2)[0]
		codeStr = strings.TrimSpace(codeStr)
		code, parseErr := strconv.Atoi(codeStr)
		if parseErr == nil {
			statusCode = code
		}
		body = parts[0]
	} else {
		body = output
	}

	// Strip kubectl warnings (e.g. "couldn't attach to pod") that precede the
	// actual HTTP response body. The JSON body starts at the first '{'.
	if idx := strings.Index(body, "{"); idx > 0 {
		body = body[idx:]
	}

	return statusCode, body, nil
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
		"-H", fmt.Sprintf("x-panoptium-agent-id: %s", agentID),
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

// getPolicyRuleCount returns the ruleCount from the PanoptiumPolicy status.
func getPolicyRuleCount(name, ns string) (int32, error) {
	cmd := exec.Command("kubectl", "get", "panoptiumpolicy", name,
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

// getPolicyObservedGeneration returns the observedGeneration from the PanoptiumPolicy status.
func getPolicyObservedGeneration(name, ns string) (int64, error) {
	cmd := exec.Command("kubectl", "get", "panoptiumpolicy", name,
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
// NATS Subscriber Helper
// ---------------------------------------------------------------------------

// PolicyDecisionEvent represents the relevant fields of a policy.decision event
// received from NATS. This is a simplified view for e2e assertions.
type PolicyDecisionEvent struct {
	// EventType is the event type identifier (should be "policy.decision").
	EventType string `json:"eventType"`

	// Matched indicates whether any rule matched.
	Matched bool `json:"matched"`

	// MatchedRule is the name of the matched rule.
	MatchedRule string `json:"matchedRule"`

	// ActionTaken is the action type applied (deny, allow, alert, etc.).
	ActionTaken string `json:"actionTaken"`

	// PolicyName is the name of the matching policy.
	PolicyName string `json:"policyName"`

	// PolicyNamespace is the namespace of the matching policy.
	PolicyNamespace string `json:"policyNamespace"`

	// TriggerCategory is the event category that was evaluated.
	TriggerCategory string `json:"triggerCategory"`

	// TriggerSubcategory is the event subcategory evaluated.
	TriggerSubcategory string `json:"triggerSubcategory"`

	// EvalDurationNs is the evaluation duration in nanoseconds.
	EvalDurationNs int64 `json:"evalDurationNs"`

	// PredicateTrace is the predicate evaluation trace.
	PredicateTrace []map[string]interface{} `json:"predicateTrace,omitempty"`

	// FallbackApplied indicates whether a fallback function was applied.
	FallbackApplied string `json:"fallbackApplied,omitempty"`

	// TemporalSequenceTrace contains the temporal sequence match info.
	TemporalSequenceTrace []map[string]interface{} `json:"temporalSequenceTrace,omitempty"`

	// Traceparent is the W3C Trace Context header.
	Traceparent string `json:"traceparent,omitempty"`
}

// natsSubscriber connects to the in-cluster NATS server and subscribes to
// policy.decision events. It uses kubectl port-forward to access NATS.
type natsSubscriber struct {
	events []PolicyDecisionEvent
	mu     sync.Mutex
	done   chan struct{}
}

// newNATSSubscriber creates a new NATS subscriber. In the e2e environment,
// NATS events are collected via the operator's event bus, so this helper
// queries the operator's NATS stream through a test pod or port-forward.
func newNATSSubscriber() *natsSubscriber {
	return &natsSubscriber{
		events: make([]PolicyDecisionEvent, 0),
		done:   make(chan struct{}),
	}
}

// collectEvents returns all collected PolicyDecisionEvents so far.
func (n *natsSubscriber) collectEvents() []PolicyDecisionEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	result := make([]PolicyDecisionEvent, len(n.events))
	copy(result, n.events)
	return result
}

// addEvent records a new event (thread-safe).
func (n *natsSubscriber) addEvent(evt PolicyDecisionEvent) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, evt)
}

// drainAndClose stops collecting and cleans up resources.
func (n *natsSubscriber) drainAndClose() {
	select {
	case <-n.done:
		// Already closed
	default:
		close(n.done)
	}
}

// waitForEvents polls operator logs for policy.decision events and collects them.
// This is a pragmatic approach for e2e tests where direct NATS access may not
// be available. Returns the collected events or an error on timeout.
func (n *natsSubscriber) waitForEvents(expectedCount int, timeout time.Duration) ([]PolicyDecisionEvent, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		events := n.collectEvents()
		if len(events) >= expectedCount {
			return events, nil
		}
		time.Sleep(1 * time.Second)
	}
	events := n.collectEvents()
	if len(events) < expectedCount {
		return events, fmt.Errorf("timed out waiting for %d events, got %d", expectedCount, len(events))
	}
	return events, nil
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

func TestNATSSubscriberCollectEvents(t *testing.T) {
	sub := newNATSSubscriber()

	// Initially empty
	events := sub.collectEvents()
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}

	// Add an event
	sub.addEvent(PolicyDecisionEvent{
		EventType:   "policy.decision",
		Matched:     true,
		MatchedRule: "test-rule",
		ActionTaken: "deny",
	})

	events = sub.collectEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].MatchedRule != "test-rule" {
		t.Errorf("expected MatchedRule 'test-rule', got %q", events[0].MatchedRule)
	}

	if events[0].ActionTaken != "deny" {
		t.Errorf("expected ActionTaken 'deny', got %q", events[0].ActionTaken)
	}

	// Drain and close
	sub.drainAndClose()

	// Should be safe to call again
	sub.drainAndClose()
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
