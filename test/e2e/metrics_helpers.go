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
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:golint,revive

	"github.com/panoptium/panoptium/test/utils"
)

// parseMetricValue parses a Prometheus text format metrics output and returns
// the value for the first matching metric line. If labels is nil, it matches
// the first line with the given metric name regardless of labels. Returns the
// value and whether the metric was found.
func parseMetricValue(metricsOutput, metricName string, labels map[string]string) (float64, bool) {
	for _, line := range strings.Split(metricsOutput, "\n") {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if the line starts with the metric name
		if !strings.HasPrefix(line, metricName) {
			continue
		}

		// Extract the part after the metric name
		rest := line[len(metricName):]

		// Parse labels if present
		var lineLabels map[string]string
		var valueStr string

		if strings.HasPrefix(rest, "{") {
			closeBrace := strings.Index(rest, "}")
			if closeBrace < 0 {
				continue
			}
			labelStr := rest[1:closeBrace]
			lineLabels = parseLabels(labelStr)
			valueStr = strings.TrimSpace(rest[closeBrace+1:])
		} else {
			// No labels — value follows directly after a space
			lineLabels = map[string]string{}
			valueStr = strings.TrimSpace(rest)
		}

		// If labels filter is nil, match any label set
		if labels != nil && !labelsMatch(lineLabels, labels) {
			continue
		}

		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			continue
		}
		return value, true
	}
	return 0, false
}

// parseLabels parses a Prometheus label string like `provider="openai",method="header"`
// into a map.
func parseLabels(labelStr string) map[string]string {
	result := make(map[string]string)
	if labelStr == "" {
		return result
	}

	pairs := strings.Split(labelStr, ",")
	for _, pair := range pairs {
		eqIdx := strings.Index(pair, "=")
		if eqIdx < 0 {
			continue
		}
		key := strings.TrimSpace(pair[:eqIdx])
		value := strings.TrimSpace(pair[eqIdx+1:])
		// Remove surrounding quotes
		value = strings.Trim(value, "\"")
		result[key] = value
	}
	return result
}

// labelsMatch checks if lineLabels contains all key-value pairs from wantLabels.
func labelsMatch(lineLabels, wantLabels map[string]string) bool {
	for k, v := range wantLabels {
		if lineLabels[k] != v {
			return false
		}
	}
	return true
}

// queryMetric fetches the metrics endpoint from the operator pod and returns
// the value of the specified metric. It execs into the operator pod to curl
// the metrics endpoint using the service account token for authentication.
func queryMetric(metricName string, labels map[string]string) (float64, bool) {
	By(fmt.Sprintf("querying metric %s with labels %v", metricName, labels))

	// Get the service account token
	token, err := serviceAccountToken()
	if err != nil {
		return 0, false
	}

	// Use kubectl exec to curl the metrics endpoint from within the cluster
	cmd := exec.Command("kubectl", "run", fmt.Sprintf("metrics-query-%d", time.Now().UnixNano()%100000),
		"--restart=Never",
		"--rm", "--attach",
		"--namespace", namespace,
		"--image=curlimages/curl:7.78.0",
		"--",
		"-s", "-k",
		"-H", fmt.Sprintf("Authorization: Bearer %s", token),
		fmt.Sprintf("https://%s.%s.svc.cluster.local:8443/metrics", metricsServiceName, namespace),
	)

	output, err := utils.Run(cmd)
	if err != nil {
		return 0, false
	}

	return parseMetricValue(output, metricName, labels)
}

// waitForMetric polls the metrics endpoint until the specified metric reaches
// the minimum value or the timeout expires. Returns the final value and whether
// the threshold was met.
func waitForMetric(metricName string, labels map[string]string, minValue float64, timeout time.Duration) (float64, bool) {
	By(fmt.Sprintf("waiting for metric %s >= %v (timeout: %s)", metricName, minValue, timeout))

	deadline := time.Now().Add(timeout)
	pollInterval := 5 * time.Second

	var lastValue float64
	for time.Now().Before(deadline) {
		value, found := queryMetric(metricName, labels)
		if found {
			lastValue = value
			if value >= minValue {
				return value, true
			}
		}
		time.Sleep(pollInterval)
	}

	return lastValue, false
}
