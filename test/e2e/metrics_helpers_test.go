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
	"testing"
)

func TestParseMetricValue(t *testing.T) {
	metricsOutput := `# HELP panoptium_extproc_requests_total Total number of ExtProc requests observed, by provider
# TYPE panoptium_extproc_requests_total counter
panoptium_extproc_requests_total{provider="openai"} 3
panoptium_extproc_requests_total{provider="anthropic"} 1
# HELP panoptium_extproc_tokens_observed_total Total number of tokens observed
# TYPE panoptium_extproc_tokens_observed_total counter
panoptium_extproc_tokens_observed_total{provider="openai"} 42
# HELP panoptium_agent_identity_resolution_total Total number of agent identity resolution attempts
# TYPE panoptium_agent_identity_resolution_total counter
panoptium_agent_identity_resolution_total{method="header",result="success"} 5
panoptium_agent_identity_resolution_total{method="header",result="unknown"} 2
# HELP panoptium_extproc_active_streams Number of active streams
# TYPE panoptium_extproc_active_streams gauge
panoptium_extproc_active_streams 0
`

	tests := []struct {
		name      string
		metric    string
		labels    map[string]string
		wantValue float64
		wantFound bool
	}{
		{
			name:      "exact label match",
			metric:    "panoptium_extproc_requests_total",
			labels:    map[string]string{"provider": "openai"},
			wantValue: 3,
			wantFound: true,
		},
		{
			name:      "different label value",
			metric:    "panoptium_extproc_requests_total",
			labels:    map[string]string{"provider": "anthropic"},
			wantValue: 1,
			wantFound: true,
		},
		{
			name:      "tokens metric",
			metric:    "panoptium_extproc_tokens_observed_total",
			labels:    map[string]string{"provider": "openai"},
			wantValue: 42,
			wantFound: true,
		},
		{
			name:      "multi label match",
			metric:    "panoptium_agent_identity_resolution_total",
			labels:    map[string]string{"method": "header", "result": "success"},
			wantValue: 5,
			wantFound: true,
		},
		{
			name:      "metric without labels",
			metric:    "panoptium_extproc_active_streams",
			labels:    nil,
			wantValue: 0,
			wantFound: true,
		},
		{
			name:      "nonexistent metric",
			metric:    "panoptium_nonexistent",
			labels:    nil,
			wantValue: 0,
			wantFound: false,
		},
		{
			name:      "wrong label value",
			metric:    "panoptium_extproc_requests_total",
			labels:    map[string]string{"provider": "google"},
			wantValue: 0,
			wantFound: false,
		},
		{
			name:      "partial label match should not match",
			metric:    "panoptium_agent_identity_resolution_total",
			labels:    map[string]string{"method": "header", "result": "failure"},
			wantValue: 0,
			wantFound: false,
		},
		{
			name:      "nil labels matches any label set",
			metric:    "panoptium_extproc_requests_total",
			labels:    nil,
			wantValue: 3,
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found := parseMetricValue(metricsOutput, tt.metric, tt.labels)
			if found != tt.wantFound {
				t.Errorf("parseMetricValue() found = %v, want %v", found, tt.wantFound)
			}
			if found && value != tt.wantValue {
				t.Errorf("parseMetricValue() value = %v, want %v", value, tt.wantValue)
			}
		})
	}
}

func TestParseMetricValueEmpty(t *testing.T) {
	_, found := parseMetricValue("", "panoptium_extproc_requests_total", nil)
	if found {
		t.Error("parseMetricValue() should return false for empty input")
	}
}
