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

// Package enforce implements policy enforcement actions for the Panoptium
// ExtProc server, including deny, throttle, modify, and suspend actions.
package enforce

import (
	"encoding/json"
	"fmt"
	"strconv"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

// EnforcementMode controls the behavior of the ExtProc enforcement layer.
type EnforcementMode string

const (
	// ModeEnforcing actively enforces policy decisions (block, throttle, etc.).
	ModeEnforcing EnforcementMode = "enforcing"

	// ModeAudit logs enforcement decisions but does not block traffic.
	ModeAudit EnforcementMode = "audit"
)

// ErrorResponse represents the structured JSON error body returned by
// enforcement actions.
type ErrorResponse struct {
	// Error is the machine-readable error type.
	Error string `json:"error"`

	// Rule is the full reference to the matching policy rule.
	Rule string `json:"rule,omitempty"`

	// Signature is the PAN-SIG signature identifier.
	Signature string `json:"signature,omitempty"`

	// Message is a human-readable explanation.
	Message string `json:"message"`

	// RetryAfter is the number of seconds until retry (optional).
	RetryAfter int `json:"retry_after,omitempty"`
}

// NewImmediateResponse creates an ExtProc ImmediateResponse with the given
// HTTP status code and JSON body.
func NewImmediateResponse(statusCode typev3.StatusCode, body *ErrorResponse) *extprocv3.ProcessingResponse {
	bodyBytes, _ := json.Marshal(body)

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{
					Code: statusCode,
				},
				Body: bodyBytes,
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						{
							Header: &corev3.HeaderValue{
								Key:      "content-type",
								RawValue: []byte("application/json"),
							},
						},
					},
				},
			},
		},
	}
}

// NewDenyResponse creates a 403 Forbidden ImmediateResponse for a policy
// deny action.
func NewDenyResponse(rule, signature, message string) *extprocv3.ProcessingResponse {
	return NewImmediateResponse(typev3.StatusCode_Forbidden, &ErrorResponse{
		Error:     "policy_violation",
		Rule:      rule,
		Signature: signature,
		Message:   message,
	})
}

// NewUnenrolledDenyResponse creates a 403 Forbidden response for un-enrolled
// pods in enforcing mode.
func NewUnenrolledDenyResponse(sourceIP string) *extprocv3.ProcessingResponse {
	return NewImmediateResponse(typev3.StatusCode_Forbidden, &ErrorResponse{
		Error:   "unenrolled_pod",
		Message: "request from un-enrolled pod (source IP: " + sourceIP + ")",
	})
}

// NewThrottleResponse creates a 429 Too Many Requests ImmediateResponse for
// a policy throttle/rate-limit action. It includes a Retry-After header and
// a structured JSON error body.
func NewThrottleResponse(rule, signature string, retryAfterSeconds int) *extprocv3.ProcessingResponse {
	bodyBytes, _ := json.Marshal(&ErrorResponse{
		Error:      "rate_limited",
		Rule:       rule,
		Signature:  signature,
		Message:    fmt.Sprintf("rate limited, retry after %d seconds", retryAfterSeconds),
		RetryAfter: retryAfterSeconds,
	})

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{
					Code: typev3.StatusCode_TooManyRequests,
				},
				Body: bodyBytes,
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						{
							Header: &corev3.HeaderValue{
								Key:      "content-type",
								RawValue: []byte("application/json"),
							},
						},
						{
							Header: &corev3.HeaderValue{
								Key:      "retry-after",
								RawValue: []byte(strconv.Itoa(retryAfterSeconds)),
							},
						},
					},
				},
			},
		},
	}
}
