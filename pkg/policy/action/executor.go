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

// Package action implements action executors for the Panoptium policy engine.
// Each executor handles a specific action type (allow, deny, throttle, alert,
// quarantine, redirect, mutate) and produces a typed ActionResult.
package action

import (
	"fmt"
	"strconv"

	"github.com/panoptium/panoptium/pkg/policy"
)

const paramTrue = "true"

// ActionContext provides the context for executing a policy action.
type ActionContext struct {
	// Event is the triggering policy event.
	Event *policy.PolicyEvent

	// Rule is the compiled rule that matched.
	Rule *policy.CompiledRule

	// CompiledAction is the action configuration from the matched rule.
	CompiledAction policy.CompiledAction

	// PolicyName is the name of the policy containing the matched rule.
	PolicyName string

	// PolicyNamespace is the namespace of the policy.
	PolicyNamespace string
}

// ActionResult is the typed outcome of executing a policy action.
type ActionResult struct {
	// ActionType is the type of action that was executed.
	ActionType string

	// Permitted indicates whether the event/request is allowed to proceed.
	Permitted bool

	// RuleName is the name of the rule that produced this result.
	RuleName string

	// RuleIndex is the index of the rule within the policy.
	RuleIndex int

	// PolicyReference is the namespace/name reference of the policy.
	PolicyReference string

	// Message is a human-readable explanation of the action.
	Message string

	// Annotations contains action-specific metadata key-value pairs.
	Annotations map[string]string

	// StatusCode is the HTTP status code to return (for throttle: 429).
	StatusCode int

	// RetryAfterSeconds is the number of seconds before retrying (for throttle).
	RetryAfterSeconds int

	// AlertEmitted indicates whether an alert event was generated.
	AlertEmitted bool

	// AlertSeverity is the severity of the emitted alert.
	AlertSeverity string

	// ContainmentLevel is the quarantine containment level (1-5).
	ContainmentLevel int

	// DenyNetwork indicates whether network access should be denied (quarantine).
	DenyNetwork bool

	// DenyTools indicates whether tool calls should be denied (quarantine).
	DenyTools bool

	// RedirectTarget is the rewritten target URL/endpoint (for redirect).
	RedirectTarget string

	// Mutations contains the field mutations to apply (for mutate).
	Mutations map[string]string
}

// ActionExecutor is the interface for executing a specific action type.
type ActionExecutor interface {
	// Execute performs the action and returns a typed result.
	Execute(ctx *ActionContext) (*ActionResult, error)
}

// AllowExecutor handles the "allow" action type. It permits the event
// and annotates the decision for audit logging.
type AllowExecutor struct{}

// Execute permits the event and adds an audit annotation.
func (e *AllowExecutor) Execute(ctx *ActionContext) (*ActionResult, error) {
	return &ActionResult{
		ActionType:      "allow",
		Permitted:       true,
		RuleName:        ctx.Rule.Name,
		RuleIndex:       ctx.Rule.Index,
		PolicyReference: formatPolicyRef(ctx.PolicyNamespace, ctx.PolicyName),
		Annotations: map[string]string{
			"audit": "allowed",
		},
	}, nil
}

// DenyExecutor handles the "deny" action type. It blocks the event
// and returns a structured error with the policy rule reference.
type DenyExecutor struct{}

// Execute blocks the event and includes the policy reference.
func (e *DenyExecutor) Execute(ctx *ActionContext) (*ActionResult, error) {
	msg := ctx.CompiledAction.Parameters["message"]
	if msg == "" {
		msg = fmt.Sprintf("denied by policy rule %q", ctx.Rule.Name)
	}

	return &ActionResult{
		ActionType:      "deny",
		Permitted:       false,
		RuleName:        ctx.Rule.Name,
		RuleIndex:       ctx.Rule.Index,
		PolicyReference: formatPolicyRef(ctx.PolicyNamespace, ctx.PolicyName),
		Message:         msg,
		Annotations: map[string]string{
			"audit": "denied",
		},
	}, nil
}

// ThrottleExecutor handles the "throttle" action type. It rate-limits the
// event by returning a 429 status with a Retry-After value.
type ThrottleExecutor struct{}

// Execute produces a throttle decision with retry-after.
func (e *ThrottleExecutor) Execute(ctx *ActionContext) (*ActionResult, error) {
	retryAfter := 60 // default 60 seconds
	if v, ok := ctx.CompiledAction.Parameters["retryAfter"]; ok {
		if parsed, err := strconv.Atoi(v); err == nil {
			retryAfter = parsed
		}
	}

	return &ActionResult{
		ActionType:        "throttle",
		Permitted:         false,
		RuleName:          ctx.Rule.Name,
		RuleIndex:         ctx.Rule.Index,
		PolicyReference:   formatPolicyRef(ctx.PolicyNamespace, ctx.PolicyName),
		StatusCode:        429,
		RetryAfterSeconds: retryAfter,
		Message:           fmt.Sprintf("rate limited, retry after %d seconds", retryAfter),
		Annotations: map[string]string{
			"audit": "throttled",
		},
	}, nil
}

// AlertExecutor handles the "alert" action type. It permits the event
// but emits a high-priority alert event to the Event Bus.
type AlertExecutor struct{}

// Execute permits the event and signals that an alert should be emitted.
func (e *AlertExecutor) Execute(ctx *ActionContext) (*ActionResult, error) {
	severity := ctx.CompiledAction.Parameters["severity"]
	if severity == "" {
		severity = "MEDIUM"
	}

	return &ActionResult{
		ActionType:      "alert",
		Permitted:       true,
		RuleName:        ctx.Rule.Name,
		RuleIndex:       ctx.Rule.Index,
		PolicyReference: formatPolicyRef(ctx.PolicyNamespace, ctx.PolicyName),
		AlertEmitted:    true,
		AlertSeverity:   severity,
		Annotations: map[string]string{
			"audit": "alert-emitted",
		},
	}, nil
}

// QuarantineExecutor handles the "quarantine" action type. It isolates
// the agent by restricting network access and tool calls.
type QuarantineExecutor struct{}

// Execute produces an isolation decision with containment parameters.
func (e *QuarantineExecutor) Execute(ctx *ActionContext) (*ActionResult, error) {
	level := 1 // default containment level
	if v, ok := ctx.CompiledAction.Parameters["level"]; ok {
		if parsed, err := strconv.Atoi(v); err == nil {
			level = parsed
		}
	}

	denyNetwork := ctx.CompiledAction.Parameters["denyNetwork"] == paramTrue
	denyTools := ctx.CompiledAction.Parameters["denyTools"] == paramTrue

	return &ActionResult{
		ActionType:       "quarantine",
		Permitted:        false,
		RuleName:         ctx.Rule.Name,
		RuleIndex:        ctx.Rule.Index,
		PolicyReference:  formatPolicyRef(ctx.PolicyNamespace, ctx.PolicyName),
		ContainmentLevel: level,
		DenyNetwork:      denyNetwork,
		DenyTools:        denyTools,
		Message:          fmt.Sprintf("quarantined at containment level %d", level),
		Annotations: map[string]string{
			"audit": "quarantined",
		},
	}, nil
}

// RedirectExecutor handles the "redirect" action type. It rewrites the
// request target to a configured alternative endpoint.
type RedirectExecutor struct{}

// Execute produces a redirect decision with the rewritten target.
func (e *RedirectExecutor) Execute(ctx *ActionContext) (*ActionResult, error) {
	target := ctx.CompiledAction.Parameters["target"]

	return &ActionResult{
		ActionType:      "redirect",
		Permitted:       true,
		RuleName:        ctx.Rule.Name,
		RuleIndex:       ctx.Rule.Index,
		PolicyReference: formatPolicyRef(ctx.PolicyNamespace, ctx.PolicyName),
		RedirectTarget:  target,
		Message:         fmt.Sprintf("redirected to %s", target),
		Annotations: map[string]string{
			"audit": "redirected",
		},
	}, nil
}

// MutateExecutor handles the "mutate" action type. It modifies the request
// in-flight by applying field-level mutations.
type MutateExecutor struct{}

// Execute produces a mutation decision with the configured field changes.
func (e *MutateExecutor) Execute(ctx *ActionContext) (*ActionResult, error) {
	mutations := make(map[string]string)
	for k, v := range ctx.CompiledAction.Parameters {
		mutations[k] = v
	}

	return &ActionResult{
		ActionType:      "mutate",
		Permitted:       true,
		RuleName:        ctx.Rule.Name,
		RuleIndex:       ctx.Rule.Index,
		PolicyReference: formatPolicyRef(ctx.PolicyNamespace, ctx.PolicyName),
		Mutations:       mutations,
		Message:         "request mutated by policy",
		Annotations: map[string]string{
			"audit": "mutated",
		},
	}, nil
}

// ActionExecutorRegistry dispatches action execution to the appropriate
// typed executor based on action type.
type ActionExecutorRegistry struct {
	executors map[string]ActionExecutor
}

// NewActionExecutorRegistry creates a new registry with all built-in
// action executors registered.
func NewActionExecutorRegistry() *ActionExecutorRegistry {
	return &ActionExecutorRegistry{
		executors: map[string]ActionExecutor{
			"allow":      &AllowExecutor{},
			"deny":       &DenyExecutor{},
			"throttle":   &ThrottleExecutor{},
			"alert":      &AlertExecutor{},
			"quarantine": &QuarantineExecutor{},
			"redirect":   &RedirectExecutor{},
			"mutate":     &MutateExecutor{},
		},
	}
}

// Execute dispatches to the appropriate executor for the given action type.
// Returns an error if no executor is registered for the action type.
func (r *ActionExecutorRegistry) Execute(actionType string, ctx *ActionContext) (*ActionResult, error) {
	exec, ok := r.executors[actionType]
	if !ok {
		return nil, fmt.Errorf("no executor registered for action type %q", actionType)
	}
	return exec.Execute(ctx)
}

// formatPolicyRef formats a policy reference as "namespace/name" or just "name".
func formatPolicyRef(namespace, name string) string {
	if namespace != "" {
		return namespace + "/" + name
	}
	return name
}
