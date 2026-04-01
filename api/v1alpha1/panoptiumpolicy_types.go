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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EnforcementMode defines the enforcement behavior of a policy.
// +kubebuilder:validation:Enum=enforcing;audit;disabled
type EnforcementMode string

const (
	// EnforcementModeEnforcing means actions are actively enforced.
	EnforcementModeEnforcing EnforcementMode = "enforcing"

	// EnforcementModeAudit means actions are logged but not enforced.
	EnforcementModeAudit EnforcementMode = "audit"

	// EnforcementModeDisabled means the policy is inactive.
	EnforcementModeDisabled EnforcementMode = "disabled"
)

// Severity indicates the severity level of a policy rule.
// +kubebuilder:validation:Enum=INFO;LOW;MEDIUM;HIGH;CRITICAL
type Severity string

const (
	// SeverityInfo indicates an informational event.
	SeverityInfo Severity = "INFO"

	// SeverityLow indicates a low-severity event.
	SeverityLow Severity = "LOW"

	// SeverityMedium indicates a medium-severity event.
	SeverityMedium Severity = "MEDIUM"

	// SeverityHigh indicates a high-severity event.
	SeverityHigh Severity = "HIGH"

	// SeverityCritical indicates a critical-severity event.
	SeverityCritical Severity = "CRITICAL"
)

// ActionType defines the type of response action a policy rule can take.
// +kubebuilder:validation:Enum=allow;deny;alert;quarantine;rateLimit
type ActionType string

const (
	// ActionTypeAllow permits the request.
	ActionTypeAllow ActionType = "allow"

	// ActionTypeDeny blocks the request.
	ActionTypeDeny ActionType = "deny"

	// ActionTypeAlert generates an alert without blocking.
	ActionTypeAlert ActionType = "alert"

	// ActionTypeQuarantine isolates the offending pod.
	ActionTypeQuarantine ActionType = "quarantine"

	// ActionTypeRateLimit applies rate limiting to the request.
	ActionTypeRateLimit ActionType = "rateLimit"
)

// Trigger defines the event category and subcategory pattern that activates a policy rule.
type Trigger struct {
	// EventCategory is the top-level event category to match (e.g., "syscall", "network", "llm").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	EventCategory string `json:"eventCategory"`

	// EventSubcategory is the event subcategory pattern to match (e.g., "execve", "connect", "request.start").
	// Supports glob patterns with '*' wildcard.
	// +optional
	EventSubcategory string `json:"eventSubcategory,omitempty"`
}

// Predicate defines a condition that must be true for a rule's action to execute.
type Predicate struct {
	// CEL is a Common Expression Language expression evaluated against the event.
	// The expression must return a boolean value.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	CEL string `json:"cel"`
}

// Action defines the response action taken when a policy rule matches.
type Action struct {
	// Type is the kind of action to take.
	// +kubebuilder:validation:Required
	Type ActionType `json:"type"`

	// Parameters contains action-specific configuration as key-value pairs.
	// For rateLimit: "requestsPerMinute", "burstSize"
	// +optional
	Parameters map[string]string `json:"parameters,omitempty"`
}

// PolicyRule defines a single trigger-predicate-action rule within a PanoptiumPolicy.
type PolicyRule struct {
	// Name is a human-readable identifier for this rule.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Trigger defines the event that activates this rule.
	// +kubebuilder:validation:Required
	Trigger Trigger `json:"trigger"`

	// Predicates are conditions that must all be true for the action to execute.
	// Each predicate contains a CEL expression evaluated against the triggering event.
	// +optional
	Predicates []Predicate `json:"predicates,omitempty"`

	// Action defines the response to take when the rule matches.
	// +kubebuilder:validation:Required
	Action Action `json:"action"`

	// Severity indicates the severity level of events matching this rule.
	// +kubebuilder:validation:Required
	Severity Severity `json:"severity"`
}

// PanoptiumPolicySpec defines the desired state of a PanoptiumPolicy.
type PanoptiumPolicySpec struct {
	// TargetSelector selects the pods this policy applies to.
	// +kubebuilder:validation:Required
	TargetSelector metav1.LabelSelector `json:"targetSelector"`

	// EnforcementMode controls whether actions are enforced, audited, or disabled.
	// +kubebuilder:validation:Required
	// +kubebuilder:default=audit
	EnforcementMode EnforcementMode `json:"enforcementMode"`

	// Priority determines evaluation order when multiple policies match the same pod.
	// Higher priority policies override lower ones on conflict. Range: 1-1000.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	Priority int32 `json:"priority"`

	// Rules is the list of trigger-predicate-action rules evaluated by this policy.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Rules []PolicyRule `json:"rules"`
}

// PanoptiumPolicyStatus defines the observed state of a PanoptiumPolicy.
type PanoptiumPolicyStatus struct {
	// Conditions represent the latest available observations of the policy's state.
	// Supported condition types: Ready, Enforcing, Degraded, Error.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// RuleCount is the number of compiled rules in this policy.
	// +optional
	RuleCount int32 `json:"ruleCount,omitempty"`

	// MatchingPods is the number of pods currently matching the targetSelector.
	// +optional
	MatchingPods int32 `json:"matchingPods,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Enforcement",type=string,JSONPath=`.spec.enforcementMode`,description="Enforcement mode"
// +kubebuilder:printcolumn:name="Priority",type=integer,JSONPath=`.spec.priority`,description="Policy priority"
// +kubebuilder:printcolumn:name="Rules",type=integer,JSONPath=`.status.ruleCount`,description="Number of rules"
// +kubebuilder:printcolumn:name="Pods",type=integer,JSONPath=`.status.matchingPods`,description="Matching pods"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready status"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PanoptiumPolicy is the Schema for the panoptiumpolicies API.
// It defines namespace-scoped security policies with trigger-predicate-action rules
// for monitoring and controlling AI agent behavior within Kubernetes.
type PanoptiumPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired policy configuration.
	Spec PanoptiumPolicySpec `json:"spec,omitempty"`

	// Status reflects the observed state of the policy.
	Status PanoptiumPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PanoptiumPolicyList contains a list of PanoptiumPolicy resources.
type PanoptiumPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PanoptiumPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PanoptiumPolicy{}, &PanoptiumPolicyList{})
}
