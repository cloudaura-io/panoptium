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

// PatternRule defines a single regex detection pattern with weight and target.
type PatternRule struct {
	// Regex is the regular expression pattern to match against content.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Regex string `json:"regex"`

	// Weight is the score weight (0.0-1.0) for this pattern when matched.
	// +kubebuilder:validation:Required
	Weight float64 `json:"weight"`

	// Target specifies where to apply this pattern.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=tool_description;tool_args;message_content;body
	Target string `json:"target"`
}

// EntropyRule defines entropy-based detection configuration.
type EntropyRule struct {
	// Enabled indicates whether entropy analysis is active.
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Threshold is the Shannon entropy threshold (bits per character) above which content is flagged.
	// +optional
	Threshold float64 `json:"threshold,omitempty"`

	// Target specifies where to apply entropy analysis.
	// +optional
	// +kubebuilder:validation:Enum=tool_description;tool_args;message_content;body
	Target string `json:"target,omitempty"`
}

// Base64Rule defines base64 payload detection configuration.
type Base64Rule struct {
	// Enabled indicates whether base64 detection is active.
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// MinLength is the minimum length of base64 strings to flag.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=20
	MinLength int `json:"minLength,omitempty"`

	// Target specifies where to apply base64 detection.
	// +optional
	// +kubebuilder:validation:Enum=tool_description;tool_args;message_content;body
	Target string `json:"target,omitempty"`
}

// CELRule defines a CEL expression for complex detection rules.
type CELRule struct {
	// Expression is the CEL expression to evaluate.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Expression string `json:"expression"`

	// Weight is the score weight (0.0-1.0) for this expression when matched.
	// +kubebuilder:validation:Required
	Weight float64 `json:"weight"`
}

// DetectionSpec defines the detection rules within a threat signature.
type DetectionSpec struct {
	// Patterns is a list of regex-based detection patterns with weights.
	// +optional
	Patterns []PatternRule `json:"patterns,omitempty"`

	// Entropy configures entropy-based anomaly detection.
	// +optional
	Entropy *EntropyRule `json:"entropy,omitempty"`

	// Base64 configures base64 payload detection.
	// +optional
	Base64 *Base64Rule `json:"base64,omitempty"`

	// CEL is a list of CEL expressions for complex detection rules.
	// +optional
	CEL []CELRule `json:"cel,omitempty"`
}

// PanoptiumThreatSignatureSpec defines the desired state of a PanoptiumThreatSignature.
type PanoptiumThreatSignatureSpec struct {
	// Protocols lists which protocols this signature applies to (empty = all).
	// +optional
	Protocols []string `json:"protocols,omitempty"`

	// Category is the attack category for grouping and policy matching
	// (e.g., "prompt_injection", "data_exfiltration", "role_confusion").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Category string `json:"category"`

	// Severity indicates the severity level of threats matching this signature.
	// +kubebuilder:validation:Required
	Severity Severity `json:"severity"`

	// MitreAtlas is the optional MITRE ATLAS reference (e.g., "AML.T0051.001").
	// +optional
	MitreAtlas string `json:"mitreAtlas,omitempty"`

	// Detection defines the detection rules for this signature.
	// +kubebuilder:validation:Required
	Detection DetectionSpec `json:"detection"`

	// Description is a human-readable description of what this signature detects.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Description string `json:"description"`
}

// PanoptiumThreatSignatureStatus defines the observed state of a PanoptiumThreatSignature.
type PanoptiumThreatSignatureStatus struct {
	// Conditions represent the latest available observations of the signature's state.
	// Supported condition types: Ready, Invalid.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// CompiledPatterns is the number of successfully compiled regex patterns.
	// +optional
	CompiledPatterns int32 `json:"compiledPatterns,omitempty"`

	// CompiledCEL is the number of successfully compiled CEL expressions.
	// +optional
	CompiledCEL int32 `json:"compiledCEL,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Category",type=string,JSONPath=`.spec.category`,description="Attack category"
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`,description="Threat severity"
// +kubebuilder:printcolumn:name="Patterns",type=integer,JSONPath=`.status.compiledPatterns`,description="Compiled patterns"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready status"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PanoptiumThreatSignature is the Schema for the panoptiumthreatsignatures API.
// It defines threat detection patterns that identify specific attack techniques
// or suspicious behaviors in monitored AI agent traffic. Signatures are cluster-scoped
// and consumed by protocol parsers via the ThreatMatcher interface.
type PanoptiumThreatSignature struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired threat signature configuration.
	Spec PanoptiumThreatSignatureSpec `json:"spec,omitempty"`

	// Status reflects the observed state of the threat signature.
	Status PanoptiumThreatSignatureStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PanoptiumThreatSignatureList contains a list of PanoptiumThreatSignature resources.
type PanoptiumThreatSignatureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PanoptiumThreatSignature `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PanoptiumThreatSignature{}, &PanoptiumThreatSignatureList{})
}
