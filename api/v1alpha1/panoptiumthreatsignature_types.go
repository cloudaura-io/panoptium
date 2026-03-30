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

// DetectionPattern defines a single detection pattern within a threat signature.
type DetectionPattern struct {
	// EventCategory is the event category to match (e.g., "syscall", "network", "llm").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	EventCategory string `json:"eventCategory"`

	// Match is a CEL expression for pattern matching against events in this category.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Match string `json:"match"`

	// WindowSeconds is the time window in seconds for temporal pattern matching.
	// Events outside this window are not correlated.
	// +optional
	// +kubebuilder:validation:Minimum=0
	WindowSeconds int32 `json:"windowSeconds,omitempty"`
}

// PanoptiumThreatSignatureSpec defines the desired state of a PanoptiumThreatSignature.
type PanoptiumThreatSignatureSpec struct {
	// SignatureID is a unique identifier for this threat signature.
	// Must match the pattern PAN-SIG-XXXX where X is a digit.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^PAN-SIG-[0-9]{4}$`
	SignatureID string `json:"signatureID"`

	// Description is a human-readable description of the threat this signature detects.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Description string `json:"description"`

	// Severity indicates the severity level of threats matching this signature.
	// +kubebuilder:validation:Required
	Severity Severity `json:"severity"`

	// Patterns is the list of detection patterns that define how to identify this threat.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Patterns []DetectionPattern `json:"patterns"`

	// DetectionPoints lists the detection layers that can identify this threat.
	// Valid values: L1-extproc, L2-network, L3-ebpf, L4-behavioral.
	// +optional
	DetectionPoints []string `json:"detectionPoints,omitempty"`

	// Enabled indicates whether this signature is active for detection.
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// MITRETactic is the MITRE ATT&CK tactic reference for this threat.
	// +optional
	MITRETactic string `json:"mitreTactic,omitempty"`

	// MITRETechnique is the MITRE ATT&CK technique reference for this threat.
	// +optional
	MITRETechnique string `json:"mitreTechnique,omitempty"`
}

// PanoptiumThreatSignatureStatus defines the observed state of a PanoptiumThreatSignature.
type PanoptiumThreatSignatureStatus struct {
	// Conditions represent the latest available observations of the signature's state.
	// Supported condition types: Ready, Active, Degraded.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// DetectionCount is the total number of times this signature has matched.
	// +optional
	DetectionCount int64 `json:"detectionCount,omitempty"`

	// LastDetection is the timestamp of the last time this signature matched.
	// +optional
	LastDetection *metav1.Time `json:"lastDetection,omitempty"`

	// FalsePositiveRate is the estimated false positive percentage for this signature.
	// +optional
	FalsePositiveRate string `json:"falsePositiveRate,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="SignatureID",type=string,JSONPath=`.spec.signatureID`,description="Signature identifier"
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`,description="Threat severity"
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`,description="Whether signature is active"
// +kubebuilder:printcolumn:name="Detections",type=integer,JSONPath=`.status.detectionCount`,description="Total detections"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready status"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PanoptiumThreatSignature is the Schema for the panoptiumthreatsignatures API.
// It defines threat detection patterns that identify specific attack techniques
// or suspicious behaviors in monitored AI agent traffic and kernel activity.
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
