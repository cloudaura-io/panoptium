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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// TestSchemeRegistration verifies that all five CRD types are registered
// in the scheme and can be constructed as runtime.Object.
func TestSchemeRegistration(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}

	tests := []struct {
		name string
		obj  runtime.Object
		gvk  string
	}{
		{"PanoptiumPolicy", &PanoptiumPolicy{}, "panoptium.io/v1alpha1, Kind=PanoptiumPolicy"},
		{"PanoptiumPolicyList", &PanoptiumPolicyList{}, "panoptium.io/v1alpha1, Kind=PanoptiumPolicyList"},
		{"ClusterPanoptiumPolicy", &ClusterPanoptiumPolicy{}, "panoptium.io/v1alpha1, Kind=ClusterPanoptiumPolicy"},
		{"ClusterPanoptiumPolicyList", &ClusterPanoptiumPolicyList{}, "panoptium.io/v1alpha1, Kind=ClusterPanoptiumPolicyList"},
		{"PanoptiumAgentProfile", &PanoptiumAgentProfile{}, "panoptium.io/v1alpha1, Kind=PanoptiumAgentProfile"},
		{"PanoptiumAgentProfileList", &PanoptiumAgentProfileList{}, "panoptium.io/v1alpha1, Kind=PanoptiumAgentProfileList"},
		{"PanoptiumThreatSignature", &PanoptiumThreatSignature{}, "panoptium.io/v1alpha1, Kind=PanoptiumThreatSignature"},
		{"PanoptiumThreatSignatureList", &PanoptiumThreatSignatureList{}, "panoptium.io/v1alpha1, Kind=PanoptiumThreatSignatureList"},
		{"PanoptiumQuarantine", &PanoptiumQuarantine{}, "panoptium.io/v1alpha1, Kind=PanoptiumQuarantine"},
		{"PanoptiumQuarantineList", &PanoptiumQuarantineList{}, "panoptium.io/v1alpha1, Kind=PanoptiumQuarantineList"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gvks, _, err := s.ObjectKinds(tt.obj)
			if err != nil {
				t.Fatalf("ObjectKinds() error = %v", err)
			}
			if len(gvks) == 0 {
				t.Fatal("ObjectKinds() returned no GVKs")
			}
			if got := gvks[0].String(); got != tt.gvk {
				t.Errorf("GVK = %q, want %q", got, tt.gvk)
			}
		})
	}
}

// TestPanoptiumPolicyDeepCopy verifies that DeepCopy works correctly for
// PanoptiumPolicy, preserving all fields without aliasing.
func TestPanoptiumPolicyDeepCopy(t *testing.T) {
	original := &PanoptiumPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			EnforcementMode: EnforcementModeEnforcing,
			Priority:        100,
			Rules: []PolicyRule{
				{
					Name: "block-exec",
					Trigger: Trigger{
						EventCategory:    "syscall",
						EventSubcategory: "execve",
					},
					Predicates: []Predicate{
						{CEL: "event.args[0].startsWith('/usr/bin/')"},
					},
					Action: Action{
						Type:       ActionTypeDeny,
						Parameters: map[string]string{"log": "true"},
					},
					Severity: SeverityHigh,
				},
			},
		},
		Status: PanoptiumPolicyStatus{
			ObservedGeneration: 1,
			RuleCount:          1,
			MatchingPods:       5,
		},
	}

	copied := original.DeepCopy()

	// Verify fields are equal
	if copied.Name != original.Name {
		t.Errorf("Name = %q, want %q", copied.Name, original.Name)
	}
	if copied.Spec.Priority != original.Spec.Priority {
		t.Errorf("Priority = %d, want %d", copied.Spec.Priority, original.Spec.Priority)
	}
	if len(copied.Spec.Rules) != len(original.Spec.Rules) {
		t.Fatalf("Rules length = %d, want %d", len(copied.Spec.Rules), len(original.Spec.Rules))
	}
	if copied.Spec.Rules[0].Name != "block-exec" {
		t.Errorf("Rule name = %q, want %q", copied.Spec.Rules[0].Name, "block-exec")
	}

	// Verify no aliasing: mutating the copy should not affect the original
	copied.Spec.Rules[0].Name = "modified"
	if original.Spec.Rules[0].Name == "modified" {
		t.Error("DeepCopy produced aliased Rules slice")
	}

	copied.Spec.TargetSelector.MatchLabels["app"] = "changed"
	if original.Spec.TargetSelector.MatchLabels["app"] == "changed" {
		t.Error("DeepCopy produced aliased MatchLabels map")
	}
}

// TestQuarantineFinalizerConstant verifies the finalizer constant is correctly defined.
func TestQuarantineFinalizerConstant(t *testing.T) {
	if QuarantineCleanupFinalizer != "panoptium.io/quarantine-cleanup" {
		t.Errorf("QuarantineCleanupFinalizer = %q, want %q",
			QuarantineCleanupFinalizer, "panoptium.io/quarantine-cleanup")
	}
}

// TestEnforcementModeValues verifies all enforcement mode enum values.
func TestEnforcementModeValues(t *testing.T) {
	tests := []struct {
		mode EnforcementMode
		want string
	}{
		{EnforcementModeEnforcing, "enforcing"},
		{EnforcementModeAudit, "audit"},
		{EnforcementModeDisabled, "disabled"},
	}
	for _, tt := range tests {
		if string(tt.mode) != tt.want {
			t.Errorf("EnforcementMode = %q, want %q", tt.mode, tt.want)
		}
	}
}

// TestSeverityValues verifies all severity enum values.
func TestSeverityValues(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}
	for _, tt := range tests {
		if string(tt.sev) != tt.want {
			t.Errorf("Severity = %q, want %q", tt.sev, tt.want)
		}
	}
}

// TestActionTypeValues verifies all action type enum values.
func TestActionTypeValues(t *testing.T) {
	tests := []struct {
		action ActionType
		want   string
	}{
		{ActionTypeAllow, "allow"},
		{ActionTypeDeny, "deny"},
		{ActionTypeAlert, "alert"},
		{ActionTypeQuarantine, "quarantine"},
		{ActionTypeRateLimit, "rateLimit"},
	}
	for _, tt := range tests {
		if string(tt.action) != tt.want {
			t.Errorf("ActionType = %q, want %q", tt.action, tt.want)
		}
	}
}

// TestContainmentLevelValues verifies all containment level enum values.
func TestContainmentLevelValues(t *testing.T) {
	tests := []struct {
		level ContainmentLevel
		want  string
	}{
		{ContainmentLevelNetworkIsolate, "network-isolate"},
		{ContainmentLevelSyscallRestrict, "syscall-restrict"},
		{ContainmentLevelFreeze, "freeze"},
		{ContainmentLevelEvict, "evict"},
	}
	for _, tt := range tests {
		if string(tt.level) != tt.want {
			t.Errorf("ContainmentLevel = %q, want %q", tt.level, tt.want)
		}
	}
}

// TestGroupVersionInfo verifies the GroupVersion is correctly configured.
func TestGroupVersionInfo(t *testing.T) {
	if GroupVersion.Group != "panoptium.io" {
		t.Errorf("Group = %q, want %q", GroupVersion.Group, "panoptium.io")
	}
	if GroupVersion.Version != "v1alpha1" {
		t.Errorf("Version = %q, want %q", GroupVersion.Version, "v1alpha1")
	}
}
