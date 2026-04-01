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

package webhook

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// TestPodLabelValidator_BlockLabelRemoval verifies that removing
// panoptium.io/monitored=true is blocked when a matching PanoptiumPolicy exists.
func TestPodLabelValidator_BlockLabelRemoval(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = panoptiumiov1alpha1.AddToScheme(scheme)

	// Create a PanoptiumPolicy that targets pods with app=agent
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name:     "block-exec",
					Trigger:  panoptiumiov1alpha1.Trigger{EventCategory: "syscall"},
					Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		Build()

	v := &PodLabelValidator{
		Client:             client,
		ExcludedNamespaces: []string{"kube-system"},
	}

	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "agent-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app":          "agent",
				MonitoredLabel: "true",
			},
		},
	}

	// New pod has the monitored label removed
	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "agent-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "agent",
			},
		},
	}

	_, err := v.ValidateUpdate(context.Background(), oldPod, newPod)
	if err == nil {
		t.Error("ValidateUpdate should block removal of panoptium.io/monitored label when matching policy exists")
	}
}

// TestPodLabelValidator_AllowLabelRemovalNoPolicy verifies that removing
// panoptium.io/monitored=true is allowed when no matching PanoptiumPolicy exists.
func TestPodLabelValidator_AllowLabelRemovalNoPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = panoptiumiov1alpha1.AddToScheme(scheme)

	// No policies in the namespace
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	v := &PodLabelValidator{
		Client:             client,
		ExcludedNamespaces: []string{"kube-system"},
	}

	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "orphan-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app":          "legacy",
				MonitoredLabel: "true",
			},
		},
	}

	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "orphan-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "legacy",
			},
		},
	}

	_, err := v.ValidateUpdate(context.Background(), oldPod, newPod)
	if err != nil {
		t.Errorf("ValidateUpdate should allow label removal when no matching policy exists, got: %v", err)
	}
}

// TestPodLabelValidator_AllowOtherLabelChanges verifies that adding, modifying,
// or removing labels other than panoptium.io/monitored is not affected.
func TestPodLabelValidator_AllowOtherLabelChanges(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = panoptiumiov1alpha1.AddToScheme(scheme)

	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name:     "block-exec",
					Trigger:  panoptiumiov1alpha1.Trigger{EventCategory: "syscall"},
					Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		Build()

	v := &PodLabelValidator{
		Client:             client,
		ExcludedNamespaces: []string{"kube-system"},
	}

	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "agent-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app":          "agent",
				MonitoredLabel: "true",
				"version":      "v1",
			},
		},
	}

	// Change version label, remove version label, but keep monitored label
	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "agent-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app":          "agent",
				MonitoredLabel: "true",
				"env":          "production",
			},
		},
	}

	_, err := v.ValidateUpdate(context.Background(), oldPod, newPod)
	if err != nil {
		t.Errorf("ValidateUpdate should allow changes to other labels, got: %v", err)
	}
}

// TestPodLabelValidator_AllowLabelRemovalExcludedNamespace verifies that
// removing the monitored label is allowed in excluded namespaces.
func TestPodLabelValidator_AllowLabelRemovalExcludedNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = panoptiumiov1alpha1.AddToScheme(scheme)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	v := &PodLabelValidator{
		Client:             client,
		ExcludedNamespaces: []string{"kube-system"},
	}

	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system-pod",
			Namespace: "kube-system",
			Labels: map[string]string{
				MonitoredLabel: "true",
			},
		},
	}

	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system-pod",
			Namespace: "kube-system",
			Labels:    map[string]string{},
		},
	}

	_, err := v.ValidateUpdate(context.Background(), oldPod, newPod)
	if err != nil {
		t.Errorf("ValidateUpdate should allow label removal in excluded namespace, got: %v", err)
	}
}

// TestPodLabelValidator_CreateAlwaysAllowed verifies that pod creation is always allowed.
func TestPodLabelValidator_CreateAlwaysAllowed(t *testing.T) {
	v := &PodLabelValidator{}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-pod",
			Namespace: "default",
		},
	}

	_, err := v.ValidateCreate(context.Background(), pod)
	if err != nil {
		t.Errorf("ValidateCreate should always allow pod creation, got: %v", err)
	}
}

// TestPodLabelValidator_DeleteAlwaysAllowed verifies that pod deletion is always allowed.
func TestPodLabelValidator_DeleteAlwaysAllowed(t *testing.T) {
	v := &PodLabelValidator{}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deleted-pod",
			Namespace: "default",
		},
	}

	_, err := v.ValidateDelete(context.Background(), pod)
	if err != nil {
		t.Errorf("ValidateDelete should always allow pod deletion, got: %v", err)
	}
}
