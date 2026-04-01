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

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// TestEnrollmentReconciler_LabelMatchingPod verifies that pods matching a
// PanoptiumPolicy but without the monitored label get labeled.
func TestEnrollmentReconciler_LabelMatchingPod(t *testing.T) {
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

	// Pod matching the policy but without monitored label
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unlabeled-agent",
			Namespace: "default",
			Labels:    map[string]string{"app": "agent"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "busybox:latest"},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, pod).
		Build()

	r := &EnrollmentReconciler{
		Client:             client,
		Scheme:             scheme,
		Recorder:           record.NewFakeRecorder(10),
		ExcludedNamespaces: []string{"kube-system"},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.Requeue {
		t.Error("Reconcile() should not requeue on success")
	}

	// Verify the pod got the monitored label
	updatedPod := &corev1.Pod{}
	if err := client.Get(context.Background(), types.NamespacedName{
		Name: "unlabeled-agent", Namespace: "default",
	}, updatedPod); err != nil {
		t.Fatalf("failed to get updated pod: %v", err)
	}

	if updatedPod.Labels["panoptium.io/monitored"] != "true" {
		t.Errorf("pod should have panoptium.io/monitored=true, got labels: %v", updatedPod.Labels)
	}
}

// TestEnrollmentReconciler_SkipNonMatchingPod verifies that pods not matching
// any policy are not labeled.
func TestEnrollmentReconciler_SkipNonMatchingPod(t *testing.T) {
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

	// Pod that does NOT match the policy
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-matching-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "web-server"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "nginx:latest"},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, pod).
		Build()

	r := &EnrollmentReconciler{
		Client:             client,
		Scheme:             scheme,
		Recorder:           record.NewFakeRecorder(10),
		ExcludedNamespaces: []string{"kube-system"},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	_, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	// Verify the pod was NOT given the monitored label
	updatedPod := &corev1.Pod{}
	if err := client.Get(context.Background(), types.NamespacedName{
		Name: "non-matching-pod", Namespace: "default",
	}, updatedPod); err != nil {
		t.Fatalf("failed to get updated pod: %v", err)
	}

	if _, exists := updatedPod.Labels["panoptium.io/monitored"]; exists {
		t.Errorf("non-matching pod should not have monitored label, got labels: %v", updatedPod.Labels)
	}
}

// TestEnrollmentReconciler_SkipExcludedNamespace verifies that pods in excluded
// namespaces are skipped even if they match a policy.
func TestEnrollmentReconciler_SkipExcludedNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = panoptiumiov1alpha1.AddToScheme(scheme)

	// Policy in kube-system (excluded)
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system-policy",
			Namespace: "kube-system",
		},
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"component": "kube-proxy"},
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

	r := &EnrollmentReconciler{
		Client:             client,
		Scheme:             scheme,
		Recorder:           record.NewFakeRecorder(10),
		ExcludedNamespaces: []string{"kube-system"},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "system-policy",
			Namespace: "kube-system",
		},
	}

	result, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.Requeue {
		t.Error("Reconcile() should not requeue for excluded namespaces")
	}
}

// TestEnrollmentReconciler_PolicyDeleted verifies reconciliation handles
// deleted policies gracefully.
func TestEnrollmentReconciler_PolicyDeleted(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = panoptiumiov1alpha1.AddToScheme(scheme)

	// No policy exists
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := &EnrollmentReconciler{
		Client:             client,
		Scheme:             scheme,
		Recorder:           record.NewFakeRecorder(10),
		ExcludedNamespaces: []string{"kube-system"},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "deleted-policy",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile() should handle deleted policy gracefully, got error: %v", err)
	}
	if result.Requeue {
		t.Error("Reconcile() should not requeue for deleted policy")
	}
}
