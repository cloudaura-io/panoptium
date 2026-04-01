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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

const (
	// monitoredLabel is the label added to pods enrolled in Panoptium monitoring.
	monitoredLabel = "panoptium.io/monitored"
)

// EnrollmentReconciler watches PanoptiumPolicy changes and ensures all pods
// matching a policy's TargetSelector are labeled with panoptium.io/monitored=true.
// This reconciler closes the enrollment drift gap: if a pod is created without
// the mutating webhook (e.g., due to webhook downtime) or has its label removed,
// the reconciler will re-label it.
type EnrollmentReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// ExcludedNamespaces is the list of namespaces to skip during enrollment.
	// Defaults to ["kube-system"].
	ExcludedNamespaces []string
}

// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;patch

// Reconcile handles a PanoptiumPolicy reconciliation event by scanning all pods
// in the policy's namespace that match the TargetSelector and adding the monitored
// label to any that are missing it.
func (r *EnrollmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Skip excluded namespaces
	for _, ns := range r.excludedNamespaces() {
		if req.Namespace == ns {
			logger.V(1).Info("Skipping enrollment reconciliation in excluded namespace",
				"namespace", req.Namespace)
			return ctrl.Result{}, nil
		}
	}

	// Fetch the PanoptiumPolicy
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Policy was deleted — nothing to reconcile
			logger.V(1).Info("PanoptiumPolicy not found, skipping enrollment",
				"name", req.Name, "namespace", req.Namespace)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling enrollment for PanoptiumPolicy",
		"policy", policy.Name, "namespace", policy.Namespace)

	// Build the label selector from the policy's TargetSelector
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.TargetSelector)
	if err != nil {
		logger.Error(err, "Failed to parse TargetSelector",
			"policy", policy.Name)
		return ctrl.Result{}, fmt.Errorf("invalid TargetSelector: %w", err)
	}

	// List pods in the namespace matching the TargetSelector
	podList := &corev1.PodList{}
	listOpts := &client.ListOptions{
		Namespace:     policy.Namespace,
		LabelSelector: selector,
	}
	if err := r.List(ctx, podList, listOpts); err != nil {
		logger.Error(err, "Failed to list pods for enrollment")
		return ctrl.Result{}, err
	}

	// Patch pods that are missing the monitored label
	enrolled := 0
	for i := range podList.Items {
		pod := &podList.Items[i]

		// Skip pods that already have the monitored label
		if pod.Labels != nil && pod.Labels[monitoredLabel] == "true" {
			continue
		}

		// Patch the pod to add the monitored label
		patch := client.MergeFrom(pod.DeepCopy())
		if pod.Labels == nil {
			pod.Labels = make(map[string]string)
		}
		pod.Labels[monitoredLabel] = "true"

		if err := r.Patch(ctx, pod, patch); err != nil {
			logger.Error(err, "Failed to patch pod with monitored label",
				"pod", pod.Name, "namespace", pod.Namespace)
			continue
		}

		enrolled++
		logger.Info("Enrolled pod via reconciliation",
			"pod", pod.Name, "namespace", pod.Namespace,
			"policy", policy.Name)
	}

	if enrolled > 0 {
		r.Recorder.Eventf(policy, corev1.EventTypeNormal, "EnrollmentReconciled",
			"Enrolled %d pods matching policy %s", enrolled, policy.Name)
	}

	// Also check pods matching via label expressions against the full label set
	logger.Info("Enrollment reconciliation complete",
		"policy", policy.Name,
		"matchingPods", len(podList.Items),
		"newlyEnrolled", enrolled)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EnrollmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&panoptiumiov1alpha1.PanoptiumPolicy{}).
		Complete(r)
}

// NeedLeaderElection implements the LeaderElectionRunnable interface.
// The enrollment reconciler must only run on the leader to avoid duplicate patches.
func (r *EnrollmentReconciler) NeedLeaderElection() bool {
	return true
}

// excludedNamespaces returns the list of excluded namespaces, defaulting to kube-system.
func (r *EnrollmentReconciler) excludedNamespaces() []string {
	if len(r.ExcludedNamespaces) > 0 {
		return r.ExcludedNamespaces
	}
	return []string{"kube-system"}
}

// matchesSelector checks if a pod's labels match a label selector.
// This is a convenience function for cases where the selector cannot be
// used directly with client.ListOptions.
func matchesSelector(podLabels map[string]string, selector *metav1.LabelSelector) (bool, error) {
	s, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, err
	}
	return s.Matches(labels.Set(podLabels)), nil
}
