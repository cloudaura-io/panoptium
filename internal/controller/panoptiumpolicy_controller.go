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

// Package controller implements Kubernetes reconcilers for the Panoptium operator CRDs.
package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// PanoptiumPolicyReconciler reconciles a PanoptiumPolicy object.
// It manages status conditions (Ready, Degraded, Error), tracks observedGeneration,
// counts compiled rules, and emits Kubernetes events for state transitions.
type PanoptiumPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation for PanoptiumPolicy resources.
// It validates the spec, sets status conditions, and updates observedGeneration.
func (r *PanoptiumPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the PanoptiumPolicy instance
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		// Resource not found (deleted) — no requeue needed
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling PanoptiumPolicy", "name", policy.Name, "namespace", policy.Namespace)

	// Validate and reconcile
	degraded := false
	var degradedMsg string

	// Check for empty targetSelector (no matchLabels and no matchExpressions)
	if len(policy.Spec.TargetSelector.MatchLabels) == 0 &&
		len(policy.Spec.TargetSelector.MatchExpressions) == 0 {
		degraded = true
		degradedMsg = "targetSelector is empty; policy matches all pods which may be unintended"
		logger.Info("Policy has empty targetSelector", "name", policy.Name)
	}

	// Update status
	policy.Status.ObservedGeneration = policy.Generation
	policy.Status.RuleCount = int32(len(policy.Spec.Rules))

	// Set Ready condition
	if degraded {
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: policy.Generation,
			Reason:             "Reconciled",
			Message:            "Policy reconciled with warnings",
		})
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "Degraded",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: policy.Generation,
			Reason:             "EmptyTargetSelector",
			Message:            degradedMsg,
		})
		r.Recorder.Event(policy, "Warning", "EmptyTargetSelector", degradedMsg)
	} else {
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: policy.Generation,
			Reason:             "Reconciled",
			Message:            fmt.Sprintf("Policy reconciled with %d rules", len(policy.Spec.Rules)),
		})
		// Remove Degraded condition if it was previously set
		meta.RemoveStatusCondition(&policy.Status.Conditions, "Degraded")
	}

	// Set Enforcing condition based on enforcement mode
	if policy.Spec.EnforcementMode == panoptiumiov1alpha1.EnforcementModeEnforcing {
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "Enforcing",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: policy.Generation,
			Reason:             "EnforcementEnabled",
			Message:            "Policy is actively enforcing rules",
		})
	} else {
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "Enforcing",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: policy.Generation,
			Reason:             "EnforcementDisabled",
			Message:            fmt.Sprintf("Policy enforcement mode is %s", policy.Spec.EnforcementMode),
		})
	}

	// Update status subresource
	if err := r.Status().Update(ctx, policy); err != nil {
		logger.Error(err, "Failed to update PanoptiumPolicy status")
		return ctrl.Result{}, err
	}

	logger.Info("PanoptiumPolicy reconciled successfully",
		"name", policy.Name,
		"ruleCount", policy.Status.RuleCount,
		"observedGeneration", policy.Status.ObservedGeneration,
	)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PanoptiumPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&panoptiumiov1alpha1.PanoptiumPolicy{}).
		Complete(r)
}
