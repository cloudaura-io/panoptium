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
	"github.com/panoptium/panoptium/pkg/policy"
)

// AgentPolicyReconciler reconciles a AgentPolicy object.
// It manages status conditions (Ready, Degraded, Error), tracks observedGeneration,
// counts compiled rules, and emits Kubernetes events for state transitions.
// When PolicyCache is set, the reconciler compiles policies into the shared cache
// on every Add/Update/Delete, keeping the ExtProc enforcement pipeline in sync.
type AgentPolicyReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	Recorder    record.EventRecorder
	PolicyCache *policy.PolicyCache
}

// +kubebuilder:rbac:groups=panoptium.io,resources=agentpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=panoptium.io,resources=agentpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=panoptium.io,resources=agentpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation for AgentPolicy resources.
// It validates the spec, sets status conditions, and updates observedGeneration.
func (r *AgentPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the AgentPolicy instance
	pol := &panoptiumiov1alpha1.AgentPolicy{}
	if err := r.Get(ctx, req.NamespacedName, pol); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Resource was deleted — remove from PolicyCache
			if r.PolicyCache != nil {
				deletedPol := &panoptiumiov1alpha1.AgentPolicy{}
				deletedPol.Name = req.Name
				deletedPol.Namespace = req.Namespace
				if cacheErr := r.PolicyCache.OnDelete(deletedPol); cacheErr != nil {
					logger.Error(cacheErr, "failed to remove policy from cache on delete")
				} else {
					logger.Info("removed policy from cache", "name", req.Name, "namespace", req.Namespace)
				}
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling AgentPolicy", "name", pol.Name, "namespace", pol.Namespace)

	// Validate and reconcile
	degraded := false
	var degradedMsg string

	// Check for empty targetSelector (no matchLabels and no matchExpressions)
	if len(pol.Spec.TargetSelector.MatchLabels) == 0 &&
		len(pol.Spec.TargetSelector.MatchExpressions) == 0 {
		degraded = true
		degradedMsg = "targetSelector is empty; policy matches all pods which may be unintended"
		logger.Info("Policy has empty targetSelector", "name", pol.Name)
	}

	// Update the PolicyCache with the latest policy spec
	if r.PolicyCache != nil {
		// OnAdd handles both new policies and updates (it replaces existing entries)
		if cacheErr := r.PolicyCache.OnAdd(pol); cacheErr != nil {
			logger.Error(cacheErr, "failed to compile policy into cache",
				"name", pol.Name, "namespace", pol.Namespace)
			// Set Error condition but continue — the status update still matters
			meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
				Type:               "Error",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: pol.Generation,
				Reason:             ConditionReasonCompilationFailed,
				Message:            fmt.Sprintf("Failed to compile policy: %v", cacheErr),
			})
		} else {
			logger.Info("compiled policy into cache",
				"name", pol.Name, "namespace", pol.Namespace)
			meta.RemoveStatusCondition(&pol.Status.Conditions, "Error")
		}
	}

	// Update status
	pol.Status.ObservedGeneration = pol.Generation
	pol.Status.RuleCount = int32(len(pol.Spec.Rules))

	// Set Ready condition
	if degraded {
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: pol.Generation,
			Reason:             "Reconciled",
			Message:            "Policy reconciled with warnings",
		})
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeDegraded,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: pol.Generation,
			Reason:             "EmptyTargetSelector",
			Message:            degradedMsg,
		})
		r.Recorder.Event(pol, "Warning", "EmptyTargetSelector", degradedMsg)
	} else {
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: pol.Generation,
			Reason:             "Reconciled",
			Message:            fmt.Sprintf("Policy reconciled with %d rules", len(pol.Spec.Rules)),
		})
		// Remove Degraded condition if it was previously set
		meta.RemoveStatusCondition(&pol.Status.Conditions, ConditionTypeDegraded)
	}

	// Set Enforcing condition based on enforcement mode
	if pol.Spec.EnforcementMode == panoptiumiov1alpha1.EnforcementModeEnforcing {
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeEnforcing,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: pol.Generation,
			Reason:             "EnforcementEnabled",
			Message:            "Policy is actively enforcing rules",
		})
	} else {
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeEnforcing,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: pol.Generation,
			Reason:             "EnforcementDisabled",
			Message:            fmt.Sprintf("Policy enforcement mode is %s", pol.Spec.EnforcementMode),
		})
	}

	// Update status subresource
	if err := r.Status().Update(ctx, pol); err != nil {
		logger.Error(err, "Failed to update AgentPolicy status")
		return ctrl.Result{}, err
	}

	logger.Info("AgentPolicy reconciled successfully",
		"name", pol.Name,
		"ruleCount", pol.Status.RuleCount,
		"observedGeneration", pol.Status.ObservedGeneration,
	)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AgentPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&panoptiumiov1alpha1.AgentPolicy{}).
		Complete(r)
}
