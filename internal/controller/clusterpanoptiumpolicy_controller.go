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

// ClusterPanoptiumPolicyReconciler reconciles a ClusterPanoptiumPolicy object.
// It manages status conditions (Ready, Degraded, Error), tracks observedGeneration,
// counts compiled rules, and emits Kubernetes events for state transitions.
type ClusterPanoptiumPolicyReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	Recorder    record.EventRecorder
	PolicyCache *policy.PolicyCache
}

// +kubebuilder:rbac:groups=panoptium.io,resources=clusterpanoptiumpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=panoptium.io,resources=clusterpanoptiumpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=panoptium.io,resources=clusterpanoptiumpolicies/finalizers,verbs=update

// Reconcile handles reconciliation for ClusterPanoptiumPolicy resources.
// It validates the spec, sets status conditions, and updates observedGeneration.
func (r *ClusterPanoptiumPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the ClusterPanoptiumPolicy instance
	pol := &panoptiumiov1alpha1.ClusterPanoptiumPolicy{}
	if err := r.Get(ctx, req.NamespacedName, pol); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Resource was deleted — remove from PolicyCache
			if r.PolicyCache != nil {
				deletedPol := &panoptiumiov1alpha1.ClusterPanoptiumPolicy{}
				deletedPol.Name = req.Name
				if cacheErr := r.PolicyCache.OnDeleteCluster(deletedPol); cacheErr != nil {
					logger.Error(cacheErr, "failed to remove cluster policy from cache on delete")
				} else {
					logger.Info("removed cluster policy from cache", "name", req.Name)
				}
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling ClusterPanoptiumPolicy", "name", pol.Name)

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

	// Update the PolicyCache with the latest cluster policy spec
	if r.PolicyCache != nil {
		if cacheErr := r.PolicyCache.OnAddCluster(pol); cacheErr != nil {
			logger.Error(cacheErr, "failed to compile cluster policy into cache",
				"name", pol.Name)
			meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
				Type:               "Error",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: pol.Generation,
				Reason:             "CompilationFailed",
				Message:            fmt.Sprintf("Failed to compile cluster policy: %v", cacheErr),
			})
		} else {
			logger.Info("compiled cluster policy into cache", "name", pol.Name)
			meta.RemoveStatusCondition(&pol.Status.Conditions, "Error")
		}
	}

	// Update status
	pol.Status.ObservedGeneration = pol.Generation
	pol.Status.RuleCount = int32(len(pol.Spec.Rules))

	// Set Ready condition
	if degraded {
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: pol.Generation,
			Reason:             "Reconciled",
			Message:            "Policy reconciled with warnings",
		})
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               "Degraded",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: pol.Generation,
			Reason:             "EmptyTargetSelector",
			Message:            degradedMsg,
		})
		r.Recorder.Event(pol, "Warning", "EmptyTargetSelector", degradedMsg)
	} else {
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: pol.Generation,
			Reason:             "Reconciled",
			Message:            fmt.Sprintf("Policy reconciled with %d rules", len(pol.Spec.Rules)),
		})
		// Remove Degraded condition if it was previously set
		meta.RemoveStatusCondition(&pol.Status.Conditions, "Degraded")
	}

	// Set Enforcing condition based on enforcement mode
	if pol.Spec.EnforcementMode == panoptiumiov1alpha1.EnforcementModeEnforcing {
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               "Enforcing",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: pol.Generation,
			Reason:             "EnforcementEnabled",
			Message:            "Policy is actively enforcing rules",
		})
	} else {
		meta.SetStatusCondition(&pol.Status.Conditions, metav1.Condition{
			Type:               "Enforcing",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: pol.Generation,
			Reason:             "EnforcementDisabled",
			Message:            fmt.Sprintf("Policy enforcement mode is %s", pol.Spec.EnforcementMode),
		})
	}

	// Update status subresource
	if err := r.Status().Update(ctx, pol); err != nil {
		logger.Error(err, "Failed to update ClusterPanoptiumPolicy status")
		return ctrl.Result{}, err
	}

	logger.Info("ClusterPanoptiumPolicy reconciled successfully",
		"name", pol.Name,
		"ruleCount", pol.Status.RuleCount,
		"observedGeneration", pol.Status.ObservedGeneration,
	)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterPanoptiumPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&panoptiumiov1alpha1.ClusterPanoptiumPolicy{}).
		Complete(r)
}
