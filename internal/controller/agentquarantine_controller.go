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
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// AgentQuarantineReconciler reconciles a AgentQuarantine object.
// It manages the quarantine lifecycle including finalizer-based cleanup,
// containment status tracking, and auto-release after TTL expiry.
//
// NOTE: Lifecycle and TTL management are active. Actual containment actions
// (NetworkPolicy creation, eBPF-LSM syscall restriction, pod eviction) are
// stubbed — will be implemented in the graduated containment track.
type AgentQuarantineReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=panoptium.io,resources=agentquarantines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=panoptium.io,resources=agentquarantines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=panoptium.io,resources=agentquarantines/finalizers,verbs=update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=create;delete;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups="",resources=pods/eviction,verbs=create

// Reconcile handles reconciliation for AgentQuarantine resources.
func (r *AgentQuarantineReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	quarantine := &panoptiumiov1alpha1.AgentQuarantine{}
	if err := r.Get(ctx, req.NamespacedName, quarantine); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling AgentQuarantine",
		"name", quarantine.Name,
		"targetPod", quarantine.Spec.TargetPod,
		"containmentLevel", quarantine.Spec.ContainmentLevel,
	)

	// Handle deletion with finalizer
	if quarantine.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(quarantine, panoptiumiov1alpha1.QuarantineCleanupFinalizer) {
			// Run cleanup logic
			r.cleanupQuarantine(ctx, quarantine)

			// Remove finalizer
			controllerutil.RemoveFinalizer(quarantine, panoptiumiov1alpha1.QuarantineCleanupFinalizer)
			if err := r.Update(ctx, quarantine); err != nil {
				return ctrl.Result{}, err
			}

			r.Recorder.Event(quarantine, "Normal", "CleanupComplete",
				fmt.Sprintf("Quarantine cleanup completed for pod %s/%s", quarantine.Spec.TargetNamespace, quarantine.Spec.TargetPod))
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(quarantine, panoptiumiov1alpha1.QuarantineCleanupFinalizer) {
		controllerutil.AddFinalizer(quarantine, panoptiumiov1alpha1.QuarantineCleanupFinalizer)
		if err := r.Update(ctx, quarantine); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Update status
	quarantine.Status.ObservedGeneration = quarantine.Generation

	// Set containedAt timestamp on first reconcile
	if quarantine.Status.ContainedAt == nil {
		now := metav1.Now()
		quarantine.Status.ContainedAt = &now
	}

	// Check auto-release
	if quarantine.Spec.Resolution.AutoRelease && quarantine.Spec.Resolution.TTLSeconds > 0 {
		containedAt := quarantine.Status.ContainedAt.Time
		ttl := time.Duration(quarantine.Spec.Resolution.TTLSeconds) * time.Second
		expiry := containedAt.Add(ttl)

		if time.Now().After(expiry) {
			// TTL expired, release the quarantine
			now := metav1.Now()
			quarantine.Status.ReleasedAt = &now
			meta.SetStatusCondition(&quarantine.Status.Conditions, metav1.Condition{
				Type:               ConditionTypeReleased,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: quarantine.Generation,
				Reason:             "TTLExpired",
				Message:            fmt.Sprintf("Auto-released after %d seconds", quarantine.Spec.Resolution.TTLSeconds),
			})
			meta.SetStatusCondition(&quarantine.Status.Conditions, metav1.Condition{
				Type:               ConditionTypeContained,
				Status:             metav1.ConditionFalse,
				ObservedGeneration: quarantine.Generation,
				Reason:             ConditionReasonReleased,
				Message:            "Quarantine has been released",
			})

			r.Recorder.Event(quarantine, "Normal", "AutoReleased",
				fmt.Sprintf("Quarantine auto-released after TTL of %d seconds", quarantine.Spec.Resolution.TTLSeconds))

			if err := r.Status().Update(ctx, quarantine); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		// Requeue before TTL expires
		requeueAfter := time.Until(expiry)
		if requeueAfter < 0 {
			requeueAfter = time.Second
		}

		// Set Contained condition (still active)
		meta.SetStatusCondition(&quarantine.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeContained,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: quarantine.Generation,
			Reason:             "ContainmentActive",
			Message:            fmt.Sprintf("Pod %s/%s is contained at level %s", quarantine.Spec.TargetNamespace, quarantine.Spec.TargetPod, quarantine.Spec.ContainmentLevel),
		})

		meta.SetStatusCondition(&quarantine.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: quarantine.Generation,
			Reason:             "Reconciled",
			Message:            "Quarantine reconciled successfully",
		})

		if err := r.Status().Update(ctx, quarantine); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Set Contained condition
	meta.SetStatusCondition(&quarantine.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeContained,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: quarantine.Generation,
		Reason:             "ContainmentActive",
		Message:            fmt.Sprintf("Pod %s/%s is contained at level %s", quarantine.Spec.TargetNamespace, quarantine.Spec.TargetPod, quarantine.Spec.ContainmentLevel),
	})

	// Set Ready condition
	meta.SetStatusCondition(&quarantine.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: quarantine.Generation,
		Reason:             "Reconciled",
		Message:            "Quarantine reconciled successfully",
	})

	if err := r.Status().Update(ctx, quarantine); err != nil {
		logger.Error(err, "Failed to update AgentQuarantine status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// cleanupQuarantine removes NetworkPolicies and other resources created by this quarantine.
func (r *AgentQuarantineReconciler) cleanupQuarantine(ctx context.Context, quarantine *panoptiumiov1alpha1.AgentQuarantine) {
	logger := log.FromContext(ctx)

	// Clean up NetworkPolicies listed in status
	for _, npName := range quarantine.Status.AppliedNetworkPolicies {
		logger.Info("Would remove NetworkPolicy", "name", npName,
			"namespace", quarantine.Spec.TargetNamespace)
		// Actual NetworkPolicy deletion will be implemented in graduated_containment track
	}

	// Clean up BPF-LSM rules listed in status
	for _, rule := range quarantine.Status.BPFLSMRules {
		logger.Info("Would remove BPF-LSM rule", "description", rule)
		// Actual BPF-LSM rule removal will be implemented in graduated_containment track
	}

}

// SetupWithManager sets up the controller with the Manager.
func (r *AgentQuarantineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&panoptiumiov1alpha1.AgentQuarantine{}).
		Complete(r)
}
