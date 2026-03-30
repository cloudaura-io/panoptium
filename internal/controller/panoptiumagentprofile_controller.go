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
)

// PanoptiumAgentProfileReconciler reconciles a PanoptiumAgentProfile object.
// It manages status conditions (Ready, Learning, BaselineEstablished),
// tracks baseline health, and counts matching agents.
type PanoptiumAgentProfileReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumagentprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumagentprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumagentprofiles/finalizers,verbs=update

// Reconcile handles reconciliation for PanoptiumAgentProfile resources.
func (r *PanoptiumAgentProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	profile := &panoptiumiov1alpha1.PanoptiumAgentProfile{}
	if err := r.Get(ctx, req.NamespacedName, profile); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling PanoptiumAgentProfile", "name", profile.Name, "namespace", profile.Namespace)

	// Update status
	profile.Status.ObservedGeneration = profile.Generation

	// Set Learning condition based on learningMode
	if profile.Spec.LearningMode {
		profile.Status.BaselineHealth = "learning"
		meta.SetStatusCondition(&profile.Status.Conditions, metav1.Condition{
			Type:               "Learning",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: profile.Generation,
			Reason:             "LearningModeEnabled",
			Message:            "Profile is in learning mode; baselines are being auto-updated",
		})
		meta.SetStatusCondition(&profile.Status.Conditions, metav1.Condition{
			Type:               "BaselineEstablished",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: profile.Generation,
			Reason:             "LearningInProgress",
			Message:            "Baselines are not yet established while in learning mode",
		})
	} else {
		// Check if baselines have meaningful data
		hasBaselines := len(profile.Spec.Baselines.ExpectedToolCalls) > 0 ||
			profile.Spec.Baselines.MaxRequestsPerMinute > 0 ||
			len(profile.Spec.Baselines.TypicalNetworkDestinations) > 0

		if hasBaselines {
			profile.Status.BaselineHealth = "healthy"
			meta.SetStatusCondition(&profile.Status.Conditions, metav1.Condition{
				Type:               "BaselineEstablished",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: profile.Generation,
				Reason:             "BaselinesPopulated",
				Message:            "Baselines are established and ready for anomaly detection",
			})
		} else {
			profile.Status.BaselineHealth = "degraded"
			meta.SetStatusCondition(&profile.Status.Conditions, metav1.Condition{
				Type:               "BaselineEstablished",
				Status:             metav1.ConditionFalse,
				ObservedGeneration: profile.Generation,
				Reason:             "BaselinesEmpty",
				Message:            "No baselines configured; consider enabling learning mode",
			})
		}
		meta.SetStatusCondition(&profile.Status.Conditions, metav1.Condition{
			Type:               "Learning",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: profile.Generation,
			Reason:             "LearningModeDisabled",
			Message:            "Learning mode is disabled",
		})
	}

	// Update lastBaselineUpdate timestamp on spec changes
	now := metav1.Now()
	profile.Status.LastBaselineUpdate = &now

	// Set Ready condition
	meta.SetStatusCondition(&profile.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		ObservedGeneration: profile.Generation,
		Reason:             "Reconciled",
		Message:            fmt.Sprintf("AgentProfile reconciled for type %q", profile.Spec.AgentType),
	})

	if err := r.Status().Update(ctx, profile); err != nil {
		logger.Error(err, "Failed to update PanoptiumAgentProfile status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PanoptiumAgentProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&panoptiumiov1alpha1.PanoptiumAgentProfile{}).
		Complete(r)
}
