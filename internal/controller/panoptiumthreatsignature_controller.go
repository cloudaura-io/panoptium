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
	"regexp"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// signatureIDPattern validates the PAN-SIG-XXXX format.
var signatureIDPattern = regexp.MustCompile(`^PAN-SIG-[0-9]{4}$`)

// PanoptiumThreatSignatureReconciler reconciles a PanoptiumThreatSignature object.
// It validates signature patterns, manages Active/Ready conditions, and tracks detection counts.
type PanoptiumThreatSignatureReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumthreatsignatures,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumthreatsignatures/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=panoptium.io,resources=panoptiumthreatsignatures/finalizers,verbs=update

// Reconcile handles reconciliation for PanoptiumThreatSignature resources.
func (r *PanoptiumThreatSignatureReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	sig := &panoptiumiov1alpha1.PanoptiumThreatSignature{}
	if err := r.Get(ctx, req.NamespacedName, sig); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling PanoptiumThreatSignature", "name", sig.Name, "signatureID", sig.Spec.SignatureID)

	sig.Status.ObservedGeneration = sig.Generation

	// Validate signatureID format
	if !signatureIDPattern.MatchString(sig.Spec.SignatureID) {
		meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: sig.Generation,
			Reason:             "InvalidSignatureID",
			Message:            fmt.Sprintf("SignatureID %q does not match required pattern PAN-SIG-XXXX", sig.Spec.SignatureID),
		})
		meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
			Type:               "Active",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: sig.Generation,
			Reason:             "ValidationFailed",
			Message:            "Signature cannot be activated due to validation errors",
		})
		r.Recorder.Event(sig, "Warning", "InvalidSignatureID",
			fmt.Sprintf("SignatureID %q does not match PAN-SIG-XXXX pattern", sig.Spec.SignatureID))

		if err := r.Status().Update(ctx, sig); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Initialize detection count if not set
	if sig.Status.DetectionCount == 0 {
		sig.Status.DetectionCount = 0
	}

	// Set Active condition based on enabled flag
	if sig.Spec.Enabled {
		meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
			Type:               "Active",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: sig.Generation,
			Reason:             "SignatureEnabled",
			Message:            fmt.Sprintf("Signature %s is active with %d patterns", sig.Spec.SignatureID, len(sig.Spec.Patterns)),
		})
	} else {
		meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
			Type:               "Active",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: sig.Generation,
			Reason:             "SignatureDisabled",
			Message:            fmt.Sprintf("Signature %s is disabled", sig.Spec.SignatureID),
		})
	}

	// Set Ready condition
	meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		ObservedGeneration: sig.Generation,
		Reason:             "Reconciled",
		Message:            fmt.Sprintf("ThreatSignature %s reconciled with %d patterns", sig.Spec.SignatureID, len(sig.Spec.Patterns)),
	})

	if err := r.Status().Update(ctx, sig); err != nil {
		logger.Error(err, "Failed to update PanoptiumThreatSignature status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PanoptiumThreatSignatureReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&panoptiumiov1alpha1.PanoptiumThreatSignature{}).
		Complete(r)
}
