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
	"github.com/panoptium/panoptium/pkg/threat"
)

type ThreatSignatureReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Registry *threat.CompiledSignatureRegistry
}

// +kubebuilder:rbac:groups=panoptium.io,resources=threatsignatures,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=panoptium.io,resources=threatsignatures/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=panoptium.io,resources=threatsignatures/finalizers,verbs=update

func (r *ThreatSignatureReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	sig := &panoptiumiov1alpha1.ThreatSignature{}
	if err := r.Get(ctx, req.NamespacedName, sig); err != nil {
		if client.IgnoreNotFound(err) == nil {
			if r.Registry != nil {
				r.Registry.RemoveSignature(req.Name)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling ThreatSignature",
		"name", sig.Name,
		"category", sig.Spec.Category,
		"severity", sig.Spec.Severity)

	sig.Status.ObservedGeneration = sig.Generation

	var compiledCount int32
	var compileErrors []string

	for i, pat := range sig.Spec.Detection.Patterns {
		_, err := regexp.Compile(pat.Regex)
		if err != nil {
			compileErrors = append(compileErrors, fmt.Sprintf("pattern[%d] regex %q: %v", i, pat.Regex, err))
		} else {
			compiledCount++
		}
	}

	sig.Status.CompiledPatterns = compiledCount

	if len(compileErrors) > 0 {
		meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: sig.Generation,
			Reason:             ConditionReasonCompilationFailed,
			Message:            fmt.Sprintf("Failed to compile %d pattern(s): %v", len(compileErrors), compileErrors),
		})

		r.Recorder.Event(sig, "Warning", ConditionReasonCompilationFailed,
			fmt.Sprintf("Failed to compile patterns: %v", compileErrors))

		if r.Registry != nil {
			r.Registry.RemoveSignature(sig.Name)
		}

		if err := r.Status().Update(ctx, sig); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if r.Registry != nil {
		sigDef := threat.SignatureDefinitionFromCRD(sig)

		if err := r.Registry.AddSignature(sigDef); err != nil {
			meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
				Type:               ConditionTypeReady,
				Status:             metav1.ConditionFalse,
				ObservedGeneration: sig.Generation,
				Reason:             "RegistryError",
				Message:            fmt.Sprintf("Failed to add signature to registry: %v", err),
			})
			if err := r.Status().Update(ctx, sig); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
	}

	meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: sig.Generation,
		Reason:             ConditionReasonCompiled,
		Message:            fmt.Sprintf("ThreatSignature compiled: %d patterns, category=%s", compiledCount, sig.Spec.Category),
	})

	if err := r.Status().Update(ctx, sig); err != nil {
		logger.Error(err, "Failed to update ThreatSignature status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *ThreatSignatureReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&panoptiumiov1alpha1.ThreatSignature{}).
		Complete(r)
}
