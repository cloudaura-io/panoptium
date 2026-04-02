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
	"fmt"
	"regexp"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/google/cel-go/cel"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// validTargets defines the allowed target values for PatternRule, EntropyRule, and Base64Rule.
var validTargets = map[string]bool{
	"tool_description": true,
	"tool_args":        true,
	"message_content":  true,
	"body":             true,
}

// ThreatSignatureValidator validates PanoptiumThreatSignature resources on create and update.
// It checks regex compilation, CEL expression syntax, enum values, and required fields.
type ThreatSignatureValidator struct{}

var _ webhook.CustomValidator = &ThreatSignatureValidator{}

// SetupWebhookWithManager registers the validating webhook with the manager.
func (v *ThreatSignatureValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&panoptiumiov1alpha1.PanoptiumThreatSignature{}).
		WithValidator(v).
		Complete()
}

// ValidateCreate validates a PanoptiumThreatSignature on creation.
func (v *ThreatSignatureValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	sig, ok := obj.(*panoptiumiov1alpha1.PanoptiumThreatSignature)
	if !ok {
		return nil, fmt.Errorf("expected PanoptiumThreatSignature but got %T", obj)
	}
	return validateThreatSignature(sig)
}

// ValidateUpdate validates a PanoptiumThreatSignature on update.
func (v *ThreatSignatureValidator) ValidateUpdate(_ context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	sig, ok := newObj.(*panoptiumiov1alpha1.PanoptiumThreatSignature)
	if !ok {
		return nil, fmt.Errorf("expected PanoptiumThreatSignature but got %T", newObj)
	}
	return validateThreatSignature(sig)
}

// ValidateDelete validates a PanoptiumThreatSignature on deletion (no-op).
func (v *ThreatSignatureValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// validateThreatSignature performs all validation checks on a PanoptiumThreatSignature.
func validateThreatSignature(sig *panoptiumiov1alpha1.PanoptiumThreatSignature) (admission.Warnings, error) {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")

	// Validate required category
	if sig.Spec.Category == "" {
		allErrs = append(allErrs, field.Required(
			specPath.Child("category"),
			"category is required",
		))
	}

	// Validate required description
	if sig.Spec.Description == "" {
		allErrs = append(allErrs, field.Required(
			specPath.Child("description"),
			"description is required",
		))
	}

	// Validate detection patterns
	detectionPath := specPath.Child("detection")
	patternsPath := detectionPath.Child("patterns")
	for i, pattern := range sig.Spec.Detection.Patterns {
		patternPath := patternsPath.Index(i)

		// Validate regex compiles
		if pattern.Regex != "" {
			if _, err := regexp.Compile(pattern.Regex); err != nil {
				allErrs = append(allErrs, field.Invalid(
					patternPath.Child("regex"),
					pattern.Regex,
					fmt.Sprintf("invalid regex pattern: %v", err),
				))
			}
		}

		// Validate target value
		if pattern.Target != "" && !validTargets[pattern.Target] {
			allErrs = append(allErrs, field.NotSupported(
				patternPath.Child("target"),
				pattern.Target,
				validTargetsList(),
			))
		}
	}

	// Validate CEL expressions
	celPath := detectionPath.Child("cel")
	for i, celRule := range sig.Spec.Detection.CEL {
		rulePath := celPath.Index(i)

		if celRule.Expression != "" {
			if err := validateThreatCELExpression(celRule.Expression); err != nil {
				allErrs = append(allErrs, field.Invalid(
					rulePath.Child("expression"),
					celRule.Expression,
					fmt.Sprintf("invalid CEL expression: %v", err),
				))
			}
		}
	}

	// Validate entropy target if specified
	if sig.Spec.Detection.Entropy != nil && sig.Spec.Detection.Entropy.Target != "" {
		if !validTargets[sig.Spec.Detection.Entropy.Target] {
			allErrs = append(allErrs, field.NotSupported(
				detectionPath.Child("entropy", "target"),
				sig.Spec.Detection.Entropy.Target,
				validTargetsList(),
			))
		}
	}

	// Validate base64 target if specified
	if sig.Spec.Detection.Base64 != nil && sig.Spec.Detection.Base64.Target != "" {
		if !validTargets[sig.Spec.Detection.Base64.Target] {
			allErrs = append(allErrs, field.NotSupported(
				detectionPath.Child("base64", "target"),
				sig.Spec.Detection.Base64.Target,
				validTargetsList(),
			))
		}
	}

	if len(allErrs) > 0 {
		return nil, allErrs.ToAggregate()
	}
	return nil, nil
}

// validateThreatCELExpression checks if a CEL expression is syntactically valid
// using the threat detection CEL environment (with content variable and custom functions).
func validateThreatCELExpression(expr string) error {
	env, err := cel.NewEnv(
		cel.Variable("content", cel.StringType),
	)
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}

	_, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return issues.Err()
	}

	return nil
}

// validTargetsList returns a sorted list of valid target values for error messages.
func validTargetsList() []string {
	return []string{"body", "message_content", "tool_args", "tool_description"}
}
