/*
Copyright 2026.

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

package threat

import (
	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

func SignatureDefinitionFromCRD(sig *v1alpha1.ThreatSignature) SignatureDefinition {
	if sig == nil {
		return SignatureDefinition{}
	}

	def := SignatureDefinition{
		Name:        sig.Name,
		Protocols:   sig.Spec.Protocols,
		Category:    sig.Spec.Category,
		Severity:    string(sig.Spec.Severity),
		MitreAtlas:  sig.Spec.MitreAtlas,
		Description: sig.Spec.Description,
	}

	for _, pat := range sig.Spec.Detection.Patterns {
		def.Patterns = append(def.Patterns, PatternDef{
			Regex:  pat.Regex,
			Weight: pat.Weight,
			Target: pat.Target,
		})
	}

	if sig.Spec.Detection.Entropy != nil {
		def.Entropy = &EntropyDef{
			Enabled:   sig.Spec.Detection.Entropy.Enabled,
			Threshold: sig.Spec.Detection.Entropy.Threshold,
			Target:    sig.Spec.Detection.Entropy.Target,
		}
	}

	if sig.Spec.Detection.Base64 != nil {
		def.Base64 = &Base64Def{
			Enabled:   sig.Spec.Detection.Base64.Enabled,
			MinLength: sig.Spec.Detection.Base64.MinLength,
			Target:    sig.Spec.Detection.Base64.Target,
		}
	}

	for _, cel := range sig.Spec.Detection.CEL {
		def.CELExpressions = append(def.CELExpressions, CELDef{
			Expression: cel.Expression,
			Weight:     cel.Weight,
		})
	}

	return def
}
