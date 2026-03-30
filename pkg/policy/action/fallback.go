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

package action

// FallbackFunction is the interface for fallback functions that attempt
// to make a denied request safe. Each fallback returns true if it
// successfully made the request safe, false if no safe alternative exists.
type FallbackFunction interface {
	// Apply attempts to make the denied request safe by modifying the fields.
	// Returns true if the request was made safe, false if no safe alternative exists.
	Apply(result *ActionResult, fields map[string]string) (bool, error)
}

// PathRewriter is a fallback function that replaces denied paths with
// pre-configured safe alternatives.
type PathRewriter struct {
	// SafePaths maps denied paths to their safe alternatives.
	SafePaths map[string]string
}

// Apply checks if the denied path has a safe alternative and rewrites it.
func (r *PathRewriter) Apply(result *ActionResult, fields map[string]string) (bool, error) {
	path, ok := fields["path"]
	if !ok {
		return false, nil
	}

	safePath, found := r.SafePaths[path]
	if !found {
		return false, nil
	}

	fields["path"] = safePath
	return true, nil
}

// ArgumentSanitizer is a fallback function that strips sensitive fields
// from the request arguments before allowing it.
type ArgumentSanitizer struct {
	// FieldsToStrip is the list of field names to remove from the request.
	FieldsToStrip []string
}

// Apply removes sensitive fields from the request arguments. If any
// fields were stripped (or no sensitive fields exist), the request is
// considered safe.
func (s *ArgumentSanitizer) Apply(result *ActionResult, fields map[string]string) (bool, error) {
	for _, field := range s.FieldsToStrip {
		delete(fields, field)
	}
	return true, nil
}

// ProviderSubstituter is a fallback function that reroutes the request
// to a safer provider endpoint.
type ProviderSubstituter struct {
	// EndpointMap maps original endpoints to their safe alternatives.
	EndpointMap map[string]string
}

// Apply checks if the endpoint has a safe alternative and rewrites it.
func (p *ProviderSubstituter) Apply(result *ActionResult, fields map[string]string) (bool, error) {
	endpoint, ok := fields["endpoint"]
	if !ok {
		return false, nil
	}

	safeEndpoint, found := p.EndpointMap[endpoint]
	if !found {
		return false, nil
	}

	fields["endpoint"] = safeEndpoint
	return true, nil
}

// FallbackEngine executes a pipeline of fallback functions in order.
// The first successful fallback converts the deny decision to allow
// with a "fallback_applied" annotation.
type FallbackEngine struct {
	// Fallbacks is the ordered list of fallback functions to attempt.
	Fallbacks []FallbackFunction
}

// TryFallbacks attempts each fallback function in order. If any succeeds,
// the result is converted from deny to allow with a "fallback_applied"
// annotation. If all fail, the original deny result is preserved.
func (e *FallbackEngine) TryFallbacks(result *ActionResult, fields map[string]string) (*ActionResult, error) {
	for _, fb := range e.Fallbacks {
		ok, err := fb.Apply(result, fields)
		if err != nil {
			return result, err
		}
		if ok {
			// Convert deny to allow
			result.Permitted = true
			if result.Annotations == nil {
				result.Annotations = make(map[string]string)
			}
			result.Annotations["fallback_applied"] = "true"
			return result, nil
		}
	}

	// All fallbacks failed, preserve deny
	return result, nil
}
