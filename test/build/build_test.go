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

// Package build contains build verification tests for the Panoptium operator.
package build

import (
	"os/exec"
	"testing"
)

// TestProjectBuilds verifies that the Go module compiles without errors.
// This serves as a build smoke test to catch compilation issues early.
func TestProjectBuilds(t *testing.T) {
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = "../.."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("project failed to build: %v\nOutput:\n%s", err, string(output))
	}
}

// TestProjectVet verifies that go vet passes without issues.
func TestProjectVet(t *testing.T) {
	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = "../.."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go vet failed: %v\nOutput:\n%s", err, string(output))
	}
}
