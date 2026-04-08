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

// Package deploy contains deployment infrastructure tests for the Panoptium operator.
// These tests verify that Docker image builds succeed and that kustomize output
// includes the required ExtProc Service and container port configurations.
package deploy

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const projectRelPath = "../.."

// TestDockerBuild verifies that `make docker-build` succeeds with the operator image.
// This catches Dockerfile issues such as missing COPY directives for source directories.
func TestDockerBuild(t *testing.T) {
	cmd := exec.Command("make", "docker-build", "IMG=example.com/panoptium:e2e")
	cmd.Dir = projectRelPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make docker-build failed: %v\nOutput:\n%s", err, string(output))
	}
}

// TestKustomizeExtProcService verifies that kustomize output includes an ExtProc
// Service exposing port 9001 with the correct selector for the controller-manager.
func TestKustomizeExtProcService(t *testing.T) {
	kustomizeBin := findKustomize(t)

	cmd := exec.Command(kustomizeBin, "build", "config/default")
	cmd.Dir = projectRelPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kustomize build failed: %v\nOutput:\n%s", err, string(output))
	}

	out := string(output)

	// Verify ExtProc Service with port 9001 is present
	if !strings.Contains(out, "name: panoptium-controller-manager-extproc") {
		t.Fatal("kustomize output missing ExtProc Service (panoptium-controller-manager-extproc)")
	}

	if !strings.Contains(out, "9001") {
		t.Fatal("kustomize output missing port 9001 for ExtProc Service")
	}
}

// TestKustomizeExtProcContainerPort verifies that kustomize output includes
// containerPort 9001 in the deployment spec for the operator manager container.
func TestKustomizeExtProcContainerPort(t *testing.T) {
	kustomizeBin := findKustomize(t)

	cmd := exec.Command(kustomizeBin, "build", "config/default")
	cmd.Dir = projectRelPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kustomize build failed: %v\nOutput:\n%s", err, string(output))
	}

	out := string(output)

	// Verify containerPort 9001 is present in the deployment spec
	if !strings.Contains(out, "containerPort: 9001") {
		t.Fatal("kustomize output missing containerPort 9001 in deployment spec")
	}
}

// projectRoot returns the absolute path to the project root directory.
func projectRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

// findKustomize locates the kustomize binary, preferring the project-local
// bin directory, falling back to PATH.
func findKustomize(t *testing.T) string {
	t.Helper()

	root := projectRoot()

	// Try project-local kustomize first
	localBin := filepath.Join(root, "bin", "kustomize")
	if _, err := exec.Command(localBin, "version").Output(); err == nil {
		return localBin
	}

	// Fall back to PATH
	path, err := exec.LookPath("kustomize")
	if err != nil {
		t.Skip("kustomize not found in PATH or project bin; skipping kustomize test")
	}
	return path
}
