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

package tetragon

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// policiesDir is the path to the TracingPolicy YAML files relative to the repo root.
const policiesDir = "../../../config/tetragon/policies"

// tracingPolicy represents the minimal structure of a Tetragon TracingPolicy CRD.
type tracingPolicy struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Spec struct {
		KProbes     []kprobeSpec     `yaml:"kprobes,omitempty"`
		Tracepoints []tracepointSpec `yaml:"tracepoints,omitempty"`
		LSM         []lsmSpec        `yaml:"lsm,omitempty"`
		// PodSelector for namespace/pod filtering.
		PodSelector []podSelectorSpec `yaml:"podSelector,omitempty"`
	} `yaml:"spec"`
}

type kprobeSpec struct {
	Call       string        `yaml:"call"`
	Syscall    bool          `yaml:"syscall"`
	Args       []argSpec     `yaml:"args,omitempty"`
	Selectors  []selectorSet `yaml:"selectors,omitempty"`
	ReturnArg  *argSpec      `yaml:"returnArg,omitempty"`
	ReturnArgAction string  `yaml:"returnArgAction,omitempty"`
}

type tracepointSpec struct {
	Subsystem string        `yaml:"subsystem"`
	Event     string        `yaml:"event"`
	Args      []argSpec     `yaml:"args,omitempty"`
	Selectors []selectorSet `yaml:"selectors,omitempty"`
}

type lsmSpec struct {
	Hook      string        `yaml:"hook"`
	Args      []argSpec     `yaml:"args,omitempty"`
	Selectors []selectorSet `yaml:"selectors,omitempty"`
}

type argSpec struct {
	Index    int    `yaml:"index"`
	Type     string `yaml:"type"`
	SizeArg  int    `yaml:"sizeArg,omitempty"`
	Label    string `yaml:"label,omitempty"`
}

type selectorSet struct {
	MatchArgs       []matchArg       `yaml:"matchArgs,omitempty"`
	MatchActions    []matchAction    `yaml:"matchActions,omitempty"`
	MatchNamespaces []matchNamespace `yaml:"matchNamespaces,omitempty"`
}

type matchArg struct {
	Index    int      `yaml:"index"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values,omitempty"`
}

type matchAction struct {
	Action   string `yaml:"action"`
	ArgError int    `yaml:"argError,omitempty"`
}

type matchNamespace struct {
	Namespace string   `yaml:"namespace"`
	Operator  string   `yaml:"operator"`
	Values    []string `yaml:"values,omitempty"`
}

type podSelectorSpec struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

// expectedPolicies lists the TracingPolicy files we expect to exist.
var expectedPolicies = []string{
	"execve-monitor.yaml",
	"openat-monitor.yaml",
	"connect-monitor.yaml",
	"fork-monitor.yaml",
	"exit-monitor.yaml",
	"namespace-monitor.yaml",
	"mount-enforce.yaml",
	"ptrace-enforce.yaml",
	"bpf-selfmon.yaml",
}

// enforcementPolicies are policies that must include Override or Signal actions.
var enforcementPolicies = map[string]bool{
	"mount-enforce.yaml":  true,
	"ptrace-enforce.yaml": true,
}

func TestAllPoliciesExist(t *testing.T) {
	for _, name := range expectedPolicies {
		path := filepath.Join(policiesDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected policy file %q to exist at %q", name, path)
		}
	}
}

func TestPoliciesAreValidYAML(t *testing.T) {
	for _, name := range expectedPolicies {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(policiesDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("policy file not found: %v", err)
				return
			}

			var policy tracingPolicy
			if err := yaml.Unmarshal(data, &policy); err != nil {
				t.Errorf("invalid YAML in %q: %v", name, err)
			}
		})
	}
}

func TestPoliciesHaveCorrectAPIVersionAndKind(t *testing.T) {
	for _, name := range expectedPolicies {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(policiesDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("policy file not found: %v", err)
				return
			}

			var policy tracingPolicy
			if err := yaml.Unmarshal(data, &policy); err != nil {
				t.Fatalf("invalid YAML: %v", err)
			}

			if policy.APIVersion != "cilium.io/v1alpha1" {
				t.Errorf("expected apiVersion cilium.io/v1alpha1, got %q", policy.APIVersion)
			}
			if policy.Kind != "TracingPolicy" {
				t.Errorf("expected kind TracingPolicy, got %q", policy.Kind)
			}
		})
	}
}

func TestPoliciesHaveMetadataName(t *testing.T) {
	for _, name := range expectedPolicies {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(policiesDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("policy file not found: %v", err)
				return
			}

			var policy tracingPolicy
			if err := yaml.Unmarshal(data, &policy); err != nil {
				t.Fatalf("invalid YAML: %v", err)
			}

			if policy.Metadata.Name == "" {
				t.Error("policy must have a metadata.name")
			}
		})
	}
}

func TestPoliciesHavePanoptiumLabels(t *testing.T) {
	for _, name := range expectedPolicies {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(policiesDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("policy file not found: %v", err)
				return
			}

			var policy tracingPolicy
			if err := yaml.Unmarshal(data, &policy); err != nil {
				t.Fatalf("invalid YAML: %v", err)
			}

			if policy.Metadata.Labels["app.kubernetes.io/part-of"] != "panoptium" {
				t.Error("policy must have label app.kubernetes.io/part-of=panoptium")
			}
		})
	}
}

func TestPoliciesHaveHookDefinitions(t *testing.T) {
	for _, name := range expectedPolicies {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(policiesDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("policy file not found: %v", err)
				return
			}

			var policy tracingPolicy
			if err := yaml.Unmarshal(data, &policy); err != nil {
				t.Fatalf("invalid YAML: %v", err)
			}

			hasHooks := len(policy.Spec.KProbes) > 0 ||
				len(policy.Spec.Tracepoints) > 0 ||
				len(policy.Spec.LSM) > 0
			if !hasHooks {
				t.Error("policy must define at least one kprobe, tracepoint, or lsm hook")
			}
		})
	}
}

func TestEnforcementPoliciesHaveActions(t *testing.T) {
	for _, name := range expectedPolicies {
		if !enforcementPolicies[name] {
			continue
		}

		t.Run(name, func(t *testing.T) {
			path := filepath.Join(policiesDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("policy file not found: %v", err)
				return
			}

			var policy tracingPolicy
			if err := yaml.Unmarshal(data, &policy); err != nil {
				t.Fatalf("invalid YAML: %v", err)
			}

			hasOverride := false
			// Check kprobes for Override/Signal actions.
			for _, kp := range policy.Spec.KProbes {
				for _, sel := range kp.Selectors {
					for _, action := range sel.MatchActions {
						if action.Action == "Override" || action.Action == "Signal" {
							hasOverride = true
						}
					}
				}
			}
			// Check LSM hooks for Override/Signal actions.
			for _, l := range policy.Spec.LSM {
				for _, sel := range l.Selectors {
					for _, action := range sel.MatchActions {
						if action.Action == "Override" || action.Action == "Signal" {
							hasOverride = true
						}
					}
				}
			}

			if !hasOverride {
				t.Errorf("enforcement policy %q must include Override or Signal action", name)
			}
		})
	}
}
