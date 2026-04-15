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

package policy_test

import (
	"strings"
	"testing"

	sigsyaml "sigs.k8s.io/yaml"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/policy"
)

const validPolicyYAML = `
apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: cli-offline-smoke
  namespace: default
spec:
  priority: 100
  enforcementMode: enforce
  targetSelector:
    matchLabels:
      app: summarizer
  rules:
    - name: deny-curl-exec
      severity: high
      trigger:
        eventCategory: kernel
        eventSubcategory: process_exec
      predicates:
        - cel: 'event.processName == "curl"'
      action:
        type: deny
    - name: regex-suspicious-path
      severity: medium
      trigger:
        eventCategory: kernel
        eventSubcategory: file_open
      predicates:
        - cel: 'event.path.matches("^/etc/.*")'
      action:
        type: alert
`

const invalidPolicyYAML = `
apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: cli-offline-smoke-invalid
  namespace: default
spec:
  priority: 100
  enforcementMode: enforce
  targetSelector:
    matchLabels:
      app: summarizer
  rules:
    - name: bogus-layer
      severity: high
      trigger:
        eventCategory: not-a-real-layer
        eventSubcategory: nothing
      action:
        type: deny
`

func TestOfflineAPI_ValidPolicy(t *testing.T) {
	var pol v1alpha1.AgentPolicy
	if err := sigsyaml.Unmarshal([]byte(validPolicyYAML), &pol); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	compiler := policy.NewPolicyCompiler()
	compiled, err := compiler.Compile(&pol)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if compiled == nil {
		t.Fatal("Compile() returned nil CompiledPolicy")
	}
	if compiled.Name != "cli-offline-smoke" {
		t.Errorf("Name = %q, want cli-offline-smoke", compiled.Name)
	}
	if compiled.Namespace != "default" {
		t.Errorf("Namespace = %q, want default", compiled.Namespace)
	}
	if got, want := len(compiled.Rules), 2; got != want {
		t.Fatalf("len(Rules) = %d, want %d", got, want)
	}

	r0 := compiled.Rules[0]
	if r0.TriggerLayer != "kernel" || r0.TriggerEvent != "process_exec" {
		t.Errorf("rule[0] trigger = %s/%s, want kernel/process_exec",
			r0.TriggerLayer, r0.TriggerEvent)
	}
	if len(r0.Predicates) != 1 {
		t.Fatalf("rule[0] predicates = %d, want 1", len(r0.Predicates))
	}
	if r0.Predicates[0].Operator != "==" {
		t.Errorf("rule[0] op = %q, want ==", r0.Predicates[0].Operator)
	}
	if r0.Action.Type != v1alpha1.ActionTypeDeny {
		t.Errorf("rule[0] action = %q, want deny", r0.Action.Type)
	}

	r1 := compiled.Rules[1]
	if r1.TriggerLayer != "kernel" || r1.TriggerEvent != "file_open" {
		t.Errorf("rule[1] trigger = %s/%s, want kernel/file_open",
			r1.TriggerLayer, r1.TriggerEvent)
	}
	if got := len(r1.CompiledRegexes); got != 1 {
		t.Errorf("rule[1] CompiledRegexes = %d, want 1", got)
	}
	if r1.Action.Type != v1alpha1.ActionTypeAlert {
		t.Errorf("rule[1] action = %q, want alert", r1.Action.Type)
	}
}

func TestOfflineAPI_InvalidPolicyReturnsCompilationError(t *testing.T) {
	var pol v1alpha1.AgentPolicy
	if err := sigsyaml.Unmarshal([]byte(invalidPolicyYAML), &pol); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	compiler := policy.NewPolicyCompiler()
	_, err := compiler.Compile(&pol)
	if err == nil {
		t.Fatal("Compile() succeeded on invalid policy, want error")
	}

	var ce *policy.CompilationError
	if typed, ok := err.(*policy.CompilationError); ok {
		ce = typed
	}
	if ce == nil {
		t.Fatalf("expected *policy.CompilationError, got %T: %v", err, err)
	}
	if ce.PolicyName != "cli-offline-smoke-invalid" {
		t.Errorf("PolicyName = %q, want cli-offline-smoke-invalid", ce.PolicyName)
	}
	if ce.Field != "trigger.eventCategory" {
		t.Errorf("Field = %q, want trigger.eventCategory", ce.Field)
	}
	if !strings.Contains(ce.Message, "unknown trigger layer") {
		t.Errorf("Message = %q, want it to mention unknown trigger layer", ce.Message)
	}
}

func TestOfflineAPI_CompileClusterPolicy(t *testing.T) {
	const clusterYAML = `
apiVersion: panoptium.io/v1alpha1
kind: AgentClusterPolicy
metadata:
  name: cli-offline-cluster
spec:
  priority: 50
  enforcementMode: enforce
  targetSelector:
    matchLabels:
      tier: production
  rules:
    - name: llm-prompt-submit
      severity: medium
      trigger:
        eventCategory: llm
        eventSubcategory: prompt_submit
      predicates:
        - cel: 'event.model == "gpt-4"'
      action:
        type: alert
`
	var pol v1alpha1.AgentClusterPolicy
	if err := sigsyaml.Unmarshal([]byte(clusterYAML), &pol); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	compiler := policy.NewPolicyCompiler()
	compiled, err := compiler.CompileCluster(&pol)
	if err != nil {
		t.Fatalf("CompileCluster() unexpected error: %v", err)
	}
	if !compiled.IsClusterScoped {
		t.Error("CompiledPolicy.IsClusterScoped = false, want true")
	}
	if compiled.Namespace != "" {
		t.Errorf("Namespace = %q, want empty", compiled.Namespace)
	}
	if got := len(compiled.Rules); got != 1 {
		t.Fatalf("len(Rules) = %d, want 1", got)
	}
	if compiled.Rules[0].TriggerLayer != "llm" {
		t.Errorf("TriggerLayer = %q, want llm", compiled.Rules[0].TriggerLayer)
	}
}
