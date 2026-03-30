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

package policy

import (
	"fmt"
	"testing"
	"time"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- Test Helpers ---

// newTestPolicy creates a PanoptiumPolicy with the given rules for testing.
func newTestPolicy(name, namespace string, priority int32, rules []v1alpha1.PolicyRule) *v1alpha1.PanoptiumPolicy {
	return &v1alpha1.PanoptiumPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        priority,
			Rules:           rules,
		},
	}
}

// --- Compiler Tests ---

func TestPolicyCompiler_ValidPolicy(t *testing.T) {
	policy := newTestPolicy("test-policy", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "deny-curl",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName == "curl"`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if compiled == nil {
		t.Fatal("Compile() returned nil CompiledPolicy")
	}
	if compiled.Name != "test-policy" {
		t.Errorf("CompiledPolicy.Name = %q, want %q", compiled.Name, "test-policy")
	}
	if compiled.Namespace != "default" {
		t.Errorf("CompiledPolicy.Namespace = %q, want %q", compiled.Namespace, "default")
	}
	if compiled.Priority != 100 {
		t.Errorf("CompiledPolicy.Priority = %d, want %d", compiled.Priority, 100)
	}
	if len(compiled.Rules) != 1 {
		t.Fatalf("CompiledPolicy.Rules length = %d, want 1", len(compiled.Rules))
	}
}

func TestPolicyCompiler_TriggerParsing_KernelLayer(t *testing.T) {
	kernelEvents := []string{
		"file_open", "file_write", "file_delete",
		"process_exec", "process_fork", "module_load", "capability_use",
	}
	for _, evt := range kernelEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("kernel-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for kernel/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "kernel" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "kernel")
			}
			if compiled.Rules[0].TriggerEvent != evt {
				t.Errorf("TriggerEvent = %q, want %q", compiled.Rules[0].TriggerEvent, evt)
			}
		})
	}
}

func TestPolicyCompiler_TriggerParsing_NetworkLayer(t *testing.T) {
	networkEvents := []string{
		"egress_attempt", "ingress_attempt", "dns_query",
		"dns_response", "connection_established", "connection_closed",
	}
	for _, evt := range networkEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("network-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "network",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for network/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "network" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "network")
			}
		})
	}
}

func TestPolicyCompiler_TriggerParsing_ProtocolLayer(t *testing.T) {
	protocolEvents := []string{
		"tool_call", "tool_response", "message_send", "message_receive", "task_delegate",
	}
	for _, evt := range protocolEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("protocol-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "protocol",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for protocol/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "protocol" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "protocol")
			}
		})
	}
}

func TestPolicyCompiler_TriggerParsing_LLMLayer(t *testing.T) {
	llmEvents := []string{
		"prompt_submit", "completion_receive", "tool_use_intent", "function_call", "token_stream",
	}
	for _, evt := range llmEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("llm-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "llm",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for llm/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "llm" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "llm")
			}
		})
	}
}

func TestPolicyCompiler_TriggerParsing_LifecycleLayer(t *testing.T) {
	lifecycleEvents := []string{
		"pod_start", "pod_stop", "container_exec", "agent_register", "agent_deregister",
	}
	for _, evt := range lifecycleEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("lifecycle-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "lifecycle",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for lifecycle/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "lifecycle" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "lifecycle")
			}
		})
	}
}

func TestPolicyCompiler_PrecompiledRegex(t *testing.T) {
	policy := newTestPolicy("regex-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "regex-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName.matches("^(curl|wget)$")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if len(compiled.Rules[0].CompiledRegexes) == 0 {
		t.Error("expected pre-compiled regex matchers, got none")
	}
}

func TestPolicyCompiler_PrecompiledGlob(t *testing.T) {
	policy := newTestPolicy("glob-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "glob-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "file_open",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.path.glob("/etc/**")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if len(compiled.Rules[0].CompiledGlobs) == 0 {
		t.Error("expected pre-compiled glob matchers, got none")
	}
}

func TestPolicyCompiler_PrecompiledCIDR(t *testing.T) {
	policy := newTestPolicy("cidr-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "cidr-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "network",
				EventSubcategory: "egress_attempt",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.destinationIP.inCIDR("10.0.0.0/8")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if len(compiled.Rules[0].CompiledCIDRs) == 0 {
		t.Error("expected pre-compiled CIDR matchers, got none")
	}
}

func TestPolicyCompiler_InvalidRegex(t *testing.T) {
	policy := newTestPolicy("bad-regex", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "bad-regex-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName.matches("[invalid")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.Compile(policy)
	if err == nil {
		t.Fatal("Compile() expected error for invalid regex, got nil")
	}
	var compErr *CompilationError
	if !asCompilationError(err, &compErr) {
		t.Errorf("expected CompilationError, got %T: %v", err, err)
	}
}

func TestPolicyCompiler_UnknownTriggerType(t *testing.T) {
	policy := newTestPolicy("unknown-trigger", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "bad-trigger-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "nonexistent",
				EventSubcategory: "something",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.Compile(policy)
	if err == nil {
		t.Fatal("Compile() expected error for unknown trigger type, got nil")
	}
	var compErr *CompilationError
	if !asCompilationError(err, &compErr) {
		t.Errorf("expected CompilationError, got %T: %v", err, err)
	}
}

func TestPolicyCompiler_MalformedCIDR(t *testing.T) {
	policy := newTestPolicy("bad-cidr", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "bad-cidr-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "network",
				EventSubcategory: "egress_attempt",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.destinationIP.inCIDR("not-a-cidr")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.Compile(policy)
	if err == nil {
		t.Fatal("Compile() expected error for malformed CIDR, got nil")
	}
	var compErr *CompilationError
	if !asCompilationError(err, &compErr) {
		t.Errorf("expected CompilationError, got %T: %v", err, err)
	}
}

func TestPolicyCompiler_LatencyUnder100ms(t *testing.T) {
	// Create a realistic-sized policy with 50 rules across various triggers.
	rules := make([]v1alpha1.PolicyRule, 50)
	layers := []string{"kernel", "network", "protocol", "llm", "lifecycle"}
	events := map[string][]string{
		"kernel":    {"file_open", "file_write", "process_exec"},
		"network":   {"egress_attempt", "dns_query", "connection_established"},
		"protocol":  {"tool_call", "message_send"},
		"llm":       {"prompt_submit", "completion_receive"},
		"lifecycle": {"pod_start", "container_exec"},
	}

	for i := range rules {
		layer := layers[i%len(layers)]
		evts := events[layer]
		evt := evts[i%len(evts)]
		rules[i] = v1alpha1.PolicyRule{
			Name: "rule-" + layer + "-" + evt,
			Trigger: v1alpha1.Trigger{
				EventCategory:    layer,
				EventSubcategory: evt,
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName == "test"`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityMedium,
		}
	}

	policy := newTestPolicy("latency-test", "default", 100, rules)
	compiler := NewPolicyCompiler()

	start := time.Now()
	_, err := compiler.Compile(policy)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("Compile() took %v, want <100ms", elapsed)
	}
}

func TestPolicyCompiler_MultipleRules(t *testing.T) {
	policy := newTestPolicy("multi-rule", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "rule-1",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
		{
			Name: "rule-2",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "network",
				EventSubcategory: "egress_attempt",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
			Severity: v1alpha1.SeverityMedium,
		},
		{
			Name: "rule-3",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "llm",
				EventSubcategory: "prompt_submit",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAllow},
			Severity: v1alpha1.SeverityLow,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if len(compiled.Rules) != 3 {
		t.Errorf("CompiledPolicy.Rules length = %d, want 3", len(compiled.Rules))
	}
}

func TestPolicyCompiler_EnforcementMode(t *testing.T) {
	modes := []v1alpha1.EnforcementMode{
		v1alpha1.EnforcementModeEnforcing,
		v1alpha1.EnforcementModeAudit,
		v1alpha1.EnforcementModeDisabled,
	}
	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			policy := newTestPolicy("mode-test", "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-1",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "process_exec",
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			})
			policy.Spec.EnforcementMode = mode

			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() unexpected error: %v", err)
			}
			if compiled.EnforcementMode != mode {
				t.Errorf("EnforcementMode = %q, want %q", compiled.EnforcementMode, mode)
			}
		})
	}
}

// --- CompileCluster Tests ---

func newTestClusterPolicy(name string, priority int32, rules []v1alpha1.PolicyRule) *v1alpha1.ClusterPanoptiumPolicy {
	return &v1alpha1.ClusterPanoptiumPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.ClusterPanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        priority,
			Rules:           rules,
		},
	}
}

func TestCompileCluster_HappyPath_IsClusterScopedAndEmptyNamespace(t *testing.T) {
	policy := newTestClusterPolicy("cluster-policy", 200, []v1alpha1.PolicyRule{
		{
			Name: "deny-curl",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName == "curl"`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.CompileCluster(policy)
	if err != nil {
		t.Fatalf("CompileCluster() unexpected error: %v", err)
	}
	if !compiled.IsClusterScoped {
		t.Error("expected IsClusterScoped == true")
	}
	if compiled.Namespace != "" {
		t.Errorf("expected Namespace == \"\", got %q", compiled.Namespace)
	}
	if compiled.Name != "cluster-policy" {
		t.Errorf("expected Name == \"cluster-policy\", got %q", compiled.Name)
	}
}

func TestCompileCluster_RulesCompileCorrectly(t *testing.T) {
	policy := newTestClusterPolicy("cluster-rules", 100, []v1alpha1.PolicyRule{
		{
			Name: "deny-curl",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName == "curl"`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.CompileCluster(policy)
	if err != nil {
		t.Fatalf("CompileCluster() unexpected error: %v", err)
	}
	if len(compiled.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled.Rules))
	}
	if compiled.Rules[0].Name != "deny-curl" {
		t.Errorf("expected rule name \"deny-curl\", got %q", compiled.Rules[0].Name)
	}
	if compiled.Rules[0].TriggerLayer != "kernel" {
		t.Errorf("expected TriggerLayer \"kernel\", got %q", compiled.Rules[0].TriggerLayer)
	}
}

func TestCompileCluster_InvalidTrigger(t *testing.T) {
	policy := newTestClusterPolicy("bad-trigger-cluster", 100, []v1alpha1.PolicyRule{
		{
			Name: "bad-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "nonexistent",
				EventSubcategory: "something",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.CompileCluster(policy)
	if err == nil {
		t.Fatal("CompileCluster() expected error for invalid trigger, got nil")
	}
	var compErr *CompilationError
	if !asCompilationError(err, &compErr) {
		t.Errorf("expected CompilationError, got %T: %v", err, err)
	}
}

func TestCompileCluster_InvalidRegex(t *testing.T) {
	policy := newTestClusterPolicy("bad-regex-cluster", 100, []v1alpha1.PolicyRule{
		{
			Name: "bad-regex-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName.matches("[invalid")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.CompileCluster(policy)
	if err == nil {
		t.Fatal("CompileCluster() expected error for invalid regex, got nil")
	}
	var compErr *CompilationError
	if !asCompilationError(err, &compErr) {
		t.Errorf("expected CompilationError, got %T: %v", err, err)
	}
}

// --- Predicate Parsing Tests ---

func TestPredicateParsing_EqualityOperator(t *testing.T) {
	policy := newTestPolicy("eq-parse", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "eq-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName == "curl"`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	pred := compiled.Rules[0].Predicates[0]
	if pred.FieldPath != "event.processName" {
		t.Errorf("FieldPath = %q, want %q", pred.FieldPath, "event.processName")
	}
	if pred.Operator != "==" {
		t.Errorf("Operator = %q, want %q", pred.Operator, "==")
	}
	if pred.Value != "curl" {
		t.Errorf("Value = %q, want %q", pred.Value, "curl")
	}
}

func TestPredicateParsing_InequalityOperator(t *testing.T) {
	policy := newTestPolicy("neq-parse", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "neq-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName != "safe"`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	pred := compiled.Rules[0].Predicates[0]
	if pred.FieldPath != "event.processName" {
		t.Errorf("FieldPath = %q, want %q", pred.FieldPath, "event.processName")
	}
	if pred.Operator != "!=" {
		t.Errorf("Operator = %q, want %q", pred.Operator, "!=")
	}
	if pred.Value != "safe" {
		t.Errorf("Value = %q, want %q", pred.Value, "safe")
	}
}

func TestPredicateParsing_GreaterThanOperator(t *testing.T) {
	policy := newTestPolicy("gt-parse", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "gt-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.fileSize > 1024`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
			Severity: v1alpha1.SeverityMedium,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	pred := compiled.Rules[0].Predicates[0]
	if pred.FieldPath != "event.fileSize" {
		t.Errorf("FieldPath = %q, want %q", pred.FieldPath, "event.fileSize")
	}
	if pred.Operator != ">" {
		t.Errorf("Operator = %q, want %q", pred.Operator, ">")
	}
	if pred.Value != "1024" {
		t.Errorf("Value = %q, want %q", pred.Value, "1024")
	}
}

func TestPredicateParsing_LessThanOperator(t *testing.T) {
	policy := newTestPolicy("lt-parse", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "lt-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.fileSize < 512`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
			Severity: v1alpha1.SeverityLow,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	pred := compiled.Rules[0].Predicates[0]
	if pred.FieldPath != "event.fileSize" {
		t.Errorf("FieldPath = %q, want %q", pred.FieldPath, "event.fileSize")
	}
	if pred.Operator != "<" {
		t.Errorf("Operator = %q, want %q", pred.Operator, "<")
	}
	if pred.Value != "512" {
		t.Errorf("Value = %q, want %q", pred.Value, "512")
	}
}

func TestPredicateParsing_RawFallback(t *testing.T) {
	policy := newTestPolicy("raw-parse", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "raw-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `someComplexCelExpression(event)`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
			Severity: v1alpha1.SeverityLow,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	pred := compiled.Rules[0].Predicates[0]
	if pred.Operator != "raw" {
		t.Errorf("Operator = %q, want %q", pred.Operator, "raw")
	}
	if pred.Value != `someComplexCelExpression(event)` {
		t.Errorf("Value = %q, want %q", pred.Value, `someComplexCelExpression(event)`)
	}
}

// --- Event Subcategory Edge Cases ---

func TestCompiler_UnknownEventSubcategory(t *testing.T) {
	policy := newTestPolicy("unknown-sub", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "bad-sub-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "nonexistent_event",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.Compile(policy)
	if err == nil {
		t.Fatal("Compile() expected error for unknown subcategory, got nil")
	}
	var compErr *CompilationError
	if !asCompilationError(err, &compErr) {
		t.Errorf("expected CompilationError, got %T: %v", err, err)
	}
}

func TestCompiler_GlobWildcardSubcategory(t *testing.T) {
	policy := newTestPolicy("glob-sub", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "glob-sub-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "file_*",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
			Severity: v1alpha1.SeverityMedium,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error for glob wildcard subcategory: %v", err)
	}
}

func TestCompiler_EmptySubcategory(t *testing.T) {
	policy := newTestPolicy("empty-sub", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "empty-sub-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
			Severity: v1alpha1.SeverityMedium,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error for empty subcategory: %v", err)
	}
}

// --- Preservation and Assignment Tests ---

func TestCompiler_TargetSelectorPreserved(t *testing.T) {
	policy := newTestPolicy("labels-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "rule-1",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})
	policy.Spec.TargetSelector.MatchLabels = map[string]string{
		"app":  "myapp",
		"tier": "frontend",
	}

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if compiled.TargetSelector["app"] != "myapp" {
		t.Errorf("TargetSelector[app] = %q, want %q", compiled.TargetSelector["app"], "myapp")
	}
	if compiled.TargetSelector["tier"] != "frontend" {
		t.Errorf("TargetSelector[tier] = %q, want %q", compiled.TargetSelector["tier"], "frontend")
	}
}

func TestCompiler_ActionParametersPreserved(t *testing.T) {
	policy := newTestPolicy("params-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "rate-limit-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "llm",
				EventSubcategory: "prompt_submit",
			},
			Action: v1alpha1.Action{
				Type: v1alpha1.ActionTypeRateLimit,
				Parameters: map[string]string{
					"requestsPerMinute": "10",
					"burstSize":         "5",
				},
			},
			Severity: v1alpha1.SeverityMedium,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	params := compiled.Rules[0].Action.Parameters
	if params["requestsPerMinute"] != "10" {
		t.Errorf("Parameters[requestsPerMinute] = %q, want %q", params["requestsPerMinute"], "10")
	}
	if params["burstSize"] != "5" {
		t.Errorf("Parameters[burstSize] = %q, want %q", params["burstSize"], "5")
	}
}

func TestCompiler_RuleIndexAssignment(t *testing.T) {
	policy := newTestPolicy("index-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name:     "rule-0",
			Trigger:  v1alpha1.Trigger{EventCategory: "kernel", EventSubcategory: "process_exec"},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
		{
			Name:     "rule-1",
			Trigger:  v1alpha1.Trigger{EventCategory: "network", EventSubcategory: "egress_attempt"},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
			Severity: v1alpha1.SeverityMedium,
		},
		{
			Name:     "rule-2",
			Trigger:  v1alpha1.Trigger{EventCategory: "llm", EventSubcategory: "prompt_submit"},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAllow},
			Severity: v1alpha1.SeverityLow,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	for i, rule := range compiled.Rules {
		if rule.Index != i {
			t.Errorf("Rule[%d].Index = %d, want %d", i, rule.Index, i)
		}
	}
}

func TestCompiler_SeverityPreserved(t *testing.T) {
	policy := newTestPolicy("severity-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name:     "critical-rule",
			Trigger:  v1alpha1.Trigger{EventCategory: "kernel", EventSubcategory: "process_exec"},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityCritical,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if compiled.Rules[0].Severity != v1alpha1.SeverityCritical {
		t.Errorf("Severity = %q, want %q", compiled.Rules[0].Severity, v1alpha1.SeverityCritical)
	}
}

func TestCompiler_EmptyRulesListCompiles(t *testing.T) {
	policy := newTestPolicy("empty-rules", "default", 100, []v1alpha1.PolicyRule{})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error for empty rules: %v", err)
	}
	if len(compiled.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(compiled.Rules))
	}
}

// --- CompilationError Method Tests ---

func TestCompilationError_ErrorWithRuleName(t *testing.T) {
	err := &CompilationError{
		PolicyName: "my-policy",
		RuleName:   "my-rule",
		RuleIndex:  2,
		Field:      "trigger.eventCategory",
		Message:    "unknown layer",
	}
	got := err.Error()
	want := `compilation error in policy "my-policy", rule "my-rule" (index 2), field "trigger.eventCategory": unknown layer`
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestCompilationError_ErrorWithoutRuleName(t *testing.T) {
	err := &CompilationError{
		PolicyName: "my-policy",
		RuleName:   "",
		RuleIndex:  0,
		Field:      "spec",
		Message:    "invalid spec",
	}
	got := err.Error()
	want := `compilation error in policy "my-policy", field "spec": invalid spec`
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestCompilationError_UnwrapWithCause(t *testing.T) {
	cause := fmt.Errorf("underlying cause")
	err := &CompilationError{
		PolicyName: "my-policy",
		Message:    "wrapped error",
		Cause:      cause,
	}
	if err.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
	}
}

func TestCompilationError_UnwrapNilCause(t *testing.T) {
	err := &CompilationError{
		PolicyName: "my-policy",
		Message:    "no cause",
		Cause:      nil,
	}
	if err.Unwrap() != nil {
		t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
	}
}

// asCompilationError is a helper that checks if err is a *CompilationError.
func asCompilationError(err error, target **CompilationError) bool {
	if err == nil {
		return false
	}
	if ce, ok := err.(*CompilationError); ok {
		*target = ce
		return true
	}
	return false
}
