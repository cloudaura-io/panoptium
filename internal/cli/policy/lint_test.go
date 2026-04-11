package policy

import (
	"bytes"
	"errors"
	"testing"

	"github.com/panoptium/panoptium/internal/cli/clierr"
	pkgpolicy "github.com/panoptium/panoptium/pkg/policy"
)

const lintyPolicyBroadSelector = `apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: broad
  namespace: default
spec:
  targetSelector: {}
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: r1
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'x'"
      action:
        type: deny
        parameters:
          message: "blocked"
      severity: HIGH
`

const lintyPolicyNoPredicatesAndNoMessage = `apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: nopred
  namespace: default
spec:
  targetSelector:
    matchLabels:
      app: agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: r1
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      action:
        type: deny
      severity: HIGH
`

const lintyPolicyAuditHighPriority = `apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: audit-high
  namespace: default
spec:
  targetSelector:
    matchLabels:
      app: agent
  enforcementMode: audit
  priority: 999
  rules:
    - name: r1
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'x'"
      action:
        type: alert
      severity: LOW
`

func diagRules(item ResultItem) []string {
	var out []string
	for _, d := range item.Diagnostics {
		if d.Rule != "" {
			out = append(out, d.Rule)
		}
	}
	return out
}

func contains(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

func TestLintFlagsBroadTargetSelector(t *testing.T) {
	docs := loadFixture(t, lintyPolicyBroadSelector)
	report := lintDocuments(docs, pkgpolicy.NewPolicyCompiler())
	rules := diagRules(report.Results[0])
	if !contains(rules, LintRuleBroadTargetSelector) {
		t.Errorf("expected %s warning, got %v", LintRuleBroadTargetSelector, rules)
	}
}

func TestLintFlagsNoPredicatesAndDenyNoMessage(t *testing.T) {
	docs := loadFixture(t, lintyPolicyNoPredicatesAndNoMessage)
	report := lintDocuments(docs, pkgpolicy.NewPolicyCompiler())
	rules := diagRules(report.Results[0])
	if !contains(rules, LintRuleNoPredicates) {
		t.Errorf("expected %s warning, got %v", LintRuleNoPredicates, rules)
	}
	if !contains(rules, LintRuleDenyNoMessage) {
		t.Errorf("expected %s warning, got %v", LintRuleDenyNoMessage, rules)
	}
}

func TestLintFlagsAuditAndHighPriority(t *testing.T) {
	docs := loadFixture(t, lintyPolicyAuditHighPriority)
	report := lintDocuments(docs, pkgpolicy.NewPolicyCompiler())
	rules := diagRules(report.Results[0])
	if !contains(rules, LintRuleEnforcementAudit) {
		t.Errorf("expected %s warning, got %v", LintRuleEnforcementAudit, rules)
	}
	if !contains(rules, LintRuleHighPriority) {
		t.Errorf("expected %s warning, got %v", LintRuleHighPriority, rules)
	}
}

func TestLintHasAtLeastThreeDistinctWarningClasses(t *testing.T) {
	inputs := []string{
		lintyPolicyBroadSelector,
		lintyPolicyNoPredicatesAndNoMessage,
		lintyPolicyAuditHighPriority,
	}
	seen := map[string]bool{}
	for _, in := range inputs {
		docs := loadFixture(t, in)
		report := lintDocuments(docs, pkgpolicy.NewPolicyCompiler())
		for _, item := range report.Results {
			for _, d := range item.Diagnostics {
				if d.Rule != "" {
					seen[d.Rule] = true
				}
			}
		}
	}
	if len(seen) < 3 {
		t.Errorf("expected ≥3 distinct lint rules, got %d: %v", len(seen), seen)
	}
}

func TestLintCommandStrictEscalatesWarnings(t *testing.T) {
	path := writeFile(t, lintyPolicyBroadSelector)
	cmd := newLintCommand(func() string { return "human" })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-f", path, "--strict"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected --strict to fail on warning, got nil")
	}
	var ee *clierr.ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Errorf("want *clierr.ExitError Code=1, got %T=%v", err, err)
	}
}

func TestLintCommandNonStrictPassesOnWarnings(t *testing.T) {
	path := writeFile(t, lintyPolicyBroadSelector)
	cmd := newLintCommand(func() string { return "human" })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-f", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected lint to pass without --strict, got %v", err)
	}
}
