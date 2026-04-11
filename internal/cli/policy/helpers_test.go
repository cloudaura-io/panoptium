package policy

import (
	"bytes"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
)

const humanFmt = "human"

func TestRelativeAgeBuckets(t *testing.T) {
	cases := map[string]time.Duration{
		"d": 48 * time.Hour,
		"h": 2 * time.Hour,
		"m": 30 * time.Minute,
		"s": 15 * time.Second,
	}
	for suffix, d := range cases {
		got := relativeAge(time.Now().Add(-d))
		if !strings.HasSuffix(got, suffix) {
			t.Errorf("relativeAge(-%v) = %q; want *%s", d, got, suffix)
		}
	}
	if got := relativeAge(time.Time{}); got != "" {
		t.Errorf("zero time should render empty, got %q", got)
	}
}

func TestReadyConditionExtractsReadyOnly(t *testing.T) {
	conds := []metav1.Condition{
		{Type: "Error", Status: "False"},
		{Type: "Ready", Status: "True"},
	}
	if got := readyCondition(conds); got != "True" {
		t.Errorf("readyCondition=%q want True", got)
	}
	if got := readyCondition(nil); got != "" {
		t.Errorf("nil conditions should return empty, got %q", got)
	}
}

func TestWriteListHumanEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := writeListHuman(&buf, &PolicyListResponse{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no policies") {
		t.Errorf("expected 'no policies' message:\n%s", buf.String())
	}
}

func TestWriteListHumanClusterPolicyUsesMarker(t *testing.T) {
	resp := &PolicyListResponse{
		Items: []PolicySummary{
			{Kind: "AgentClusterPolicy", Name: "cluster-wide", Priority: 10, EnforcementMode: "enforcing", RuleCount: 1, Age: "1h"},
		},
	}
	var buf bytes.Buffer
	if err := writeListHuman(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<cluster>") {
		t.Errorf("expected <cluster> marker for cluster-scoped:\n%s", buf.String())
	}
}

func TestNewCommandHasExpectedSubcommands(t *testing.T) {
	cmd := NewCommand(func() string { return humanFmt }, func() (*k8s.Built, error) { return nil, nil })
	want := map[string]bool{
		"validate": false,
		"lint":     false,
		"list":     false,
		"show":     false,
	}
	for _, sub := range cmd.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("policy command missing subcommand %q", name)
		}
	}
}

func TestRunClusterPolicyLintRules(t *testing.T) {
	spec := &v1alpha1.AgentClusterPolicySpec{
		TargetSelector:  metav1.LabelSelector{},
		EnforcementMode: v1alpha1.EnforcementModeAudit,
		Priority:        999,
		Rules: []v1alpha1.PolicyRule{
			{
				Name: "r",
				Action: v1alpha1.Action{
					Type: v1alpha1.ActionTypeDeny,
				},
			},
		},
	}
	item := &ResultItem{Status: StatusOK}
	runClusterPolicyLintRules(spec, item)
	rules := map[string]bool{}
	for _, d := range item.Diagnostics {
		rules[d.Rule] = true
	}
	for _, want := range []string{
		LintRuleBroadTargetSelector,
		LintRuleEnforcementAudit,
		LintRuleHighPriority,
		LintRuleNoPredicates,
		LintRuleSeverityMissing,
		LintRuleDenyNoMessage,
	} {
		if !rules[want] {
			t.Errorf("missing expected lint rule %q; got %v", want, rules)
		}
	}
}
