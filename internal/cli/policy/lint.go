package policy

import (
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kyaml "sigs.k8s.io/yaml"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/clierr"
	"github.com/panoptium/panoptium/internal/cli/fileload"
	"github.com/panoptium/panoptium/internal/cli/output"
	pkgpolicy "github.com/panoptium/panoptium/pkg/policy"
)

const (
	LintRuleBroadTargetSelector = "broad-target-selector"
	LintRuleNoPredicates        = "rule-without-predicates"
	LintRuleDenyNoMessage       = "deny-without-message"
	LintRuleSeverityMissing     = "severity-missing"
	LintRuleHighPriority        = "priority-over-900"
	LintRuleEnforcementAudit    = "enforcement-audit-mode"
)

func newLintCommand(getFormat func() string) *cobra.Command {
	var files []string
	var strict bool
	cmd := &cobra.Command{
		Use:   "lint [-f <file>...]",
		Short: "Validate policies and surface warnings about common mistakes",
		Long: `lint is a superset of validate: it runs the compiler and then emits
warnings for broad selectors, rules without predicates, deny actions
without a user-facing message, missing severity, and other patterns
that tend to misbehave in production.

With --strict, any warning causes a non-zero exit.`,
		Example: `  panoptium policy lint -f examples/policies/
  panoptium policy lint -f policy.yaml --strict -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			docs, err := fileload.LoadPaths(files, cmd.InOrStdin())
			if err != nil {
				return err
			}
			report := lintDocuments(docs, pkgpolicy.NewPolicyCompiler())
			if err := WriteReport(cmd.OutOrStdout(), format, &report); err != nil {
				return err
			}
			failCount := report.Summary.Errors
			if strict {
				failCount += report.Summary.Warnings
			}
			if failCount > 0 {
				return &clierr.ExitError{
					Code: 1,
					Message: fmt.Sprintf(
						"lint failed: %d error(s), %d warning(s)%s",
						report.Summary.Errors, report.Summary.Warnings,
						strictMsg(strict)),
				}
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&files, "file", "f", nil, "files, directories, or '-' for stdin")
	cmd.Flags().BoolVar(&strict, "strict", false, "treat warnings as errors (non-zero exit on any warning)")
	return cmd
}

func strictMsg(strict bool) string {
	if strict {
		return " (--strict: warnings escalated)"
	}
	return ""
}

func lintDocuments(docs []fileload.Document, compiler *pkgpolicy.PolicyCompiler) Report {
	report := Report{}
	for _, d := range docs {
		item := ResultItem{
			Source:   d.Source,
			DocIndex: d.DocIndex,
			Line:     d.Line,
			Status:   StatusOK,
		}

		var tm metav1.TypeMeta
		if err := kyaml.Unmarshal(d.Body, &tm); err != nil {
			item.Status = StatusError
			item.Diagnostics = append(item.Diagnostics, Diagnostic{
				Severity: SeverityError,
				Message:  "invalid YAML: " + err.Error(),
			})
			report.Results = append(report.Results, item)
			continue
		}
		item.Kind = tm.Kind

		switch tm.Kind {
		case kindAgentPolicy:
			var p v1alpha1.AgentPolicy
			if err := kyaml.Unmarshal(d.Body, &p); err != nil {
				item.Status = StatusError
				item.Diagnostics = append(item.Diagnostics, Diagnostic{
					Severity: SeverityError,
					Message:  "unmarshal AgentPolicy: " + err.Error(),
				})
				break
			}
			item.Name = p.Name
			item.Namespace = p.Namespace
			if _, err := compiler.Compile(&p); err != nil {
				recordCompileError(&item, err)
			}
			runPolicyLintRules(&p.Spec, &item)
		case kindAgentClusterPolicy:
			var p v1alpha1.AgentClusterPolicy
			if err := kyaml.Unmarshal(d.Body, &p); err != nil {
				item.Status = StatusError
				item.Diagnostics = append(item.Diagnostics, Diagnostic{
					Severity: SeverityError,
					Message:  "unmarshal AgentClusterPolicy: " + err.Error(),
				})
				break
			}
			item.Name = p.Name
			if _, err := compiler.CompileCluster(&p); err != nil {
				recordCompileError(&item, err)
			}
			runClusterPolicyLintRules(&p.Spec, &item)
		default:
			item.Status = StatusSkipped
			item.Diagnostics = append(item.Diagnostics, Diagnostic{
				Severity: SeverityWarning,
				Message:  "skipped: not a policy resource (kind=" + tm.Kind + ")",
			})
		}
		report.Results = append(report.Results, item)
	}
	report.recompute()
	return report
}

func runPolicyLintRules(spec *v1alpha1.AgentPolicySpec, item *ResultItem) {
	if isEmptyLabelSelector(&spec.TargetSelector) {
		warn(item, LintRuleBroadTargetSelector, "spec.targetSelector",
			"target selector is empty; this policy will match every pod in the namespace")
	}
	if spec.EnforcementMode == v1alpha1.EnforcementModeAudit {
		warn(item, LintRuleEnforcementAudit, "spec.enforcementMode",
			"policy is in audit mode; matching events will be logged but not blocked")
	}
	if spec.Priority > 900 {
		warn(item, LintRuleHighPriority, "spec.priority",
			fmt.Sprintf("priority %d is above 900; values in that range are conventionally reserved for cluster-wide defaults", spec.Priority))
	}
	for i, rule := range spec.Rules {
		ruleField := fmt.Sprintf("spec.rules[%d]", i)
		checkRule(item, ruleField, rule)
	}
}

func runClusterPolicyLintRules(spec *v1alpha1.AgentClusterPolicySpec, item *ResultItem) {
	if isEmptyLabelSelector(&spec.TargetSelector) {
		warn(item, LintRuleBroadTargetSelector, "spec.targetSelector",
			"target selector is empty; this cluster policy will match every pod in every namespace")
	}
	if spec.EnforcementMode == v1alpha1.EnforcementModeAudit {
		warn(item, LintRuleEnforcementAudit, "spec.enforcementMode",
			"cluster policy is in audit mode; matching events will be logged but not blocked")
	}
	if spec.Priority > 900 {
		warn(item, LintRuleHighPriority, "spec.priority",
			fmt.Sprintf("priority %d is above 900; values in that range conflict with conventional cluster defaults", spec.Priority))
	}
	for i, rule := range spec.Rules {
		ruleField := fmt.Sprintf("spec.rules[%d]", i)
		checkRule(item, ruleField, rule)
	}
}

func checkRule(item *ResultItem, field string, rule v1alpha1.PolicyRule) {
	if len(rule.Predicates) == 0 && rule.ThreatSignatures == nil {
		warn(item, LintRuleNoPredicates, field+".predicates",
			"rule has no predicates or threat signature matchers; the action will fire on every event matching the trigger")
	}
	if rule.Severity == "" {
		warn(item, LintRuleSeverityMissing, field+".severity",
			"rule is missing a severity; escalation heuristics rely on severity to accumulate risk")
	}
	if rule.Action.Type == v1alpha1.ActionTypeDeny {
		if rule.Action.Parameters == nil || rule.Action.Parameters["message"] == "" {
			warn(item, LintRuleDenyNoMessage, field+".action.parameters.message",
				"deny action has no message; callers receiving the deny won't know why")
		}
	}
}

func warn(item *ResultItem, rule, field, msg string) {
	item.Diagnostics = append(item.Diagnostics, Diagnostic{
		Severity: SeverityWarning,
		Rule:     rule,
		Field:    field,
		Message:  msg,
	})
	if item.Status != StatusError {
		item.Status = StatusWarning
	}
}

func isEmptyLabelSelector(sel *metav1.LabelSelector) bool {
	if sel == nil {
		return true
	}
	return len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0
}
