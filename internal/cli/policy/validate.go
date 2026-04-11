package policy

import (
	"errors"
	"fmt"
	"io"

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
	kindAgentPolicy        = "AgentPolicy"
	kindAgentClusterPolicy = "AgentClusterPolicy"
)

func newValidateCommand(getFormat func() string) *cobra.Command {
	var files []string
	cmd := &cobra.Command{
		Use:   "validate [-f <file>...]",
		Short: "Validate AgentPolicy and AgentClusterPolicy YAML offline",
		Long: `Validate one or more YAML files containing AgentPolicy or
AgentClusterPolicy resources using the same compiler the operator runs
at admission time.

No cluster is contacted. Any file, directory (recursively scanned for
*.yaml/*.yml), or "-" (stdin) is accepted.

Exits 0 if every document compiles cleanly, 1 if any document reports
an error.`,
		Example: `  # validate one file
  panoptium policy validate -f policy.yaml

  # validate every YAML under a directory
  panoptium policy validate -f examples/policies/

  # validate from stdin
  cat policy.yaml | panoptium policy validate -f -

  # machine-parseable output
  panoptium policy validate -f policy.yaml -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			docs, err := fileload.LoadPaths(files, cmd.InOrStdin())
			if err != nil {
				return err
			}
			report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
			if err := WriteReport(cmd.OutOrStdout(), format, &report); err != nil {
				return err
			}
			if report.Summary.Errors > 0 {
				return &clierr.ExitError{Code: 1, Message: fmt.Sprintf("validation failed: %d error(s) across %d document(s)", report.Summary.Errors, report.Summary.Total)}
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&files, "file", "f", nil, "files, directories, or '-' for stdin")
	return cmd
}

func validateDocuments(docs []fileload.Document, compiler *pkgpolicy.PolicyCompiler) Report {
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
				Field:    "",
				Message:  "invalid YAML: " + err.Error(),
			})
			report.Results = append(report.Results, item)
			continue
		}
		item.Kind = tm.Kind

		switch tm.Kind {
		case kindAgentPolicy:
			validatePolicyDoc(d, &item, compiler)
		case kindAgentClusterPolicy:
			validateClusterPolicyDoc(d, &item, compiler)
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

func validatePolicyDoc(d fileload.Document, item *ResultItem, compiler *pkgpolicy.PolicyCompiler) {
	var p v1alpha1.AgentPolicy
	if err := kyaml.Unmarshal(d.Body, &p); err != nil {
		item.Status = StatusError
		item.Diagnostics = append(item.Diagnostics, Diagnostic{
			Severity: SeverityError,
			Field:    "",
			Message:  "unmarshal AgentPolicy: " + err.Error(),
		})
		return
	}
	item.Name = p.Name
	item.Namespace = p.Namespace
	if _, err := compiler.Compile(&p); err != nil {
		recordCompileError(item, err)
	}
}

func validateClusterPolicyDoc(d fileload.Document, item *ResultItem, compiler *pkgpolicy.PolicyCompiler) {
	var p v1alpha1.AgentClusterPolicy
	if err := kyaml.Unmarshal(d.Body, &p); err != nil {
		item.Status = StatusError
		item.Diagnostics = append(item.Diagnostics, Diagnostic{
			Severity: SeverityError,
			Field:    "",
			Message:  "unmarshal AgentClusterPolicy: " + err.Error(),
		})
		return
	}
	item.Name = p.Name
	if _, err := compiler.CompileCluster(&p); err != nil {
		recordCompileError(item, err)
	}
}

func recordCompileError(item *ResultItem, err error) {
	item.Status = StatusError
	var ce *pkgpolicy.CompilationError
	if errors.As(err, &ce) {
		item.Diagnostics = append(item.Diagnostics, Diagnostic{
			Severity: SeverityError,
			Field:    ce.Field,
			Message:  ce.Message,
		})
		return
	}
	item.Diagnostics = append(item.Diagnostics, Diagnostic{
		Severity: SeverityError,
		Message:  err.Error(),
	})
}

func WriteReport(w io.Writer, format output.Format, r *Report) error {
	switch format {
	case output.FormatJSON:
		return output.WriteJSON(w, r)
	case output.FormatYAML:
		return output.WriteYAML(w, r)
	case output.FormatTable:
		tbl := reportToTable(r)
		return output.WriteTable(w, tbl)
	case output.FormatHuman:
		fallthrough
	default:
		return writeHumanReport(w, r)
	}
}

func reportToTable(r *Report) *output.Table {
	tbl := &output.Table{
		Headers: []string{"LOCATION", "KIND", "NAME", "STATUS", "DIAGNOSTICS"},
	}
	for _, item := range r.Results {
		diag := fmt.Sprintf("%d", len(item.Diagnostics))
		tbl.Rows = append(tbl.Rows, []string{
			item.Location(),
			item.Kind,
			item.Name,
			item.Status,
			diag,
		})
	}
	return tbl
}

func writeHumanReport(w io.Writer, r *Report) error {
	for _, item := range r.Results {
		mark := "[ok]  "
		switch item.Status {
		case StatusError:
			mark = "[err] "
		case StatusWarning:
			mark = "[warn]"
		case StatusSkipped:
			mark = "[skip]"
		}
		kind := item.Kind
		if kind == "" {
			kind = "?"
		}
		name := item.Name
		if name == "" {
			name = "<unknown>"
		}
		if _, err := fmt.Fprintf(w, "%s %s (%s/%s)\n", mark, item.Location(), kind, name); err != nil {
			return err
		}
		for _, d := range item.Diagnostics {
			field := d.Field
			if field != "" {
				field = " " + field + ":"
			}
			rule := ""
			if d.Rule != "" {
				rule = "[" + d.Rule + "] "
			}
			if _, err := fmt.Fprintf(w, "    %s:%s %s%s\n", d.Severity, field, rule, d.Message); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(w,
		"\nTotal: %d | ok: %d | errors: %d | warnings: %d | skipped: %d\n",
		r.Summary.Total, r.Summary.OK, r.Summary.Errors, r.Summary.Warnings, r.Summary.Skipped)
	return err
}
