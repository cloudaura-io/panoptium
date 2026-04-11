package signature

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kyaml "sigs.k8s.io/yaml"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/clierr"
	"github.com/panoptium/panoptium/internal/cli/fileload"
	"github.com/panoptium/panoptium/internal/cli/output"
	pkgthreat "github.com/panoptium/panoptium/pkg/threat"
)

const kindThreatSignature = "ThreatSignature"

type Diagnostic struct {
	Severity string `json:"severity"       yaml:"severity"`
	Field    string `json:"field,omitempty" yaml:"field,omitempty"`
	Message  string `json:"message"        yaml:"message"`
}

type ResultItem struct {
	Source      string       `json:"source"               yaml:"source"`
	DocIndex    int          `json:"docIndex"             yaml:"docIndex"`
	Line        int          `json:"line,omitempty"       yaml:"line,omitempty"`
	Kind        string       `json:"kind,omitempty"       yaml:"kind,omitempty"`
	Name        string       `json:"name,omitempty"       yaml:"name,omitempty"`
	Status      string       `json:"status"               yaml:"status"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty" yaml:"diagnostics,omitempty"`
}

type Summary struct {
	Total   int `json:"total"   yaml:"total"`
	OK      int `json:"ok"      yaml:"ok"`
	Errors  int `json:"errors"  yaml:"errors"`
	Skipped int `json:"skipped" yaml:"skipped"`
}

type Report struct {
	Results []ResultItem `json:"results" yaml:"results"`
	Summary Summary      `json:"summary" yaml:"summary"`
}

const (
	SeverityError   = "error"
	SeverityWarning = "warning"
	StatusOK        = "ok"
	StatusError     = "error"
	StatusSkipped   = "skipped"
)

func newValidateCommand(getFormat func() string) *cobra.Command {
	var files []string
	cmd := &cobra.Command{
		Use:   "validate [-f <file>...]",
		Short: "Validate ThreatSignature YAML offline",
		Long: `Validate one or more YAML files containing ThreatSignature
resources by running each one through the same compiled signature
registry the operator uses at runtime.

No cluster is contacted. Any file, directory (recursively scanned for
*.yaml/*.yml), or "-" (stdin) is accepted.`,
		Example: `  panoptium signature validate -f signature.yaml
  panoptium signature validate -f examples/threat-signatures/
  cat sig.yaml | panoptium signature validate -f -
  panoptium signature validate -f examples/threat-signatures/ -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			docs, err := fileload.LoadPaths(files, cmd.InOrStdin())
			if err != nil {
				return err
			}
			report := validateDocuments(docs)
			if err := WriteReport(cmd.OutOrStdout(), format, &report); err != nil {
				return err
			}
			if report.Summary.Errors > 0 {
				return &clierr.ExitError{
					Code:    1,
					Message: fmt.Sprintf("signature validation failed: %d error(s) across %d document(s)", report.Summary.Errors, report.Summary.Total),
				}
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&files, "file", "f", nil, "files, directories, or '-' for stdin")
	return cmd
}

func validateDocuments(docs []fileload.Document) Report {
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

		if tm.Kind != kindThreatSignature {
			item.Status = StatusSkipped
			item.Diagnostics = append(item.Diagnostics, Diagnostic{
				Severity: SeverityWarning,
				Message:  "skipped: not a ThreatSignature (kind=" + tm.Kind + ")",
			})
			report.Results = append(report.Results, item)
			continue
		}

		var sig v1alpha1.ThreatSignature
		if err := kyaml.Unmarshal(d.Body, &sig); err != nil {
			item.Status = StatusError
			item.Diagnostics = append(item.Diagnostics, Diagnostic{
				Severity: SeverityError,
				Message:  "unmarshal ThreatSignature: " + err.Error(),
			})
			report.Results = append(report.Results, item)
			continue
		}
		item.Name = sig.Name

		def := pkgthreat.SignatureDefinitionFromCRD(&sig)
		registry := pkgthreat.NewCompiledSignatureRegistry()
		if err := registry.AddSignature(def); err != nil {
			item.Status = StatusError
			item.Diagnostics = append(item.Diagnostics, Diagnostic{
				Severity: SeverityError,
				Message:  err.Error(),
			})
		}
		report.Results = append(report.Results, item)
	}
	recomputeSummary(&report)
	return report
}

func recomputeSummary(r *Report) {
	r.Summary = Summary{Total: len(r.Results)}
	for _, item := range r.Results {
		switch item.Status {
		case StatusOK:
			r.Summary.OK++
		case StatusError:
			r.Summary.Errors++
		case StatusSkipped:
			r.Summary.Skipped++
		}
	}
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
		Headers: []string{"LOCATION", "NAME", "STATUS", "DIAGNOSTICS"},
	}
	for _, item := range r.Results {
		loc := item.Source
		if item.Line > 0 {
			loc = fmt.Sprintf("%s:%d", item.Source, item.Line)
		}
		tbl.Rows = append(tbl.Rows, []string{
			loc, item.Name, item.Status, fmt.Sprintf("%d", len(item.Diagnostics)),
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
		case StatusSkipped:
			mark = "[skip]"
		}
		name := item.Name
		if name == "" {
			name = "<unknown>"
		}
		loc := item.Source
		if item.Line > 0 {
			loc = fmt.Sprintf("%s:%d", item.Source, item.Line)
		}
		if _, err := fmt.Fprintf(w, "%s %s (ThreatSignature/%s)\n", mark, loc, name); err != nil {
			return err
		}
		for _, d := range item.Diagnostics {
			field := ""
			if d.Field != "" {
				field = " " + d.Field + ":"
			}
			if _, err := fmt.Fprintf(w, "    %s:%s %s\n", d.Severity, field, d.Message); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(w,
		"\nTotal: %d | ok: %d | errors: %d | skipped: %d\n",
		r.Summary.Total, r.Summary.OK, r.Summary.Errors, r.Summary.Skipped)
	return err
}
