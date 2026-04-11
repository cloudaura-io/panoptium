package risk

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

type RiskReport struct {
	Available bool        `json:"available" yaml:"available"`
	Reason    string      `json:"reason,omitempty" yaml:"reason,omitempty"`
	Entries   []RiskEntry `json:"entries,omitempty" yaml:"entries,omitempty"`
}

type RiskEntry struct {
	Namespace string  `json:"namespace" yaml:"namespace"`
	AgentName string  `json:"agentName" yaml:"agentName"`
	Score     float64 `json:"score"     yaml:"score"`
	Level     string  `json:"level,omitempty" yaml:"level,omitempty"`
}

func newShowCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	var (
		agent     string
		namespace string
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show accumulated risk scores per agent",
		Long: `show renders the current risk state for one or all agents.

The risk scoring subsystem is introduced by the graduated-escalation
track (#10) and is not yet wired into the operator. Until that lands,
this command returns an explicit "risk scoring not yet available on
this operator version" response so callers can detect the gap in
both human and machine-parseable output.

When #10 lands, this command will switch to reading risk state from
the operator without requiring a CLI change: only the inner fetch
layer will grow a real implementation.`,
		Example: `  panoptium risk show
  panoptium risk show --agent my-agent -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			if _, buildErr := factory(); buildErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: cluster not reachable (%v); reporting CLI-only view\n", buildErr)
			}
			report := fetchRisk(agent, namespace)
			return writeReport(cmd.OutOrStdout(), format, report)
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "show risk for a specific agent name")
	cmd.Flags().StringVar(&namespace, "risk-namespace", "", "filter by namespace (default: current)")
	return cmd
}

func fetchRisk(agent, namespace string) *RiskReport {
	_ = agent
	_ = namespace
	return &RiskReport{
		Available: false,
		Reason:    "risk scoring not yet available on this operator version (waiting on #10 graduated escalation)",
	}
}

func writeReport(w io.Writer, format output.Format, r *RiskReport) error {
	switch format {
	case output.FormatJSON:
		return output.WriteJSON(w, r)
	case output.FormatYAML:
		return output.WriteYAML(w, r)
	case output.FormatTable:
		if !r.Available {
			tbl := &output.Table{
				Headers: []string{"STATUS", "REASON"},
				Rows:    [][]string{{"unavailable", r.Reason}},
			}
			return output.WriteTable(w, tbl)
		}
		tbl := &output.Table{Headers: []string{"NAMESPACE", "AGENT", "SCORE", "LEVEL"}}
		for _, e := range r.Entries {
			tbl.Rows = append(tbl.Rows, []string{e.Namespace, e.AgentName, fmt.Sprintf("%.2f", e.Score), e.Level})
		}
		return output.WriteTable(w, tbl)
	case output.FormatHuman:
		fallthrough
	default:
		if !r.Available {
			_, err := fmt.Fprintf(w, "risk scoring unavailable: %s\n", r.Reason)
			return err
		}
		for _, e := range r.Entries {
			if _, err := fmt.Fprintf(w, "%s/%s score=%.2f level=%s\n", e.Namespace, e.AgentName, e.Score, e.Level); err != nil {
				return err
			}
		}
		return nil
	}
}
