package quarantine

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

type QuarantineSummary struct {
	Name             string `json:"name"                       yaml:"name"`
	Namespace        string `json:"namespace"                  yaml:"namespace"`
	TargetPod        string `json:"targetPod"                  yaml:"targetPod"`
	TargetNamespace  string `json:"targetNamespace"            yaml:"targetNamespace"`
	ContainmentLevel string `json:"containmentLevel"           yaml:"containmentLevel"`
	Reason           string `json:"reason,omitempty"           yaml:"reason,omitempty"`
	Contained        string `json:"contained,omitempty"        yaml:"contained,omitempty"`
	Released         string `json:"released,omitempty"         yaml:"released,omitempty"`
	Age              string `json:"age,omitempty"              yaml:"age,omitempty"`
}

type QuarantineListResponse struct {
	Items []QuarantineSummary `json:"items" yaml:"items"`
}

func newListCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List AgentQuarantine resources",
		Example: `  panoptium quarantine list
  panoptium quarantine list -A -o table
  panoptium quarantine list -n production -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			built, err := factory()
			if err != nil {
				return err
			}
			resp, err := listQuarantines(cmd.Context(), built)
			if err != nil {
				return err
			}
			return writeListResponse(cmd.OutOrStdout(), format, resp)
		},
	}
	return cmd
}

func listQuarantines(ctx context.Context, built *k8s.Built) (*QuarantineListResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	resp := &QuarantineListResponse{}
	opts := []client.ListOption{client.Limit(500)}
	if !built.AllNamespaces && built.Namespace != "" {
		opts = append(opts, client.InNamespace(built.Namespace))
	}
	for {
		var list v1alpha1.AgentQuarantineList
		if err := built.Client.List(ctx, &list, opts...); err != nil {
			if meta.IsNoMatchError(err) {
				return nil, fmt.Errorf("%w: %v", k8s.ErrCRDNotFound, err)
			}
			return nil, fmt.Errorf("list AgentQuarantine: %w", err)
		}
		for i := range list.Items {
			resp.Items = append(resp.Items, summarize(&list.Items[i]))
		}
		if list.Continue == "" {
			break
		}
		opts = []client.ListOption{client.Limit(500), client.Continue(list.Continue)}
		if !built.AllNamespaces && built.Namespace != "" {
			opts = append(opts, client.InNamespace(built.Namespace))
		}
	}
	sort.SliceStable(resp.Items, func(i, j int) bool {
		a, b := resp.Items[i], resp.Items[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return resp, nil
}

func summarize(q *v1alpha1.AgentQuarantine) QuarantineSummary {
	s := QuarantineSummary{
		Name:             q.Name,
		Namespace:        q.Namespace,
		TargetPod:        q.Spec.TargetPod,
		TargetNamespace:  q.Spec.TargetNamespace,
		ContainmentLevel: string(q.Spec.ContainmentLevel),
		Reason:           q.Spec.Reason,
		Age:              relativeAge(q.CreationTimestamp.Time),
	}
	if q.Status.ContainedAt != nil {
		s.Contained = q.Status.ContainedAt.Format(time.RFC3339)
	}
	if q.Status.ReleasedAt != nil {
		s.Released = q.Status.ReleasedAt.Format(time.RFC3339)
	}
	return s
}

func writeListResponse(w io.Writer, format output.Format, resp *QuarantineListResponse) error {
	switch format {
	case output.FormatJSON:
		return output.WriteJSON(w, resp)
	case output.FormatYAML:
		return output.WriteYAML(w, resp)
	case output.FormatTable:
		return writeListTable(w, resp)
	case output.FormatHuman:
		fallthrough
	default:
		return writeListHuman(w, resp)
	}
}

func writeListTable(w io.Writer, resp *QuarantineListResponse) error {
	tbl := &output.Table{
		Headers: []string{"NAMESPACE", "NAME", "POD", "LEVEL", "STATE", "AGE"},
	}
	for _, q := range resp.Items {
		state := "contained"
		if q.Released != "" {
			state = "released"
		}
		tbl.Rows = append(tbl.Rows, []string{
			q.Namespace, q.Name, q.TargetPod, q.ContainmentLevel, state, q.Age,
		})
	}
	return output.WriteTable(w, tbl)
}

func writeListHuman(w io.Writer, resp *QuarantineListResponse) error {
	if len(resp.Items) == 0 {
		_, err := fmt.Fprintln(w, "no quarantines found")
		return err
	}
	for _, q := range resp.Items {
		state := "contained"
		if q.Released != "" {
			state = "released"
		}
		if _, err := fmt.Fprintf(w,
			"%s/%s  pod=%s/%s  level=%s  state=%s  age=%s\n",
			q.Namespace, q.Name, q.TargetNamespace, q.TargetPod,
			q.ContainmentLevel, state, q.Age); err != nil {
			return err
		}
	}
	return nil
}

func relativeAge(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	default:
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
}
