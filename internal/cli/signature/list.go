package signature

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

type SignatureSummary struct {
	Name        string   `json:"name"                   yaml:"name"`
	Category    string   `json:"category"               yaml:"category"`
	Severity    string   `json:"severity"               yaml:"severity"`
	Protocols   []string `json:"protocols,omitempty"    yaml:"protocols,omitempty"`
	Patterns    int      `json:"patterns"               yaml:"patterns"`
	Ready       string   `json:"ready,omitempty"        yaml:"ready,omitempty"`
	Age         string   `json:"age,omitempty"          yaml:"age,omitempty"`
	Description string   `json:"description,omitempty"  yaml:"description,omitempty"`
}

type SignatureListResponse struct {
	Items []SignatureSummary `json:"items" yaml:"items"`
}

func newListCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List ThreatSignature resources in a cluster",
		Example: `  panoptium signature list
  panoptium signature list -o table
  panoptium signature list -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			built, err := factory()
			if err != nil {
				return err
			}
			resp, err := listSignatures(cmd.Context(), built)
			if err != nil {
				return err
			}
			return writeListResponse(cmd.OutOrStdout(), format, resp)
		},
	}
	return cmd
}

func listSignatures(ctx context.Context, built *k8s.Built) (*SignatureListResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	resp := &SignatureListResponse{}
	opts := []client.ListOption{client.Limit(500)}
	for {
		var list v1alpha1.ThreatSignatureList
		if err := built.Client.List(ctx, &list, opts...); err != nil {
			if meta.IsNoMatchError(err) {
				return nil, fmt.Errorf("%w: %v", k8s.ErrCRDNotFound, err)
			}
			return nil, fmt.Errorf("list ThreatSignature: %w", err)
		}
		for i := range list.Items {
			s := &list.Items[i]
			ready := ""
			for _, c := range s.Status.Conditions {
				if c.Type == "Ready" {
					ready = string(c.Status)
					break
				}
			}
			resp.Items = append(resp.Items, SignatureSummary{
				Name:        s.Name,
				Category:    s.Spec.Category,
				Severity:    string(s.Spec.Severity),
				Protocols:   s.Spec.Protocols,
				Patterns:    len(s.Spec.Detection.Patterns),
				Ready:       ready,
				Age:         relativeAge(s.CreationTimestamp.Time),
				Description: s.Spec.Description,
			})
		}
		if list.Continue == "" {
			break
		}
		opts = []client.ListOption{client.Limit(500), client.Continue(list.Continue)}
	}
	sort.SliceStable(resp.Items, func(i, j int) bool {
		return resp.Items[i].Name < resp.Items[j].Name
	})
	return resp, nil
}

func writeListResponse(w io.Writer, format output.Format, resp *SignatureListResponse) error {
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

func writeListTable(w io.Writer, resp *SignatureListResponse) error {
	tbl := &output.Table{
		Headers: []string{"NAME", "CATEGORY", "SEVERITY", "PROTOCOLS", "PATTERNS", "READY", "AGE"},
	}
	for _, s := range resp.Items {
		tbl.Rows = append(tbl.Rows, []string{
			s.Name, s.Category, s.Severity,
			strings.Join(s.Protocols, ","),
			fmt.Sprintf("%d", s.Patterns),
			s.Ready, s.Age,
		})
	}
	return output.WriteTable(w, tbl)
}

func writeListHuman(w io.Writer, resp *SignatureListResponse) error {
	if len(resp.Items) == 0 {
		_, err := fmt.Fprintln(w, "no threat signatures found")
		return err
	}
	for _, s := range resp.Items {
		ready := s.Ready
		if ready == "" {
			ready = "?"
		}
		if _, err := fmt.Fprintf(w,
			"%s  [%s, severity=%s, patterns=%d, ready=%s, age=%s]\n",
			s.Name, s.Category, s.Severity, s.Patterns, ready, s.Age); err != nil {
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
