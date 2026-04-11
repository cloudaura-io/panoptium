package policy

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

type PolicySummary struct {
	Kind            string `json:"kind"                       yaml:"kind"`
	Name            string `json:"name"                       yaml:"name"`
	Namespace       string `json:"namespace,omitempty"        yaml:"namespace,omitempty"`
	Priority        int32  `json:"priority"                   yaml:"priority"`
	EnforcementMode string `json:"enforcementMode"            yaml:"enforcementMode"`
	RuleCount       int    `json:"ruleCount"                  yaml:"ruleCount"`
	Ready           string `json:"ready,omitempty"            yaml:"ready,omitempty"`
	Age             string `json:"age,omitempty"              yaml:"age,omitempty"`
}

type PolicyListResponse struct {
	Items []PolicySummary `json:"items" yaml:"items"`
}

func newListCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List AgentPolicy and AgentClusterPolicy resources in a cluster",
		Long: `list reads AgentPolicy and AgentClusterPolicy resources from the target
cluster using the caller's kubeconfig. Namespaced policies respect -n and
-A; cluster policies are always included.`,
		Example: `  panoptium policy list
  panoptium policy list -n kube-system
  panoptium policy list -A -o table
  panoptium policy list -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			built, err := factory()
			if err != nil {
				return err
			}
			resp, err := listPolicies(cmd.Context(), built)
			if err != nil {
				return err
			}
			return writeListResponse(cmd.OutOrStdout(), format, resp)
		},
	}
	return cmd
}

func listPolicies(ctx context.Context, built *k8s.Built) (*PolicyListResponse, error) {
	resp := &PolicyListResponse{}
	if ctx == nil {
		ctx = context.Background()
	}

	var nsList v1alpha1.AgentPolicyList
	opts := []client.ListOption{}
	if !built.AllNamespaces && built.Namespace != "" {
		opts = append(opts, client.InNamespace(built.Namespace))
	}
	if err := built.Client.List(ctx, &nsList, opts...); err != nil {
		if meta.IsNoMatchError(err) {
			return nil, fmt.Errorf("%w: %v", k8s.ErrCRDNotFound, err)
		}
		return nil, fmt.Errorf("list AgentPolicy: %w", err)
	}
	for i := range nsList.Items {
		resp.Items = append(resp.Items, summaryFromPolicy(&nsList.Items[i]))
	}

	var cpList v1alpha1.AgentClusterPolicyList
	if err := built.Client.List(ctx, &cpList); err != nil {
		if meta.IsNoMatchError(err) {
			return nil, fmt.Errorf("%w: %v", k8s.ErrCRDNotFound, err)
		}
		return nil, fmt.Errorf("list AgentClusterPolicy: %w", err)
	}
	for i := range cpList.Items {
		resp.Items = append(resp.Items, summaryFromClusterPolicy(&cpList.Items[i]))
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

func summaryFromPolicy(p *v1alpha1.AgentPolicy) PolicySummary {
	return PolicySummary{
		Kind:            "AgentPolicy",
		Name:            p.Name,
		Namespace:       p.Namespace,
		Priority:        p.Spec.Priority,
		EnforcementMode: string(p.Spec.EnforcementMode),
		RuleCount:       len(p.Spec.Rules),
		Ready:           readyCondition(p.Status.Conditions),
		Age:             relativeAge(p.CreationTimestamp.Time),
	}
}

func summaryFromClusterPolicy(p *v1alpha1.AgentClusterPolicy) PolicySummary {
	return PolicySummary{
		Kind:            "AgentClusterPolicy",
		Name:            p.Name,
		Namespace:       "",
		Priority:        p.Spec.Priority,
		EnforcementMode: string(p.Spec.EnforcementMode),
		RuleCount:       len(p.Spec.Rules),
		Ready:           readyCondition(p.Status.Conditions),
		Age:             relativeAge(p.CreationTimestamp.Time),
	}
}

func readyCondition(conds []metav1.Condition) string {
	for _, c := range conds {
		if c.Type == "Ready" {
			return string(c.Status)
		}
	}
	return ""
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

func writeListResponse(w io.Writer, format output.Format, resp *PolicyListResponse) error {
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

func writeListTable(w io.Writer, resp *PolicyListResponse) error {
	tbl := &output.Table{
		Headers: []string{"NAMESPACE", "NAME", "KIND", "MODE", "PRIORITY", "RULES", "READY", "AGE"},
	}
	for _, p := range resp.Items {
		ns := p.Namespace
		if ns == "" {
			ns = "<cluster>"
		}
		tbl.Rows = append(tbl.Rows, []string{
			ns, p.Name, p.Kind, p.EnforcementMode, fmt.Sprintf("%d", p.Priority),
			fmt.Sprintf("%d", p.RuleCount), p.Ready, p.Age,
		})
	}
	return output.WriteTable(w, tbl)
}

func writeListHuman(w io.Writer, resp *PolicyListResponse) error {
	if len(resp.Items) == 0 {
		_, err := fmt.Fprintln(w, "no policies found")
		return err
	}
	for _, p := range resp.Items {
		ns := p.Namespace
		if ns == "" {
			ns = "<cluster>"
		}
		if _, err := fmt.Fprintf(w,
			"%s/%s  (%s, mode=%s, priority=%d, rules=%d, age=%s)\n",
			ns, p.Name, p.Kind, p.EnforcementMode, p.Priority, p.RuleCount, p.Age); err != nil {
			return err
		}
	}
	return nil
}
