package policy

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

var errNotFound = errors.New("not found")

func newShowCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	var clusterScoped bool
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show a single AgentPolicy or AgentClusterPolicy",
		Long: `show fetches a single policy by name and prints it in the requested
format. Uses -n for namespace (or the current kube-context default).
Pass --cluster to fetch an AgentClusterPolicy instead.

The yaml output is round-trippable: the result of -o yaml can be piped
directly into kubectl apply -f -.`,
		Example: `  panoptium policy show deny-shell
  panoptium policy show deny-shell -n default -o yaml
  panoptium policy show cluster-baseline --cluster
  panoptium policy show deny-shell -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			built, err := factory()
			if err != nil {
				return err
			}
			return showPolicy(cmd.Context(), cmd.OutOrStdout(), built, args[0], clusterScoped, format)
		},
	}
	cmd.Flags().BoolVar(&clusterScoped, "cluster", false, "fetch an AgentClusterPolicy instead of a namespaced AgentPolicy")
	return cmd
}

func showPolicy(ctx context.Context, w io.Writer, built *k8s.Built, name string, clusterScoped bool, format output.Format) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if format == output.FormatTable {
		return &output.FormatUnsupportedError{Command: "policy show", Format: format}
	}

	if clusterScoped {
		var obj v1alpha1.AgentClusterPolicy
		if err := built.Client.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
			return translateGetError(err, name)
		}
		return writeShowOutput(w, format, &obj)
	}
	ns := built.Namespace
	if ns == "" {
		ns = "default"
	}
	var obj v1alpha1.AgentPolicy
	if err := built.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &obj); err != nil {
		return translateGetError(err, name)
	}
	return writeShowOutput(w, format, &obj)
}

func translateGetError(err error, name string) error {
	if err == nil {
		return nil
	}
	if meta.IsNoMatchError(err) {
		return fmt.Errorf("%w: %v", k8s.ErrCRDNotFound, err)
	}
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: policy %q", errNotFound, name)
	}
	return err
}

func writeShowOutput(w io.Writer, format output.Format, obj interface{}) error {
	switch format {
	case output.FormatJSON:
		return output.WriteJSON(w, obj)
	case output.FormatYAML:
		return output.WriteYAML(w, obj)
	case output.FormatHuman:
		return writeHumanPolicy(w, obj)
	}
	return &output.FormatUnsupportedError{Command: "policy show", Format: format}
}

func writeHumanPolicy(w io.Writer, obj interface{}) error {
	var lines []string
	switch p := obj.(type) {
	case *v1alpha1.AgentPolicy:
		lines = append(lines,
			"Kind:              AgentPolicy",
			fmt.Sprintf("Name:              %s", p.Name),
			fmt.Sprintf("Namespace:         %s", p.Namespace),
			fmt.Sprintf("Priority:          %d", p.Spec.Priority),
			fmt.Sprintf("Enforcement Mode:  %s", p.Spec.EnforcementMode),
			fmt.Sprintf("Rules:             %d", len(p.Spec.Rules)),
			fmt.Sprintf("Ready:             %s", readyCondition(p.Status.Conditions)),
			fmt.Sprintf("Age:               %s", relativeAge(p.CreationTimestamp.Time)),
		)
		for i, rule := range p.Spec.Rules {
			lines = append(lines,
				"",
				fmt.Sprintf("Rule %d: %s", i, rule.Name),
				fmt.Sprintf("  Trigger:   %s / %s", rule.Trigger.EventCategory, rule.Trigger.EventSubcategory),
				fmt.Sprintf("  Action:    %s", rule.Action.Type),
				fmt.Sprintf("  Severity:  %s", rule.Severity),
				fmt.Sprintf("  Predicates: %d", len(rule.Predicates)),
			)
		}
	case *v1alpha1.AgentClusterPolicy:
		lines = append(lines,
			"Kind:              AgentClusterPolicy",
			fmt.Sprintf("Name:              %s", p.Name),
			fmt.Sprintf("Priority:          %d", p.Spec.Priority),
			fmt.Sprintf("Enforcement Mode:  %s", p.Spec.EnforcementMode),
			fmt.Sprintf("Rules:             %d", len(p.Spec.Rules)),
			fmt.Sprintf("Ready:             %s", readyCondition(p.Status.Conditions)),
			fmt.Sprintf("Age:               %s", relativeAge(p.CreationTimestamp.Time)),
		)
	default:
		return fmt.Errorf("unexpected policy type %T", obj)
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func IsNotFoundError(err error) bool {
	return errors.Is(err, errNotFound)
}
