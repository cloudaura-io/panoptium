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
	switch p := obj.(type) {
	case *v1alpha1.AgentPolicy:
		fmt.Fprintf(w, "Kind:              AgentPolicy\n")
		fmt.Fprintf(w, "Name:              %s\n", p.Name)
		fmt.Fprintf(w, "Namespace:         %s\n", p.Namespace)
		fmt.Fprintf(w, "Priority:          %d\n", p.Spec.Priority)
		fmt.Fprintf(w, "Enforcement Mode:  %s\n", p.Spec.EnforcementMode)
		fmt.Fprintf(w, "Rules:             %d\n", len(p.Spec.Rules))
		fmt.Fprintf(w, "Ready:             %s\n", readyCondition(p.Status.Conditions))
		fmt.Fprintf(w, "Age:               %s\n", relativeAge(p.CreationTimestamp.Time))
		for i, rule := range p.Spec.Rules {
			fmt.Fprintf(w, "\nRule %d: %s\n", i, rule.Name)
			fmt.Fprintf(w, "  Trigger:   %s / %s\n", rule.Trigger.EventCategory, rule.Trigger.EventSubcategory)
			fmt.Fprintf(w, "  Action:    %s\n", rule.Action.Type)
			fmt.Fprintf(w, "  Severity:  %s\n", rule.Severity)
			fmt.Fprintf(w, "  Predicates: %d\n", len(rule.Predicates))
		}
	case *v1alpha1.AgentClusterPolicy:
		fmt.Fprintf(w, "Kind:              AgentClusterPolicy\n")
		fmt.Fprintf(w, "Name:              %s\n", p.Name)
		fmt.Fprintf(w, "Priority:          %d\n", p.Spec.Priority)
		fmt.Fprintf(w, "Enforcement Mode:  %s\n", p.Spec.EnforcementMode)
		fmt.Fprintf(w, "Rules:             %d\n", len(p.Spec.Rules))
		fmt.Fprintf(w, "Ready:             %s\n", readyCondition(p.Status.Conditions))
		fmt.Fprintf(w, "Age:               %s\n", relativeAge(p.CreationTimestamp.Time))
	default:
		return fmt.Errorf("unexpected policy type %T", obj)
	}
	return nil
}

func IsNotFoundError(err error) bool {
	return errors.Is(err, errNotFound)
}
