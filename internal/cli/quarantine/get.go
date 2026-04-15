package quarantine

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

func newGetCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Show a single AgentQuarantine by name",
		Long: `get fetches one AgentQuarantine resource with its full spec and
status. The -n flag selects the namespace; -o yaml is round-trippable.`,
		Example: `  panoptium quarantine get agent-foo-quarantine
  panoptium quarantine get agent-foo -n prod -o yaml`,
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
			return showQuarantine(cmd.Context(), cmd.OutOrStdout(), built, args[0], format)
		},
	}
	return cmd
}

func showQuarantine(ctx context.Context, w io.Writer, built *k8s.Built, name string, format output.Format) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if format == output.FormatTable {
		return &output.FormatUnsupportedError{Command: "quarantine get", Format: format}
	}
	ns := built.Namespace
	if ns == "" {
		ns = defaultNamespace
	}
	var obj v1alpha1.AgentQuarantine
	if err := built.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &obj); err != nil {
		return translateGetError(err, name)
	}
	return writeGetOutput(w, format, &obj)
}

func translateGetError(err error, name string) error {
	if err == nil {
		return nil
	}
	if meta.IsNoMatchError(err) {
		return fmt.Errorf("%w: %v", k8s.ErrCRDNotFound, err)
	}
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: quarantine %q", errNotFound, name)
	}
	return err
}

func writeGetOutput(w io.Writer, format output.Format, q *v1alpha1.AgentQuarantine) error {
	switch format {
	case output.FormatJSON:
		return output.WriteJSON(w, q)
	case output.FormatYAML:
		return output.WriteYAML(w, q)
	case output.FormatHuman:
		return writeHumanQuarantine(w, q)
	}
	return &output.FormatUnsupportedError{Command: "quarantine get", Format: format}
}

func writeHumanQuarantine(w io.Writer, q *v1alpha1.AgentQuarantine) error {
	lines := []string{
		fmt.Sprintf("Name:              %s", q.Name),
		fmt.Sprintf("Namespace:         %s", q.Namespace),
		fmt.Sprintf("Target Pod:        %s/%s", q.Spec.TargetNamespace, q.Spec.TargetPod),
		fmt.Sprintf("Containment:       %s", q.Spec.ContainmentLevel),
		fmt.Sprintf("Reason:            %s", q.Spec.Reason),
	}
	if q.Spec.TriggeringPolicy != "" {
		lines = append(lines, fmt.Sprintf("Triggering Policy: %s", q.Spec.TriggeringPolicy))
	}
	if q.Spec.TriggeringSignature != "" {
		lines = append(lines, fmt.Sprintf("Signature:         %s", q.Spec.TriggeringSignature))
	}
	if q.Status.ContainedAt != nil {
		lines = append(lines, fmt.Sprintf("Contained At:      %s", q.Status.ContainedAt.String()))
	}
	if q.Status.ReleasedAt != nil {
		lines = append(lines, fmt.Sprintf("Released At:       %s", q.Status.ReleasedAt.String()))
	}
	if len(q.Status.AppliedNetworkPolicies) > 0 {
		lines = append(lines, fmt.Sprintf("NetworkPolicies:   %v", q.Status.AppliedNetworkPolicies))
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
