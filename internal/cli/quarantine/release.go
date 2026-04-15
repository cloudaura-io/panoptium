package quarantine

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

var ErrAlreadyReleased = errors.New("quarantine already released")

func newReleaseCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release <name>",
		Short: "Release an AgentQuarantine by stamping status.releasedAt",
		Long: `release transitions an AgentQuarantine into the released state by
setting status.releasedAt to the current time. The operator observes
the change and tears down the associated NetworkPolicies and BPF-LSM
rules (see #8 for enforcement progress).

release is idempotent: calling it on an already-released quarantine
returns an ErrAlreadyReleased error.`,
		Example: `  panoptium quarantine release agent-foo-q
  panoptium quarantine release agent-foo-q -n prod`,
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
			return releaseQuarantine(cmd.Context(), cmd.OutOrStdout(), built, args[0], format)
		},
	}
	return cmd
}

func releaseQuarantine(ctx context.Context, w io.Writer, built *k8s.Built, name string, format output.Format) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ns := built.Namespace
	if ns == "" {
		ns = defaultNamespace
	}

	var obj v1alpha1.AgentQuarantine
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := built.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &obj); err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("%w: quarantine %q", errNotFound, name)
			}
			return err
		}
		if obj.Status.ReleasedAt != nil {
			return fmt.Errorf("%w: %s/%s already released at %s", ErrAlreadyReleased, ns, name, obj.Status.ReleasedAt.String())
		}
		now := metav1.Now()
		obj.Status.ReleasedAt = &now
		return built.Client.Status().Update(ctx, &obj)
	})
	if err != nil {
		return err
	}
	return writeGetOutput(w, format, &obj)
}
