package quarantine

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

const defaultNamespace = "default"

func newCreateCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	var (
		targetPod       string
		targetNamespace string
		level           string
		reason          string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an AgentQuarantine CRD for manual containment",
		Long: `create writes a new AgentQuarantine resource into the cluster. The
operator watches for new quarantines and applies the configured
containment level. Until #8 (NetworkPolicy-based quarantine) lands in
the operator, the CRD is persisted correctly but the network-isolate
enforcement path may be partial — the CRD level is the source of
truth in either case.`,
		Example: `  panoptium quarantine create agent-foo-q \
    --pod agent-foo --target-namespace prod --level network-isolate \
    --reason "manual review after suspicious activity"`,
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
			if targetPod == "" {
				return fmt.Errorf("--pod is required")
			}
			if targetNamespace == "" {
				targetNamespace = built.Namespace
			}
			if targetNamespace == "" {
				return fmt.Errorf("--target-namespace is required (or set -n)")
			}
			if reason == "" {
				return fmt.Errorf("--reason is required")
			}
			if level == "" {
				level = string(v1alpha1.ContainmentLevelNetworkIsolate)
			}
			if !isValidContainmentLevel(level) {
				return fmt.Errorf("invalid --level %q: must be one of network-isolate, syscall-restrict, freeze, evict", level)
			}
			return createQuarantine(cmd.Context(), cmd.OutOrStdout(), built, args[0], targetPod, targetNamespace, level, reason, format)
		},
	}
	cmd.Flags().StringVar(&targetPod, "pod", "", "target pod name (required)")
	cmd.Flags().StringVar(&targetNamespace, "target-namespace", "", "target pod namespace (default: current namespace)")
	cmd.Flags().StringVar(&level, "level", "network-isolate", "containment level (network-isolate|syscall-restrict|freeze|evict)")
	cmd.Flags().StringVar(&reason, "reason", "", "human-readable reason for this quarantine (required)")
	return cmd
}

func createQuarantine(ctx context.Context, w io.Writer, built *k8s.Built, name, pod, targetNS, level, reason string, format output.Format) error {
	if ctx == nil {
		ctx = context.Background()
	}
	qNS := built.Namespace
	if qNS == "" {
		qNS = defaultNamespace
	}

	q := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: qNS,
		},
		Spec: v1alpha1.AgentQuarantineSpec{
			TargetPod:        pod,
			TargetNamespace:  targetNS,
			ContainmentLevel: v1alpha1.ContainmentLevel(level),
			Reason:           reason,
		},
	}

	if err := built.Client.Create(ctx, q); err != nil {
		if apierrors.IsAlreadyExists(err) {
			var existing v1alpha1.AgentQuarantine
			if getErr := built.Client.Get(ctx, client.ObjectKey{Namespace: qNS, Name: name}, &existing); getErr != nil {
				return fmt.Errorf("create returned AlreadyExists but get failed: %w", getErr)
			}
			existing.Spec.ContainmentLevel = v1alpha1.ContainmentLevel(level)
			existing.Spec.Reason = reason
			if updErr := built.Client.Update(ctx, &existing); updErr != nil {
				return fmt.Errorf("update existing quarantine %q: %w", name, updErr)
			}
			q = &existing
		} else {
			return fmt.Errorf("create quarantine %q: %w", name, err)
		}
	}
	return writeGetOutput(w, format, q)
}

var validContainmentLevels = map[string]bool{
	string(v1alpha1.ContainmentLevelNetworkIsolate):  true,
	string(v1alpha1.ContainmentLevelSyscallRestrict): true,
	string(v1alpha1.ContainmentLevelFreeze):          true,
	string(v1alpha1.ContainmentLevelEvict):           true,
}

func isValidContainmentLevel(level string) bool {
	return validContainmentLevels[level]
}
