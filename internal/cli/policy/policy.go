package policy

import (
	"github.com/spf13/cobra"

	"github.com/panoptium/panoptium/internal/cli/k8s"
)

func NewCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Validate, lint, list, and inspect agent policies",
	}
	cmd.AddCommand(newValidateCommand(getFormat))
	cmd.AddCommand(newLintCommand(getFormat))
	cmd.AddCommand(newListCommand(getFormat, factory))
	cmd.AddCommand(newShowCommand(getFormat, factory))
	return cmd
}
