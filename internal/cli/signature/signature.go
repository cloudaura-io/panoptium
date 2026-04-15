package signature

import (
	"github.com/spf13/cobra"

	"github.com/panoptium/panoptium/internal/cli/k8s"
)

func NewCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signature",
		Short: "Validate, list, and inspect threat signatures",
	}
	cmd.AddCommand(newValidateCommand(getFormat))
	cmd.AddCommand(newListCommand(getFormat, factory))
	return cmd
}
