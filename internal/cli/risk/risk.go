package risk

import (
	"github.com/spf13/cobra"

	"github.com/panoptium/panoptium/internal/cli/k8s"
)

func NewCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "View agent risk scoring state",
	}
	cmd.AddCommand(newShowCommand(getFormat, factory))
	return cmd
}
