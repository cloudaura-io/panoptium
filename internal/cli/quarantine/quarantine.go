package quarantine

import (
	"github.com/spf13/cobra"

	"github.com/panoptium/panoptium/internal/cli/k8s"
)

func NewCommand(getFormat func() string, factory k8s.ClientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quarantine",
		Short: "List, inspect, and manage agent quarantine state",
	}
	cmd.AddCommand(newListCommand(getFormat, factory))
	cmd.AddCommand(newGetCommand(getFormat, factory))
	return cmd
}
