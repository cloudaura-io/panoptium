package events

import (
	"github.com/spf13/cobra"
)

func NewCommand(getFormat func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Stream events from the Panoptium event bus",
	}
	cmd.AddCommand(newTailCommand(getFormat))
	return cmd
}
