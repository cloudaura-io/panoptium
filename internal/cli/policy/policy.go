package policy

import (
	"github.com/spf13/cobra"
)

func NewCommand(getFormat func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Validate, lint, and inspect agent policies",
	}
	cmd.AddCommand(newValidateCommand(getFormat))
	cmd.AddCommand(newLintCommand(getFormat))
	return cmd
}
