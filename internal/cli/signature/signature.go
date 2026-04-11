package signature

import "github.com/spf13/cobra"

func NewCommand(getFormat func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signature",
		Short: "Validate and inspect threat signatures",
	}
	cmd.AddCommand(newValidateCommand(getFormat))
	return cmd
}
