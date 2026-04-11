package version

import (
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/panoptium/panoptium/internal/cli/output"
)

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Version   string `json:"version"   yaml:"version"`
	Commit    string `json:"commit"    yaml:"commit"`
	BuildDate string `json:"buildDate" yaml:"buildDate"`
	GoVersion string `json:"goVersion" yaml:"goVersion"`
	Platform  string `json:"platform"  yaml:"platform"`
}

func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: Date,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func NewCommand(getFormat func() string) *cobra.Command {
	var clientOnly bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print panoptium CLI version information",
		Example: `  # human-readable (default)
  panoptium version

  # machine-parseable
  panoptium version -o json
  panoptium version -o yaml

  # client-only, no cluster contact
  panoptium version --client`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			info := Current()
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			return writeInfo(cmd.OutOrStdout(), format, info)
		},
	}
	cmd.Flags().BoolVar(&clientOnly, "client", false, "print CLI version only; do not contact the operator")
	return cmd
}

func writeInfo(w io.Writer, format output.Format, info Info) error {
	switch format {
	case output.FormatJSON:
		return output.WriteJSON(w, info)
	case output.FormatYAML:
		return output.WriteYAML(w, info)
	case output.FormatTable:
		tbl := &output.Table{
			Headers: []string{"VERSION", "COMMIT", "BUILD DATE", "GO", "PLATFORM"},
			Rows:    [][]string{{info.Version, info.Commit, info.BuildDate, info.GoVersion, info.Platform}},
		}
		return output.WriteTable(w, tbl)
	case output.FormatHuman:
		fallthrough
	default:
		_, err := fmt.Fprintf(w,
			"panoptium-cli %s\n  commit:     %s\n  build date: %s\n  go:         %s\n  platform:   %s\n",
			info.Version, info.Commit, info.BuildDate, info.GoVersion, info.Platform)
		return err
	}
}
