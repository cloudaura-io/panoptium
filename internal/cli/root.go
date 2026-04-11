package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/panoptium/panoptium/internal/cli/clierr"
	"github.com/panoptium/panoptium/internal/cli/policy"
	"github.com/panoptium/panoptium/internal/cli/signature"
	"github.com/panoptium/panoptium/internal/cli/version"
)

type Flags struct {
	Output        string
	Kubeconfig    string
	Context       string
	Namespace     string
	AllNamespaces bool
	Verbose       bool
	NoColor       bool
}

func NewRootCommand(out, errOut io.Writer) *cobra.Command {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	flags := &Flags{}

	root := &cobra.Command{
		Use:   "panoptium",
		Short: "Panoptium CLI — policy validation, cluster introspection, and runtime operations",
		Long: `panoptium is the command-line interface for the Panoptium Kubernetes operator.

Use it to validate policies and threat signatures offline, inspect running
policies and quarantine state in a cluster, tail events from the event bus,
and manage agent quarantine and risk state.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(out)
	root.SetErr(errOut)

	pf := root.PersistentFlags()
	pf.StringVarP(&flags.Output, "output", "o", "human", "output format: human|json|yaml|table")
	pf.StringVar(&flags.Kubeconfig, "kubeconfig", "", "path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	pf.StringVar(&flags.Context, "context", "", "kubeconfig context to use")
	pf.StringVarP(&flags.Namespace, "namespace", "n", "", "namespace scope (default: current context namespace)")
	pf.BoolVarP(&flags.AllNamespaces, "all-namespaces", "A", false, "list across all namespaces")
	pf.BoolVarP(&flags.Verbose, "verbose", "v", false, "enable verbose debug logging on stderr")
	pf.BoolVar(&flags.NoColor, "no-color", noColorDefault(), "disable ANSI colors in output (respects NO_COLOR)")

	root.AddCommand(version.NewCommand(func() string { return flags.Output }))
	root.AddCommand(newCompletionCommand())
	root.AddCommand(policy.NewCommand(func() string { return flags.Output }))
	root.AddCommand(signature.NewCommand(func() string { return flags.Output }))

	return root
}

func Execute() {
	root := NewRootCommand(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		var exitErr *clierr.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
		os.Exit(1)
	}
}

func noColorDefault() bool {
	return os.Getenv("NO_COLOR") != ""
}
