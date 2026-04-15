package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/panoptium/panoptium/internal/cli/clierr"
	"github.com/panoptium/panoptium/internal/cli/events"
	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/policy"
	"github.com/panoptium/panoptium/internal/cli/quarantine"
	"github.com/panoptium/panoptium/internal/cli/risk"
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

	clientFactory := func() (*k8s.Built, error) {
		return k8s.NewFactory(&k8s.Flags{
			Kubeconfig:    flags.Kubeconfig,
			Context:       flags.Context,
			Namespace:     flags.Namespace,
			AllNamespaces: flags.AllNamespaces,
		})()
	}

	root.AddCommand(version.NewCommand(func() string { return flags.Output }))
	root.AddCommand(newCompletionCommand())
	root.AddCommand(policy.NewCommand(func() string { return flags.Output }, clientFactory))
	root.AddCommand(signature.NewCommand(func() string { return flags.Output }, clientFactory))
	root.AddCommand(quarantine.NewCommand(func() string { return flags.Output }, clientFactory))
	root.AddCommand(events.NewCommand(func() string { return flags.Output }))
	root.AddCommand(risk.NewCommand(func() string { return flags.Output }, clientFactory))

	return root
}

func Execute() {
	os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr))
}

func Run(args []string, out, errOut io.Writer) int {
	root := NewRootCommand(out, errOut)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var exitErr *clierr.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.Code
		}
		_, _ = fmt.Fprintf(errOut, "error: %s\n", err.Error())
		return 1
	}
	return 0
}

func noColorDefault() bool {
	return os.Getenv("NO_COLOR") != ""
}
