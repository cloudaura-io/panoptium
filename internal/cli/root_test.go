package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewRootCommandRegistersCoreSubcommands(t *testing.T) {
	root := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	want := map[string]bool{
		"version":    false,
		"completion": false,
	}
	for _, sub := range root.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("root command missing subcommand %q", name)
		}
	}
}

func TestRootHelpMentionsGlobalFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	combined := out.String() + errOut.String()
	for _, flag := range []string{"--output", "--kubeconfig", "--context", "--namespace", "--all-namespaces", "--verbose", "--no-color"} {
		if !strings.Contains(combined, flag) {
			t.Errorf("help missing flag %q:\n%s", flag, combined)
		}
	}
}

func TestCompletionZshEmitsScript(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"completion", "zsh"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "#compdef") {
		t.Errorf("zsh completion missing #compdef header:\n%s", out.String())
	}
}

func TestCompletionBashEmitsScript(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"completion", "bash"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "bash completion") && !strings.Contains(out.String(), "_panoptium") {
		t.Errorf("bash completion output looks empty:\n%s", out.String())
	}
}

func TestCompletionRejectsInvalidShell(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"completion", "tcsh"})
	if err := root.Execute(); err == nil {
		t.Error("expected error for invalid shell, got nil")
	}
}

func TestVersionSubcommandJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"version", "-o", "json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"version"`) {
		t.Errorf("version json missing version field:\n%s", out.String())
	}
}
