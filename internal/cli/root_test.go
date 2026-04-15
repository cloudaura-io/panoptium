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

func TestCompletionFishEmitsScript(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"completion", "fish"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		t.Error("fish completion output empty")
	}
}

func TestCompletionPowerShellEmitsScript(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"completion", "powershell"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		t.Error("powershell completion output empty")
	}
}

func TestNoColorDefaultRespectsEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if !noColorDefault() {
		t.Error("expected NO_COLOR=1 to make default true")
	}
	t.Setenv("NO_COLOR", "")
	if noColorDefault() {
		t.Error("expected empty NO_COLOR to make default false")
	}
}

func TestRunVersionSuccessReturnsZero(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"version"}, &out, &errOut)
	if code != 0 {
		t.Errorf("version exit code=%d want 0", code)
	}
	if !strings.Contains(out.String(), "panoptium-cli") {
		t.Errorf("missing version banner:\n%s", out.String())
	}
}

func TestRunUnknownSubcommandReturnsOne(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"nonsense"}, &out, &errOut)
	if code != 1 {
		t.Errorf("unknown command should exit 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "error:") {
		t.Errorf("expected 'error:' prefix on stderr:\n%s", errOut.String())
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
