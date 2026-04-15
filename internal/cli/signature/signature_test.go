package signature

import (
	"testing"

	"github.com/panoptium/panoptium/internal/cli/k8s"
)

func TestNewCommandHasExpectedSubcommands(t *testing.T) {
	cmd := NewCommand(
		func() string { return humanFmt },
		func() (*k8s.Built, error) { return nil, nil },
	)
	want := map[string]bool{
		"validate": false,
		"list":     false,
	}
	for _, sub := range cmd.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("signature command missing subcommand %q", name)
		}
	}
}
