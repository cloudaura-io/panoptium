package risk

import (
	"testing"

	"github.com/panoptium/panoptium/internal/cli/k8s"
)

func TestNewCommandHasShowSubcommand(t *testing.T) {
	cmd := NewCommand(
		func() string { return "human" },
		func() (*k8s.Built, error) { return nil, nil },
	)
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Name() == "show" {
			found = true
		}
	}
	if !found {
		t.Error("risk command missing 'show' subcommand")
	}
}
