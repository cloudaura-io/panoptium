package events

import "testing"

func TestNewCommandHasTailSubcommand(t *testing.T) {
	cmd := NewCommand(func() string { return "human" })
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Name() == "tail" {
			found = true
		}
	}
	if !found {
		t.Error("events command missing 'tail' subcommand")
	}
}
