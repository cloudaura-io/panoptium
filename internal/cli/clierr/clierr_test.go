package clierr

import "testing"

func TestExitErrorMessagePreferred(t *testing.T) {
	err := &ExitError{Code: 2, Message: "boom"}
	if err.Error() != "boom" {
		t.Errorf("Error()=%q want %q", err.Error(), "boom")
	}
}

func TestExitErrorFallsBackToCode(t *testing.T) {
	err := &ExitError{Code: 7}
	if err.Error() != "exit code 7" {
		t.Errorf("Error()=%q want %q", err.Error(), "exit code 7")
	}
}
