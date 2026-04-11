package version

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/panoptium/panoptium/internal/cli/output"
)

func TestCurrentPopulatesRuntimeFields(t *testing.T) {
	info := Current()
	if info.GoVersion == "" {
		t.Error("GoVersion empty")
	}
	if info.Platform == "" {
		t.Error("Platform empty")
	}
}

func TestWriteInfoHumanContainsAllFields(t *testing.T) {
	info := Info{Version: "1.2.3", Commit: "abc1234", BuildDate: "2026-04-11", GoVersion: "go1.26", Platform: "linux/amd64"}
	var buf bytes.Buffer
	if err := writeInfo(&buf, output.FormatHuman, info); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"1.2.3", "abc1234", "2026-04-11", "go1.26", "linux/amd64"} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteInfoJSONRoundTrips(t *testing.T) {
	info := Info{Version: "1.2.3", Commit: "abc1234", BuildDate: "2026-04-11", GoVersion: "go1.26", Platform: "linux/amd64"}
	var buf bytes.Buffer
	if err := writeInfo(&buf, output.FormatJSON, info); err != nil {
		t.Fatal(err)
	}
	var got Info
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got != info {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, info)
	}
}

func TestWriteInfoYAMLContainsVersion(t *testing.T) {
	info := Info{Version: "1.2.3"}
	var buf bytes.Buffer
	if err := writeInfo(&buf, output.FormatYAML, info); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "version: 1.2.3") {
		t.Errorf("yaml missing version:\n%s", buf.String())
	}
}

func TestWriteInfoTableHasHeaders(t *testing.T) {
	info := Info{Version: "1.2.3", Commit: "abc", BuildDate: "d", GoVersion: "g", Platform: "p"}
	var buf bytes.Buffer
	if err := writeInfo(&buf, output.FormatTable, info); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"VERSION", "COMMIT", "PLATFORM"} {
		if !strings.Contains(buf.String(), h) {
			t.Errorf("table missing header %q:\n%s", h, buf.String())
		}
	}
}

func TestNewCommandExecutes(t *testing.T) {
	var buf bytes.Buffer
	cmd := NewCommand(func() string { return "human" })
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "panoptium-cli") {
		t.Errorf("missing header in output:\n%s", buf.String())
	}
}

func TestNewCommandRejectsBadFormat(t *testing.T) {
	cmd := NewCommand(func() string { return "toml" })
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for bad format, got nil")
	}
}
