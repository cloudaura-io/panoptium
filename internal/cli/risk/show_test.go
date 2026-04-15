package risk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

func TestFetchRiskReportsUnavailable(t *testing.T) {
	r := fetchRisk("", "")
	if r.Available {
		t.Error("risk should report unavailable until #10 lands")
	}
	if r.Reason == "" {
		t.Error("reason should be populated")
	}
}

func TestWriteReportHumanWhenUnavailable(t *testing.T) {
	r := fetchRisk("", "")
	var buf bytes.Buffer
	if err := writeReport(&buf, output.FormatHuman, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "unavailable") {
		t.Errorf("expected 'unavailable' in output:\n%s", buf.String())
	}
}

func TestWriteReportJSONRoundTrip(t *testing.T) {
	r := fetchRisk("", "")
	var buf bytes.Buffer
	if err := writeReport(&buf, output.FormatJSON, r); err != nil {
		t.Fatal(err)
	}
	var got RiskReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got.Available {
		t.Error("round-trip should preserve Available=false")
	}
}

func TestWriteReportAllFormats(t *testing.T) {
	r := fetchRisk("", "")
	for _, f := range []output.Format{output.FormatHuman, output.FormatJSON, output.FormatYAML, output.FormatTable} {
		var buf bytes.Buffer
		if err := writeReport(&buf, f, r); err != nil {
			t.Errorf("format %s: %v", f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("format %s: empty output", f)
		}
	}
}

func TestWriteReportWithEntries(t *testing.T) {
	r := &RiskReport{
		Available: true,
		Entries: []RiskEntry{
			{Namespace: "ns1", AgentName: "a", Score: 0.75, Level: "medium"},
		},
	}
	var buf bytes.Buffer
	if err := writeReport(&buf, output.FormatHuman, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ns1") || !strings.Contains(buf.String(), "0.75") {
		t.Errorf("missing entry fields:\n%s", buf.String())
	}
}

func TestWriteReportTableWithEntries(t *testing.T) {
	r := &RiskReport{
		Available: true,
		Entries: []RiskEntry{
			{Namespace: "ns1", AgentName: "a", Score: 0.9, Level: "high"},
		},
	}
	var buf bytes.Buffer
	if err := writeReport(&buf, output.FormatTable, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "SCORE") || !strings.Contains(buf.String(), "0.90") {
		t.Errorf("missing table fields:\n%s", buf.String())
	}
}

func TestNewShowCommandDegradesGracefully(t *testing.T) {
	cmd := newShowCommand(
		func() string { return "human" },
		func() (*k8s.Built, error) { return nil, fmt.Errorf("no cluster") },
	)
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "warning: cluster not reachable") {
		t.Errorf("expected warning on stderr:\n%s", errOut.String())
	}
	if !strings.Contains(out.String(), "unavailable") {
		t.Errorf("expected unavailable in stdout:\n%s", out.String())
	}
}

func TestNewShowCommandRejectsBadFormat(t *testing.T) {
	cmd := newShowCommand(
		func() string { return "invalid" },
		func() (*k8s.Built, error) { return nil, nil },
	)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for bad format")
	}
}
