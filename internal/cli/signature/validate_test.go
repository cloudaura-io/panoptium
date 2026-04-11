package signature

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/panoptium/panoptium/internal/cli/clierr"
	"github.com/panoptium/panoptium/internal/cli/fileload"
	"github.com/panoptium/panoptium/internal/cli/output"
)

const validSignature = `apiVersion: panoptium.io/v1alpha1
kind: ThreatSignature
metadata:
  name: prompt-injection-direct
spec:
  protocols:
    - openai
    - anthropic
  category: prompt_injection
  severity: HIGH
  description: direct prompt injection via 'ignore previous instructions'
  detection:
    patterns:
      - regex: '(?i)ignore\s+(all\s+)?previous\s+instructions'
        weight: 0.9
        target: message_content
`

const invalidSignatureBadRegex = `apiVersion: panoptium.io/v1alpha1
kind: ThreatSignature
metadata:
  name: broken
spec:
  category: test
  severity: HIGH
  detection:
    patterns:
      - regex: '[a-z'
        weight: 0.5
        target: message_content
`

const nonSignatureYAML = `apiVersion: v1
kind: ConfigMap
metadata:
  name: hello
data:
  foo: bar
`

func writeFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sig.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadFixture(t *testing.T, content string) []fileload.Document {
	t.Helper()
	path := writeFile(t, content)
	docs, err := fileload.LoadPaths([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return docs
}

func TestValidateSignatureValid(t *testing.T) {
	docs := loadFixture(t, validSignature)
	report := validateDocuments(docs)
	if report.Summary.Errors != 0 {
		t.Errorf("expected 0 errors, got %d: %+v", report.Summary.Errors, report.Results[0].Diagnostics)
	}
	if report.Summary.OK != 1 {
		t.Errorf("expected 1 ok, got %d", report.Summary.OK)
	}
}

func TestValidateSignatureBadRegex(t *testing.T) {
	docs := loadFixture(t, invalidSignatureBadRegex)
	report := validateDocuments(docs)
	if report.Summary.Errors != 1 {
		t.Errorf("expected 1 error, got %d", report.Summary.Errors)
	}
	if len(report.Results[0].Diagnostics) == 0 {
		t.Fatal("expected at least 1 diagnostic")
	}
}

func TestValidateSignatureNonSignatureSkipped(t *testing.T) {
	docs := loadFixture(t, nonSignatureYAML)
	report := validateDocuments(docs)
	if report.Summary.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", report.Summary.Skipped)
	}
}

func TestWriteReportJSONRoundTrip(t *testing.T) {
	docs := loadFixture(t, validSignature)
	report := validateDocuments(docs)
	var buf bytes.Buffer
	if err := WriteReport(&buf, output.FormatJSON, &report); err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got.Summary.OK != 1 {
		t.Errorf("round-trip summary.ok=%d want 1", got.Summary.OK)
	}
}

func TestWriteReportAllFormats(t *testing.T) {
	docs := loadFixture(t, validSignature)
	report := validateDocuments(docs)
	for _, f := range []output.Format{output.FormatHuman, output.FormatJSON, output.FormatYAML, output.FormatTable} {
		var buf bytes.Buffer
		if err := WriteReport(&buf, f, &report); err != nil {
			t.Errorf("format %s: %v", f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("format %s: empty output", f)
		}
	}
}

func TestValidateCommandExitErrorOnFailure(t *testing.T) {
	path := writeFile(t, invalidSignatureBadRegex)
	cmd := newValidateCommand(func() string { return "human" })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-f", path})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
	var ee *clierr.ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Errorf("want *clierr.ExitError Code=1, got %T=%v", err, err)
	}
}

func TestValidateCommandSuccess(t *testing.T) {
	path := writeFile(t, validSignature)
	cmd := newValidateCommand(func() string { return "human" })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-f", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "[ok]") {
		t.Errorf("expected [ok] marker:\n%s", out.String())
	}
}

func TestValidateCommandFromStdin(t *testing.T) {
	cmd := newValidateCommand(func() string { return "human" })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(validSignature))
	cmd.SetArgs([]string{"-f", "-"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
