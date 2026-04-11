package policy

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
	pkgpolicy "github.com/panoptium/panoptium/pkg/policy"
)

const validPolicy = `apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: deny-shell
  namespace: default
spec:
  targetSelector:
    matchLabels:
      app: agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: no-shell
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'shell_exec'"
      action:
        type: deny
        parameters:
          message: "shell execution is not allowed"
      severity: HIGH
`

const validClusterPolicy = `apiVersion: panoptium.io/v1alpha1
kind: AgentClusterPolicy
metadata:
  name: cluster-baseline
spec:
  targetSelector:
    matchLabels:
      tier: prod
  enforcementMode: enforcing
  priority: 50
  rules:
    - name: audit-tools
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName != ''"
      action:
        type: alert
      severity: LOW
`

const invalidPolicyBadCEL = `apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: broken
  namespace: default
spec:
  targetSelector:
    matchLabels:
      app: agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: bad
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "not a valid CEL 🎭"
      action:
        type: deny
        parameters:
          message: "blocked"
      severity: HIGH
`

const invalidPolicyUnknownAction = `apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: broken-action
  namespace: default
spec:
  targetSelector:
    matchLabels:
      app: agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: bad
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'x'"
      action:
        type: explode
      severity: HIGH
`

const nonPolicyYAML = `apiVersion: v1
kind: ConfigMap
metadata:
  name: hello
data:
  foo: bar
`

func writeFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "doc.yaml")
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

func TestValidateDocumentsValidPolicy(t *testing.T) {
	docs := loadFixture(t, validPolicy)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	if report.Summary.Errors != 0 {
		t.Errorf("expected 0 errors, got %d: %+v", report.Summary.Errors, report.Results[0].Diagnostics)
	}
	if report.Summary.OK != 1 {
		t.Errorf("expected 1 ok, got %d", report.Summary.OK)
	}
}

func TestValidateDocumentsValidClusterPolicy(t *testing.T) {
	docs := loadFixture(t, validClusterPolicy)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	if report.Summary.Errors != 0 {
		t.Errorf("expected 0 errors, got %d: %+v", report.Summary.Errors, report.Results[0].Diagnostics)
	}
	if report.Results[0].Kind != "AgentClusterPolicy" {
		t.Errorf("Kind=%q want AgentClusterPolicy", report.Results[0].Kind)
	}
}

func TestValidateDocumentsBadCEL(t *testing.T) {
	docs := loadFixture(t, invalidPolicyBadCEL)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	if report.Summary.Errors != 1 {
		t.Errorf("expected 1 error, got %d", report.Summary.Errors)
	}
	if len(report.Results[0].Diagnostics) == 0 {
		t.Fatal("expected at least 1 diagnostic")
	}
}

func TestValidateDocumentsUnknownAction(t *testing.T) {
	docs := loadFixture(t, invalidPolicyUnknownAction)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	if report.Summary.Errors != 1 {
		t.Errorf("expected 1 error, got %d", report.Summary.Errors)
	}
}

func TestValidateDocumentsNonPolicySkipped(t *testing.T) {
	docs := loadFixture(t, nonPolicyYAML)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	if report.Summary.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", report.Summary.Skipped)
	}
	if report.Summary.Errors != 0 {
		t.Errorf("non-policy should not be an error, got %d errors", report.Summary.Errors)
	}
}

func TestWriteReportJSONRoundTrip(t *testing.T) {
	docs := loadFixture(t, validPolicy)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
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

func TestWriteReportYAML(t *testing.T) {
	docs := loadFixture(t, validPolicy)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	var buf bytes.Buffer
	if err := WriteReport(&buf, output.FormatYAML, &report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "summary:") {
		t.Errorf("yaml missing summary:\n%s", buf.String())
	}
}

func TestWriteReportTable(t *testing.T) {
	docs := loadFixture(t, validPolicy)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	var buf bytes.Buffer
	if err := WriteReport(&buf, output.FormatTable, &report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "LOCATION") {
		t.Errorf("table missing header:\n%s", buf.String())
	}
}

func TestWriteReportHuman(t *testing.T) {
	docs := loadFixture(t, validPolicy)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	var buf bytes.Buffer
	if err := WriteReport(&buf, output.FormatHuman, &report); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"[ok]", "AgentPolicy", "deny-shell", "Total:"} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q:\n%s", want, out)
		}
	}
}

func TestValidateCommandReturnsExitErrorOnFailure(t *testing.T) {
	path := writeFile(t, invalidPolicyBadCEL)
	cmd := newValidateCommand(func() string { return humanFmt })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-f", path})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid policy, got nil")
	}
	var ee *clierr.ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Errorf("want *clierr.ExitError with Code=1, got %T=%v", err, err)
	}
}

func TestValidateCommandSuccessReturnsNil(t *testing.T) {
	path := writeFile(t, validPolicy)
	cmd := newValidateCommand(func() string { return humanFmt })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-f", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "[ok]") {
		t.Errorf("expected [ok] marker in output:\n%s", out.String())
	}
}

func TestValidateCommandFromStdin(t *testing.T) {
	cmd := newValidateCommand(func() string { return humanFmt })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(validPolicy))
	cmd.SetArgs([]string{"-f", "-"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
