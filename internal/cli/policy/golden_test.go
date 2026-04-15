package policy

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/panoptium/panoptium/internal/cli/output"
	pkgpolicy "github.com/panoptium/panoptium/pkg/policy"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite golden files to current output")

var sourceRegex = regexp.MustCompile(`(?m)("source":\s*")[^"]+(\.yaml")`)
var humanSourceRegex = regexp.MustCompile(`(?m)/tmp/[^\s]+?/doc\.yaml`)

func maskSource(b []byte) []byte {
	b = sourceRegex.ReplaceAll(b, []byte(`${1}<masked>$2`))
	b = humanSourceRegex.ReplaceAll(b, []byte("<masked>/doc.yaml"))
	return b
}

func checkGolden(t *testing.T, goldenFile string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", goldenFile)
	got = maskSource(got)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file %s (run with -update-golden to create): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s.\n--- want\n%s\n--- got\n%s", goldenFile, want, got)
	}
}

func TestGoldenValidateHuman(t *testing.T) {
	docs := loadFixture(t, validPolicy)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	var buf bytes.Buffer
	if err := WriteReport(&buf, output.FormatHuman, &report); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "validate_valid_human.txt", buf.Bytes())
}

func TestGoldenValidateJSON(t *testing.T) {
	docs := loadFixture(t, validPolicy)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	var buf bytes.Buffer
	if err := WriteReport(&buf, output.FormatJSON, &report); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "validate_valid_json.json", buf.Bytes())
}

func TestGoldenLintHuman(t *testing.T) {
	docs := loadFixture(t, lintyPolicyBroadSelector)
	report := lintDocuments(docs, pkgpolicy.NewPolicyCompiler())
	var buf bytes.Buffer
	if err := WriteReport(&buf, output.FormatHuman, &report); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "lint_broad_human.txt", buf.Bytes())
}

func TestGoldenValidateInvalidJSON(t *testing.T) {
	docs := loadFixture(t, invalidPolicyUnknownAction)
	report := validateDocuments(docs, pkgpolicy.NewPolicyCompiler())
	var buf bytes.Buffer
	if err := WriteReport(&buf, output.FormatJSON, &report); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "validate_invalid_json.json", buf.Bytes())
}
