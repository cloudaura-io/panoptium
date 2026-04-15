package fileload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := `apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: test
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	docs, err := LoadPaths([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("want 1 doc, got %d", len(docs))
	}
	if docs[0].Source != path {
		t.Errorf("Source=%q want %q", docs[0].Source, path)
	}
	if docs[0].DocIndex != 0 {
		t.Errorf("DocIndex=%d want 0", docs[0].DocIndex)
	}
	if docs[0].Line != 1 {
		t.Errorf("Line=%d want 1", docs[0].Line)
	}
	if !strings.Contains(string(docs[0].Body), "kind: AgentPolicy") {
		t.Errorf("body missing content:\n%s", docs[0].Body)
	}
}

func TestLoadMultiDocumentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.yaml")
	content := `apiVersion: v1
kind: First
metadata:
  name: a
---
apiVersion: v1
kind: Second
metadata:
  name: b
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	docs, err := LoadPaths([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatalf("want 2 docs, got %d", len(docs))
	}
	if docs[0].DocIndex != 0 || docs[1].DocIndex != 1 {
		t.Errorf("doc indices not sequential: %d, %d", docs[0].DocIndex, docs[1].DocIndex)
	}
	if docs[0].Line != 1 {
		t.Errorf("doc 0 Line=%d want 1", docs[0].Line)
	}
	if docs[1].Line != 6 {
		t.Errorf("doc 1 Line=%d want 6", docs[1].Line)
	}
	if !strings.Contains(string(docs[0].Body), "First") {
		t.Errorf("doc 0 body wrong: %s", docs[0].Body)
	}
	if !strings.Contains(string(docs[1].Body), "Second") {
		t.Errorf("doc 1 body wrong: %s", docs[1].Body)
	}
}

func TestLoadIgnoresEmptyDocuments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.yaml")
	content := `---
---
apiVersion: v1
kind: Real
---

---
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	docs, err := LoadPaths([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("want 1 non-empty doc, got %d", len(docs))
	}
}

func TestLoadDirectoryRecursively(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	_ = os.Mkdir(sub, 0o755)
	files := map[string]string{
		filepath.Join(dir, "a.yaml"):     "apiVersion: v1\nkind: A\nmetadata:\n  name: a\n",
		filepath.Join(dir, "b.yml"):      "apiVersion: v1\nkind: B\nmetadata:\n  name: b\n",
		filepath.Join(dir, "ignore.txt"): "not a yaml",
		filepath.Join(sub, "deep.yaml"):  "apiVersion: v1\nkind: C\nmetadata:\n  name: c\n",
	}
	for p, content := range files {
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	docs, err := LoadPaths([]string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 3 {
		t.Fatalf("want 3 docs, got %d", len(docs))
	}
}

func TestLoadStdinDash(t *testing.T) {
	content := "apiVersion: v1\nkind: A\nmetadata:\n  name: a\n"
	docs, err := LoadPaths([]string{StdinPath}, strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("want 1 doc, got %d", len(docs))
	}
	if docs[0].Source != "<stdin>" {
		t.Errorf("Source=%q want <stdin>", docs[0].Source)
	}
}

func TestLoadNoPathsReadsStdin(t *testing.T) {
	content := "apiVersion: v1\nkind: A\nmetadata:\n  name: a\n"
	docs, err := LoadPaths(nil, strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("want 1 doc, got %d", len(docs))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := LoadPaths([]string{"/nonexistent/thing.yaml"}, nil)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestDocumentLocation(t *testing.T) {
	d := Document{Source: "x.yaml", Line: 12}
	if got, want := d.Location(), "x.yaml:12"; got != want {
		t.Errorf("Location=%q want %q", got, want)
	}
	d2 := Document{Source: "x.yaml", Line: 0}
	if got, want := d2.Location(), "x.yaml"; got != want {
		t.Errorf("Location (no line)=%q want %q", got, want)
	}
}
