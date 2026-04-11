package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseFormatAccepted(t *testing.T) {
	cases := []string{"human", "json", "yaml", "table"}
	for _, c := range cases {
		got, err := ParseFormat(c)
		if err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", c, err)
		}
		if string(got) != c {
			t.Errorf("ParseFormat(%q) = %q, want %q", c, got, c)
		}
	}
}

func TestParseFormatRejectsUnknown(t *testing.T) {
	_, err := ParseFormat("xml")
	if err == nil {
		t.Fatal("expected error for xml, got nil")
	}
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("expected ErrUnsupportedFormat wrap, got %v", err)
	}
	if !strings.Contains(err.Error(), "human") {
		t.Errorf("error should list valid formats, got %q", err.Error())
	}
}

type sample struct {
	Name  string `json:"name"  yaml:"name"`
	Count int    `json:"count" yaml:"count"`
}

func TestWriteJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sample{Name: "alpha", Count: 3}); err != nil {
		t.Fatal(err)
	}
	var got sample
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal failed: %v\noutput:\n%s", err, buf.String())
	}
	if got.Name != "alpha" || got.Count != 3 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if !strings.Contains(buf.String(), "  ") {
		t.Errorf("expected indented JSON, got %q", buf.String())
	}
}

func TestWriteJSONDeterministic(t *testing.T) {
	obj := sample{Name: "alpha", Count: 3}
	var a, b bytes.Buffer
	_ = WriteJSON(&a, obj)
	_ = WriteJSON(&b, obj)
	if a.String() != b.String() {
		t.Errorf("non-deterministic JSON:\n%s\nvs\n%s", a.String(), b.String())
	}
}

func TestWriteYAMLRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteYAML(&buf, sample{Name: "alpha", Count: 3}); err != nil {
		t.Fatal(err)
	}
	var got sample
	if err := yaml.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal failed: %v\noutput:\n%s", err, buf.String())
	}
	if got.Name != "alpha" || got.Count != 3 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestWriteTableHeadersAndRows(t *testing.T) {
	tbl := &Table{
		Headers: []string{"NAME", "AGE"},
		Rows: [][]string{
			{"alpha", "1d"},
			{"bravo-longer", "2h"},
		},
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, tbl); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"NAME", "AGE", "alpha", "bravo-longer", "1d", "2h"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines (header + 2 rows), got %d:\n%s", len(lines), out)
	}
}

func TestWriteTableEmptyHeadersOnly(t *testing.T) {
	tbl := &Table{Headers: []string{"NAME"}, Rows: nil}
	var buf bytes.Buffer
	if err := WriteTable(&buf, tbl); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "NAME") {
		t.Errorf("header not written:\n%s", buf.String())
	}
}

func TestFormatUnsupportedErrorMessage(t *testing.T) {
	err := &FormatUnsupportedError{Command: "events tail", Format: FormatTable}
	if !strings.Contains(err.Error(), "events tail") || !strings.Contains(err.Error(), "table") {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}
