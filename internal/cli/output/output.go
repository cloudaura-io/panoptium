package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

type Format string

const (
	FormatHuman Format = "human"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
	FormatTable Format = "table"
)

var AllFormats = []Format{FormatHuman, FormatJSON, FormatYAML, FormatTable}

var ErrUnsupportedFormat = errors.New("unsupported output format")

func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatHuman, FormatJSON, FormatYAML, FormatTable:
		return Format(s), nil
	default:
		return "", fmt.Errorf("%w: %q (valid: %s)", ErrUnsupportedFormat, s, strings.Join(formatStrings(), ", "))
	}
}

func formatStrings() []string {
	out := make([]string, len(AllFormats))
	for i, f := range AllFormats {
		out[i] = string(f)
	}
	return out
}

func WriteJSON(w io.Writer, obj interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(obj)
}

func WriteYAML(w io.Writer, obj interface{}) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()
	return enc.Encode(obj)
}

type Table struct {
	Headers []string
	Rows    [][]string
}

func WriteTable(w io.Writer, t *Table) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(t.Headers) > 0 {
		if _, err := fmt.Fprintln(tw, strings.Join(t.Headers, "\t")); err != nil {
			return err
		}
	}
	for _, row := range t.Rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

type FormatUnsupportedError struct {
	Command string
	Format  Format
}

func (e *FormatUnsupportedError) Error() string {
	return fmt.Sprintf("%s: output format %q is not supported by this command", e.Command, e.Format)
}
