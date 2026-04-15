package fileload

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const StdinPath = "-"

const maxFileSize = 10 << 20

type Document struct {
	Source   string
	DocIndex int
	Line     int
	Body     []byte
}

func (d Document) Location() string {
	if d.Line > 0 {
		return fmt.Sprintf("%s:%d", d.Source, d.Line)
	}
	return d.Source
}

func LoadPaths(paths []string, stdin io.Reader) ([]Document, error) {
	if len(paths) == 0 {
		return readStdinDocs(stdin)
	}

	var docs []Document
	seenStdin := false
	for _, p := range paths {
		if p == StdinPath {
			if seenStdin {
				continue
			}
			seenStdin = true
			sd, err := readStdinDocs(stdin)
			if err != nil {
				return nil, err
			}
			docs = append(docs, sd...)
			continue
		}

		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		if info.IsDir() {
			dd, err := loadDir(p)
			if err != nil {
				return nil, err
			}
			docs = append(docs, dd...)
			continue
		}
		fd, err := loadFile(p)
		if err != nil {
			return nil, err
		}
		docs = append(docs, fd...)
	}
	return docs, nil
}

func readStdinDocs(stdin io.Reader) ([]Document, error) {
	if stdin == nil {
		return nil, errors.New("no stdin reader provided")
	}
	b, err := io.ReadAll(io.LimitReader(stdin, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("stdin exceeds maximum size (%d MB)", maxFileSize>>20)
	}
	return splitDocuments("<stdin>", b), nil
}

func loadFile(path string) ([]Document, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("%s: file size %d exceeds maximum (%d MB)", path, info.Size(), maxFileSize>>20)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return splitDocuments(path, b), nil
}

func loadDir(dir string) ([]Document, error) {
	var out []Document
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		fd, err := loadFile(path)
		if err != nil {
			return err
		}
		out = append(out, fd...)
		return nil
	})
	return out, err
}

func splitDocuments(source string, content []byte) []Document {
	var docs []Document
	var buf bytes.Buffer
	line := 1
	docStart := 0 // 0 until the first content line of the current doc

	flush := func() {
		trimmed := bytes.TrimSpace(buf.Bytes())
		if len(trimmed) > 0 {
			docs = append(docs, Document{
				Source:   source,
				DocIndex: len(docs),
				Line:     docStart,
				Body:     append([]byte(nil), buf.Bytes()...),
			})
		}
		buf.Reset()
		docStart = 0
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		l := scanner.Text()
		if strings.TrimSpace(l) == "---" {
			flush()
		} else {
			if docStart == 0 && strings.TrimSpace(l) != "" {
				docStart = line
			}
			buf.WriteString(l)
			buf.WriteByte('\n')
		}
		line++
	}
	flush()
	return docs
}
