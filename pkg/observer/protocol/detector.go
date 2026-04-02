/*
Copyright 2026 Cloudaura sp. z o.o.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protocol

import (
	"errors"
	"sync"
)

// Detection method constants identify how the protocol was detected.
const (
	// DetectionMethodAnnotation indicates the protocol was detected via pod annotation.
	DetectionMethodAnnotation = "annotation"

	// DetectionMethodPath indicates the protocol was detected via URL path matching.
	DetectionMethodPath = "path"

	// DetectionMethodContentType indicates the protocol was detected via Content-Type header.
	DetectionMethodContentType = "content-type"

	// DetectionMethodJSONRPC indicates the protocol was detected via JSON-RPC method inspection.
	DetectionMethodJSONRPC = "jsonrpc"

	// DetectionMethodParserDetect indicates the protocol was detected via the parser's Detect method.
	DetectionMethodParserDetect = "parser-detect"

	// DetectionMethodFallback indicates no parser matched and fallback was used.
	DetectionMethodFallback = "fallback"
)

// Confidence score constants for each detection method.
const (
	ConfidenceAnnotation  float32 = 1.0
	ConfidencePath        float32 = 0.9
	ConfidenceContentType float32 = 0.7
	ConfidenceJSONRPC     float32 = 0.6
	ConfidenceFallback    float32 = 0.1
)

// ErrDuplicateParser is returned when attempting to register a parser with a
// name that is already registered.
var ErrDuplicateParser = errors.New("parser with this name is already registered")

// DetectionResult contains the result of protocol detection.
type DetectionResult struct {
	// Parser is the matched ProtocolParser, or nil if no parser matched.
	Parser ProtocolParser

	// Confidence is the confidence score of the detection (0.0-1.0).
	Confidence float32

	// Method indicates how the protocol was detected.
	Method string
}

// ProtocolDetector implements a priority-based detection cascade that identifies
// which protocol parser should handle a given request. The cascade order is:
// annotation (1.0) > path (0.9) > Content-Type (0.7) > JSON-RPC (0.6) > fallback (0.1).
type ProtocolDetector struct {
	mu             sync.RWMutex
	parsers        map[string]ProtocolParser
	pathPatterns   map[string]string // path prefix -> parser name
	contentTypes   map[string]string // content-type -> parser name
	jsonrpcMethods map[string]string // JSON-RPC method -> parser name
}

// NewProtocolDetector creates a new ProtocolDetector.
func NewProtocolDetector() *ProtocolDetector {
	return &ProtocolDetector{
		parsers:        make(map[string]ProtocolParser),
		pathPatterns:   make(map[string]string),
		contentTypes:   make(map[string]string),
		jsonrpcMethods: make(map[string]string),
	}
}

// Register adds a ProtocolParser to the detector.
// Returns ErrDuplicateParser if a parser with the same name is already registered.
func (d *ProtocolDetector) Register(parser ProtocolParser) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	name := parser.Name()
	if _, exists := d.parsers[name]; exists {
		return ErrDuplicateParser
	}

	d.parsers[name] = parser
	return nil
}

// RegisterPathPattern registers a URL path prefix pattern for a parser.
func (d *ProtocolDetector) RegisterPathPattern(pathPrefix string, parserName string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pathPatterns[pathPrefix] = parserName
}

// RegisterContentType registers a Content-Type value for a parser.
func (d *ProtocolDetector) RegisterContentType(contentType string, parserName string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.contentTypes[contentType] = parserName
}

// RegisterJSONRPCMethod registers a JSON-RPC method name for a parser.
func (d *ProtocolDetector) RegisterJSONRPCMethod(method string, parserName string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.jsonrpcMethods[method] = parserName
}

// Parsers returns a list of all registered parser names.
func (d *ProtocolDetector) Parsers() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	names := make([]string, 0, len(d.parsers))
	for name := range d.parsers {
		names = append(names, name)
	}
	return names
}

// Detect runs the priority cascade to identify the best parser for the given request.
// The cascade order is: annotation > path > Content-Type > JSON-RPC > parser Detect > fallback.
//
// Parameters:
//   - headers: HTTP request headers as key-value pairs
//   - path: HTTP request path
//   - method: HTTP method (GET, POST, etc.)
//   - annotations: pod annotations (may be nil)
//   - body: request body for JSON-RPC inspection (may be nil)
func (d *ProtocolDetector) Detect(headers map[string]string, path string, method string, annotations map[string]string, body []byte) DetectionResult {
	// TODO: implement detection cascade
	return DetectionResult{
		Confidence: ConfidenceFallback,
		Method:     DetectionMethodFallback,
	}
}
