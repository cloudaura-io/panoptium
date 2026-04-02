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
	"encoding/json"
	"errors"
	"strings"
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
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Level 1: Explicit pod annotation (confidence 1.0)
	if annotations != nil {
		if protoName, ok := annotations["panoptium.io/protocol"]; ok {
			if parser, exists := d.parsers[protoName]; exists {
				return DetectionResult{
					Parser:     parser,
					Confidence: ConfidenceAnnotation,
					Method:     DetectionMethodAnnotation,
				}
			}
			// Annotation refers to unknown parser — fall through
		}
	}

	// Level 2: Path matching (confidence 0.9)
	for prefix, parserName := range d.pathPatterns {
		if strings.HasPrefix(path, prefix) {
			if parser, exists := d.parsers[parserName]; exists {
				return DetectionResult{
					Parser:     parser,
					Confidence: ConfidencePath,
					Method:     DetectionMethodPath,
				}
			}
		}
	}

	// Level 3: Content-Type inspection (confidence 0.7)
	if ct, ok := headers["Content-Type"]; ok {
		if parserName, exists := d.contentTypes[ct]; exists {
			if parser, exists := d.parsers[parserName]; exists {
				return DetectionResult{
					Parser:     parser,
					Confidence: ConfidenceContentType,
					Method:     DetectionMethodContentType,
				}
			}
		}
	}

	// Level 4: JSON-RPC method inspection (confidence 0.6)
	if len(body) > 0 {
		if result, ok := d.detectJSONRPC(body); ok {
			return result
		}
	}

	// Level 5: Ask each parser's own Detect method — pick highest confidence
	var bestParser ProtocolParser
	var bestConfidence float32
	for _, parser := range d.parsers {
		canHandle, confidence := parser.Detect(headers, path, method)
		if canHandle && confidence > bestConfidence {
			bestParser = parser
			bestConfidence = confidence
		}
	}
	if bestParser != nil {
		return DetectionResult{
			Parser:     bestParser,
			Confidence: bestConfidence,
			Method:     DetectionMethodParserDetect,
		}
	}

	// Level 6: Fallback (confidence 0.1)
	return DetectionResult{
		Confidence: ConfidenceFallback,
		Method:     DetectionMethodFallback,
	}
}

// jsonrpcRequest is a minimal struct for JSON-RPC 2.0 method detection.
type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
}

// detectJSONRPC attempts to parse the body as JSON-RPC 2.0 and match the method
// field against registered JSON-RPC methods. Supports both single requests and
// batched requests (JSON array).
func (d *ProtocolDetector) detectJSONRPC(body []byte) (DetectionResult, bool) {
	// Try single request first
	var single jsonrpcRequest
	if err := json.Unmarshal(body, &single); err == nil {
		if single.JSONRPC == "2.0" && single.Method != "" {
			if parserName, exists := d.jsonrpcMethods[single.Method]; exists {
				if parser, exists := d.parsers[parserName]; exists {
					return DetectionResult{
						Parser:     parser,
						Confidence: ConfidenceJSONRPC,
						Method:     DetectionMethodJSONRPC,
					}, true
				}
			}
		}
		return DetectionResult{}, false
	}

	// Try batched request (JSON array)
	var batch []jsonrpcRequest
	if err := json.Unmarshal(body, &batch); err == nil && len(batch) > 0 {
		// Match on the first request in the batch
		for _, req := range batch {
			if req.JSONRPC == "2.0" && req.Method != "" {
				if parserName, exists := d.jsonrpcMethods[req.Method]; exists {
					if parser, exists := d.parsers[parserName]; exists {
						return DetectionResult{
							Parser:     parser,
							Confidence: ConfidenceJSONRPC,
							Method:     DetectionMethodJSONRPC,
						}, true
					}
				}
			}
		}
	}

	return DetectionResult{}, false
}
