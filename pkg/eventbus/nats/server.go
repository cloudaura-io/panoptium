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

// Package nats provides an embedded NATS server with JetStream for the
// Panoptium event bus, replacing the in-memory SimpleBus with durable,
// multi-subscriber event streaming.
package nats

import (
	"fmt"
	"os"
	"sync"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
)

// ServerConfig configures the embedded NATS server.
type ServerConfig struct {
	// StoreDir is the directory for JetStream file-based storage.
	// If empty, a temporary directory is created.
	StoreDir string

	// Port is the NATS client port. If 0, a random available port is used.
	Port int

	// MaxPayload is the maximum message payload size in bytes.
	// Default: 1MB.
	MaxPayload int32
}

// Server wraps an embedded nats-server with JetStream enabled.
type Server struct {
	mu      sync.Mutex
	ns      *natsserver.Server
	opts    *natsserver.Options
	cfg     ServerConfig
	tmpDir  string // populated if we created a temp dir
	started bool
}

// NewServer creates a new embedded NATS server instance with the given configuration.
// The server is not started until Start() is called.
func NewServer(cfg ServerConfig) (*Server, error) {
	storeDir := cfg.StoreDir
	var tmpDir string
	if storeDir == "" {
		var err error
		tmpDir, err = os.MkdirTemp("", "panoptium-nats-*")
		if err != nil {
			return nil, fmt.Errorf("creating temp dir for JetStream: %w", err)
		}
		storeDir = tmpDir
	}

	maxPayload := cfg.MaxPayload
	if maxPayload == 0 {
		maxPayload = 1024 * 1024 // 1MB default
	}

	port := cfg.Port
	if port == 0 {
		port = -1 // NATS convention: -1 means random available port
	}

	opts := &natsserver.Options{
		Host:       "127.0.0.1",
		Port:       port,
		NoSigs:     true,
		MaxPayload: maxPayload,
		JetStream:  true,
		StoreDir:   storeDir,
		// Suppress logging in tests by default
		NoLog: true,
	}

	return &Server{
		opts:   opts,
		cfg:    cfg,
		tmpDir: tmpDir,
	}, nil
}

// Start initializes and starts the embedded NATS server.
// It blocks until the server is ready to accept connections.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return fmt.Errorf("server already started")
	}

	ns, err := natsserver.NewServer(s.opts)
	if err != nil {
		return fmt.Errorf("creating NATS server: %w", err)
	}

	ns.Start()

	// Wait for the server to be ready
	if !ns.ReadyForConnections(10 * time.Second) {
		ns.Shutdown()
		return fmt.Errorf("NATS server failed to become ready within timeout")
	}

	s.ns = ns
	s.started = true
	return nil
}

// Shutdown gracefully stops the embedded NATS server and cleans up resources.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ns != nil {
		s.ns.Shutdown()
		s.ns.WaitForShutdown()
		s.ns = nil
	}
	s.started = false

	// Clean up temp directory if we created it
	if s.tmpDir != "" {
		_ = os.RemoveAll(s.tmpDir)
		s.tmpDir = ""
	}
}

// HealthCheck returns nil if the server is running and ready, or an error otherwise.
func (s *Server) HealthCheck() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started || s.ns == nil {
		return fmt.Errorf("NATS server is not running")
	}

	if !s.ns.ReadyForConnections(1 * time.Second) {
		return fmt.Errorf("NATS server is not ready for connections")
	}

	return nil
}

// ClientURL returns the URL clients can use to connect to the embedded server.
func (s *Server) ClientURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ns == nil {
		return ""
	}
	return s.ns.ClientURL()
}
