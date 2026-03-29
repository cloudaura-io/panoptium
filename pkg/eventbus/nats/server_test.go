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

package nats

import (
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
)

// TestServerStart verifies that the embedded NATS server starts and accepts connections.
func TestServerStart(t *testing.T) {
	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	defer srv.Shutdown()

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Verify we can connect to the server
	nc, err := natsgo.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("Failed to connect to embedded NATS: %v", err)
	}
	defer nc.Close()

	if !nc.IsConnected() {
		t.Error("Expected NATS connection to be active")
	}
}

// TestServerHealthCheck verifies that the health check returns healthy status.
func TestServerHealthCheck(t *testing.T) {
	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	defer srv.Shutdown()

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	if err := srv.HealthCheck(); err != nil {
		t.Errorf("HealthCheck() error: %v", err)
	}
}

// TestServerShutdown verifies that graceful shutdown closes all connections.
func TestServerShutdown(t *testing.T) {
	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Connect a client
	nc, err := natsgo.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Shutdown the server
	srv.Shutdown()

	// Wait for connection to close
	time.Sleep(100 * time.Millisecond)

	// Verify the connection is no longer active
	if nc.IsConnected() {
		t.Error("Expected NATS connection to be closed after server shutdown")
	}
	nc.Close()
}

// TestServerRestart verifies that the server can be stopped and started again.
func TestServerRestart(t *testing.T) {
	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	// First start
	if err := srv.Start(); err != nil {
		t.Fatalf("First Start() error: %v", err)
	}

	url1 := srv.ClientURL()

	// Connect and verify
	nc1, err := natsgo.Connect(url1)
	if err != nil {
		t.Fatalf("First connection error: %v", err)
	}
	nc1.Close()

	// Shutdown
	srv.Shutdown()

	// Create new server (embedded NATS server can't restart in-place)
	srv2, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer() for restart error: %v", err)
	}
	defer srv2.Shutdown()

	if err := srv2.Start(); err != nil {
		t.Fatalf("Restart Start() error: %v", err)
	}

	// Connect and verify
	nc2, err := natsgo.Connect(srv2.ClientURL())
	if err != nil {
		t.Fatalf("Restart connection error: %v", err)
	}
	defer nc2.Close()

	if !nc2.IsConnected() {
		t.Error("Expected connection to be active after restart")
	}
}

// TestServerJetStreamEnabled verifies that JetStream is enabled on the embedded server.
func TestServerJetStreamEnabled(t *testing.T) {
	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	defer srv.Shutdown()

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	nc, err := natsgo.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("JetStream() error: %v", err)
	}

	// Verify JetStream is operational by checking account info
	info, err := js.AccountInfo()
	if err != nil {
		t.Fatalf("AccountInfo() error: %v", err)
	}

	if info == nil {
		t.Error("JetStream AccountInfo should not be nil")
	}
}

// TestServerHealthCheckBeforeStart verifies that health check fails before start.
func TestServerHealthCheckBeforeStart(t *testing.T) {
	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	defer srv.Shutdown()

	if err := srv.HealthCheck(); err == nil {
		t.Error("HealthCheck() should return error before Start()")
	}
}
