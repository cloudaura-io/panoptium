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

// newTestJetStream creates an embedded NATS server, connects, and returns a JetStream context.
func newTestJetStream(t *testing.T) (natsgo.JetStreamContext, func()) {
	t.Helper()
	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	nc, err := natsgo.Connect(srv.ClientURL())
	if err != nil {
		srv.Shutdown()
		t.Fatalf("Connect error: %v", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		srv.Shutdown()
		t.Fatalf("JetStream error: %v", err)
	}
	cleanup := func() {
		nc.Close()
		srv.Shutdown()
	}
	return js, cleanup
}

// TestStreamManager_CreateStreams verifies that streams are created for each event category.
func TestStreamManager_CreateStreams(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	mgr := NewStreamManager(js, DefaultStreamConfig())
	if err := mgr.EnsureStreams(); err != nil {
		t.Fatalf("EnsureStreams() error: %v", err)
	}

	// Verify expected streams exist
	expectedStreams := []string{
		"PANOPTIUM_SYSCALL",
		"PANOPTIUM_NETWORK",
		"PANOPTIUM_PROTOCOL",
		"PANOPTIUM_LLM",
		"PANOPTIUM_POLICY",
		"PANOPTIUM_LIFECYCLE",
		"PANOPTIUM_HIGH_SEVERITY",
	}

	for _, name := range expectedStreams {
		info, err := js.StreamInfo(name)
		if err != nil {
			t.Errorf("StreamInfo(%q) error: %v", name, err)
			continue
		}
		if info == nil {
			t.Errorf("Stream %q does not exist", name)
		}
	}
}

// TestStreamManager_PolicyRetention verifies 7-day retention for policy.* stream.
func TestStreamManager_PolicyRetention(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	mgr := NewStreamManager(js, DefaultStreamConfig())
	if err := mgr.EnsureStreams(); err != nil {
		t.Fatalf("EnsureStreams() error: %v", err)
	}

	info, err := js.StreamInfo("PANOPTIUM_POLICY")
	if err != nil {
		t.Fatalf("StreamInfo error: %v", err)
	}

	expected := 7 * 24 * time.Hour
	if info.Config.MaxAge != expected {
		t.Errorf("PANOPTIUM_POLICY MaxAge = %v, want %v", info.Config.MaxAge, expected)
	}
}

// TestStreamManager_LifecycleRetention verifies 30-day retention for lifecycle.* stream.
func TestStreamManager_LifecycleRetention(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	mgr := NewStreamManager(js, DefaultStreamConfig())
	if err := mgr.EnsureStreams(); err != nil {
		t.Fatalf("EnsureStreams() error: %v", err)
	}

	info, err := js.StreamInfo("PANOPTIUM_LIFECYCLE")
	if err != nil {
		t.Fatalf("StreamInfo error: %v", err)
	}

	expected := 30 * 24 * time.Hour
	if info.Config.MaxAge != expected {
		t.Errorf("PANOPTIUM_LIFECYCLE MaxAge = %v, want %v", info.Config.MaxAge, expected)
	}
}

// TestStreamManager_HighSeverityRetention verifies 90-day retention for high-severity stream.
func TestStreamManager_HighSeverityRetention(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	mgr := NewStreamManager(js, DefaultStreamConfig())
	if err := mgr.EnsureStreams(); err != nil {
		t.Fatalf("EnsureStreams() error: %v", err)
	}

	info, err := js.StreamInfo("PANOPTIUM_HIGH_SEVERITY")
	if err != nil {
		t.Fatalf("StreamInfo error: %v", err)
	}

	expected := 90 * 24 * time.Hour
	if info.Config.MaxAge != expected {
		t.Errorf("PANOPTIUM_HIGH_SEVERITY MaxAge = %v, want %v", info.Config.MaxAge, expected)
	}
}

// TestStreamManager_DefaultRetention verifies 24-hour default retention for standard streams.
func TestStreamManager_DefaultRetention(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	mgr := NewStreamManager(js, DefaultStreamConfig())
	if err := mgr.EnsureStreams(); err != nil {
		t.Fatalf("EnsureStreams() error: %v", err)
	}

	// PANOPTIUM_SYSCALL, PANOPTIUM_NETWORK, PANOPTIUM_PROTOCOL, PANOPTIUM_LLM use default
	defaultStreams := []string{"PANOPTIUM_SYSCALL", "PANOPTIUM_NETWORK", "PANOPTIUM_PROTOCOL", "PANOPTIUM_LLM"}
	expected := 24 * time.Hour

	for _, name := range defaultStreams {
		info, err := js.StreamInfo(name)
		if err != nil {
			t.Errorf("StreamInfo(%q) error: %v", name, err)
			continue
		}
		if info.Config.MaxAge != expected {
			t.Errorf("%s MaxAge = %v, want %v", name, info.Config.MaxAge, expected)
		}
	}
}

// TestStreamManager_MaxStreamSize verifies max stream size enforcement (1GB default).
func TestStreamManager_MaxStreamSize(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	mgr := NewStreamManager(js, DefaultStreamConfig())
	if err := mgr.EnsureStreams(); err != nil {
		t.Fatalf("EnsureStreams() error: %v", err)
	}

	info, err := js.StreamInfo("PANOPTIUM_LLM")
	if err != nil {
		t.Fatalf("StreamInfo error: %v", err)
	}

	expectedBytes := int64(1024 * 1024 * 1024) // 1GB
	if info.Config.MaxBytes != expectedBytes {
		t.Errorf("MaxBytes = %d, want %d", info.Config.MaxBytes, expectedBytes)
	}
}

// TestStreamManager_DiscardOldPolicy verifies that streams use DiscardOld policy.
func TestStreamManager_DiscardOldPolicy(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	mgr := NewStreamManager(js, DefaultStreamConfig())
	if err := mgr.EnsureStreams(); err != nil {
		t.Fatalf("EnsureStreams() error: %v", err)
	}

	info, err := js.StreamInfo("PANOPTIUM_POLICY")
	if err != nil {
		t.Fatalf("StreamInfo error: %v", err)
	}

	if info.Config.Discard != natsgo.DiscardOld {
		t.Errorf("Discard = %v, want DiscardOld", info.Config.Discard)
	}
}

// TestStreamManager_Idempotent verifies that EnsureStreams is idempotent.
func TestStreamManager_Idempotent(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	mgr := NewStreamManager(js, DefaultStreamConfig())

	// Call twice; second call should not error
	if err := mgr.EnsureStreams(); err != nil {
		t.Fatalf("First EnsureStreams() error: %v", err)
	}
	if err := mgr.EnsureStreams(); err != nil {
		t.Fatalf("Second EnsureStreams() error: %v", err)
	}
}
