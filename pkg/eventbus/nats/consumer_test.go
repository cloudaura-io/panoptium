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
	"fmt"
	"os"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
)

// TestDurableConsumer_PersistAcrossRestart verifies events persist after NATS restart.
func TestDurableConsumer_PersistAcrossRestart(t *testing.T) {
	// Use a persistent store directory
	storeDir, err := os.MkdirTemp("", "panoptium-nats-persist-*")
	if err != nil {
		t.Fatalf("MkdirTemp error: %v", err)
	}
	defer func() { _ = os.RemoveAll(storeDir) }()

	// Start server, publish events, then shut down
	srv, err := NewServer(ServerConfig{StoreDir: storeDir})
	if err != nil {
		t.Fatalf("NewServer error: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	nc, err := natsgo.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("JetStream error: %v", err)
	}

	// Create a stream
	_, err = js.AddStream(&natsgo.StreamConfig{
		Name:     "TEST_PERSIST",
		Subjects: []string{"test.persist.>"},
		MaxAge:   24 * time.Hour,
		Storage:  natsgo.FileStorage,
	})
	if err != nil {
		t.Fatalf("AddStream error: %v", err)
	}

	// Publish 5 events
	for i := 0; i < 5; i++ {
		_, err := js.Publish("test.persist.event", []byte(fmt.Sprintf("event-%d", i)))
		if err != nil {
			t.Fatalf("Publish error: %v", err)
		}
	}

	nc.Close()
	srv.Shutdown()

	// Restart with the same store directory
	srv2, err := NewServer(ServerConfig{StoreDir: storeDir})
	if err != nil {
		t.Fatalf("NewServer (restart) error: %v", err)
	}
	defer srv2.Shutdown()
	if err := srv2.Start(); err != nil {
		t.Fatalf("Start (restart) error: %v", err)
	}

	nc2, err := natsgo.Connect(srv2.ClientURL())
	if err != nil {
		t.Fatalf("Connect (restart) error: %v", err)
	}
	defer nc2.Close()

	js2, err := nc2.JetStream()
	if err != nil {
		t.Fatalf("JetStream (restart) error: %v", err)
	}

	// Verify events persisted
	info, err := js2.StreamInfo("TEST_PERSIST")
	if err != nil {
		t.Fatalf("StreamInfo error: %v", err)
	}
	if info.State.Msgs != 5 {
		t.Errorf("Stream message count = %d, want 5", info.State.Msgs)
	}
}

// TestDurableConsumer_ReplayFromSequence verifies consumer can replay from a specific sequence.
func TestDurableConsumer_ReplayFromSequence(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	_, err := js.AddStream(&natsgo.StreamConfig{
		Name:     "TEST_REPLAY",
		Subjects: []string{"test.replay.>"},
		MaxAge:   24 * time.Hour,
		Storage:  natsgo.FileStorage,
	})
	if err != nil {
		t.Fatalf("AddStream error: %v", err)
	}

	// Publish 10 events
	for i := 0; i < 10; i++ {
		_, err := js.Publish("test.replay.event", []byte(fmt.Sprintf("event-%d", i)))
		if err != nil {
			t.Fatalf("Publish error: %v", err)
		}
	}

	// Create a consumer starting from sequence 6
	factory := NewConsumerFactory(js)
	sub, err := factory.Subscribe("TEST_REPLAY", "replay-consumer", DeliverByStartSequence(6))
	if err != nil {
		t.Fatalf("Subscribe error: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	// Should receive events starting from sequence 6 (5 events: 6,7,8,9,10)
	msgs, err := sub.Fetch(5, natsgo.MaxWait(5*time.Second))
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}

	if len(msgs) != 5 {
		t.Fatalf("Received %d events, want 5", len(msgs))
	}

	// First event should be event-5 (sequence 6, 0-indexed)
	if string(msgs[0].Data) != "event-5" {
		t.Errorf("First event = %q, want %q", string(msgs[0].Data), "event-5")
	}

	for _, msg := range msgs {
		_ = msg.Ack()
	}
}

// TestDurableConsumer_ResumesFromLastAck verifies durable consumer resumes
// from last acknowledged position.
func TestDurableConsumer_ResumesFromLastAck(t *testing.T) {
	js, cleanup := newTestJetStream(t)
	defer cleanup()

	_, err := js.AddStream(&natsgo.StreamConfig{
		Name:     "TEST_DURABLE",
		Subjects: []string{"test.durable.>"},
		MaxAge:   24 * time.Hour,
		Storage:  natsgo.FileStorage,
	})
	if err != nil {
		t.Fatalf("AddStream error: %v", err)
	}

	// Publish 10 events
	for i := 0; i < 10; i++ {
		_, err := js.Publish("test.durable.event", []byte(fmt.Sprintf("event-%d", i)))
		if err != nil {
			t.Fatalf("Publish error: %v", err)
		}
	}

	// Create a durable consumer and read first 5 events
	factory := NewConsumerFactory(js)
	sub1, err := factory.Subscribe("TEST_DURABLE", "durable-test", DeliverAll())
	if err != nil {
		t.Fatalf("Subscribe error: %v", err)
	}

	msgs, err := sub1.Fetch(5, natsgo.MaxWait(5*time.Second))
	if err != nil {
		t.Fatalf("First Fetch error: %v", err)
	}
	for _, msg := range msgs {
		_ = msg.Ack()
	}
	_ = sub1.Unsubscribe()

	// Re-subscribe with the same durable name
	sub2, err := factory.Subscribe("TEST_DURABLE", "durable-test", DeliverAll())
	if err != nil {
		t.Fatalf("Re-subscribe error: %v", err)
	}
	defer func() { _ = sub2.Unsubscribe() }()

	// Should resume from event 6 (after the 5 acknowledged)
	msgs2, err := sub2.Fetch(1, natsgo.MaxWait(5*time.Second))
	if err != nil {
		t.Fatalf("Resume Fetch error: %v", err)
	}

	if len(msgs2) != 1 {
		t.Fatalf("Received %d events, want 1", len(msgs2))
	}
	_ = msgs2[0].Ack()

	if string(msgs2[0].Data) != "event-5" {
		t.Errorf("Resumed event = %q, want %q", string(msgs2[0].Data), "event-5")
	}
}
