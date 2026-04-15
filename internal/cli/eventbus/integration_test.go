package eventbus

import (
	"context"
	"testing"
	"time"

	natstest "github.com/nats-io/nats-server/v2/test"
	natsgo "github.com/nats-io/nats.go"
)

func TestConnectAndSubscribe(t *testing.T) {
	opts := natstest.DefaultTestOptions
	opts.Port = -1
	s := natstest.RunServer(&opts)
	defer func() {
		s.Shutdown()
		s.WaitForShutdown()
	}()
	if !s.ReadyForConnections(2 * time.Second) {
		t.Fatal("NATS not ready")
	}

	conn, err := Connect(s.ClientURL(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	received := make(chan string, 1)
	cancelSub, err := Subscribe(ctx, conn, Filters{Namespace: "default", Category: "policy"}, func(m *natsgo.Msg) {
		received <- m.Subject
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancelSub()

	pub, err := natsgo.Connect(s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	if err := pub.Publish("panoptium.events.default.policy.decision", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := pub.Publish("panoptium.events.other.protocol.tool_call", []byte("other")); err != nil {
		t.Fatal(err)
	}
	_ = pub.Flush()

	select {
	case subj := <-received:
		if subj != "panoptium.events.default.policy.decision" {
			t.Errorf("unexpected subject: %q", subj)
		}
	case <-ctx.Done():
		t.Fatal("no message received within timeout")
	}
}

func TestConnectFailsOnBadURL(t *testing.T) {
	_, err := Connect("nats://127.0.0.1:1", 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected error for unreachable NATS, got nil")
	}
}
