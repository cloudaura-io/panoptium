package events

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	natsgo "github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/panoptium/panoptium/internal/cli/eventbus"
	"github.com/panoptium/panoptium/internal/cli/output"
	pb "github.com/panoptium/panoptium/pkg/eventbus/pb"
)

func runNATSServer(t *testing.T) (string, func()) {
	t.Helper()
	opts := natstest.DefaultTestOptions
	opts.Port = -1
	s := natstest.RunServer(&opts)
	if !s.ReadyForConnections(2 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	return s.ClientURL(), func() {
		s.Shutdown()
		s.WaitForShutdown()
	}
}

func encodeEvent(t *testing.T, ev *pb.PanoptiumEvent) []byte {
	t.Helper()
	b, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnwrapExtractsFields(t *testing.T) {
	ev := &pb.PanoptiumEvent{
		Id:          "abc",
		Timestamp:   timestamppb.New(time.Unix(1000, 0)),
		Category:    "protocol",
		Subcategory: "tool_call",
		Severity:    pb.Severity_HIGH,
		Agent: &pb.AgentIdentity{
			PodName:   "my-pod",
			Namespace: "default",
		},
	}
	msg := &natsgo.Msg{
		Subject: "panoptium.events.default.protocol.tool_call",
		Data:    encodeEvent(t, ev),
	}
	view, ok := unwrap(msg)
	if !ok {
		t.Fatal("unwrap failed")
	}
	if view.ID != "abc" {
		t.Errorf("ID=%q", view.ID)
	}
	if view.Category != "protocol" {
		t.Errorf("Category=%q", view.Category)
	}
	if view.Namespace != "default" {
		t.Errorf("Namespace=%q", view.Namespace)
	}
	if view.PodName != "my-pod" {
		t.Errorf("PodName=%q", view.PodName)
	}
	if view.AgentName != "my-pod" {
		t.Errorf("AgentName=%q", view.AgentName)
	}
	if view.Subject != "panoptium.events.default.protocol.tool_call" {
		t.Errorf("Subject=%q", view.Subject)
	}
}

func TestUnwrapBadPayloadDropped(t *testing.T) {
	msg := &natsgo.Msg{Subject: "x", Data: []byte("not a proto")}
	if _, ok := unwrap(msg); ok {
		t.Error("bad payload should return ok=false")
	}
}

func TestWriteEventHuman(t *testing.T) {
	view := &EventView{
		ID: "abc", Timestamp: "2026-04-11T00:00:00Z",
		Category: "protocol", Subcategory: "tool_call",
		Severity: "SEVERITY_HIGH", Namespace: "default", AgentName: "my-pod",
	}
	var buf bytes.Buffer
	if err := writeEvent(&buf, output.FormatHuman, view); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"protocol", "tool_call", "default", "my-pod", "SEVERITY_HIGH"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q:\n%s", want, buf.String())
		}
	}
}

func TestWriteEventJSONOneLine(t *testing.T) {
	view := &EventView{ID: "abc", Category: "protocol", Severity: "SEVERITY_HIGH"}
	var buf bytes.Buffer
	if err := writeEvent(&buf, output.FormatJSON, view); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("json output should end with newline")
	}
	var got EventView
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got.ID != "abc" {
		t.Errorf("round-trip ID=%q", got.ID)
	}
}

func TestTailCommandRejectsTableFormat(t *testing.T) {
	t.Setenv("NATS_URL", "nats://127.0.0.1:4222") // won't actually dial
	cmd := newTailCommand(func() string { return "table" })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected FormatUnsupportedError, got nil")
	}
	if _, ok := err.(*output.FormatUnsupportedError); !ok {
		t.Errorf("expected FormatUnsupportedError, got %T: %v", err, err)
	}
}

func TestTailCommandErrorsWithoutEndpoint(t *testing.T) {
	t.Setenv("NATS_URL", "")
	t.Setenv("PANOPTIUM_NATS_URL", "")
	cmd := newTailCommand(func() string { return "human" })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected ErrNoEndpoint, got nil")
	}
}

func TestStreamEventsIntegration(t *testing.T) {
	url, shutdown := runNATSServer(t)
	defer shutdown()

	conn, err := eventbus.Connect(url, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	publisher, err := natsgo.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()

	evs := []*pb.PanoptiumEvent{
		{
			Id: "ev-1", Timestamp: timestamppb.Now(),
			Category: "protocol", Subcategory: "tool_call",
			Severity: pb.Severity_INFO,
			Agent:    &pb.AgentIdentity{PodName: "pod1", Namespace: "default"},
		},
		{
			Id: "ev-2", Timestamp: timestamppb.Now(),
			Category: "policy", Subcategory: "decision",
			Severity: pb.Severity_CRITICAL,
			Agent:    &pb.AgentIdentity{PodName: "pod2", Namespace: "default"},
		},
	}

	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		time.Sleep(150 * time.Millisecond)
		for _, ev := range evs {
			subj := "panoptium.events.default." + ev.Category + "." + ev.Subcategory
			_ = publisher.Publish(subj, encodeEvent(t, ev))
		}
		_ = publisher.Flush()
	}()

	err = streamEvents(ctx, &buf, conn, eventbus.Filters{Namespace: "default"}, output.FormatJSON, 2)
	if err != nil {
		t.Fatalf("streamEvents: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "ev-1") || !strings.Contains(out, "ev-2") {
		t.Errorf("expected both event ids in output:\n%s", out)
	}
	if lines := strings.Count(out, "\n"); lines != 2 {
		t.Errorf("expected exactly 2 json lines, got %d:\n%s", lines, out)
	}
}

var _ = natsserver.Options{}
