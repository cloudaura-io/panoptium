package eventbus

import (
	"errors"
	"testing"
)

func TestResolveEndpointExplicit(t *testing.T) {
	got, err := ResolveEndpoint("nats://explicit:4222")
	if err != nil {
		t.Fatal(err)
	}
	if got != "nats://explicit:4222" {
		t.Errorf("explicit path ignored, got %q", got)
	}
}

func TestResolveEndpointFromNATSURL(t *testing.T) {
	t.Setenv("NATS_URL", "nats://env:4222")
	t.Setenv("PANOPTIUM_NATS_URL", "")
	got, err := ResolveEndpoint("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "nats://env:4222" {
		t.Errorf("NATS_URL not used: %q", got)
	}
}

func TestResolveEndpointFromPanoptiumNATSURL(t *testing.T) {
	t.Setenv("NATS_URL", "")
	t.Setenv("PANOPTIUM_NATS_URL", "nats://panop:4222")
	got, err := ResolveEndpoint("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "nats://panop:4222" {
		t.Errorf("PANOPTIUM_NATS_URL not used: %q", got)
	}
}

func TestResolveEndpointNoneReturnsError(t *testing.T) {
	t.Setenv("NATS_URL", "")
	t.Setenv("PANOPTIUM_NATS_URL", "")
	_, err := ResolveEndpoint("")
	if err == nil {
		t.Fatal("expected ErrNoEndpoint, got nil")
	}
	if !errors.Is(err, ErrNoEndpoint) {
		t.Errorf("expected ErrNoEndpoint, got %v", err)
	}
}

func TestSubjectEmptyFilters(t *testing.T) {
	got := Subject(Filters{})
	want := "panoptium.events.*.*.>"
	if got != want {
		t.Errorf("Subject(empty)=%q want %q", got, want)
	}
}

func TestSubjectWithNamespace(t *testing.T) {
	got := Subject(Filters{Namespace: "default"})
	want := "panoptium.events.default.*.>"
	if got != want {
		t.Errorf("Subject=%q want %q", got, want)
	}
}

func TestSubjectWithCategory(t *testing.T) {
	got := Subject(Filters{Namespace: "default", Category: "protocol"})
	want := "panoptium.events.default.protocol.>"
	if got != want {
		t.Errorf("Subject=%q want %q", got, want)
	}
}

func TestSubjectWithSubcategory(t *testing.T) {
	got := Subject(Filters{Namespace: "default", Category: "protocol", Subcategory: "tool_call"})
	want := "panoptium.events.default.protocol.tool_call"
	if got != want {
		t.Errorf("Subject=%q want %q", got, want)
	}
}

func TestMatchesAgentEmpty(t *testing.T) {
	if !MatchesAgent("", "anything") {
		t.Error("empty filter should match anything")
	}
}

func TestMatchesAgentCaseInsensitive(t *testing.T) {
	if !MatchesAgent("MyAgent", "myagent") {
		t.Error("matching should be case-insensitive")
	}
}

func TestMatchesAgentNoMatch(t *testing.T) {
	if MatchesAgent("foo", "bar") {
		t.Error("non-matching names should return false")
	}
}
