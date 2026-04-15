package quarantine

import (
	"bytes"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
)

const humanFmt = "human"

func TestRelativeAgeBuckets(t *testing.T) {
	cases := map[string]time.Duration{
		"d": 48 * time.Hour,
		"h": 2 * time.Hour,
		"m": 30 * time.Minute,
		"s": 15 * time.Second,
	}
	for suffix, d := range cases {
		got := relativeAge(time.Now().Add(-d))
		if !strings.HasSuffix(got, suffix) {
			t.Errorf("relativeAge(-%v) = %q; want *%s", d, got, suffix)
		}
	}
	if relativeAge(time.Time{}) != "" {
		t.Error("zero time should render empty")
	}
}

func TestWriteListHumanEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := writeListHuman(&buf, &QuarantineListResponse{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no quarantines") {
		t.Errorf("expected 'no quarantines' message:\n%s", buf.String())
	}
}

func TestSummarizeWithStatus(t *testing.T) {
	now := metav1.Now()
	q := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "q1", Namespace: "default", CreationTimestamp: metav1.Now()},
		Spec: v1alpha1.AgentQuarantineSpec{
			TargetPod:        "p",
			TargetNamespace:  "default",
			ContainmentLevel: v1alpha1.ContainmentLevelNetworkIsolate,
			Reason:           "r",
		},
		Status: v1alpha1.AgentQuarantineStatus{
			ContainedAt: &now,
			ReleasedAt:  &now,
		},
	}
	s := summarize(q)
	if s.Contained == "" {
		t.Error("Contained timestamp missing")
	}
	if s.Released == "" {
		t.Error("Released timestamp missing")
	}
}

func TestNewCommandHasExpectedSubcommands(t *testing.T) {
	cmd := NewCommand(func() string { return humanFmt }, func() (*k8s.Built, error) { return nil, nil })
	want := map[string]bool{
		"list":    false,
		"get":     false,
		"create":  false,
		"release": false,
	}
	for _, sub := range cmd.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("quarantine command missing subcommand %q", name)
		}
	}
}
