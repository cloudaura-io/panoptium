package quarantine

import (
	"bytes"
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

func makeFactory(built *k8s.Built) k8s.ClientFactory {
	return func() (*k8s.Built, error) { return built, nil }
}

func newBuilt(ns string, all bool, qs ...*v1alpha1.AgentQuarantine) *k8s.Built {
	b := fake.NewClientBuilder().WithScheme(k8s.BuildScheme())
	for _, q := range qs {
		b = b.WithObjects(q)
	}
	return &k8s.Built{Client: b.Build(), Namespace: ns, AllNamespaces: all}
}

func TestListQuarantinesSingleNamespace(t *testing.T) {
	q1 := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "default"},
		Spec: v1alpha1.AgentQuarantineSpec{
			TargetPod:        "foo",
			TargetNamespace:  "default",
			ContainmentLevel: v1alpha1.ContainmentLevelNetworkIsolate,
			Reason:           "test",
		},
	}
	built := newBuilt("default", false, q1)
	resp, err := listQuarantines(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("expected 1, got %d", len(resp.Items))
	}
	if resp.Items[0].ContainmentLevel != string(v1alpha1.ContainmentLevelNetworkIsolate) {
		t.Errorf("level=%q", resp.Items[0].ContainmentLevel)
	}
}

func TestListQuarantinesAllNamespaces(t *testing.T) {
	q1 := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns1"},
		Spec:       v1alpha1.AgentQuarantineSpec{TargetPod: "x", TargetNamespace: "ns1", ContainmentLevel: v1alpha1.ContainmentLevelFreeze, Reason: "r"},
	}
	q2 := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns2"},
		Spec:       v1alpha1.AgentQuarantineSpec{TargetPod: "y", TargetNamespace: "ns2", ContainmentLevel: v1alpha1.ContainmentLevelFreeze, Reason: "r"},
	}
	built := newBuilt("ns1", true, q1, q2)
	resp, err := listQuarantines(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 2 {
		t.Errorf("expected 2, got %d", len(resp.Items))
	}
}

func TestListQuarantinesAllFormats(t *testing.T) {
	q := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "default"},
		Spec:       v1alpha1.AgentQuarantineSpec{TargetPod: "pod", TargetNamespace: "default", ContainmentLevel: v1alpha1.ContainmentLevelNetworkIsolate, Reason: "r"},
	}
	built := newBuilt("default", false, q)
	resp, err := listQuarantines(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []output.Format{output.FormatHuman, output.FormatJSON, output.FormatYAML, output.FormatTable} {
		var buf bytes.Buffer
		if err := writeListResponse(&buf, f, resp); err != nil {
			t.Errorf("format %s: %v", f, err)
		}
	}
}

func TestGetQuarantineFound(t *testing.T) {
	q := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "default"},
		Spec:       v1alpha1.AgentQuarantineSpec{TargetPod: "pod", TargetNamespace: "default", ContainmentLevel: v1alpha1.ContainmentLevelNetworkIsolate, Reason: "r"},
	}
	built := newBuilt("default", false, q)
	var buf bytes.Buffer
	if err := showQuarantine(context.Background(), &buf, built, "alpha", output.FormatHuman); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"alpha", "pod", "network-isolate"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q:\n%s", want, buf.String())
		}
	}
}

func TestGetQuarantineNotFound(t *testing.T) {
	built := newBuilt("default", false)
	err := showQuarantine(context.Background(), &bytes.Buffer{}, built, "missing", output.FormatHuman)
	if err == nil || !IsNotFoundError(err) {
		t.Errorf("expected not-found, got %v", err)
	}
}

func TestGetQuarantineRejectsTable(t *testing.T) {
	built := newBuilt("default", false)
	err := showQuarantine(context.Background(), &bytes.Buffer{}, built, "x", output.FormatTable)
	if err == nil {
		t.Fatal("expected format error")
	}
	if _, ok := err.(*output.FormatUnsupportedError); !ok {
		t.Errorf("expected FormatUnsupportedError, got %T", err)
	}
}

func TestListCommandWiredThroughFactory(t *testing.T) {
	q := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "default"},
		Spec:       v1alpha1.AgentQuarantineSpec{TargetPod: "pod", TargetNamespace: "default", ContainmentLevel: v1alpha1.ContainmentLevelNetworkIsolate, Reason: "r"},
	}
	built := newBuilt("default", false, q)
	cmd := newListCommand(func() string { return "human" }, makeFactory(built))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "alpha") {
		t.Errorf("expected alpha, got:\n%s", out.String())
	}
}
