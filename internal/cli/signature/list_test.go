package signature

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

const humanFmt = "human"

func makeFactory(built *k8s.Built) k8s.ClientFactory {
	return func() (*k8s.Built, error) { return built, nil }
}

func newBuiltWithSignatures(sigs ...*v1alpha1.ThreatSignature) *k8s.Built {
	b := fake.NewClientBuilder().WithScheme(k8s.BuildScheme())
	for _, s := range sigs {
		b = b.WithObjects(s)
	}
	return &k8s.Built{Client: b.Build(), Namespace: "default"}
}

func TestListSignaturesReturnsAll(t *testing.T) {
	s1 := &v1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha"},
		Spec: v1alpha1.ThreatSignatureSpec{
			Category: "prompt_injection",
			Severity: v1alpha1.SeverityHigh,
		},
	}
	s2 := &v1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "bravo"},
		Spec: v1alpha1.ThreatSignatureSpec{
			Category: "data_exfiltration",
			Severity: v1alpha1.SeverityCritical,
		},
	}
	built := newBuiltWithSignatures(s1, s2)
	resp, err := listSignatures(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(resp.Items))
	}
	if resp.Items[0].Name != "alpha" || resp.Items[1].Name != "bravo" {
		t.Errorf("items not sorted: %+v", resp.Items)
	}
}

func TestListSignaturesEmpty(t *testing.T) {
	built := newBuiltWithSignatures()
	resp, err := listSignatures(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 0 {
		t.Errorf("expected empty, got %d", len(resp.Items))
	}
}

func TestSignatureListAllFormats(t *testing.T) {
	s := &v1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "x"},
		Spec:       v1alpha1.ThreatSignatureSpec{Category: "c", Severity: v1alpha1.SeverityMedium},
	}
	built := newBuiltWithSignatures(s)
	resp, err := listSignatures(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []output.Format{output.FormatHuman, output.FormatJSON, output.FormatYAML, output.FormatTable} {
		var buf bytes.Buffer
		if err := writeListResponse(&buf, f, resp); err != nil {
			t.Errorf("format %s: %v", f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("format %s: empty output", f)
		}
	}
}

func TestListCommandWiredThroughFactory(t *testing.T) {
	s := &v1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha"},
		Spec:       v1alpha1.ThreatSignatureSpec{Category: "c", Severity: v1alpha1.SeverityHigh},
	}
	built := newBuiltWithSignatures(s)
	cmd := newListCommand(func() string { return humanFmt }, makeFactory(built))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "alpha") {
		t.Errorf("expected alpha in output:\n%s", out.String())
	}
}
