package policy

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

func newFakeBuiltWithPolicies(ns string, all bool, objs ...*v1alpha1.AgentPolicy) *k8s.Built {
	scheme := k8s.BuildScheme()
	b := fake.NewClientBuilder().WithScheme(scheme)
	for _, o := range objs {
		b = b.WithObjects(o)
	}
	return &k8s.Built{Client: b.Build(), Namespace: ns, AllNamespaces: all}
}

func TestListPoliciesReturnsNamespaced(t *testing.T) {
	p1 := &v1alpha1.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "default"}}
	p2 := &v1alpha1.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "bravo", Namespace: "default"}}
	built := newFakeBuiltWithPolicies("default", false, p1, p2)

	resp, err := listPolicies(context.Background(), built)
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

func TestListPoliciesRespectsAllNamespaces(t *testing.T) {
	p1 := &v1alpha1.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns1"}}
	p2 := &v1alpha1.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns2"}}
	built := newFakeBuiltWithPolicies("ns1", true, p1, p2)

	resp, err := listPolicies(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 2 {
		t.Errorf("with -A expected 2, got %d", len(resp.Items))
	}
}

func TestListPoliciesScopedWithoutAllNamespaces(t *testing.T) {
	p1 := &v1alpha1.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns1"}}
	p2 := &v1alpha1.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns2"}}
	built := newFakeBuiltWithPolicies("ns1", false, p1, p2)

	resp, err := listPolicies(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Namespace != "ns1" {
		t.Errorf("scoped list should only return ns1, got %+v", resp.Items)
	}
}

func TestListPoliciesIncludesClusterPolicies(t *testing.T) {
	cp := &v1alpha1.AgentClusterPolicy{ObjectMeta: metav1.ObjectMeta{Name: "cluster-wide"}}
	scheme := k8s.BuildScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cp).Build()
	built := &k8s.Built{Client: c, Namespace: "default", AllNamespaces: false}

	resp, err := listPolicies(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Kind != "AgentClusterPolicy" {
		t.Errorf("expected cluster policy, got %+v", resp.Items)
	}
}

func TestWriteListResponseAllFormats(t *testing.T) {
	p1 := &v1alpha1.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "default"}, Spec: v1alpha1.AgentPolicySpec{Priority: 100, EnforcementMode: v1alpha1.EnforcementModeEnforcing}}
	built := newFakeBuiltWithPolicies("default", false, p1)
	resp, err := listPolicies(context.Background(), built)
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
	p1 := &v1alpha1.AgentPolicy{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "default"}}
	built := newFakeBuiltWithPolicies("default", false, p1)
	cmd := newListCommand(func() string { return humanFmt }, makeFactory(built))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "alpha") {
		t.Errorf("expected 'alpha' in output:\n%s", out.String())
	}
}
