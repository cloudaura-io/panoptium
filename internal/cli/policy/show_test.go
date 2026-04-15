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

func TestShowPolicyHuman(t *testing.T) {
	p := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-shell", Namespace: "default"},
		Spec: v1alpha1.AgentPolicySpec{
			Priority:        100,
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Rules: []v1alpha1.PolicyRule{
				{Name: "rule1", Action: v1alpha1.Action{Type: v1alpha1.ActionTypeDeny}, Severity: v1alpha1.SeverityHigh},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(k8s.BuildScheme()).WithObjects(p).Build()
	built := &k8s.Built{Client: c, Namespace: "default"}
	var buf bytes.Buffer
	if err := showPolicy(context.Background(), &buf, built, "deny-shell", false, output.FormatHuman); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AgentPolicy", "deny-shell", "default", "enforcing", "rule1"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q:\n%s", want, buf.String())
		}
	}
}

func TestShowPolicyYAMLRoundTrippable(t *testing.T) {
	p := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-shell", Namespace: "default"},
		Spec: v1alpha1.AgentPolicySpec{
			Priority:        100,
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
		},
	}
	c := fake.NewClientBuilder().WithScheme(k8s.BuildScheme()).WithObjects(p).Build()
	built := &k8s.Built{Client: c, Namespace: "default"}
	var buf bytes.Buffer
	if err := showPolicy(context.Background(), &buf, built, "deny-shell", false, output.FormatYAML); err != nil {
		t.Fatal(err)
	}
	// A yaml rendering should include a metadata: section and spec:.
	if !strings.Contains(buf.String(), "metadata:") || !strings.Contains(buf.String(), "spec:") {
		t.Errorf("yaml round-trip missing expected sections:\n%s", buf.String())
	}
}

func TestShowPolicyNotFound(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(k8s.BuildScheme()).Build()
	built := &k8s.Built{Client: c, Namespace: "default"}
	err := showPolicy(context.Background(), &bytes.Buffer{}, built, "missing", false, output.FormatHuman)
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !IsNotFoundError(err) {
		t.Errorf("expected IsNotFoundError, got %v", err)
	}
}

func TestShowPolicyRejectsTableFormat(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(k8s.BuildScheme()).Build()
	built := &k8s.Built{Client: c, Namespace: "default"}
	err := showPolicy(context.Background(), &bytes.Buffer{}, built, "x", false, output.FormatTable)
	if err == nil {
		t.Fatal("expected format error, got nil")
	}
	if _, ok := err.(*output.FormatUnsupportedError); !ok {
		t.Errorf("expected *output.FormatUnsupportedError, got %T: %v", err, err)
	}
}

func TestShowClusterPolicy(t *testing.T) {
	cp := &v1alpha1.AgentClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-wide"},
		Spec:       v1alpha1.AgentClusterPolicySpec{Priority: 10, EnforcementMode: v1alpha1.EnforcementModeAudit},
	}
	c := fake.NewClientBuilder().WithScheme(k8s.BuildScheme()).WithObjects(cp).Build()
	built := &k8s.Built{Client: c, Namespace: ""}
	var buf bytes.Buffer
	if err := showPolicy(context.Background(), &buf, built, "cluster-wide", true, output.FormatHuman); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "AgentClusterPolicy") {
		t.Errorf("missing kind:\n%s", buf.String())
	}
}
