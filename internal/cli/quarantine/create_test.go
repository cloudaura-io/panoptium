package quarantine

import (
	"bytes"
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/cli/k8s"
	"github.com/panoptium/panoptium/internal/cli/output"
)

func TestCreateQuarantineWritesCRD(t *testing.T) {
	scheme := k8s.BuildScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	built := &k8s.Built{Client: c, Namespace: "default"}
	var buf bytes.Buffer
	err := createQuarantine(context.Background(), &buf, built,
		"q1", "agent-pod", "prod", "network-isolate", "manual review", output.FormatHuman)
	if err != nil {
		t.Fatal(err)
	}
	var got v1alpha1.AgentQuarantine
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "q1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.TargetPod != "agent-pod" {
		t.Errorf("TargetPod=%q", got.Spec.TargetPod)
	}
	if got.Spec.TargetNamespace != "prod" {
		t.Errorf("TargetNamespace=%q", got.Spec.TargetNamespace)
	}
	if got.Spec.ContainmentLevel != v1alpha1.ContainmentLevelNetworkIsolate {
		t.Errorf("Level=%q", got.Spec.ContainmentLevel)
	}
	if got.Spec.Reason != "manual review" {
		t.Errorf("Reason=%q", got.Spec.Reason)
	}
}

func TestCreateQuarantineIdempotent(t *testing.T) {
	existing := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "q1", Namespace: "default"},
		Spec: v1alpha1.AgentQuarantineSpec{
			TargetPod: "old-pod", TargetNamespace: "old-ns",
			ContainmentLevel: v1alpha1.ContainmentLevelFreeze,
			Reason:           "old",
		},
	}
	c := fake.NewClientBuilder().WithScheme(k8s.BuildScheme()).WithObjects(existing).Build()
	built := &k8s.Built{Client: c, Namespace: "default"}

	var buf bytes.Buffer
	err := createQuarantine(context.Background(), &buf, built,
		"q1", "new-pod", "new-ns", "evict", "updated reason", output.FormatHuman)
	if err != nil {
		t.Fatalf("idempotent create should succeed, got %v", err)
	}
	var got v1alpha1.AgentQuarantine
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "q1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Reason != "updated reason" {
		t.Errorf("Reason=%q want updated reason", got.Spec.Reason)
	}
	if got.Spec.ContainmentLevel != v1alpha1.ContainmentLevelEvict {
		t.Errorf("Level=%q want evict", got.Spec.ContainmentLevel)
	}
}

func TestReleaseQuarantineStampsReleasedAt(t *testing.T) {
	existing := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "q1", Namespace: "default"},
		Spec: v1alpha1.AgentQuarantineSpec{
			TargetPod: "p", TargetNamespace: "default",
			ContainmentLevel: v1alpha1.ContainmentLevelNetworkIsolate, Reason: "r",
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(k8s.BuildScheme()).
		WithStatusSubresource(&v1alpha1.AgentQuarantine{}).
		WithObjects(existing).
		Build()
	built := &k8s.Built{Client: c, Namespace: "default"}

	var buf bytes.Buffer
	err := releaseQuarantine(context.Background(), &buf, built, "q1", output.FormatHuman)
	if err != nil {
		t.Fatal(err)
	}

	var got v1alpha1.AgentQuarantine
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "q1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ReleasedAt == nil {
		t.Error("ReleasedAt should be set after release")
	}
}

func TestReleaseQuarantineAlreadyReleased(t *testing.T) {
	now := metav1.Now()
	existing := &v1alpha1.AgentQuarantine{
		ObjectMeta: metav1.ObjectMeta{Name: "q1", Namespace: "default"},
		Spec: v1alpha1.AgentQuarantineSpec{
			TargetPod: "p", TargetNamespace: "default",
			ContainmentLevel: v1alpha1.ContainmentLevelNetworkIsolate, Reason: "r",
		},
		Status: v1alpha1.AgentQuarantineStatus{ReleasedAt: &now},
	}
	c := fake.NewClientBuilder().
		WithScheme(k8s.BuildScheme()).
		WithStatusSubresource(&v1alpha1.AgentQuarantine{}).
		WithObjects(existing).
		Build()
	built := &k8s.Built{Client: c, Namespace: "default"}
	err := releaseQuarantine(context.Background(), &bytes.Buffer{}, built, "q1", output.FormatHuman)
	if err == nil || !errors.Is(err, ErrAlreadyReleased) {
		t.Errorf("expected ErrAlreadyReleased, got %v", err)
	}
}

func TestReleaseQuarantineNotFound(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(k8s.BuildScheme()).Build()
	built := &k8s.Built{Client: c, Namespace: "default"}
	err := releaseQuarantine(context.Background(), &bytes.Buffer{}, built, "missing", output.FormatHuman)
	if err == nil || !IsNotFoundError(err) {
		t.Errorf("expected not-found, got %v", err)
	}
}
