package k8s

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

func TestBuildSchemeKnowsV1alpha1Kinds(t *testing.T) {
	s := BuildScheme()
	gvk := v1alpha1.GroupVersion.WithKind("AgentPolicy")
	if !s.Recognizes(gvk) {
		t.Errorf("scheme does not recognize %v", gvk)
	}
}

func TestFakeClientListsAgentPolicies(t *testing.T) {
	scheme := BuildScheme()
	obj := &v1alpha1.AgentPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj).Build()

	var list v1alpha1.AgentPolicyList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Errorf("expected 1 policy, got %d", len(list.Items))
	}
	if list.Items[0].Name != "p1" {
		t.Errorf("Name=%q want p1", list.Items[0].Name)
	}
}

func TestInterpretListErrorMapsKindErrors(t *testing.T) {
	err := errors.New(`no kind "AgentPolicy" is registered`)
	got := InterpretListError(err)
	if !errors.Is(got, ErrCRDNotFound) {
		t.Errorf("expected ErrCRDNotFound wrap, got %v", got)
	}
}

func TestInterpretListErrorPassesThroughOthers(t *testing.T) {
	err := errors.New("boom")
	got := InterpretListError(err)
	if errors.Is(got, ErrCRDNotFound) {
		t.Errorf("should not wrap unrelated errors: %v", got)
	}
}

func TestInterpretListErrorNil(t *testing.T) {
	if InterpretListError(nil) != nil {
		t.Error("nil in should be nil out")
	}
}
