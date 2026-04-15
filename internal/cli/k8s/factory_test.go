package k8s

import (
	"os"
	"path/filepath"
	"testing"
)

const fakeKubeconfig = `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: fake-cluster
contexts:
- context:
    cluster: fake-cluster
    namespace: my-ns
    user: fake-user
  name: fake-ctx
current-context: fake-ctx
users:
- name: fake-user
  user:
    token: fake-token
`

func writeKubeconfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(fakeKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewFactoryLoadsKubeconfigAndNamespace(t *testing.T) {
	path := writeKubeconfig(t)
	factory := NewFactory(&Flags{Kubeconfig: path})
	built, err := factory()
	if err != nil {
		t.Fatalf("factory build failed: %v", err)
	}
	if built.Client == nil {
		t.Error("Client should be non-nil")
	}
	if built.Namespace != "my-ns" {
		t.Errorf("Namespace=%q want my-ns (from kubeconfig current-context)", built.Namespace)
	}
}

func TestNewFactoryExplicitNamespaceOverridesKubeconfig(t *testing.T) {
	path := writeKubeconfig(t)
	factory := NewFactory(&Flags{Kubeconfig: path, Namespace: "override-ns"})
	built, err := factory()
	if err != nil {
		t.Fatalf("factory build failed: %v", err)
	}
	if built.Namespace != "override-ns" {
		t.Errorf("Namespace=%q want override-ns", built.Namespace)
	}
}

func TestNewFactoryAllNamespacesFlagIsPropagated(t *testing.T) {
	path := writeKubeconfig(t)
	factory := NewFactory(&Flags{Kubeconfig: path, AllNamespaces: true})
	built, err := factory()
	if err != nil {
		t.Fatal(err)
	}
	if !built.AllNamespaces {
		t.Error("AllNamespaces flag not propagated")
	}
}

func TestNewFactoryBadKubeconfigReturnsError(t *testing.T) {
	factory := NewFactory(&Flags{Kubeconfig: "/definitely/not/a/real/path.yaml"})
	_, err := factory()
	if err == nil {
		t.Fatal("expected error for missing kubeconfig, got nil")
	}
}
