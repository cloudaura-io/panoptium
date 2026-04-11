package k8s

import (
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

var ErrNoKubeconfig = errors.New("no kubeconfig found (tried --kubeconfig, $KUBECONFIG, ~/.kube/config, and in-cluster config)")

var ErrCRDNotFound = errors.New("panoptium v1alpha1 CRDs are not installed on the target cluster")

type Flags struct {
	Kubeconfig    string
	Context       string
	Namespace     string
	AllNamespaces bool
}

type Built struct {
	Client        client.Client
	Namespace     string
	AllNamespaces bool
}

type ClientFactory func() (*Built, error)

func NewFactory(flags *Flags) ClientFactory {
	return func() (*Built, error) {
		cfg, ns, err := loadConfig(flags)
		if err != nil {
			return nil, err
		}
		scheme := buildScheme()
		c, err := client.New(cfg, client.Options{Scheme: scheme})
		if err != nil {
			return nil, fmt.Errorf("build controller-runtime client: %w", err)
		}
		if flags.Namespace != "" {
			ns = flags.Namespace
		}
		return &Built{
			Client:        c,
			Namespace:     ns,
			AllNamespaces: flags.AllNamespaces,
		}, nil
	}
}

func BuildScheme() *runtime.Scheme {
	return buildScheme()
}

func buildScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1alpha1.AddToScheme(s))
	return s
}

func loadConfig(flags *Flags) (*rest.Config, string, error) {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	if flags.Kubeconfig != "" {
		loader.ExplicitPath = flags.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if flags.Context != "" {
		overrides.CurrentContext = flags.Context
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides)

	cfg, err := clientConfig.ClientConfig()
	if err != nil {
		inCluster, icErr := rest.InClusterConfig()
		if icErr != nil {
			return nil, "", fmt.Errorf("%w: %v", ErrNoKubeconfig, err)
		}
		return inCluster, "default", nil
	}

	ns, _, err := clientConfig.Namespace()
	if err != nil || ns == "" {
		ns = "default"
	}
	return cfg, ns, nil
}

func InterpretListError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, needle := range []string{"no kind", "no matches for kind", "could not find"} {
		if contains(msg, needle) {
			return fmt.Errorf("%w: %v", ErrCRDNotFound, err)
		}
	}
	return err
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
