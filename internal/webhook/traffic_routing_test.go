/*
Copyright 2026 Cloudaura sp. z o.o.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- Traffic Routing Webhook Tests ---

// TestTrafficRouting_InterceptAnnotation_Pod verifies that the webhook
// intercepts Pod CREATE requests for pods with panoptium.io/intercept=true.
func TestTrafficRouting_InterceptAnnotation_True(t *testing.T) {
	m := &TrafficRoutingMutator{
		GatewayAddress: "panoptium-gateway.panoptium-system.svc.cluster.local:8443",
		EnvoyImage:     "envoyproxy/envoy:v1.30-latest",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "routed-pod",
			Namespace: "default",
			Annotations: map[string]string{
				InterceptAnnotation: "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "app:latest"},
			},
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}

	// Default mode is sidecar; verify sidecar was injected
	hasSidecar := false
	for _, c := range pod.Spec.Containers {
		if c.Name == "panoptium-envoy-sidecar" {
			hasSidecar = true
			break
		}
	}
	if !hasSidecar {
		t.Fatal("expected Envoy sidecar container to be injected")
	}
}

// TestTrafficRouting_InterceptAnnotation_False verifies that pods with
// panoptium.io/intercept=false are skipped.
func TestTrafficRouting_InterceptAnnotation_False(t *testing.T) {
	m := &TrafficRoutingMutator{
		GatewayAddress: "panoptium-gateway:8443",
		EnvoyImage:     "envoyproxy/envoy:v1.30-latest",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "skip-pod",
			Namespace: "default",
			Annotations: map[string]string{
				InterceptAnnotation: "false",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "app:latest"},
			},
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}

	// Should NOT inject anything
	if len(pod.Spec.Containers) != 1 {
		t.Errorf("expected 1 container (no sidecar), got %d", len(pod.Spec.Containers))
	}
	if len(pod.Spec.InitContainers) != 0 {
		t.Errorf("expected 0 init containers, got %d", len(pod.Spec.InitContainers))
	}
}

// TestTrafficRouting_SidecarMode verifies Envoy sidecar injection with
// ExtProc configuration pointing to the gateway.
func TestTrafficRouting_SidecarMode(t *testing.T) {
	m := &TrafficRoutingMutator{
		GatewayAddress: "panoptium-gateway.panoptium-system.svc.cluster.local:8443",
		EnvoyImage:     "envoyproxy/envoy:v1.30-latest",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidecar-pod",
			Namespace: "default",
			Annotations: map[string]string{
				InterceptAnnotation:     "true",
				InterceptModeAnnotation: "sidecar",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "app:latest"},
			},
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}

	// Verify Envoy sidecar container was injected
	var sidecar *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "panoptium-envoy-sidecar" {
			sidecar = &pod.Spec.Containers[i]
			break
		}
	}
	if sidecar == nil {
		t.Fatal("expected panoptium-envoy-sidecar container")
	}
	if sidecar.Image != "envoyproxy/envoy:v1.30-latest" {
		t.Errorf("expected envoy image, got %q", sidecar.Image)
	}

	// Verify iptables init container was injected
	var initContainer *corev1.Container
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == "panoptium-iptables" {
			initContainer = &pod.Spec.InitContainers[i]
			break
		}
	}
	if initContainer == nil {
		t.Fatal("expected panoptium-iptables init container for traffic interception")
	}
}

// TestTrafficRouting_ProxyMode verifies HTTPS_PROXY/HTTP_PROXY env var injection.
func TestTrafficRouting_ProxyMode(t *testing.T) {
	m := &TrafficRoutingMutator{
		GatewayAddress: "panoptium-gateway.panoptium-system.svc.cluster.local:8443",
		EnvoyImage:     "envoyproxy/envoy:v1.30-latest",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-pod",
			Namespace: "default",
			Annotations: map[string]string{
				InterceptAnnotation:     "true",
				InterceptModeAnnotation: "proxy",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "app:latest"},
			},
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}

	// Verify NO sidecar was injected (proxy mode doesn't need one)
	for _, c := range pod.Spec.Containers {
		if c.Name == "panoptium-envoy-sidecar" {
			t.Fatal("expected no Envoy sidecar in proxy mode")
		}
	}

	// Verify HTTPS_PROXY and HTTP_PROXY env vars were added to agent containers
	mainContainer := pod.Spec.Containers[0]
	hasHTTPS := false
	hasHTTP := false
	for _, env := range mainContainer.Env {
		if env.Name == "HTTPS_PROXY" {
			hasHTTPS = true
			if env.Value != "http://panoptium-gateway.panoptium-system.svc.cluster.local:8443" {
				t.Errorf("unexpected HTTPS_PROXY value: %q", env.Value)
			}
		}
		if env.Name == "HTTP_PROXY" {
			hasHTTP = true
		}
	}
	if !hasHTTPS {
		t.Fatal("expected HTTPS_PROXY env var in proxy mode")
	}
	if !hasHTTP {
		t.Fatal("expected HTTP_PROXY env var in proxy mode")
	}
}

// TestTrafficRouting_NoAnnotation verifies that pods without the
// intercept annotation are not modified.
func TestTrafficRouting_NoAnnotation(t *testing.T) {
	m := &TrafficRoutingMutator{
		GatewayAddress: "panoptium-gateway:8443",
		EnvoyImage:     "envoyproxy/envoy:v1.30-latest",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-annotation-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "app:latest"},
			},
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}

	if len(pod.Spec.Containers) != 1 {
		t.Errorf("expected 1 container (untouched), got %d", len(pod.Spec.Containers))
	}
}

// TestTrafficRouting_DefaultModeIsSidecar verifies that when no intercept-mode
// annotation is present but intercept is true, the default mode is sidecar.
func TestTrafficRouting_DefaultModeIsSidecar(t *testing.T) {
	m := &TrafficRoutingMutator{
		GatewayAddress: "panoptium-gateway:8443",
		EnvoyImage:     "envoyproxy/envoy:v1.30-latest",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-mode-pod",
			Namespace: "default",
			Annotations: map[string]string{
				InterceptAnnotation: "true",
				// No intercept-mode annotation -> should default to sidecar
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "app:latest"},
			},
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}

	hasSidecar := false
	for _, c := range pod.Spec.Containers {
		if c.Name == "panoptium-envoy-sidecar" {
			hasSidecar = true
		}
	}
	if !hasSidecar {
		t.Fatal("expected sidecar injection when intercept-mode not specified (default is sidecar)")
	}
}

// TestTrafficRouting_ExcludedNamespace verifies that pods in excluded
// namespaces are not modified even with intercept=true.
func TestTrafficRouting_ExcludedNamespace(t *testing.T) {
	m := &TrafficRoutingMutator{
		GatewayAddress:     "panoptium-gateway:8443",
		EnvoyImage:         "envoyproxy/envoy:v1.30-latest",
		ExcludedNamespaces: []string{"kube-system", "panoptium-system"},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-pod",
			Namespace: "kube-system",
			Annotations: map[string]string{
				InterceptAnnotation: "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "app:latest"},
			},
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}

	if len(pod.Spec.Containers) != 1 {
		t.Errorf("expected 1 container in excluded namespace, got %d", len(pod.Spec.Containers))
	}
}

// TestTrafficRouting_NonPodObject verifies that the webhook rejects non-Pod objects.
func TestTrafficRouting_NonPodObject(t *testing.T) {
	m := &TrafficRoutingMutator{
		GatewayAddress: "panoptium-gateway:8443",
		EnvoyImage:     "envoyproxy/envoy:v1.30-latest",
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc",
			Namespace: "default",
		},
	}

	err := m.Default(context.Background(), svc)
	if err == nil {
		t.Fatal("expected error for non-Pod object")
	}
}
