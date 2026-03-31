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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// InterceptAnnotation controls whether traffic interception is enabled
	// for a pod. Set to "true" to enable, "false" to skip.
	InterceptAnnotation = "panoptium.io/intercept"

	// InterceptModeAnnotation selects the traffic interception method.
	// Supported values: "sidecar" (default), "proxy".
	InterceptModeAnnotation = "panoptium.io/intercept-mode"

	// envoySidecarContainerName is the name of the injected Envoy sidecar.
	envoySidecarContainerName = "panoptium-envoy-sidecar"

	// iptablesInitContainerName is the name of the iptables init container.
	iptablesInitContainerName = "panoptium-iptables"
)

// TrafficRoutingMutator is a MutatingAdmissionWebhook that intercepts Pod
// creation to inject traffic routing configuration. It supports two modes:
//   - sidecar: Inject an Envoy sidecar with ExtProc configuration pointing
//     to the Panoptium enforcement gateway, plus an iptables init container
//     for traffic interception.
//   - proxy: Set HTTPS_PROXY and HTTP_PROXY environment variables on agent
//     containers to route traffic through the gateway.
//
// The webhook respects the panoptium.io/intercept and
// panoptium.io/intercept-mode annotations on Pods.
type TrafficRoutingMutator struct {
	// GatewayAddress is the address of the Panoptium enforcement gateway
	// (e.g., "panoptium-gateway.panoptium-system.svc.cluster.local:8443").
	GatewayAddress string

	// EnvoyImage is the container image for the Envoy sidecar.
	EnvoyImage string

	// IptablesImage is the container image for the iptables init container.
	// Defaults to "panoptium/iptables-init:latest".
	IptablesImage string

	// ExcludedNamespaces is the list of namespaces to skip during mutation.
	ExcludedNamespaces []string
}

// Default implements admission.CustomDefaulter for traffic routing mutation.
func (m *TrafficRoutingMutator) Default(ctx context.Context, obj runtime.Object) error {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return fmt.Errorf("expected Pod but got %T", obj)
	}

	logger := log.FromContext(ctx)

	// Skip excluded namespaces
	for _, ns := range m.excludedNamespaces() {
		if pod.Namespace == ns {
			logger.V(1).Info("Skipping pod in excluded namespace",
				"pod", pod.Name, "namespace", pod.Namespace)
			return nil
		}
	}

	// Check intercept annotation
	if pod.Annotations == nil {
		return nil
	}
	intercept, exists := pod.Annotations[InterceptAnnotation]
	if !exists || intercept != "true" {
		return nil
	}

	// Determine interception mode
	mode := pod.Annotations[InterceptModeAnnotation]
	if mode == "" {
		mode = "sidecar" // default
	}

	switch mode {
	case "sidecar":
		m.injectEnvoySidecar(pod)
		m.injectIptablesInit(pod)
		logger.Info("Injected Envoy sidecar and iptables init container",
			"pod", pod.Name, "namespace", pod.Namespace)

	case "proxy":
		m.injectProxyEnvVars(pod)
		logger.Info("Injected HTTPS_PROXY/HTTP_PROXY env vars",
			"pod", pod.Name, "namespace", pod.Namespace)

	default:
		logger.Info("Unknown intercept mode, defaulting to sidecar",
			"mode", mode, "pod", pod.Name)
		m.injectEnvoySidecar(pod)
		m.injectIptablesInit(pod)
	}

	return nil
}

// injectEnvoySidecar adds an Envoy sidecar container with ExtProc
// configuration pointing to the Panoptium enforcement gateway.
func (m *TrafficRoutingMutator) injectEnvoySidecar(pod *corev1.Pod) {
	image := m.EnvoyImage
	if image == "" {
		image = "envoyproxy/envoy:v1.30-latest"
	}

	sidecar := corev1.Container{
		Name:  envoySidecarContainerName,
		Image: image,
		Args:  []string{"--config-path", "/etc/envoy/envoy.yaml", "--log-level", "info"},
		Ports: []corev1.ContainerPort{
			{
				Name:          "envoy-proxy",
				ContainerPort: 15001,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		Env: []corev1.EnvVar{
			{
				Name:  "PANOPTIUM_GATEWAY_ADDRESS",
				Value: m.GatewayAddress,
			},
		},
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
		},
	}

	pod.Spec.Containers = append(pod.Spec.Containers, sidecar)
}

// injectIptablesInit adds an init container that sets up iptables rules
// to redirect all outbound HTTP/HTTPS traffic through the Envoy sidecar.
func (m *TrafficRoutingMutator) injectIptablesInit(pod *corev1.Pod) {
	image := m.IptablesImage
	if image == "" {
		image = "panoptium/iptables-init:latest"
	}

	privileged := true
	initContainer := corev1.Container{
		Name:  iptablesInitContainerName,
		Image: image,
		Command: []string{
			"/bin/sh", "-c",
			"iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 15001 && " +
				"iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 15001",
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
		},
	}

	pod.Spec.InitContainers = append(pod.Spec.InitContainers, initContainer)
}

// injectProxyEnvVars adds HTTPS_PROXY and HTTP_PROXY environment variables
// to all agent containers, routing their HTTP traffic through the gateway.
func (m *TrafficRoutingMutator) injectProxyEnvVars(pod *corev1.Pod) {
	proxyURL := fmt.Sprintf("http://%s", m.GatewayAddress)

	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].Env = append(pod.Spec.Containers[i].Env,
			corev1.EnvVar{
				Name:  "HTTPS_PROXY",
				Value: proxyURL,
			},
			corev1.EnvVar{
				Name:  "HTTP_PROXY",
				Value: proxyURL,
			},
			corev1.EnvVar{
				Name:  "NO_PROXY",
				Value: "kubernetes.default.svc,localhost,127.0.0.1",
			},
		)
	}
}

// excludedNamespaces returns the list of excluded namespaces, defaulting
// to kube-system and panoptium-system.
func (m *TrafficRoutingMutator) excludedNamespaces() []string {
	if len(m.ExcludedNamespaces) > 0 {
		return m.ExcludedNamespaces
	}
	return []string{"kube-system", "panoptium-system"}
}
