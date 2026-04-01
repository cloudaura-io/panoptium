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
	"k8s.io/apimachinery/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

const (
	// MonitoredLabel is the label added to pods enrolled in Panoptium monitoring.
	MonitoredLabel = "panoptium.io/monitored"

	// InjectSidecarAnnotation triggers sidecar container injection when present.
	InjectSidecarAnnotation = "panoptium.io/inject-sidecar"
)

// PodMutator mutates pods on creation to enroll them in Panoptium monitoring.
// It adds the panoptium.io/monitored label to pods matching any PanoptiumPolicy
// targetSelector and optionally injects a sidecar container.
type PodMutator struct {
	Client client.Client

	// ExcludedNamespaces is the list of namespaces to skip during mutation.
	// Defaults to ["kube-system"].
	ExcludedNamespaces []string

	// SidecarImage is the container image for the injected sidecar.
	SidecarImage string
}

// SetupWebhookWithManager registers the mutating webhook with the manager.
func (m *PodMutator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&corev1.Pod{}).
		WithDefaulter(m).
		Complete()
}

// Default implements admission.CustomDefaulter for pod mutation.
func (m *PodMutator) Default(ctx context.Context, obj runtime.Object) error {
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

	// Skip pods already labeled
	if pod.Labels != nil && pod.Labels[MonitoredLabel] == "true" {
		return nil
	}

	// Check if any PanoptiumPolicy matches this pod.
	// Fail-closed: if the policy check fails, block the operation rather than
	// allowing unmonitored pods through. This is consistent with failurePolicy=Fail
	// on the webhook configuration.
	matches, err := m.matchesPanoptiumPolicy(ctx, pod)
	if err != nil {
		logger.Error(err, "Failed to check policy match, blocking pod (fail-closed)", "pod", pod.Name)
		return fmt.Errorf("failed to check policy match for pod %s/%s: %w (fail-closed)", pod.Namespace, pod.Name, err)
	}

	if !matches {
		return nil
	}

	// Add monitored label
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels[MonitoredLabel] = "true"
	logger.Info("Enrolled pod in Panoptium monitoring",
		"pod", pod.Name, "namespace", pod.Namespace)

	// Inject sidecar if annotation is present
	if pod.Annotations != nil && pod.Annotations[InjectSidecarAnnotation] == "true" {
		m.injectSidecar(pod)
		logger.Info("Injected sidecar container",
			"pod", pod.Name, "namespace", pod.Namespace)
	}

	return nil
}

// matchesPanoptiumPolicy checks if the pod matches any PanoptiumPolicy targetSelector.
// Returns an error if the check cannot be performed (fail-closed).
func (m *PodMutator) matchesPanoptiumPolicy(ctx context.Context, pod *corev1.Pod) (bool, error) {
	if m.Client == nil {
		return false, fmt.Errorf("kubernetes client is nil, cannot verify policy match")
	}

	policies := &panoptiumiov1alpha1.PanoptiumPolicyList{}
	if err := m.Client.List(ctx, policies, client.InNamespace(pod.Namespace)); err != nil {
		return false, err
	}

	for _, policy := range policies.Items {
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.TargetSelector)
		if err != nil {
			continue
		}
		if selector.Matches(labels.Set(pod.Labels)) {
			return true, nil
		}
	}

	return false, nil
}

// injectSidecar adds the Panoptium sidecar container to the pod.
func (m *PodMutator) injectSidecar(pod *corev1.Pod) {
	image := m.SidecarImage
	if image == "" {
		image = "panoptium/sidecar:latest"
	}

	sidecar := corev1.Container{
		Name:  "panoptium-sidecar",
		Image: image,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("50m"),
				corev1.ResourceMemory: resource.MustParse("32Mi"),
			},
		},
	}

	pod.Spec.Containers = append(pod.Spec.Containers, sidecar)
}

// excludedNamespaces returns the list of excluded namespaces, defaulting to kube-system.
func (m *PodMutator) excludedNamespaces() []string {
	if len(m.ExcludedNamespaces) > 0 {
		return m.ExcludedNamespaces
	}
	return []string{"kube-system"}
}
