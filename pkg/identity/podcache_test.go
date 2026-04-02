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

package identity

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestPodCache_SetAndGet verifies basic cache set and get operations.
func TestPodCache_SetAndGet(t *testing.T) {
	cache := NewPodCache()

	info := PodInfo{
		Name:           "my-pod",
		Namespace:      "default",
		Labels:         map[string]string{"app": "test"},
		ServiceAccount: "test-sa",
	}

	cache.Set("10.0.0.1", info)

	got, ok := cache.Get("10.0.0.1")
	if !ok {
		t.Fatal("Get() returned false, want true for existing entry")
	}
	if got.Name != "my-pod" {
		t.Errorf("Name = %q, want %q", got.Name, "my-pod")
	}
	if got.Namespace != "default" {
		t.Errorf("Namespace = %q, want %q", got.Namespace, "default")
	}
	if got.Labels["app"] != "test" {
		t.Errorf("Labels[app] = %q, want %q", got.Labels["app"], "test")
	}
	if got.ServiceAccount != "test-sa" {
		t.Errorf("ServiceAccount = %q, want %q", got.ServiceAccount, "test-sa")
	}
}

// TestPodCache_CacheMiss verifies Get returns false for unknown IPs.
func TestPodCache_CacheMiss(t *testing.T) {
	cache := NewPodCache()

	_, ok := cache.Get("10.0.0.99")
	if ok {
		t.Error("Get() returned true for non-existent entry, want false")
	}
}

// TestPodCache_Delete verifies cache entries can be removed.
func TestPodCache_Delete(t *testing.T) {
	cache := NewPodCache()

	cache.Set("10.0.0.1", PodInfo{Name: "pod-1", Namespace: "default"})
	cache.Delete("10.0.0.1")

	_, ok := cache.Get("10.0.0.1")
	if ok {
		t.Error("Get() returned true after Delete(), want false")
	}
}

// TestPodCache_DeleteNonExistent verifies deleting a non-existent entry is safe.
func TestPodCache_DeleteNonExistent(t *testing.T) {
	cache := NewPodCache()

	// Should not panic
	cache.Delete("10.0.0.99")
}

// TestPodCache_Overwrite verifies that setting an existing key overwrites it.
func TestPodCache_Overwrite(t *testing.T) {
	cache := NewPodCache()

	cache.Set("10.0.0.1", PodInfo{Name: "pod-v1", Namespace: "ns-1"})
	cache.Set("10.0.0.1", PodInfo{Name: "pod-v2", Namespace: "ns-2"})

	got, ok := cache.Get("10.0.0.1")
	if !ok {
		t.Fatal("Get() returned false after overwrite, want true")
	}
	if got.Name != "pod-v2" {
		t.Errorf("Name = %q, want %q after overwrite", got.Name, "pod-v2")
	}
	if got.Namespace != "ns-2" {
		t.Errorf("Namespace = %q, want %q after overwrite", got.Namespace, "ns-2")
	}
}

// TestPodCache_MultipleEntries verifies the cache handles multiple distinct entries.
func TestPodCache_MultipleEntries(t *testing.T) {
	cache := NewPodCache()

	cache.Set("10.0.0.1", PodInfo{Name: "pod-1", Namespace: "ns-1"})
	cache.Set("10.0.0.2", PodInfo{Name: "pod-2", Namespace: "ns-2"})
	cache.Set("10.0.0.3", PodInfo{Name: "pod-3", Namespace: "ns-3"})

	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		got, ok := cache.Get(ip)
		if !ok {
			t.Errorf("Get(%q) returned false, want true", ip)
			continue
		}
		wantName := "pod-" + string(rune('1'+i))
		if got.Name != wantName {
			t.Errorf("Get(%q).Name = %q, want %q", ip, got.Name, wantName)
		}
	}
}

// TestPodCacheInformer_AddEvent verifies that a pod Add event populates the cache.
func TestPodCacheInformer_AddEvent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "agent"},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "agent-sa",
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.1.1",
		},
	}

	client := fake.NewSimpleClientset(pod)
	cache := NewPodCache()
	informer := NewPodCacheInformer(client, cache)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go informer.Run(ctx)

	// Wait for the informer to sync
	if !informer.WaitForSync(ctx) {
		t.Fatal("Informer failed to sync")
	}

	// The cache should have the pod from the initial list
	got, ok := cache.Get("10.0.1.1")
	if !ok {
		t.Fatal("Get() returned false for pod added via informer, want true")
	}
	if got.Name != "test-pod" {
		t.Errorf("Name = %q, want %q", got.Name, "test-pod")
	}
	if got.Namespace != "test-ns" {
		t.Errorf("Namespace = %q, want %q", got.Namespace, "test-ns")
	}
	if got.Labels["app"] != "agent" {
		t.Errorf("Labels[app] = %q, want %q", got.Labels["app"], "agent")
	}
	if got.ServiceAccount != "agent-sa" {
		t.Errorf("ServiceAccount = %q, want %q", got.ServiceAccount, "agent-sa")
	}
}

// TestPodCacheInformer_DeleteEvent verifies that a pod Delete event removes
// the entry from the cache.
func TestPodCacheInformer_DeleteEvent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "delete-me",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "agent"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.2.2",
		},
	}

	client := fake.NewSimpleClientset(pod)
	cache := NewPodCache()
	informer := NewPodCacheInformer(client, cache)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go informer.Run(ctx)

	if !informer.WaitForSync(ctx) {
		t.Fatal("Informer failed to sync")
	}

	// Verify the pod is in cache
	_, ok := cache.Get("10.0.2.2")
	if !ok {
		t.Fatal("Get() returned false for initial pod, want true")
	}

	// Delete the pod
	err := client.CoreV1().Pods("test-ns").Delete(ctx, "delete-me", metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete pod: %v", err)
	}

	// Wait for the delete event to propagate
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := cache.Get("10.0.2.2"); !ok {
			return // Success: pod was removed from cache
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Error("Pod was not removed from cache after delete event")
}

// TestPodCacheInformer_UpdateEvent verifies that a pod Update event refreshes
// the cache entry (e.g., when a pod's IP changes or labels are updated).
func TestPodCacheInformer_UpdateEvent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "update-pod",
			Namespace: "test-ns",
			Labels:    map[string]string{"version": "v1"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.3.3",
		},
	}

	client := fake.NewSimpleClientset(pod)
	cache := NewPodCache()
	informer := NewPodCacheInformer(client, cache)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go informer.Run(ctx)

	if !informer.WaitForSync(ctx) {
		t.Fatal("Informer failed to sync")
	}

	// Update the pod's labels
	pod.Labels["version"] = "v2"
	_, err := client.CoreV1().Pods("test-ns").Update(ctx, pod, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update pod: %v", err)
	}

	// Wait for the update event to propagate
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, ok := cache.Get("10.0.3.3")
		if ok && got.Labels["version"] == "v2" {
			return // Success: cache was updated
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Error("Cache was not updated after pod update event")
}

// TestPodCacheInformer_UnfilteredFactory verifies that NewPodCacheInformer
// watches ALL pods regardless of labels (no label selector filter).
// After this refactor, the informer must use NewSharedInformerFactory (unfiltered)
// instead of NewFilteredSharedInformerFactory with a label selector.
func TestPodCacheInformer_UnfilteredFactory(t *testing.T) {
	// Create a pod with standard app labels (no special monitoring label needed)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unlabeled-pod",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "agent"},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "agent-sa",
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.4.1",
		},
	}

	client := fake.NewSimpleClientset(pod)
	cache := NewPodCache()
	informer := NewPodCacheInformer(client, cache)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go informer.Run(ctx)

	if !informer.WaitForSync(ctx) {
		t.Fatal("Informer failed to sync")
	}

	// The unfiltered informer should cache all pods
	got, ok := cache.Get("10.0.4.1")
	if !ok {
		t.Fatal("Get() returned false for pod without monitored label; " +
			"informer must be unfiltered to cache all pods")
	}
	if got.Name != "unlabeled-pod" {
		t.Errorf("Name = %q, want %q", got.Name, "unlabeled-pod")
	}
	if got.Namespace != "test-ns" {
		t.Errorf("Namespace = %q, want %q", got.Namespace, "test-ns")
	}
	if got.Labels["app"] != "agent" {
		t.Errorf("Labels[app] = %q, want %q", got.Labels["app"], "agent")
	}
	if got.ServiceAccount != "agent-sa" {
		t.Errorf("ServiceAccount = %q, want %q", got.ServiceAccount, "agent-sa")
	}
}

// TestPodCacheInformer_CachesAllPods verifies that pods with different label
// sets are all cached by the unfiltered informer.
func TestPodCacheInformer_CachesAllPods(t *testing.T) {
	// Pod with app label
	podLabeled := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "labeled-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "agent"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.5.1",
		},
	}

	// Pod with different labels
	podUnlabeled := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bare-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "worker"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.5.2",
		},
	}

	client := fake.NewSimpleClientset(podLabeled, podUnlabeled)
	cache := NewPodCache()
	informer := NewPodCacheInformer(client, cache)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go informer.Run(ctx)

	if !informer.WaitForSync(ctx) {
		t.Fatal("Informer failed to sync")
	}

	// Both pods should be cached
	if _, ok := cache.Get("10.0.5.1"); !ok {
		t.Error("labeled pod not in cache; informer should cache all pods")
	}
	if _, ok := cache.Get("10.0.5.2"); !ok {
		t.Error("unlabeled pod not in cache; informer must be unfiltered")
	}
}

// TestPodCacheInformer_PodWithNoIP verifies that pods without an IP
// (e.g., Pending pods) are not added to the cache.
func TestPodCacheInformer_PodWithNoIP(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-pod",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "agent"},
		},
		Status: corev1.PodStatus{
			PodIP: "", // No IP assigned yet
		},
	}

	client := fake.NewSimpleClientset(pod)
	cache := NewPodCache()
	informer := NewPodCacheInformer(client, cache)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go informer.Run(ctx)

	if !informer.WaitForSync(ctx) {
		t.Fatal("Informer failed to sync")
	}

	// Cache should not contain any entries for pods without IPs
	if _, ok := cache.Get(""); ok {
		t.Error("Get(\"\") returned true for pod with no IP, want false")
	}
}
