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
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PodInfo contains resolved pod metadata stored in the IP cache.
type PodInfo struct {
	// Name is the Kubernetes pod name.
	Name string

	// Namespace is the Kubernetes namespace.
	Namespace string

	// UID is the Kubernetes pod UID for unambiguous identification.
	UID string

	// Labels contains the pod's Kubernetes labels.
	Labels map[string]string

	// ServiceAccount is the pod's service account name.
	ServiceAccount string
}

// PodCache is a thread-safe in-memory cache mapping pod IPs to pod metadata.
type PodCache struct {
	mu    sync.RWMutex
	items map[string]PodInfo
}

// NewPodCache creates a new empty PodCache.
func NewPodCache() *PodCache {
	return &PodCache{
		items: make(map[string]PodInfo),
	}
}

// Get retrieves pod info for the given IP. Returns false if not found.
func (c *PodCache) Get(ip string) (PodInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, ok := c.items[ip]
	return info, ok
}

// Set adds or updates a pod info entry for the given IP.
func (c *PodCache) Set(ip string, info PodInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[ip] = info
}

// Delete removes a pod info entry for the given IP.
func (c *PodCache) Delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, ip)
}

// PodCacheInformer watches Kubernetes pods and keeps the PodCache in sync
// using a Kubernetes SharedInformer. It handles Add, Update, and Delete events
// to maintain an accurate pod IP to metadata mapping without per-request API calls.
type PodCacheInformer struct {
	client  kubernetes.Interface
	cache   *PodCache
	factory informers.SharedInformerFactory
	synced  []cache.InformerSynced
}

// MonitoredLabelSelector is the label selector used to filter watched pods.
// Only pods with panoptium.io/monitored=true are cached.
const MonitoredLabelSelector = "panoptium.io/monitored=true"

// NewPodCacheInformer creates a new PodCacheInformer that watches pods with
// the panoptium.io/monitored=true label across all namespaces and keeps the
// PodCache in sync. This filtered informer ensures only enrolled pods are
// watched and cached, reducing memory usage on large clusters.
func NewPodCacheInformer(client kubernetes.Interface, podCache *PodCache) *PodCacheInformer {
	factory := informers.NewFilteredSharedInformerFactory(client, 0, metav1.NamespaceAll,
		func(opts *metav1.ListOptions) {
			opts.LabelSelector = MonitoredLabelSelector
		},
	)

	pci := &PodCacheInformer{
		client:  client,
		cache:   podCache,
		factory: factory,
	}

	podInformer := factory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			pci.onPodAdd(pod)
		},
		UpdateFunc: func(_, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			pci.onPodUpdate(pod)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				// Handle deleted final state unknown
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				pod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					return
				}
			}
			pci.onPodDelete(pod)
		},
	})

	pci.synced = append(pci.synced, podInformer.HasSynced)

	return pci
}

// Run starts the informer factory and blocks until the context is cancelled.
func (pci *PodCacheInformer) Run(ctx context.Context) {
	pci.factory.Start(ctx.Done())
	<-ctx.Done()
}

// WaitForSync blocks until the informer's cache has synced or the context is cancelled.
// Returns true if the cache successfully synced, false if the context was cancelled.
func (pci *PodCacheInformer) WaitForSync(ctx context.Context) bool {
	return cache.WaitForCacheSync(ctx.Done(), pci.synced...)
}

// onPodAdd handles a pod Add event by adding the pod's IP to the cache.
func (pci *PodCacheInformer) onPodAdd(pod *corev1.Pod) {
	if pod.Status.PodIP == "" {
		return
	}

	pci.cache.Set(pod.Status.PodIP, podInfoFromPod(pod))
}

// onPodUpdate handles a pod Update event by refreshing the cache entry.
func (pci *PodCacheInformer) onPodUpdate(pod *corev1.Pod) {
	if pod.Status.PodIP == "" {
		return
	}

	pci.cache.Set(pod.Status.PodIP, podInfoFromPod(pod))
}

// onPodDelete handles a pod Delete event by removing the cache entry.
func (pci *PodCacheInformer) onPodDelete(pod *corev1.Pod) {
	if pod.Status.PodIP == "" {
		return
	}

	pci.cache.Delete(pod.Status.PodIP)
}

// podInfoFromPod extracts PodInfo from a Kubernetes Pod object.
func podInfoFromPod(pod *corev1.Pod) PodInfo {
	labels := make(map[string]string, len(pod.Labels))
	for k, v := range pod.Labels {
		labels[k] = v
	}

	return PodInfo{
		Name:           pod.Name,
		Namespace:      pod.Namespace,
		UID:            string(pod.UID),
		Labels:         labels,
		ServiceAccount: pod.Spec.ServiceAccountName,
	}
}
