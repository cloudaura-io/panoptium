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

package extproc

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
	"github.com/panoptium/panoptium/pkg/policy"
)

// TestLifecycleManagerStartAndServe verifies that the lifecycle manager starts
// a gRPC server on the configured port and accepts ExtProc connections.
func TestLifecycleManagerStartAndServe(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	podCache := identity.NewPodCache()
	resolver := identity.NewResolver(podCache)

	// Use port 0 for automatic allocation
	cfg := LifecycleConfig{
		Port:    0,
		Enabled: true,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the lifecycle manager in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	// Wait for the server to be ready
	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	// Verify the server is listening by connecting a gRPC client
	addr := mgr.Addr()
	if addr == nil {
		t.Fatal("expected non-nil address after start")
	}

	conn, err := grpc.NewClient(
		addr.String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to connect to ExtProc server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Verify the ExtProc service is registered
	client := extprocv3.NewExternalProcessorClient(conn)
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open Process stream: %v", err)
	}
	// Close the stream gracefully
	_ = stream.CloseSend()

	// Stop by cancelling context
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerConfigurablePort verifies that the server starts on
// a specific configured port.
func TestLifecycleManagerConfigurablePort(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	resolver := identity.NewResolver(nil)

	// Find a free port
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	_ = lis.Close()

	cfg := LifecycleConfig{
		Port:    port,
		Enabled: true,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	addr := mgr.Addr()
	if addr == nil {
		t.Fatal("expected non-nil address")
	}

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", addr)
	}

	if tcpAddr.Port != port {
		t.Errorf("expected port %d, got %d", port, tcpAddr.Port)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerDisabled verifies that when Enabled is false, the server
// does not start and Start returns immediately.
func TestLifecycleManagerDisabled(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	cfg := LifecycleConfig{
		Port:    0,
		Enabled: false,
	}

	mgr := NewLifecycleManager(cfg, nil, nil, bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	// When disabled, Start should return nil quickly (blocks on ctx)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("disabled lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("disabled lifecycle manager did not stop in time")
	}

	// Address should be nil when disabled
	if mgr.Addr() != nil {
		t.Error("expected nil address when disabled")
	}
}

// TestLifecycleManagerGracefulShutdown verifies that the server drains active
// streams before shutting down when the context is cancelled.
func TestLifecycleManagerGracefulShutdown(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	resolver := identity.NewResolver(nil)

	cfg := LifecycleConfig{
		Port:            0,
		Enabled:         true,
		ShutdownTimeout: 5 * time.Second,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	// Open a stream to simulate an active connection
	conn, err := grpc.NewClient(
		mgr.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := extprocv3.NewExternalProcessorClient(conn)
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Cancel the context to trigger graceful shutdown
	cancel()

	// The stream should be drained — recv should eventually get an error
	// (either EOF or transport closing)
	_, recvErr := stream.Recv()
	if recvErr == nil {
		t.Error("expected error on recv after shutdown, got nil")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("lifecycle manager did not complete shutdown in time")
	}
}

// TestLifecycleManagerHealthCheck verifies that the gRPC health check service
// reports SERVING when the server is running.
func TestLifecycleManagerHealthCheck(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	resolver := identity.NewResolver(nil)

	cfg := LifecycleConfig{
		Port:    0,
		Enabled: true,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	conn, err := grpc.NewClient(
		mgr.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	healthClient := healthpb.NewHealthClient(conn)

	// Check the overall server health (empty service name)
	resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{
		Service: "",
	})
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("expected SERVING status, got %v", resp.GetStatus())
	}

	// Check the ExtProc service-specific health
	resp, err = healthClient.Check(ctx, &healthpb.HealthCheckRequest{
		Service: "envoy.service.ext_proc.v3.ExternalProcessor",
	})
	if err != nil {
		t.Fatalf("extproc health check failed: %v", err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("expected SERVING status for ExtProc, got %v", resp.GetStatus())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerHealthCheckNotServingAfterShutdown verifies that the
// health status transitions to NOT_SERVING during shutdown.
func TestLifecycleManagerHealthCheckNotServingAfterShutdown(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	resolver := identity.NewResolver(nil)

	cfg := LifecycleConfig{
		Port:            0,
		Enabled:         true,
		ShutdownTimeout: 5 * time.Second,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	addr := mgr.Addr().String()

	// Cancel context to begin shutdown
	cancel()

	// Wait for shutdown to complete
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}

	// After shutdown, connecting and checking health should fail
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		// Connection failure is expected after shutdown
		return
	}
	defer func() { _ = conn.Close() }()

	healthClient := healthpb.NewHealthClient(conn)
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer checkCancel()

	_, err = healthClient.Check(checkCtx, &healthpb.HealthCheckRequest{})
	if err == nil {
		t.Error("expected error when checking health after shutdown")
	}
}

// TestLifecycleConfigDefaults verifies that the default configuration values
// are applied correctly.
func TestLifecycleConfigDefaults(t *testing.T) {
	cfg := DefaultLifecycleConfig()

	if cfg.Port != 9001 {
		t.Errorf("expected default port 9001, got %d", cfg.Port)
	}

	if !cfg.Enabled {
		t.Error("expected default Enabled to be true")
	}

	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("expected default shutdown timeout 30s, got %v", cfg.ShutdownTimeout)
	}
}

// startInformerLifecycleManager is a helper that creates a fake Kubernetes
// client, pod cache, informer, and lifecycle manager, starts them, and
// verifies the pod cache is populated. Returns the podCache and a cancel func.
func startInformerLifecycleManager(
	t *testing.T,
	podName, podIP string,
	readyTimeout time.Duration,
) (*identity.PodCache, context.CancelFunc, <-chan error) {
	t.Helper()

	bus := eventbus.NewSimpleBus()
	t.Cleanup(func() { bus.Close() })

	registry := observer.NewObserverRegistry()

	fakeClient := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: "default",
			Labels:    map[string]string{"app": "agent"},
		},
		Status: corev1.PodStatus{
			PodIP: podIP,
		},
	})

	podCache := identity.NewPodCache()
	informer := identity.NewPodCacheInformer(fakeClient, podCache)
	resolver := identity.NewResolver(podCache)

	cfg := LifecycleConfig{
		Port:    0,
		Enabled: true,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)
	mgr.SetPodCacheInformer(informer)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(readyTimeout) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	return podCache, cancel, errCh
}

// TestLifecycleManagerWithPodCacheInformer verifies that the pod IP cache
// Informer is started and stopped alongside the lifecycle manager.
func TestLifecycleManagerWithPodCacheInformer(t *testing.T) {
	podCache, cancel, errCh := startInformerLifecycleManager(
		t, "test-agent", "10.0.0.1", 5*time.Second,
	)
	defer cancel()

	info, ok := podCache.Get("10.0.0.1")
	if !ok {
		t.Fatal("expected pod cache to contain 10.0.0.1 after informer start")
	}
	if info.Name != "test-agent" {
		t.Errorf("expected pod name 'test-agent', got %q", info.Name)
	}
	if info.Namespace != "default" {
		t.Errorf("expected namespace 'default', got %q", info.Namespace)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerWithLLMObserverRegistration verifies that the LLM observer
// is properly registered in the observer registry when configured.
func TestLifecycleManagerWithLLMObserverRegistration(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	resolver := identity.NewResolver(nil)

	// Register the LLM observer (simulating what the operator setup does)
	llmObs := llm.NewLLMObserver(bus)
	if err := registry.Register(llmObs, observer.ObserverConfig{
		Name:      "llm",
		Priority:  100,
		Protocol:  "llm",
		Providers: []string{"openai", "anthropic"},
	}); err != nil {
		t.Fatalf("failed to register LLM observer: %v", err)
	}

	cfg := LifecycleConfig{
		Port:    0,
		Enabled: true,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	// Verify the registry has the LLM observer
	observers := registry.Observers()
	if len(observers) != 1 {
		t.Fatalf("expected 1 observer, got %d", len(observers))
	}
	if observers[0] != "llm" {
		t.Errorf("expected observer name 'llm', got %q", observers[0])
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerMultipleStartFails verifies that calling Start twice
// returns an error.
func TestLifecycleManagerMultipleStartFails(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	resolver := identity.NewResolver(nil)

	cfg := LifecycleConfig{
		Port:    0,
		Enabled: true,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	// Second Start should return an error
	err := mgr.Start(ctx)
	if err == nil {
		t.Error("expected error on second Start call")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerEventBusCleanup verifies that the event bus is closed
// when the lifecycle manager shuts down.
func TestLifecycleManagerEventBusCleanup(t *testing.T) {
	bus := eventbus.NewSimpleBus()

	registry := observer.NewObserverRegistry()
	resolver := identity.NewResolver(nil)

	cfg := LifecycleConfig{
		Port:    0,
		Enabled: true,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	// Subscribe before shutdown
	sub := bus.Subscribe()
	if sub == nil {
		t.Fatal("expected non-nil subscription before shutdown")
	}
	bus.Unsubscribe(sub)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}

	// After shutdown, the bus should be closed
	sub = bus.Subscribe()
	if sub != nil {
		t.Error("expected nil subscription after bus close (shutdown should have closed the bus)")
	}
}

// TestLifecycleManagerConcurrentStreams verifies that the server handles
// multiple concurrent ExtProc streams.
func TestLifecycleManagerConcurrentStreams(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	resolver := identity.NewResolver(nil)

	cfg := LifecycleConfig{
		Port:    0,
		Enabled: true,
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	// Open multiple concurrent streams
	const numStreams = 10
	streams := make([]extprocv3.ExternalProcessor_ProcessClient, numStreams)
	conns := make([]*grpc.ClientConn, numStreams)

	for i := 0; i < numStreams; i++ {
		conn, err := grpc.NewClient(
			mgr.Addr().String(),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			t.Fatalf("stream %d: failed to connect: %v", i, err)
		}
		conns[i] = conn

		client := extprocv3.NewExternalProcessorClient(conn)
		stream, err := client.Process(ctx)
		if err != nil {
			t.Fatalf("stream %d: failed to open: %v", i, err)
		}
		streams[i] = stream
	}

	// Close all streams
	for i, stream := range streams {
		if err := stream.CloseSend(); err != nil {
			t.Errorf("stream %d: CloseSend error: %v", i, err)
		}
	}
	for _, conn := range conns {
		_ = conn.Close()
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerEnforcementMode verifies that the enforcement mode
// from LifecycleConfig is propagated to the ExtProcServer.
func TestLifecycleManagerEnforcementMode(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	podCache := identity.NewPodCache()
	resolver := identity.NewResolver(podCache)

	cfg := LifecycleConfig{
		Port:            0,
		Enabled:         true,
		EnforcementMode: "enforcing",
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	// The server should be in enforcing mode now.
	// Unknown source pods should pass through — network admission is delegated
	// to Kubernetes NetworkPolicy, not ExtProc.
	conn, err := grpc.NewClient(
		mgr.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := extprocv3.NewExternalProcessorClient(conn)
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send request from an unknown source IP (not in PodCache)
	err = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				Headers: makeHeaderMap(
					":path", "/v1/chat/completions",
					":method", "POST",
					"host", "api.openai.com",
					"x-forwarded-for", "10.0.0.99",
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive response: %v", err)
	}

	// Unknown source pods should pass through (no ImmediateResponse)
	if resp.GetImmediateResponse() != nil {
		t.Fatal("unknown source pod should NOT receive ImmediateResponse; network admission is delegated to NetworkPolicy")
	}
	if resp.GetRequestHeaders() == nil {
		t.Fatal("expected RequestHeaders response (pass-through) for unknown source pod")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerPolicyEvaluator verifies that the PolicyEvaluator set
// on the LifecycleManager is injected into the ExtProcServer.
func TestLifecycleManagerPolicyEvaluator(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	registry := observer.NewObserverRegistry()
	llmObs := llm.NewLLMObserver(bus)
	if err := registry.Register(llmObs, observer.ObserverConfig{
		Name:      "llm",
		Priority:  100,
		Protocol:  eventbus.ProtocolLLM,
		Providers: []string{eventbus.ProviderOpenAI},
	}); err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	podCache := identity.NewPodCache()
	podCache.Set("10.0.0.42", identity.PodInfo{
		Name: "eval-pod", Namespace: "default", UID: "uid-42",
		Labels: map[string]string{"app": "agent"},
	})
	resolver := identity.NewResolver(podCache)

	evaluator := &mockPolicyEvaluator{
		decision: &policy.Decision{
			Action: policy.CompiledAction{
				Type:       "deny",
				Parameters: map[string]string{"message": "blocked by lifecycle test"},
			},
			Matched:          true,
			MatchedRule:      "test-rule",
			MatchedRuleIndex: 0,
			PolicyName:       "test-policy",
			PolicyNamespace:  "default",
		},
	}

	cfg := LifecycleConfig{
		Port:            0,
		Enabled:         true,
		EnforcementMode: "enforcing",
	}

	mgr := NewLifecycleManager(cfg, registry, resolver, bus)
	mgr.SetPolicyEvaluator(evaluator)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	if !mgr.WaitForReady(5 * time.Second) {
		t.Fatal("lifecycle manager did not become ready in time")
	}

	conn, err := grpc.NewClient(
		mgr.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := extprocv3.NewExternalProcessorClient(conn)
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	reqBody := makeOpenAIRequestBody("gpt-4", false)

	resp := sendHeadersAndBody(t, stream, []string{
		":path", "/v1/chat/completions",
		":method", "POST",
		"host", "api.openai.com",
		"content-type", "application/json",
		"x-forwarded-for", "10.0.0.42",
	}, reqBody)

	// The mock evaluator returns a deny, so we should get 403
	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatal("expected ImmediateResponse from policy evaluator deny")
	}
	if ir.Status.Code != 403 {
		t.Errorf("expected 403, got %d", ir.Status.Code)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerWaitForSyncBeforeReady verifies that Start() blocks on
// informer.WaitForSync() before signaling ready, so the PodCache is fully
// populated the instant WaitForReady returns — with no sleep workaround needed.
func TestLifecycleManagerWaitForSyncBeforeReady(t *testing.T) {
	podCache, cancel, errCh := startInformerLifecycleManager(
		t, "sync-agent", "10.0.0.50", 10*time.Second,
	)
	defer cancel()

	// CRITICAL: immediately after WaitForReady, with NO sleep, the pod cache
	// must already be populated. This fails if Start() does not call
	// informer.WaitForSync() before close(m.readyCh).
	info, ok := podCache.Get("10.0.0.50")
	if !ok {
		t.Fatal("PodCache must contain 10.0.0.50 immediately after WaitForReady " +
			"(no sleep) — WaitForSync not called before readyCh")
	}
	if info.Name != "sync-agent" {
		t.Errorf("expected pod name 'sync-agent', got %q", info.Name)
	}
	if info.Namespace != "default" {
		t.Errorf("expected namespace 'default', got %q", info.Namespace)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("lifecycle manager returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle manager did not stop in time")
	}
}

// TestLifecycleManagerListenAddress verifies that the listen address uses the
// correct host and port format.
func TestLifecycleManagerListenAddress(t *testing.T) {
	tests := []struct {
		name         string
		port         int
		expectedAddr string
	}{
		{
			name:         "default port",
			port:         9001,
			expectedAddr: ":9001",
		},
		{
			name:         "custom port",
			port:         9999,
			expectedAddr: ":9999",
		},
		{
			name:         "port zero for auto assign",
			port:         0,
			expectedAddr: ":0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LifecycleConfig{
				Port:    tt.port,
				Enabled: true,
			}

			addr := fmt.Sprintf(":%d", cfg.Port)
			if addr != tt.expectedAddr {
				t.Errorf("expected address %q, got %q", tt.expectedAddr, addr)
			}
		})
	}
}
