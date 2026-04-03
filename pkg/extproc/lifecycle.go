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
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/extproc/enforce"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
)

const (
	// extProcServiceName is the gRPC service name for health checks.
	extProcServiceName = "envoy.service.ext_proc.v3.ExternalProcessor"
)

// LifecycleConfig holds configuration for the ExtProc server lifecycle.
type LifecycleConfig struct {
	// Port is the TCP port the ExtProc gRPC server listens on.
	// Use 0 for automatic port allocation.
	Port int

	// Enabled determines whether the ExtProc server should start.
	Enabled bool

	// ShutdownTimeout is the maximum time to wait for graceful shutdown.
	// If zero, defaults to 30 seconds.
	ShutdownTimeout time.Duration

	// EnforcementMode controls the enforcement behavior ("enforcing" or "audit").
	// In "enforcing" mode, policy decisions are actively enforced.
	// In "audit" mode, decisions are logged but traffic passes through.
	// Defaults to "audit" if empty.
	EnforcementMode string
}

// DefaultLifecycleConfig returns a LifecycleConfig with sensible defaults.
func DefaultLifecycleConfig() LifecycleConfig {
	return LifecycleConfig{
		Port:            9001,
		Enabled:         true,
		ShutdownTimeout: 30 * time.Second,
	}
}

// LifecycleManager manages the lifecycle of the ExtProc gRPC server,
// including startup, shutdown coordination, health checks, and the
// pod IP cache Informer.
type LifecycleManager struct {
	cfg      LifecycleConfig
	registry *observer.ObserverRegistry
	resolver *identity.Resolver
	bus      eventbus.EventBus

	informer        *identity.PodCacheInformer
	policyEvaluator PolicyEvaluator

	mu         sync.Mutex
	started    bool
	listener   net.Listener
	grpcServer *grpc.Server
	readyCh    chan struct{}
}

// NewLifecycleManager creates a new LifecycleManager with the given
// configuration and dependencies.
func NewLifecycleManager(
	cfg LifecycleConfig,
	registry *observer.ObserverRegistry,
	resolver *identity.Resolver,
	bus eventbus.EventBus,
) *LifecycleManager {
	return &LifecycleManager{
		cfg:      cfg,
		registry: registry,
		resolver: resolver,
		bus:      bus,
		readyCh:  make(chan struct{}),
	}
}

// SetPodCacheInformer sets the pod cache Informer that will be started
// alongside the ExtProc server. The Informer watches Kubernetes pods
// and keeps the pod IP cache in sync.
func (m *LifecycleManager) SetPodCacheInformer(informer *identity.PodCacheInformer) {
	m.informer = informer
}

// SetPolicyEvaluator configures the policy evaluator that will be injected
// into the ExtProcServer at startup. When set, every request is evaluated
// against the active policy set before being passed through.
func (m *LifecycleManager) SetPolicyEvaluator(evaluator PolicyEvaluator) {
	m.policyEvaluator = evaluator
}

// Start begins serving the ExtProc gRPC server and blocks until the
// provided context is cancelled. It coordinates graceful shutdown of
// the gRPC server, event bus, and pod cache Informer.
//
// If the server is disabled via configuration, Start blocks on the
// context and returns nil when cancelled.
//
// Returns an error if the server is already started or if it fails
// to bind to the configured port.
func (m *LifecycleManager) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("extproc-lifecycle")

	if !m.cfg.Enabled {
		logger.Info("ExtProc server is disabled")
		<-ctx.Done()
		return nil
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("lifecycle manager already started")
	}
	m.started = true
	m.mu.Unlock()

	// Create the gRPC server with interceptors for observability
	streamInterceptor := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		logger.Info("gRPC stream opened", "method", info.FullMethod)
		err := handler(srv, ss)
		if err != nil {
			logger.Info("gRPC stream closed with error", "method", info.FullMethod, "error", err)
		} else {
			logger.Info("gRPC stream closed", "method", info.FullMethod)
		}
		return err
	}
	unaryInterceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		logger.V(1).Info("gRPC unary call", "method", info.FullMethod)
		return handler(ctx, req)
	}
	m.grpcServer = grpc.NewServer(
		grpc.StreamInterceptor(streamInterceptor),
		grpc.UnaryInterceptor(unaryInterceptor),
	)

	// Register the ExtProc service
	extProcSrv := NewExtProcServer(m.registry, m.resolver, m.bus)

	// Apply enforcement mode from config
	if m.cfg.EnforcementMode == string(enforce.ModeEnforcing) {
		extProcSrv.SetEnforcementMode(enforce.ModeEnforcing)
	} else {
		extProcSrv.SetEnforcementMode(enforce.ModeAudit)
	}

	// Inject policy evaluator if configured
	if m.policyEvaluator != nil {
		extProcSrv.SetPolicyEvaluator(m.policyEvaluator)
	}

	extprocv3.RegisterExternalProcessorServer(m.grpcServer, extProcSrv)

	// Register gRPC reflection for debugging
	reflection.Register(m.grpcServer)

	// Register the health check service
	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(m.grpcServer, healthSrv)
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus(extProcServiceName, healthpb.HealthCheckResponse_SERVING)

	// Bind to the configured port
	addr := fmt.Sprintf(":%d", m.cfg.Port)
	var err error
	m.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	logger.Info("ExtProc server starting", "address", m.listener.Addr().String())

	// Start the pod cache Informer if configured and wait for its cache to
	// sync before accepting gRPC requests. Without this, early requests hit
	// an empty PodCache, producing degraded identity (empty Namespace/Labels)
	// that causes namespace-scoped policies to be filtered out.
	if m.informer != nil {
		go m.informer.Run(ctx)
		logger.Info("waiting for PodCache informer to sync")
		if !m.informer.WaitForSync(ctx) {
			return fmt.Errorf("PodCache informer failed to sync")
		}
		logger.Info("PodCache informer synced")
	}

	// Signal that we are ready
	close(m.readyCh)

	// Serve in a goroutine so we can handle shutdown
	serveCh := make(chan error, 1)
	go func() {
		serveCh <- m.grpcServer.Serve(m.listener)
	}()

	// Wait for context cancellation or serve error
	select {
	case <-ctx.Done():
		logger.Info("shutting down ExtProc server")

		// Update health status to NOT_SERVING
		healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		healthSrv.SetServingStatus(extProcServiceName, healthpb.HealthCheckResponse_NOT_SERVING)

		// Graceful stop with timeout
		shutdownTimeout := m.cfg.ShutdownTimeout
		if shutdownTimeout == 0 {
			shutdownTimeout = 30 * time.Second
		}

		stopped := make(chan struct{})
		go func() {
			m.grpcServer.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			logger.Info("ExtProc server stopped gracefully")
		case <-time.After(shutdownTimeout):
			logger.Info("ExtProc server shutdown timed out, forcing stop")
			m.grpcServer.Stop()
		}

		// Close the event bus
		m.bus.Close()

		return nil

	case err := <-serveCh:
		if err != nil {
			return fmt.Errorf("gRPC server error: %w", err)
		}
		return nil
	}
}

// WaitForReady blocks until the server is ready to accept connections
// or the timeout expires. Returns true if the server is ready, false
// if the timeout was reached.
func (m *LifecycleManager) WaitForReady(timeout time.Duration) bool {
	select {
	case <-m.readyCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Addr returns the network address the server is listening on.
// Returns nil if the server has not started yet or is disabled.
func (m *LifecycleManager) Addr() net.Addr {
	if m.listener == nil {
		return nil
	}
	return m.listener.Addr()
}
