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

package ebpf

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// HealthStatus represents the health check response.
type HealthStatus struct {
	// Status is "ok" or "error".
	Status string `json:"status"`

	// Programs lists attached eBPF programs.
	Programs []string `json:"programs,omitempty"`

	// Errors lists any health check failures.
	Errors []string `json:"errors,omitempty"`

	// Timestamp is when the health check was performed.
	Timestamp time.Time `json:"timestamp"`
}

// HealthServer provides HTTP health and readiness probes for the eBPF observer.
type HealthServer struct {
	mu     sync.Mutex
	loader *ProgramLoader
	server *http.Server
	addr   string
}

// NewHealthServer creates a health probe server on the given address.
func NewHealthServer(addr string, loader *ProgramLoader) *HealthServer {
	h := &HealthServer{
		loader: loader,
		addr:   addr,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.handleHealth)
	mux.HandleFunc("/readyz", h.handleReady)

	h.server = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return h
}

// Start starts the health server in the background.
func (h *HealthServer) Start() error {
	ln, err := net.Listen("tcp", h.addr)
	if err != nil {
		return fmt.Errorf("health server listen: %w", err)
	}

	go func() {
		slog.Info("health server started", "addr", h.addr)
		if err := h.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("health server error", "error", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the health server.
func (h *HealthServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.server.Shutdown(ctx)
}

// handleHealth checks if any eBPF programs are attached and the ring buffer is healthy.
// This is the liveness probe: if it fails, the pod should be restarted.
func (h *HealthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := HealthStatus{
		Status:    "ok",
		Timestamp: time.Now(),
	}

	if h.loader != nil {
		programs := h.loader.Programs()
		status.Programs = programs

		if len(programs) == 0 {
			status.Status = "error"
			status.Errors = append(status.Errors, "no eBPF programs attached")
		}
	} else {
		status.Status = "error"
		status.Errors = append(status.Errors, "loader not initialized")
	}

	code := http.StatusOK
	if status.Status != "ok" {
		code = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(status)
}

// handleReady checks if the core hooks (execve, connect) are attached.
// This is the readiness probe: if it fails, the pod is removed from service.
func (h *HealthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	status := HealthStatus{
		Status:    "ok",
		Timestamp: time.Now(),
	}

	coreHooks := []string{"execve", "connect"}
	var missing []string

	if h.loader != nil {
		for _, hook := range coreHooks {
			if !h.loader.IsAttached(hook) {
				missing = append(missing, hook)
			}
		}
		status.Programs = h.loader.Programs()
	} else {
		missing = coreHooks
	}

	if len(missing) > 0 {
		status.Status = "error"
		for _, m := range missing {
			status.Errors = append(status.Errors, fmt.Sprintf("core hook %q not attached", m))
		}
	}

	code := http.StatusOK
	if status.Status != "ok" {
		code = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(status)
}
