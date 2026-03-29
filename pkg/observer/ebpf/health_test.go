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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpointNoLoader(t *testing.T) {
	server := NewHealthServer(":0", nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	server.handleHealth(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var status HealthStatus
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if status.Status != "error" {
		t.Errorf("expected error status, got %q", status.Status)
	}
}

func TestHealthEndpointEmptyLoader(t *testing.T) {
	loader := NewProgramLoader()
	server := NewHealthServer(":0", loader)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	server.handleHealth(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for empty loader, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var status HealthStatus
	json.Unmarshal(body, &status)

	if len(status.Errors) == 0 {
		t.Error("expected errors for empty loader")
	}
}

func TestReadyEndpointNoLoader(t *testing.T) {
	server := NewHealthServer(":0", nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	server.handleReady(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var status HealthStatus
	json.Unmarshal(body, &status)

	if status.Status != "error" {
		t.Errorf("expected error status, got %q", status.Status)
	}
	// Should report missing execve and connect hooks.
	if len(status.Errors) < 2 {
		t.Errorf("expected at least 2 missing core hooks, got %d errors", len(status.Errors))
	}
}

func TestReadyEndpointMissingCoreHooks(t *testing.T) {
	loader := NewProgramLoader()
	server := NewHealthServer(":0", loader)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	server.handleReady(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for missing core hooks, got %d", resp.StatusCode)
	}
}

func TestHealthServerStartStop(t *testing.T) {
	loader := NewProgramLoader()
	server := NewHealthServer("127.0.0.1:0", loader)

	err := server.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	err = server.Stop()
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestHealthStatusJSON(t *testing.T) {
	status := HealthStatus{
		Status:   "ok",
		Programs: []string{"execve", "connect"},
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded HealthStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Status != "ok" {
		t.Errorf("expected ok, got %q", decoded.Status)
	}
	if len(decoded.Programs) != 2 {
		t.Errorf("expected 2 programs, got %d", len(decoded.Programs))
	}
}
