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

package tetragon

import (
	"testing"
	"time"
)

func TestTranslateProcessExecEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessExec,
		ProcessPID:  1234,
		ProcessComm: "agent-worker",
		ParentPID:   100,
		ParentComm:  "init",
		Namespace:   "default",
		PodName:     "agent-pod-abc",
		Labels:      map[string]string{"app": "ai-agent"},
		Timestamp:   1000000000, // nanoseconds
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "syscall.execve" {
		t.Errorf("expected event type syscall.execve, got %q", event.EventType())
	}
	if event.Protocol() != "ebpf" {
		t.Errorf("expected protocol ebpf, got %q", event.Protocol())
	}
	if event.Provider() != "execve" {
		t.Errorf("expected provider execve, got %q", event.Provider())
	}
	if event.Identity().PodName != "agent-pod-abc" {
		t.Errorf("expected pod name agent-pod-abc, got %q", event.Identity().PodName)
	}
	if event.Identity().Namespace != "default" {
		t.Errorf("expected namespace default, got %q", event.Identity().Namespace)
	}
	if event.Identity().Labels["app"] != "ai-agent" {
		t.Errorf("expected label app=ai-agent, got %v", event.Identity().Labels)
	}
	if event.RequestID() == "" {
		t.Error("expected non-empty request ID")
	}
	if event.Timestamp().IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestTranslateOpenatKprobeEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessKprobe,
		ProcessPID:  5678,
		ProcessComm: "python",
		KprobeFunc:  "sys_openat",
		KprobeArgs:  map[string]interface{}{"pathname": "/etc/passwd"},
		Namespace:   "ml-team",
		PodName:     "model-server-1",
		Timestamp:   2000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "syscall.openat" {
		t.Errorf("expected event type syscall.openat, got %q", event.EventType())
	}
	if event.Provider() != "openat" {
		t.Errorf("expected provider openat, got %q", event.Provider())
	}
}

func TestTranslateConnectKprobeEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessKprobe,
		ProcessPID:  9999,
		ProcessComm: "curl",
		KprobeFunc:  "sys_connect",
		KprobeArgs:  map[string]interface{}{"addr": "10.0.0.1:443"},
		Namespace:   "default",
		PodName:     "test-pod",
		Timestamp:   3000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "syscall.connect" {
		t.Errorf("expected event type syscall.connect, got %q", event.EventType())
	}
	if event.Provider() != "connect" {
		t.Errorf("expected provider connect, got %q", event.Provider())
	}
}

func TestTranslateForkTracepointEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessKprobe,
		ProcessPID:  100,
		ProcessComm: "bash",
		KprobeFunc:  "sched_process_fork",
		ParentPID:   50,
		Namespace:   "default",
		PodName:     "shell-pod",
		Timestamp:   4000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "syscall.fork" {
		t.Errorf("expected event type syscall.fork, got %q", event.EventType())
	}
}

func TestTranslateNamespaceEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessKprobe,
		ProcessPID:  200,
		ProcessComm: "nsenter",
		KprobeFunc:  "sys_setns",
		Namespace:   "default",
		PodName:     "admin-pod",
		Timestamp:   5000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "security.setns" {
		t.Errorf("expected event type security.setns, got %q", event.EventType())
	}
}

func TestTranslateLSMEnforcementEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessLSM,
		ProcessPID:  300,
		ProcessComm: "mount",
		LSMHook:     "security_sb_mount",
		LSMAction:   "Override",
		Namespace:   "default",
		PodName:     "attacker-pod",
		Timestamp:   6000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "security.mount" {
		t.Errorf("expected event type security.mount, got %q", event.EventType())
	}
}

func TestTranslatePtraceEnforcementEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessLSM,
		ProcessPID:  400,
		ProcessComm: "strace",
		LSMHook:     "security_ptrace_access_check",
		LSMAction:   "Override",
		Namespace:   "default",
		PodName:     "debug-pod",
		Timestamp:   7000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "security.ptrace" {
		t.Errorf("expected event type security.ptrace, got %q", event.EventType())
	}
}

func TestTranslateUnknownEventReturnsNil(t *testing.T) {
	raw := &RawEvent{
		Type:        "unknown_event_type",
		ProcessPID:  500,
		ProcessComm: "mystery",
		Timestamp:   8000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error for unknown event: %v", err)
	}
	if event != nil {
		t.Error("expected nil event for unknown type")
	}
}

func TestTranslateUsesKernelTimestamp(t *testing.T) {
	kernelNanos := uint64(1711843200000000000) // fixed timestamp
	raw := &RawEvent{
		Type:        EventTypeProcessExec,
		ProcessPID:  1,
		ProcessComm: "init",
		Timestamp:   kernelNanos,
		Namespace:   "kube-system",
		PodName:     "kube-dns",
	}

	before := time.Now()
	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The event timestamp should come from the kernel, not time.Now().
	eventTime := event.Timestamp()
	expected := time.Unix(0, int64(kernelNanos))

	if !eventTime.Equal(expected) {
		t.Errorf("expected timestamp %v (from kernel), got %v", expected, eventTime)
	}

	// It should NOT be close to current time (unless kernel nanos happens to be now).
	if eventTime.After(before) {
		t.Error("event timestamp should use kernel timestamp, not time.Now()")
	}
}

func TestTranslateDeterministicRequestID(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessExec,
		ProcessPID:  42,
		ProcessComm: "test",
		Timestamp:   1000000000,
		Namespace:   "default",
		PodName:     "test-pod",
	}

	translator := NewTranslator()
	event1, _ := translator.Translate(raw)
	event2, _ := translator.Translate(raw)

	if event1.RequestID() != event2.RequestID() {
		t.Errorf("expected deterministic request IDs, got %q and %q", event1.RequestID(), event2.RequestID())
	}
}

func TestTranslateProcessExitEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessExit,
		ProcessPID:  999,
		ProcessComm: "worker",
		Namespace:   "default",
		PodName:     "worker-pod",
		Timestamp:   9000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "lifecycle.exit" {
		t.Errorf("expected event type lifecycle.exit, got %q", event.EventType())
	}
}

func TestTranslateBPFSelfmonEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessKprobe,
		ProcessPID:  777,
		ProcessComm: "bpftool",
		KprobeFunc:  "sys_bpf",
		Namespace:   "default",
		PodName:     "suspicious-pod",
		Timestamp:   10000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "security.unauthorized-bpf" {
		t.Errorf("expected event type security.unauthorized-bpf, got %q", event.EventType())
	}
}

func TestTranslateUnshareEvent(t *testing.T) {
	raw := &RawEvent{
		Type:        EventTypeProcessKprobe,
		ProcessPID:  555,
		ProcessComm: "unshare",
		KprobeFunc:  "sys_unshare",
		Namespace:   "default",
		PodName:     "escape-pod",
		Timestamp:   11000000000,
	}

	translator := NewTranslator()
	event, err := translator.Translate(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.EventType() != "security.unshare" {
		t.Errorf("expected event type security.unshare, got %q", event.EventType())
	}
}
