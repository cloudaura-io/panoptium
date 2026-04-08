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
	"fmt"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

const (
	eventSyscallExecve  = "syscall.execve"
	subcatExecve        = "execve"
	eventLifecycleExit  = "lifecycle.exit"
	eventSyscallFork    = "syscall.fork"
	eventSecurityMount  = "security.mount"
	eventSecurityPtrace = "security.ptrace"
)

// Translator converts Tetragon RawEvents into Panoptium eventbus.Event instances.
type Translator struct{}

// NewTranslator creates a new Translator.
func NewTranslator() *Translator {
	return &Translator{}
}

// Translate converts a Tetragon RawEvent into a Panoptium eventbus.Event.
// Returns nil (without error) for unknown event types that should be skipped.
func (tr *Translator) Translate(raw *RawEvent) (eventbus.Event, error) {
	var eventType string
	var subcategory string

	switch raw.Type {
	case EventTypeProcessExec:
		eventType = eventSyscallExecve
		subcategory = subcatExecve

	case EventTypeProcessExit:
		eventType = eventLifecycleExit
		subcategory = "exit"

	case EventTypeProcessKprobe:
		eventType, subcategory = tr.translateKprobe(raw)
		if eventType == "" {
			return nil, nil
		}

	case EventTypeProcessTracepoint:
		eventType, subcategory = tr.translateTracepoint(raw)
		if eventType == "" {
			return nil, nil
		}

	case EventTypeProcessLSM:
		eventType, subcategory = tr.translateLSM(raw)
		if eventType == "" {
			return nil, nil
		}

	default:
		// Unknown event type: skip gracefully.
		return nil, nil
	}

	agentInfo := eventbus.AgentIdentity{
		PodName:   raw.PodName,
		Namespace: raw.Namespace,
		Labels:    raw.Labels,
	}

	// Use kernel timestamp instead of time.Now().
	eventTime := time.Unix(0, int64(raw.Timestamp))

	// Generate deterministic request ID from process info + timestamp.
	reqID := fmt.Sprintf("tetragon-%d-%d", raw.ProcessPID, raw.Timestamp)

	return &eventbus.BaseEvent{
		Type:      eventType,
		Time:      eventTime,
		ReqID:     reqID,
		Proto:     "ebpf",
		Prov:      subcategory,
		AgentInfo: agentInfo,
	}, nil
}

// translateKprobe maps kprobe function names to Panoptium event types.
func (tr *Translator) translateKprobe(raw *RawEvent) (eventType, subcategory string) {
	switch raw.KprobeFunc {
	case "sys_openat", "__x64_sys_openat", "__arm64_sys_openat":
		return "syscall.openat", "openat"
	case "sys_connect", "__x64_sys_connect", "__arm64_sys_connect":
		return "syscall.connect", "connect"
	case "sched_process_fork":
		return eventSyscallFork, "fork"
	case "sys_setns", "__x64_sys_setns", "__arm64_sys_setns":
		return "security.setns", "setns"
	case "sys_unshare", "__x64_sys_unshare", "__arm64_sys_unshare":
		return "security.unshare", "unshare"
	case "sys_bpf", "__x64_sys_bpf", "__arm64_sys_bpf":
		return "security.unauthorized-bpf", "unauthorized-bpf"
	case "security_sb_mount":
		return eventSecurityMount, "mount"
	case "security_ptrace_access_check":
		return eventSecurityPtrace, "ptrace"
	default:
		// Unknown kprobe: skip gracefully.
		return "", ""
	}
}

// translateTracepoint maps tracepoint events to Panoptium event types.
func (tr *Translator) translateTracepoint(raw *RawEvent) (eventType, subcategory string) {
	switch raw.KprobeFunc {
	case "sched_process_exec":
		return eventSyscallExecve, subcatExecve
	case "sched_process_fork":
		return eventSyscallFork, "fork"
	case "sched_process_exit":
		return eventLifecycleExit, "exit"
	default:
		return "", ""
	}
}

// translateLSM maps LSM hook names to Panoptium event types.
func (tr *Translator) translateLSM(raw *RawEvent) (eventType, subcategory string) {
	switch raw.LSMHook {
	case "security_sb_mount":
		return eventSecurityMount, "mount"
	case "security_ptrace_access_check":
		return eventSecurityPtrace, "ptrace"
	default:
		return "", ""
	}
}
