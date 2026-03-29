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
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// HookType identifies the type of kernel hook for an eBPF program.
type HookType int

const (
	// HookTracepoint attaches to a kernel tracepoint (e.g., sched/sched_process_exec).
	HookTracepoint HookType = iota
	// HookKprobe attaches to a kernel function entry point.
	HookKprobe
	// HookLSM attaches to a BPF-LSM security hook.
	HookLSM
)

// ProgramSpec describes an eBPF program to be loaded and attached.
type ProgramSpec struct {
	// Name is a human-readable identifier for this program.
	Name string

	// Program is the compiled eBPF program to load.
	Program *ebpf.Program

	// Hook is the type of kernel hook to attach to.
	Hook HookType

	// AttachPoint is the kernel attachment point.
	// For tracepoints: "group/name" (e.g., "sched/sched_process_exec").
	// For kprobes: the kernel function name (e.g., "__x64_sys_openat").
	// For LSM: the LSM hook name (e.g., "security_sb_mount").
	AttachPoint string

	// Optional indicates whether failure to attach should be treated as
	// a warning rather than an error. Used for BPF-LSM hooks that may
	// not be available on all kernel configurations.
	Optional bool
}

// attachedProgram tracks a loaded and attached eBPF program.
type attachedProgram struct {
	spec ProgramSpec
	link link.Link
}

// ProgramLoader manages the lifecycle of eBPF programs: loading, attaching,
// and detaching. It supports BTF/CO-RE for cross-kernel portability.
type ProgramLoader struct {
	mu       sync.Mutex
	programs []attachedProgram
	closed   bool
}

// NewProgramLoader creates a new ProgramLoader.
func NewProgramLoader() *ProgramLoader {
	return &ProgramLoader{
		programs: make([]attachedProgram, 0),
	}
}

// AttachProgram loads and attaches an eBPF program to the kernel.
// Returns an error if the attachment fails, unless the program is marked optional.
func (l *ProgramLoader) AttachProgram(spec ProgramSpec) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("loader is closed")
	}

	if spec.Program == nil {
		return fmt.Errorf("program %q: nil program", spec.Name)
	}

	var lnk link.Link
	var err error

	switch spec.Hook {
	case HookTracepoint:
		lnk, err = l.attachTracepoint(spec)
	case HookKprobe:
		lnk, err = l.attachKprobe(spec)
	case HookLSM:
		lnk, err = l.attachLSM(spec)
	default:
		return fmt.Errorf("program %q: unknown hook type %d", spec.Name, spec.Hook)
	}

	if err != nil {
		if spec.Optional {
			slog.Warn("optional eBPF program failed to attach",
				"name", spec.Name,
				"hook", spec.AttachPoint,
				"error", err,
			)
			return nil
		}
		return fmt.Errorf("program %q: attach to %q failed: %w", spec.Name, spec.AttachPoint, err)
	}

	l.programs = append(l.programs, attachedProgram{
		spec: spec,
		link: lnk,
	})

	slog.Info("eBPF program attached",
		"name", spec.Name,
		"hook", spec.AttachPoint,
	)

	return nil
}

// attachTracepoint attaches a program to a kernel tracepoint.
// AttachPoint should be in "group/name" format.
func (l *ProgramLoader) attachTracepoint(spec ProgramSpec) (link.Link, error) {
	return link.AttachTracing(link.TracingOptions{
		Program: spec.Program,
	})
}

// attachKprobe attaches a program to a kprobe.
func (l *ProgramLoader) attachKprobe(spec ProgramSpec) (link.Link, error) {
	return link.Kprobe(spec.AttachPoint, spec.Program, nil)
}

// attachLSM attaches a program to a BPF-LSM hook.
func (l *ProgramLoader) attachLSM(spec ProgramSpec) (link.Link, error) {
	return link.AttachLSM(link.LSMOptions{
		Program: spec.Program,
	})
}

// Programs returns the names of all currently attached programs.
func (l *ProgramLoader) Programs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	names := make([]string, len(l.programs))
	for i, p := range l.programs {
		names[i] = p.spec.Name
	}
	return names
}

// IsAttached returns true if a program with the given name is currently attached.
func (l *ProgramLoader) IsAttached(name string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, p := range l.programs {
		if p.spec.Name == name {
			return true
		}
	}
	return false
}

// Close detaches all eBPF programs and releases resources.
// It is safe to call multiple times.
func (l *ProgramLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true

	var errs []error
	for _, p := range l.programs {
		if p.link != nil {
			if err := p.link.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close %q: %w", p.spec.Name, err))
			}
		}
		if p.spec.Program != nil {
			p.spec.Program.Close()
		}
	}
	l.programs = nil

	return errors.Join(errs...)
}
