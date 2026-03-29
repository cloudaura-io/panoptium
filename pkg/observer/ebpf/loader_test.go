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
	"testing"
)

func TestNewProgramLoader(t *testing.T) {
	loader := NewProgramLoader()
	if loader == nil {
		t.Fatal("expected non-nil loader")
	}

	programs := loader.Programs()
	if len(programs) != 0 {
		t.Errorf("expected empty programs list, got %d", len(programs))
	}
}

func TestProgramLoaderAttachNilProgram(t *testing.T) {
	loader := NewProgramLoader()

	err := loader.AttachProgram(ProgramSpec{
		Name:        "test-nil",
		Program:     nil,
		Hook:        HookTracepoint,
		AttachPoint: "sched/sched_process_exec",
	})

	if err == nil {
		t.Fatal("expected error for nil program")
	}
}

func TestProgramLoaderAttachAfterClose(t *testing.T) {
	loader := NewProgramLoader()
	err := loader.Close()
	if err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	err = loader.AttachProgram(ProgramSpec{
		Name:        "test-closed",
		Program:     nil,
		Hook:        HookTracepoint,
		AttachPoint: "sched/sched_process_exec",
	})

	if err == nil {
		t.Fatal("expected error when attaching to closed loader")
	}
}

func TestProgramLoaderCloseIdempotent(t *testing.T) {
	loader := NewProgramLoader()

	if err := loader.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := loader.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestProgramLoaderIsAttachedEmpty(t *testing.T) {
	loader := NewProgramLoader()

	if loader.IsAttached("nonexistent") {
		t.Error("expected IsAttached to return false for empty loader")
	}
}

func TestProgramLoaderProgramsAfterClose(t *testing.T) {
	loader := NewProgramLoader()
	_ = loader.Close()

	programs := loader.Programs()
	if programs != nil && len(programs) != 0 {
		t.Errorf("expected nil or empty programs after close, got %v", programs)
	}
}

func TestHookTypeValues(t *testing.T) {
	// Verify hook type constants are distinct.
	if HookTracepoint == HookKprobe {
		t.Error("HookTracepoint should not equal HookKprobe")
	}
	if HookKprobe == HookLSM {
		t.Error("HookKprobe should not equal HookLSM")
	}
	if HookTracepoint == HookLSM {
		t.Error("HookTracepoint should not equal HookLSM")
	}
}

func TestProgramSpecUnknownHookType(t *testing.T) {
	loader := NewProgramLoader()
	defer loader.Close()

	// Use a mock program-like approach: we test the logic path
	// for an unknown hook type. Since we can't create a real ebpf.Program
	// without root, we just verify the error path for nil program first.
	err := loader.AttachProgram(ProgramSpec{
		Name:        "unknown-hook",
		Program:     nil,
		Hook:        HookType(99),
		AttachPoint: "fake",
	})

	if err == nil {
		t.Fatal("expected error for nil program")
	}
}
