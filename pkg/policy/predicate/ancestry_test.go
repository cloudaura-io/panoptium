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

package predicate

import (
	"testing"

	"github.com/panoptium/panoptium/pkg/policy"
)

func TestProcessAncestryEvaluator_DirectParent(t *testing.T) {
	// Process tree: bash(1) -> curl(2)
	tree := &MockProcessTree{
		ancestry: map[int][]ProcessInfo{
			2: {
				{PID: 2, Name: "curl"},
				{PID: 1, Name: "bash"},
			},
		},
	}

	eval := &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "bash",
		MatchMode:    AncestorMatchExact,
		ProcessTree:  tree,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"pid":         2,
			"processName": "curl",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected true (direct parent is bash), got false")
	}
}

func TestProcessAncestryEvaluator_GrandparentMatch(t *testing.T) {
	// Process tree: sshd(1) -> bash(2) -> python(3) -> curl(4)
	tree := &MockProcessTree{
		ancestry: map[int][]ProcessInfo{
			4: {
				{PID: 4, Name: "curl"},
				{PID: 3, Name: "python"},
				{PID: 2, Name: "bash"},
				{PID: 1, Name: "sshd"},
			},
		},
	}

	eval := &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "sshd",
		MatchMode:    AncestorMatchExact,
		ProcessTree:  tree,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"pid": 4,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected true (grandparent sshd in ancestry), got false")
	}
}

func TestProcessAncestryEvaluator_DeeperAncestry(t *testing.T) {
	// Process tree: init(1) -> sshd(10) -> bash(20) -> python(30) -> curl(40)
	tree := &MockProcessTree{
		ancestry: map[int][]ProcessInfo{
			40: {
				{PID: 40, Name: "curl"},
				{PID: 30, Name: "python"},
				{PID: 20, Name: "bash"},
				{PID: 10, Name: "sshd"},
				{PID: 1, Name: "init"},
			},
		},
	}

	evalBash := &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "bash",
		MatchMode:    AncestorMatchExact,
		ProcessTree:  tree,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"pid": 40,
		},
	}

	matched, err := evalBash.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected true (bash is ancestor of curl), got false")
	}
}

func TestProcessAncestryEvaluator_NoMatch(t *testing.T) {
	// Process tree: systemd(1) -> python(2) -> curl(3)
	tree := &MockProcessTree{
		ancestry: map[int][]ProcessInfo{
			3: {
				{PID: 3, Name: "curl"},
				{PID: 2, Name: "python"},
				{PID: 1, Name: "systemd"},
			},
		},
	}

	eval := &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "bash",
		MatchMode:    AncestorMatchExact,
		ProcessTree:  tree,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"pid": 3,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (bash not in ancestry), got true")
	}
}

func TestProcessAncestryEvaluator_GlobPattern(t *testing.T) {
	// Process tree: sshd(1) -> bash(2) -> curl(3)
	tree := &MockProcessTree{
		ancestry: map[int][]ProcessInfo{
			3: {
				{PID: 3, Name: "curl"},
				{PID: 2, Name: "bash"},
				{PID: 1, Name: "sshd"},
			},
		},
	}

	eval := &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "ssh*",
		MatchMode:    AncestorMatchGlob,
		ProcessTree:  tree,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"pid": 3,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Error("expected true (sshd matches glob ssh*), got false")
	}
}

func TestProcessAncestryEvaluator_GlobPattern_NoMatch(t *testing.T) {
	tree := &MockProcessTree{
		ancestry: map[int][]ProcessInfo{
			3: {
				{PID: 3, Name: "curl"},
				{PID: 2, Name: "python"},
				{PID: 1, Name: "systemd"},
			},
		},
	}

	eval := &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "ssh*",
		MatchMode:    AncestorMatchGlob,
		ProcessTree:  tree,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"pid": 3,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (no ancestor matches ssh*), got true")
	}
}

func TestProcessAncestryEvaluator_ProcessTreeUnavailable(t *testing.T) {
	tree := &MockProcessTree{
		ancestry: map[int][]ProcessInfo{},
	}

	eval := &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "bash",
		MatchMode:    AncestorMatchExact,
		ProcessTree:  tree,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"pid": 999,
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (process tree unavailable for PID), got true")
	}
}

func TestProcessAncestryEvaluator_MissingPIDField(t *testing.T) {
	tree := &MockProcessTree{
		ancestry: map[int][]ProcessInfo{},
	}

	eval := &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "bash",
		MatchMode:    AncestorMatchExact,
		ProcessTree:  tree,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (missing PID field), got true")
	}
}

func TestProcessAncestryEvaluator_NonIntPIDField(t *testing.T) {
	tree := &MockProcessTree{
		ancestry: map[int][]ProcessInfo{},
	}

	eval := &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "bash",
		MatchMode:    AncestorMatchExact,
		ProcessTree:  tree,
	}

	event := &policy.PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields: map[string]interface{}{
			"pid": "not-a-number",
		},
	}

	matched, err := eval.Evaluate(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("expected false (non-int PID), got true")
	}
}

func TestProcessAncestryEvaluator_ImplementsInterface(t *testing.T) {
	tree := &MockProcessTree{ancestry: map[int][]ProcessInfo{}}
	var _ PredicateEvaluator = &ProcessAncestryEvaluator{
		PIDField:     "pid",
		AncestorName: "bash",
		MatchMode:    AncestorMatchExact,
		ProcessTree:  tree,
	}
}

// MockProcessTree is a test double for ProcessTreeProvider.
type MockProcessTree struct {
	ancestry map[int][]ProcessInfo
}

// GetAncestry returns the mocked ancestry chain for the given PID.
func (m *MockProcessTree) GetAncestry(pid int) []ProcessInfo {
	return m.ancestry[pid]
}
