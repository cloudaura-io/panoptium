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
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// EventType identifies the kind of eBPF kernel event.
type EventType uint32

const (
	// EventTypeExecve is emitted on process execution (sched_process_exec).
	EventTypeExecve EventType = 1
	// EventTypeOpenat is emitted on file open (openat kprobe).
	EventTypeOpenat EventType = 2
	// EventTypeConnect is emitted on network connect (connect kprobe).
	EventTypeConnect EventType = 3
	// EventTypeFork is emitted on process fork (sched_process_fork).
	EventTypeFork EventType = 4
	// EventTypeSetns is emitted on namespace change (setns kprobe).
	EventTypeSetns EventType = 5
	// EventTypeUnshare is emitted on namespace unshare (unshare kprobe).
	EventTypeUnshare EventType = 6
	// EventTypeMount is emitted on mount attempts (security_sb_mount LSM).
	EventTypeMount EventType = 7
	// EventTypePtrace is emitted on ptrace access (security_ptrace_access_check LSM).
	EventTypePtrace EventType = 8
	// EventTypeBPFSelfMon is emitted on unauthorized bpf() syscalls.
	EventTypeBPFSelfMon EventType = 9
)

// String returns the human-readable name of the event type.
func (t EventType) String() string {
	switch t {
	case EventTypeExecve:
		return "execve"
	case EventTypeOpenat:
		return "openat"
	case EventTypeConnect:
		return "connect"
	case EventTypeFork:
		return "fork"
	case EventTypeSetns:
		return "setns"
	case EventTypeUnshare:
		return "unshare"
	case EventTypeMount:
		return "mount"
	case EventTypePtrace:
		return "ptrace"
	case EventTypeBPFSelfMon:
		return "bpf_selfmon"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// maxFilenameLen is the max length of filename/pathname fields in eBPF events.
const maxFilenameLen = 256

// maxArgLen is the max length of each argv entry.
const maxArgLen = 256

// maxArgs is the max number of argv entries captured.
const maxArgs = 6

// maxCommLen is the max length of the comm field.
const maxCommLen = 16

// maxDevNameLen is the max length of a mount device name.
const maxDevNameLen = 256

// maxFSTypeLen is the max length of a filesystem type.
const maxFSTypeLen = 64

// EventHeader is the common header shared by all eBPF events.
// It mirrors the C struct event_header.
type EventHeader struct {
	Type      EventType
	Timestamp uint64
	PID       uint32
	TGID      uint32
	UID       uint32
	CgroupID  uint64
	Comm      [maxCommLen]byte
}

// CommString returns the comm field as a trimmed Go string.
func (h *EventHeader) CommString() string {
	return nullTerminatedString(h.Comm[:])
}

// ExecveEvent represents a process execution event from the kernel.
type ExecveEvent struct {
	Header   EventHeader
	Filename [maxFilenameLen]byte
	Argv     [maxArgs][maxArgLen]byte
}

// FilenameString returns the filename as a trimmed Go string.
func (e *ExecveEvent) FilenameString() string {
	return nullTerminatedString(e.Filename[:])
}

// ArgvStrings returns the argv array as a slice of Go strings,
// excluding empty entries.
func (e *ExecveEvent) ArgvStrings() []string {
	var args []string
	for _, arg := range e.Argv {
		s := nullTerminatedString(arg[:])
		if s == "" {
			break
		}
		args = append(args, s)
	}
	return args
}

// OpenatEvent represents a file open event from the kernel.
type OpenatEvent struct {
	Header   EventHeader
	Pathname [maxFilenameLen]byte
	Flags    uint32
	Mode     uint32
}

// PathnameString returns the pathname as a trimmed Go string.
func (e *OpenatEvent) PathnameString() string {
	return nullTerminatedString(e.Pathname[:])
}

// ConnectEvent represents a network connect event from the kernel.
type ConnectEvent struct {
	Header     EventHeader
	AddrFamily uint16
	DstAddr    [16]byte // IPv4 in first 4 bytes, or full IPv6
	DstPort    uint16
	_          [2]byte // padding
}

// DstIP returns the destination IP address as a Go net.IP.
func (e *ConnectEvent) DstIP() net.IP {
	switch e.AddrFamily {
	case 2: // AF_INET
		return net.IP(e.DstAddr[:4])
	case 10: // AF_INET6
		return net.IP(e.DstAddr[:16])
	default:
		return nil
	}
}

// ForkEvent represents a process fork event from the kernel.
type ForkEvent struct {
	Header     EventHeader
	ParentPID  uint32
	ChildPID   uint32
	ParentComm [maxCommLen]byte
	CloneFlags uint64
}

// ParentCommString returns the parent comm as a trimmed Go string.
func (e *ForkEvent) ParentCommString() string {
	return nullTerminatedString(e.ParentComm[:])
}

// SetnsEvent represents a setns syscall event from the kernel.
type SetnsEvent struct {
	Header EventHeader
	FD     int32
	NSType int32
}

// UnshareEvent represents an unshare syscall event from the kernel.
type UnshareEvent struct {
	Header EventHeader
	Flags  uint64
}

// MountEvent represents a mount attempt event from the kernel (BPF-LSM).
type MountEvent struct {
	Header  EventHeader
	DevName [maxDevNameLen]byte
	Path    [maxFilenameLen]byte
	FSType  [maxFSTypeLen]byte
	Flags   uint64
}

// DevNameString returns the device name as a trimmed Go string.
func (e *MountEvent) DevNameString() string {
	return nullTerminatedString(e.DevName[:])
}

// PathString returns the mount path as a trimmed Go string.
func (e *MountEvent) PathString() string {
	return nullTerminatedString(e.Path[:])
}

// FSTypeString returns the filesystem type as a trimmed Go string.
func (e *MountEvent) FSTypeString() string {
	return nullTerminatedString(e.FSType[:])
}

// PtraceEvent represents a ptrace access check event from the kernel (BPF-LSM).
type PtraceEvent struct {
	Header   EventHeader
	ChildPID uint32
	Mode     uint32
}

// BPFSelfMonEvent represents a bpf() syscall self-monitoring event.
type BPFSelfMonEvent struct {
	Header EventHeader
	Cmd    uint32
	Size   uint32
}

// ParseEvent parses raw bytes from a ring buffer into the appropriate event type.
func ParseEvent(data []byte) (interface{}, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	eventType := EventType(binary.LittleEndian.Uint32(data[:4]))

	switch eventType {
	case EventTypeExecve:
		var evt ExecveEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return nil, fmt.Errorf("parse execve event: %w", err)
		}
		return &evt, nil

	case EventTypeOpenat:
		var evt OpenatEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return nil, fmt.Errorf("parse openat event: %w", err)
		}
		return &evt, nil

	case EventTypeConnect:
		var evt ConnectEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return nil, fmt.Errorf("parse connect event: %w", err)
		}
		return &evt, nil

	case EventTypeFork:
		var evt ForkEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return nil, fmt.Errorf("parse fork event: %w", err)
		}
		return &evt, nil

	case EventTypeSetns:
		var evt SetnsEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return nil, fmt.Errorf("parse setns event: %w", err)
		}
		return &evt, nil

	case EventTypeUnshare:
		var evt UnshareEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return nil, fmt.Errorf("parse unshare event: %w", err)
		}
		return &evt, nil

	case EventTypeMount:
		var evt MountEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return nil, fmt.Errorf("parse mount event: %w", err)
		}
		return &evt, nil

	case EventTypePtrace:
		var evt PtraceEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return nil, fmt.Errorf("parse ptrace event: %w", err)
		}
		return &evt, nil

	case EventTypeBPFSelfMon:
		var evt BPFSelfMonEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return nil, fmt.Errorf("parse bpf selfmon event: %w", err)
		}
		return &evt, nil

	default:
		return nil, fmt.Errorf("unknown event type: %d", eventType)
	}
}

// nullTerminatedString extracts a null-terminated string from a byte slice.
func nullTerminatedString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx < 0 {
		return string(b)
	}
	return string(b[:idx])
}
