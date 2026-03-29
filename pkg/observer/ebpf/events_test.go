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
	"net"
	"testing"
)

func TestNullTerminatedString(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{"empty", []byte{0, 0, 0}, ""},
		{"simple", []byte{'h', 'i', 0, 'x'}, "hi"},
		{"full", []byte{'a', 'b', 'c'}, "abc"},
		{"null only", []byte{0}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nullTerminatedString(tc.input)
			if got != tc.expect {
				t.Errorf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		et     EventType
		expect string
	}{
		{EventTypeExecve, "execve"},
		{EventTypeOpenat, "openat"},
		{EventTypeConnect, "connect"},
		{EventTypeFork, "fork"},
		{EventTypeSetns, "setns"},
		{EventTypeUnshare, "unshare"},
		{EventTypeMount, "mount"},
		{EventTypePtrace, "ptrace"},
		{EventTypeBPFSelfMon, "bpf_selfmon"},
		{EventType(99), "unknown(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.expect, func(t *testing.T) {
			got := tc.et.String()
			if got != tc.expect {
				t.Errorf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

func TestParseEventTooShort(t *testing.T) {
	_, err := ParseEvent([]byte{0, 0})
	if err == nil {
		t.Fatal("expected error for data too short")
	}
}

func TestParseEventUnknownType(t *testing.T) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 255)

	_, err := ParseEvent(data)
	if err == nil {
		t.Fatal("expected error for unknown event type")
	}
}

func TestParseExecveEvent(t *testing.T) {
	evt := ExecveEvent{}
	evt.Header.Type = EventTypeExecve
	evt.Header.Timestamp = 123456789
	evt.Header.PID = 1234
	evt.Header.TGID = 1234
	evt.Header.UID = 1000
	evt.Header.CgroupID = 42
	copy(evt.Header.Comm[:], "bash")
	copy(evt.Filename[:], "/usr/bin/ls")
	copy(evt.Argv[0][:], "ls")
	copy(evt.Argv[1][:], "-la")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	execEvt, ok := parsed.(*ExecveEvent)
	if !ok {
		t.Fatalf("expected *ExecveEvent, got %T", parsed)
	}

	if execEvt.Header.PID != 1234 {
		t.Errorf("PID: expected 1234, got %d", execEvt.Header.PID)
	}
	if execEvt.Header.CgroupID != 42 {
		t.Errorf("CgroupID: expected 42, got %d", execEvt.Header.CgroupID)
	}
	if execEvt.Header.Timestamp != 123456789 {
		t.Errorf("Timestamp: expected 123456789, got %d", execEvt.Header.Timestamp)
	}
	if execEvt.FilenameString() != "/usr/bin/ls" {
		t.Errorf("Filename: expected /usr/bin/ls, got %q", execEvt.FilenameString())
	}
	if execEvt.Header.CommString() != "bash" {
		t.Errorf("Comm: expected bash, got %q", execEvt.Header.CommString())
	}

	argv := execEvt.ArgvStrings()
	if len(argv) != 2 {
		t.Fatalf("expected 2 argv entries, got %d", len(argv))
	}
	if argv[0] != "ls" {
		t.Errorf("argv[0]: expected ls, got %q", argv[0])
	}
	if argv[1] != "-la" {
		t.Errorf("argv[1]: expected -la, got %q", argv[1])
	}
}

func TestParseOpenatEvent(t *testing.T) {
	evt := OpenatEvent{}
	evt.Header.Type = EventTypeOpenat
	evt.Header.PID = 5678
	evt.Header.CgroupID = 99
	copy(evt.Pathname[:], "/etc/passwd")
	evt.Flags = 0x0
	evt.Mode = 0644

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	openEvt, ok := parsed.(*OpenatEvent)
	if !ok {
		t.Fatalf("expected *OpenatEvent, got %T", parsed)
	}

	if openEvt.PathnameString() != "/etc/passwd" {
		t.Errorf("Pathname: expected /etc/passwd, got %q", openEvt.PathnameString())
	}
	if openEvt.Flags != 0 {
		t.Errorf("Flags: expected 0, got %d", openEvt.Flags)
	}
	if openEvt.Mode != 0644 {
		t.Errorf("Mode: expected 0644, got %o", openEvt.Mode)
	}
}

func TestParseOpenatTruncatedPath(t *testing.T) {
	evt := OpenatEvent{}
	evt.Header.Type = EventTypeOpenat

	// Fill pathname to max length (no null terminator)
	for i := range evt.Pathname {
		evt.Pathname[i] = 'a'
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	openEvt := parsed.(*OpenatEvent)
	path := openEvt.PathnameString()
	if len(path) != maxFilenameLen {
		t.Errorf("expected truncated path of length %d, got %d", maxFilenameLen, len(path))
	}
}

func TestParseConnectEventIPv4(t *testing.T) {
	evt := ConnectEvent{}
	evt.Header.Type = EventTypeConnect
	evt.Header.PID = 100
	evt.AddrFamily = 2 // AF_INET
	copy(evt.DstAddr[:4], net.ParseIP("10.0.0.1").To4())
	evt.DstPort = 8080

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	connEvt := parsed.(*ConnectEvent)
	ip := connEvt.DstIP()
	if !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("expected 10.0.0.1, got %s", ip)
	}
	if connEvt.DstPort != 8080 {
		t.Errorf("expected port 8080, got %d", connEvt.DstPort)
	}
}

func TestParseConnectEventIPv6(t *testing.T) {
	evt := ConnectEvent{}
	evt.Header.Type = EventTypeConnect
	evt.AddrFamily = 10 // AF_INET6
	ipv6 := net.ParseIP("::1")
	copy(evt.DstAddr[:16], ipv6.To16())
	evt.DstPort = 443

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	connEvt := parsed.(*ConnectEvent)
	ip := connEvt.DstIP()
	if !ip.Equal(net.ParseIP("::1")) {
		t.Errorf("expected ::1, got %s", ip)
	}
}

func TestParseConnectEventUnknownFamily(t *testing.T) {
	evt := ConnectEvent{}
	evt.Header.Type = EventTypeConnect
	evt.AddrFamily = 99 // unknown

	if ip := evt.DstIP(); ip != nil {
		t.Errorf("expected nil IP for unknown family, got %s", ip)
	}
}

func TestParseForkEvent(t *testing.T) {
	evt := ForkEvent{}
	evt.Header.Type = EventTypeFork
	evt.ParentPID = 100
	evt.ChildPID = 101
	copy(evt.ParentComm[:], "parent_proc")
	evt.CloneFlags = 0x00100011

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	forkEvt := parsed.(*ForkEvent)
	if forkEvt.ParentPID != 100 || forkEvt.ChildPID != 101 {
		t.Errorf("expected parent=100 child=101, got parent=%d child=%d",
			forkEvt.ParentPID, forkEvt.ChildPID)
	}
	if forkEvt.ParentCommString() != "parent_proc" {
		t.Errorf("expected parent_proc, got %q", forkEvt.ParentCommString())
	}
	if forkEvt.CloneFlags != 0x00100011 {
		t.Errorf("expected clone_flags 0x00100011, got 0x%x", forkEvt.CloneFlags)
	}
}

func TestParseSetnsEvent(t *testing.T) {
	evt := SetnsEvent{}
	evt.Header.Type = EventTypeSetns
	evt.Header.PID = 200
	evt.FD = 3
	evt.NSType = 0x20000000 // CLONE_NEWNET

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	setnsEvt := parsed.(*SetnsEvent)
	if setnsEvt.NSType != 0x20000000 {
		t.Errorf("expected nstype 0x20000000, got 0x%x", setnsEvt.NSType)
	}
}

func TestParseUnshareEvent(t *testing.T) {
	evt := UnshareEvent{}
	evt.Header.Type = EventTypeUnshare
	evt.Flags = 0x02000000 // CLONE_NEWNS

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	unshareEvt := parsed.(*UnshareEvent)
	if unshareEvt.Flags != 0x02000000 {
		t.Errorf("expected flags 0x02000000, got 0x%x", unshareEvt.Flags)
	}
}

func TestParseMountEvent(t *testing.T) {
	evt := MountEvent{}
	evt.Header.Type = EventTypeMount
	copy(evt.DevName[:], "/dev/sda1")
	copy(evt.Path[:], "/mnt/data")
	copy(evt.FSType[:], "ext4")
	evt.Flags = 0x01 // MS_RDONLY

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	mountEvt := parsed.(*MountEvent)
	if mountEvt.DevNameString() != "/dev/sda1" {
		t.Errorf("expected /dev/sda1, got %q", mountEvt.DevNameString())
	}
	if mountEvt.PathString() != "/mnt/data" {
		t.Errorf("expected /mnt/data, got %q", mountEvt.PathString())
	}
	if mountEvt.FSTypeString() != "ext4" {
		t.Errorf("expected ext4, got %q", mountEvt.FSTypeString())
	}
}

func TestParsePtraceEvent(t *testing.T) {
	evt := PtraceEvent{}
	evt.Header.Type = EventTypePtrace
	evt.ChildPID = 500
	evt.Mode = 0x10 // PTRACE_MODE_ATTACH

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ptraceEvt := parsed.(*PtraceEvent)
	if ptraceEvt.ChildPID != 500 {
		t.Errorf("expected child_pid 500, got %d", ptraceEvt.ChildPID)
	}
	if ptraceEvt.Mode != 0x10 {
		t.Errorf("expected mode 0x10, got 0x%x", ptraceEvt.Mode)
	}
}

func TestParseBPFSelfMonEvent(t *testing.T) {
	evt := BPFSelfMonEvent{}
	evt.Header.Type = EventTypeBPFSelfMon
	evt.Header.PID = 999
	evt.Cmd = 5  // BPF_PROG_LOAD
	evt.Size = 64

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	parsed, err := ParseEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	bpfEvt := parsed.(*BPFSelfMonEvent)
	if bpfEvt.Cmd != 5 {
		t.Errorf("expected cmd 5, got %d", bpfEvt.Cmd)
	}
	if bpfEvt.Header.PID != 999 {
		t.Errorf("expected PID 999, got %d", bpfEvt.Header.PID)
	}
}

func TestEventHeaderCommString(t *testing.T) {
	hdr := EventHeader{}
	copy(hdr.Comm[:], "test_comm")

	if hdr.CommString() != "test_comm" {
		t.Errorf("expected test_comm, got %q", hdr.CommString())
	}
}

func TestExecveArgvEmptyEntries(t *testing.T) {
	evt := ExecveEvent{}
	// All argv entries are zero-filled (empty).
	argv := evt.ArgvStrings()
	if len(argv) != 0 {
		t.Errorf("expected 0 argv for empty event, got %d", len(argv))
	}
}
