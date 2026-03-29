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

#ifndef __PANOPTIUM_COMMON_H
#define __PANOPTIUM_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Common event header shared by all eBPF programs.
// Every event struct must begin with this header.
struct event_header {
    __u32 event_type;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u64 cgroup_id;
    char comm[16];
};

// Event type constants for identifying events in userspace.
enum event_type {
    EVENT_EXECVE      = 1,
    EVENT_OPENAT      = 2,
    EVENT_CONNECT     = 3,
    EVENT_FORK        = 4,
    EVENT_SETNS       = 5,
    EVENT_UNSHARE     = 6,
    EVENT_MOUNT       = 7,
    EVENT_PTRACE      = 8,
    EVENT_BPF_SELFMON = 9,
};

// Maximum sizes for variable-length fields.
#define MAX_FILENAME_LEN  256
#define MAX_ARGS          6
#define MAX_ARG_LEN       256
#define MAX_PATH_LEN      256
#define MAX_COMM_LEN      16
#define MAX_DEV_NAME_LEN  256
#define MAX_FS_TYPE_LEN   64

// Ring buffer size: 256KB (default).
#define RINGBUF_SIZE      (256 * 1024)

// Helper to populate the common event header fields.
static __always_inline void fill_header(struct event_header *hdr, __u32 event_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    hdr->event_type = event_type;
    hdr->timestamp_ns = bpf_ktime_get_ns();
    hdr->pid = (__u32)pid_tgid;
    hdr->tgid = (__u32)(pid_tgid >> 32);
    hdr->uid = (__u32)uid_gid;
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

#endif /* __PANOPTIUM_COMMON_H */
