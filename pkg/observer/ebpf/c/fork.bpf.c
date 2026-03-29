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

#include "common.h"

// Fork event captures process creation details.
struct fork_event {
    struct event_header hdr;
    __u32 parent_pid;
    __u32 child_pid;
    char parent_comm[MAX_COMM_LEN];
    __u64 clone_flags;
};

// Cgroup allowlist: shared with other programs.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // cgroup_id
    __type(value, __u8);  // 1 = allowed
} cgroup_allowlist SEC(".maps");

// Process tree map: PID -> parent PID for ancestry tracking.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // child PID
    __type(value, __u32); // parent PID
} process_tree SEC(".maps");

// Ring buffer for fork events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} fork_events SEC(".maps");

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    // Cgroup allowlist filter.
    __u8 *allowed = bpf_map_lookup_elem(&cgroup_allowlist, &cgroup_id);
    if (!allowed) {
        return 0;
    }

    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;

    // Update process tree map for ancestry tracking.
    bpf_map_update_elem(&process_tree, &child_pid, &parent_pid, BPF_ANY);

    struct fork_event *evt;
    evt = bpf_ringbuf_reserve(&fork_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    fill_header(&evt->hdr, EVENT_FORK);
    evt->parent_pid = parent_pid;
    evt->child_pid = child_pid;
    bpf_probe_read_str(evt->parent_comm, sizeof(evt->parent_comm), ctx->parent_comm);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
