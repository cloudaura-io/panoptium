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

// BPF self-monitoring event captures unauthorized bpf() syscall details.
struct bpf_selfmon_event {
    struct event_header hdr;
    __u32 cmd;
    __u32 size;
};

// Known agent PIDs: bpf() calls from these PIDs are expected and filtered.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);   // PID
    __type(value, __u8);  // 1 = known
} known_agent_pids SEC(".maps");

// Ring buffer for self-monitoring events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} selfmon_events SEC(".maps");

SEC("kprobe/__sys_bpf")
int kprobe__bpf(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;

    // Filter out known Panoptium agent PIDs.
    __u8 *known = bpf_map_lookup_elem(&known_agent_pids, &pid);
    if (known) {
        return 0;
    }

    struct bpf_selfmon_event *evt;
    evt = bpf_ringbuf_reserve(&selfmon_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    fill_header(&evt->hdr, EVENT_BPF_SELFMON);
    evt->cmd = (__u32)ctx->di;
    evt->size = (__u32)ctx->dx;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
