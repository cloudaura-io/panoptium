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

// Setns event captures namespace change details.
struct setns_event {
    struct event_header hdr;
    __s32 fd;
    __s32 nstype;
};

// Unshare event captures namespace unshare details.
struct unshare_event {
    struct event_header hdr;
    __u64 flags;
};

// Cgroup allowlist: shared with other programs.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // cgroup_id
    __type(value, __u8);  // 1 = allowed
} cgroup_allowlist SEC(".maps");

// Ring buffer for namespace events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} namespace_events SEC(".maps");

SEC("kprobe/__x64_sys_setns")
int kprobe__setns(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    __u8 *allowed = bpf_map_lookup_elem(&cgroup_allowlist, &cgroup_id);
    if (!allowed) {
        return 0;
    }

    struct setns_event *evt;
    evt = bpf_ringbuf_reserve(&namespace_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    fill_header(&evt->hdr, EVENT_SETNS);
    evt->fd = (__s32)ctx->di;
    evt->nstype = (__s32)ctx->si;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("kprobe/__x64_sys_unshare")
int kprobe__unshare(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    __u8 *allowed = bpf_map_lookup_elem(&cgroup_allowlist, &cgroup_id);
    if (!allowed) {
        return 0;
    }

    struct unshare_event *evt;
    evt = bpf_ringbuf_reserve(&namespace_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    fill_header(&evt->hdr, EVENT_UNSHARE);
    evt->flags = (__u64)ctx->di;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
