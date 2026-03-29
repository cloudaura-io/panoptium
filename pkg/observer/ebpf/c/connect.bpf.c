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

// Connect event captures network connection details.
struct connect_event {
    struct event_header hdr;
    __u16 addr_family;
    __u8  dst_addr[16];    // IPv4 in first 4 bytes, or full IPv6.
    __u16 dst_port;
    __u8  _pad[2];         // Alignment padding.
};

// Cgroup allowlist: shared with other programs.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // cgroup_id
    __type(value, __u8);  // 1 = allowed
} cgroup_allowlist SEC(".maps");

// Ring buffer for connect events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} connect_events SEC(".maps");

SEC("kprobe/__sys_connect")
int kprobe__connect(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    // Cgroup allowlist filter.
    __u8 *allowed = bpf_map_lookup_elem(&cgroup_allowlist, &cgroup_id);
    if (!allowed) {
        return 0;
    }

    // Second argument: struct sockaddr __user *uservaddr.
    struct sockaddr *addr = (struct sockaddr *)ctx->si;
    if (!addr) {
        return 0;
    }

    // Read the address family first.
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    // Only handle AF_INET and AF_INET6.
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    struct connect_event *evt;
    evt = bpf_ringbuf_reserve(&connect_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    fill_header(&evt->hdr, EVENT_CONNECT);
    evt->addr_family = family;

    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        __builtin_memcpy(evt->dst_addr, &sin.sin_addr, 4);
        evt->dst_port = __builtin_bswap16(sin.sin_port);
    } else { // AF_INET6
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), addr);
        __builtin_memcpy(evt->dst_addr, &sin6.sin6_addr, 16);
        evt->dst_port = __builtin_bswap16(sin6.sin6_port);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
