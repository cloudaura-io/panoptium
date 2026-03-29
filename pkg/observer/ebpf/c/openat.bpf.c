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

// Openat event captures file access details.
struct openat_event {
    struct event_header hdr;
    char pathname[MAX_PATH_LEN];
    __u32 flags;
    __u32 mode;
};

// Cgroup allowlist: shared with other programs.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // cgroup_id
    __type(value, __u8);  // 1 = allowed
} cgroup_allowlist SEC(".maps");

// Path prefix blocklist: suppress events for noisy paths (LPM trie).
// Key: prefix length (in bits) + path bytes.
struct path_prefix_key {
    __u32 prefixlen;
    char data[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct path_prefix_key);
    __type(value, __u8);
} path_blocklist SEC(".maps");

// Ring buffer for openat events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} openat_events SEC(".maps");

SEC("kprobe/__x64_sys_openat")
int kprobe__openat(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    // Cgroup allowlist filter.
    __u8 *allowed = bpf_map_lookup_elem(&cgroup_allowlist, &cgroup_id);
    if (!allowed) {
        return 0;
    }

    struct openat_event *evt;
    evt = bpf_ringbuf_reserve(&openat_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    fill_header(&evt->hdr, EVENT_OPENAT);

    // Read pathname from second argument (const char __user *filename).
    const char *pathname = (const char *)ctx->si;
    bpf_probe_read_user_str(evt->pathname, sizeof(evt->pathname), pathname);

    // Check path prefix blocklist.
    struct path_prefix_key key = {};
    __builtin_memcpy(key.data, evt->pathname, sizeof(key.data));
    // Use full path length in bits for the lookup.
    key.prefixlen = MAX_PATH_LEN * 8;
    __u8 *blocked = bpf_map_lookup_elem(&path_blocklist, &key);
    if (blocked) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    // Read flags and mode from arguments.
    evt->flags = (__u32)ctx->dx;
    evt->mode = (__u32)ctx->r10;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
