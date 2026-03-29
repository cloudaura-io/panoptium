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

// Execve event captures process execution details.
struct execve_event {
    struct event_header hdr;
    char filename[MAX_FILENAME_LEN];
    char argv[MAX_ARGS][MAX_ARG_LEN];
};

// Cgroup allowlist: only emit events for monitored cgroups.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // cgroup_id
    __type(value, __u8);  // 1 = allowed
} cgroup_allowlist SEC(".maps");

// Ring buffer for execve events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} execve_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    // Check cgroup allowlist: if map is non-empty, only emit for allowed cgroups.
    __u8 *allowed = bpf_map_lookup_elem(&cgroup_allowlist, &cgroup_id);
    if (!allowed) {
        return 0;
    }

    struct execve_event *evt;
    evt = bpf_ringbuf_reserve(&execve_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    fill_header(&evt->hdr, EVENT_EXECVE);

    // Read filename from tracepoint data.
    unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(evt->filename, sizeof(evt->filename),
                       (void *)ctx + fname_off);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
