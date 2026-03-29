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

// Mount event captures filesystem mount attempt details.
struct mount_event {
    struct event_header hdr;
    char dev_name[MAX_DEV_NAME_LEN];
    char path[MAX_PATH_LEN];
    char type[MAX_FS_TYPE_LEN];
    __u64 flags;
};

// Cgroup allowlist: shared with other programs.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // cgroup_id
    __type(value, __u8);  // 1 = allowed
} cgroup_allowlist SEC(".maps");

// Ring buffer for mount events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} mount_events SEC(".maps");

// BPF-LSM hook on security_sb_mount.
// Parameters: const char *dev_name, const struct path *path,
//             const char *type, unsigned long flags, void *data
SEC("lsm/security_sb_mount")
int BPF_PROG(lsm_mount, const char *dev_name, const void *path,
             const char *type, unsigned long flags, void *data)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    __u8 *allowed = bpf_map_lookup_elem(&cgroup_allowlist, &cgroup_id);
    if (!allowed) {
        return 0;
    }

    struct mount_event *evt;
    evt = bpf_ringbuf_reserve(&mount_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    fill_header(&evt->hdr, EVENT_MOUNT);
    evt->flags = flags;

    if (dev_name) {
        bpf_probe_read_kernel_str(evt->dev_name, sizeof(evt->dev_name), dev_name);
    }
    if (type) {
        bpf_probe_read_kernel_str(evt->type, sizeof(evt->type), type);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0; // Allow the mount (observation only, not enforcement).
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
