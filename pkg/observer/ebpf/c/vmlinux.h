/*
Minimal vmlinux.h for CO-RE eBPF programs.

This provides the type definitions needed by Panoptium eBPF programs.
In production, generate a full vmlinux.h from the target kernel using:
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

This minimal version provides the subset of types required for compilation
with CO-RE relocations enabled.
*/

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
typedef signed char         __s8;
typedef signed short        __s16;
typedef signed int          __s32;
typedef signed long long    __s64;
typedef _Bool               bool;

#define true  1
#define false 0

typedef __u16 __be16;
typedef __u32 __be32;

/* Task struct (CO-RE safe subset) */
struct task_struct {
    int pid;
    int tgid;
    struct task_struct *parent;
    char comm[16];
} __attribute__((preserve_access_index));

/* Socket address families */
#define AF_INET   2
#define AF_INET6  10

/* Socket address structures */
struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
} __attribute__((preserve_access_index));

struct in_addr {
    __be32 s_addr;
} __attribute__((preserve_access_index));

struct sockaddr_in {
    unsigned short sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
    unsigned char __pad[8];
} __attribute__((preserve_access_index));

struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((preserve_access_index));

struct sockaddr_in6 {
    unsigned short sin6_family;
    __be16 sin6_port;
    __be32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32 sin6_scope_id;
} __attribute__((preserve_access_index));

/* Trace event context for sched_process_exec */
struct trace_event_raw_sched_process_exec {
    int __data_loc_filename;
    int pid;
    int old_pid;
} __attribute__((preserve_access_index));

/* Trace event context for sched_process_fork */
struct trace_event_raw_sched_process_fork {
    char parent_comm[16];
    int parent_pid;
    char child_comm[16];
    int child_pid;
} __attribute__((preserve_access_index));

/* PT_REGS for kprobes */
struct pt_regs {
    unsigned long di;
    unsigned long si;
    unsigned long dx;
    unsigned long r10;
    unsigned long r8;
    unsigned long r9;
    unsigned long ax;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
