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

// Package ebpf provides eBPF program loading, lifecycle management, and
// kernel event consumption for the Panoptium observer.
package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type execve_event execve ./c/execve.bpf.c -- -I./c -O2 -g -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type openat_event openat ./c/openat.bpf.c -- -I./c -O2 -g -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type connect_event connect ./c/connect.bpf.c -- -I./c -O2 -g -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type fork_event fork ./c/fork.bpf.c -- -I./c -O2 -g -Wall -Werror
