# Context & Specification: dsnitch

## 1. Project Overview
`dsnitch` is a single-binary, zero-overhead, real-time terminal UI (TUI) network and DNS egress inspector for Docker containers powered by modern eBPF. 

It provides instant attribution of all outbound Layer 4 connections (TCP/UDP) and Layer 7 DNS queries directly to specific Docker container names and Docker Compose service labels without modifying container network stacks, running sidecars, or installing heavy telemetry daemons.

---

## 2. Core Constraints & Scope (v1)
- **Passive Observability Only:** Strictly read-only monitoring in v1. No active socket filtering, packet dropping, or firewall blocking (zero risk of breaking host network traffic on crash).
- **Target Kernel:** Linux 5.8+ strictly required.
  - Relies on BPF Type Format (BTF) / Compile Once – Run Everywhere (CO-RE) with `vmlinux.h`.
  - Uses `BPF_MAP_TYPE_RINGBUF` (unified, multi-core memory-mapped ring buffer).
  - Assumes cgroups v2 unified hierarchy (`/sys/fs/cgroup`).
- **Binary Architecture:** Zero runtime dependencies. No external requirement for `clang`, `llvm`, or kernel development headers on the target host.
- **Privilege Model:** Requires `sudo` or capability grants (`CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`) plus read access to `/var/run/docker.sock`.

---

## 3. System Architecture

```text
[In-Kernel eBPF Layer]
  ├── Sockets / Connect Hook:
  │     Attaches to cgroup v2 root for Docker (/sys/fs/cgroup/.../docker) via BPF_CGROUP_INET4_CONNECT
  │     or hooks tracepoint/syscalls/sys_enter_connect with in-kernel cgroup hash map filter.
  │     Captures: cgroup_id, PID, src_ip, src_port, dst_ip, dst_port, protocol.
  ├── DNS Snooper:
  │     Inspects UDP/53 DNS response payloads to extract (A/AAAA) IP-to-Domain mappings.
  └── In-Kernel Ring Buffer:
        Pushes compact event structs to a single BPF_MAP_TYPE_RINGBUF.

──────────────────────────────────────────── IPC (mmap / epoll) ─────────────

[Userspace Daemon & TUI (Go / Rust)]
  ├── Docker Engine Synchronizer:
  │     Queries /var/run/docker.sock to resolve cgroup_id <-> container_name / compose_service.
  │     Listens to Docker events (start/die) to update cgroup lookup tables dynamically.
  ├── DNS Correlation Cache:
  │     In-memory LRU cache matching raw outbound destination IPs to domain names.
  ├── Ring Buffer Ingestion Loop:
  │     Zero-copy consumer draining mmap'd ring buffer memory on epoll wakeup.
  └── TUI View (Bubbletea / Ratatui):
        Interactive split-pane interface:
        - Left/Top: Active Docker containers with outbound connection counters & rates.
        - Right/Bottom: Live stream of outbound egress (Container -> Resolved Domain/IP:Port).
```

---

## 4. Technical Implementation Details

### A. eBPF Subsystem
- **Kernel Probe:** C compiled to eBPF ELF bytecode using CO-RE (`vmlinux.h`).
- **Connection Interception:**
  - Read calling task cgroup ID via `bpf_get_current_cgroup_id()`.
  - Extract destination IPv4/IPv6 and destination port from the socket context (`struct bpf_sock_addr` or `struct sockaddr_in`).
- **Data Transport:** Write event structs to ring buffer via `bpf_ringbuf_reserve()` -> `bpf_ringbuf_submit()`.

### B. Userspace Engine
- **Recommended Stack:** 
  - **Go:** `cilium/ebpf` (loader/CO-RE), `docker/docker/client`, `charmbracelet/bubbletea` (TUI), `miekg/dns` (DNS parsing).
  - *OR* **Rust:** `aya` (eBPF), `bollard` (Docker), `ratatui` (TUI), `trust-dns-proto` / `hickory-dns`.
- **Event Handling:** Ingestion worker runs on an `epoll` event loop sleeping on the ring buffer notification FD, waking up only to drain unconsumed ring buffer memory slots.
- **Docker Mapping:** Polls initial container list on startup and subscribes to the Docker events stream (`/events`) to maintain an active map of `cgroup_id -> ContainerMetadata`.

---

## 5. Development Phases

1. ✅ **Phase 1 (Kernel Probe & Loader):** Pure Rust eBPF probe capturing outbound `connect()` events with `cgroup_id` via Aya, loaded via userspace async loader.
2. ✅ **Phase 2 (Docker Integration):** Connect to `/var/run/docker.sock`, extract cgroup IDs for running containers, and correlate incoming kernel events with container names and Compose service labels.
3. ⏳ **Phase 3 (DNS Enrichment):** Add DNS packet snooping to populate the local `IP -> Hostname` cache.
4. ⏳ **Phase 4 (TUI & Packaging):** Build the terminal UI layout (container selector, live connection table, search/filter) and package with static binary builds.
