# dsnitch Design & Architecture

This document details the internal design, in-kernel eBPF architecture, socket attribution mechanics, and design invariants of `dsnitch`.

---

## 1. System Architecture

`dsnitch` is divided into an in-kernel eBPF probe layer and a multi-threaded userspace processing engine written in Rust using [Aya](https://aya-rs.dev/):

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            In-Kernel eBPF Layer                             │
├───────────────────────┬────────────────────────────┬────────────────────────┤
│  connect4 / connect6  │   cgroup_skb (in/egress)   │  inet_sock_set_state   │
│  (cgroup_sock_addr)   │   (DNS & Layer-3 ICMP)     │      (Tracepoint)      │
└───────────┬───────────┴──────────────┬─────────────┴───────────┬────────────┘
            │ (ConnectEvent)           │ (DnsPacketEvent)        │ (SocketCloseEvent)
            ▼                          ▼                         ▼
     EVENTS RingBuf             DNS_EVENTS RingBuf        CLOSE_EVENTS RingBuf
  (BPF_MAP_TYPE_RINGBUF)     (BPF_MAP_TYPE_RINGBUF)    (BPF_MAP_TYPE_RINGBUF)
            │                          │                         │
════════════╪══════════════════════════╪═════════════════════════╪═════════════ IPC (mmap / epoll)
            │                          │                         │
┌───────────▼──────────────────────────▼─────────────────────────▼────────────┐
│                         Userspace Engine (Rust / Tokio)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Docker Engine Synchronizer (Bollard):                                    │
│      Resolves cgroup_id <-> container_name / compose_service.                │
│      Maintains running / recently-stopped cache via Docker events stream.   │
│                                                                             │
│  • Per-Cgroup DNS Correlation Cache (Hickory DNS):                          │
│      Isolated in-memory cache mapping (cgroup_id, IP) -> DomainName         │
│      Resolves full CNAME chains with fallback to prevent CDN IP collisions. │
│                                                                             │
│  • Stateful Socket Tracker (skaddr):                                        │
│      Tracks connection state transitions: [● ACTIVE] -> [○ CLOSED].         │
│      Prunes closed sockets after configurable --grace-period (default 5s).  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Ratatui Split-Pane TUI                            │
│  ┌──────────────────────────────┬────────────────────────────────────────┐  │
│  │ Containers Pane              │ Live Egress Feed Table                 │  │
│  │ ● web-worker (backend) [12]  │ STATUS   TIME  SERVICE  PROTO DEST  IP │  │
│  │ ● db-worker  (postgres)[4]   │ ● ACTIVE 1.2s  backend  TCP   ...   ...│  │
│  │ ○ cache-box  (redis)   [0]   │ ○ CLOSED 1.8s  backend  TCP   ...   ...│  │
│  └──────────────────────────────┴────────────────────────────────────────┘  │
│  [Tab] Switch Pane  [/] Filter  [Enter] Lock Container  [a] Host Toggle  [q] Quit │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Comparison Matrix: How dsnitch Compares

| Capability / Dimension | `tcpdump` / `wireshark` | `conntrack -E` | `ss` / `netstat` | Sidecars (Envoy / Istio) | OpenSnitch | `dsnitch` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Container Attribution** | ❌ None (bridge packets only) | ❌ None (L4 flow table) | ⚠️ Polling inside netns | ✅ Full | ⚠️ Host PID only | ✅ Instant Docker & Compose label resolution |
| **DNS Domain Correlation** | ⚠️ Raw payload dump | ❌ None (IPs only) | ❌ None | ✅ L7 HTTP proxy | ⚠️ Reverse DNS | ✅ In-kernel DNS snoop + CNAME cache |
| **Lifecycle Tracking** | ⚠️ Raw packet stream | ⚠️ L4 TCP states | ❌ Misses <100ms sockets | ✅ Full session | ⚠️ Interactive prompts | ✅ Deterministic in-kernel `skaddr` lifecycle |
| **Overhead & Latency** | ⚠️ Packet copy overhead | ✅ Low | ⚠️ Polling CPU cost | ❌ Proxy latency & 50-100MB RAM/pod | ⚠️ Desktop UI / prompt latency | ✅ Near-zero (<1% CPU, event-driven eBPF) |
| **Zero Modifications** | ✅ Yes | ✅ Yes | ⚠️ Needs netns access | ❌ Needs YAML & pod restarts | ✅ Yes | ✅ 100% passive, zero container changes |

---

## 3. Protocol & eBPF Hook Matrix

`dsnitch` uses distinct, specialized eBPF program types tailored to each protocol's semantics:

| Protocol | eBPF Hook / Program Type | Lifecycle & Attribution Mechanism |
| :--- | :--- | :--- |
| **TCP** | `tracepoint/sock/inet_sock_set_state` | **Activation (`TCP_SYN_SENT = 2`)**: Captures outbound connection initiation in the task's syscall context, binding the container metadata to the 64-bit kernel socket address (`skaddr`) and client port (`sport`).<br>**Termination (`TCP_CLOSE = 7` / `TCP_TIME_WAIT = 6`)**: Matches the exact socket by `skaddr` to transition state to `○ CLOSED` with 0% softirq context collision risk. |
| **UDP** | `cgroup_sock_addr/connect4`<br>`cgroup_sock_addr/connect6` | Intercepts outbound UDP `connect()` syscalls with container `cgroup_id`. Sockets are tracked with a 3-second sliding activity window in userspace before transitioning to `○ CLOSED`. |
| **ICMP / ICMPv6** | `cgroup_skb/egress` | Intercepts raw Layer-3 IP packets. Parses IP header protocol bytes (`proto == 1` for ICMPv4, `proto == 58` for ICMPv6), extracts destination IP directly from packet headers, and tags with container `bpf_skb_cgroup_id(skb)`. |
| **DNS (UDP 53)** | `cgroup_skb/ingress`<br>`cgroup_skb/egress` | Inspects UDP/53 packet wire payloads (up to 768 bytes), emitting raw DNS events tagged with `cgroup_id`. Userspace parses answers with Hickory DNS to populate the per-cgroup `(cgroup_id, IP) -> DomainName` cache. |

---

## 4. Key Architectural Invariants

### Deterministic `skaddr` State Machine
A major hurdle in eBPF socket monitoring is that TCP termination (`TCP_CLOSE` / `TCP_TIME_WAIT`) typically fires from **kernel timer or softirq contexts**. In softirq context, calling `bpf_get_current_cgroup_id()` or `bpf_get_current_pid_tgid()` returns the identity of whatever random process happened to be interrupted on that CPU core.

`dsnitch` solves this by recording the physical 64-bit kernel memory address of the socket struct (`struct sock * skaddr`) upon `TCP_SYN_SENT`. When `TCP_CLOSE` fires, the userspace engine matches the connection solely by `skaddr`, guaranteeing deterministic attribution across namespaces and softirq switches.

### Multi-Tenant Per-Cgroup DNS Isolation
Public CDN Anycast IPs (such as Cloudflare `104.16.x.x` or Fastly `151.101.x.x`) host thousands of unrelated domains. If two different containers connect to different domains that resolve to the same Anycast IP, a naive global cache would cross-contaminate domain names.

`dsnitch` maintains a strictly isolated `(cgroup_id, IP) -> DomainName` cache. Domain lookups are scoped strictly to the container making the query, with full CNAME chain resolution.
