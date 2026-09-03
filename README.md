# dsnitch

[![CI](https://github.com/infomaniac777/dsnitch/actions/workflows/ci.yml/badge.svg)](https://github.com/infomaniac777/dsnitch/actions/workflows/ci.yml)

A single-binary, lightweight, zero-configuration, real-time terminal UI (TUI) network and DNS egress inspector for Docker containers powered by modern Linux eBPF.

`dsnitch` provides instantaneous attribution of all outbound Layer 4 connections (TCP/UDP), Layer 3 ICMP pings, and Layer 7 DNS queries directly to specific Docker container names and Docker Compose service labels without modifying container network stacks, running sidecars, or installing heavy telemetry daemons.

---

## Key Features

- **Zero-Touch Container Attribution**: Attaches directly to the host's unified cgroup v2 hierarchy (`/sys/fs/cgroup`) via eBPF. Zero sidecars, proxies, or container agent injections required.
- **In-Kernel DNS Snooping & Userspace Enrichment**: Intercepts raw UDP/53 packet payloads in kernel space via eBPF ring buffers, with userspace Hickory DNS decoding the records to map IP endpoints to domain names (with full CNAME chain resolution) per container cgroup.
- **Deterministic Stateful Socket Tracking (`skaddr`)**: Hooks kernel `sock:inet_sock_set_state` to track the full lifecycle of TCP connections (`● ACTIVE` -> `○ CLOSED`) keyed by physical 64-bit kernel memory pointers (`skaddr`), guaranteeing 100% collision-free tracking across concurrent connections and network namespaces.
- **Native ICMP Protocol Support**: Inspects Layer-3 IP header protocol bytes (`IPPROTO_ICMP = 1`, `IPPROTO_ICMPV6 = 58`) to cleanly capture container connectivity checks (`ping`) as `ICMP` without artificial port mangling.
- **Dual Destination & Physical IP Columns**: Clean separation between DNS-resolved hostnames (`api.github.com:443`) and underlying edge IP endpoints (`20.207.73.85:443`).
- **Glibc Noise Filtering**: Intelligently skips dummy POSIX/glibc `getaddrinfo()` UDP port `0` route-lookup probes.
- **Interactive Split-Pane TUI (Ratatui)**: Container hierarchy tree with live connection counters on the left, real-time color-coded egress stream on the right, instant search filtering, container locking, and host traffic toggling.
- **Headless / Streaming Mode (`-s`)**: Supports non-interactive plain-text streaming for logging, CI/CD, or headless pipelines.

---

## Why dsnitch? (How It Compares)

| Capability / Dimension | `tcpdump` / `wireshark` | `conntrack -E` | `ss` / `netstat` | Sidecars (Envoy / Istio) | OpenSnitch | `dsnitch` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Container Attribution** | ❌ None (bridge packets only) | ❌ None (L4 flow table) | ⚠️ Polling inside netns | ✅ Full | ⚠️ Host PID only | ✅ Instant Docker & Compose label resolution |
| **DNS Domain Correlation** | ⚠️ Raw payload dump | ❌ None (IPs only) | ❌ None | ✅ L7 HTTP proxy | ⚠️ Reverse DNS | ✅ In-kernel DNS snoop + CNAME cache |
| **Lifecycle Tracking** | ⚠️ Raw packet stream | ⚠️ L4 TCP states | ❌ Misses <100ms sockets | ✅ Full session | ⚠️ Interactive prompts | ✅ Deterministic in-kernel `skaddr` lifecycle |
| **Overhead & Latency** | ⚠️ Packet copy overhead | ✅ Low | ⚠️ Polling CPU cost | ❌ Proxy latency & 50-100MB RAM/pod | ⚠️ Desktop UI / prompt latency | ✅ Near-zero (<1% CPU, event-driven eBPF) |
| **Zero Modifications** | ✅ Yes | ✅ Yes | ⚠️ Needs netns access | ❌ Needs YAML & pod restarts | ✅ Yes | ✅ 100% passive, zero container changes |

---

## Protocol & eBPF Hook Matrix

`dsnitch` uses distinct, specialized eBPF program types tailored to each protocol's semantics:

| Protocol | eBPF Hook / Program Type | Lifecycle & Attribution Mechanism |
| :--- | :--- | :--- |
| **TCP** | `tracepoint/sock/inet_sock_set_state` | **Activation (`TCP_SYN_SENT = 2`)**: Captures outbound connection initiation in the task's syscall context, binding the container metadata to the 64-bit kernel socket address (`skaddr`) and client port (`sport`).<br>**Termination (`TCP_CLOSE = 7` / `TCP_TIME_WAIT = 6`)**: Matches the exact socket by `skaddr` to transition state to `○ CLOSED` with 0% softirq context collision risk. |
| **UDP** | `cgroup_sock_addr/connect4`<br>`cgroup_sock_addr/connect6` | Intercepts outbound UDP `connect()` syscalls with container `cgroup_id`. Sockets are tracked with a 3-second sliding activity window in userspace before transitioning to `○ CLOSED`. |
| **ICMP / ICMPv6** | `cgroup_skb/egress` | Intercepts raw Layer-3 IP packets. Parses IP header protocol bytes (`proto == 1` for ICMPv4, `proto == 58` for ICMPv6), extracts destination IP directly from packet headers, and tags with container `bpf_skb_cgroup_id(skb)`. |
| **DNS (UDP 53)** | `cgroup_skb/ingress`<br>`cgroup_skb/egress` | Inspects UDP/53 packet wire payloads (up to 768 bytes), emitting raw DNS events tagged with `cgroup_id`. Userspace parses answers with Hickory DNS to populate the per-cgroup `(cgroup_id, IP) -> DomainName` cache. |

---

## System Architecture

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

## Quickstart & Installation

### Prerequisites
- **Linux Kernel**: Version **5.8+** with unified cgroups v2 (`/sys/fs/cgroup`) and BTF enabled.
- **Docker Engine**: Access to Docker daemon (`/var/run/docker.sock`).
- **Rust Toolchain**: Nightly toolchain installed (for building eBPF bytecode via `bpfel-unknown-none`).

### Building from Source

```bash
# 1. Clone repository
git clone https://github.com/infomaniac777/dsnitch.git
cd dsnitch

# 2. Add eBPF compilation target
rustup target add bpfel-unknown-none --toolchain nightly

# 3. Build eBPF bytecode & release binary (recommended via cargo xtask)
cargo xtask build-ebpf --release
cargo build --release

# Alternatively, compile eBPF directly:
# cargo +nightly build --manifest-path dsnitch-ebpf/Cargo.toml --target bpfel-unknown-none --release -Z build-std=core
# cargo build --release
```

---

## Usage

### 1. Interactive TUI Mode (Default on TTY)
Launch the full interactive split-pane interface:
```bash
sudo ./target/release/dsnitch
```

#### Interactive Controls & Keybindings
| Key | Action |
| :--- | :--- |
| `Tab` / `←` / `→` | Switch focus between **Containers Pane** and **Live Egress Feed** |
| `↑` / `↓` or `j` / `k` | Navigate containers or connection rows |
| `Enter` | Lock / filter feed to the selected container (press again to reset) |
| `/` | Open search bar (filter in real-time by container, service, domain, or IP) |
| `Esc` | Clear active search filter and container selection |
| `a` | Live toggle host processes view (`ON` / `OFF`) |
| `c` | Clear current connection feed history |
| `q` | Quit `dsnitch` cleanly |

---

### 2. Custom Grace Period
Retain closed connections on screen for a custom duration (e.g. 10 seconds) before auto-pruning:
```bash
sudo ./target/release/dsnitch --grace-period 10
```

---

### 3. Plain-Text Streaming Mode (`-s`)
Ideal for headless logging, scripts, or piping to other CLI tools:
```bash
# Docker containers only
sudo ./target/release/dsnitch -s

# Docker containers + Host processes
sudo ./target/release/dsnitch -a -s
```

---

## Testing & Verification Suite

The following test suite was executed against `dsnitch` to verify correctness across edge cases:

### Test 1: Multi-Container Docker Compose Stack Simulation
Simulates multiple concurrent services with Docker Compose project and service labels:
```bash
# Run in background: sudo ./target/release/dsnitch -s
docker run --rm --name shop-gateway -l com.docker.compose.project=shop -l com.docker.compose.service=gateway alpine sh -c "wget -q -O /dev/null https://api.github.com && sleep 1 && wget -q -O /dev/null http://example.com" &
docker run --rm --name shop-auth -l com.docker.compose.project=shop -l com.docker.compose.service=auth alpine sh -c "wget -q -O /dev/null https://registry.npmjs.org" &
docker run --rm --name shop-probe -l com.docker.compose.project=shop -l com.docker.compose.service=probe alpine sh -c "ping -c 2 1.1.1.1" &
wait
```

**Captured Output:**
```text
STATUS     TIME         CONTAINER       SERVICE    IMAGE/PROCESS    PROTO  DESTINATION             DST IP                  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
● ACTIVE   6080.470s    shop-probe      probe      alpine           ICMP   -                       1.1.1.1                 
● ACTIVE   6080.492s    shop-gateway    gateway    alpine           TCP    api.github.com:443      20.207.73.85:443        
● ACTIVE   6080.498s    shop-auth       auth       alpine           TCP    registry.npmjs.org:443  104.16.4.34:443         
○ CLOSED   6080.592s    shop-auth       auth       alpine           TCP    registry.npmjs.org:443  104.16.4.34:443         
○ CLOSED   6080.631s    shop-gateway    gateway    alpine           TCP    api.github.com:443      20.207.73.85:443        
● ACTIVE   6081.661s    shop-gateway    gateway    alpine           TCP    example.com:80          172.66.147.243:80       
○ CLOSED   6081.713s    shop-gateway    gateway    alpine           TCP    example.com:80          172.66.147.243:80       
```

---

### Test 2: High Concurrency Burst (20 Parallel Sockets)
Verifies `skaddr` collision resistance and ring buffer throughput under concurrent load:
```bash
docker run --rm --name burst-tester alpine sh -c '
for i in $(seq 1 20); do
  wget -q -O /dev/null http://example.com &
done
wait
'
```

**Captured Output (Summary):**
```text
● ACTIVE   6103.914s    burst-tester    -          alpine           TCP    example.com:80          104.20.23.154:80  [x20]
○ CLOSED   6103.952s    burst-tester    -          alpine           TCP    example.com:80          104.20.23.154:80  [x20]
```

---

### Test 3: User-Defined Bridge Network & Embedded DNS (`127.0.0.11`)
Verifies DNS resolution and packet snooping inside custom Docker bridge network namespaces:
```bash
docker network create test-net
docker run --rm --network test-net --name bridge-worker alpine wget -q -O /dev/null https://httpbin.org/ip
docker network rm test-net
```

**Captured Output:**
```text
STATUS     TIME         CONTAINER       SERVICE    IMAGE/PROCESS    PROTO  DESTINATION             DST IP                  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
● ACTIVE   6125.709s    bridge-worker   -          alpine           TCP    httpbin.org:443         100.63.40.118:443       
○ CLOSED   6127.305s    bridge-worker   -          alpine           TCP    httpbin.org:443         100.63.40.118:443       
```

---

### Test 4: Rapid Container Churn & Lifecycle Races
Verifies that containers exiting in sub-second intervals are correctly resolved via the `recently_stopped` cache:
```bash
for i in $(seq 1 6); do
  docker run --rm --name "churn-$i" alpine wget -q -O /dev/null http://example.com &
done
wait
```

**Captured Output:**
```text
STATUS     TIME         CONTAINER       SERVICE    IMAGE/PROCESS    PROTO  DESTINATION             DST IP                  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
● ACTIVE   6148.707s    churn-2         -          alpine           TCP    example.com:80          172.66.147.243:80       
○ CLOSED   6148.761s    churn-2         -          alpine           TCP    example.com:80          172.66.147.243:80       
● ACTIVE   6148.795s    churn-1         -          alpine           TCP    example.com:80          172.66.147.243:80       
● ACTIVE   6148.819s    churn-5         -          alpine           TCP    example.com:80          172.66.147.243:80       
● ACTIVE   6148.819s    churn-6         -          alpine           TCP    example.com:80          172.66.147.243:80       
● ACTIVE   6148.819s    churn-4         -          alpine           TCP    example.com:80          172.66.147.243:80       
○ CLOSED   6148.841s    churn-1         -          alpine           TCP    example.com:80          172.66.147.243:80       
○ CLOSED   6148.861s    churn-5         -          alpine           TCP    example.com:80          172.66.147.243:80       
○ CLOSED   6148.863s    churn-6         -          alpine           TCP    example.com:80          172.66.147.243:80       
○ CLOSED   6148.864s    churn-4         -          alpine           TCP    example.com:80          172.66.147.243:80       
● ACTIVE   6148.856s    churn-3         -          alpine           TCP    example.com:80          172.66.147.243:80       
○ CLOSED   6148.901s    churn-3         -          alpine           TCP    example.com:80          172.66.147.243:80       
```

---

### Test 5: Host Traffic Isolation
Verifies that host traffic is strictly omitted when running in default container mode:
```bash
wget -q -O /dev/null http://example.com  # Host traffic (omitted)
docker run --rm --name container-only alpine wget -q -O /dev/null http://example.com
```

**Captured Output:**
```text
STATUS     TIME         CONTAINER       SERVICE    IMAGE/PROCESS    PROTO  DESTINATION             DST IP                  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
● ACTIVE   6165.890s    container-only  -          alpine           TCP    example.com:80          104.20.23.154:80        
○ CLOSED   6165.937s    container-only  -          alpine           TCP    example.com:80          104.20.23.154:80        
```

---

### Test 6: Multi-Hop CNAME Chaining & CDNs
Verifies full recursive CNAME resolution to edge Anycast IPs:
```bash
docker run --rm --name cname-tester alpine sh -c "wget -q -O /dev/null https://cdnjs.cloudflare.com && wget -q -O /dev/null https://reddit.com"
```

**Captured Output:**
```text
STATUS     TIME         CONTAINER       SERVICE    IMAGE/PROCESS    PROTO  DESTINATION             DST IP                  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
● ACTIVE   6192.024s    cname-tester    -          alpine           TCP    cdnjs.cloudflare.com:443 104.17.24.14:443       
○ CLOSED   6192.092s    cname-tester    -          alpine           TCP    cdnjs.cloudflare.com:443 104.17.24.14:443        
● ACTIVE   6192.121s    cname-tester    -          alpine           TCP    reddit.com:443          151.101.65.140:443      
○ CLOSED   6192.185s    cname-tester    -          alpine           TCP    reddit.com:443          151.101.65.140:443      
● ACTIVE   6192.243s    cname-tester    -          alpine           TCP    www.reddit.com:443      151.101.65.140:443      
○ CLOSED   6192.325s    cname-tester    -          alpine           TCP    www.reddit.com:443      151.101.65.140:443      
```

---

## CLI Options Reference

```text
Usage: dsnitch [OPTIONS]

Options:
      --cgroup-path <PATH>   Cgroup v2 root path [default: /sys/fs/cgroup]
  -a, --all                  Include host processes in monitoring alongside Docker containers
  -s, --stream               Run in plain streaming output mode instead of interactive TUI
      --tui                  Force interactive TUI mode (default when attached to a TTY)
      --grace-period <SECS>  Grace period in seconds to retain closed connections before removal [default: 5]
  -h, --help                 Print help
  -V, --version              Print version
```

---

## Security, Permissions & Safety Invariants

1. **Privilege Model**:
   - `dsnitch` requires elevated privileges to attach eBPF probes to the root cgroup hierarchy:
     ```bash
     sudo ./target/release/dsnitch
     ```
   - Alternatively, grant explicit Linux capabilities without full root:
     ```bash
     sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./target/release/dsnitch
     ```
   - Requires read access to the Docker daemon socket (`/var/run/docker.sock`) and unified cgroup v2 hierarchy (`/sys/fs/cgroup`).
2. **Passive Read-Only Safety**: All in-kernel eBPF probes inspect socket and packet headers without blocking, redirecting, or dropping packets (`return 1`), guaranteeing host network stability.
3. **Deterministic `skaddr` Correlation**: Sockets transition through kernel states (`TCP_SYN_SENT` -> `TCP_CLOSE`) mapped directly to their kernel `struct sock *` pointer address, eliminating multi-connection race conditions.
4. **Multi-Tenant DNS Isolation**: DNS records are isolated by `cgroup_id` so that overlapping container networks or shared Anycast/CDN IPs do not cross-contaminate hostname resolution.
