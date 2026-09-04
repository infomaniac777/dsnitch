# dsnitch

[![CI (x86_64)](https://github.com/infomaniac777/dsnitch/actions/workflows/ci-x86.yml/badge.svg)](https://github.com/infomaniac777/dsnitch/actions/workflows/ci-x86.yml)
[![CI (aarch64)](https://github.com/infomaniac777/dsnitch/actions/workflows/ci-arm.yml/badge.svg)](https://github.com/infomaniac777/dsnitch/actions/workflows/ci-arm.yml)
[![Unit Tests](https://github.com/infomaniac777/dsnitch/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/infomaniac777/dsnitch/actions/workflows/unit-tests.yml)
[![E2E Tests](https://github.com/infomaniac777/dsnitch/actions/workflows/e2e.yml/badge.svg)](https://github.com/infomaniac777/dsnitch/actions/workflows/e2e.yml)

![demo](res/demo.gif)

A single-binary, lightweight, zero-configuration, real-time terminal UI (TUI) network and DNS egress inspector for Docker containers powered by modern Linux eBPF.

`dsnitch` provides instantaneous attribution of all outbound Layer 4 connections (TCP/UDP), Layer 3 ICMP pings, and Layer 7 DNS queries directly to specific Docker container names and Docker Compose service labels without modifying container network stacks, running sidecars, or installing heavy telemetry daemons.

---

## Table of Contents
- [Key Features](#key-features)
- [How Does It Work?](#how-does-it-work)
- [Installation](#installation)
  - [Download a Prebuilt Binary](#download-a-prebuilt-binary)
  - [Building from Source](#building-from-source)
- [Running](#running)
  - [1. setcap (Recommended for Unprivileged Users)](#1-setcap-recommended-for-unprivileged-users)
  - [2. sudo (Standard Alternative)](#2-sudo-standard-alternative)
- [Usage](#usage)
  - [1. Interactive TUI Mode](#1-interactive-tui-mode-default-on-tty)
  - [2. Custom Grace Period](#2-custom-grace-period)
  - [3. Plain-Text Streaming Mode](#3-plain-text-streaming-mode--s)
- [Testing](#testing)
- [CLI Options Reference](#cli-options-reference)
- [Architecture & Design (DESIGN.md)](DESIGN.md)
- [License](#license)

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

## How Does It Work?

`dsnitch` attaches passive, in-kernel eBPF probes directly to the host's unified cgroup v2 hierarchy (`/sys/fs/cgroup`) and the kernel's TCP socket state tracepoint. It intercepts outbound connection requests (TCP/UDP), Layer-3 ICMP pings, and raw DNS wire payloads on port 53, correlating sockets to Docker container metadata and resolved hostnames in userspace via lockless BPF ring buffers with near-zero (<1%) CPU overhead.

> For in-depth kernel architecture, eBPF hook internals, and comparison matrices, see [**DESIGN.md**](DESIGN.md).

---

## Installation

### Download a Prebuilt Binary
Generic precompiled 64-bit binaries are available for Linux on the [GitHub Releases](https://github.com/infomaniac777/dsnitch/releases) page:

| Architecture | Platform Target | Support |
| :--- | :--- | :--- |
| **x86_64** | `x86_64-unknown-linux-gnu` | Full (Intel/AMD Desktops, Servers, VMs) |
| **ARM64** | `aarch64-unknown-linux-gnu` | Full (Raspberry Pi 4/5, Graviton, Apple Silicon VMs) |

```bash
# Download and extract the latest release (example for x86_64):
curl -sSL https://github.com/infomaniac777/dsnitch/releases/latest/download/dsnitch-x86_64-unknown-linux-gnu.tar.gz | tar -xz
sudo mv dsnitch /usr/local/bin/
```

### Building from Source

#### Prerequisites
- **Linux Kernel**: Version **5.8+** with unified cgroups v2 (`/sys/fs/cgroup`) and BTF enabled.
- **Docker Engine**: Access to Docker daemon (`/var/run/docker.sock`).
- **Rust Toolchain**: Nightly toolchain installed with `rust-src` component (for compiling eBPF bytecode via `bpfel-unknown-none`).

```bash
# 1. Clone repository
git clone https://github.com/infomaniac777/dsnitch.git
cd dsnitch

# 2. Build eBPF bytecode & release binary (via cargo xtask)
cargo xtask build-ebpf --release
cargo build --release
```

---

## Running

### 1. `setcap` (Recommended for Unprivileged Users)
Permanently grant `dsnitch` its required Linux capabilities so any user in the `docker` group can run it without `sudo`:

```bash
# Assign minimal capabilities to the binary:
# (Note: If running directly from a local source build, replace $(command -v dsnitch) with ./target/release/dsnitch)
sudo setcap cap_sys_admin,cap_net_admin,cap_dac_read_search+ep $(command -v dsnitch)

# Run directly as an unprivileged user:
dsnitch
```

#### Capabilities Explained:
- **`cap_sys_admin`**: Grants `perf_event_open` rights to attach the TCP socket state tracepoint (`sock:inet_sock_set_state`).
- **`cap_net_admin`**: Allows attaching passive in-kernel eBPF socket and packet probes to cgroup v2 (`connect4`, `connect6`, and DNS/ICMP packet snoopers).
- **`cap_dac_read_search`**: Allows reading tracepoint format descriptors from `/sys/kernel/tracing` without requiring full root privileges.

> [!NOTE]
> **Why `CAP_SYS_ADMIN` instead of `CAP_PERFMON` on Debian / Ubuntu / Fedora?**  
> While upstream Linux 5.8+ split eBPF privileges into `CAP_BPF` and `CAP_PERFMON`, major distributions ship with `kernel.perf_event_paranoid >= 2` by default. Under this security policy, the kernel's `perf_event_open` subsystem explicitly mandates `CAP_SYS_ADMIN` to attach tracepoints (`sock:inet_sock_set_state`), ignoring `CAP_PERFMON`.  
> 
> If your host has `kernel.perf_event_paranoid <= 1` (or if configured via `sudo sysctl -w kernel.perf_event_paranoid=1`), `dsnitch` runs under the strict minimal set without `CAP_SYS_ADMIN`:
> ```bash
> sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_dac_read_search+ep $(command -v dsnitch)
> ```

### 2. `sudo` (Standard Alternative)
Alternatively, run directly with root escalation:
```bash
sudo dsnitch
```

---

## Usage

### 1. Interactive TUI Mode (Default on TTY)
Launch the full interactive split-pane interface:
```bash
dsnitch
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
dsnitch --grace-period 10
```

---

### 3. Plain-Text Streaming Mode (`-s`)
Ideal for headless logging, scripts, or piping to other CLI tools:
```bash
# Docker containers only
dsnitch -s

# Docker containers + Host processes
dsnitch -a -s
```

---

## Testing

`dsnitch` includes both in-memory unit tests and an automated end-to-end integration test suite that runs against live Docker containers:

```bash
# Run in-memory unit tests:
cargo test

# Run automated E2E integration suite (Docker required):
bash tests/e2e.sh
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

## License

GNU General Public License v3.0 ([LICENSE](LICENSE))
