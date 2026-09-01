mod dns;
mod docker;
mod ui;

use std::{
    collections::HashMap,
    fs::File,
    io::{stdout, IsTerminal},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSockAddr, TracePoint},
    Ebpf,
};
use clap::Parser;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dns::DnsCache;
use docker::DockerManager;
use dsnitch_common::{ConnectEvent, DnsPacketEvent, SocketCloseEvent};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::signal;
use ui::{render_ui, App, ConnectionItem, ConnectionStatus};

#[derive(Parser, Debug)]
#[command(
    name = "dsnitch",
    author,
    version,
    about = "Zero-overhead Docker network & DNS egress inspector"
)]
struct Args {
    /// Cgroup v2 root path
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_path: PathBuf,

    /// Show host processes in addition to Docker containers
    #[arg(long, short = 'a', default_value_t = false)]
    all: bool,

    /// Run in plain streaming output mode instead of interactive TUI
    #[arg(long, short = 's', default_value_t = false)]
    stream: bool,

    /// Force interactive TUI mode
    #[arg(long, default_value_t = false)]
    tui: bool,

    /// Grace period (in seconds) to retain closed connections before removal
    #[arg(long, default_value_t = 5)]
    grace_period: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    bump_memlock_rlimit()?;

    log::info!("Initializing Docker Egress & DNS Inspector (Phase 4: Ratatui TUI)...");
    log::info!("Target cgroup path: {}", args.cgroup_path.display());

    // 1. Initialize Per-Cgroup DNS Cache
    let dns_cache = Arc::new(DnsCache::new(256));

    // 2. Initialize Docker Engine synchronizer
    let docker_mgr = match DockerManager::new() {
        Ok(mgr) => {
            let mgr = Arc::new(mgr);
            match mgr.sync_running_containers().await {
                Ok(count) => {
                    log::info!("Connected to Docker daemon (Active containers: {})", count);
                }
                Err(err) => {
                    log::warn!("Could not list running containers: {:#}", err);
                }
            }
            let listener_mgr = Arc::clone(&mgr);
            let listener_dns = Arc::clone(&dns_cache);
            tokio::spawn(async move {
                listener_mgr.start_event_listener(Some(listener_dns)).await;
            });
            Some(mgr)
        }
        Err(err) => {
            log::warn!("Docker not available: {:#}. Running in host-only mode.", err);
            None
        }
    };

    // 3. Load eBPF bytecode
    #[cfg(debug_assertions)]
    let bpf_bytes = include_bytes_aligned!("../../dsnitch-ebpf/target/bpfel-unknown-none/debug/dsnitch");
    #[cfg(not(debug_assertions))]
    let bpf_bytes = include_bytes_aligned!("../../dsnitch-ebpf/target/bpfel-unknown-none/release/dsnitch");

    let mut ebpf = Ebpf::load(bpf_bytes).context("Failed to load eBPF bytecode")?;

    let cgroup_file = File::open(&args.cgroup_path)
        .with_context(|| format!("Failed to open cgroup path: {}", args.cgroup_path.display()))?;

    // Attach IPv4 connect hook
    if let Some(prog) = ebpf.program_mut("dsnitch_connect4") {
        let prog4: &mut CgroupSockAddr = prog.try_into()?;
        prog4.load()?;
        prog4.attach(&cgroup_file, CgroupAttachMode::Single)?;
        log::info!("Attached connect4 probe to cgroup v2");
    }

    // Attach IPv6 connect hook
    if let Some(prog) = ebpf.program_mut("dsnitch_connect6") {
        let prog6: &mut CgroupSockAddr = prog.try_into()?;
        prog6.load()?;
        prog6.attach(&cgroup_file, CgroupAttachMode::Single)?;
        log::info!("Attached connect6 probe to cgroup v2");
    }

    // Attach sendmsg4 probe (for ICMP and connectionless UDP sendto)
    if let Some(prog) = ebpf.program_mut("dsnitch_sendmsg4") {
        let prog4: &mut CgroupSockAddr = prog.try_into()?;
        prog4.load()?;
        prog4.attach(&cgroup_file, CgroupAttachMode::Single)?;
        log::info!("Attached sendmsg4 probe to cgroup v2");
    }

    // Attach sendmsg6 probe (for ICMPv6 and connectionless UDP sendto)
    if let Some(prog) = ebpf.program_mut("dsnitch_sendmsg6") {
        let prog6: &mut CgroupSockAddr = prog.try_into()?;
        prog6.load()?;
        prog6.attach(&cgroup_file, CgroupAttachMode::Single)?;
        log::info!("Attached sendmsg6 probe to cgroup v2");
    }

    // Attach socket state change tracepoint (for TCP close transitions)
    if let Some(prog) = ebpf.program_mut("dsnitch_sock_set_state") {
        let prog_tp: &mut TracePoint = prog.try_into()?;
        prog_tp.load()?;
        if let Err(err) = prog_tp.attach("sock", "inet_sock_set_state") {
            log::warn!("Could not attach inet_sock_set_state tracepoint: {:#}", err);
        } else {
            log::info!("Attached socket state tracepoint (inet_sock_set_state)");
        }
    }

    // Attach DNS packet snooper (cgroup_skb ingress & egress)
    if let Some(prog) = ebpf.program_mut("dsnitch_dns_ingress") {
        let prog_dns: &mut CgroupSkb = prog.try_into()?;
        prog_dns.load()?;
        prog_dns.attach(&cgroup_file, CgroupSkbAttachType::Ingress, CgroupAttachMode::Single)?;
        log::info!("Attached DNS ingress snooper to cgroup v2 (UDP/53)");
    }
    if let Some(prog) = ebpf.program_mut("dsnitch_dns_egress") {
        let prog_dns: &mut CgroupSkb = prog.try_into()?;
        prog_dns.load()?;
        prog_dns.attach(&cgroup_file, CgroupSkbAttachType::Egress, CgroupAttachMode::Single)?;
        log::info!("Attached DNS egress snooper to cgroup v2 (UDP/53)");
    }

    // Open Ring Buffer maps
    let ring_buf_map = ebpf.take_map("EVENTS").context("Map EVENTS not found in eBPF program")?;
    let ring_buf = RingBuf::try_from(ring_buf_map)?;

    let dns_ring_buf_map = ebpf
        .take_map("DNS_EVENTS")
        .context("Map DNS_EVENTS not found in eBPF program")?;
    let dns_ring_buf = RingBuf::try_from(dns_ring_buf_map)?;

    let close_ring_buf_map = ebpf
        .take_map("CLOSE_EVENTS")
        .context("Map CLOSE_EVENTS not found in eBPF program")?;
    let close_ring_buf = RingBuf::try_from(close_ring_buf_map)?;

    let use_tui = if args.stream {
        false
    } else if args.tui {
        true
    } else {
        std::io::stdout().is_terminal()
    };

    if use_tui {
        run_tui_loop(ring_buf, dns_ring_buf, close_ring_buf, docker_mgr, dns_cache, args.all, args.grace_period).await?;
    } else {
        run_plain_streaming_loop(ring_buf, dns_ring_buf, close_ring_buf, docker_mgr, dns_cache, args.all, args.grace_period).await?;
    }

    Ok(())
}

async fn run_tui_loop(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    mut dns_ring_buf: RingBuf<aya::maps::MapData>,
    mut close_ring_buf: RingBuf<aya::maps::MapData>,
    docker_mgr: Option<Arc<DockerManager>>,
    dns_cache: Arc<DnsCache>,
    show_host: bool,
    grace_period: u64,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(show_host, grace_period);

    // Initial container population
    if let Some(ref mgr) = docker_mgr {
        let active = mgr.sync_running_containers().await.unwrap_or(0);
        log::info!("TUI started with {} active containers", active);
    }

    let mut interval = tokio::time::interval(Duration::from_millis(30));

    loop {
        if !app.running {
            break;
        }

        tokio::select! {
            _ = interval.tick() => {
                // 1. Drain incoming DNS response packets
                while let Some(item) = dns_ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<DnsPacketEvent>() {
                        let dns_event = unsafe { *(data.as_ptr() as *const DnsPacketEvent) };
                        dns_cache.process_packet(&dns_event).await;
                    }
                }

                // 2. Drain socket close events
                while let Some(item) = close_ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<SocketCloseEvent>() {
                        let close_event = unsafe { *(data.as_ptr() as *const SocketCloseEvent) };
                        let dst_ip: IpAddr = if close_event.ip_version == 4 {
                            IpAddr::V4(Ipv4Addr::new(
                                close_event.daddr[0],
                                close_event.daddr[1],
                                close_event.daddr[2],
                                close_event.daddr[3],
                            ))
                        } else {
                            IpAddr::V6(Ipv6Addr::from(close_event.daddr))
                        };
                        let dst_str = format!("{}:{}", dst_ip, close_event.dport);
                        app.close_connection(close_event.skaddr, &dst_str);
                    }
                }

                // 3. Drain outbound socket connect events
                while let Some(item) = ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<ConnectEvent>() {
                        let event = unsafe { *(data.as_ptr() as *const ConnectEvent) };
                        let container = if let Some(ref mgr) = docker_mgr {
                            mgr.lookup(event.cgroup_id).await
                        } else {
                            None
                        };

                        if let Some(ref c) = container {
                            app.update_container(
                                c.cgroup_id,
                                c.name.clone(),
                                c.compose_service.clone().unwrap_or_else(|| "-".to_string()),
                                c.image.clone(),
                            );
                        }

                        let comm = String::from_utf8_lossy(&event.comm)
                            .trim_matches(char::from(0))
                            .to_string();

                        let proto = match event.proto {
                            1 => "ICMP",
                            6 => "TCP",
                            17 => "UDP",
                            58 => "ICMPv6",
                            _ => "RAW",
                        };

                        let dst_ip: IpAddr = if event.ip_version == 4 {
                            IpAddr::V4(Ipv4Addr::new(
                                event.daddr[0],
                                event.daddr[1],
                                event.daddr[2],
                                event.daddr[3],
                            ))
                        } else {
                            IpAddr::V6(Ipv6Addr::from(event.daddr))
                        };

                        let raw_ip_str = match dst_ip {
                            IpAddr::V4(ip) => {
                                if proto == "ICMP" {
                                    format!("{}", ip)
                                } else {
                                    format!("{}:{}", ip, event.dport)
                                }
                            }
                            IpAddr::V6(ip) => {
                                if proto == "ICMPv6" {
                                    format!("{}", ip)
                                } else {
                                    format!("[{}]:{}", ip, event.dport)
                                }
                            }
                        };

                        let resolved_domain = dns_cache.resolve(event.cgroup_id, &dst_ip).await;
                        let dst_str = match resolved_domain {
                            Some(domain) => {
                                if proto == "ICMP" || proto == "ICMPv6" {
                                    domain
                                } else {
                                    format!("{}:{}", domain, event.dport)
                                }
                            }
                            None => "-".to_string(),
                        };

                        let time_str = format!("{:.3}s", (event.timestamp_ns as f64) / 1_000_000_000.0);

                        let (container_name, service_name, image_name, is_docker) = match container {
                            Some(info) => (
                                info.name,
                                info.compose_service.unwrap_or_else(|| "-".to_string()),
                                info.image,
                                true,
                            ),
                            None => ("[HOST]".to_string(), "-".to_string(), comm, false),
                        };

                        let key = if event.skaddr != 0 {
                            format!("{}:{}:{}", event.cgroup_id, proto, event.skaddr)
                        } else {
                            format!("{}:{}:{}", event.cgroup_id, proto, raw_ip_str)
                        };

                        let conn_item = ConnectionItem {
                            key,
                            skaddr: event.skaddr,
                            time_str,
                            container_name,
                            service: service_name,
                            image: image_name,
                            proto: proto.to_string(),
                            destination: dst_str,
                            dst_ip_str: raw_ip_str,
                            is_docker,
                            cgroup_id: event.cgroup_id,
                            status: ConnectionStatus::Active,
                            closed_at: None,
                            last_seen: Instant::now(),
                        };

                        app.add_connection(conn_item);
                    }
                }

                // 4. Draw terminal frame
                terminal.draw(|f| render_ui(f, &mut app))?;
            }
            _ = signal::ctrl_c() => {
                app.running = false;
            }
        }

        // 5. Poll keyboard events (non-blocking)
        if event::poll(Duration::from_millis(5))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }
    }

    // Cleanup terminal on exit
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

async fn run_plain_streaming_loop(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    mut dns_ring_buf: RingBuf<aya::maps::MapData>,
    mut close_ring_buf: RingBuf<aya::maps::MapData>,
    docker_mgr: Option<Arc<DockerManager>>,
    dns_cache: Arc<DnsCache>,
    show_host: bool,
    _grace_period: u64,
) -> anyhow::Result<()> {
    println!("\n{:<10} {:<12} {:<24} {:<16} {:<20} {:<6} {:<32} {:<24}", "STATUS", "TIME", "CONTAINER", "SERVICE", "IMAGE/PROCESS", "PROTO", "DESTINATION", "DST IP");
    println!("{}", "─".repeat(150));

    let mut active_sockets: HashMap<u64, (String, String, String, String, String)> = HashMap::new();
    let mut interval = tokio::time::interval(Duration::from_millis(30));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\n[INFO] Detaching probes and shutting down gracefully.");
                break;
            }
            _ = interval.tick() => {
                while let Some(item) = dns_ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<DnsPacketEvent>() {
                        let dns_event = unsafe { *(data.as_ptr() as *const DnsPacketEvent) };
                        dns_cache.process_packet(&dns_event).await;
                    }
                }

                while let Some(item) = close_ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<SocketCloseEvent>() {
                        let close_event = unsafe { *(data.as_ptr() as *const SocketCloseEvent) };
                        let time_str = format!("{:.3}s", (close_event.timestamp_ns as f64) / 1_000_000_000.0);

                        if let Some((c_col, s_col, img_col, d_str, raw_ip)) = active_sockets.remove(&close_event.skaddr) {
                            println!(
                                "\x1b[90m{:<10} {:<12} {:<33} {:<16} {:<29} {:<6} {:<41} {:<24}\x1b[0m",
                                "○ CLOSED", time_str, c_col, s_col, img_col, "TCP", d_str, raw_ip
                            );
                        } else if show_host {
                            let dst_ip: IpAddr = if close_event.ip_version == 4 {
                                IpAddr::V4(Ipv4Addr::new(
                                    close_event.daddr[0],
                                    close_event.daddr[1],
                                    close_event.daddr[2],
                                    close_event.daddr[3],
                                ))
                            } else {
                                IpAddr::V6(Ipv6Addr::from(close_event.daddr))
                            };
                            let raw_ip_str = format!("{}:{}", dst_ip, close_event.dport);
                            let resolved = dns_cache.resolve(close_event.cgroup_id, &dst_ip).await;
                            let dst_str = match resolved {
                                Some(d) => format!("{}:{}", d, close_event.dport),
                                None => "-".to_string(),
                            };
                            println!(
                                "\x1b[90m{:<10} {:<12} {:<33} {:<16} {:<29} {:<6} {:<41} {:<24}\x1b[0m",
                                "○ CLOSED", time_str, "\x1b[90m[HOST]\x1b[0m", "-", "-", "TCP", dst_str, raw_ip_str
                            );
                        }
                    }
                }

                while let Some(item) = ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<ConnectEvent>() {
                        let event = unsafe { *(data.as_ptr() as *const ConnectEvent) };
                        let container = if let Some(ref mgr) = docker_mgr {
                            mgr.lookup(event.cgroup_id).await
                        } else {
                            None
                        };

                        if container.is_some() || show_host {
                            let comm = String::from_utf8_lossy(&event.comm)
                                .trim_matches(char::from(0))
                                .to_string();

                            let proto = match event.proto {
                                1 => "ICMP",
                                6 => "TCP",
                                17 => "UDP",
                                58 => "ICMPv6",
                                _ => "RAW",
                            };

                            let dst_ip: IpAddr = if event.ip_version == 4 {
                                IpAddr::V4(Ipv4Addr::new(
                                    event.daddr[0],
                                    event.daddr[1],
                                    event.daddr[2],
                                    event.daddr[3],
                                ))
                            } else {
                                IpAddr::V6(Ipv6Addr::from(event.daddr))
                            };

                            let raw_ip_str = match dst_ip {
                                IpAddr::V4(ip) => {
                                    if proto == "ICMP" {
                                        format!("{}", ip)
                                    } else {
                                        format!("{}:{}", ip, event.dport)
                                    }
                                }
                                IpAddr::V6(ip) => {
                                    if proto == "ICMPv6" {
                                        format!("{}", ip)
                                    } else {
                                        format!("[{}]:{}", ip, event.dport)
                                    }
                                }
                            };

                            let resolved_domain = dns_cache.resolve(event.cgroup_id, &dst_ip).await;
                            let dst_str = match resolved_domain {
                                Some(domain) => {
                                    if proto == "ICMP" || proto == "ICMPv6" {
                                        format!("\x1b[1;33m{}\x1b[0m", domain)
                                    } else {
                                        format!("\x1b[1;33m{}:{}\x1b[0m", domain, event.dport)
                                    }
                                }
                                None => "-".to_string(),
                            };

                            let time_str = format!("{:.3}s", (event.timestamp_ns as f64) / 1_000_000_000.0);

                            let (container_col, service_col, image_col) = match container {
                                Some(info) => {
                                    let name_display = format!("\x1b[1;32m{}\x1b[0m", info.name);
                                    let service_display = info.compose_service.as_deref().unwrap_or("-").to_string();
                                    let image_display = info.image.clone();
                                    (name_display, service_display, image_display)
                                }
                                None => {
                                    let name_display = "\x1b[90m[HOST]\x1b[0m".to_string();
                                    let service_display = "-".to_string();
                                    let image_display = format!("\x1b[90m{}\x1b[0m", comm);
                                    (name_display, service_display, image_display)
                                }
                            };

                            println!(
                                "\x1b[1;32m{:<10}\x1b[0m {:<12} {:<33} {:<16} {:<29} {:<6} {:<41} {:<24}",
                                "● ACTIVE",
                                time_str,
                                container_col,
                                service_col,
                                image_col,
                                proto,
                                dst_str,
                                raw_ip_str
                            );

                            if event.skaddr != 0 {
                                active_sockets.insert(
                                    event.skaddr,
                                    (container_col, service_col, image_col, dst_str, raw_ip_str),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn bump_memlock_rlimit() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::warn!("Failed to increase RLIMIT_MEMLOCK: {}", std::io::Error::last_os_error());
    }
    Ok(())
}
