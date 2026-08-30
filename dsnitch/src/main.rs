mod dns;
mod docker;

use std::{
    fs::File,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSockAddr},
    Ebpf,
};
use clap::Parser;
use dns::DnsCache;
use docker::{ContainerInfo, DockerManager};
use dsnitch_common::{ConnectEvent, DnsPacketEvent};
use tokio::signal;

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    bump_memlock_rlimit()?;

    log::info!("Initializing Docker Egress & DNS Inspector (Phase 3: DNS Enrichment)...");
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
    let mut ring_buf = RingBuf::try_from(ring_buf_map)?;

    let dns_ring_buf_map = ebpf
        .take_map("DNS_EVENTS")
        .context("Map DNS_EVENTS not found in eBPF program")?;
    let mut dns_ring_buf = RingBuf::try_from(dns_ring_buf_map)?;

    println!("\n{:<12} {:<24} {:<16} {:<20} {:<6} {:<36}", "TIME", "CONTAINER", "SERVICE", "IMAGE/PROCESS", "PROTO", "DESTINATION");
    println!("{}", "─".repeat(120));

    let mut interval = tokio::time::interval(Duration::from_millis(30));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\n[INFO] Detaching probes and shutting down gracefully.");
                break;
            }
            _ = interval.tick() => {
                // 1. Drain incoming DNS response packets first
                while let Some(item) = dns_ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<DnsPacketEvent>() {
                        let dns_event = unsafe { *(data.as_ptr() as *const DnsPacketEvent) };
                        dns_cache.process_packet(&dns_event).await;
                    }
                }

                // 2. Drain outbound socket connect events
                while let Some(item) = ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<ConnectEvent>() {
                        let event = unsafe { *(data.as_ptr() as *const ConnectEvent) };
                        let container = if let Some(ref mgr) = docker_mgr {
                            mgr.lookup(event.cgroup_id).await
                        } else {
                            None
                        };

                        if container.is_some() || args.all {
                            display_event(&event, container.as_ref(), &dns_cache).await;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn display_event(
    event: &ConnectEvent,
    container: Option<&ContainerInfo>,
    dns_cache: &DnsCache,
) {
    let comm = String::from_utf8_lossy(&event.comm)
        .trim_matches(char::from(0))
        .to_string();

    let proto = match event.proto {
        6 => "TCP",
        17 => "UDP",
        _ => "OTHER",
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

    // Query per-cgroup DNS cache
    let resolved_domain = dns_cache.resolve(event.cgroup_id, &dst_ip).await;

    let dst_str = match resolved_domain {
        Some(domain) => {
            format!("\x1b[1;33m{}:{}\x1b[0m", domain, event.dport)
        }
        None => match dst_ip {
            IpAddr::V4(ip) => format!("{}:{}", ip, event.dport),
            IpAddr::V6(ip) => format!("[{}]:{}", ip, event.dport),
        },
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
        "{:<12} {:<33} {:<16} {:<29} {:<6} {:<45}",
        time_str,
        container_col,
        service_col,
        image_col,
        proto,
        dst_str
    );
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
