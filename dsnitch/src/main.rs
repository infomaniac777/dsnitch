mod docker;

use std::{
    fs::File,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{CgroupAttachMode, CgroupSockAddr},
    Ebpf,
};
use clap::Parser;
use docker::{ContainerInfo, DockerManager};
use dsnitch_common::ConnectEvent;
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

    println!("\x1b[1;36m[dsnitch]\x1b[0m Initializing Docker Egress Inspector (Phase 2: Docker Integration)...");
    println!("[INFO] Target cgroup path: {}", args.cgroup_path.display());

    // 1. Initialize Docker Engine synchronizer
    let docker_mgr = match DockerManager::new() {
        Ok(mgr) => {
            let mgr = Arc::new(mgr);
            match mgr.sync_running_containers().await {
                Ok(count) => {
                    println!("\x1b[1;32m[DOCKER]\x1b[0m Connected to Docker daemon (Active containers: {})", count);
                }
                Err(err) => {
                    println!("\x1b[1;33m[WARN]\x1b[0m Could not list running containers: {:#}", err);
                }
            }
            let listener_mgr = Arc::clone(&mgr);
            tokio::spawn(async move {
                listener_mgr.start_event_listener().await;
            });
            Some(mgr)
        }
        Err(err) => {
            println!("\x1b[1;33m[WARN]\x1b[0m Docker not available: {:#}. Running in host-only mode.", err);
            None
        }
    };

    // 2. Load eBPF bytecode
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
        println!("\x1b[1;32m[SUCCESS]\x1b[0m Attached connect4 probe to cgroup v2");
    }

    // Attach IPv6 connect hook
    if let Some(prog) = ebpf.program_mut("dsnitch_connect6") {
        let prog6: &mut CgroupSockAddr = prog.try_into()?;
        prog6.load()?;
        prog6.attach(&cgroup_file, CgroupAttachMode::Single)?;
        println!("\x1b[1;32m[SUCCESS]\x1b[0m Attached connect6 probe to cgroup v2");
    }

    // Open Ring Buffer map
    let ring_buf_map = ebpf.take_map("EVENTS").context("Map EVENTS not found in eBPF program")?;
    let mut ring_buf = RingBuf::try_from(ring_buf_map)?;

    println!("\n{:<12} {:<24} {:<16} {:<20} {:<6} {:<30}", "TIME", "CONTAINER", "SERVICE", "IMAGE/PROCESS", "PROTO", "DESTINATION");
    println!("{}", "─".repeat(115));

    let mut interval = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\n[INFO] Detaching probes and shutting down gracefully.");
                break;
            }
            _ = interval.tick() => {
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
                            display_event(&event, container.as_ref());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn display_event(event: &ConnectEvent, container: Option<&ContainerInfo>) {
    let comm = String::from_utf8_lossy(&event.comm)
        .trim_matches(char::from(0))
        .to_string();

    let proto = match event.proto {
        6 => "TCP",
        17 => "UDP",
        _ => "OTHER",
    };

    let dst_str = if event.ip_version == 4 {
        let ip = Ipv4Addr::new(
            event.daddr[0],
            event.daddr[1],
            event.daddr[2],
            event.daddr[3],
        );
        format!("{}:{}", ip, event.dport)
    } else {
        let ip = Ipv6Addr::from(event.daddr);
        format!("[{}]:{}", ip, event.dport)
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
        "{:<12} {:<33} {:<16} {:<29} {:<6} {:<30}",
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
