use std::{
    fs::File,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
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
use dsnitch_common::ConnectEvent;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(
    name = "dsnitch",
    author,
    version,
    about = "Zero-overhead container network & DNS egress inspector"
)]
struct Args {
    /// Cgroup v2 root path
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    bump_memlock_rlimit()?;

    println!("[INFO] Initializing dsnitch (Phase 1: Kernel Probe & Loader)...");
    println!("[INFO] Target cgroup path: {}", args.cgroup_path.display());

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
        println!("[SUCCESS] Attached connect4 probe to cgroup v2");
    }

    // Attach IPv6 connect hook
    if let Some(prog) = ebpf.program_mut("dsnitch_connect6") {
        let prog6: &mut CgroupSockAddr = prog.try_into()?;
        prog6.load()?;
        prog6.attach(&cgroup_file, CgroupAttachMode::Single)?;
        println!("[SUCCESS] Attached connect6 probe to cgroup v2");
    }

    // Open Ring Buffer map
    let ring_buf_map = ebpf.take_map("EVENTS").context("Map EVENTS not found in eBPF program")?;
    let mut ring_buf = RingBuf::try_from(ring_buf_map)?;

    println!("\n{:<12} {:<18} {:<8} {:<16} {:<6} {:<45}", "TIME", "CGROUP_ID", "PID", "PROCESS", "PROTO", "DESTINATION");
    println!("{}", "-".repeat(110));

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
                        display_event(&event);
                    }
                }
            }
        }
    }

    Ok(())
}

fn display_event(event: &ConnectEvent) {
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

    println!(
        "{:<12} {:<18} {:<8} {:<16} {:<6} {:<45}",
        time_str,
        event.cgroup_id,
        event.pid,
        comm,
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
