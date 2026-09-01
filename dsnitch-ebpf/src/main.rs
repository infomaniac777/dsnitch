#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_sock_addr,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_skb_cgroup_id,
    },
    macros::{cgroup_skb, cgroup_sock_addr, map, tracepoint},
    maps::RingBuf,
    programs::{SkBuffContext, SockAddrContext, TracePointContext},
    EbpfContext,
};
use dsnitch_common::{ConnectEvent, DnsPacketEvent, SocketCloseEvent, MAX_DNS_PAYLOAD};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CLOSE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[cgroup_sock_addr(connect4)]
pub fn dsnitch_connect4(ctx: SockAddrContext) -> i32 {
    let sock_addr = ctx.sock_addr as *const bpf_sock_addr;
    if sock_addr.is_null() {
        return 1;
    }

    let user_ip4 = unsafe { (*sock_addr).user_ip4 };
    let user_port = unsafe { (*sock_addr).user_port };
    let mut protocol = unsafe { (*sock_addr).protocol } as u8;

    // Detect ICMP / RAW sockets
    let sk_type = unsafe { (*sock_addr).type_ };
    if protocol == 1 || (sk_type == 3 && protocol == 0) {
        protocol = 1; // IPPROTO_ICMP
    }

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    let ip_bytes = user_ip4.to_ne_bytes();
    let mut daddr = [0u8; 16];
    daddr[0] = ip_bytes[0];
    daddr[1] = ip_bytes[1];
    daddr[2] = ip_bytes[2];
    daddr[3] = ip_bytes[3];

    let dport = u16::from_be(user_port as u16);

    // Skip TCP sockets (handled exclusively by inet_sock_set_state with real skaddr)
    if protocol == 6 {
        return 1;
    }

    // Skip internal glibc/kernel route lookup dummy connects (UDP with port 0)
    if protocol == 17 && dport == 0 {
        return 1;
    }

    let event = ConnectEvent {
        timestamp_ns,
        cgroup_id,
        skaddr: 0,
        pid,
        uid,
        saddr: [0u8; 16],
        daddr,
        sport: 0,
        dport,
        proto: protocol,
        ip_version: 4,
        comm,
    };

    if let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    1
}

#[cgroup_sock_addr(connect6)]
pub fn dsnitch_connect6(ctx: SockAddrContext) -> i32 {
    let sock_addr = ctx.sock_addr as *const bpf_sock_addr;
    if sock_addr.is_null() {
        return 1;
    }

    let user_ip6 = unsafe { (*sock_addr).user_ip6 };
    let user_port = unsafe { (*sock_addr).user_port };
    let mut protocol = unsafe { (*sock_addr).protocol } as u8;

    let sk_type = unsafe { (*sock_addr).type_ };
    if protocol == 58 || (sk_type == 3 && protocol == 0) {
        protocol = 58; // IPPROTO_ICMPV6
    }

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    let b0 = user_ip6[0].to_ne_bytes();
    let b1 = user_ip6[1].to_ne_bytes();
    let b2 = user_ip6[2].to_ne_bytes();
    let b3 = user_ip6[3].to_ne_bytes();

    let daddr = [
        b0[0], b0[1], b0[2], b0[3],
        b1[0], b1[1], b1[2], b1[3],
        b2[0], b2[1], b2[2], b2[3],
        b3[0], b3[1], b3[2], b3[3],
    ];

    let dport = u16::from_be(user_port as u16);

    // Skip TCP sockets (handled exclusively by inet_sock_set_state with real skaddr)
    if protocol == 6 {
        return 1;
    }

    // Skip internal glibc/kernel route lookup dummy connects (UDP with port 0)
    if protocol == 17 && dport == 0 {
        return 1;
    }

    let event = ConnectEvent {
        timestamp_ns,
        cgroup_id,
        skaddr: 0,
        pid,
        uid,
        saddr: [0u8; 16],
        daddr,
        sport: 0,
        dport,
        proto: protocol,
        ip_version: 6,
        comm,
    };

    if let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    1
}

#[tracepoint]
pub fn dsnitch_sock_set_state(ctx: TracePointContext) -> u32 {
    let _ = try_sock_set_state(&ctx);
    0
}

#[inline(always)]
fn try_sock_set_state(ctx: &TracePointContext) -> Result<(), ()> {
    let skaddr: u64 = unsafe { ctx.read_at(8).map_err(|_| ())? };
    let newstate: i32 = unsafe { ctx.read_at(20).map_err(|_| ())? };

    let family: u16 = unsafe { ctx.read_at(28).map_err(|_| ())? };
    let protocol: u16 = unsafe { ctx.read_at(30).map_err(|_| ())? };
    let sport: u16 = unsafe { ctx.read_at(24).map_err(|_| ())? };
    let dport: u16 = unsafe { ctx.read_at(26).map_err(|_| ())? };

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    // 1. TCP Connection Initiation (SYN_SENT = 2)
    if newstate == 2 {
        if family == 2 {
            let saddr4: [u8; 4] = unsafe { ctx.read_at(32).map_err(|_| ())? };
            let daddr4: [u8; 4] = unsafe { ctx.read_at(36).map_err(|_| ())? };

            let mut saddr = [0u8; 16];
            let mut daddr = [0u8; 16];
            saddr[0..4].copy_from_slice(&saddr4);
            daddr[0..4].copy_from_slice(&daddr4);

            let event = ConnectEvent {
                timestamp_ns,
                cgroup_id,
                skaddr,
                pid: 0,
                uid: 0,
                saddr,
                daddr,
                sport,
                dport,
                proto: 6, // TCP
                ip_version: 4,
                comm,
            };

            if let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) {
                entry.write(event);
                entry.submit(0);
            }
        } else if family == 10 {
            let saddr_v6: [u8; 16] = unsafe { ctx.read_at(40).map_err(|_| ())? };
            let daddr_v6: [u8; 16] = unsafe { ctx.read_at(56).map_err(|_| ())? };

            let event = ConnectEvent {
                timestamp_ns,
                cgroup_id,
                skaddr,
                pid: 0,
                uid: 0,
                saddr: saddr_v6,
                daddr: daddr_v6,
                sport,
                dport,
                proto: 6,
                ip_version: 6,
                comm,
            };

            if let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) {
                entry.write(event);
                entry.submit(0);
            }
        }
        return Ok(());
    }

    // 2. TCP Connection Termination (TCP_CLOSE = 7, TCP_TIME_WAIT = 6)
    if newstate == 7 || newstate == 6 {
        if family == 2 {
            let saddr4: [u8; 4] = unsafe { ctx.read_at(32).map_err(|_| ())? };
            let daddr4: [u8; 4] = unsafe { ctx.read_at(36).map_err(|_| ())? };

            let mut saddr = [0u8; 16];
            let mut daddr = [0u8; 16];
            saddr[0..4].copy_from_slice(&saddr4);
            daddr[0..4].copy_from_slice(&daddr4);

            let event = SocketCloseEvent {
                timestamp_ns,
                cgroup_id,
                skaddr,
                saddr,
                daddr,
                sport,
                dport,
                proto: protocol as u8,
                ip_version: 4,
            };

            if let Some(mut entry) = CLOSE_EVENTS.reserve::<SocketCloseEvent>(0) {
                entry.write(event);
                entry.submit(0);
            }
        } else if family == 10 {
            let saddr_v6: [u8; 16] = unsafe { ctx.read_at(40).map_err(|_| ())? };
            let daddr_v6: [u8; 16] = unsafe { ctx.read_at(56).map_err(|_| ())? };

            let event = SocketCloseEvent {
                timestamp_ns,
                cgroup_id,
                skaddr,
                saddr: saddr_v6,
                daddr: daddr_v6,
                sport,
                dport,
                proto: protocol as u8,
                ip_version: 6,
            };

            if let Some(mut entry) = CLOSE_EVENTS.reserve::<SocketCloseEvent>(0) {
                entry.write(event);
                entry.submit(0);
            }
        }
    }

    Ok(())
}

#[cgroup_skb(ingress)]
pub fn dsnitch_dns_ingress(ctx: SkBuffContext) -> i32 {
    let _ = try_dns_packet(&ctx);
    1
}

#[cgroup_skb(egress)]
pub fn dsnitch_dns_egress(ctx: SkBuffContext) -> i32 {
    let _ = try_dns_packet(&ctx);
    1
}

#[inline(always)]
fn try_dns_packet(ctx: &SkBuffContext) -> Result<(), ()> {
    let ver_ihl = ctx.load::<u8>(0).map_err(|_| ())?;
    let version = ver_ihl >> 4;

    let (payload_offset, payload_len) = if version == 4 {
        let ihl = ((ver_ihl & 0x0f) * 4) as usize;
        let proto = ctx.load::<u8>(9).map_err(|_| ())?;

        // Canonical Layer-3 ICMPv4 inspection (RFC 791, Protocol 1)
        if proto == 1 {
            let d0 = ctx.load::<u8>(16).map_err(|_| ())?;
            let d1 = ctx.load::<u8>(17).map_err(|_| ())?;
            let d2 = ctx.load::<u8>(18).map_err(|_| ())?;
            let d3 = ctx.load::<u8>(19).map_err(|_| ())?;

            let mut daddr = [0u8; 16];
            daddr[0] = d0;
            daddr[1] = d1;
            daddr[2] = d2;
            daddr[3] = d3;

            let mut cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.as_ptr() as *mut _) };
            if cgroup_id == 0 {
                cgroup_id = unsafe { bpf_get_current_cgroup_id() };
            }
            let timestamp_ns = unsafe { bpf_ktime_get_ns() };

            let event = ConnectEvent {
                timestamp_ns,
                cgroup_id,
                skaddr: 0,
                pid: 0,
                uid: 0,
                saddr: [0u8; 16],
                daddr,
                sport: 0,
                dport: 0,
                proto: 1, // IPPROTO_ICMP
                ip_version: 4,
                comm: [0u8; 16],
            };

            if let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) {
                entry.write(event);
                entry.submit(0);
            }
            return Ok(());
        }

        if proto != 17 {
            return Ok(());
        }

        let p0 = ctx.load::<u8>(ihl).map_err(|_| ())? as u16;
        let p1 = ctx.load::<u8>(ihl + 1).map_err(|_| ())? as u16;
        let src_port = (p0 << 8) | p1;

        let p2 = ctx.load::<u8>(ihl + 2).map_err(|_| ())? as u16;
        let p3 = ctx.load::<u8>(ihl + 3).map_err(|_| ())? as u16;
        let dst_port = (p2 << 8) | p3;

        let l0 = ctx.load::<u8>(ihl + 4).map_err(|_| ())? as usize;
        let l1 = ctx.load::<u8>(ihl + 5).map_err(|_| ())? as usize;
        let udp_len = (l0 << 8) | l1;

        if src_port != 53 && dst_port != 53 {
            return Ok(());
        }
        let p_len = if udp_len > 8 { udp_len - 8 } else { 0 };
        (ihl + 8, p_len)
    } else if version == 6 {
        let proto = ctx.load::<u8>(6).map_err(|_| ())?;

        // Canonical Layer-3 ICMPv6 inspection (RFC 8200, NextHeader 58)
        if proto == 58 {
            let mut daddr = [0u8; 16];
            let mut i = 0;
            while i < 16 {
                if let Ok(b) = ctx.load::<u8>(24 + i) {
                    daddr[i] = b;
                }
                i += 1;
            }

            let mut cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.as_ptr() as *mut _) };
            if cgroup_id == 0 {
                cgroup_id = unsafe { bpf_get_current_cgroup_id() };
            }
            let timestamp_ns = unsafe { bpf_ktime_get_ns() };

            let event = ConnectEvent {
                timestamp_ns,
                cgroup_id,
                skaddr: 0,
                pid: 0,
                uid: 0,
                saddr: [0u8; 16],
                daddr,
                sport: 0,
                dport: 0,
                proto: 58, // IPPROTO_ICMPV6
                ip_version: 6,
                comm: [0u8; 16],
            };

            if let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) {
                entry.write(event);
                entry.submit(0);
            }
            return Ok(());
        }

        if proto != 17 {
            return Ok(());
        }

        let p0 = ctx.load::<u8>(40).map_err(|_| ())? as u16;
        let p1 = ctx.load::<u8>(41).map_err(|_| ())? as u16;
        let src_port = (p0 << 8) | p1;

        let p2 = ctx.load::<u8>(42).map_err(|_| ())? as u16;
        let p3 = ctx.load::<u8>(43).map_err(|_| ())? as u16;
        let dst_port = (p2 << 8) | p3;

        let l0 = ctx.load::<u8>(44).map_err(|_| ())? as usize;
        let l1 = ctx.load::<u8>(45).map_err(|_| ())? as usize;
        let udp_len = (l0 << 8) | l1;

        if src_port != 53 && dst_port != 53 {
            return Ok(());
        }
        let p_len = if udp_len > 8 { udp_len - 8 } else { 0 };
        (48, p_len)
    } else {
        return Ok(());
    };

    if payload_len == 0 {
        return Ok(());
    }

    let max_len = if payload_len > MAX_DNS_PAYLOAD {
        MAX_DNS_PAYLOAD
    } else {
        payload_len
    };

    let mut cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.as_ptr() as *mut _) };
    if cgroup_id == 0 {
        cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    }
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    if let Some(mut entry) = DNS_EVENTS.reserve::<DnsPacketEvent>(0) {
        let ptr = entry.as_mut_ptr() as *mut DnsPacketEvent;
        unsafe {
            (*ptr).timestamp_ns = timestamp_ns;
            (*ptr).cgroup_id = cgroup_id;
            (*ptr).len = max_len as u32;

            let mut i = 0;
            while i < MAX_DNS_PAYLOAD {
                if i >= max_len {
                    break;
                }
                if let Ok(b) = ctx.load::<u8>(payload_offset + i) {
                    (*ptr).payload[i] = b;
                } else {
                    break;
                }
                i += 1;
            }
        }
        entry.submit(0);
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
