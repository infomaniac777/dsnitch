#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_sock_addr,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{cgroup_sock_addr, map},
    maps::RingBuf,
    programs::SockAddrContext,
};
use dsnitch_common::ConnectEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[cgroup_sock_addr(connect4)]
pub fn dsnitch_connect4(ctx: SockAddrContext) -> i32 {
    let sock_addr = ctx.sock_addr as *const bpf_sock_addr;
    if sock_addr.is_null() {
        return 1;
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

    let user_ip4 = unsafe { (*sock_addr).user_ip4 };
    let user_port = unsafe { (*sock_addr).user_port };
    let protocol = unsafe { (*sock_addr).protocol };

    let ip_bytes = user_ip4.to_ne_bytes();
    let mut daddr = [0u8; 16];
    daddr[0] = ip_bytes[0];
    daddr[1] = ip_bytes[1];
    daddr[2] = ip_bytes[2];
    daddr[3] = ip_bytes[3];

    let dport = u16::from_be(user_port as u16);

    let event = ConnectEvent {
        timestamp_ns,
        cgroup_id,
        pid,
        uid,
        saddr: [0u8; 16],
        daddr,
        sport: 0,
        dport,
        proto: protocol as u8,
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

    let user_ip6 = unsafe { (*sock_addr).user_ip6 };
    let user_port = unsafe { (*sock_addr).user_port };
    let protocol = unsafe { (*sock_addr).protocol };

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

    let event = ConnectEvent {
        timestamp_ns,
        cgroup_id,
        pid,
        uid,
        saddr: [0u8; 16],
        daddr,
        sport: 0,
        dport,
        proto: protocol as u8,
        ip_version: 6,
        comm,
    };

    if let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    1
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
