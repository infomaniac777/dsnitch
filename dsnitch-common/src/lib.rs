#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub uid: u32,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub ip_version: u8, // 4 for IPv4, 6 for IPv6
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectEvent {}
