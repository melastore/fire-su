#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct BlockListKey {
    pub uid: u32,
    pub ifindex: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AppConfig {
    pub log_connections: u8,
    pub enable_l4_filter: u8,
    pub enable_ratelimit: u8,
    pub enable_dns_filter: u8,
    pub _pad: u32,
    pub rate_limit_bytes_per_sec: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateLimitState {
    pub tokens: u64,
    pub last_time: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ipv4LpmKey {
    pub uid: u32,
    pub ip: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrafficStats {
    pub allowed_packets: u64,
    pub blocked_packets: u64,
    pub allowed_bytes: u64,
    pub blocked_bytes: u64,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficStats {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockEvent {
    pub uid: u32,
    pub ifindex: u32,
    pub reason: u32,
    pub bytes: u32,
    pub seen: u64,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockEvent {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectionLog {
    pub uid: u32,
    pub protocol: u8,
    pub action: u8, // 0 = allowed, 1 = blocked
    pub _pad: u16,
    pub src_ip: [u32; 4], // IPv4 mapped or IPv6
    pub dst_ip: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub bytes: u32,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionLog {}
