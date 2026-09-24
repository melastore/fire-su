#![no_std]

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
    // bpf_ktime_get_ns, i.e. CLOCK_MONOTONIC
    pub seen: u64,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockEvent {}
