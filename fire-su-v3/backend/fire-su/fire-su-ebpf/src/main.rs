#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::generated::bpf_ktime_get_ns,
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};

use fire_su_common::{BlockEvent, TrafficStats};

const BLOCK_INTERNET: u32 = 1 << 0;
const BLOCK_LAN: u32 = 1 << 4;

const DROP: i32 = 0;
const ALLOW: i32 = 1;

// lo is always ifindex 1 in the init netns. Localhost is never filtered: apps
// talk to their own local services and to proxies like Orbot over it.
const LOOPBACK_IFINDEX: u32 = 1;

// Key layout: uid alone for per-app bits, (ifindex << 32 | uid) for per-interface blocks.
#[map]
static BLOCK_LIST: HashMap<u64, u32> = HashMap::with_max_entries(16384, 0);

#[map]
static TRAFFIC_STATS: HashMap<u64, TrafficStats> = HashMap::with_max_entries(32768, 0);

#[map]
static BLOCK_EVENTS: HashMap<u64, BlockEvent> = HashMap::with_max_entries(4096, 0);

#[cgroup_skb]
pub fn fire_su(ctx: SkBuffContext) -> i32 {
    let uid = ctx.skb.get_socket_uid() as u64;
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    if ifindex == LOOPBACK_IFINDEX {
        return ALLOW;
    }
    let bytes = ctx.skb.len();
    let mask = uid_mask(uid);
    let iface = iface_reason(uid, ifindex);
    if mask == 0 && iface == 0 {
        return verdict(uid, ifindex, 0, bytes);
    }

    // Local traffic is decided by the LAN bit alone, whatever interface it
    // leaves on. Otherwise "LAN open" would still drop LAN over a blocked Wi-Fi.
    if is_lan(&ctx) {
        return verdict(uid, ifindex, mask & BLOCK_LAN, bytes);
    }
    let reason = if iface != 0 {
        iface
    } else {
        mask & BLOCK_INTERNET
    };
    verdict(uid, ifindex, reason, bytes)
}

// Fallback for kernels that reject packet loads: LAN can't be told apart here.
#[cgroup_skb]
pub fn fire_su_basic(ctx: SkBuffContext) -> i32 {
    let uid = ctx.skb.get_socket_uid() as u64;
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    if ifindex == LOOPBACK_IFINDEX {
        return ALLOW;
    }
    let bytes = ctx.skb.len();
    let iface = iface_reason(uid, ifindex);
    if iface != 0 {
        return verdict(uid, ifindex, iface, bytes);
    }
    verdict(uid, ifindex, first_bit(uid_mask(uid)), bytes)
}

#[cgroup_skb]
pub fn fire_su_uid(ctx: SkBuffContext) -> i32 {
    let uid = ctx.skb.get_socket_uid() as u64;
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    if ifindex == LOOPBACK_IFINDEX {
        return ALLOW;
    }
    verdict(uid, 0, first_bit(uid_mask(uid)), ctx.skb.len())
}

#[cgroup_skb]
pub fn fire_su_min(ctx: SkBuffContext) -> i32 {
    let uid = ctx.skb.get_socket_uid() as u64;
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    if ifindex != LOOPBACK_IFINDEX && uid_mask(uid) != 0 {
        DROP
    } else {
        ALLOW
    }
}

fn uid_mask(uid: u64) -> u32 {
    unsafe { BLOCK_LIST.get(&uid) }.copied().unwrap_or(0)
}

fn iface_reason(uid: u64, ifindex: u32) -> u32 {
    if ifindex == 0 {
        return 0;
    }
    let key = ((ifindex as u64) << 32) | uid;
    unsafe { BLOCK_LIST.get(&key) }.copied().unwrap_or(0)
}

fn first_bit(mask: u32) -> u32 {
    mask & mask.wrapping_neg()
}

fn is_lan(ctx: &SkBuffContext) -> bool {
    let Ok(version_ihl) = ctx.load::<u8>(0) else {
        return false;
    };
    match version_ihl >> 4 {
        4 => ipv4_dst_is_lan(ctx).unwrap_or(false),
        6 => ipv6_dst_is_lan(ctx).unwrap_or(false),
        _ => false,
    }
}

fn ipv4_dst_is_lan(ctx: &SkBuffContext) -> Result<bool, i64> {
    let a = ctx.load::<u8>(16)?;
    let b = ctx.load::<u8>(17)?;
    Ok(a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || a >= 224)
}

fn ipv6_dst_is_lan(ctx: &SkBuffContext) -> Result<bool, i64> {
    let a = ctx.load::<u8>(24)?;
    let b = ctx.load::<u8>(25)?;
    // multicast, ULA fc00::/7, link-local fe80::/10
    Ok(a == 0xff || (a & 0xfe) == 0xfc || (a == 0xfe && (b & 0xc0) == 0x80))
}

fn verdict(uid: u64, ifindex: u32, reason: u32, bytes: u32) -> i32 {
    let blocked = reason != 0;
    let key = (uid << 32) | reason as u64;
    count(key, bytes, blocked);
    if !blocked {
        return ALLOW;
    }
    let event = BlockEvent {
        uid: uid as u32,
        ifindex,
        reason,
        bytes,
        seen: unsafe { bpf_ktime_get_ns() },
    };
    let _ = BLOCK_EVENTS.insert(&key, &event, 0);
    DROP
}

fn count(key: u64, bytes: u32, blocked: bool) {
    if let Some(stats) = TRAFFIC_STATS.get_ptr_mut(&key) {
        let stats = unsafe { &mut *stats };
        if blocked {
            stats.blocked_packets = stats.blocked_packets.saturating_add(1);
            stats.blocked_bytes = stats.blocked_bytes.saturating_add(bytes as u64);
        } else {
            stats.allowed_packets = stats.allowed_packets.saturating_add(1);
            stats.allowed_bytes = stats.allowed_bytes.saturating_add(bytes as u64);
        }
        return;
    }
    let (packets, bytes) = (1, bytes as u64);
    let stats = if blocked {
        TrafficStats {
            allowed_packets: 0,
            blocked_packets: packets,
            allowed_bytes: 0,
            blocked_bytes: bytes,
        }
    } else {
        TrafficStats {
            allowed_packets: packets,
            blocked_packets: 0,
            allowed_bytes: bytes,
            blocked_bytes: 0,
        }
    };
    let _ = TRAFFIC_STATS.insert(&key, &stats, 0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
