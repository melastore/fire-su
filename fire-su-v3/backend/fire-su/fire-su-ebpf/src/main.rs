#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};

use fire_su_common::{BlockEvent, TrafficStats};

const BLOCK_INTERNET: u32 = 1 << 0;
const BLOCK_LAN: u32 = 1 << 4;
const BLOCK_DNS: u32 = 1 << 5;

#[map]
static BLOCK_LIST: HashMap<u64, u32> = HashMap::with_max_entries(16384, 0);

#[map]
static TRAFFIC_STATS: HashMap<u64, TrafficStats> = HashMap::with_max_entries(32768, 0);

#[map]
static BLOCK_EVENTS: HashMap<u64, BlockEvent> = HashMap::with_max_entries(4096, 0);

#[cgroup_skb]
pub fn fire_su(ctx: SkBuffContext) -> i32 {
    match try_fire_su(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fire_su(ctx: SkBuffContext) -> Result<i32, i32> {
    let uid = ctx.skb.get_socket_uid() as u64;
    let ifindex = unsafe { (*ctx.skb.skb).ifindex as u64 };
    let bytes = ctx.skb.len();
    let packet = packet_info(&ctx);

    let iface_key = (ifindex << 32) | uid;
    if let Some(reason) = unsafe { BLOCK_LIST.get(&iface_key) } {
        record(uid, ifindex as u32, *reason, bytes, true);
        return Ok(0);
    }

    let Some(mask) = (unsafe { BLOCK_LIST.get(&uid) }) else {
        record(uid, ifindex as u32, 0, bytes, false);
        return Ok(1);
    };

    if packet.is_dns && *mask & BLOCK_DNS != 0 {
        record(uid, ifindex as u32, BLOCK_DNS, bytes, true);
        return Ok(0);
    }

    if packet.is_lan {
        if *mask & BLOCK_LAN != 0 {
            record(uid, ifindex as u32, BLOCK_LAN, bytes, true);
            return Ok(0);
        }
    } else if *mask & BLOCK_INTERNET != 0 {
        record(uid, ifindex as u32, BLOCK_INTERNET, bytes, true);
        return Ok(0);
    }

    record(uid, ifindex as u32, 0, bytes, false);
    Ok(1)
}

#[derive(Clone, Copy)]
struct PacketInfo {
    is_lan: bool,
    is_dns: bool,
}

fn packet_info(ctx: &SkBuffContext) -> PacketInfo {
    let Ok(version_ihl) = ctx.load::<u8>(0) else {
        return PacketInfo {
            is_lan: false,
            is_dns: false,
        };
    };
    match version_ihl >> 4 {
        4 => ipv4_info(ctx, version_ihl).unwrap_or(PacketInfo {
            is_lan: false,
            is_dns: false,
        }),
        6 => ipv6_info(ctx).unwrap_or(PacketInfo {
            is_lan: false,
            is_dns: false,
        }),
        _ => PacketInfo {
            is_lan: false,
            is_dns: false,
        },
    }
}

fn ipv4_info(ctx: &SkBuffContext, version_ihl: u8) -> Result<PacketInfo, i32> {
    let a = ctx.load::<u8>(16).map_err(|_| 1)?;
    let b = ctx.load::<u8>(17).map_err(|_| 1)?;
    let protocol = ctx.load::<u8>(9).map_err(|_| 1)?;
    let ihl = ((version_ihl & 0x0f) as usize) * 4;

    Ok(PacketInfo {
        is_lan: a == 10
            || a == 127
            || (a == 100 && b >= 64 && b <= 127)
            || (a == 172 && b >= 16 && b <= 31)
            || (a == 192 && b == 168)
            || (a == 169 && b == 254)
            || a >= 224,
        is_dns: l4_is_dns(ctx, protocol, ihl).unwrap_or(false),
    })
}

fn ipv6_info(ctx: &SkBuffContext) -> Result<PacketInfo, i32> {
    let a = ctx.load::<u8>(24).map_err(|_| 1)?;
    let b = ctx.load::<u8>(25).map_err(|_| 1)?;
    let last = ctx.load::<u8>(39).map_err(|_| 1)?;
    let next_header = ctx.load::<u8>(6).map_err(|_| 1)?;

    Ok(PacketInfo {
        is_lan: a == 0xff
            || (a & 0xfe) == 0xfc
            || (a == 0xfe && (b & 0xc0) == 0x80)
            || (a == 0 && b == 0 && last == 1 && ipv6_prefix_is_zero(ctx)?),
        is_dns: l4_is_dns(ctx, next_header, 40).unwrap_or(false),
    })
}

fn ipv6_prefix_is_zero(ctx: &SkBuffContext) -> Result<bool, i32> {
    Ok(ctx.load::<u8>(26).map_err(|_| 1)? == 0
        && ctx.load::<u8>(27).map_err(|_| 1)? == 0
        && ctx.load::<u8>(28).map_err(|_| 1)? == 0
        && ctx.load::<u8>(29).map_err(|_| 1)? == 0
        && ctx.load::<u8>(30).map_err(|_| 1)? == 0
        && ctx.load::<u8>(31).map_err(|_| 1)? == 0
        && ctx.load::<u8>(32).map_err(|_| 1)? == 0
        && ctx.load::<u8>(33).map_err(|_| 1)? == 0
        && ctx.load::<u8>(34).map_err(|_| 1)? == 0
        && ctx.load::<u8>(35).map_err(|_| 1)? == 0
        && ctx.load::<u8>(36).map_err(|_| 1)? == 0
        && ctx.load::<u8>(37).map_err(|_| 1)? == 0
        && ctx.load::<u8>(38).map_err(|_| 1)? == 0)
}

fn l4_is_dns(ctx: &SkBuffContext, protocol: u8, offset: usize) -> Result<bool, i32> {
    if protocol != 6 && protocol != 17 {
        return Ok(false);
    }
    let dst_port = u16::from_be(ctx.load::<u16>(offset + 2).map_err(|_| 1)?);
    Ok(dst_port == 53 || dst_port == 853)
}

fn record(uid: u64, ifindex: u32, reason: u32, bytes: u32, blocked: bool) {
    let scope = if reason == 0 { 0 } else { reason };
    let stats_key = (uid << 32) | scope as u64;
    if let Some(stats) = TRAFFIC_STATS.get_ptr_mut(&stats_key) {
        unsafe {
            if blocked {
                (*stats).blocked_packets = (*stats).blocked_packets.saturating_add(1);
                (*stats).blocked_bytes = (*stats).blocked_bytes.saturating_add(bytes as u64);
            } else {
                (*stats).allowed_packets = (*stats).allowed_packets.saturating_add(1);
                (*stats).allowed_bytes = (*stats).allowed_bytes.saturating_add(bytes as u64);
            }
        }
    } else {
        let stats = if blocked {
            TrafficStats {
                allowed_packets: 0,
                blocked_packets: 1,
                allowed_bytes: 0,
                blocked_bytes: bytes as u64,
            }
        } else {
            TrafficStats {
                allowed_packets: 1,
                blocked_packets: 0,
                allowed_bytes: bytes as u64,
                blocked_bytes: 0,
            }
        };
        let _ = TRAFFIC_STATS.insert(&stats_key, &stats, 0);
    }

    let event = BlockEvent {
        uid: uid as u32,
        ifindex,
        reason,
        bytes,
        seen: 0,
    };
    let _ = BLOCK_EVENTS.insert(&stats_key, &event, 0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
