#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}, udp::UdpHdr};

use dns_query_blocker_common::{djb2_hash_domain, MAX_DOMAIN_LEN};

#[map]
static BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(100_000, 0);

#[xdp]
pub fn dns_query_blocker(ctx: XdpContext) -> u32 {
    match try_dns_query_blocker(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] // (1)
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_dns_query_blocker(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Layer 2 (Ethernet)
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // 2. Layer 3 (IPv4)
    let ip_offset = mem::size_of::<EthHdr>();
    let iphdr: *const Ipv4Hdr = ptr_at(&ctx, ip_offset)?;

    let is_udp = unsafe { (*iphdr).proto == IpProto::Udp.into() };
    if !is_udp {
        return Ok(xdp_action::XDP_PASS);
    }

    // 3. Layer 4 (UDP)
    let udp_offset = ip_offset + mem::size_of::<Ipv4Hdr>();
    let udp_hdr: *const UdpHdr = ptr_at(&ctx, udp_offset)?;

    let src_port = u16::from_be_bytes(unsafe { (*udp_hdr).src });

    if src_port != 53 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 4. DNS Header + QNAME Extraction
    let dns_offset = udp_offset + mem::size_of::<UdpHdr>();

    info!(&ctx, "DNS Header: {}", dns_offset);
 
    // Ensure at least 12-byte DNS header is present
    if ctx.data() + dns_offset + 12 > ctx.data_end() {
        info!(&ctx, "DNS header is not 12 bytes");

        return Ok(xdp_action::XDP_PASS);
    }

    let qname_ptr = ctx.data() + dns_offset + 12;
    let mut current_ptr = qname_ptr;
    let mut qname_len = 0;

    for _ in 0..MAX_DOMAIN_LEN {
        if current_ptr + 1 > ctx.data_end() {
            break;
        }

        let byte = unsafe { *(current_ptr as *const u8) };
        qname_len += 1;

        if byte == 0 {
            break;
        }

        current_ptr += 1;
    }

    let qname_slice = unsafe { 
        core::slice::from_raw_parts(qname_ptr as *const u8, qname_len) 
    };

    let hash = djb2_hash_domain(qname_slice);

    if unsafe { BLOCKLIST.get(&hash) }.is_some() {
        info!(&ctx, "Dropping DNS query (Hash: {})", hash);
        return Ok(xdp_action::XDP_DROP);
    }
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
