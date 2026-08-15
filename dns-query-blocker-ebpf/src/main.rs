#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{eth::{EthHdr, EtherType}, ip::{IpError, IpProto, Ipv4Hdr}, udp::UdpHdr};

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
        Ok(EtherType::Ipv4) => {
            // 2. Layer 3 (IPv4)
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

            match unsafe { (*ipv4hdr).proto().map_err(|_: IpError| ())? } {
                IpProto::Tcp => return Ok(xdp_action::XDP_PASS),
                IpProto::Udp => {
                    // 3. Layer 4 (UDP)
                    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                    let src_port = u16::from_be_bytes(unsafe {(*udphdr).src});

                    if src_port != 53 {
                        return Ok(xdp_action::XDP_PASS)
                    }

                    // Ensure at least 12-byte DNS header is present
                    let dns_offset =  EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + 12;

                    if ctx.data() + dns_offset > ctx.data_end() {
                        return Ok(xdp_action::XDP_PASS);
                    }

                    // 4. DNS Header + QNAME Extraction
                    let qname_ptr = ctx.data() + dns_offset;
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
                }
                _ => return Ok(xdp_action::XDP_PASS)
            };
        }
        _ => return Ok(xdp_action::XDP_PASS),
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
