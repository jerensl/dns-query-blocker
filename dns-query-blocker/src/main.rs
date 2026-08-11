use anyhow::Context as _;
use aya::programs::{Xdp, XdpMode};
use aya::{
    maps::HashMap
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

use dns_query_blocker_common::djb2_hash_domain;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlo1")]
    iface: String,
}

/// Helper to convert standard domains into DNS wire format
/// "example.com" -> b"\x07example\x03com\x00"
fn to_dns_wire_format(domain: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    for part in domain.split('.') {
        wire.push(part.len() as u8);
        wire.extend_from_slice(part.as_bytes());
    }
    wire.push(0);
    wire
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dns-query-blocker"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("dns_query_blocker").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    let mut blocklist: HashMap<_, u32, u8> = HashMap::try_from(ebpf.map_mut("BLOCKLIST").unwrap())?;

    let blocked_domains = vec![
        "ads.google.com",
        "tracker.adtech.com",
        "telemetry.badsite.org",
        "example.com",
    ];

    for domain in blocked_domains {
        // 1. Convert standard string to DNS wire format (returns Vec<u8>)
        let wire_bytes = to_dns_wire_format(domain);

        // 2. Compute the u32 hash from those wire bytes
        let hash = djb2_hash_domain(&wire_bytes);

        // 3. Insert the computed hash into the eBPF map
        blocklist.insert(hash, 1, 0)?;

        println!("Blocked: {} (Hash: {:#x})", domain, hash);
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
