#![no_std]

// Required to bound loops for the eBPF verifier
pub const MAX_DOMAIN_LEN: usize = 64;

#[inline(always)]
pub fn djb2_hash_domain(domain: &[u8]) -> u32 {
    let mut hash: u32 = 5381;

    for i in 0..MAX_DOMAIN_LEN {
        if i >= domain.len() {
            break;
        }

        let byte = domain[i];
        let c = byte.to_ascii_lowercase() as u32;
        hash = hash.wrapping_shl(5).wrapping_add(hash).wrapping_add(c);

        if byte == 0 {
            break;
        }
    }

    hash
}
