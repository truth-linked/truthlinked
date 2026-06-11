//! ABI helpers - selector hashing and calldata encoding/decoding.

/// FNV-1a 32-bit selector hash - matches the system cells and SDK.
pub fn selector_of(name: &str) -> [u8; 4] {
    let mut h: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h.to_le_bytes()
}

/// Read a 32-byte account ID from calldata at offset.
pub fn read_account(cd: &[u8], off: usize) -> Option<[u8; 32]> {
    if cd.len() < off + 32 {
        return None;
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&cd[off..off + 32]);
    Some(b)
}

/// Read a u64 (little-endian) from calldata at offset.
pub fn read_u64(cd: &[u8], off: usize) -> Option<u64> {
    if cd.len() < off + 8 {
        return None;
    }
    Some(u64::from_le_bytes(cd[off..off + 8].try_into().unwrap()))
}

/// Read a u128 (little-endian) from calldata at offset.
pub fn read_u128(cd: &[u8], off: usize) -> Option<u128> {
    if cd.len() < off + 16 {
        return None;
    }
    Some(u128::from_le_bytes(cd[off..off + 16].try_into().unwrap()))
}

/// Encode a u64 as 8 LE bytes.
pub fn encode_u64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// Encode a u128 as 16 LE bytes.
pub fn encode_u128(v: u128) -> [u8; 16] {
    v.to_le_bytes()
}

/// Build calldata: [4-byte selector] ++ args
pub fn calldata(selector: &str, args: &[&[u8]]) -> Vec<u8> {
    let mut out = selector_of(selector).to_vec();
    for a in args {
        out.extend_from_slice(a);
    }
    out
}
