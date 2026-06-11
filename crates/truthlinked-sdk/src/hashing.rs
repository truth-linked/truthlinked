//! Hashing helpers - storage key derivation matching the node's conventions.

use sha2::{Digest, Sha256};

/// SHA-256 of input.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Derive a storage namespace key: SHA-256(namespace_str).
pub fn namespace(name: &str) -> [u8; 32] {
    sha256(name.as_bytes())
}

/// Derive a storage slot: SHA-256(namespace || key).
pub fn storage_key(ns: &[u8; 32], key: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 64];
    d[..32].copy_from_slice(ns);
    d[32..].copy_from_slice(key);
    sha256(&d)
}

/// Derive a storage slot from multiple key parts.
pub fn storage_key_parts(ns: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut d = ns.to_vec();
    for p in parts {
        d.extend_from_slice(p);
    }
    sha256(&d)
}

/// Derive account ID from a Dilithium public key.
pub fn account_id_from_pubkey(pubkey: &[u8]) -> [u8; 32] {
    let mut d = b"truthlinked-account-id-v1".to_vec();
    d.extend_from_slice(pubkey);
    sha256(&d)
}

/// Derive a governance param key: SHA-256("truthlinked.param.v1" || name).
pub fn param_key(name: &str) -> [u8; 32] {
    let mut d = b"truthlinked.param.v1".to_vec();
    d.extend_from_slice(name.as_bytes());
    sha256(&d)
}
