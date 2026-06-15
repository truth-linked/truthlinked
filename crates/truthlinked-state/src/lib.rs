//! Deterministic state transition logic for the TruthLinked protocol.
//!
//! This crate owns account state, token accounting, cell execution hooks,
//! metrics, logs, parallel execution, and protocol constants used by validators.
//! State changes are consensus-sensitive and must preserve deterministic
//! serialization, execution ordering, and replay behavior.

pub mod cells;
pub mod constants;
pub mod log;
pub mod metrics;
pub mod parallel_executor;
pub mod pq_execution;
pub mod token;
pub mod vm;

pub use log::Log;
pub use pq_execution::State;
pub use token::{format_amount, parse_amount, TokenInfo};

// Genesis hash for genesis fingerprint
static GENESIS_HASH: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
static CURRENT_HEIGHT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn set_genesis_hash(hash: [u8; 32]) {
    let _ = GENESIS_HASH.set(hash);
}

pub fn get_genesis_hash() -> [u8; 32] {
    *GENESIS_HASH.get().unwrap_or(&[0u8; 32])
}

pub fn set_current_height(height: u64) {
    CURRENT_HEIGHT.store(height, std::sync::atomic::Ordering::SeqCst);
}

pub fn get_current_height() -> Option<u64> {
    let height = CURRENT_HEIGHT.load(std::sync::atomic::Ordering::SeqCst);
    if height > 0 {
        Some(height)
    } else {
        None
    }
}

pub fn is_testnet() -> bool {
    return true; // devnet/testnet faucet enabled
    #[allow(unreachable_code)]
    let genesis = get_genesis_hash();
    genesis == [0u8; 32]
}
pub mod system_cells;
// force rebuild Sat Jun 13 18:40:34 CEST 2026
