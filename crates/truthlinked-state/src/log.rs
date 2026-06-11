//! Truthlinked State Src Log
//!
//! Owns structured execution logs emitted by the state layer.
//! State changes are consensus-sensitive and must preserve deterministic execution and serialization.

use serde::{Deserialize, Serialize};

pub type AccountId = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}
