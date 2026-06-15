//! Core protocol primitives for TruthLinked.
//!
//! This crate defines the shared transaction, identity, cell, and protocol constant
//! types used by the node, CLI, SDKs, and tooling. The public surface is kept
//! intentionally small so downstream components can rely on stable serialization
//! and signing boundaries.

pub mod cells;
pub mod constants;
pub mod pq_execution;
pub mod pq_identity;

pub use cells::{ManifestAnalysis, StorageKeySpec};
pub use constants::ONE_TLKD;
pub use pq_execution::{BatchTransferEntry, CellCall, Transaction, TransactionIntent};
pub use pq_identity::{account_id_from_pubkey, sign_transaction, DualKeypair};

pub type AccountId = [u8; 32];
