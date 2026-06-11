//! Streaming consensus, finality, sync, and recovery primitives for TruthLinked.
//!
//! The consensus crate coordinates transaction admission, nonce reservation,
//! block production, attestation collection, finality tracking, block repair,
//! snapshot recovery, and live sync. Changes here are protocol-critical and must
//! preserve deterministic replay across validators.

pub mod attestation_pipeline;
pub mod block_repairer;
pub mod blockchain;
pub mod genesis;
pub mod persistence;
pub mod round_state;
pub mod snapshot;
pub mod streaming_consensus;
pub mod sync;

pub use crate::blockchain::{Batch, BatchHeader, BlockChain};
pub use crate::persistence::Storage as Persistence;
pub use crate::snapshot::StateSnapshot;
pub use crate::streaming_consensus::Attestation;

use async_trait::async_trait;
use truthlinked_core::pq_execution::Transaction;
use truthlinked_net::ingress::IngressHandler;

#[async_trait]
impl IngressHandler for streaming_consensus::StreamingConsensus {
    async fn submit_transaction(&self, tx: Transaction) -> Result<[u8; 32], String> {
        streaming_consensus::StreamingConsensus::submit_transaction(self, tx).await
    }
}

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum SlashProof {
    InvalidBatchCommitment {
        height: u64,
        expected: [u8; 32],
        got: [u8; 32],
        leader_pubkey: Vec<u8>,
        leader_signature: Vec<u8>,
    },
    InvalidLeader {
        height: u64,
        expected_pubkey: Vec<u8>,
        got_pubkey: Vec<u8>,
        leader_signature: Vec<u8>,
    },
    InvalidLeaderSignature {
        height: u64,
        leader_pubkey: Vec<u8>,
        leader_signature: Vec<u8>,
    },
    InvalidParentHash {
        height: u64,
        expected_parent: [u8; 32],
        got_parent: [u8; 32],
        leader_pubkey: Vec<u8>,
        leader_signature: Vec<u8>,
    },
    InvalidExecutionOrder {
        height: u64,
        expected: [u8; 32],
        got: [u8; 32],
        leader_pubkey: Vec<u8>,
        leader_signature: Vec<u8>,
    },
    InvalidStateRoot {
        height: u64,
        expected: [u8; 32],
        got: [u8; 32],
        leader_pubkey: Vec<u8>,
        leader_signature: Vec<u8>,
    },
    InvalidAttestations {
        height: u64,
        reason: String,
        leader_pubkey: Vec<u8>,
        leader_signature: Vec<u8>,
    },
    /// Validator sent two different prevotes for the same height+round (equivocation).
    DoublePrevote {
        height: u64,
        round: u32,
        vote_a: Vec<u8>, // serialized Vote
        vote_b: Vec<u8>,
        validator_pubkey: Vec<u8>,
    },
    /// Validator sent two different precommits for the same height+round (equivocation).
    DoublePrecommit {
        height: u64,
        round: u32,
        vote_a: Vec<u8>,
        vote_b: Vec<u8>,
        validator_pubkey: Vec<u8>,
    },
}
