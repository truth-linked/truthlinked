//! Truthlinked Consensus Src Streaming Consensus
//!
//! Owns the live validator consensus, gossip, sync, and recovery protocol.
//! Consensus changes are protocol-critical; preserve deterministic replay, recovery safety, and wire compatibility.

use fips204::ml_dsa_65::PublicKey as DilithiumPublicKey;
use fips204::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, Duration};
use truthlinked_core::pq_execution::{AccountId, Transaction};
use truthlinked_core::DualKeypair;
use truthlinked_net::pq_transport::{PQHandshake, PQSession, PQStream};

use truthlinked_staking::{DoubleSignEvidence, SlashReason};

use truthlinked_governance::params as gp;
use truthlinked_state::constants::*;

const OUTBOUND_QUEUE_CAP: usize = 4096;
const TX_ADMISSION_LAG_TOLERANCE: u64 = 8;
const LIVE_SYNC_STATUS_LAG_TOLERANCE: u64 = 8;
const RAW_BLOCK_RETENTION: u64 = 256;

#[derive(Clone, Serialize, Deserialize)]
pub struct StreamedTx {
    pub tx: Transaction,
    pub validator_sig: Vec<u8>, // Cached signature
    pub validator_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TxLifecycleStatus {
    Pending { since_height: u64 },
    Confirmed,
    Rejected { reason: String },
}

#[derive(Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    Transaction(StreamedTx),
    BlockHeader(crate::BatchHeader),
    /// Leader broadcasts batch proposal before quorum - non-leaders attest to this.
    BatchProposal {
        height: u64,
        parent_hash: [u8; 32],
        batch_hash: [u8; 32],
        batch: Vec<Transaction>,
        state_root: [u8; 32],
        leader_pubkey: Vec<u8>,
        leader_round: u32,
    },
    CompactBatchProposal {
        height: u64,
        parent_hash: [u8; 32],
        batch_hash: [u8; 32],
        tx_hashes: Vec<[u8; 32]>,
        state_root: [u8; 32],
        leader_pubkey: Vec<u8>,
        leader_round: u32,
    },
    BatchRequest {
        batch_hash: [u8; 32],
    },
    BatchResponse {
        batch_hash: [u8; 32],
        batch: Vec<Transaction>,
    },
    Attestation(Attestation),
    HeightAnnouncement(HeightAnnouncement),
    /// Every validator broadcasts its independently-computed batch_hash before leader election.
    /// The leader must propose the hash seen by 2/3+ validators - prevents censorship.
    BatchCommitment {
        height: u64,
        batch_hash: [u8; 32],
        validator_pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    /// BFT prevote: validator votes for (or against with None) a proposed block.
    Prevote {
        height: u64,
        round: u32,
        block_hash: Option<[u8; 32]>,
        validator_pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    /// BFT precommit: validator commits after seeing 2/3+ prevotes for same block.
    Precommit {
        height: u64,
        round: u32,
        block_hash: Option<[u8; 32]>,
        validator_pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Request blocks by height range anchored to the receiver's canonical parent.
    /// A peer must only serve the range if `anchor_hash` is canonical at `anchor_height`.
    SyncRequest {
        from_height: u64,
        to_height: u64,
        anchor_height: u64,
        anchor_hash: [u8; 32],
    },
    /// Response with headers, batches, and tx results for the requested range.
    /// The request anchor is echoed so receivers can reject stale/incompatible responses.
    SyncResponse {
        request_from_height: u64,
        request_to_height: u64,
        request_anchor_height: u64,
        request_anchor_hash: [u8; 32],
        responder_height: u64,
        blocks: Vec<(crate::BatchHeader, Vec<Transaction>, Vec<String>)>,
    },
    /// New node requests a snapshot at or above the requested recovery height.
    SnapshotRequest {
        min_height: u64,
    },
    /// Peer responds with its latest snapshot
    SnapshotResponse {
        snapshot: Box<crate::StateSnapshot>,
        tip_header: Option<crate::BatchHeader>,
    },
    /// Keepalive ping - peer must respond with Pong
    Ping,
    /// Keepalive pong response
    Pong,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Attestation {
    pub height: u64,
    pub round: u64,
    pub batch_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub validator_pubkey: Vec<u8>,
    pub signature: Vec<u8>, // ML-DSA signature over finality vote domain
}

fn validate_sync_response_shape(
    request_from_height: u64,
    request_to_height: u64,
    request_anchor_height: u64,
    request_anchor_hash: [u8; 32],
    responder_height: u64,
    headers: &[crate::BatchHeader],
) -> Result<(), String> {
    if headers.is_empty() {
        return Err("empty sync response".to_string());
    }
    if request_from_height == 0 || request_anchor_height.saturating_add(1) != request_from_height {
        return Err(format!(
            "invalid echoed anchor height {} for request {}-{}",
            request_anchor_height, request_from_height, request_to_height
        ));
    }

    let expected_len = request_to_height
        .saturating_sub(request_from_height)
        .saturating_add(1) as usize;
    if headers.len() != expected_len {
        return Err(format!(
            "partial sync response: got {} headers for request {}-{} (expected {})",
            headers.len(),
            request_from_height,
            request_to_height,
            expected_len
        ));
    }
    if responder_height < request_to_height {
        return Err(format!(
            "responder height {} is below requested tail {}",
            responder_height, request_to_height
        ));
    }

    let mut expected_height = request_from_height;
    let mut expected_parent = request_anchor_hash;
    for header in headers {
        if header.height != expected_height {
            return Err(format!(
                "non-contiguous sync response: expected height {}, got {}",
                expected_height, header.height
            ));
        }
        if header.parent_hash != expected_parent {
            return Err(format!(
                "sync response block {} parent {} does not extend expected {}",
                header.height,
                hex::encode(&header.parent_hash[..8]),
                hex::encode(&expected_parent[..8])
            ));
        }
        expected_parent = header.batch_hash;
        expected_height = expected_height.saturating_add(1);
    }

    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HeightAnnouncement {
    pub validator_pubkey: Vec<u8>,
    pub height: u64,
    pub peer_addr: String,
    pub signature: Vec<u8>, // Signature over height + peer_addr
}

#[derive(Clone)]
struct CachedBatch {
    batch: Vec<Transaction>,
}

#[derive(Clone)]
struct PendingHeaderEntry {
    header: crate::BatchHeader,
    received_at: Instant,
}

#[derive(Clone)]
struct PendingBatchEntry {
    batch: Vec<Transaction>,
    created_at: Instant,
}

#[derive(Default)]
struct NonceReservations {
    by_sender: HashMap<AccountId, HashMap<u64, [u8; 32]>>,
    by_hash: HashMap<[u8; 32], (AccountId, u64)>,
}

#[allow(dead_code)]
pub struct StreamingConsensus {
    keypair: Arc<DualKeypair>,
    validator_pubkey: Vec<u8>,
    validators: Arc<Vec<Vec<u8>>>,

    handshake: Arc<PQHandshake>,
    sessions: Arc<RwLock<HashMap<Vec<u8>, PQSession>>>,
    peer_senders: Arc<RwLock<HashMap<Vec<u8>, tokio::sync::mpsc::Sender<Vec<u8>>>>>,

    peer_discovery: Arc<truthlinked_net::discovery::PeerDiscovery>,

    attestation_pipeline: Option<Arc<crate::attestation_pipeline::AttestationPipeline>>,

    state: Arc<arc_swap::ArcSwap<truthlinked_state::State>>,

    blockchain: Arc<tokio::sync::RwLock<crate::BlockChain>>,
    finalized_height: Arc<std::sync::atomic::AtomicU64>,

    storage: Option<Arc<crate::Persistence>>,

    sync_buffer: Arc<RwLock<HashMap<u64, (crate::BatchHeader, crate::Batch)>>>,
    is_syncing: Arc<RwLock<bool>>,

    current_epoch: Arc<RwLock<u64>>,
    active_attesters: Arc<RwLock<Vec<Vec<u8>>>>,
    am_i_active_attester: Arc<RwLock<bool>>,

    // Batch accumulation
    batch: Arc<RwLock<Vec<Transaction>>>,
    mempool_index: Arc<RwLock<HashMap<AccountId, Vec<[u8; 32]>>>>,
    nonce_reservations: Arc<RwLock<NonceReservations>>,
    seen_txs: Arc<RwLock<HashSet<[u8; 32]>>>,
    seen_txs_order: Arc<RwLock<VecDeque<[u8; 32]>>>,
    tx_lifecycle: Arc<RwLock<HashMap<[u8; 32], TxLifecycleStatus>>>,
    tx_lifecycle_order: Arc<RwLock<VecDeque<[u8; 32]>>>,

    // Cached batches for on-demand fetch
    batch_cache: Arc<RwLock<HashMap<[u8; 32], CachedBatch>>>,
    batch_cache_order: Arc<RwLock<VecDeque<[u8; 32]>>>,
    pending_headers: Arc<RwLock<HashMap<[u8; 32], PendingHeaderEntry>>>,
    pending_batches: Arc<RwLock<HashMap<[u8; 32], PendingBatchEntry>>>,
    current_height: Arc<std::sync::atomic::AtomicU64>,

    // Sync manager
    sync_manager: Arc<RwLock<crate::sync::SyncManager>>,

    // Autonomous block repairer - runs in background, fixes corrupt/missing blocks
    block_repairer: Option<Arc<crate::block_repairer::BlockRepairer>>,

    /// Last batch execution time in ms - used to dynamically cap batch size.
    last_exec_ms: Arc<std::sync::atomic::AtomicU64>,

    /// Tracks how many times each batch has timed out waiting for its leader.
    /// On each timeout the round increments, rotating the leader election to
    /// the next validator. Resets when the batch is successfully committed.
    leader_skip_rounds: Arc<RwLock<HashMap<[u8; 32], u32>>>,

    /// Tracks the last height at which each validator successfully attested.
    /// Validators that haven't attested in LIVENESS_WINDOW blocks are excluded
    /// from the active attester set and quorum - prevents offline validators from halting the chain.
    validator_last_attested: Arc<RwLock<HashMap<Vec<u8>, u64>>>,

    /// Local equivocation guard for consensus votes. A validator may sign one
    /// batch/state pair per height and round; conflicting proposals must rotate
    /// to a later round instead of collecting mixed certificates.
    signed_attestations: Arc<RwLock<HashMap<(u64, u64), ([u8; 32], [u8; 32])>>>,

    // Broadcast channel for incoming TXs
    tx_broadcast: broadcast::Sender<StreamedTx>,
    /// Cache: (state pointer addr, state_root). Avoids recomputing on every block.
    state_root_cache: Arc<std::sync::Mutex<(usize, [u8; 32])>>,

    // Broadcast channel for attestations
    attestation_broadcast: broadcast::Sender<Attestation>,

    /// Serializes all batch executions to prevent concurrent mutation of process-wide
    /// globals (PARAM_CACHE, GLOBAL_ORACLE_RESULTS, etc.) causing state root divergence.
    execution_lock: Arc<tokio::sync::Mutex<()>>,

    /// Phase-2 censorship resistance: tracks which validators committed to which
    /// batch_hash at each height. Key: height → (batch_hash → set of validator pubkeys).
    /// Cleared when height is finalized.
    batch_commitments: Arc<RwLock<HashMap<u64, HashMap<[u8; 32], HashSet<Vec<u8>>>>>>,

    /// Phase-3 BFT: per-height round state (Tendermint Prevote/Precommit).
    /// Replaced when height advances.
    bft_round: Arc<RwLock<crate::round_state::RoundState>>,
}

impl StreamingConsensus {
    fn is_active_validator(&self, pubkey: &[u8]) -> bool {
        let state = self.state.load();
        let height = state.staking.current_height;
        state
            .staking
            .validators
            .get(pubkey)
            .map(|stake| stake.is_active(height))
            .unwrap_or(false)
    }

    fn active_validators(&self) -> Vec<Vec<u8>> {
        let state = self.state.load();
        let height = state.staking.current_height;
        let mut validators: Vec<Vec<u8>> = state
            .staking
            .validators
            .iter()
            .filter(|(_, stake)| stake.is_active(height))
            .map(|(pk, _)| pk.clone())
            .collect();
        // CRITICAL: sort for deterministic leader election across all nodes.
        // HashMap iteration order is randomized per-process; without sorting,
        // different nodes elect different leaders for the same (height, round, batch_hash).
        validators.sort_unstable();
        validators
    }

    pub fn new(
        keypair: DualKeypair,
        validators: Vec<Vec<u8>>,
        initial_state: truthlinked_state::State,
    ) -> (Self, broadcast::Receiver<StreamedTx>) {
        let validator_pubkey = keypair.dilithium_pk.clone().into_bytes().to_vec();
        let (tx_broadcast, rx) = broadcast::channel(10000);
        let (attestation_broadcast, _) = broadcast::channel(1000);

        let handshake = Arc::new(PQHandshake::from_keypair(&keypair));

        let attester_set_size = validators.len().min(21);
        let attestation_pipeline = Some(Arc::new(
            crate::attestation_pipeline::AttestationPipeline::new(attester_set_size),
        ));

        let consensus = Self {
            keypair: Arc::new(keypair),
            validator_pubkey,
            validators: Arc::new(validators.clone()),
            handshake,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            peer_senders: Arc::new(RwLock::new(HashMap::new())),
            peer_discovery: Arc::new(truthlinked_net::discovery::PeerDiscovery::new()),
            attestation_pipeline,
            state: Arc::new(arc_swap::ArcSwap::from_pointee(initial_state)),
            blockchain: Arc::new(tokio::sync::RwLock::new(crate::BlockChain::new())),
            finalized_height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            storage: None,
            sync_buffer: Arc::new(RwLock::new(HashMap::new())),
            is_syncing: Arc::new(RwLock::new(false)),
            current_epoch: Arc::new(RwLock::new(0)),
            active_attesters: Arc::new(RwLock::new(Vec::new())),
            am_i_active_attester: Arc::new(RwLock::new(false)),
            batch: Arc::new(RwLock::new(Vec::new())),
            mempool_index: Arc::new(RwLock::new(HashMap::new())),
            nonce_reservations: Arc::new(RwLock::new(NonceReservations::default())),
            seen_txs: Arc::new(RwLock::new(HashSet::new())),
            seen_txs_order: Arc::new(RwLock::new(VecDeque::new())),
            tx_lifecycle: Arc::new(RwLock::new(HashMap::new())),
            tx_lifecycle_order: Arc::new(RwLock::new(VecDeque::new())),
            batch_cache: Arc::new(RwLock::new(HashMap::new())),
            batch_cache_order: Arc::new(RwLock::new(VecDeque::new())),
            pending_headers: Arc::new(RwLock::new(HashMap::new())),
            pending_batches: Arc::new(RwLock::new(HashMap::new())),
            current_height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            sync_manager: Arc::new(RwLock::new(crate::sync::SyncManager::new())),
            block_repairer: None,
            last_exec_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            leader_skip_rounds: Arc::new(RwLock::new(HashMap::new())),
            validator_last_attested: Arc::new(RwLock::new(HashMap::new())),
            signed_attestations: Arc::new(RwLock::new(HashMap::new())),
            tx_broadcast,
            attestation_broadcast,
            state_root_cache: Arc::new(std::sync::Mutex::new((0, [0u8; 32]))),
            execution_lock: Arc::new(tokio::sync::Mutex::new(())),
            batch_commitments: Arc::new(RwLock::new(HashMap::new())),
            bft_round: Arc::new(RwLock::new(crate::round_state::RoundState::new(1))),
        };

        (consensus, rx)
    }

    /// Set storage backend
    pub fn set_storage(&mut self, storage: Arc<crate::Persistence>) {
        // Create the block repairer now that we have storage
        let repairer = Arc::new(crate::block_repairer::BlockRepairer::new(
            storage.clone(),
            self.peer_senders.clone(),
            self.sync_manager.clone(),
        ));
        self.block_repairer = Some(repairer);
        self.storage = Some(storage);
    }

    pub fn get_storage(&self) -> Option<&Arc<crate::Persistence>> {
        self.storage.as_ref()
    }

    fn maybe_persist_snapshot(&self, height: u64, state: &truthlinked_state::State) {
        if height == 0 {
            return;
        }
        if let Some(ref storage) = self.storage {
            let storage = storage.clone();
            let snapshot = crate::StateSnapshot::from_state(height, state);
            tokio::spawn(async move {
                if let Err(e) = storage.save_snapshot(&snapshot) {
                    tracing::error!("Failed to save snapshot at height {}: {}", height, e);
                } else {
                    tracing::debug!("Snapshot saved at height {}", height);
                }
            });
        }
    }

    pub fn state_snapshot(&self) -> Arc<truthlinked_state::State> {
        self.state.load_full()
    }

    /// Get active attester set reference
    pub fn get_active_attesters(&self) -> Arc<RwLock<Vec<Vec<u8>>>> {
        self.active_attesters.clone()
    }

    pub async fn refresh_active_attesters(&self, epoch: u64) {
        let active_validators = self.active_validators();
        if active_validators.is_empty() {
            *self.active_attesters.write().await = Vec::new();
            *self.am_i_active_attester.write().await = false;
            *self.current_epoch.write().await = epoch;
            tracing::warn!(
                " No active validators for validator-set refresh at epoch {}",
                epoch
            );
            return;
        }

        let new_attesters = active_validators;
        let am_i_in = self.is_active_validator(&self.validator_pubkey);

        *self.active_attesters.write().await = new_attesters.clone();
        *self.am_i_active_attester.write().await = am_i_in;
        *self.current_epoch.write().await = epoch;

        if am_i_in {
            tracing::info!(" I am in active validator set for epoch {}", epoch);
        } else {
            tracing::info!(
                " I am NOT in active validator set for epoch {} (listen-only)",
                epoch
            );
        }
    }

    // ========== PUBLIC API FOR MCP TRANSPORT ==========

    /// Submit a pre-signed transaction from an agent or external client.
    /// Performs structural validation then feeds into the mempool via handle_incoming_tx.
    /// Returns the transaction hash on success.
    pub async fn submit_transaction(&self, tx: crate::Transaction) -> Result<[u8; 32], String> {
        // Compute tx hash before move.
        let tx_bytes =
            postcard::to_allocvec(&tx).map_err(|e| format!("Tx serialization failed: {}", e))?;
        let tx_hash = *blake3::hash(&tx_bytes).as_bytes();

        truthlinked_state::metrics::global().inc_tx_submitted();

        // Feed into consensus mempool (signature verification happens inside).
        self.handle_incoming_tx(tx, vec![], vec![]).await?;

        Ok(tx_hash)
    }

    /// Check if validator is in current active attester set
    pub async fn is_active_attester(&self) -> bool {
        self.is_active_validator(&self.validator_pubkey)
    }

    /// Number of peers known via discovery (addresses).
    pub async fn get_peer_count(&self) -> usize {
        self.peer_discovery.get_peers().await.len()
    }

    /// Number of active PQ sessions (connected peers).
    pub async fn get_session_count(&self) -> usize {
        self.peer_senders.read().await.len()
    }

    /// Returns true if we already have an active PQ session with this validator pubkey.
    pub async fn is_peer_connected(&self, pubkey: &[u8]) -> bool {
        self.peer_senders.read().await.contains_key(pubkey)
    }

    /// Whether the node is fully synced.
    pub async fn is_synced(&self) -> bool {
        self.sync_manager.read().await.is_synced()
    }

    fn observed_local_height(&self, blockchain: &crate::BlockChain) -> u64 {
        let chain_height = blockchain.get_current_height();
        let canonical_height = blockchain
            .get_canonical_tip()
            .ok()
            .map(|header| header.height)
            .unwrap_or(0);

        chain_height
            .max(canonical_height)
            .max(self.get_current_height())
            .max(self.get_finalized_height())
    }

    /// Whether the node is close enough to live head for user-facing status.
    pub async fn is_live_synced(&self) -> bool {
        let my_height = {
            let blockchain = self.blockchain.read().await;
            self.observed_local_height(&blockchain)
        };
        let sync_manager = self.sync_manager.read().await;
        if sync_manager.is_synced() {
            return true;
        }
        sync_manager
            .get_highest_peer_height()
            .map(|peer_height| {
                peer_height <= my_height.saturating_add(LIVE_SYNC_STATUS_LAG_TOLERANCE)
            })
            .unwrap_or(false)
    }

    /// Whether this node can safely accept client transactions.
    /// Small head lag is normal in live consensus and should not blackhole tx ingress.
    pub async fn can_accept_transactions(&self) -> Result<(), String> {
        let my_height = {
            let blockchain = self.blockchain.read().await;
            self.observed_local_height(&blockchain)
        };
        let sync_manager = self.sync_manager.read().await;

        if let Some(peer_height) = sync_manager.get_highest_peer_height() {
            if peer_height > my_height.saturating_add(TX_ADMISSION_LAG_TOLERANCE) {
                return Err(format!(
                    "Node is syncing; lag {} exceeds tx admission tolerance {} (current={}, target={})",
                    peer_height.saturating_sub(my_height),
                    TX_ADMISSION_LAG_TOLERANCE,
                    my_height,
                    peer_height
                ));
            }
        } else if !sync_manager.is_synced() {
            return Err(format!(
                "Node is not synced (state={:?}, no peer height)",
                sync_manager.state
            ));
        }

        Ok(())
    }

    /// Current mempool size (pending txs in the batch buffer).
    pub async fn get_mempool_len(&self) -> usize {
        self.batch.read().await.len()
    }

    /// Snapshot of current mempool transactions.
    pub async fn get_mempool_txs(&self) -> Vec<Transaction> {
        self.batch.read().await.clone()
    }

    /// Snapshot of mempool transactions with hashes.
    pub async fn get_mempool_txs_with_hashes(&self) -> Vec<([u8; 32], Transaction)> {
        let txs = self.batch.read().await;
        txs.iter()
            .filter_map(|tx| self.compute_tx_hash(tx).ok().map(|h| (h, tx.clone())))
            .collect()
    }

    pub async fn get_mempool_byte_weight(&self) -> usize {
        let txs = self.batch.read().await;
        txs.iter().filter_map(|tx| tx.byte_weight().ok()).sum()
    }

    pub async fn get_tx_lifecycle(&self, tx_hash: &[u8; 32]) -> Option<TxLifecycleStatus> {
        self.tx_lifecycle.read().await.get(tx_hash).cloned()
    }

    async fn remember_tx_lifecycle(&self, tx_hash: [u8; 32], status: TxLifecycleStatus) {
        if matches!(
            status,
            TxLifecycleStatus::Confirmed | TxLifecycleStatus::Rejected { .. }
        ) {
            self.release_nonce_reservation(&tx_hash).await;
        }

        let mut lifecycle = self.tx_lifecycle.write().await;
        let mut order = self.tx_lifecycle_order.write().await;
        if !lifecycle.contains_key(&tx_hash) {
            order.push_back(tx_hash);
        }
        lifecycle.insert(tx_hash, status);

        let max_seen = gp::get_usize(gp::PARAM_STREAMING_MAX_SEEN_TXS).max(10_000);
        while order.len() > max_seen {
            if let Some(old) = order.pop_front() {
                lifecycle.remove(&old);
            }
        }
    }

    async fn rebuild_mempool_index(&self) {
        let txs = self.batch.read().await;
        let mut index: HashMap<AccountId, Vec<[u8; 32]>> = HashMap::new();
        for tx in txs.iter() {
            if let Ok(hash) = self.compute_tx_hash(tx) {
                index.entry(tx.sender).or_default().push(hash);
            }
        }
        *self.mempool_index.write().await = index;
    }

    async fn reserve_sender_nonce(
        &self,
        tx_hash: [u8; 32],
        sender: AccountId,
        nonce: u64,
        committed_nonce: u64,
        lookahead: u64,
    ) -> Result<(), String> {
        let expected = committed_nonce.saturating_add(1);
        let mut reservations = self.nonce_reservations.write().await;
        let sender_reservations = reservations.by_sender.entry(sender).or_default();

        if sender_reservations.contains_key(&nonce) {
            let next_nonce = sender_reservations
                .keys()
                .copied()
                .max()
                .unwrap_or(nonce)
                .saturating_add(1);
            return Err(format!(
                "Invalid nonce window: expected {}..={}, got {} (sender nonce already pending)",
                next_nonce,
                next_nonce.saturating_add(lookahead),
                nonce
            ));
        }

        if nonce > expected {
            let mut missing = expected;
            while missing < nonce && sender_reservations.contains_key(&missing) {
                missing = missing.saturating_add(1);
            }
            if missing < nonce {
                return Err(format!(
                    "Invalid nonce sequence: missing nonce {} before future nonce {}",
                    missing, nonce
                ));
            }
        }

        sender_reservations.insert(nonce, tx_hash);
        reservations.by_hash.insert(tx_hash, (sender, nonce));
        Ok(())
    }

    async fn release_nonce_reservation(&self, tx_hash: &[u8; 32]) {
        let mut reservations = self.nonce_reservations.write().await;
        let Some((sender, nonce)) = reservations.by_hash.remove(tx_hash) else {
            return;
        };
        if let Some(sender_reservations) = reservations.by_sender.get_mut(&sender) {
            sender_reservations.remove(&nonce);
            if sender_reservations.is_empty() {
                reservations.by_sender.remove(&sender);
            }
        }
    }

    async fn reconcile_nonce_reservations(&self) {
        let mut live_hashes: HashSet<[u8; 32]> = HashSet::new();
        let state = self.state.load();
        let current_height = self.get_current_height();
        let lookahead = gp::get_u64(gp::PARAM_NONCE_LOOKAHEAD);
        {
            let mempool = self.batch.read().await;
            for tx in mempool.iter() {
                if let Ok(hash) = self.compute_tx_hash(tx) {
                    live_hashes.insert(hash);
                }
            }
        }
        {
            let pending = self.pending_batches.read().await;
            for entry in pending.values() {
                for tx in &entry.batch {
                    let Ok(hash) = self.compute_tx_hash(tx) else {
                        continue;
                    };
                    if state.executed_tx_hashes.contains(&hash)
                        || tx.expiration_height <= current_height
                    {
                        continue;
                    }
                    let Some(account) = state.accounts.get(&tx.sender) else {
                        continue;
                    };
                    let min_nonce = account.nonce.saturating_add(1);
                    let max_nonce = account.nonce.saturating_add(1 + lookahead);
                    if tx.nonce >= min_nonce && tx.nonce <= max_nonce {
                        live_hashes.insert(hash);
                    }
                }
            }
        }

        let mut orphaned: Vec<([u8; 32], u64)> = Vec::new();
        {
            let mut reservations = self.nonce_reservations.write().await;
            let stale: Vec<([u8; 32], AccountId, u64)> = reservations
                .by_hash
                .iter()
                .filter_map(|(hash, (sender, nonce))| {
                    (!live_hashes.contains(hash)).then_some((*hash, *sender, *nonce))
                })
                .collect();
            for (hash, sender, nonce) in stale {
                reservations.by_hash.remove(&hash);
                if let Some(sender_reservations) = reservations.by_sender.get_mut(&sender) {
                    sender_reservations.remove(&nonce);
                    if sender_reservations.is_empty() {
                        reservations.by_sender.remove(&sender);
                    }
                }
                orphaned.push((hash, nonce));
            }
        }

        for (hash, nonce) in orphaned {
            tracing::debug!(
                "Releasing orphaned nonce reservation {} for tx {}",
                nonce,
                hex::encode(hash)
            );
        }
    }

    async fn sender_nonce_is_waitable(&self, sender: AccountId, nonce: u64) -> bool {
        let reserved_hash = {
            let reservations = self.nonce_reservations.read().await;
            reservations
                .by_sender
                .get(&sender)
                .and_then(|sender_reservations| sender_reservations.get(&nonce).copied())
        };
        let Some(reserved_hash) = reserved_hash else {
            return false;
        };

        let in_pending_batch = {
            let pending = self.pending_batches.read().await;
            pending.values().any(|entry| {
                entry.batch.iter().any(|tx| {
                    self.compute_tx_hash(tx)
                        .map(|hash| hash == reserved_hash)
                        .unwrap_or(false)
                })
            })
        };
        if in_pending_batch {
            return true;
        }

        self.release_nonce_reservation(&reserved_hash).await;
        tracing::debug!(
            "Released non-waitable nonce reservation {} for tx {}",
            nonce,
            hex::encode(reserved_hash)
        );
        false
    }

    async fn forget_seen_tx(&self, tx_hash: &[u8; 32]) {
        self.seen_txs.write().await.remove(tx_hash);
        self.seen_txs_order.write().await.retain(|h| h != tx_hash);
    }

    async fn forget_admitted_tx(&self, tx_hash: &[u8; 32]) {
        self.forget_seen_tx(tx_hash).await;
        self.release_nonce_reservation(tx_hash).await;
    }

    async fn prune_committed_from_mempool(
        &self,
        batch: &[Transaction],
        failed: &[(usize, String)],
    ) {
        if batch.is_empty() {
            return;
        }

        let mut committed: HashSet<[u8; 32]> = HashSet::new();
        let mut rejected: HashMap<[u8; 32], String> = HashMap::new();
        for (idx, reason) in failed {
            if let Some(tx) = batch.get(*idx) {
                if let Ok(hash) = self.compute_tx_hash(tx) {
                    rejected.insert(hash, reason.clone());
                }
            }
        }
        for tx in batch {
            if let Ok(hash) = self.compute_tx_hash(tx) {
                committed.insert(hash);
            }
        }
        if committed.is_empty() {
            return;
        }
        for hash in &committed {
            if let Some(reason) = rejected.get(hash) {
                self.remember_tx_lifecycle(
                    *hash,
                    TxLifecycleStatus::Rejected {
                        reason: reason.clone(),
                    },
                )
                .await;
            } else {
                self.remember_tx_lifecycle(*hash, TxLifecycleStatus::Confirmed)
                    .await;
            }
        }

        let before = {
            let mut mempool = self.batch.write().await;
            let before = mempool.len();
            mempool.retain(|tx| {
                self.compute_tx_hash(tx)
                    .map(|hash| !committed.contains(&hash))
                    .unwrap_or(true)
            });
            before
        };

        self.rebuild_mempool_index().await;

        {
            let mut pending = self.pending_batches.write().await;
            let before_pending = pending.len();
            pending.retain(|batch_hash, entry| {
                let overlaps_committed = entry.batch.iter().any(|tx| {
                    self.compute_tx_hash(tx)
                        .map(|hash| committed.contains(&hash))
                        .unwrap_or(false)
                });
                if overlaps_committed {
                    tracing::debug!(
                        " Dropping pending batch {} because it overlaps committed block",
                        hex::encode(&batch_hash[..8])
                    );
                }
                !overlaps_committed
            });
            let removed_pending = before_pending.saturating_sub(pending.len());
            if removed_pending > 0 {
                tracing::info!(
                    " Dropped {} stale pending batch(es) after canonical commit",
                    removed_pending
                );
            }
        }

        let after = self.batch.read().await.len();
        if before != after {
            tracing::info!(
                " Pruned {} committed txs from mempool ({} -> {})",
                before.saturating_sub(after),
                before,
                after
            );
        }
    }

    async fn prune_ineligible_from_mempool(&self, state: &truthlinked_state::State) {
        let lookahead = gp::get_u64(gp::PARAM_NONCE_LOOKAHEAD);
        let current_height = self.get_current_height();
        let mut rejected: Vec<([u8; 32], String)> = Vec::new();
        let before = {
            let mut mempool = self.batch.write().await;
            let before = mempool.len();
            mempool.retain(|tx| {
                if tx.expiration_height <= current_height {
                    if let Ok(hash) = self.compute_tx_hash(tx) {
                        rejected.push((hash, "expired before inclusion".to_string()));
                    }
                    return false;
                }

                let Ok(tx_hash) = self.compute_tx_hash(tx) else {
                    return false;
                };
                if state.executed_tx_hashes.contains(&tx_hash) {
                    rejected.push((tx_hash, "already executed".to_string()));
                    return false;
                }

                let Some(account) = state.accounts.get(&tx.sender) else {
                    rejected.push((tx_hash, "sender account not found".to_string()));
                    return false;
                };
                let min_nonce = account.nonce.saturating_add(1);
                let max_nonce = account.nonce.saturating_add(1 + lookahead);
                let live = tx.nonce >= min_nonce && tx.nonce <= max_nonce;
                if !live {
                    rejected.push((
                        tx_hash,
                        format!(
                            "nonce {} outside live window {}..={}",
                            tx.nonce, min_nonce, max_nonce
                        ),
                    ));
                }
                live
            });
            before
        };
        for (hash, reason) in rejected {
            self.remember_tx_lifecycle(hash, TxLifecycleStatus::Rejected { reason })
                .await;
        }

        self.rebuild_mempool_index().await;

        let mut dropped_pending_txs: Vec<([u8; 32], String)> = Vec::new();
        {
            let mut pending = self.pending_batches.write().await;
            pending.retain(|batch_hash, entry| {
                let has_live_tx = entry.batch.iter().any(|tx| {
                    let Ok(tx_hash) = self.compute_tx_hash(tx) else {
                        return false;
                    };
                    if state.executed_tx_hashes.contains(&tx_hash)
                        || tx.expiration_height <= current_height
                    {
                        return false;
                    }
                    let Some(account) = state.accounts.get(&tx.sender) else {
                        return false;
                    };
                    let min_nonce = account.nonce.saturating_add(1);
                    let max_nonce = account.nonce.saturating_add(1 + lookahead);
                    tx.nonce >= min_nonce && tx.nonce <= max_nonce
                });
                if !has_live_tx {
                    for tx in &entry.batch {
                        if let Ok(tx_hash) = self.compute_tx_hash(tx) {
                            dropped_pending_txs.push((
                                tx_hash,
                                "pending batch dropped after tx became ineligible".to_string(),
                            ));
                        }
                    }
                    tracing::debug!(
                        " Dropping pending batch {} because it has no live transactions",
                        hex::encode(&batch_hash[..8])
                    );
                }
                has_live_tx
            });
        }
        for (hash, reason) in dropped_pending_txs {
            self.remember_tx_lifecycle(hash, TxLifecycleStatus::Rejected { reason })
                .await;
        }

        let after = self.batch.read().await.len();
        if before != after {
            tracing::info!(
                " Pruned {} ineligible txs from mempool after state advance ({} -> {})",
                before.saturating_sub(after),
                before,
                after
            );
        }
    }

    /// Mark node as synced and ready to accept transactions
    pub async fn set_synced(&self) {
        self.sync_manager.write().await.set_synced();
    }

    /// Handle incoming transaction - All validators stream; active validators attest
    pub async fn handle_incoming_tx(
        &self,
        tx: Transaction,
        first_sig: Vec<u8>,
        first_pubkey: Vec<u8>,
    ) -> Result<(), String> {
        // Reject only when materially behind. Minor live head skew is acceptable for mempool ingress.
        if let Err(e) = self.can_accept_transactions().await {
            tracing::warn!("Rejecting TX - {}", e);
            return Err(e);
        }

        let tx_hash = match self.compute_tx_hash(&tx) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(" Rejecting TX: {}", e);
                return Err(e);
            }
        };

        tracing::debug!("Processing transaction {}", hex::encode(&tx_hash[..8]));

        {
            let seen = self.seen_txs.read().await;
            if seen.contains(&tx_hash) {
                let msg = "Transaction already seen".to_string();
                tracing::trace!("{}", msg);
                return Err(msg);
            }
        }

        // Verify transaction signature and nonce window BEFORE adding to batch.
        let state = self.state.load();
        let lookahead = gp::get_u64(gp::PARAM_NONCE_LOOKAHEAD);
        if let Err(e) = state.validate_transaction_for_mempool(&tx, lookahead) {
            tracing::warn!(" Rejecting invalid TX: {}", e);
            return Err(e);
        }

        tracing::trace!(
            "Transaction {} passed mempool validation",
            hex::encode(&tx_hash[..8])
        );

        // If forwarding signature is present, verify it (anti-spam, accountability).
        if !first_sig.is_empty() || !first_pubkey.is_empty() {
            if let Err(e) = self.verify_streamed_tx_sig(&tx_hash, &first_pubkey, &first_sig) {
                tracing::warn!(" Rejecting streamed TX: {}", e);
                return Err(e);
            }
            tracing::trace!("Streamed transaction signature verified");
        }

        // Atomic dedupe after validation so rejected transactions do not poison seen_txs.
        {
            let mut seen = self.seen_txs.write().await;
            if !seen.insert(tx_hash) {
                let msg = "Transaction already seen".to_string();
                tracing::trace!("{}", msg);
                return Err(msg);
            }
            let mut order = self.seen_txs_order.write().await;
            order.push_back(tx_hash);
            let max_seen = gp::get_usize(gp::PARAM_STREAMING_MAX_SEEN_TXS);
            while order.len() > max_seen {
                if let Some(evicted) = order.pop_front() {
                    seen.remove(&evicted);
                }
            }
        }

        self.reconcile_nonce_reservations().await;

        let committed_nonce = state
            .accounts
            .get(&tx.sender)
            .map(|account| account.nonce)
            .unwrap_or(0);
        if let Err(msg) = self
            .reserve_sender_nonce(tx_hash, tx.sender, tx.nonce, committed_nonce, lookahead)
            .await
        {
            self.forget_seen_tx(&tx_hash).await;
            tracing::warn!("Rejecting TX with reserved sender nonce: {}", msg);
            return Err(msg);
        }

        // NEW TX - Add to batch (automatic, no choice).
        {
            let mut batch = self.batch.write().await;

            if batch.len() >= gp::get_usize(gp::PARAM_MAX_BATCH_SIZE) {
                drop(batch);
                self.forget_admitted_tx(&tx_hash).await;
                let msg = "Mempool batch is full".to_string();
                tracing::warn!("Batch full, dropping TX");
                return Err(msg);
            }

            let tx_bytes = tx
                .byte_weight()
                .map_err(|e| format!("Failed to compute tx byte weight: {}", e))?;
            let current_bytes: usize = batch
                .iter()
                .filter_map(|pending| pending.byte_weight().ok())
                .sum();
            let max_bytes = gp::get_usize(gp::PARAM_MEMPOOL_MAX_BYTES);
            if current_bytes.saturating_add(tx_bytes) > max_bytes {
                let msg = format!(
                    "Mempool byte limit exceeded: {} + {} > {}",
                    current_bytes, tx_bytes, max_bytes
                );
                drop(batch);
                self.forget_admitted_tx(&tx_hash).await;
                tracing::warn!("{}", msg);
                return Err(msg);
            }

            tracing::debug!(
                "Queued transaction {} (mempool_txs={}, mempool_bytes={} -> {})",
                hex::encode(&tx_hash[..8]),
                batch.len() + 1,
                current_bytes,
                current_bytes.saturating_add(tx_bytes)
            );
            batch.push(tx.clone());
        }
        self.remember_tx_lifecycle(
            tx_hash,
            TxLifecycleStatus::Pending {
                since_height: self.get_current_height(),
            },
        )
        .await;
        {
            let mut index = self.mempool_index.write().await;
            index.entry(tx.sender).or_default().push(tx_hash);
        }

        // ALL validators stream (automatic forwarding)
        let my_sig = match self
            .keypair
            .dilithium_sk
            .try_sign(&tx_hash, STREAM_TX_CONTEXT)
        {
            Ok(sig) => sig.to_vec(),
            Err(e) => {
                tracing::warn!(" Failed to sign streamed TX: {}", e);
                Vec::new()
            }
        };
        let streamed = StreamedTx {
            tx: tx.clone(),
            validator_sig: if first_sig.is_empty() {
                my_sig
            } else {
                first_sig
            },
            validator_pubkey: if first_pubkey.is_empty() {
                self.validator_pubkey.clone()
            } else {
                first_pubkey
            },
        };

        self.stream_to_peers(streamed).await;

        // Note: Attestations are sent per-batch, not per-transaction.
        // See batch_timer_task for batch attestation logic.
        Ok(())
    }

    /// Stream transaction to all connected validators (encrypted TCP)
    async fn stream_to_peers(&self, streamed: StreamedTx) {
        let msg = P2PMessage::Transaction(streamed.clone());
        let data = postcard::to_allocvec(&msg).unwrap();

        // Send via encrypted TCP to all peers
        let peer_senders = self.peer_senders.read().await;
        tracing::trace!("Streaming transaction to {} peer(s)", peer_senders.len());
        for (peer_pk, sender) in peer_senders.iter() {
            if sender.try_send(data.clone()).is_err() {
                tracing::warn!("Failed to send TX to {}", hex::encode(&peer_pk[..8]));
            } else {
                tracing::trace!(
                    "Streamed transaction to peer {}",
                    hex::encode(&peer_pk[..8])
                );
            }
        }

        let _ = self.tx_broadcast.send(streamed);
    }

    /// Broadcast block header to all peers (TCP)
    async fn broadcast_header(&self, header: crate::BatchHeader) {
        let mut compact_header = header.clone();
        compact_header.finality_certificate = header.finality_certificate.compact_for_gossip();
        let msg = P2PMessage::BlockHeader(compact_header);
        let data = postcard::to_allocvec(&msg).unwrap();

        // Send via TCP to all peers
        let peer_senders = self.peer_senders.read().await;
        tracing::info!(
            "BROADCAST Broadcasting block {} to {} peers",
            header.height,
            peer_senders.len()
        );
        for (peer_pk, sender) in peer_senders.iter() {
            if sender.try_send(data.clone()).is_err() {
                tracing::warn!("Failed to send header to {}", hex::encode(&peer_pk[..8]));
            } else {
                tracing::info!("  OK Sent header to peer {}", hex::encode(&peer_pk[..8]));
            }
        }
    }

    async fn request_batch_from_peer(
        &self,
        peer_pubkey: &[u8],
        batch_hash: [u8; 32],
    ) -> Result<(), String> {
        let peer_senders = self.peer_senders.read().await;
        let sender = peer_senders
            .get(peer_pubkey)
            .ok_or("Peer sender not found")?;
        let msg = P2PMessage::BatchRequest { batch_hash };
        let data = postcard::to_allocvec(&msg)
            .map_err(|e| format!("Failed to serialize batch request: {}", e))?;
        sender
            .try_send(data)
            .map_err(|_| "Failed to send batch request".to_string())
    }

    async fn handle_batch_response(&self, batch_hash: [u8; 32], batch: Vec<Transaction>) {
        if batch.len() > gp::get_usize(gp::PARAM_MAX_BATCH_SIZE) {
            tracing::warn!(" Rejected batch response: too large ({} txs)", batch.len());
            return;
        }

        let pending_ctx = {
            let pending = self.pending_headers.read().await;
            pending
                .get(&batch_hash)
                .map(|e| (e.header.parent_hash, e.header.height))
        };
        if let Some((ph, ht)) = pending_ctx {
            match self.compute_batch_commitment(&batch, &ph, ht) {
                Ok(c) if c != batch_hash => {
                    tracing::warn!(" Rejected batch response: commitment mismatch");
                    return;
                }
                Err(e) => {
                    tracing::warn!(" Rejected batch response: {}", e);
                    return;
                }
                Ok(_) => {}
            }
        }

        self.cache_batch(batch_hash, batch.clone()).await;

        // If we were waiting on this header, process now.
        if let Some(entry) = self.pending_headers.write().await.remove(&batch_hash) {
            self.process_header_with_batch(entry.header, batch).await;
        }
    }

    async fn handle_batch_proposal(
        &self,
        height: u64,
        parent_hash: [u8; 32],
        batch_hash: [u8; 32],
        batch: Vec<Transaction>,
        state_root: [u8; 32],
        leader_pubkey: Vec<u8>,
        leader_round: u32,
    ) {
        if batch.len() > gp::get_usize(gp::PARAM_MAX_BATCH_SIZE) {
            tracing::warn!("Ignoring oversized batch proposal at height {}", height);
            return;
        }
        if leader_pubkey == self.validator_pubkey {
            return;
        }

        let expected_leader =
            self.select_leader_hash_round(&parent_hash, height, &batch_hash, leader_round);
        if expected_leader != leader_pubkey {
            tracing::warn!(
                "Ignoring batch proposal for height {} from non-leader {}",
                height,
                hex::encode(&leader_pubkey[..8])
            );
            return;
        }

        let current_parent = {
            let blockchain = self.blockchain.read().await;
            match blockchain.get_canonical_tip() {
                Ok(tip) if tip.height + 1 == height => tip.batch_hash,
                Ok(tip) => {
                    tracing::debug!(
                        "Ignoring batch proposal for height {} while local tip is {}",
                        height,
                        tip.height
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!("Ignoring batch proposal without canonical tip: {}", e);
                    return;
                }
            }
        };
        if current_parent != parent_hash {
            tracing::debug!(
                "Ignoring batch proposal for height {} with stale parent {}",
                height,
                hex::encode(&parent_hash[..8])
            );
            return;
        }

        let Ok(computed_hash) = self.compute_batch_commitment(&batch, &parent_hash, height) else {
            tracing::warn!("Ignoring batch proposal with invalid commitment input");
            return;
        };
        if computed_hash != batch_hash {
            tracing::warn!(
                "Ignoring batch proposal with mismatched hash at height {}",
                height
            );
            return;
        }

        self.cache_batch(batch_hash, batch.clone()).await;

        let state = self.state.load();
        let Ok(new_state) = self.execute_batch(&state, &batch).await else {
            tracing::warn!(
                "Ignoring batch proposal {}: local execution failed",
                hex::encode(&batch_hash[..8])
            );
            return;
        };
        let local_state_root = self.compute_state_root(&new_state);
        if local_state_root != state_root {
            tracing::warn!(
                "Ignoring batch proposal {}: state root mismatch",
                hex::encode(&batch_hash[..8])
            );
            return;
        }

        tracing::debug!(
            "Attesting to leader proposal {} at height {} ({} txs)",
            hex::encode(&batch_hash[..8]),
            height,
            batch.len()
        );
        self.send_attestation(height, leader_round as u64, batch_hash, state_root)
            .await;
    }

    async fn handle_compact_batch_proposal(
        &self,
        from_peer: Vec<u8>,
        height: u64,
        parent_hash: [u8; 32],
        batch_hash: [u8; 32],
        tx_hashes: Vec<[u8; 32]>,
        state_root: [u8; 32],
        leader_pubkey: Vec<u8>,
        leader_round: u32,
    ) {
        if tx_hashes.len() > gp::get_usize(gp::PARAM_MAX_BATCH_SIZE) {
            tracing::warn!(
                "Ignoring oversized compact batch proposal at height {} ({} txs)",
                height,
                tx_hashes.len()
            );
            return;
        }

        let batch = match self.reconstruct_batch_from_hashes(&tx_hashes).await {
            Ok(batch) => batch,
            Err(missing) => {
                tracing::info!(
                    "Compact proposal {} at height {} missing {}/{} txs; requesting full batch",
                    hex::encode(&batch_hash[..8]),
                    height,
                    missing.len(),
                    tx_hashes.len()
                );
                if let Err(e) = self.request_batch_from_peer(&from_peer, batch_hash).await {
                    tracing::warn!(" Failed to request full compact batch fallback: {}", e);
                }
                return;
            }
        };
        tracing::debug!(
            "Reconstructed compact proposal {} at height {} ({} txs)",
            hex::encode(&batch_hash[..8]),
            height,
            batch.len()
        );

        self.handle_batch_proposal(
            height,
            parent_hash,
            batch_hash,
            batch,
            state_root,
            leader_pubkey,
            leader_round,
        )
        .await;
    }

    /// Send attestation to pipeline (pipelined, non-blocking)
    async fn send_attestation(
        &self,
        height: u64,
        round: u64,
        batch_hash: [u8; 32],
        state_root: [u8; 32],
    ) {
        if !self.is_active_validator(&self.validator_pubkey) {
            tracing::warn!(" Skipping attestation: validator is jailed or inactive");
            return;
        }

        {
            let mut signed = self.signed_attestations.write().await;
            let key = (height, round);
            if let Some((prev_batch, prev_state)) = signed.get(&key) {
                if prev_batch != &batch_hash || prev_state != &state_root {
                    tracing::warn!(
                        " Refusing conflicting attestation at height {} round {}: existing {}:{}, new {}:{}",
                        height,
                        round,
                        hex::encode(&prev_batch[..8]),
                        hex::encode(&prev_state[..8]),
                        hex::encode(&batch_hash[..8]),
                        hex::encode(&state_root[..8])
                    );
                    return;
                }
                tracing::debug!(
                    "Skipping duplicate attestation at height {} round {} for batch {}",
                    height,
                    round,
                    hex::encode(&batch_hash[..8])
                );
                return;
            } else {
                signed.insert(key, (batch_hash, state_root));
                let retain_from = height.saturating_sub(256);
                signed.retain(|(h, _), _| *h >= retain_from);
            }
        }

        tracing::debug!(
            " Sending attestation for batch {} at height {} round {}",
            hex::encode(&batch_hash[..8]),
            height,
            round
        );
        let message = Self::attestation_message(height, round, &batch_hash, &state_root);
        let signature = self
            .keypair
            .dilithium_sk
            .try_sign(&message, ATTESTATION_CONTEXT)
            .expect("Attestation signing failed")
            .to_vec();

        let attestation = Attestation {
            height,
            round,
            batch_hash,
            state_root,
            validator_pubkey: self.validator_pubkey.clone(),
            signature,
        };

        // Broadcast to ACK server and peers
        self.broadcast_attestation(attestation).await;
    }

    /// Broadcast attestation to all peers via gossip
    async fn broadcast_attestation(&self, attestation: Attestation) {
        // Add to local attestation pipeline
        if let Some(ref pipeline) = self.attestation_pipeline {
            let batch_hash = attestation.batch_hash;
            pipeline
                .add_attestation(batch_hash, attestation.clone())
                .await;
        }

        // Broadcast to all peers via P2P gossip
        let msg = P2PMessage::Attestation(attestation.clone());
        let data = postcard::to_allocvec(&msg).unwrap();

        let peer_senders = self.peer_senders.read().await;
        tracing::info!(
            "📡 Broadcasting attestation for {} to {} peers",
            hex::encode(&attestation.batch_hash[..8]),
            peer_senders.len()
        );
        for (peer_pk, sender) in peer_senders.iter() {
            if sender.try_send(data.clone()).is_err() {
                tracing::warn!(
                    "Failed to send attestation to {}",
                    hex::encode(&peer_pk[..8])
                );
            }
        }
    }

    /// Broadcast our independently-computed batch_hash to all peers so they can
    /// verify the leader is not censoring transactions.
    async fn broadcast_batch_commitment(&self, height: u64, batch_hash: [u8; 32]) {
        let mut msg_bytes = Vec::with_capacity(40);
        msg_bytes.extend_from_slice(&height.to_le_bytes());
        msg_bytes.extend_from_slice(&batch_hash);
        let Ok(sig) = self
            .keypair
            .dilithium_sk
            .try_sign(&msg_bytes, b"batch-commitment-v1")
        else {
            return;
        };
        let commitment = P2PMessage::BatchCommitment {
            height,
            batch_hash,
            validator_pubkey: self.validator_pubkey.clone(),
            signature: sig.to_vec(),
        };
        let Ok(data) = postcard::to_allocvec(&commitment) else {
            return;
        };
        // Record our own commitment first
        self.record_batch_commitment(height, batch_hash, self.validator_pubkey.clone())
            .await;
        let peer_senders = self.peer_senders.read().await;
        for sender in peer_senders.values() {
            let _ = sender.try_send(data.clone());
        }
    }

    async fn record_batch_commitment(
        &self,
        height: u64,
        batch_hash: [u8; 32],
        validator_pubkey: Vec<u8>,
    ) {
        let mut map = self.batch_commitments.write().await;
        map.entry(height)
            .or_default()
            .entry(batch_hash)
            .or_default()
            .insert(validator_pubkey);
        // Prune heights more than 10 behind current to bound memory
        let finalized = self
            .finalized_height
            .load(std::sync::atomic::Ordering::Relaxed);
        map.retain(|h, _| *h + 10 >= finalized);
    }

    /// Returns the batch_hash that 2/3+ of active validators committed to at this height,
    /// or None if no majority exists yet.
    async fn majority_committed_hash(&self, height: u64) -> Option<[u8; 32]> {
        let state = self.state.load();
        let active = state.staking.get_active_validators();
        let total_stake: u64 = active.values().sum();
        if total_stake == 0 {
            return None;
        }
        let threshold = (total_stake * 2 / 3) + 1;

        let map = self.batch_commitments.read().await;
        let by_hash = map.get(&height)?;
        for (hash, voters) in by_hash {
            let stake: u64 = voters.iter().filter_map(|pk| active.get(pk)).sum();
            if stake >= threshold {
                return Some(*hash);
            }
        }
        None
    }

    /// Handle an incoming BatchCommitment from a peer - verify signature then record.
    async fn handle_batch_commitment(
        &self,
        height: u64,
        batch_hash: [u8; 32],
        validator_pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) {
        use fips204::traits::{SerDes, Verifier};
        // Only accept from active validators
        if !self.is_active_validator(&validator_pubkey) {
            return;
        }
        let Ok(pk_bytes) = <[u8; 1952]>::try_from(validator_pubkey.as_slice()) else {
            return;
        };
        let Ok(pk) = DilithiumPublicKey::try_from_bytes(pk_bytes) else {
            return;
        };
        let Ok(sig_bytes) = <[u8; 3309]>::try_from(signature.as_slice()) else {
            return;
        };
        let mut msg_bytes = Vec::with_capacity(40);
        msg_bytes.extend_from_slice(&height.to_le_bytes());
        msg_bytes.extend_from_slice(&batch_hash);
        if !pk.verify(&msg_bytes, &sig_bytes, b"batch-commitment-v1") {
            return;
        }
        self.record_batch_commitment(height, batch_hash, validator_pubkey)
            .await;
    }

    // ── Phase-3 BFT helpers ───────────────────────────────────────────────────

    fn bft_vote_message(
        height: u64,
        round: u32,
        block_hash: Option<[u8; 32]>,
        kind: &[u8],
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(48);
        m.extend_from_slice(kind);
        m.extend_from_slice(&height.to_le_bytes());
        m.extend_from_slice(&round.to_le_bytes());
        match block_hash {
            Some(h) => {
                m.push(1);
                m.extend_from_slice(&h);
            }
            None => {
                m.push(0);
                m.extend_from_slice(&[0u8; 32]);
            }
        }
        m
    }

    fn sign_bft_vote(
        &self,
        height: u64,
        round: u32,
        block_hash: Option<[u8; 32]>,
        kind: &[u8],
    ) -> Vec<u8> {
        let msg = Self::bft_vote_message(height, round, block_hash, kind);
        self.keypair
            .dilithium_sk
            .try_sign(&msg, b"bft-vote-v1")
            .map(|s| s.to_vec())
            .unwrap_or_default()
    }

    fn verify_bft_vote_sig(
        pubkey: &[u8],
        height: u64,
        round: u32,
        block_hash: Option<[u8; 32]>,
        kind: &[u8],
        signature: &[u8],
    ) -> bool {
        use fips204::traits::{SerDes, Verifier};
        let Ok(pk_bytes) = <[u8; 1952]>::try_from(pubkey) else {
            return false;
        };
        let Ok(pk) = DilithiumPublicKey::try_from_bytes(pk_bytes) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 3309]>::try_from(signature) else {
            return false;
        };
        let msg = Self::bft_vote_message(height, round, block_hash, kind);
        pk.verify(&msg, &sig_bytes, b"bft-vote-v1")
    }

    async fn broadcast_prevote(&self, height: u64, round: u32, block_hash: Option<[u8; 32]>) {
        let sig = self.sign_bft_vote(height, round, block_hash, b"prevote");
        let msg = P2PMessage::Prevote {
            height,
            round,
            block_hash,
            validator_pubkey: self.validator_pubkey.clone(),
            signature: sig.clone(),
        };
        // Record own vote
        self.handle_prevote(
            height,
            round,
            block_hash,
            self.validator_pubkey.clone(),
            sig,
        )
        .await;
        let Ok(data) = postcard::to_allocvec(&msg) else {
            return;
        };
        let senders = self.peer_senders.read().await;
        for s in senders.values() {
            let _ = s.try_send(data.clone());
        }
    }

    async fn broadcast_precommit(&self, height: u64, round: u32, block_hash: Option<[u8; 32]>) {
        let sig = self.sign_bft_vote(height, round, block_hash, b"precommit");
        let msg = P2PMessage::Precommit {
            height,
            round,
            block_hash,
            validator_pubkey: self.validator_pubkey.clone(),
            signature: sig.clone(),
        };
        // Record own vote
        self.handle_precommit(
            height,
            round,
            block_hash,
            self.validator_pubkey.clone(),
            sig,
        )
        .await;
        let Ok(data) = postcard::to_allocvec(&msg) else {
            return;
        };
        let senders = self.peer_senders.read().await;
        for s in senders.values() {
            let _ = s.try_send(data.clone());
        }
    }

    async fn handle_prevote(
        &self,
        height: u64,
        round: u32,
        block_hash: Option<[u8; 32]>,
        validator_pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) {
        if !Self::verify_bft_vote_sig(
            &validator_pubkey,
            height,
            round,
            block_hash,
            b"prevote",
            &signature,
        ) {
            return;
        }
        if !self.is_active_validator(&validator_pubkey) {
            return;
        }
        let mut rs = self.bft_round.write().await;
        if rs.height != height {
            return;
        }
        // Fast-forward our round if peers are ahead - but cap at MAX_BFT_ROUND
        // to prevent runaway round numbers from stale peers causing permanent stalls.
        const MAX_BFT_ROUND: u32 = 10;
        if round > rs.round && round <= MAX_BFT_ROUND {
            tracing::info!("BFT fast-forward prevote: round {} → {}", rs.round, round);
            while rs.round < round {
                rs.next_round();
            }
        }
        // Equivocation check: if validator already prevoted a DIFFERENT hash this round, slash.
        if let Some(existing) = rs
            .prevotes
            .get(&round)
            .and_then(|m| m.get(&validator_pubkey))
        {
            if existing.block_hash != block_hash && existing.signature != signature {
                tracing::warn!(
                    "Equivocation (double prevote) from {} at height {} round {}",
                    hex::encode(&validator_pubkey[..8]),
                    height,
                    round
                );
                let proof = crate::SlashProof::DoublePrevote {
                    height,
                    round,
                    vote_a: postcard::to_allocvec(existing).unwrap_or_default(),
                    vote_b: postcard::to_allocvec(&crate::round_state::Vote {
                        height,
                        round,
                        block_hash,
                        validator_pubkey: validator_pubkey.clone(),
                        signature: signature.clone(),
                    })
                    .unwrap_or_default(),
                    validator_pubkey,
                };
                tracing::error!("SlashProof::DoublePrevote: {:?}", proof);
            }
            return;
        }
        let vote = crate::round_state::Vote {
            height,
            round,
            block_hash,
            validator_pubkey,
            signature,
        };
        rs.add_prevote(vote);
    }

    async fn handle_precommit(
        &self,
        height: u64,
        round: u32,
        block_hash: Option<[u8; 32]>,
        validator_pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) {
        if !Self::verify_bft_vote_sig(
            &validator_pubkey,
            height,
            round,
            block_hash,
            b"precommit",
            &signature,
        ) {
            return;
        }
        if !self.is_active_validator(&validator_pubkey) {
            return;
        }
        let mut rs = self.bft_round.write().await;
        if rs.height != height {
            return;
        }
        // Fast-forward our round if peers are ahead - capped at MAX_BFT_ROUND.
        const MAX_BFT_ROUND: u32 = 10;
        if round > rs.round && round <= MAX_BFT_ROUND {
            tracing::info!("BFT fast-forward precommit: round {} → {}", rs.round, round);
            while rs.round < round {
                rs.next_round();
            }
        }
        // Equivocation check
        if let Some(existing) = rs
            .precommits
            .get(&round)
            .and_then(|m| m.get(&validator_pubkey))
        {
            if existing.block_hash != block_hash && existing.signature != signature {
                tracing::warn!(
                    "Equivocation (double precommit) from {} at height {} round {}",
                    hex::encode(&validator_pubkey[..8]),
                    height,
                    round
                );
                let proof = crate::SlashProof::DoublePrecommit {
                    height,
                    round,
                    vote_a: postcard::to_allocvec(existing).unwrap_or_default(),
                    vote_b: postcard::to_allocvec(&crate::round_state::Vote {
                        height,
                        round,
                        block_hash,
                        validator_pubkey: validator_pubkey.clone(),
                        signature: signature.clone(),
                    })
                    .unwrap_or_default(),
                    validator_pubkey,
                };
                tracing::error!("SlashProof::DoublePrecommit: {:?}", proof);
            }
            return;
        }
        let vote = crate::round_state::Vote {
            height,
            round,
            block_hash,
            validator_pubkey,
            signature,
        };
        rs.add_precommit(vote);
    }

    /// Returns the block_hash that reached 2/3+ precommit stake in ANY round,
    /// or None if quorum not yet reached.
    async fn bft_precommit_quorum(&self) -> Option<[u8; 32]> {
        let state = self.state.load();
        let stake_map = Self::stake_map_from_state(&state);
        let total: u64 = stake_map.values().sum();
        if total == 0 {
            return None;
        }
        let threshold = (total * 2 / 3) + 1;
        let rs = self.bft_round.read().await;
        // Check all rounds - votes may arrive for an earlier round than current
        for round in 0..=rs.round {
            if let Some(h) = rs.precommit_quorum(round, threshold, &stake_map) {
                return Some(h);
            }
        }
        None
    }

    /// Returns the block_hash that reached 2/3+ prevote stake in ANY round.
    async fn bft_prevote_quorum(&self) -> Option<[u8; 32]> {
        let state = self.state.load();
        let stake_map = Self::stake_map_from_state(&state);
        let total: u64 = stake_map.values().sum();
        if total == 0 {
            return None;
        }
        let threshold = (total * 2 / 3) + 1;
        let rs = self.bft_round.read().await;
        for round in 0..=rs.round {
            if let Some(h) = rs.prevote_quorum(round, threshold, &stake_map) {
                return Some(h);
            }
        }
        None
    }

    // ─────────────────────────────────────────────────────────────────────────

    async fn verify_attestation(&self, attestation: &Attestation) -> bool {
        use fips204::traits::{SerDes, Verifier};

        // Must be an active validator
        // Note: skip is_active_validator check here - the active set may diverge
        // during catch-up. Signature validity + active validatorship is sufficient.

        // Must be in current active attester set OR be an active validator
        // (attestations can straddle epoch boundaries - do not reject on attester-set mismatch alone)
        let active_attesters = self.active_attesters.read().await;
        let in_active_attesters = active_attesters.contains(&attestation.validator_pubkey);
        drop(active_attesters);
        if !in_active_attesters && !self.is_active_validator(&attestation.validator_pubkey) {
            tracing::warn!(" Attestation from non-attester, inactive validator");
            return false;
        }

        let pk_bytes: [u8; 1952] = match attestation.validator_pubkey.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_bytes: [u8; 3309] = match attestation.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let pk = match DilithiumPublicKey::try_from_bytes(pk_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let message = Self::attestation_message(
            attestation.height,
            attestation.round,
            &attestation.batch_hash,
            &attestation.state_root,
        );
        let valid = pk.verify(&message, &sig_bytes, ATTESTATION_CONTEXT);
        if valid {
            let height = self
                .current_height
                .load(std::sync::atomic::Ordering::Relaxed);
            self.record_attestation(&attestation.validator_pubkey, height)
                .await;
        } else {
            tracing::warn!(
                " Attestation signature invalid from {}",
                hex::encode(&attestation.validator_pubkey[..8])
            );
        }
        valid
    }

    /// Compute transaction hash
    fn compute_tx_hash(&self, tx: &Transaction) -> Result<[u8; 32], String> {
        use blake3::Hasher;
        let bytes =
            postcard::to_allocvec(tx).map_err(|e| format!("Failed to serialize tx: {}", e))?;
        let mut hasher = Hasher::new();
        hasher.update(&bytes);
        Ok((*hasher.finalize().as_bytes()).into())
    }

    fn verify_streamed_tx_sig(
        &self,
        tx_hash: &[u8; 32],
        pubkey_bytes: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), String> {
        use fips204::traits::{SerDes, Verifier};

        if !self.is_active_validator(pubkey_bytes) {
            return Err("Streamed TX from inactive or unknown validator".to_string());
        }

        let pk_bytes: [u8; 1952] = pubkey_bytes
            .try_into()
            .map_err(|_| "Invalid streamed TX pubkey length")?;
        let pk = DilithiumPublicKey::try_from_bytes(pk_bytes)
            .map_err(|_| "Invalid streamed TX pubkey")?;

        let sig_bytes: [u8; 3309] = sig_bytes
            .try_into()
            .map_err(|_| "Invalid streamed TX signature length")?;

        if !pk.verify(tx_hash, &sig_bytes, STREAM_TX_CONTEXT) {
            return Err("Invalid streamed TX signature".to_string());
        }

        Ok(())
    }

    /// Cache a batch for on-demand fetching.
    async fn cache_batch(&self, batch_hash: [u8; 32], batch: Vec<Transaction>) {
        let mut cache = self.batch_cache.write().await;
        let mut order = self.batch_cache_order.write().await;

        if !cache.contains_key(&batch_hash) {
            order.push_back(batch_hash);
        }
        cache.insert(batch_hash, CachedBatch { batch });

        while order.len() > gp::get_usize(gp::PARAM_STREAMING_MAX_BATCH_CACHE) {
            if let Some(old) = order.pop_front() {
                cache.remove(&old);
            }
        }
    }

    async fn get_cached_batch(&self, batch_hash: &[u8; 32]) -> Option<CachedBatch> {
        self.batch_cache.read().await.get(batch_hash).cloned()
    }

    async fn reconstruct_batch_from_hashes(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<Vec<Transaction>, Vec<[u8; 32]>> {
        let mut by_hash: HashMap<[u8; 32], Transaction> = HashMap::new();

        {
            let mempool = self.batch.read().await;
            for tx in mempool.iter() {
                if let Ok(hash) = self.compute_tx_hash(tx) {
                    by_hash.entry(hash).or_insert_with(|| tx.clone());
                }
            }
        }

        {
            let cache = self.batch_cache.read().await;
            for cached in cache.values() {
                for tx in &cached.batch {
                    if let Ok(hash) = self.compute_tx_hash(tx) {
                        by_hash.entry(hash).or_insert_with(|| tx.clone());
                    }
                }
            }
        }

        let mut missing = Vec::new();
        let mut batch = Vec::with_capacity(tx_hashes.len());
        for hash in tx_hashes {
            if let Some(tx) = by_hash.get(hash) {
                batch.push(tx.clone());
            } else {
                missing.push(*hash);
            }
        }

        if missing.is_empty() {
            Ok(batch)
        } else {
            Err(missing)
        }
    }

    /// Deterministic leader selection from parent height + timeout round.
    ///
    /// The local mempool contents must not influence leader election. Under
    /// concurrent transaction ingress, validators can build different candidate
    /// batch hashes for the same height; if the batch hash feeds election, they
    /// wait for different leaders and the height stalls.
    /// Round 0 is the primary leader; later rounds are deterministic fallbacks.
    fn select_leader_hash(
        &self,
        parent_hash: &[u8; 32],
        height: u64,
        batch_hash: &[u8; 32],
        round: u32,
    ) -> Vec<u8> {
        self.select_leader_hash_round(parent_hash, height, batch_hash, round)
    }

    fn select_leader_hash_round(
        &self,
        parent_hash: &[u8; 32],
        height: u64,
        batch_hash: &[u8; 32],
        round: u32,
    ) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"leader-selection-v2");
        hasher.update(parent_hash);
        hasher.update(height.to_le_bytes());
        let _ = batch_hash;
        hasher.update(round.to_le_bytes()); // round rotates the leader
        let leader_hash: [u8; 32] = hasher.finalize().into();

        let active_validators = self.active_validators();
        if active_validators.is_empty() {
            tracing::warn!(" No active validators for leader selection; defaulting to self");
            return self.validator_pubkey.clone();
        }

        if let Ok(bytes) = leader_hash[..8].try_into() {
            let leader_index = u64::from_le_bytes(bytes) % active_validators.len() as u64;
            return active_validators[leader_index as usize].clone();
        }
        active_validators[0].clone()
    }

    fn leader_election_key(parent_hash: &[u8; 32], height: u64) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"leader-election-key-v1");
        hasher.update(parent_hash);
        hasher.update(height.to_le_bytes());
        hasher.finalize().into()
    }

    /// Compute batch commitment (order-independent)
    fn compute_batch_commitment(
        &self,
        batch: &[Transaction],
        parent_hash: &[u8; 32],
        height: u64,
    ) -> Result<[u8; 32], String> {
        self.compute_batch_commitment_round(batch, parent_hash, height, 0, 0)
    }

    fn compute_batch_commitment_round(
        &self,
        batch: &[Transaction],
        parent_hash: &[u8; 32],
        height: u64,
        _round: u64,
        _parent_ts_secs: u64,
    ) -> Result<[u8; 32], String> {
        let mut tx_hashes: Vec<[u8; 32]> = batch
            .iter()
            .map(|tx| {
                let bytes = postcard::to_allocvec(tx)
                    .map_err(|e| format!("Failed to serialize tx: {}", e))?;
                Ok::<[u8; 32], String>(*blake3::hash(&bytes).as_bytes())
            })
            .collect::<Result<Vec<_>, _>>()?;
        tx_hashes.sort_unstable();
        let mut ctx = [0u8; 40];
        ctx[..32].copy_from_slice(parent_hash);
        ctx[32..40].copy_from_slice(&height.to_le_bytes());
        tx_hashes.push(*blake3::hash(&ctx).as_bytes());
        Ok(Self::merkle_root(&tx_hashes))
    }

    /// Compute deterministic execution order
    fn compute_execution_order(
        &self,
        batch: &mut [Transaction],
        commitment: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, String> {
        // Sort transactions deterministically
        let mut keyed: Vec<([u8; 32], Transaction)> = Vec::with_capacity(batch.len());
        for tx in batch.iter() {
            let mut hasher = blake3::Hasher::new();
            let bytes =
                postcard::to_allocvec(tx).map_err(|e| format!("Failed to serialize tx: {}", e))?;
            hasher.update(&bytes);
            hasher.update(commitment); // Mix with commitment
            keyed.push((*hasher.finalize().as_bytes(), tx.clone()));
        }
        keyed.sort_by_key(|(k, _)| *k);
        for (idx, (_, tx)) in keyed.into_iter().enumerate() {
            batch[idx] = tx;
        }

        // Return sorted TX hashes
        let hashes = batch
            .iter()
            .map(|tx| {
                let bytes = postcard::to_allocvec(tx)
                    .map_err(|e| format!("Failed to serialize tx: {}", e))?;
                Ok::<[u8; 32], String>(*blake3::hash(&bytes).as_bytes())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(hashes)
    }

    /// Epoch rotation task (1 minute epochs)
    pub async fn epoch_rotation_task(self: Arc<Self>) {
        let mut timer = interval(Duration::from_millis(gp::get_u64(
            gp::PARAM_EPOCH_DURATION_MS,
        )));

        loop {
            timer.tick().await;

            // Derive epoch from wall clock - same formula as attesters_for_header -
            // so all nodes independently compute the same active attester set regardless of start time.
            let epoch_ms = gp::get_u64(gp::PARAM_EPOCH_DURATION_MS);
            let now_ms = Self::current_timestamp().saturating_mul(1000);
            let epoch = if epoch_ms == 0 { 0 } else { now_ms / epoch_ms };

            self.refresh_active_attesters(epoch).await;

            tracing::info!(
                " Epoch {} started, active attester set size: {}",
                epoch,
                self.active_attesters.read().await.len()
            );
        }
    }

    /// Profile gossip task - broadcast new profiles every 30 seconds
    pub async fn profile_gossip_task(self: Arc<Self>) {
        let mut timer = interval(Duration::from_secs(30));

        loop {
            timer.tick().await;
        }
    }

    /// Attestation pipeline cleanup task - remove stale batches every 60s
    pub async fn attestation_cleanup_task(self: Arc<Self>) {
        use tokio::time::{interval, Duration};

        let mut timer = interval(Duration::from_secs(60));

        loop {
            timer.tick().await;

            if let Some(ref pipeline) = self.attestation_pipeline {
                pipeline.cleanup_stale(300).await; // Remove batches older than 5 minutes

                let stats = pipeline.get_stats().await;
                tracing::debug!(
                    " Attestation stats: {} batches, avg {}ms, {} failures",
                    stats.total_batches,
                    stats.avg_attestation_time_ms,
                    stats.quorum_failures
                );
            }
        }
    }

    /// Height announcement task - broadcast our height to peers every 10 seconds
    pub async fn height_announcement_task(self: Arc<Self>) {
        use tokio::time::{interval, Duration};

        let mut timer = interval(Duration::from_secs(10));

        loop {
            timer.tick().await;

            // Prune stale peers from discovery table.
            self.peer_discovery.prune_stale().await;

            let height = self.blockchain.read().await.get_current_height();

            // Get our address (use first known peer's perspective or empty)
            let our_addr = self
                .get_known_peers()
                .await
                .first()
                .cloned()
                .unwrap_or_default();

            // Broadcast height to all peers
            if let Some(announcement) = self.build_height_announcement(height, our_addr) {
                let msg = P2PMessage::HeightAnnouncement(announcement);
                if let Ok(data) = postcard::to_allocvec(&msg) {
                    let peer_senders = self.peer_senders.read().await;
                    for sender in peer_senders.values() {
                        let _ = sender.try_send(data.clone());
                    }
                }
            }
        }
    }

    fn height_announcement_message(height: u64, peer_addr: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&height.to_le_bytes());
        msg.extend_from_slice(&(peer_addr.len() as u32).to_le_bytes());
        msg.extend_from_slice(peer_addr.as_bytes());
        msg
    }

    fn build_height_announcement(
        &self,
        height: u64,
        peer_addr: String,
    ) -> Option<HeightAnnouncement> {
        let message = Self::height_announcement_message(height, &peer_addr);
        let signature = self
            .keypair
            .dilithium_sk
            .try_sign(&message, b"height-announcement-v1")
            .ok()?
            .to_vec();
        Some(HeightAnnouncement {
            validator_pubkey: self.validator_pubkey.clone(),
            height,
            peer_addr,
            signature,
        })
    }

    /// Handle received height announcement from peer
    pub async fn handle_height_announcement(
        &self,
        announcement: HeightAnnouncement,
    ) -> Result<(), String> {
        use fips204::traits::{SerDes, Verifier};
        // Note: active validator check intentionally omitted for height announcements.
        // Signature verification below is sufficient - height gossip is low-stakes
        // and the active check was silently dropping valid announcements from peers
        // whose pubkeys weren't yet in the local staking state.

        // Verify signature
        let pk_bytes: [u8; 1952] = announcement
            .validator_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid pubkey length")?;
        let pk = DilithiumPublicKey::try_from_bytes(pk_bytes).map_err(|_| "Invalid pubkey")?;

        let sig_bytes: [u8; 3309] = announcement
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length")?;

        let message =
            Self::height_announcement_message(announcement.height, &announcement.peer_addr);
        if !pk.verify(&message, &sig_bytes, b"height-announcement-v1") {
            return Err("Invalid height signature".to_string());
        }

        // Update peer height in sync manager
        self.update_peer_height(announcement.validator_pubkey, announcement.height)
            .await;
        self.peer_discovery
            .update_peer_height(&announcement.peer_addr, announcement.height)
            .await;

        Ok(())
    }

    /// Continuous batch processing
    /// Processes batches as soon as they reach optimal size or 50ms timeout
    pub async fn batch_timer_task(self: Arc<Self>) {
        let mut timer = interval(Duration::from_millis(gp::get_u64(
            gp::PARAM_STREAMING_MAX_WAIT_MS,
        )));
        let mut last_height = 0u64;

        loop {
            timer.tick().await;

            // Reset round when height advances; increment when stuck at same height
            let current_height = self
                .finalized_height
                .load(std::sync::atomic::Ordering::SeqCst);
            if current_height > last_height {
                last_height = current_height;
            }

            self.requeue_stale_batches().await;

            // Produce a batch if:
            //   a) there are transactions waiting, OR
            //   b) the network is fully formed (each node has >= 2 active PQ sessions,
            //      meaning every validator is connected to at least 2 peers).
            // This ensures the chain advances even with no user activity once the
            // validator mesh is established.
            let session_count = self.get_session_count().await;
            let network_ready = session_count >= 2;
            let has_txs = {
                let batch_lock = self.batch.read().await;
                !batch_lock.is_empty()
            };

            if !has_txs && !network_ready {
                continue;
            }

            // Do not propose next block until previous is finalized - keeps all nodes on same canonical tip.
            {
                let current = self
                    .current_height
                    .load(std::sync::atomic::Ordering::SeqCst);
                let finalized = self
                    .finalized_height
                    .load(std::sync::atomic::Ordering::SeqCst);
                if current > finalized {
                    continue;
                }
            }

            // Do not produce until sync manager confirms we're caught up with peers.
            // This prevents producing a block with a stale parent immediately after replay,
            // before receiving the latest attested block from connected peers.
            if !self.sync_manager.read().await.is_synced() {
                continue;
            }

            // Get batch (arrival order does not matter)
            let mut batch = {
                let mut batch_lock = self.batch.write().await;
                let batch: Vec<Transaction> = batch_lock.drain(..).collect();
                // Do not clear seen_txs here - let executed_tx_hashes handle replay protection
                batch
            };

            // Nonce-gating: only include contiguous nonces per sender.
            let state = self.state.load();
            let mut by_sender: std::collections::HashMap<
                AccountId,
                Vec<(u64, [u8; 32], Transaction)>,
            > = std::collections::HashMap::new();
            for tx in batch.drain(..) {
                let hash = match self.compute_tx_hash(&tx) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                by_sender
                    .entry(tx.sender)
                    .or_default()
                    .push((tx.nonce, hash, tx));
            }

            let mut senders: Vec<AccountId> = by_sender.keys().copied().collect();
            senders.sort();
            let mut executable: Vec<Transaction> = Vec::new();
            let mut deferred_nonce_wait: Vec<Transaction> = Vec::new();
            let mut nonce_rejections: Vec<([u8; 32], String)> = Vec::new();

            for sender in senders {
                let mut entries = by_sender.remove(&sender).unwrap_or_default();
                entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                let current_nonce = state.accounts.get(&sender).map(|a| a.nonce).unwrap_or(0);
                let mut expected = current_nonce.saturating_add(1);

                for (nonce, hash, tx) in entries {
                    if nonce == expected {
                        executable.push(tx);
                        expected = expected.saturating_add(1);
                    } else if nonce > expected {
                        let mut waiting_on_inflight_nonce = false;
                        let mut missing = expected;
                        while missing < nonce {
                            if self.sender_nonce_is_waitable(sender, missing).await {
                                waiting_on_inflight_nonce = true;
                                missing = missing.saturating_add(1);
                            } else {
                                waiting_on_inflight_nonce = false;
                                break;
                            }
                        }

                        if waiting_on_inflight_nonce {
                            deferred_nonce_wait.push(tx);
                        } else {
                            nonce_rejections.push((
                                hash,
                                format!("nonce gap: expected {}, got {}", expected, nonce),
                            ));
                        }
                    } else {
                        nonce_rejections.push((
                            hash,
                            format!("stale nonce {} below expected {}", nonce, expected),
                        ));
                    }
                }
            }
            for (hash, reason) in nonce_rejections {
                self.remember_tx_lifecycle(hash, TxLifecycleStatus::Rejected { reason })
                    .await;
            }
            if !deferred_nonce_wait.is_empty() {
                let deferred_count = deferred_nonce_wait.len();
                let mut batch_lock = self.batch.write().await;
                batch_lock.extend(deferred_nonce_wait);
                tracing::debug!(
                    deferred_count,
                    "Deferred transactions waiting for lower in-flight sender nonces"
                );
            }

            self.rebuild_mempool_index().await;

            batch = executable;

            // Adaptive batch size: if the last batch took >200ms to execute, shrink the
            // current batch so execution fits within the 300ms window.
            // Floor: MIN_BATCH_SIZE (1,000). Ceiling: PARAM_MAX_BATCH_SIZE (30,000).
            let last_ms = self.last_exec_ms.load(std::sync::atomic::Ordering::Relaxed);
            if last_ms > 200 && !batch.is_empty() {
                let max = gp::get_usize(gp::PARAM_MAX_BATCH_SIZE);
                let target = ((batch.len() as u64 * 200 / last_ms) as usize).clamp(1_000, max);
                if target < batch.len() {
                    tracing::info!(
                        "Adaptive batch: last_exec={}ms → capping {} → {} txs",
                        last_ms,
                        batch.len(),
                        target
                    );
                    // Return excess to mempool
                    let excess = batch.split_off(target);
                    let mut batch_lock = self.batch.write().await;
                    batch_lock.extend(excess);
                }
            }

            // ===== PHASE 1: COMMITMENT (ORDER-INDEPENDENT) =====
            // Only build on finalized blocks - ensures all nodes use the same parent hash.
            let finalized = self
                .finalized_height
                .load(std::sync::atomic::Ordering::SeqCst);
            let (parent_hash, next_height) = {
                let bc = self.blockchain.read().await;
                // Find the header at finalized_height, not just the canonical tip
                let tip = bc.get_canonical_tip().ok();
                match tip {
                    Some(t) if t.height == finalized => (t.batch_hash, finalized + 1),
                    Some(t) if t.height > finalized => {
                        // Canonical tip is ahead of finalized; walk the
                        // canonical chain to the finalized block instead of
                        // picking an arbitrary header at that height. Forked
                        // headers can share the same height under congestion,
                        // and HashMap iteration order is not a protocol rule.
                        if let Some(h) = bc.get_batch_by_height(finalized) {
                            (h.batch_hash, finalized + 1)
                        } else {
                            (t.batch_hash, t.height + 1)
                        }
                    }
                    Some(t) => (t.batch_hash, t.height + 1),
                    None => ([0u8; 32], 1),
                }
            };
            let own_batch_commitment =
                match self.compute_batch_commitment(&batch, &parent_hash, next_height) {
                    Ok(commitment) => commitment,
                    Err(e) => {
                        tracing::error!(" Failed to compute batch commitment: {}", e);
                        continue;
                    }
                };

            if batch.is_empty() {
                tracing::trace!(
                    "Idle batch commitment {} at height {}",
                    hex::encode(&own_batch_commitment[..8]),
                    next_height
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    gp::get_u64(gp::PARAM_STREAMING_MAX_WAIT_MS).max(200),
                ))
                .await;
                continue;
            }
            tracing::debug!(
                "Prepared batch {} at height {} ({} txs)",
                hex::encode(&own_batch_commitment[..8]),
                next_height,
                batch.len()
            );
            // Cache our exact executable batch before broadcasting the commitment
            // so peers can fetch it if it becomes the majority hash.
            self.cache_batch(own_batch_commitment, batch.clone()).await;

            // ── Phase-2: broadcast our commitment and wait briefly for peers ──
            // All validators independently compute batch_hash and sign it.
            // The leader must use the hash that 2/3+ of validators committed to.
            self.broadcast_batch_commitment(next_height, own_batch_commitment)
                .await;
            // Wait up to half a batch window for peer commitments to arrive.
            let commit_wait_ms = (gp::get_u64(gp::PARAM_STREAMING_MAX_WAIT_MS) / 2).max(50);
            tokio::time::sleep(tokio::time::Duration::from_millis(commit_wait_ms)).await;
            let majority_hash = self.majority_committed_hash(next_height).await;
            let batch_commitment = match majority_hash {
                Some(mh) if mh == own_batch_commitment => mh,
                Some(mh) => {
                    if let Some(cached) = self.get_cached_batch(&mh).await {
                        match self.compute_batch_commitment(
                            &cached.batch,
                            &parent_hash,
                            next_height,
                        ) {
                            Ok(commitment) if commitment == mh => {
                                tracing::info!(
                                    " Adopting majority batch {} at height {} over local {}",
                                    hex::encode(&mh[..8]),
                                    next_height,
                                    hex::encode(&own_batch_commitment[..8])
                                );
                                batch = cached.batch;
                                mh
                            }
                            Ok(commitment) => {
                                tracing::warn!(
                                    " Cached majority batch {} recomputed as {}; requesting fresh copy",
                                    hex::encode(&mh[..8]),
                                    hex::encode(&commitment[..8])
                                );
                                let msg = P2PMessage::BatchRequest { batch_hash: mh };
                                if let Ok(data) = postcard::to_allocvec(&msg) {
                                    for sender in self.peer_senders.read().await.values() {
                                        let _ = sender.try_send(data.clone());
                                    }
                                }
                                self.requeue_batch_immediately(batch).await;
                                continue;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    " Cached majority batch {} is not executable: {}; requesting fresh copy",
                                    hex::encode(&mh[..8]),
                                    e
                                );
                                let msg = P2PMessage::BatchRequest { batch_hash: mh };
                                if let Ok(data) = postcard::to_allocvec(&msg) {
                                    for sender in self.peer_senders.read().await.values() {
                                        let _ = sender.try_send(data.clone());
                                    }
                                }
                                self.requeue_batch_immediately(batch).await;
                                continue;
                            }
                        }
                    } else {
                        tracing::warn!(
                            " Majority batch {} at height {} is not cached locally; requesting it and standing down from local {}",
                            hex::encode(&mh[..8]),
                            next_height,
                            hex::encode(&own_batch_commitment[..8])
                        );
                        let msg = P2PMessage::BatchRequest { batch_hash: mh };
                        if let Ok(data) = postcard::to_allocvec(&msg) {
                            for sender in self.peer_senders.read().await.values() {
                                let _ = sender.try_send(data.clone());
                            }
                        }
                        self.requeue_batch_immediately(batch).await;
                        continue;
                    }
                }
                None => own_batch_commitment,
            };
            tracing::debug!(
                " Effective batch commitment: {}",
                hex::encode(&batch_commitment[..8])
            );
            // ─────────────────────────────────────────────────────────────────

            // Cache only the batch under the hash it actually commits to.
            self.cache_batch(batch_commitment, batch.clone()).await;

            let election_key = Self::leader_election_key(&parent_hash, next_height);
            let effective_leader_round = {
                let rounds = self.leader_skip_rounds.read().await;
                rounds.get(&election_key).copied().unwrap_or(0)
            };
            let leader_pubkey = self.select_leader_hash(
                &parent_hash,
                next_height,
                &batch_commitment,
                effective_leader_round,
            );
            tracing::debug!(
                "Selected leader {} for height {} round {} (parent={}, batch={})",
                hex::encode(&leader_pubkey[..8]),
                next_height,
                effective_leader_round,
                hex::encode(&parent_hash[..4]),
                hex::encode(&batch_commitment[..4])
            );
            // Do not lead if we're still syncing.
            let am_leader = leader_pubkey == self.validator_pubkey
                && self.sync_manager.read().await.is_synced();

            // ===== PHASE 2: EXECUTION ORDER (DETERMINISTIC) =====

            // Compute execution order (deterministic across all nodes)
            let execution_order = match self.compute_execution_order(&mut batch, &batch_commitment)
            {
                Ok(order) => order,
                Err(e) => {
                    tracing::error!(" Failed to compute execution order: {}", e);
                    continue;
                }
            };
            let execution_order_root = Self::merkle_root(&execution_order);

            tracing::debug!(
                " Execution order: {}",
                hex::encode(&execution_order_root[..8])
            );

            // ALL active validators execute batch to compute state root, then attest.
            // The leader uses execute_batch_with_results to avoid a second execution later.
            let mut leader_state: Option<truthlinked_state::State> = None;
            let mut leader_state_root: Option<[u8; 32]> = None;
            let mut leader_batch_result: Option<truthlinked_state::parallel_executor::BatchResult> =
                None;
            if self.is_active_attester().await {
                let state = self.state.load();
                if am_leader {
                    match self.execute_batch_with_results(&state, &batch).await {
                        Ok(result) => {
                            let state_root = self.compute_state_root(&result.state);
                            leader_state = Some(result.state.clone());
                            leader_state_root = Some(state_root);
                            leader_batch_result = Some(result);
                            if let Some(ref pipeline) = self.attestation_pipeline {
                                pipeline
                                    .start_collection(
                                        next_height,
                                        effective_leader_round as u64,
                                        batch_commitment,
                                        state_root,
                                    )
                                    .await;
                                tracing::info!(
                                    "🔔 Started attestation collection for batch {} at height {} round {}",
                                    hex::encode(&batch_commitment[..8]),
                                    next_height,
                                    effective_leader_round
                                );
                            }
                            self.send_attestation(
                                next_height,
                                effective_leader_round as u64,
                                batch_commitment,
                                state_root,
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!(
                                " Attester execution failed, skipping attestation: {}",
                                e
                            );
                        }
                    }
                } else {
                    // Non-leaders do not sign speculative local executions. They
                    // attest only after receiving the elected leader's proposal or
                    // header, which binds the vote to one state root and avoids
                    // certificate retry storms under congestion.
                }
            }

            if !am_leader {
                tracing::info!(
                    " Leader is {}, waiting for block",
                    hex::encode(&leader_pubkey[..8])
                );
                // Non-leaders: cache batch for potential requeue if leader never produces a block.
                self.cache_pending_batch(batch_commitment, batch.clone())
                    .await;

                // Leader timeout: if the leader does not produce a header within
                // PARAM_STREAMING_MAX_WAIT_MS * 6, requeue the batch so the next
                // leader election can proceed. This prevents a missing/offline leader
                // from halting the chain indefinitely.
                let timeout_ms = gp::get_u64(gp::PARAM_STREAMING_MAX_WAIT_MS)
                    .saturating_mul(4)
                    .max(1200);
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    // Check if this height has been finalized (by any block, not just our batch_hash).
                    // The leader may have had a different mempool snapshot → different batch_hash.
                    {
                        let finalized = self
                            .finalized_height
                            .load(std::sync::atomic::Ordering::SeqCst);
                        if finalized >= next_height {
                            break; // height committed by some leader - move on
                        }
                        // Also check if our specific batch_hash landed (same-mempool case)
                        let blockchain = self.blockchain.read().await;
                        if blockchain.get_header(&batch_commitment).is_some() {
                            break; // leader produced with same batch - normal path
                        }
                    }
                    if std::time::Instant::now() >= deadline {
                        // Increment skip round - next leader election will pick a different validator
                        let new_round = {
                            let mut rounds = self.leader_skip_rounds.write().await;
                            let r = rounds.entry(election_key).or_insert(0);
                            *r += 1;
                            *r
                        };
                        tracing::info!(
                            "Leader {} timed out after {}ms; rotating to round {} for batch {}",
                            hex::encode(&leader_pubkey[..8]),
                            timeout_ms,
                            new_round,
                            hex::encode(&batch_commitment[..8])
                        );
                        self.requeue_batch_immediately(batch.clone()).await;
                        break;
                    }
                }
                continue;
            }

            tracing::info!(
                " I am the leader for batch {}",
                hex::encode(&batch_commitment[..8])
            );

            // If the leader was not an active attester, execute now (single execution).
            if leader_batch_result.is_none() {
                let state = self.state.load();
                match self.execute_batch_with_results(&state, &batch).await {
                    Ok(result) => {
                        let root = self.compute_state_root(&result.state);
                        leader_state = Some(result.state.clone());
                        leader_state_root = Some(root);
                        leader_batch_result = Some(result);
                    }
                    Err(e) => {
                        tracing::error!("Failed to execute batch as leader: {}", e);
                        continue;
                    }
                }
            }
            let leader_state_root = match leader_state_root {
                Some(root) => root,
                None => {
                    tracing::error!("Leader state root missing");
                    continue;
                }
            };

            // Broadcast a compact proposal to non-leaders so they can attest
            // using locally gossiped mempool transactions. Peers that are
            // missing any tx fall back to BatchRequest/BatchResponse.
            {
                let proposal = match batch
                    .iter()
                    .map(|tx| self.compute_tx_hash(tx))
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(tx_hashes) => P2PMessage::CompactBatchProposal {
                        height: next_height,
                        parent_hash,
                        batch_hash: batch_commitment,
                        tx_hashes,
                        state_root: leader_state_root,
                        leader_pubkey: self.validator_pubkey.clone(),
                        leader_round: effective_leader_round,
                    },
                    Err(e) => {
                        tracing::warn!(
                            "Failed to build compact batch proposal, falling back to full: {}",
                            e
                        );
                        P2PMessage::BatchProposal {
                            height: next_height,
                            parent_hash,
                            batch_hash: batch_commitment,
                            batch: batch.clone(),
                            state_root: leader_state_root,
                            leader_pubkey: self.validator_pubkey.clone(),
                            leader_round: effective_leader_round,
                        }
                    }
                };
                let data = postcard::to_allocvec(&proposal).unwrap_or_default();
                let peer_senders = self.peer_senders.read().await;
                for sender in peer_senders.values() {
                    let _ = sender.try_send(data.clone());
                }
            }

            // Wait for attestation quorum (leader only) - use pipelined attestation with timeout
            tracing::info!(
                "🔔 Leader waiting for quorum on batch {}",
                hex::encode(&batch_commitment[..8])
            );
            let state_snapshot = self.state.load();
            let stake_map = Self::stake_map_from_state(&state_snapshot);
            let active_attesters: Vec<Vec<u8>> = state_snapshot
                .staking
                .get_active_validators()
                .keys()
                .cloned()
                .collect();
            let current_height_for_liveness = self
                .current_height
                .load(std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1);
            let quorum_attesters = self
                .live_attesters(&active_attesters, current_height_for_liveness)
                .await;
            let required_stake = Self::required_non_leader_stake_for_attesters(
                &stake_map,
                &quorum_attesters,
                &self.validator_pubkey,
            );
            let solo_local_quorum = required_stake == 0
                && active_attesters.len() == 1
                && quorum_attesters.len() == 1
                && quorum_attesters
                    .first()
                    .map(|pk| pk.as_slice() == self.validator_pubkey.as_slice())
                    .unwrap_or(false);
            if required_stake == 0 && !solo_local_quorum {
                tracing::debug!(
                    "Skipping batch: no live non-leader stake available for quorum at height {}",
                    next_height
                );
                self.requeue_batch_immediately(batch).await;
                continue;
            }

            // Mature attestation delivery:
            // - Wait up to PARAM_STREAMING_MAX_WAIT_MS * 20 total (governance-tunable)
            // - Retry in windows of PARAM_STREAMING_MAX_WAIT_MS * 4 each
            // - On each retry window, re-broadcast batch header to ensure peers have it
            // - Never requeue if we have partial progress - keep accumulating
            // - Only give up and requeue if zero attestations after full timeout
            let attestation_window_ms = gp::get_u64(gp::PARAM_STREAMING_MAX_WAIT_MS)
                .saturating_mul(10)
                .max(3000);
            let max_retries = 5usize;
            let mut attestations: Vec<Attestation> = Vec::new();
            let mut quorum_reached = false;

            if solo_local_quorum {
                quorum_reached = true;
                tracing::info!(
                    " Solo local quorum: committing batch {} without non-leader attestations",
                    hex::encode(&batch_commitment[..8])
                );
            }

            'quorum: for attempt in 0..max_retries {
                if quorum_reached {
                    break 'quorum;
                }
                if attempt > 0 {
                    // Re-broadcast header on retry so late/slow peers can catch up
                    tracing::info!(
                        "🔁 Attestation retry {}/{} for batch {}",
                        attempt,
                        max_retries,
                        hex::encode(&batch_commitment[..8])
                    );
                }

                if let Some(ref pipeline) = self.attestation_pipeline {
                    match pipeline
                        .wait_for_quorum(
                            next_height,
                            effective_leader_round as u64,
                            batch_commitment,
                            attestation_window_ms,
                            required_stake,
                            &stake_map,
                            leader_state_root,
                            &self.validator_pubkey,
                            Some(&quorum_attesters),
                        )
                        .await
                    {
                        Some(atts) => {
                            attestations = atts
                                .into_iter()
                                .filter(|a| a.state_root == leader_state_root)
                                .collect();
                            quorum_reached = true;
                            tracing::info!(
                                " Quorum on attempt {}: {} attestations",
                                attempt + 1,
                                attestations.len()
                            );
                            break 'quorum;
                        }
                        None => {
                            let partial = pipeline
                                .get_partial_stake(
                                    next_height,
                                    effective_leader_round as u64,
                                    &batch_commitment,
                                    &stake_map,
                                    leader_state_root,
                                    &self.validator_pubkey,
                                    Some(&quorum_attesters),
                                )
                                .await;
                            // Compute threshold with the same non-leader live quorum rule
                            // used by wait_for_quorum so timeout logs reflect the real gate.
                            let non_leader_required: u64 = {
                                let nl_total: u64 = quorum_attesters
                                    .iter()
                                    .filter(|pk| pk.as_slice() != self.validator_pubkey.as_slice())
                                    .filter_map(|pk| stake_map.get(pk))
                                    .fold(0u64, |a, b| a.saturating_add(*b));
                                let nl_count = quorum_attesters
                                    .iter()
                                    .filter(|pk| pk.as_slice() != self.validator_pubkey.as_slice())
                                    .filter(|pk| stake_map.contains_key(*pk))
                                    .count();
                                crate::attestation_pipeline::AttestationPipeline::effective_non_leader_quorum_required(
                                    nl_total,
                                    nl_count,
                                )
                            };
                            tracing::warn!(
                                "  Attestation window {} timed out for batch {} ({}/{} stake)",
                                attempt + 1,
                                hex::encode(&batch_commitment[..8]),
                                partial,
                                non_leader_required
                            );
                        }
                    }
                }
            }

            if !quorum_reached {
                // Increment skip round so the next iteration elects a different leader
                let new_round = {
                    let mut rounds = self.leader_skip_rounds.write().await;
                    let r = rounds.entry(election_key).or_insert(0);
                    *r += 1;
                    *r
                };
                tracing::info!(
                    "Rotating leader for batch {} after {} attestation window(s) (round {})",
                    hex::encode(&batch_commitment[..8]),
                    max_retries,
                    new_round
                );
                self.requeue_batch_immediately(batch).await;
                continue;
            }

            let mut attestations: Vec<Attestation> = attestations
                .into_iter()
                .map(|a| Attestation {
                    height: a.height,
                    round: a.round,
                    batch_hash: a.batch_hash,
                    state_root: a.state_root,
                    validator_pubkey: a.validator_pubkey,
                    signature: a.signature,
                })
                .collect();
            attestations.sort_by(|a, b| a.validator_pubkey.cmp(&b.validator_pubkey));

            // Leader executes batch

            tracing::debug!(
                " Execution order: {}",
                hex::encode(&execution_order_root[..8])
            );
            tracing::debug!("Batch size: {} transaction(s)", batch.len());

            // Log unique TX hashes in batch
            let unique_hashes: std::collections::HashSet<_> = batch
                .iter()
                .map(|tx| {
                    let bytes = postcard::to_allocvec(tx).unwrap_or_default();
                    *blake3::hash(&bytes).as_bytes()
                })
                .collect();
            tracing::debug!("Unique transactions in batch: {}", unique_hashes.len());

            match leader_state.take() {
                Some(new_state) => {
                    self.state.store(Arc::new(new_state.clone()));
                    tracing::debug!("State stored: {} account(s)", new_state.accounts.len());

                    // Compute state root
                    let state_root = leader_state_root;

                    let leader_sig = self.sign_batch(&batch_commitment);

                    // CRITICAL: use the same parent_hash that was used to compute
                    // batch_commitment. Do NOT re-read canonical tip here - if the
                    // tip changed during attestation collection the commitment would
                    // not match the header's parent_hash on every other node.
                    let parent_ts = {
                        let blockchain = self.blockchain.read().await;
                        match blockchain.get_canonical_tip() {
                            Ok(tip) => {
                                // If the canonical tip changed since we computed the
                                // commitment, the batch is stale - requeue it.
                                if tip.batch_hash != parent_hash {
                                    tracing::warn!(
                                        " Canonical tip changed during attestation (was {}, now {}), requeueing batch",
                                        hex::encode(&parent_hash[..8]),
                                        hex::encode(&tip.batch_hash[..8])
                                    );
                                    self.requeue_batch_immediately(batch).await;
                                    continue;
                                }
                                tip.timestamp
                            }
                            Err(e) => {
                                tracing::error!("Missing canonical tip: {}", e);
                                continue;
                            }
                        }
                    };
                    truthlinked_state::set_current_height(next_height);
                    let mut timestamp = Self::current_timestamp();
                    if timestamp < parent_ts {
                        timestamp = parent_ts;
                    }

                    let total_fees = leader_batch_result
                        .as_ref()
                        .map(|r| r.total_fees)
                        .unwrap_or(0);
                    let finality_certificate =
                        match crate::blockchain::PqFinalityCertificate::from_attestations(
                            next_height,
                            effective_leader_round as u64,
                            batch_commitment,
                            state_root,
                            &active_attesters,
                            &stake_map,
                            &self.validator_pubkey,
                            &attestations,
                        ) {
                            Ok(cert) => cert,
                            Err(e) => {
                                tracing::error!("Failed to build PQ finality certificate: {}", e);
                                continue;
                            }
                        };
                    let header = crate::BatchHeader::new(
                        next_height,
                        parent_hash,
                        batch_commitment,
                        execution_order_root,
                        state_root,
                        timestamp,
                        total_fees,
                        finality_certificate,
                        self.validator_pubkey.clone(),
                        leader_sig,
                        effective_leader_round as u64,
                    );

                    // Add to my blockchain
                    {
                        let mut blockchain = self.blockchain.write().await;
                        if let Err(e) = blockchain.add_header(header.clone()) {
                            tracing::error!("Failed to add header: {}", e);
                            continue;
                        }

                        let active_validators = new_state.staking.get_active_validators();
                        let total_stake: u64 = active_validators.values().sum();
                        // Use real fork choice so the rule is exercised even for the leader.
                        if let Err(e) = blockchain.set_canonical_tip(header.batch_hash, total_stake)
                        {
                            tracing::error!(
                                "Fork choice rejected own block at height {}: {}",
                                next_height,
                                e
                            );
                            continue;
                        }
                    }

                    // Persist batch + header before this height is advertised or
                    // reported. Sync anchors are storage-backed, so advancing first
                    // creates a height that peers cannot safely request from.
                    if let Some(ref storage) = self.storage {
                        let name_registry =
                            Self::active_name_registry(&new_state, header.timestamp);
                        let results = leader_batch_result
                            .as_ref()
                            .map(|res| Self::batch_results(batch.len(), &res.failed))
                            .unwrap_or_else(|| vec!["success".to_string(); batch.len()]);
                        if let Err(e) =
                            storage.save_block(&header, &batch, &results, &name_registry)
                        {
                            tracing::error!("Failed to save block: {}", e);
                            continue;
                        }
                    }

                    let committed_failures = leader_batch_result
                        .as_ref()
                        .map(|res| res.failed.as_slice())
                        .unwrap_or(&[]);
                    self.prune_committed_from_mempool(&batch, committed_failures)
                        .await;

                    // Advance current_height atomic only after successful add_header
                    // and durable block storage.
                    self.current_height
                        .store(next_height, std::sync::atomic::Ordering::SeqCst);
                    self.prune_ineligible_from_mempool(&new_state).await;

                    self.maybe_persist_snapshot(next_height, &new_state);

                    // Broadcast to peers
                    self.broadcast_header(header.clone()).await;
                    tracing::debug!("Block {} produced and broadcast", next_height);

                    self.pending_batches.write().await.remove(&batch_commitment);
                    // Reset skip round - this batch committed successfully
                    self.leader_skip_rounds.write().await.remove(&election_key);
                    // Advance finalized height.
                    self.advance_finalized_height(next_height).await;

                    // ── Inline BFT: Prevote + Precommit ──────────────────
                    // Block is committed via attestation quorum. Now run the
                    // BFT prevote/precommit round so all nodes agree on finality.
                    // This replaces the separate bft_consensus_task.
                    {
                        let round = {
                            let mut rs = self.bft_round.write().await;
                            if rs.height != next_height {
                                *rs = crate::round_state::RoundState::new(next_height);
                            }
                            rs.proposal = Some(batch_commitment);
                            rs.step = crate::round_state::Step::Prevote;
                            rs.round = 0;
                            rs.prevotes.clear();
                            rs.precommits.clear();
                            rs.round
                        };
                        if self.is_active_attester().await {
                            self.broadcast_prevote(next_height, round, Some(batch_commitment))
                                .await;
                            self.broadcast_precommit(next_height, round, Some(batch_commitment))
                                .await;
                        }
                        // Brief window for peers to exchange votes
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            gp::get_u64(gp::PARAM_STREAMING_MAX_WAIT_MS).max(200),
                        ))
                        .await;
                    }
                    tracing::info!(
                        "Finalized block {} ({} txs, fees={} base units)",
                        next_height,
                        batch.len(),
                        total_fees
                    );
                }
                None => {
                    tracing::error!("Failed to execute batch: missing leader state");
                    continue;
                }
            }

            // Clean up old attestations in pipeline
            if let Some(ref pipeline) = self.attestation_pipeline {
                pipeline
                    .cleanup_stale(gp::get_u64(gp::PARAM_ACK_MAX_BATCH_AGE_SECS))
                    .await;
            }
        }
    }

    async fn cache_pending_batch(&self, batch_hash: [u8; 32], batch: Vec<Transaction>) {
        let mut pending = self.pending_batches.write().await;
        // Hard cap — evict oldest if full.
        if pending.len() >= truthlinked_state::constants::MAX_PENDING_BATCHES {
            if let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, e)| e.created_at)
                .map(|(k, _)| *k)
            {
                pending.remove(&oldest);
            }
        }
        pending.insert(
            batch_hash,
            PendingBatchEntry {
                batch,
                created_at: Instant::now(),
            },
        );
    }

    async fn requeue_batch_immediately(&self, batch: Vec<Transaction>) {
        let state = self.state.load();
        let current_height = self.get_current_height();
        let lookahead = gp::get_u64(gp::PARAM_NONCE_LOOKAHEAD);
        let max_batch = gp::get_usize(gp::PARAM_MAX_BATCH_SIZE);
        let mut lifecycle_updates: Vec<([u8; 32], TxLifecycleStatus)> = Vec::new();

        {
            let mut batch_lock = self.batch.write().await;
            let mut existing: HashSet<[u8; 32]> = batch_lock
                .iter()
                .filter_map(|tx| self.compute_tx_hash(tx).ok())
                .collect();

            for tx in batch {
                if batch_lock.len() >= max_batch {
                    break;
                }
                let hash = match self.compute_tx_hash(&tx) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if state.executed_tx_hashes.contains(&hash) {
                    lifecycle_updates.push((hash, TxLifecycleStatus::Confirmed));
                    continue;
                }
                if tx.expiration_height <= current_height {
                    lifecycle_updates.push((
                        hash,
                        TxLifecycleStatus::Rejected {
                            reason: "expired before requeue".to_string(),
                        },
                    ));
                    continue;
                }
                let Some(account) = state.accounts.get(&tx.sender) else {
                    lifecycle_updates.push((
                        hash,
                        TxLifecycleStatus::Rejected {
                            reason: "sender account not found during requeue".to_string(),
                        },
                    ));
                    continue;
                };
                let min_nonce = account.nonce.saturating_add(1);
                let max_nonce = account.nonce.saturating_add(1 + lookahead);
                if tx.nonce < min_nonce || tx.nonce > max_nonce {
                    lifecycle_updates.push((
                        hash,
                        TxLifecycleStatus::Rejected {
                            reason: format!(
                                "nonce {} outside requeue window {}..={}",
                                tx.nonce, min_nonce, max_nonce
                            ),
                        },
                    ));
                    continue;
                }
                if existing.insert(hash) {
                    batch_lock.push(tx);
                    lifecycle_updates.push((
                        hash,
                        TxLifecycleStatus::Pending {
                            since_height: current_height,
                        },
                    ));
                }
            }
        }

        for (hash, status) in lifecycle_updates {
            self.remember_tx_lifecycle(hash, status).await;
        }
    }

    async fn requeue_stale_batches(&self) {
        let timeout_ms = gp::get_u64(gp::PARAM_STREAMING_PENDING_BATCH_TIMEOUT_MS);
        if timeout_ms == 0 {
            return;
        }
        let current_height = {
            let blockchain = self.blockchain.read().await;
            self.observed_local_height(&blockchain)
        };
        let peer_ahead = {
            let sync_manager = self.sync_manager.read().await;
            sync_manager
                .get_highest_peer_height()
                .map(|peer_height| peer_height > current_height)
                .unwrap_or(false)
        };
        if peer_ahead {
            tracing::debug!(
                " Skipping stale batch requeue while local height {} is behind peers",
                current_height
            );
            return;
        }
        let now = Instant::now();
        let mut stale: Vec<Vec<Transaction>> = Vec::new();
        {
            let state = self.state.load();
            let lookahead = gp::get_u64(gp::PARAM_NONCE_LOOKAHEAD);
            let committed: HashSet<[u8; 32]> = {
                let blockchain = self.blockchain.read().await;
                self.pending_batches
                    .read()
                    .await
                    .keys()
                    .filter(|hash| blockchain.get_header(hash).is_some())
                    .copied()
                    .collect()
            };
            let mut pending = self.pending_batches.write().await;
            pending.retain(|hash, entry| {
                if committed.contains(hash) {
                    tracing::debug!(
                        " Dropping pending batch {} because it is already committed",
                        hex::encode(&hash[..8])
                    );
                    return false;
                }
                let has_live_tx = entry.batch.iter().any(|tx| {
                    let Ok(tx_hash) = self.compute_tx_hash(tx) else {
                        return false;
                    };
                    if state.executed_tx_hashes.contains(&tx_hash)
                        || tx.expiration_height <= current_height
                    {
                        return false;
                    }
                    let Some(account) = state.accounts.get(&tx.sender) else {
                        return false;
                    };
                    let min_nonce = account.nonce.saturating_add(1);
                    let max_nonce = account.nonce.saturating_add(1 + lookahead);
                    tx.nonce >= min_nonce && tx.nonce <= max_nonce
                });
                if !entry.batch.is_empty() && !has_live_tx {
                    tracing::debug!(
                        " Dropping pending batch {} because its transactions are no longer live",
                        hex::encode(&hash[..8])
                    );
                    return false;
                }
                let age_ms = now.duration_since(entry.created_at).as_millis() as u64;
                if age_ms >= timeout_ms {
                    tracing::warn!(
                        " Requeueing stale batch {} after {}ms without header",
                        hex::encode(&hash[..8]),
                        age_ms
                    );
                    stale.push(entry.batch.clone());
                    false
                } else {
                    true
                }
            });
        }
        for batch in stale {
            self.requeue_batch_immediately(batch).await;
        }
    }

    /// Sign batch as leader (Dilithium signature)
    fn sign_batch(&self, batch_hash: &[u8; 32]) -> Vec<u8> {
        self.keypair
            .dilithium_sk
            .try_sign(batch_hash, BATCH_SIGN_CONTEXT)
            .expect("Signing failed")
            .to_vec()
    }

    /// Broadcast finalized batch
    #[allow(dead_code)]
    async fn broadcast_finalized_batch(
        &self,
        batch: Vec<Transaction>,
        _batch_hash: [u8; 32],
        _leader_sig: Vec<u8>,
    ) {
        tracing::info!(" Broadcasting finalized batch: {} txs", batch.len());

        // Execute batch and update state
        let state = self.state.load();
        match self.execute_batch(&state, &batch).await {
            Ok(new_state) => {
                self.state.store(Arc::new(new_state));
            }
            Err(e) => {
                tracing::error!("Failed to execute batch: {}", e);
            }
        }
    }

    /// Add authenticated peer connection
    pub async fn add_peer(self: &Arc<Self>, mut stream: TcpStream) {
        let consensus = self.clone();

        tokio::spawn(async move {
            // Perform PQ handshake (responder side)
            let (session, peer_dilithium_pk) =
                match consensus.handshake.handshake_responder(&mut stream).await {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::error!(" Handshake failed: {}", e);
                        return;
                    }
                };

            // Verify peer is an active validator
            if !consensus.is_active_validator(&peer_dilithium_pk) {
                tracing::error!(
                    " Rejected inactive or unknown validator: {}",
                    hex::encode(&peer_dilithium_pk[..8])
                );
                return;
            }

            tracing::info!(
                " Authenticated validator: {}",
                hex::encode(&peer_dilithium_pk[..8])
            );

            // Add to peer discovery with metadata
            if let Ok(peer_addr) = stream.peer_addr() {
                let peer_info = truthlinked_net::discovery::PeerInfo {
                    pubkey: peer_dilithium_pk.clone(),
                    addresses: vec![peer_addr.to_string()],
                    height: 0, // Will be updated via gossip
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                };
                consensus
                    .peer_discovery
                    .add_peer(peer_addr.to_string(), peer_info)
                    .await;
            }

            // Store session
            consensus
                .sessions
                .write()
                .await
                .insert(peer_dilithium_pk.clone(), session.clone());

            // Create channel for outgoing messages
            let (tx, mut rx) = tokio::sync::mpsc::channel(OUTBOUND_QUEUE_CAP);
            consensus
                .peer_senders
                .write()
                .await
                .insert(peer_dilithium_pk.clone(), tx);
            tracing::info!(
                "OK Added inbound peer {} to senders (total: {})",
                hex::encode(&peer_dilithium_pk[..8]),
                consensus.peer_senders.read().await.len()
            );

            // Heartbeat: send Ping every 5s to keep connection alive
            {
                let hb_senders = consensus.peer_senders.clone();
                let hb_pk = peer_dilithium_pk.clone();
                tokio::spawn(async move {
                    let ping = postcard::to_allocvec(&P2PMessage::Ping).unwrap_or_default();
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        let senders = hb_senders.read().await;
                        match senders.get(&hb_pk) {
                            Some(s) if s.try_send(ping.clone()).is_ok() => {}
                            _ => break,
                        }
                    }
                });
            }
            // Split stream for bidirectional communication
            let (read_half, write_half) = tokio::io::split(stream);
            let mut read_stream = PQStream::new(read_half, session.clone());
            let mut write_stream = PQStream::new(write_half, session.clone());

            // Spawn writer task
            let peer_pk_clone = peer_dilithium_pk.clone();
            tokio::spawn(async move {
                while let Some(data) = rx.recv().await {
                    if let Err(e) = write_stream.write_encrypted(&data).await {
                        tracing::error!(
                            "Failed to send to {}: {}",
                            hex::encode(&peer_pk_clone[..8]),
                            e
                        );
                        break;
                    }
                }
            });

            // Handle incoming messages
            let consensus_clone = consensus.clone();
            loop {
                match read_stream.read_encrypted().await {
                    Ok(data) => {
                        match postcard::from_bytes::<P2PMessage>(&data) {
                            Ok(P2PMessage::Transaction(streamed)) => {
                                tracing::trace!(
                                    "Received transaction from peer {}",
                                    hex::encode(&peer_dilithium_pk[..8])
                                );
                                if let Err(e) = consensus
                                    .handle_incoming_tx(
                                        streamed.tx,
                                        streamed.validator_sig,
                                        streamed.validator_pubkey,
                                    )
                                    .await
                                {
                                    tracing::debug!("Dropped streamed TX: {}", e);
                                }
                            }
                            Ok(P2PMessage::BlockHeader(header)) => {
                                tracing::debug!(
                                    "Received block header {} from inbound peer {}",
                                    header.height,
                                    hex::encode(&peer_dilithium_pk[..8])
                                );
                                {
                                    let c = consensus_clone.clone();
                                    let pk = peer_dilithium_pk.clone();
                                    tokio::spawn(async move {
                                        c.handle_incoming_header(header, pk).await;
                                    });
                                }
                            }
                            Ok(P2PMessage::BatchRequest { batch_hash }) => {
                                if let Some(cached) = consensus.get_cached_batch(&batch_hash).await
                                {
                                    let msg = P2PMessage::BatchResponse {
                                        batch_hash,
                                        batch: cached.batch,
                                    };
                                    if let Ok(data) = postcard::to_allocvec(&msg) {
                                        if let Some(sender) = consensus
                                            .peer_senders
                                            .read()
                                            .await
                                            .get(&peer_dilithium_pk)
                                        {
                                            let _ = sender.try_send(data);
                                        }
                                    }
                                }
                            }
                            Ok(P2PMessage::BatchResponse { batch_hash, batch }) => {
                                consensus.handle_batch_response(batch_hash, batch).await;
                            }
                            Ok(P2PMessage::BatchProposal {
                                height,
                                parent_hash,
                                batch_hash,
                                batch,
                                state_root,
                                leader_pubkey,
                                leader_round,
                            }) => {
                                consensus
                                    .handle_batch_proposal(
                                        height,
                                        parent_hash,
                                        batch_hash,
                                        batch,
                                        state_root,
                                        leader_pubkey,
                                        leader_round,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::BatchCommitment {
                                height,
                                batch_hash,
                                validator_pubkey,
                                signature,
                            }) => {
                                consensus
                                    .handle_batch_commitment(
                                        height,
                                        batch_hash,
                                        validator_pubkey,
                                        signature,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::Prevote {
                                height,
                                round,
                                block_hash,
                                validator_pubkey,
                                signature,
                            }) => {
                                consensus
                                    .handle_prevote(
                                        height,
                                        round,
                                        block_hash,
                                        validator_pubkey,
                                        signature,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::Precommit {
                                height,
                                round,
                                block_hash,
                                validator_pubkey,
                                signature,
                            }) => {
                                consensus
                                    .handle_precommit(
                                        height,
                                        round,
                                        block_hash,
                                        validator_pubkey,
                                        signature,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::Attestation(attestation)) => {
                                if consensus.verify_attestation(&attestation).await {
                                    tracing::info!(
                                        "📥 [H1] Received attestation for {}",
                                        hex::encode(&attestation.batch_hash[..8])
                                    );
                                    // Add to local attestation pipeline via gossip
                                    if let Some(ref pipeline) = consensus.attestation_pipeline {
                                        let batch_hash = attestation.batch_hash;
                                        pipeline.add_attestation(batch_hash, attestation).await;
                                    }
                                }
                            }
                            Ok(P2PMessage::HeightAnnouncement(announcement)) => {
                                if let Err(e) =
                                    consensus.handle_height_announcement(announcement).await
                                {
                                    tracing::warn!("Invalid height announcement: {}", e);
                                }
                            }
                            Ok(P2PMessage::SyncRequest {
                                from_height,
                                to_height,
                                anchor_height,
                                anchor_hash,
                            }) => {
                                // Peer is requesting blocks for sync
                                match consensus
                                    .handle_sync_request(
                                        from_height,
                                        to_height,
                                        anchor_height,
                                        anchor_hash,
                                    )
                                    .await
                                {
                                    Ok(blocks) => {
                                        tracing::info!(
                                            " Serving SyncResponse for request {}-{} with {} blocks",
                                            from_height,
                                            to_height,
                                            blocks.len()
                                        );
                                        let msg = P2PMessage::SyncResponse {
                                            request_from_height: from_height,
                                            request_to_height: to_height,
                                            request_anchor_height: anchor_height,
                                            request_anchor_hash: anchor_hash,
                                            responder_height: consensus.get_finalized_height(),
                                            blocks,
                                        };
                                        if let Ok(data) = postcard::to_allocvec(&msg) {
                                            if let Some(sender) = consensus
                                                .peer_senders
                                                .read()
                                                .await
                                                .get(&peer_dilithium_pk)
                                            {
                                                let _ = sender.try_send(data);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            " Failed to serve sync request {}-{}: {}",
                                            from_height,
                                            to_height,
                                            e
                                        );
                                    }
                                }
                            }
                            Ok(P2PMessage::SyncResponse {
                                request_from_height,
                                request_to_height,
                                request_anchor_height,
                                request_anchor_hash,
                                responder_height,
                                blocks,
                            }) => {
                                consensus
                                    .handle_sync_response_from_peer(
                                        peer_dilithium_pk.clone(),
                                        request_from_height,
                                        request_to_height,
                                        request_anchor_height,
                                        request_anchor_hash,
                                        responder_height,
                                        blocks,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::SnapshotRequest { min_height }) => {
                                if let Some(ref storage) = consensus.storage {
                                    let stored_snapshot = storage
                                        .load_latest_snapshot()
                                        .ok()
                                        .flatten()
                                        .filter(|s| s.height >= min_height);

                                    let snapshot = match stored_snapshot {
                                        Some(snapshot) => Some(snapshot),
                                        None => {
                                            let finalized_height = consensus.get_finalized_height();
                                            if finalized_height >= min_height {
                                                tracing::info!(
                                                    " Generating on-demand snapshot at finalized height {} for request min_height {}",
                                                    finalized_height,
                                                    min_height
                                                );
                                                Some(crate::StateSnapshot::from_state(
                                                    finalized_height,
                                                    &consensus.state_snapshot(),
                                                ))
                                            } else {
                                                tracing::warn!(
                                                    " No local snapshot satisfies request min_height {} and finalized height is {}",
                                                    min_height,
                                                    finalized_height
                                                );
                                                None
                                            }
                                        }
                                    };

                                    if let Some(snapshot) = snapshot {
                                        let height = snapshot.height;
                                        let tip_header =
                                            consensus.storage.as_ref().and_then(|storage| {
                                                storage
                                                    .load_batch_header_by_height(height)
                                                    .ok()
                                                    .flatten()
                                            });
                                        match postcard::to_allocvec(&P2PMessage::SnapshotResponse {
                                            snapshot: Box::new(snapshot),
                                            tip_header,
                                        }) {
                                            Ok(data) => {
                                                if let Some(sender) = consensus
                                                    .peer_senders
                                                    .read()
                                                    .await
                                                    .get(&peer_dilithium_pk)
                                                {
                                                    let _ = sender.try_send(data);
                                                    tracing::info!(
                                                        " Served snapshot at height {} for request min_height {}",
                                                        height,
                                                        min_height
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    " Failed to serialize snapshot response: {}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(P2PMessage::SnapshotResponse {
                                snapshot,
                                tip_header,
                            }) => {
                                consensus.handle_peer_snapshot(*snapshot, tip_header).await;
                            }
                            Ok(P2PMessage::Ping) => {
                                let data =
                                    postcard::to_allocvec(&P2PMessage::Pong).unwrap_or_default();
                                if let Some(sender) =
                                    consensus.peer_senders.read().await.get(&peer_dilithium_pk)
                                {
                                    let _ = sender.try_send(data);
                                }
                            }
                            Ok(P2PMessage::Pong) => {} // keepalive ack
                            Ok(P2PMessage::CompactBatchProposal {
                                height,
                                parent_hash,
                                batch_hash,
                                tx_hashes,
                                state_root,
                                leader_pubkey,
                                leader_round,
                            }) => {
                                consensus
                                    .handle_compact_batch_proposal(
                                        peer_dilithium_pk.clone(),
                                        height,
                                        parent_hash,
                                        batch_hash,
                                        tx_hashes,
                                        state_root,
                                        leader_pubkey,
                                        leader_round,
                                    )
                                    .await;
                            }
                            Err(e) => tracing::debug!("Failed to deserialize: {}", e),
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Connection closed: {}", e);
                        break;
                    }
                }
            }

            // Cleanup
            consensus.sessions.write().await.remove(&peer_dilithium_pk);
            consensus
                .peer_senders
                .write()
                .await
                .remove(&peer_dilithium_pk);
            tracing::info!(
                " Peer disconnected: {}",
                hex::encode(&peer_dilithium_pk[..8])
            );
        });
    }

    /// Get batch size
    pub async fn batch_len(&self) -> usize {
        self.batch.read().await.len()
    }

    /// Get known peers from discovery
    pub async fn get_known_peers(&self) -> Vec<String> {
        self.peer_discovery.get_peers().await
    }

    /// Handle incoming block header from leader
    async fn handle_incoming_header(&self, header: crate::BatchHeader, from_peer: Vec<u8>) {
        // Check if we already have this block
        {
            let blockchain = self.blockchain.read().await;
            if blockchain.get_header(&header.batch_hash).is_some() {
                tracing::debug!(" Already have block {}, ignoring", header.height);
                return;
            }
        }

        let my_height = self.get_current_height();
        if header.height <= my_height {
            tracing::debug!(
                "Ignoring stale/competing header at height {} (current height: {}, batch {})",
                header.height,
                my_height,
                hex::encode(&header.batch_hash[..8])
            );
            return;
        }

        // Check if we're missing parent blocks - if so, request them first
        if header.height > my_height + 1 {
            tracing::warn!(
                "  Received header {} but missing {} blocks (my height: {})",
                header.height,
                header.height - my_height - 1,
                my_height
            );

            // Request all missing blocks from this peer
            let from_height = my_height + 1;
            let to_height = header.height;
            tracing::info!(
                " Requesting missing blocks {}-{} from peer",
                from_height,
                to_height
            );

            if let Err(e) = self.request_blocks_from_peer(from_height, to_height).await {
                tracing::warn!(" Failed to request missing blocks: {}", e);
            }

            // Cache this header for later processing after we catch up
            let mut pending = self.pending_headers.write().await;
            pending.insert(
                header.batch_hash,
                PendingHeaderEntry {
                    header: header.clone(),
                    received_at: Instant::now(),
                },
            );
            return;
        }

        self.pending_batches
            .write()
            .await
            .remove(&header.batch_hash);

        if let Some(cached) = self.get_cached_batch(&header.batch_hash).await {
            self.process_header_with_batch(header, cached.batch).await;
            return;
        }

        // Cache header until batch arrives
        let mut pending = self.pending_headers.write().await;
        let max_pending = gp::get_usize(gp::PARAM_STREAMING_MAX_PENDING_HEADERS);
        if pending.len() >= max_pending {
            if let Some((oldest_hash, _)) = pending
                .iter()
                .min_by_key(|(_, entry)| entry.received_at)
                .map(|(hash, entry)| (*hash, entry.received_at))
            {
                pending.remove(&oldest_hash);
            }
        }
        let is_new = pending
            .insert(
                header.batch_hash,
                PendingHeaderEntry {
                    header: header.clone(),
                    received_at: Instant::now(),
                },
            )
            .is_none();
        drop(pending);

        if is_new {
            if let Err(e) = self
                .request_batch_from_peer(&from_peer, header.batch_hash)
                .await
            {
                tracing::warn!(" Failed to request batch: {}", e);
            }
        }
    }

    async fn process_header_with_batch(&self, header: crate::BatchHeader, batch: Vec<Transaction>) {
        self.pending_batches
            .write()
            .await
            .remove(&header.batch_hash);
        // Cancel attestation collection for any other batch at this height.
        // This unblocks the batch_timer_task loop on non-leaders that computed
        // a different batch_hash (different mempool snapshot) for the same height.
        if let Some(ref pipeline) = self.attestation_pipeline {
            pipeline.cancel_all_except(Some(header.batch_hash)).await;
        }
        match self.validate_sync_header_with_batch(&header, &batch).await {
            Ok(()) => {
                let state = self.state.load();
                let batch_result = match self.execute_batch_with_results(&state, &batch).await {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::warn!("Verified header execution failed: {}", e);
                        return;
                    }
                };
                let new_state = batch_result.state.clone();
                let computed_root = self.compute_state_root(&new_state);
                if computed_root != header.state_root {
                    tracing::warn!(
                        "Rejecting leader header at height {}: local state root {} does not match header {}",
                        header.height,
                        hex::encode(computed_root),
                        hex::encode(header.state_root)
                    );
                    if let Err(e) = self
                        .request_blocks_from_peer(header.height, header.height)
                        .await
                    {
                        tracing::warn!(
                            " Failed to request recovery block {}: {}",
                            header.height,
                            e
                        );
                    }
                    return;
                }
                tracing::info!(" Leader header verified for height {}", header.height);

                let active_validators = new_state.staking.get_active_validators();
                let total_stake: u64 = active_validators.values().sum();

                let fork_switch = {
                    let mut blockchain = self.blockchain.write().await;
                    if let Err(e) = blockchain.add_header(header.clone()) {
                        tracing::debug!("Failed to add header: {}", e);
                        return;
                    }
                    // Use real fork choice — not seed_canonical_tip — so the
                    // attestation-anchored rule runs and fork switches are detected.
                    match blockchain.set_canonical_tip(header.batch_hash, total_stake) {
                        Ok((switched, Some(old_tip))) if switched => {
                            if blockchain
                                .get_canonical_tip()
                                .map(|tip| tip.batch_hash != header.batch_hash)
                                .unwrap_or(true)
                            {
                                tracing::debug!(
                                    "Header at height {} lost fork choice; leaving live state unchanged",
                                    header.height
                                );
                                return;
                            }
                            Some((old_tip, header.batch_hash))
                        }
                        Ok(_) => {
                            if blockchain
                                .get_canonical_tip()
                                .map(|tip| tip.batch_hash != header.batch_hash)
                                .unwrap_or(true)
                            {
                                tracing::debug!(
                                    "Header at height {} lost fork choice; leaving live state unchanged",
                                    header.height
                                );
                                return;
                            }
                            None
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Fork choice rejected block at height {}: {}",
                                header.height,
                                e
                            );
                            return;
                        }
                    }
                };

                if let Some((old_tip, new_tip)) = fork_switch {
                    if let Err(e) = self.handle_fork_switch(old_tip, new_tip).await {
                        tracing::error!("Fork switch failed: {}", e);
                        return;
                    }
                }

                // Apply state only after fork choice has accepted the header as
                // canonical. A losing fork must never overwrite the live state.
                self.state.store(Arc::new(new_state.clone()));
                self.set_current_height_monotonic(header.height);

                self.prune_committed_from_mempool(&batch, batch_result.failed.as_slice())
                    .await;
                self.prune_ineligible_from_mempool(&new_state).await;

                tracing::info!(" Received block {} from leader", header.height);

                // Send attestation immediately upon receiving a valid leader header.
                // This is the primary attestation path — don't wait for the batch timer.
                let am_the_leader = header.leader_pubkey == self.validator_pubkey;
                if self.is_active_attester().await && !am_the_leader {
                    let state_root = self.compute_state_root(&new_state);
                    self.send_attestation(
                        header.height,
                        header.leader_round,
                        header.batch_hash,
                        state_root,
                    )
                    .await;
                    tracing::debug!(" Attested to block {} from leader", header.height);
                }

                // Reset skip round — block received means leader succeeded.
                self.leader_skip_rounds
                    .write()
                    .await
                    .remove(&header.batch_hash);
                // Advance finalized height.
                self.advance_finalized_height(header.height).await;

                // ── Inline BFT: Prevote + Precommit (non-leader) ─────────────
                {
                    let h = header.height;
                    let batch_hash = header.batch_hash;
                    let round = {
                        let mut rs = self.bft_round.write().await;
                        if rs.height != h {
                            *rs = crate::round_state::RoundState::new(h);
                        }
                        rs.proposal = Some(batch_hash);
                        rs.step = crate::round_state::Step::Prevote;
                        rs.round = 0;
                        rs.prevotes.clear();
                        rs.precommits.clear();
                        rs.round
                    };
                    if self.is_active_attester().await && !am_the_leader {
                        self.broadcast_prevote(h, round, Some(batch_hash)).await;
                        self.broadcast_precommit(h, round, Some(batch_hash)).await;
                    }
                }
                tracing::info!(" Block {} received and finalized", header.height);

                if let Some(ref storage) = self.storage {
                    let storage = storage.clone();
                    let header_clone = header.clone();
                    let batch_clone = batch.clone();
                    let name_registry =
                        Self::active_name_registry(&new_state, header_clone.timestamp);
                    let results_clone = Self::batch_results(batch.len(), &batch_result.failed);
                    tokio::spawn(async move {
                        if let Err(e) = storage.save_block(
                            &header_clone,
                            &batch_clone,
                            &results_clone,
                            &name_registry,
                        ) {
                            tracing::error!("Failed to save block: {}", e);
                        }
                    });
                }

                self.maybe_persist_snapshot(header.height, &new_state);
            }
            Err(slash_proof) => {
                tracing::warn!(
                    " State root mismatch at height {} — skipping slash on devnet",
                    header.height
                );
                tracing::warn!("   Leader: {}", hex::encode(&header.leader_pubkey[..8]));
                tracing::warn!("   Proof: {:?}", slash_proof);

                tracing::warn!(
                    " Rejected malicious block from {}",
                    hex::encode(&header.leader_pubkey[..8])
                );
            }
        }
    }

    /// Verify leader's block header (called by non-leaders)
    fn verify_header_leader(&self, header: &crate::BatchHeader) -> Result<(), crate::SlashProof> {
        // Use the round from the header itself — local skip-round counters diverge across nodes
        let expected_leader = self.select_leader_hash_round(
            &header.parent_hash,
            header.height,
            &header.batch_hash,
            header.leader_round as u32,
        );
        if header.leader_pubkey != expected_leader {
            return Err(crate::SlashProof::InvalidLeader {
                height: header.height,
                expected_pubkey: expected_leader,
                got_pubkey: header.leader_pubkey.clone(),
                leader_signature: header.leader_signature.clone(),
            });
        }

        let pk_bytes: [u8; 1952] = header.leader_pubkey.as_slice().try_into().map_err(|_| {
            crate::SlashProof::InvalidLeaderSignature {
                height: header.height,
                leader_pubkey: header.leader_pubkey.clone(),
                leader_signature: header.leader_signature.clone(),
            }
        })?;
        let pk = DilithiumPublicKey::try_from_bytes(pk_bytes).map_err(|_| {
            crate::SlashProof::InvalidLeaderSignature {
                height: header.height,
                leader_pubkey: header.leader_pubkey.clone(),
                leader_signature: header.leader_signature.clone(),
            }
        })?;
        let sig_bytes: [u8; 3309] =
            header.leader_signature.as_slice().try_into().map_err(|_| {
                crate::SlashProof::InvalidLeaderSignature {
                    height: header.height,
                    leader_pubkey: header.leader_pubkey.clone(),
                    leader_signature: header.leader_signature.clone(),
                }
            })?;

        if !pk.verify(&header.batch_hash, &sig_bytes, BATCH_SIGN_CONTEXT) {
            return Err(crate::SlashProof::InvalidLeaderSignature {
                height: header.height,
                leader_pubkey: header.leader_pubkey.clone(),
                leader_signature: header.leader_signature.clone(),
            });
        }

        Ok(())
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs()
    }

    fn active_name_registry(
        state: &truthlinked_state::pq_execution::State,
        now: u64,
    ) -> std::collections::HashMap<String, [u8; 32]> {
        state
            .name_registry
            .iter()
            .filter(|(_, reg)| now < reg.expires_at)
            .map(|(name, reg)| (name.clone(), reg.target))
            .collect()
    }

    fn attestation_message(
        height: u64,
        round: u64,
        batch_hash: &[u8; 32],
        state_root: &[u8; 32],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(16 + 32 + 32);
        msg.extend_from_slice(&height.to_le_bytes());
        msg.extend_from_slice(&round.to_le_bytes());
        msg.extend_from_slice(batch_hash);
        msg.extend_from_slice(state_root);
        msg
    }

    fn stake_map_from_state(
        state: &truthlinked_state::State,
    ) -> std::collections::HashMap<Vec<u8>, u64> {
        let active = state.staking.get_active_validators();
        let mut stake_map = std::collections::HashMap::with_capacity(active.len());
        for (pk, stake) in active.iter() {
            stake_map.insert(pk.clone(), *stake);
        }
        stake_map
    }

    #[allow(dead_code)]
    fn required_stake_for_attesters(
        stake_map: &std::collections::HashMap<Vec<u8>, u64>,
        active_attesters: &[Vec<u8>],
    ) -> u64 {
        let mut total = 0u64;
        for pk in active_attesters {
            if let Some(stake) = stake_map.get(pk) {
                total = total.saturating_add(*stake);
            }
        }
        if total == 0 {
            return 0;
        }
        total.saturating_mul(2) / 3
    }

    fn required_non_leader_stake_for_attesters(
        stake_map: &std::collections::HashMap<Vec<u8>, u64>,
        active_attesters: &[Vec<u8>],
        leader_pubkey: &[u8],
    ) -> u64 {
        let mut total = 0u64;
        for pk in active_attesters {
            if pk.as_slice() == leader_pubkey {
                continue;
            }
            if let Some(stake) = stake_map.get(pk) {
                total = total.saturating_add(*stake);
            }
        }
        if total == 0 {
            return 0;
        }
        let non_leader_count = active_attesters
            .iter()
            .filter(|pk| pk.as_slice() != leader_pubkey)
            .filter(|pk| stake_map.contains_key(*pk))
            .count();
        crate::attestation_pipeline::AttestationPipeline::effective_non_leader_quorum_required(
            total,
            non_leader_count,
        )
    }

    /// Returns the subset of the active validator set that is live at this node's current tip.
    ///
    /// A validator is live only if it is not known to be far behind by signed height
    /// announcements and it has either attested recently or the chain is still inside
    /// the startup liveness window. This deliberately does not rely on attestation
    /// gossip alone: a lagging validator can still gossip attestations for batches it
    /// cannot finalize, so peer height is the stronger liveness signal.
    async fn live_attesters(
        &self,
        active_attesters: &[Vec<u8>],
        current_height: u64,
    ) -> Vec<Vec<u8>> {
        const LIVENESS_WINDOW: u64 = 10; // blocks
                                         // A validator must be at the parent height to attest the next block.
                                         // A two-block lag falsely keeps stalled validators in the live quorum set,
                                         // making the leader wait for attestations they cannot produce.
        const HEIGHT_LAG_TOLERANCE: u64 = 1;

        let last_attested = self.validator_last_attested.read().await;
        let sync_manager = self.sync_manager.read().await;

        active_attesters
            .iter()
            .filter(|pk| {
                if pk.as_slice() == self.validator_pubkey.as_slice() {
                    return true;
                }

                if let Some(info) = sync_manager.peer_heights.get(*pk) {
                    if info.height.saturating_add(HEIGHT_LAG_TOLERANCE) < current_height {
                        tracing::debug!(
                            "Validator {} inactive by height gossip: peer_height={}, current_height={}",
                            hex::encode(&pk[..8]),
                            info.height,
                            current_height
                        );
                    }
                }

                last_attested
                    .get(*pk)
                    .map(|&h| current_height.saturating_sub(h) <= LIVENESS_WINDOW)
                    .unwrap_or(current_height <= LIVENESS_WINDOW)
            })
            .cloned()
            .collect()
    }

    /// Record that a validator attested at a given height.
    async fn record_attestation(&self, validator_pk: &[u8], height: u64) {
        let mut map = self.validator_last_attested.write().await;
        let entry = map.entry(validator_pk.to_vec()).or_insert(0);
        if height > *entry {
            *entry = height;
        }
    }

    #[allow(dead_code)]
    fn attested_stake(
        attestations: &[Attestation],
        stake_map: &std::collections::HashMap<Vec<u8>, u64>,
        expected_state_root: [u8; 32],
    ) -> u64 {
        let mut total = 0u64;
        for att in attestations {
            if att.state_root != expected_state_root {
                continue;
            }
            if let Some(stake) = stake_map.get(&att.validator_pubkey) {
                total = total.saturating_add(*stake);
            }
        }
        total
    }

    fn attesters_for_header(
        state: &truthlinked_state::State,
        _header: &crate::BatchHeader,
    ) -> Vec<Vec<u8>> {
        state
            .staking
            .get_active_validators()
            .keys()
            .cloned()
            .collect()
    }

    #[allow(dead_code)]
    fn compute_attesters_for_epoch(
        mut validators: Vec<Vec<u8>>,
        _epoch: u64,
        _max_size: usize,
    ) -> Vec<Vec<u8>> {
        validators.sort();
        validators
    }

    fn verify_attestation_signature(attestation: &Attestation) -> bool {
        let pk_bytes: [u8; 1952] = match attestation.validator_pubkey.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_bytes: [u8; 3309] = match attestation.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let pk = match DilithiumPublicKey::try_from_bytes(pk_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let message = Self::attestation_message(
            attestation.height,
            attestation.round,
            &attestation.batch_hash,
            &attestation.state_root,
        );
        pk.verify(&message, &sig_bytes, ATTESTATION_CONTEXT)
    }

    fn verify_attestation_set(
        &self,
        header: &crate::BatchHeader,
        active_attesters: &[Vec<u8>],
        stake_map: &std::collections::HashMap<Vec<u8>, u64>,
        required_stake: u64,
    ) -> Result<(), String> {
        let cert = &header.finality_certificate;
        if cert.version != crate::blockchain::PqFinalityCertificate::VERSION {
            return Err("Unsupported PQ finality certificate version".to_string());
        }
        if cert.height != header.height
            || cert.round != header.leader_round
            || cert.batch_hash != header.batch_hash
            || cert.state_root != header.state_root
        {
            return Err("PQ finality certificate does not match header".to_string());
        }

        let leader_pk = &header.leader_pubkey;
        if required_stake == 0 {
            let solo_leader_attester_set = active_attesters.len() == 1
                && active_attesters
                    .first()
                    .map(|pk| pk.as_slice() == leader_pk.as_slice())
                    .unwrap_or(false);
            if solo_leader_attester_set && cert.signer_count() == 0 && cert.signed_stake == 0 {
                return Ok(());
            }
            return Err("No non-leader stake for quorum".to_string());
        }

        cert.validate_compact_metadata(active_attesters, stake_map, leader_pk, required_stake)?;

        let mut canonical_attesters = active_attesters.to_vec();
        canonical_attesters.sort();
        canonical_attesters.dedup();

        // Live block gossip carries compact certificates: bitmap, signed stake, and the
        // signature root committed by the header hash. Sync and recovery keep strict
        // verification when full PQ signature blobs are present.
        if cert.signatures.is_empty() {
            return Ok(());
        }

        if cert.signature_root
            != crate::blockchain::PqFinalityCertificate::signature_root_for(&cert.signatures)
        {
            return Err("PQ finality certificate signature root mismatch".to_string());
        }

        let mut seen = std::collections::HashSet::new();
        let mut total = 0u64;
        for sig in &cert.signatures {
            let idx = sig.validator_index as usize;
            if idx >= canonical_attesters.len() {
                return Err("PQ finality certificate signer index out of range".to_string());
            }
            if canonical_attesters[idx] != sig.validator_pubkey {
                return Err("PQ finality certificate signer index mismatch".to_string());
            }
            let byte = cert.signer_bitmap[idx / 8];
            if (byte & (1u8 << (idx % 8))) == 0 {
                return Err("PQ finality certificate signer missing from bitmap".to_string());
            }
            if !seen.insert(sig.validator_pubkey.clone()) {
                return Err("Duplicate PQ finality certificate signer".to_string());
            }
            let att = Attestation {
                height: cert.height,
                round: cert.round,
                batch_hash: cert.batch_hash,
                state_root: cert.state_root,
                validator_pubkey: sig.validator_pubkey.clone(),
                signature: sig.signature.clone(),
            };
            if !Self::verify_attestation_signature(&att) {
                return Err("Invalid PQ finality certificate signature".to_string());
            }
            if sig.validator_pubkey == *leader_pk {
                continue;
            }
            total =
                total.saturating_add(stake_map.get(&sig.validator_pubkey).copied().unwrap_or(0));
        }
        if total != cert.signed_stake {
            return Err(format!(
                "PQ finality certificate signed stake mismatch: computed {}, header {}",
                total, cert.signed_stake
            ));
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn sync_lenient_quorum_enabled() -> bool {
        if std::env::var("TRUTHLINKED_SYNC_LENIENT").ok().as_deref() == Some("1") {
            tracing::warn!("TRUTHLINKED_SYNC_LENIENT is ignored for canonical consensus safety");
        }
        false
    }
    fn verify_historical_sync_attestation_set(
        &self,
        header: &crate::BatchHeader,
        active_attesters: &[Vec<u8>],
        stake_map: &std::collections::HashMap<Vec<u8>, u64>,
        required_stake: u64,
    ) -> Result<(), String> {
        self.verify_attestation_set(header, active_attesters, stake_map, required_stake)
    }

    /// Connect to peer validator (initiator side)
    pub async fn connect_to_peer(
        self: &Arc<Self>,
        peer_addr: &str,
        peer_dilithium_pk: Vec<u8>,
    ) -> Result<(), String> {
        let peer_addr = peer_addr.to_string();
        let mut stream = TcpStream::connect(&peer_addr)
            .await
            .map_err(|e| format!("Connection failed: {}", e))?;
        truthlinked_net::tcp_config::configure(&stream);

        // Perform PQ handshake (initiator side)
        let (session, authenticated_pk) = self
            .handshake
            .handshake_initiator(&mut stream)
            .await
            .map_err(|e| format!("Handshake failed: {}", e))?;

        // Verify authenticated peer matches expected
        if authenticated_pk != peer_dilithium_pk {
            return Err("Peer identity mismatch".to_string());
        }

        tracing::info!(
            " Connected to validator: {}",
            hex::encode(&peer_dilithium_pk[..8])
        );

        // Add to peer discovery with metadata
        let peer_info = truthlinked_net::discovery::PeerInfo {
            pubkey: peer_dilithium_pk.clone(),
            addresses: vec![peer_addr.to_string()],
            height: 0, // Will be updated via gossip
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        self.peer_discovery
            .add_peer(peer_addr.to_string(), peer_info)
            .await;

        // Store session
        self.sessions
            .write()
            .await
            .insert(peer_dilithium_pk.clone(), session.clone());

        // Create channel for outgoing messages
        let (tx, mut rx) = tokio::sync::mpsc::channel(OUTBOUND_QUEUE_CAP);
        self.peer_senders
            .write()
            .await
            .insert(peer_dilithium_pk.clone(), tx);
        tracing::info!(
            "OK Added outbound peer {} to senders (total: {})",
            hex::encode(&peer_dilithium_pk[..8]),
            self.peer_senders.read().await.len()
        );

        // Heartbeat: send Ping every 5s to keep connection alive
        {
            let hb_senders = self.peer_senders.clone();
            let hb_pk = peer_dilithium_pk.clone();
            tokio::spawn(async move {
                let ping = postcard::to_allocvec(&P2PMessage::Ping).unwrap_or_default();
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    let senders = hb_senders.read().await;
                    match senders.get(&hb_pk) {
                        Some(s) if s.try_send(ping.clone()).is_ok() => {}
                        _ => break,
                    }
                }
            });
        }
        // Split stream for bidirectional communication
        let (read_half, write_half) = tokio::io::split(stream);
        let mut read_stream = PQStream::new(read_half, session.clone());
        let mut write_stream = PQStream::new(write_half, session.clone());

        // Spawn writer task
        let peer_pk_clone = peer_dilithium_pk.clone();
        let consensus_for_writer = self.clone();
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if let Err(e) = write_stream.write_encrypted(&data).await {
                    tracing::error!(
                        "Failed to send to {}: {}",
                        hex::encode(&peer_pk_clone[..8]),
                        e
                    );
                    break;
                }
            }
            // Remove dead sender so broadcast_attestation stops trying this peer
            consensus_for_writer
                .peer_senders
                .write()
                .await
                .remove(&peer_pk_clone);
        });

        // Handle incoming messages
        let consensus = self.clone();
        let consensus_clone = self.clone();
        tokio::spawn(async move {
            loop {
                match read_stream.read_encrypted().await {
                    Ok(data) => {
                        match postcard::from_bytes::<P2PMessage>(&data) {
                            Ok(P2PMessage::Transaction(streamed)) => {
                                tracing::trace!("Received transaction from outbound peer");
                                if let Err(e) = consensus
                                    .handle_incoming_tx(
                                        streamed.tx,
                                        streamed.validator_sig,
                                        streamed.validator_pubkey,
                                    )
                                    .await
                                {
                                    tracing::debug!("Dropped streamed TX: {}", e);
                                }
                            }
                            Ok(P2PMessage::BlockHeader(header)) => {
                                tracing::debug!(
                                    "Received block header {} from outbound peer",
                                    header.height
                                );
                                {
                                    let c = consensus_clone.clone();
                                    let pk = peer_dilithium_pk.clone();
                                    tokio::spawn(async move {
                                        c.handle_incoming_header(header, pk).await;
                                    });
                                }
                            }
                            Ok(P2PMessage::BatchRequest { batch_hash }) => {
                                if let Some(cached) = consensus.get_cached_batch(&batch_hash).await
                                {
                                    let msg = P2PMessage::BatchResponse {
                                        batch_hash,
                                        batch: cached.batch,
                                    };
                                    if let Ok(data) = postcard::to_allocvec(&msg) {
                                        if let Some(sender) = consensus
                                            .peer_senders
                                            .read()
                                            .await
                                            .get(&peer_dilithium_pk)
                                        {
                                            let _ = sender.try_send(data);
                                        }
                                    }
                                }
                            }
                            Ok(P2PMessage::BatchResponse { batch_hash, batch }) => {
                                consensus.handle_batch_response(batch_hash, batch).await;
                            }
                            Ok(P2PMessage::BatchProposal {
                                height,
                                parent_hash,
                                batch_hash,
                                batch,
                                state_root,
                                leader_pubkey,
                                leader_round,
                            }) => {
                                consensus
                                    .handle_batch_proposal(
                                        height,
                                        parent_hash,
                                        batch_hash,
                                        batch,
                                        state_root,
                                        leader_pubkey,
                                        leader_round,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::CompactBatchProposal {
                                height,
                                parent_hash,
                                batch_hash,
                                tx_hashes,
                                state_root,
                                leader_pubkey,
                                leader_round,
                            }) => {
                                consensus
                                    .handle_compact_batch_proposal(
                                        peer_dilithium_pk.clone(),
                                        height,
                                        parent_hash,
                                        batch_hash,
                                        tx_hashes,
                                        state_root,
                                        leader_pubkey,
                                        leader_round,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::BatchCommitment {
                                height,
                                batch_hash,
                                validator_pubkey,
                                signature,
                            }) => {
                                consensus
                                    .handle_batch_commitment(
                                        height,
                                        batch_hash,
                                        validator_pubkey,
                                        signature,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::Prevote {
                                height,
                                round,
                                block_hash,
                                validator_pubkey,
                                signature,
                            }) => {
                                consensus
                                    .handle_prevote(
                                        height,
                                        round,
                                        block_hash,
                                        validator_pubkey,
                                        signature,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::Precommit {
                                height,
                                round,
                                block_hash,
                                validator_pubkey,
                                signature,
                            }) => {
                                consensus
                                    .handle_precommit(
                                        height,
                                        round,
                                        block_hash,
                                        validator_pubkey,
                                        signature,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::Attestation(attestation)) => {
                                if consensus.verify_attestation(&attestation).await {
                                    tracing::info!(
                                        "📥 [H2] Received attestation for {}",
                                        hex::encode(&attestation.batch_hash[..8])
                                    );
                                    // Add to local attestation pipeline via gossip
                                    if let Some(ref pipeline) = consensus.attestation_pipeline {
                                        let batch_hash = attestation.batch_hash;
                                        pipeline.add_attestation(batch_hash, attestation).await;
                                    }
                                }
                            }
                            Ok(P2PMessage::HeightAnnouncement(announcement)) => {
                                if let Err(e) =
                                    consensus.handle_height_announcement(announcement).await
                                {
                                    tracing::warn!("Invalid height announcement: {}", e);
                                }
                            }
                            Ok(P2PMessage::SyncRequest {
                                from_height,
                                to_height,
                                anchor_height,
                                anchor_hash,
                            }) => {
                                // Peer is requesting blocks for sync
                                match consensus
                                    .handle_sync_request(
                                        from_height,
                                        to_height,
                                        anchor_height,
                                        anchor_hash,
                                    )
                                    .await
                                {
                                    Ok(blocks) => {
                                        tracing::info!(
                                            " Serving SyncResponse for request {}-{} with {} blocks",
                                            from_height,
                                            to_height,
                                            blocks.len()
                                        );
                                        let msg = P2PMessage::SyncResponse {
                                            request_from_height: from_height,
                                            request_to_height: to_height,
                                            request_anchor_height: anchor_height,
                                            request_anchor_hash: anchor_hash,
                                            responder_height: consensus.get_finalized_height(),
                                            blocks,
                                        };
                                        if let Ok(data) = postcard::to_allocvec(&msg) {
                                            if let Some(sender) = consensus
                                                .peer_senders
                                                .read()
                                                .await
                                                .get(&peer_dilithium_pk)
                                            {
                                                let _ = sender.try_send(data);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            " Failed to serve sync request {}-{}: {}",
                                            from_height,
                                            to_height,
                                            e
                                        );
                                    }
                                }
                            }
                            Ok(P2PMessage::SyncResponse {
                                request_from_height,
                                request_to_height,
                                request_anchor_height,
                                request_anchor_hash,
                                responder_height,
                                blocks,
                            }) => {
                                consensus
                                    .handle_sync_response_from_peer(
                                        peer_dilithium_pk.clone(),
                                        request_from_height,
                                        request_to_height,
                                        request_anchor_height,
                                        request_anchor_hash,
                                        responder_height,
                                        blocks,
                                    )
                                    .await;
                            }
                            Ok(P2PMessage::SnapshotRequest { min_height }) => {
                                if let Some(ref storage) = consensus.storage {
                                    let stored_snapshot =
                                        storage.load_latest_snapshot().ok().flatten().filter(|s| {
                                            s.height >= min_height
                                                && s.compute_state_root() == s.state_root
                                        });

                                    let snapshot = match stored_snapshot {
                                        Some(snapshot) => Some(snapshot),
                                        None => {
                                            let finalized_height = consensus.get_finalized_height();
                                            if finalized_height >= min_height {
                                                tracing::info!(
                                                    " Generating on-demand snapshot at finalized height {} for request min_height {}",
                                                    finalized_height,
                                                    min_height
                                                );
                                                Some(crate::StateSnapshot::from_state(
                                                    finalized_height,
                                                    &consensus.state_snapshot(),
                                                ))
                                            } else {
                                                tracing::warn!(
                                                    " No local snapshot satisfies request min_height {} and finalized height is {}",
                                                    min_height,
                                                    finalized_height
                                                );
                                                None
                                            }
                                        }
                                    };

                                    if let Some(snapshot) = snapshot {
                                        let height = snapshot.height;
                                        let tip_header = consensus.storage.as_ref().and_then(|s| {
                                            s.load_batch_header_by_height(height).ok().flatten()
                                        });
                                        match postcard::to_allocvec(&P2PMessage::SnapshotResponse {
                                            snapshot: Box::new(snapshot),
                                            tip_header,
                                        }) {
                                            Ok(data) => {
                                                if let Some(sender) = consensus
                                                    .peer_senders
                                                    .read()
                                                    .await
                                                    .get(&peer_dilithium_pk)
                                                {
                                                    let _ = sender.try_send(data);
                                                    tracing::info!(
                                                        " Served snapshot at height {} for request min_height {}",
                                                        height,
                                                        min_height
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    " Failed to serialize snapshot response: {}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(P2PMessage::SnapshotResponse {
                                snapshot,
                                tip_header,
                            }) => {
                                consensus.handle_peer_snapshot(*snapshot, tip_header).await;
                            }
                            Ok(P2PMessage::Ping) => {
                                let data =
                                    postcard::to_allocvec(&P2PMessage::Pong).unwrap_or_default();
                                if let Some(sender) =
                                    consensus.peer_senders.read().await.get(&peer_dilithium_pk)
                                {
                                    let _ = sender.try_send(data);
                                }
                            }
                            Ok(P2PMessage::Pong) => {} // keepalive ack
                            Err(e) => tracing::debug!("Failed to deserialize: {}", e),
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Connection closed: {}", e);
                        break;
                    }
                }
            }

            // Cleanup
            consensus.sessions.write().await.remove(&peer_dilithium_pk);
            consensus
                .peer_senders
                .write()
                .await
                .remove(&peer_dilithium_pk);
            tracing::info!(
                " Outbound peer disconnected: {}",
                hex::encode(&peer_dilithium_pk[..8])
            );

            // Reconnect: use a dedicated OS thread to avoid Send constraint on connect_to_peer
            let reconnect_consensus = consensus.clone();
            let reconnect_pk = peer_dilithium_pk.clone();
            let reconnect_addr = peer_addr.clone();
            let rt = tokio::runtime::Handle::current();
            std::thread::spawn(move || {
                rt.block_on(async move {
                    let mut delay_ms = 1_000u64;
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        if reconnect_consensus.is_connected(&reconnect_pk).await {
                            break;
                        }
                        tracing::info!(" Reconnecting to {}", hex::encode(&reconnect_pk[..8]));
                        match reconnect_consensus
                            .connect_to_peer(&reconnect_addr, reconnect_pk.clone())
                            .await
                        {
                            Ok(_) => {
                                tracing::info!(
                                    " Reconnected to {}",
                                    hex::encode(&reconnect_pk[..8])
                                );
                                break;
                            }
                            Err(e) => {
                                tracing::warn!(" Reconnect failed: {}", e);
                                delay_ms = (delay_ms * 2).min(30_000);
                            }
                        }
                    }
                });
            });
        });

        Ok(())
    }

    #[allow(dead_code)]
    async fn reconnect_loop(self: &Arc<Self>, peer_addr: String, peer_pk: Vec<u8>) {
        let mut delay_ms = 1_000u64;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            if self.is_connected(&peer_pk).await {
                break;
            }
            tracing::info!(" Reconnecting to {}", hex::encode(&peer_pk[..8]));
            match self.connect_to_peer(&peer_addr, peer_pk.clone()).await {
                Ok(_) => {
                    tracing::info!(" Reconnected to {}", hex::encode(&peer_pk[..8]));
                    break;
                }
                Err(e) => {
                    tracing::warn!(" Reconnect failed: {}", e);
                    delay_ms = (delay_ms * 2).min(30_000);
                }
            }
        }
    }

    pub async fn is_connected(&self, pubkey: &[u8]) -> bool {
        self.peer_senders.read().await.contains_key(pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use truthlinked_core::constants::MIN_VALIDATOR_STAKE;

    #[tokio::test]
    async fn jailed_validators_are_excluded_from_active_attesters() {
        let kp_active = DualKeypair::generate();
        let kp_jailed = DualKeypair::generate();
        let active_pk = kp_active.dilithium_pk.clone().into_bytes().to_vec();
        let jailed_pk = kp_jailed.dilithium_pk.clone().into_bytes().to_vec();

        let mut state = truthlinked_state::pq_execution::State::genesis();
        state.staking.current_height = 10;
        state
            .staking
            .stake(active_pk.clone(), MIN_VALIDATOR_STAKE)
            .unwrap();
        state
            .staking
            .stake(jailed_pk.clone(), MIN_VALIDATOR_STAKE)
            .unwrap();
        if let Some(stake) = state.staking.validators.get_mut(&jailed_pk) {
            stake.jailed_until = Some(20);
        }

        let (consensus, _rx) =
            StreamingConsensus::new(kp_active, vec![active_pk.clone(), jailed_pk.clone()], state);

        consensus.refresh_active_attesters(1).await;
        let active_attesters = consensus.get_active_attesters().read().await.clone();

        assert!(active_attesters.contains(&active_pk));
        assert!(!active_attesters.contains(&jailed_pk));
    }

    fn test_header(height: u64, parent_hash: [u8; 32], batch_hash: [u8; 32]) -> crate::BatchHeader {
        crate::BatchHeader::new(
            height,
            parent_hash,
            batch_hash,
            [height as u8; 32],
            [height.saturating_add(1) as u8; 32],
            height,
            0,
            crate::blockchain::PqFinalityCertificate::empty(
                height,
                0,
                batch_hash,
                [height.saturating_add(1) as u8; 32],
            ),
            vec![1u8; 4],
            vec![2u8; 8],
            0,
        )
    }

    #[test]
    fn sync_response_shape_accepts_exact_contiguous_chain() {
        let h1 = test_header(1, [0u8; 32], [1u8; 32]);
        let h2 = test_header(2, h1.batch_hash, [2u8; 32]);
        validate_sync_response_shape(1, 2, 0, [0u8; 32], 2, &[h1, h2]).unwrap();
    }

    #[test]
    fn sync_response_shape_rejects_partial_range() {
        let h1 = test_header(1, [0u8; 32], [1u8; 32]);
        let err = validate_sync_response_shape(1, 2, 0, [0u8; 32], 2, &[h1]).unwrap_err();
        assert!(err.contains("partial sync response"));
    }

    #[test]
    fn sync_response_shape_rejects_reordered_or_gap_height() {
        let h1 = test_header(1, [0u8; 32], [1u8; 32]);
        let h3 = test_header(3, h1.batch_hash, [3u8; 32]);
        let err = validate_sync_response_shape(1, 3, 0, [0u8; 32], 3, &[h1, h3]).unwrap_err();
        assert!(err.contains("partial sync response") || err.contains("non-contiguous"));
    }

    #[test]
    fn sync_response_shape_rejects_wrong_parent_chain() {
        let h1 = test_header(1, [9u8; 32], [1u8; 32]);
        let err = validate_sync_response_shape(1, 1, 0, [0u8; 32], 1, &[h1]).unwrap_err();
        assert!(err.contains("does not extend expected"));
    }

    #[test]
    fn sync_response_shape_rejects_responder_height_lie() {
        let h1 = test_header(1, [0u8; 32], [1u8; 32]);
        let h2 = test_header(2, h1.batch_hash, [2u8; 32]);
        let err = validate_sync_response_shape(1, 2, 0, [0u8; 32], 1, &[h1, h2]).unwrap_err();
        assert!(err.contains("responder height"));
    }

    #[test]
    fn active_name_registry_filters_expired_entries() {
        let mut state = truthlinked_state::pq_execution::State::genesis();
        let name = "expired.tl".to_string();
        let owner = [7u8; 32];
        let target = [9u8; 32];

        state.name_registry.insert(
            name.clone(),
            truthlinked_governance::NameRegistration {
                name,
                owner,
                target,
                registered_at: 0,
                expires_at: 50,
                is_cell: false,
            },
        );

        let active = StreamingConsensus::active_name_registry(&state, 100);
        assert!(active.is_empty());
    }
}

impl StreamingConsensus {
    /// Get batch size

    pub async fn peer_catchup_task(self: Arc<Self>) {
        self.sync_detection_task().await;
    }
}

/// Ingress server - accepts authenticated validator connections
pub async fn start_ingress_server(
    port: u16,
    consensus: Arc<StreamingConsensus>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(" Ingress server listening on {} (PQ-secured)", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        truthlinked_net::tcp_config::configure(&stream);
        let consensus = consensus.clone();

        tokio::spawn(async move {
            tracing::info!(" New connection from {}", peer_addr);
            consensus.add_peer(stream).await;
        });
    }
}

impl StreamingConsensus {
    // ========== STATE MANAGEMENT ==========

    /// Get current state
    pub fn get_state(&self) -> Arc<arc_swap::ArcSwap<truthlinked_state::State>> {
        self.state.clone()
    }

    /// Restore state from storage
    pub fn restore_state(&self, state: truthlinked_state::State) {
        self.state.store(Arc::new(state));
    }

    /// Compute state root (Merkle root of all accounts)
    pub fn compute_state_root(&self, state: &truthlinked_state::State) -> [u8; 32] {
        crate::StateSnapshot::compute_state_root_from_state(state)
    }

    /// Compute Merkle root from leaves
    pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        if leaves.is_empty() {
            return Sha256::digest(b"").into();
        }

        let mut layer = leaves.to_vec();

        while layer.len() > 1 {
            let mut next_layer = Vec::new();

            for chunk in layer.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&[0x01]); // Node prefix
                hasher.update(&chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]); // Duplicate if odd
                }
                next_layer.push(hasher.finalize().into());
            }

            layer = next_layer;
        }

        layer[0]
    }

    /// Verify Merkle proof (for light clients)
    pub fn verify_merkle_proof(
        leaf: &[u8; 32],
        proof: &[[u8; 32]],
        index: usize,
        root: &[u8; 32],
    ) -> bool {
        use sha2::{Digest, Sha256};

        let mut hash = *leaf;
        let mut idx = index;

        for sibling in proof {
            let mut hasher = Sha256::new();
            hasher.update(&[0x01]);

            if idx % 2 == 0 {
                hasher.update(&hash);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&hash);
            }

            hash = hasher.finalize().into();
            idx /= 2;
        }

        &hash == root
    }

    // ========== BLOCKCHAIN MANAGEMENT ==========

    /// Get blockchain (for reading/writing headers)
    pub fn get_blockchain_arc(&self) -> Arc<tokio::sync::RwLock<crate::BlockChain>> {
        self.blockchain.clone()
    }

    /// Get this validator's Dilithium public key bytes.
    pub fn get_validator_pubkey(&self) -> Vec<u8> {
        self.validator_pubkey.clone()
    }

    /// Get a reference-counted handle to the validator keypair for signing.
    pub fn get_keypair(&self) -> Arc<DualKeypair> {
        self.keypair.clone()
    }

    /// Get current height
    pub fn get_current_height(&self) -> u64 {
        self.current_height
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get current finalized height
    pub fn get_finalized_height(&self) -> u64 {
        self.finalized_height
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Set finalized height monotonically.
    ///
    /// Live sync and snapshot recovery must never lower finalized height. A
    /// lower value can arrive from stale snapshots or old sync recovery data
    /// while this node is already at the live tip; accepting it makes the node
    /// replay old ranges and exposes the explorer/RPC to backward movement.
    pub fn set_finalized_height(&self, height: u64) {
        let old = self
            .finalized_height
            .fetch_max(height, std::sync::atomic::Ordering::SeqCst);
        if height < old {
            tracing::warn!(
                " Ignoring finalized height regression {} -> {}",
                old,
                height
            );
        }
    }

    /// Set current height monotonically and propagate the runtime global height.
    ///
    /// This prevents stale snapshot/recovery paths from moving a live node
    /// backward into an old sync range after it has reached the tip.
    pub fn set_current_height_monotonic(&self, height: u64) {
        let old = self
            .current_height
            .fetch_max(height, std::sync::atomic::Ordering::SeqCst);
        if height < old {
            tracing::warn!(" Ignoring current height regression {} -> {}", old, height);
            return;
        }
        truthlinked_state::set_current_height(height);
    }

    /// Reset local height during verified snapshot recovery.
    ///
    /// This is intentionally not used by normal block application. Recovery
    /// must be able to move a divergent node back to the last verified state
    /// checkpoint before replaying canonical blocks.
    fn set_recovery_height(&self, height: u64) {
        self.finalized_height
            .store(height, std::sync::atomic::Ordering::SeqCst);
        self.current_height
            .store(height, std::sync::atomic::Ordering::SeqCst);
        truthlinked_state::set_current_height(height);
    }

    /// Set finalized height AND propagate into BlockChain so its reorg guard fires.
    /// Always prefer this over `set_finalized_height` when a write lock on blockchain
    /// is not already held by the caller.
    pub async fn advance_finalized_height(&self, height: u64) {
        let old = self
            .finalized_height
            .fetch_max(height, std::sync::atomic::Ordering::SeqCst);
        if height > old {
            self.blockchain.write().await.finalize_height(height);
            truthlinked_state::metrics::global().set_finalized_height(height);
        }
    }

    /// Prune non-canonical pending batches (cleanup after finalization)
    pub async fn prune_non_canonical_pending(&self) {
        let blockchain = self.blockchain.read().await;
        let finalized_height = self.get_finalized_height();
        let canonical_tip = blockchain.get_canonical_tip();

        tracing::debug!(
            "Pruning non-canonical batches below height {} (canonical tip height: {})",
            finalized_height,
            canonical_tip.map(|h| h.height).unwrap_or(0)
        );

        // In streaming consensus, we do not keep pending batches
        // Batches are finalized after safety delay (see finalization_task)
        // This function is called to maintain consistency with blockchain pruning
    }

    /// Tendermint-style BFT consensus task (Phase 3).
    ///
    /// Runs one round per height:
    ///   Propose → Prevote → Precommit → Commit
    ///
    /// Safety: a validator only precommits after seeing 2/3+ prevotes for the
    /// same block_hash. It locks on that hash and carries the lock into future
    /// rounds, preventing two honest nodes from ever committing different blocks.
    ///
    /// Liveness: on timeout the round increments and a new leader is elected.
    pub async fn bft_consensus_task(self: Arc<Self>) {
        use tokio::time::Duration;

        // Timeout per step - governance-tunable via STREAMING_MAX_WAIT_MS.
        let step_ms = || gp::get_u64(gp::PARAM_STREAMING_MAX_WAIT_MS).max(200);

        loop {
            // ── Determine current height and reset round state ────────────────
            let height = self
                .finalized_height
                .load(std::sync::atomic::Ordering::SeqCst)
                + 1;
            {
                let mut rs = self.bft_round.write().await;
                if rs.height != height {
                    *rs = crate::round_state::RoundState::new(height);
                }
            }

            // ── PROPOSE step ──────────────────────────────────────────────────
            let propose_deadline =
                tokio::time::Instant::now() + Duration::from_millis(step_ms() * 3);
            loop {
                let proposal_hash = {
                    let bc = self.blockchain.read().await;
                    bc.get_batch_by_height(height).map(|h| h.batch_hash)
                };
                if let Some(hash) = proposal_hash {
                    let mut rs = self.bft_round.write().await;
                    rs.proposal = Some(hash);
                    rs.step = crate::round_state::Step::Prevote;
                    // A block exists - always vote at round 0.
                    // Round only matters for leader rotation when no block exists.
                    // Resetting here prevents unbounded round growth across restarts.
                    rs.round = 0;
                    rs.prevotes.clear();
                    rs.precommits.clear();
                    break;
                }
                if tokio::time::Instant::now() >= propose_deadline {
                    let mut rs = self.bft_round.write().await;
                    rs.step = crate::round_state::Step::Prevote;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            // ── PREVOTE step ──────────────────────────────────────────────────
            let (round, proposal) = {
                let rs = self.bft_round.read().await;
                (rs.round, rs.proposal)
            };

            // Lock rule: prevote for proposal only if allowed by lock.
            let prevote_hash = if let Some(ph) = proposal {
                let state = self.state.load();
                let stake_map = Self::stake_map_from_state(&state);
                let total: u64 = stake_map.values().sum();
                let threshold = (total * 2 / 3) + 1;
                let rs = self.bft_round.read().await;
                if rs.should_prevote(ph, threshold, &stake_map) {
                    Some(ph)
                } else {
                    None // locked on different block - prevote nil
                }
            } else {
                None // no proposal - prevote nil
            };

            if self.is_active_attester().await {
                self.broadcast_prevote(height, round, prevote_hash).await;
            }

            // Wait for 2/3+ prevotes
            let prevote_deadline =
                tokio::time::Instant::now() + Duration::from_millis(step_ms() * 4);
            let prevote_quorum = loop {
                if let Some(qh) = self.bft_prevote_quorum().await {
                    break Some(qh);
                }
                // Fast-path: already finalized via attestations.
                if self
                    .finalized_height
                    .load(std::sync::atomic::Ordering::SeqCst)
                    >= height
                {
                    break Some([0u8; 32]);
                }
                // Nil-vote fast path: if 2/3+ stake has nil-prevoted, no block will
                // reach quorum this round - skip immediately to next round.
                {
                    let state = self.state.load();
                    let stake_map = Self::stake_map_from_state(&state);
                    let total: u64 = stake_map.values().sum();
                    let threshold = (total * 2 / 3) + 1;
                    let rs = self.bft_round.read().await;
                    let nil_stake = rs.prevote_stake(rs.round, None, &stake_map);
                    if nil_stake >= threshold {
                        tracing::info!(
                            "BFT nil-prevote quorum at height {} round {} - fast view-change",
                            height,
                            rs.round
                        );
                        break None;
                    }
                }
                if tokio::time::Instant::now() >= prevote_deadline {
                    break None;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            };

            // ── PRECOMMIT step ────────────────────────────────────────────────
            let precommit_hash = prevote_quorum; // only precommit if we saw 2/3+ prevotes

            // Update lock
            if let Some(h) = precommit_hash {
                let mut rs = self.bft_round.write().await;
                rs.locked_block = Some(h);
                rs.locked_round = round as i64;
                rs.step = crate::round_state::Step::Precommit;
            }

            if self.is_active_attester().await {
                self.broadcast_precommit(height, round, precommit_hash)
                    .await;
            }

            // Wait for 2/3+ precommits
            let precommit_deadline =
                tokio::time::Instant::now() + Duration::from_millis(step_ms() * 4);
            let commit_hash = loop {
                if let Some(qh) = self.bft_precommit_quorum().await {
                    break Some(qh);
                }
                // Fast-path: batch_timer_task already committed this height via attestations.
                if self
                    .finalized_height
                    .load(std::sync::atomic::Ordering::SeqCst)
                    >= height
                {
                    tracing::info!(
                        "BFT height {} already finalized via attestations - advancing",
                        height
                    );
                    break Some([0u8; 32]); // sentinel: skip BFT commit, height already done
                }
                // Nil-precommit fast path: 2/3+ nil precommits → advance round immediately.
                {
                    let state = self.state.load();
                    let stake_map = Self::stake_map_from_state(&state);
                    let total: u64 = stake_map.values().sum();
                    let threshold = (total * 2 / 3) + 1;
                    let rs = self.bft_round.read().await;
                    let nil_stake = rs.precommit_stake(rs.round, None, &stake_map);
                    if nil_stake >= threshold {
                        tracing::info!(
                            "BFT nil-precommit quorum at height {} round {} - fast view-change",
                            height,
                            rs.round
                        );
                        break None;
                    }
                }
                if tokio::time::Instant::now() >= precommit_deadline {
                    break None;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            };

            // ── COMMIT or VIEW-CHANGE ─────────────────────────────────────────
            if let Some(committed_hash) = commit_hash {
                // 2/3+ precommits - finalize this block immediately.
                {
                    let mut rs = self.bft_round.write().await;
                    rs.step = crate::round_state::Step::Committed;
                }
                // advance_finalized_height wires into BlockChain and metrics.
                self.advance_finalized_height(height).await;
                tracing::info!(
                    "BFT committed height {} hash={}",
                    height,
                    hex::encode(&committed_hash[..8])
                );
                // Small yield before next height
                tokio::time::sleep(Duration::from_millis(10)).await;
            } else {
                // Timeout - rotate to next round, new leader will be elected by batch_timer_task.
                let new_round = {
                    let mut rs = self.bft_round.write().await;
                    rs.next_round();
                    rs.round
                };
                tracing::warn!(
                    "BFT timeout at height {} - starting round {}",
                    height,
                    new_round
                );
                // Brief pause before retrying so we do not spin
                tokio::time::sleep(Duration::from_millis(step_ms())).await;
            }
        }
    }

    /// Finalizes blocks after 2/3+ of stake votes on a descendant
    pub async fn finalization_task(self: Arc<Self>) {
        use tokio::time::{interval, Duration};

        let mut timer = interval(Duration::from_secs(2)); // Check every 2s (10 batches)

        loop {
            timer.tick().await;

            let blockchain = self.blockchain.read().await;
            let current_height = blockchain.get_current_height();
            let finalized_height = self.get_finalized_height();

            // Only check finalization if we're significantly ahead
            if current_height <= finalized_height + gp::get_u64(gp::PARAM_FINALIZATION_LAG) {
                continue;
            }

            // Find the highest block with 2/3+ stake voting on descendants
            let state = self.state.load();
            let active_validators = state.staking.get_active_validators();
            let total_stake: u64 = active_validators.values().sum();
            let required_stake = (total_stake * 2) / 3;

            // Walk backwards from current tip to find finalization point
            let mut check_height = finalized_height + 1;
            let mut new_finalized = finalized_height;

            while check_height <= current_height - gp::get_u64(gp::PARAM_FINALIZATION_LAG) {
                // Get stake weight at this height
                if let Some(header) = blockchain.get_batch_by_height(check_height) {
                    // stake_weight is set by set_canonical_tip when a block is accepted.
                    // A block with stake_weight=0 has not been through fork choice yet
                    // (e.g. restored from snapshot) - must not treat it as fully attested.
                    // Instead, check that the block carries 2/3+ embedded attestations.
                    let stake_weight = blockchain.get_stake_weight(&header.batch_hash);
                    let effective_stake = if stake_weight > 0 {
                        stake_weight
                    } else {
                        header.finality_certificate.signed_stake
                    };

                    if effective_stake >= required_stake {
                        new_finalized = check_height;
                    } else {
                        break;
                    }
                }
                check_height += 1;
            }

            if new_finalized > finalized_height {
                drop(blockchain);
                self.advance_finalized_height(new_finalized).await;
                tracing::debug!(
                    " Finalized height: {} (current: {})",
                    new_finalized,
                    current_height
                );

                // Distribute treasury revenue to validators and Staked TLKD holders,
                // with the remaining protocol share burned every interval.
                if new_finalized % gp::get_u64(gp::PARAM_GAS_DISTRIBUTION_INTERVAL) == 0 {
                    let mut state = self.state.load_full();
                    let state_mut = Arc::make_mut(&mut state);

                    // Storage rent is now a one-time deposit (no ongoing collection).
                    let _ = new_finalized;

                    match state_mut.compute_treasury_distribution_diff() {
                        Ok(diff) => {
                            if let Err(e) = state_mut.apply_diff(diff) {
                                tracing::error!(
                                    "Failed to apply treasury distribution diff at height {}: {}",
                                    new_finalized,
                                    e
                                );
                            } else {
                                tracing::info!(
                                    " Distributed treasury revenue at height {}",
                                    new_finalized
                                );
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to distribute treasury revenue at height {}: {}",
                                new_finalized,
                                e
                            );
                        }
                    }

                    self.state.store(state);
                }
            }
        }
    }

    /// Partition detection task - monitors network health and triggers recovery
    pub async fn partition_detection_task(self: Arc<Self>) {
        use tokio::time::{interval, Duration};

        let mut timer = interval(Duration::from_secs(30));
        let mut last_progress = 0u64;
        let mut stall_count = 0u32;

        loop {
            timer.tick().await;

            let current_height = self.get_current_height();
            let peer_count = self.peer_senders.read().await.len();

            if current_height == last_progress {
                stall_count += 1;
            } else {
                stall_count = 0;
                last_progress = current_height;
            }

            if stall_count >= 3 && peer_count > 0 {
                tracing::warn!(
                    " PARTITION DETECTED: No progress for {}s with {} peers",
                    stall_count * 30,
                    peer_count
                );

                let consensus = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = consensus.recover_from_partition().await {
                        tracing::error!("Partition recovery failed: {}", e);
                    }
                });

                stall_count = 0;
            }
        }
    }

    /// Recover from network partition by syncing with majority chain
    async fn recover_from_partition(&self) -> Result<(), String> {
        tracing::info!(" Starting partition recovery");

        let sync_manager = self.sync_manager.read().await;
        let target_height = sync_manager
            .get_highest_peer_height()
            .ok_or("No peer heights available")?;
        drop(sync_manager);

        let my_height = self.get_current_height();

        if target_height <= my_height {
            tracing::info!(" Already at or ahead of peers");
            return Ok(());
        }

        tracing::warn!(
            " Partition recovery: syncing from {} to {}",
            my_height,
            target_height
        );
        self.sync_to_height(target_height).await?;
        tracing::info!(
            " Partition recovery complete at height {}",
            self.get_current_height()
        );
        Ok(())
    }
    pub async fn sync_detection_task(self: Arc<Self>) {
        use tokio::time::{interval, Duration};

        let mut timer = interval(Duration::from_secs(5));
        let mut last_sync_attempt_height: Option<u64> = None;
        let mut last_sync_attempt_time: Option<std::time::Instant> = None;
        let mut stuck_sync_attempts: u32 = 0;
        let mut uncorroborated_tip: Option<(u64, std::time::Instant)> = None;

        loop {
            timer.tick().await;

            let my_height = self.blockchain.read().await.get_current_height();
            let mut sync_manager = self.sync_manager.write().await;
            sync_manager.prune_stale(gp::get_u64(gp::PARAM_SYNC_PEER_TTL_SECS));

            // Get highest peer height from sync manager. Keep hysteresis above normal
            // leader/propagation skew so nodes do not flap into Syncing during ingress.
            let threshold = gp::get_u64(gp::PARAM_SYNC_THRESHOLD).max(8);
            let highest_peer = sync_manager.get_highest_peer_height();

            match highest_peer {
                Some(peer_height) if peer_height >= my_height + threshold => {
                    // We're behind - need to sync
                    let should_trigger_sync = if sync_manager.is_synced() {
                        // Was synced, now falling behind beyond the hysteresis threshold.
                        if peer_height >= my_height + threshold {
                            tracing::warn!(
                                "  Falling behind: my_height={}, peer_height={}",
                                my_height,
                                peer_height
                            );
                            sync_manager.set_syncing(my_height, peer_height);
                            true
                        } else {
                            false
                        }
                    } else {
                        // Already syncing - check if we're stuck
                        let stuck = last_sync_attempt_height
                            .map(|h| h == my_height)
                            .unwrap_or(true);
                        let timeout = last_sync_attempt_time
                            .map(|t| t.elapsed() > Duration::from_secs(10))
                            .unwrap_or(true);

                        if stuck && timeout {
                            stuck_sync_attempts = stuck_sync_attempts.saturating_add(1);
                            tracing::warn!(
                                "  Sync stuck at height {} for {} attempt(s), retrying",
                                my_height,
                                stuck_sync_attempts
                            );
                            true
                        } else {
                            // Still making progress or recently started
                            sync_manager.update_syncing_progress(my_height);
                            tracing::info!("Syncing: {}/{}", my_height, peer_height);
                            if !stuck {
                                stuck_sync_attempts = 0;
                            }
                            false
                        }
                    };

                    if should_trigger_sync {
                        last_sync_attempt_height = Some(my_height);
                        last_sync_attempt_time = Some(std::time::Instant::now());
                        let should_request_snapshot = stuck_sync_attempts >= 2;

                        // Trigger sync in background
                        let consensus = self.clone();
                        tokio::spawn(async move {
                            if should_request_snapshot {
                                tracing::warn!(
                                    " Sync did not advance after repeated attempts; requesting verified snapshot recovery to peer height {}",
                                    peer_height
                                );
                                if let Err(e) =
                                    consensus.request_snapshot_from_peer(peer_height).await
                                {
                                    tracing::warn!("Snapshot recovery request failed: {}", e);
                                } else {
                                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                }
                            }
                            if let Err(e) = consensus.sync_to_height(peer_height).await {
                                tracing::error!("Sync failed: {}", e);
                            }
                        });
                    }
                }
                Some(peer_height) => {
                    // Potentially caught up - require 2+ peers confirming our height.
                    // If only 1 peer and it is ahead, fetch the missing block first.
                    let confirming = sync_manager.peer_count_at_or_above(my_height);
                    let mut height_counts: HashMap<u64, usize> = HashMap::new();
                    for info in sync_manager.peer_heights.values() {
                        *height_counts.entry(info.height).or_default() += 1;
                    }
                    let corroborated_peer_height = height_counts
                        .iter()
                        .filter(|(_, count)| **count >= 2)
                        .map(|(height, _)| *height)
                        .max();
                    if sync_manager.is_synced() {
                        let timeout = last_sync_attempt_time
                            .map(|t| t.elapsed() > Duration::from_secs(10))
                            .unwrap_or(true);
                        if let Some(target_height) = corroborated_peer_height {
                            if target_height > my_height && timeout {
                                uncorroborated_tip = None;
                                tracing::info!(
                                    " Opportunistic catch-up inside sync hysteresis: {} -> corroborated {}",
                                    my_height,
                                    target_height
                                );
                                last_sync_attempt_height = Some(my_height);
                                last_sync_attempt_time = Some(std::time::Instant::now());
                                drop(sync_manager);
                                let consensus = self.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = consensus.sync_to_height(target_height).await {
                                        tracing::warn!("Opportunistic catch-up failed: {}", e);
                                    }
                                });
                                continue;
                            }
                            if my_height > target_height && confirming < 2 && timeout {
                                let same_uncorroborated_tip = uncorroborated_tip
                                    .map(|(height, _)| height == my_height)
                                    .unwrap_or(false);
                                let first_seen = if same_uncorroborated_tip {
                                    uncorroborated_tip
                                        .map(|(_, seen_at)| seen_at)
                                        .unwrap_or_else(std::time::Instant::now)
                                } else {
                                    let now = std::time::Instant::now();
                                    uncorroborated_tip = Some((my_height, now));
                                    now
                                };
                                if first_seen.elapsed() < Duration::from_secs(20) {
                                    tracing::info!(
                                        " Local tip {} is ahead of peer-majority height {}; waiting for propagation before rollback",
                                        my_height,
                                        target_height
                                    );
                                    continue;
                                }
                                tracing::warn!(
                                    " Local tip {} is not corroborated; requesting verified snapshot rollback to peer-majority height {}",
                                    my_height,
                                    target_height
                                );
                                sync_manager.set_syncing(my_height, target_height);
                                last_sync_attempt_height = Some(my_height);
                                last_sync_attempt_time = Some(std::time::Instant::now());
                                drop(sync_manager);
                                let consensus = self.clone();
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        consensus.request_snapshot_from_peer(target_height).await
                                    {
                                        tracing::warn!(
                                            "Peer-majority snapshot rollback request failed: {}",
                                            e
                                        );
                                    }
                                });
                                continue;
                            }
                        }
                    } else if !sync_manager.is_synced() {
                        if confirming >= 2 {
                            sync_manager.set_synced();
                            last_sync_attempt_height = None;
                            last_sync_attempt_time = None;
                            stuck_sync_attempts = 0;
                            uncorroborated_tip = None;
                            tracing::info!(
                                " Sync confirmed by {} peers at height {}",
                                confirming,
                                my_height
                            );
                        } else if confirming == 1 && peer_height > my_height {
                            // Only 1 peer is ahead - try to fetch the missing block,
                            // but if it fails (block not yet finalized), mark synced anyway.
                            // This prevents the node from being stuck in Syncing when it's
                            // actually at the chain tip waiting for the next block.
                            let ahead_by = peer_height - my_height;
                            if ahead_by == 1 {
                                tracing::info!(
                                    " 1 peer ahead by 1 block, fetching or marking synced"
                                );
                                drop(sync_manager);
                                let consensus = self.clone();
                                tokio::spawn(async move {
                                    if let Err(_) = consensus.sync_to_height(peer_height).await {
                                        // Block does not exist yet - we're at the tip, mark synced
                                        consensus.sync_manager.write().await.set_synced();
                                    }
                                });
                            } else {
                                tracing::info!(
                                    " 1 peer ahead at {}, fetching missing block",
                                    peer_height
                                );
                                drop(sync_manager);
                                let consensus = self.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = consensus.sync_to_height(peer_height).await {
                                        tracing::error!("Catch-up sync failed: {}", e);
                                    }
                                });
                            }
                            continue;
                        } else {
                            tracing::debug!(
                                "Waiting for 2+ peers to confirm height {} (have {})",
                                my_height,
                                confirming
                            );
                        }
                    }
                }
                None => {
                    // No peers - never auto-mark synced without peer confirmation.
                    tracing::debug!("No peers yet, staying offline");
                }
            }
        }
    }

    /// Sync to target height by requesting missing blocks
    async fn sync_to_height(&self, target_height: u64) -> Result<(), String> {
        *self.is_syncing.write().await = true;
        let result = async {
            let my_height = self.blockchain.read().await.get_current_height();
            tracing::info!(" Starting sync from {} to {}", my_height, target_height);

            let snapshot_threshold =
                gp::get_u64(gp::PARAM_SYNC_SNAPSHOT_THRESHOLD).min(RAW_BLOCK_RETENTION);
            if target_height > my_height + snapshot_threshold {
                // 1. Try local snapshot first (restart case)
                let local_ok = self.fast_sync_from_snapshot().await.is_ok();

                // 2. If no local snapshot, request one from a canonical-tip peer
                if !local_ok {
                    tracing::info!(" No local snapshot - requesting from peer");
                    if let Err(e) = self.request_snapshot_from_peer(target_height).await {
                        tracing::warn!(
                            "Peer snapshot request failed: {} - falling back to block sync",
                            e
                        );
                    } else {
                        // Give the peer a moment to respond via the message loop
                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                    }
                }
            }

            // Sync only the delta from wherever we are now to target
            let current = self.blockchain.read().await.get_current_height();
            if current < target_height {
                self.sync_remaining_blocks(current, target_height).await?;
            }
            Ok(())
        }
        .await;
        *self.is_syncing.write().await = false;
        result
    }

    /// Send a SnapshotRequest to a peer at a corroborated height.
    pub async fn request_snapshot_from_peer(&self, min_height: u64) -> Result<(), String> {
        let peer_senders = self.peer_senders.read().await;
        let sync_mgr = self.sync_manager.read().await;

        let mut height_counts: HashMap<u64, usize> = HashMap::new();
        for info in sync_mgr.peer_heights.values() {
            *height_counts.entry(info.height).or_default() += 1;
        }

        let corroborated_height = height_counts
            .iter()
            .filter(|(_, count)| **count >= 2)
            .filter(|(height, _)| **height >= min_height)
            .map(|(height, _)| *height)
            .max();
        let highest_corroborated_height = height_counts
            .iter()
            .filter(|(_, count)| **count >= 2)
            .map(|(height, _)| *height)
            .max();
        let request_min_height = corroborated_height
            .or(highest_corroborated_height)
            .unwrap_or(min_height);
        if corroborated_height.is_none() && highest_corroborated_height.is_some() {
            tracing::warn!(
                " No corroborated peer height >= {}; falling back to peer-majority snapshot height {}",
                min_height,
                request_min_height
            );
        }

        let mut candidates: Vec<(Vec<u8>, tokio::sync::mpsc::Sender<Vec<u8>>, u64)> = Vec::new();
        let mut seen = HashSet::new();
        if let Some(height) = corroborated_height.or(highest_corroborated_height) {
            for (pk, info) in sync_mgr
                .peer_heights
                .iter()
                .filter(|(_, info)| info.height == height)
            {
                if let Some(sender) = peer_senders.get(pk) {
                    candidates.push((pk.clone(), sender.clone(), info.height));
                    seen.insert(pk.clone());
                }
            }
        }

        let mut remaining: Vec<_> = sync_mgr
            .peer_heights
            .iter()
            .filter(|(_, info)| info.height >= request_min_height)
            .filter_map(|(pk, info)| {
                if seen.contains(pk) {
                    None
                } else {
                    peer_senders
                        .get(pk)
                        .map(|sender| (pk.clone(), sender.clone(), info.height))
                }
            })
            .collect();
        remaining.sort_by(|a, b| b.2.cmp(&a.2));
        candidates.extend(remaining);

        if candidates.is_empty() {
            candidates.extend(
                peer_senders
                    .iter()
                    .map(|(pk, sender)| (pk.clone(), sender.clone(), request_min_height)),
            );
        }

        if candidates.is_empty() {
            return Err(format!(
                "No connected peer available for snapshot recovery at min height {}",
                request_min_height
            ));
        }
        drop(sync_mgr);
        drop(peer_senders);

        if corroborated_height.is_none() {
            tracing::warn!(
                " No corroborated peer height >= {} for snapshot recovery; requesting snapshot from best connected peers",
                request_min_height
            );
        } else {
            tracing::info!(
                " Requesting snapshot at corroborated peer height {} (min {})",
                corroborated_height.unwrap_or(request_min_height),
                request_min_height
            );
        }
        let data = postcard::to_allocvec(&P2PMessage::SnapshotRequest {
            min_height: request_min_height,
        })
        .map_err(|e| format!("Serialize: {}", e))?;
        let max_fanout = 3usize;
        let mut sent = 0usize;
        let mut full = 0usize;
        let mut targets = Vec::new();
        for (peer_pk, sender, height) in candidates.into_iter().take(max_fanout) {
            match sender.try_send(data.clone()) {
                Ok(()) => {
                    sent += 1;
                    targets.push(format!("{}@{}", hex::encode(&peer_pk[..8]), height));
                }
                Err(_) => {
                    full += 1;
                }
            }
        }

        if sent == 0 {
            return Err(format!(
                "Failed to send snapshot request for min height {}: {} selected peer queues full",
                request_min_height, full
            ));
        }

        tracing::info!(
            " Requested snapshot min height {} from {} peer(s): {}",
            request_min_height,
            sent,
            targets.join(",")
        );
        Ok(())
    }

    /// Update peer height (called when receiving blocks/attestations from peers)
    pub async fn update_peer_height(&self, peer_pubkey: Vec<u8>, height: u64) {
        self.sync_manager
            .write()
            .await
            .update_peer_height(peer_pubkey, height);
    }

    /// Handle fork switch (reorg) - Full state rollback implementation
    pub async fn handle_fork_switch(
        &self,
        old_tip: [u8; 32],
        new_tip: [u8; 32],
    ) -> Result<(), String> {
        tracing::warn!(
            " FORK SWITCH: {} -> {}",
            hex::encode(&old_tip[..8]),
            hex::encode(&new_tip[..8])
        );

        // Acquire locks in consistent order (blockchain first, then sync_manager).
        let (_common_ancestor, common_header, apply_chain, finalized_height) = {
            let blockchain = self.blockchain.read().await;

            // Find common ancestor
            let common_ancestor = blockchain
                .find_common_ancestor(old_tip, new_tip)
                .ok_or("No common ancestor found")?;

            let common_header = blockchain
                .get_header(&common_ancestor)
                .ok_or("Common ancestor header not found")?
                .clone();

            tracing::info!(
                " Common ancestor at height {}: {}",
                common_header.height,
                hex::encode(&common_ancestor[..8])
            );

            // Detect equivocation - check if any validator signed both forks at same height
            self.detect_and_slash_equivocation(&blockchain, old_tip, new_tip, common_ancestor)
                .await;

            // Get chains
            let apply_chain = blockchain.get_chain_between(common_ancestor, new_tip);

            tracing::warn!(
                "Applying {} blocks from common ancestor {}",
                apply_chain.len(),
                hex::encode(&common_ancestor[..8])
            );

            let finalized_height = self.get_finalized_height();

            (
                common_ancestor,
                common_header,
                apply_chain,
                finalized_height,
            )
        }; // blockchain lock released here

        // Finality is irreversible. Never reorg past finalized height.
        if common_header.height < finalized_height {
            return Err(format!(
                "Cannot reorg past finalized height {} (common ancestor at {})",
                finalized_height, common_header.height
            ));
        }

        // Step 1: Load state at common ancestor
        tracing::info!(" Loading state at height {}", common_header.height);
        let rollback_state = self.load_state_at_height(common_header.height).await?;

        // Step 2: Re-execute new chain batches
        tracing::info!(" Re-executing {} batches", apply_chain.len());
        let mut new_state = rollback_state;
        let last_height = apply_chain.last().map(|h| h.height);

        for header in apply_chain {
            tracing::debug!("Executing batch at height {}", header.height);

            // Load batch transactions from storage
            let batch = self.load_batch_at_height(header.height).await?;

            // Execute batch
            new_state = self.execute_batch(&new_state, &batch).await?;

            // Verify state root matches
            let computed_root = self.compute_state_root(&new_state);
            if computed_root != header.state_root {
                return Err(format!(
                    "State root mismatch at height {}: expected {}, got {}",
                    header.height,
                    hex::encode(header.state_root),
                    hex::encode(computed_root)
                ));
            }

            tracing::debug!(" Height {} verified", header.height);
        }

        // Step 3: Atomically update state and height (height first to prevent race)
        tracing::info!(" Updating canonical state");
        let new_height = last_height.unwrap_or(common_header.height);

        // Update height before state to avoid height/state mismatch.
        self.set_finalized_height(new_height);
        self.state.store(Arc::new(new_state));

        tracing::info!(" Fork switch complete: now at height {}", new_height);

        Ok(())
    }

    /// Load state at specific height from storage
    async fn load_state_at_height(&self, height: u64) -> Result<truthlinked_state::State, String> {
        let storage = self.storage.as_ref().ok_or("Storage not initialized")?;

        // Try to load snapshot at or before this height
        let snapshot = storage
            .load_latest_snapshot_before(height)
            .map_err(|e| format!("Failed to load snapshot: {}", e))?
            .ok_or(format!("No snapshot found at or before height {}", height))?;

        if snapshot.height == height {
            // Exact match - return snapshot state
            tracing::info!(" Loaded snapshot at height {}", height);
            return Ok(truthlinked_state::State {
                accounts: snapshot.accounts,
                staking: snapshot.staking,
                nfts: snapshot.nfts,
                cells: snapshot.cells,
                accumulated_gas_fees: snapshot.accumulated_gas_fees,
                accumulated_name_fees: snapshot.accumulated_name_fees,
                accumulated_compute_fees_trth: snapshot.accumulated_compute_fees_trth,
                accumulated_treasury_fees: snapshot.accumulated_treasury_fees,
                params: snapshot.params,
                name_registry: snapshot.name_registry,
                pending_names: snapshot.pending_names,
                token_authority_proposals: snapshot.token_authority_proposals,
                executed_tx_hashes: snapshot.executed_tx_hashes.into_iter().collect(),
                airdrop_claims: snapshot.airdrop_claims,
                total_minted: snapshot.total_minted,
                foundation_mint_authority: snapshot.foundation_mint_authority,
                pending_oracle_requests: snapshot.pending_oracle_requests,
                oracle_pending: snapshot.oracle_pending,
                oracle_results: snapshot.oracle_results,
                url_proposals: snapshot.url_proposals,
                schema_proposals: snapshot.schema_proposals,
                schema_registry: snapshot.schema_registry,
                cell_visibility: snapshot.cell_visibility,
                accumulated_epoch_fees: snapshot.accumulated_epoch_fees,
                last_emission_epoch: snapshot.last_emission_epoch,
                chain_age_years: snapshot.chain_age_years,
            });
        }

        // Need to replay batches from snapshot to target height
        tracing::info!(
            " Loaded snapshot at height {}, replaying to {}",
            snapshot.height,
            height
        );

        let mut state = truthlinked_state::State {
            accounts: snapshot.accounts,
            staking: snapshot.staking,
            nfts: snapshot.nfts,
            cells: snapshot.cells,
            accumulated_gas_fees: snapshot.accumulated_gas_fees,
            accumulated_name_fees: snapshot.accumulated_name_fees,
            accumulated_compute_fees_trth: snapshot.accumulated_compute_fees_trth,
            accumulated_treasury_fees: snapshot.accumulated_treasury_fees,
            params: snapshot.params,
            name_registry: snapshot.name_registry,
            pending_names: snapshot.pending_names,
            token_authority_proposals: snapshot.token_authority_proposals,
            executed_tx_hashes: snapshot.executed_tx_hashes.into_iter().collect(),
            airdrop_claims: snapshot.airdrop_claims,
            total_minted: snapshot.total_minted,
            foundation_mint_authority: snapshot.foundation_mint_authority,
            pending_oracle_requests: snapshot.pending_oracle_requests,
            oracle_pending: snapshot.oracle_pending,
            oracle_results: snapshot.oracle_results,
            url_proposals: snapshot.url_proposals,
            schema_proposals: snapshot.schema_proposals,
            schema_registry: snapshot.schema_registry,
            cell_visibility: snapshot.cell_visibility,
            accumulated_epoch_fees: snapshot.accumulated_epoch_fees,
            last_emission_epoch: snapshot.last_emission_epoch,
            chain_age_years: snapshot.chain_age_years,
        };

        // Replay batches from snapshot.height + 1 to height
        for h in (snapshot.height + 1)..=height {
            let batch = self.load_batch_at_height(h).await?;
            state = self.execute_batch(&state, &batch).await?;
        }

        Ok(state)
    }

    /// Load batch at specific height from storage
    async fn load_batch_at_height(&self, height: u64) -> Result<Vec<Transaction>, String> {
        let storage = self.storage.as_ref().ok_or("Storage not initialized")?;

        // Load batch from storage
        let batch = storage
            .load_batch(height)
            .map_err(|e| format!("Failed to load batch at height {}: {}", height, e))?
            .ok_or(format!("Batch at height {} not found", height))?;

        Ok(batch)
    }

    /// Build per-transaction result strings for persistence indexing.
    fn batch_results(batch_len: usize, failed: &[(usize, String)]) -> Vec<String> {
        let mut results = vec!["success".to_string(); batch_len];
        for (idx, err) in failed {
            if *idx < batch_len {
                results[*idx] = err.clone();
            }
        }
        results
    }

    /// Execute batch and return full batch result (state + failures).
    async fn execute_batch_with_results(
        &self,
        state: &truthlinked_state::State,
        batch: &[Transaction],
    ) -> Result<truthlinked_state::parallel_executor::BatchResult, String> {
        let _lock = self.execution_lock.lock().await;
        truthlinked_state::pq_execution::rehydrate_runtime_globals_from_state(state);
        let exec_start = std::time::Instant::now();
        let mut result =
            truthlinked_state::parallel_executor::execute_batch_parallel_with_profiler(
                state, batch, None,
            )?;

        let exec_ms = exec_start.elapsed().as_millis() as u64;
        self.last_exec_ms
            .store(exec_ms, std::sync::atomic::Ordering::Relaxed);

        if !result.failed.is_empty() {
            tracing::warn!(
                "  Batch had {} failures out of {} txs",
                result.failed.len(),
                batch.len()
            );
        }
        let metrics = truthlinked_state::metrics::global();
        metrics.add_tx_applied(result.applied as u64);
        metrics.add_tx_failed(result.failed.len() as u64);

        let mut new_state = result.state;
        new_state.advance_block_counters();
        let block_height = new_state.staking.current_height;
        truthlinked_state::set_current_height(block_height);
        new_state.run_end_of_block_maintenance(block_height);
        result.state = new_state;

        Ok(result)
    }

    /// Execute batch and return new state.
    async fn execute_batch(
        &self,
        state: &truthlinked_state::State,
        batch: &[Transaction],
    ) -> Result<truthlinked_state::State, String> {
        let result = self.execute_batch_with_results(state, batch).await?;
        Ok(result.state)
    }

    // ========== SNAPSHOT SYSTEM ==========

    /// Create snapshot at current height.
    pub async fn create_snapshot(&self, height: u64) -> Result<crate::StateSnapshot, String> {
        let state = self.state.load();
        let snapshot = crate::StateSnapshot::from_state(height, &state);
        if let Some(ref storage) = self.storage {
            match storage.load_batch_header_by_height(height) {
                Ok(Some(header)) if header.state_root == snapshot.state_root => {}
                Ok(Some(header)) => {
                    return Err(format!(
                        "Snapshot root mismatch at height {}: canonical {}, snapshot {}",
                        height,
                        hex::encode(header.state_root),
                        hex::encode(snapshot.state_root)
                    ));
                }
                Ok(None) => {
                    return Err(format!(
                        "Cannot create snapshot at height {}: canonical header missing",
                        height
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "Cannot load canonical header for snapshot at height {}: {}",
                        height, e
                    ));
                }
            }
            storage
                .save_snapshot(&snapshot)
                .map_err(|e| format!("Failed to save snapshot: {}", e))?;
            tracing::info!(" Created snapshot at height {}", height);
        }
        Ok(snapshot)
    }

    /// Verify snapshot signatures (2/3+ validators must sign)
    pub async fn verify_snapshot(&self, snapshot: &crate::StateSnapshot) -> Result<(), String> {
        use fips204::traits::{SerDes, Verifier};

        if snapshot.validator_signatures.is_empty() {
            return Err("No signatures on snapshot".to_string());
        }

        // Compute message to verify
        let message = snapshot.compute_message();

        // Get active validators and their stake
        let active_validators = snapshot.staking.get_active_validators();
        let total_stake: u64 = active_validators.values().sum();

        if total_stake == 0 {
            return Err("No active stake".to_string());
        }

        // Verify signatures and count stake
        let mut signed_stake = 0u64;

        for sig_data in &snapshot.validator_signatures {
            let pk_bytes: [u8; 1952] = sig_data
                .validator_pubkey
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid pubkey length")?;
            let pk = DilithiumPublicKey::try_from_bytes(pk_bytes).map_err(|_| "Invalid pubkey")?;

            let sig_bytes: [u8; 3309] = sig_data
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid signature length")?;

            if !pk.verify(&message, &sig_bytes, b"truthlinked-snapshot-v1") {
                tracing::warn!(
                    "Invalid signature from {}",
                    hex::encode(&sig_data.validator_pubkey[..8])
                );
                continue;
            }

            if let Some(&stake) = active_validators.get(&sig_data.validator_pubkey) {
                signed_stake += stake;
            } else {
                tracing::warn!(
                    "Validator {} has no stake",
                    hex::encode(&sig_data.validator_pubkey[..8])
                );
            }
        }

        // Require 2/3+ stake
        if signed_stake * 3 < total_stake * 2 {
            return Err(format!(
                "Insufficient stake: {}/{} (need 2/3+)",
                signed_stake, total_stake
            ));
        }

        tracing::info!(
            " Snapshot verified: {}/{} stake signed",
            signed_stake,
            total_stake
        );
        Ok(())
    }

    /// Apply received snapshot (from peer during sync)
    fn repair_storage_anchors_from_tip(
        &self,
        storage: &crate::persistence::Storage,
        tip_header: crate::BatchHeader,
    ) {
        let mut cursor = tip_header;
        for _ in 0..RAW_BLOCK_RETENTION {
            if let Err(e) = storage.store_anchor(cursor.height, &cursor.batch_hash) {
                tracing::warn!(
                    "Failed to repair canonical anchor at height {}: {}",
                    cursor.height,
                    e
                );
                return;
            }
            if cursor.height == 0 || cursor.parent_hash == [0u8; 32] {
                break;
            }
            match storage.load_batch_header(&cursor.parent_hash) {
                Ok(Some(parent)) => cursor = parent,
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(
                        "Failed to load parent header while repairing anchors at height {}: {}",
                        cursor.height.saturating_sub(1),
                        e
                    );
                    break;
                }
            }
        }
    }

    /// Apply received snapshot (from peer during sync)
    pub async fn apply_received_snapshot(
        &self,
        snapshot: crate::StateSnapshot,
    ) -> Result<(), String> {
        // Verify snapshot first
        self.verify_snapshot(&snapshot).await?;

        // Verify state root matches snapshot data
        let computed_root = {
            let temp_state = truthlinked_state::State {
                accounts: snapshot.accounts.clone(),
                staking: snapshot.staking.clone(),
                nfts: snapshot.nfts.clone(),
                cells: snapshot.cells.clone(),
                accumulated_gas_fees: snapshot.accumulated_gas_fees,
                accumulated_name_fees: snapshot.accumulated_name_fees,
                accumulated_compute_fees_trth: snapshot.accumulated_compute_fees_trth,
                accumulated_treasury_fees: snapshot.accumulated_treasury_fees,
                params: snapshot.params.clone(),
                name_registry: snapshot.name_registry.clone(),
                pending_names: snapshot.pending_names.clone(),
                token_authority_proposals: snapshot.token_authority_proposals.clone(),
                executed_tx_hashes: snapshot.executed_tx_hashes.iter().copied().collect(),
                airdrop_claims: snapshot.airdrop_claims.clone(),
                total_minted: snapshot.total_minted,
                foundation_mint_authority: snapshot.foundation_mint_authority,
                pending_oracle_requests: snapshot.pending_oracle_requests.clone(),
                oracle_pending: snapshot.oracle_pending.clone(),
                oracle_results: snapshot.oracle_results.clone(),
                url_proposals: snapshot.url_proposals.clone(),
                schema_proposals: snapshot.schema_proposals.clone(),
                schema_registry: snapshot.schema_registry.clone(),
                cell_visibility: snapshot.cell_visibility.clone(),
                accumulated_epoch_fees: snapshot.accumulated_epoch_fees,
                last_emission_epoch: snapshot.last_emission_epoch,
                chain_age_years: snapshot.chain_age_years,
            };
            self.compute_state_root(&temp_state)
        };

        if computed_root != snapshot.state_root {
            return Err(format!(
                "State root mismatch: expected {}, got {}",
                hex::encode(snapshot.state_root),
                hex::encode(computed_root)
            ));
        }

        let snapshot_height = snapshot.height;
        let current_height = self.get_current_height();
        let allow_recovery_rollback =
            *self.is_syncing.read().await || !self.sync_manager.read().await.is_synced();
        if snapshot_height <= current_height && !allow_recovery_rollback {
            return Err(format!(
                "Stale peer snapshot at height {} <= current {}",
                snapshot_height, current_height
            ));
        }
        if snapshot_height <= current_height {
            tracing::warn!(
                " Applying verified peer recovery snapshot at height {} over local height {}",
                snapshot_height,
                current_height
            );
        }

        // Apply snapshot
        let mut new_state = truthlinked_state::State {
            accounts: snapshot.accounts.clone(),
            staking: snapshot.staking.clone(),
            nfts: snapshot.nfts.clone(),
            cells: snapshot.cells.clone(),
            accumulated_gas_fees: snapshot.accumulated_gas_fees,
            accumulated_name_fees: snapshot.accumulated_name_fees,
            accumulated_compute_fees_trth: snapshot.accumulated_compute_fees_trth,
            accumulated_treasury_fees: snapshot.accumulated_treasury_fees,
            params: snapshot.params.clone(),
            name_registry: snapshot.name_registry.clone(),
            pending_names: snapshot.pending_names.clone(),
            token_authority_proposals: snapshot.token_authority_proposals.clone(),
            executed_tx_hashes: snapshot.executed_tx_hashes.iter().copied().collect(),
            airdrop_claims: snapshot.airdrop_claims.clone(),
            total_minted: snapshot.total_minted,
            foundation_mint_authority: snapshot.foundation_mint_authority,
            pending_oracle_requests: snapshot.pending_oracle_requests.clone(),
            oracle_pending: snapshot.oracle_pending.clone(),
            oracle_results: snapshot.oracle_results.clone(),
            url_proposals: snapshot.url_proposals.clone(),
            schema_proposals: snapshot.schema_proposals.clone(),
            schema_registry: snapshot.schema_registry.clone(),
            cell_visibility: snapshot.cell_visibility.clone(),
            accumulated_epoch_fees: snapshot.accumulated_epoch_fees,
            last_emission_epoch: snapshot.last_emission_epoch,
            chain_age_years: snapshot.chain_age_years,
        };
        new_state.staking.current_height = snapshot_height;

        let total_stake: u64 = new_state.staking.get_active_validators().values().sum();
        self.state.store(Arc::new(new_state));
        if snapshot_height <= current_height {
            self.set_recovery_height(snapshot_height);
        } else {
            self.set_finalized_height(snapshot_height);
            self.set_current_height_monotonic(snapshot_height);
        }
        self.batch.write().await.clear();
        self.mempool_index.write().await.clear();
        self.pending_batches.write().await.clear();

        // Seed the blockchain index with just the snapshot tip.
        // For a node without local history receiving a peer snapshot, request the actual header
        // for snapshot_height via SyncRequest so the real batch_hash is known.
        // Without it, block snapshot_height+1 cannot chain (parent_hash mismatch).
        if let Some(ref storage) = self.storage {
            let mut blockchain = self.blockchain.write().await;
            *blockchain = crate::BlockChain::new();
            if let Ok(Some(header)) = storage.load_batch_header_by_height(snapshot_height) {
                self.repair_storage_anchors_from_tip(storage, header.clone());
                blockchain.seed_canonical_tip(header, total_stake);
            }
            // If no local header (node without local history), the sync loop will request blocks
            // starting from snapshot_height and apply them sequentially.
            // seed_anchor at height 0 is fine - sync will fill the gap.
        }

        // Save to storage
        if let Some(ref storage) = self.storage {
            storage
                .save_snapshot(&snapshot)
                .map_err(|e| format!("Failed to save snapshot: {}", e))?;
        }

        tracing::info!(" Applied snapshot at height {}", snapshot_height);
        Ok(())
    }

    /// Apply a local snapshot directly - skips peer signature check, trusts state root.
    /// Apply a snapshot received from a peer. Verifies state root before applying.
    pub async fn handle_peer_snapshot(
        &self,
        snapshot: crate::StateSnapshot,
        tip_header: Option<crate::BatchHeader>,
    ) {
        let computed =
            crate::StateSnapshot::compute_state_root_from_state(&truthlinked_state::State {
                accounts: snapshot.accounts.clone(),
                staking: snapshot.staking.clone(),
                nfts: snapshot.nfts.clone(),
                cells: snapshot.cells.clone(),
                accumulated_gas_fees: snapshot.accumulated_gas_fees,
                accumulated_name_fees: snapshot.accumulated_name_fees,
                accumulated_compute_fees_trth: snapshot.accumulated_compute_fees_trth,
                accumulated_treasury_fees: snapshot.accumulated_treasury_fees,
                params: snapshot.params.clone(),
                name_registry: snapshot.name_registry.clone(),
                pending_names: snapshot.pending_names.clone(),
                token_authority_proposals: snapshot.token_authority_proposals.clone(),
                executed_tx_hashes: snapshot.executed_tx_hashes.iter().copied().collect(),
                airdrop_claims: snapshot.airdrop_claims.clone(),
                total_minted: snapshot.total_minted,
                foundation_mint_authority: snapshot.foundation_mint_authority,
                pending_oracle_requests: snapshot.pending_oracle_requests.clone(),
                oracle_pending: snapshot.oracle_pending.clone(),
                oracle_results: snapshot.oracle_results.clone(),
                url_proposals: snapshot.url_proposals.clone(),
                schema_proposals: snapshot.schema_proposals.clone(),
                schema_registry: snapshot.schema_registry.clone(),
                cell_visibility: snapshot.cell_visibility.clone(),
                accumulated_epoch_fees: snapshot.accumulated_epoch_fees,
                last_emission_epoch: snapshot.last_emission_epoch,
                chain_age_years: snapshot.chain_age_years,
            });
        if computed != snapshot.state_root {
            tracing::warn!(
                "Peer snapshot at height {} failed state root check - discarding",
                snapshot.height
            );
            return;
        }
        let height = snapshot.height;
        let trusted_tip_header = tip_header.filter(|header| {
            let valid = header.height == height && header.state_root == snapshot.state_root;
            if !valid {
                tracing::warn!(
                    "Peer snapshot tip header mismatch at height {} - discarding header",
                    height
                );
            }
            valid
        });
        if let Err(e) = self.apply_snapshot_state(snapshot.clone()).await {
            tracing::warn!("Failed to apply peer snapshot at {}: {}", height, e);
            return;
        }
        if let Some(ref storage) = self.storage {
            if let Some(ref header) = trusted_tip_header {
                let saved_tip_header = match storage.save_batch_header(header) {
                    Ok(()) => true,
                    Err(e) => {
                        let err = e.to_string();
                        tracing::warn!(
                            "Failed to persist peer snapshot tip header at {}: {}",
                            height,
                            err
                        );
                        false
                    }
                };
                if saved_tip_header {
                    let total_stake: u64 = self
                        .state
                        .load()
                        .staking
                        .get_active_validators()
                        .values()
                        .sum();
                    self.blockchain
                        .write()
                        .await
                        .seed_canonical_tip(header.clone(), total_stake);
                    self.repair_storage_anchors_from_tip(storage, header.clone());
                    tracing::info!(" Seeded peer snapshot tip anchor at height {}", height);
                }
            }
            if let Err(e) = storage.save_snapshot(&snapshot) {
                tracing::warn!("Failed to persist peer snapshot at {}: {}", height, e);
            }
        }
        tracing::info!(" Applied peer snapshot at height {}", height);
        // Fetch the anchor block header from a peer and seed it into the blockchain
        // index so block height+1 can chain correctly (parent_hash must match batch_hash).
        // We do this by sending a SyncRequest for just that one block and handling
        // the response in the normal SyncResponse path. When no tip header was attached, request it explicitly.
        // Use a direct RPC call to the node itself as a direct request path.
        if trusted_tip_header.is_none() {
            if let Some(ref storage) = self.storage {
                if storage
                    .load_batch_header_by_height(height)
                    .ok()
                    .flatten()
                    .is_none()
                {
                    // No local header - request it from a peer
                    let _ = self.request_blocks_from_peer(height, height).await;
                }
            }
        }
    }

    async fn apply_snapshot_state(&self, snapshot: crate::StateSnapshot) -> Result<(), String> {
        let snapshot_height = snapshot.height;
        let current_height = self.get_current_height();
        let allow_recovery_rollback =
            *self.is_syncing.read().await || !self.sync_manager.read().await.is_synced();
        if snapshot_height <= current_height && !allow_recovery_rollback {
            return Err(format!(
                "Stale snapshot state at height {} <= current {}",
                snapshot_height, current_height
            ));
        }
        if snapshot_height <= current_height {
            tracing::warn!(
                " Applying verified recovery snapshot at height {} over local height {}",
                snapshot_height,
                current_height
            );
        }
        let mut new_state = truthlinked_state::State {
            accounts: snapshot.accounts.clone(),
            staking: snapshot.staking.clone(),
            nfts: snapshot.nfts.clone(),
            cells: snapshot.cells.clone(),
            accumulated_gas_fees: snapshot.accumulated_gas_fees,
            accumulated_name_fees: snapshot.accumulated_name_fees,
            accumulated_compute_fees_trth: snapshot.accumulated_compute_fees_trth,
            accumulated_treasury_fees: snapshot.accumulated_treasury_fees,
            params: snapshot.params.clone(),
            name_registry: snapshot.name_registry.clone(),
            pending_names: snapshot.pending_names.clone(),
            token_authority_proposals: snapshot.token_authority_proposals.clone(),
            executed_tx_hashes: snapshot.executed_tx_hashes.iter().copied().collect(),
            airdrop_claims: snapshot.airdrop_claims.clone(),
            total_minted: snapshot.total_minted,
            foundation_mint_authority: snapshot.foundation_mint_authority,
            pending_oracle_requests: snapshot.pending_oracle_requests.clone(),
            oracle_pending: snapshot.oracle_pending.clone(),
            oracle_results: snapshot.oracle_results.clone(),
            url_proposals: snapshot.url_proposals.clone(),
            schema_proposals: snapshot.schema_proposals.clone(),
            schema_registry: snapshot.schema_registry.clone(),
            cell_visibility: snapshot.cell_visibility.clone(),
            accumulated_epoch_fees: snapshot.accumulated_epoch_fees,
            last_emission_epoch: snapshot.last_emission_epoch,
            chain_age_years: snapshot.chain_age_years,
        };
        new_state.staking.current_height = snapshot_height;
        let total_stake_local: u64 = new_state.staking.get_active_validators().values().sum();
        self.state.store(Arc::new(new_state));
        if snapshot_height <= current_height {
            self.set_recovery_height(snapshot_height);
        } else {
            self.set_finalized_height(snapshot_height);
            self.set_current_height_monotonic(snapshot_height);
        }
        self.batch.write().await.clear();
        self.mempool_index.write().await.clear();
        self.pending_batches.write().await.clear();

        if let Some(ref storage) = self.storage {
            let mut blockchain = self.blockchain.write().await;
            *blockchain = crate::BlockChain::new();
            if let Ok(Some(header)) = storage.load_batch_header_by_height(snapshot_height) {
                blockchain.seed_canonical_tip(header, total_stake_local);
            }
        }
        tracing::info!(" Applied local snapshot at height {}", snapshot_height);
        Ok(())
    }

    /// Replay finalized blocks from DonaDB storage to restore consensus state after restart.
    pub async fn replay_from_storage(&self) -> Result<u64, String> {
        let storage = self.storage.as_ref().ok_or("Storage not initialized")?;

        let tip = storage.get_latest_block_height();
        if tip == 0 {
            return Err("No blocks in storage".to_string());
        }

        tracing::info!(" Replaying {} blocks from storage...", tip);

        // ── Start from the latest snapshot, not genesis ───────────────────────
        // Without this, a 500k-block chain replays every block from height 1,
        // holding the full accumulated state in RAM - unsafe memory growth on long chains.
        // Snapshots are taken every ~10k blocks; we only replay the delta.
        let replay_from = match storage.load_latest_snapshot_before(tip).ok().flatten() {
            Some(snap) => {
                let snap_height = snap.height;
                tracing::info!(
                    " Resuming from snapshot at height {} (skipping {} blocks)",
                    snap_height,
                    snap_height
                );
                self.apply_snapshot_state(snap)
                    .await
                    .map_err(|e| format!("Failed to apply snapshot: {}", e))?;
                snap_height + 1
            }
            None => {
                tracing::info!(" No snapshot found, replaying from genesis");
                1
            }
        };

        let mut state: truthlinked_state::State = (**self.state.load()).clone();

        for height in replay_from..=tip {
            let header = match storage.load_batch_header_by_height(height) {
                Ok(Some(h)) => h,
                Ok(None) => {
                    tracing::info!(" Replay stopped: no header at height {}", height);
                    break;
                }
                Err(e) => {
                    tracing::warn!(" Replay stopped: load header {}: {}", height, e);
                    break;
                }
            };

            let batch = match storage.load_batch(height) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    tracing::info!(" Replay stopped: no batch at height {}", height);
                    break;
                }
                Err(e) => {
                    tracing::warn!(" Replay stopped: load batch {}: {}", height, e);
                    break;
                }
            };

            match self.execute_batch(&state, &batch).await {
                Ok(new_state) => {
                    let computed_root = self.compute_state_root(&new_state);
                    if computed_root != header.state_root {
                        return Err(format!(
                            "Replay state root mismatch at height {}: canonical {}, replay {}",
                            height,
                            hex::encode(header.state_root),
                            hex::encode(computed_root)
                        ));
                    }
                    state = new_state;
                }
                Err(e) => {
                    return Err(format!(
                        "Replay execution failed at height {}: {}",
                        height, e
                    ));
                }
            }

            // Update blockchain index
            {
                let mut blockchain = self.blockchain.write().await;
                let _ = blockchain.add_header(header.clone());
                let active = state.staking.get_active_validators();
                let total_stake: u64 = active.values().sum();
                blockchain.seed_canonical_tip(header.clone(), total_stake);
            }

            self.set_current_height_monotonic(height);
            self.set_finalized_height(height);
        }

        self.state.store(Arc::new(state));

        let replayed = self
            .current_height
            .load(std::sync::atomic::Ordering::SeqCst);
        tracing::info!(" Replay complete: restored to height {}", replayed);
        Ok(replayed)
    }

    /// Compatibility stub: apply_snapshot_state now seeds the canonical tip directly.
    /// Kept for API compatibility.
    pub async fn rebuild_header_index(&self) -> Result<(), String> {
        Ok(())
    }

    /// Fast sync from snapshot (bootstrap new node)

    pub async fn fast_sync_from_snapshot(&self) -> Result<(), String> {
        let storage = self.storage.as_ref().ok_or("Storage not initialized")?;

        // Load latest snapshot
        let snapshot = storage
            .load_latest_snapshot()
            .map_err(|e| format!("Failed to load snapshot: {}", e))?
            .ok_or("No snapshot found")?;

        let current_height = self.get_current_height();
        if snapshot.height <= current_height {
            return Err(format!(
                "Local snapshot at height {} does not advance current {}",
                snapshot.height, current_height
            ));
        }
        tracing::info!(" Fast syncing from snapshot at height {}", snapshot.height);

        // For local snapshots, verify state root integrity instead of requiring signatures.
        // Signatures are only required for cross-node (peer) snapshot sync.
        let computed_root =
            crate::StateSnapshot::compute_state_root_from_state(&truthlinked_state::State {
                accounts: snapshot.accounts.clone(),
                staking: snapshot.staking.clone(),
                nfts: snapshot.nfts.clone(),
                cells: snapshot.cells.clone(),
                accumulated_gas_fees: snapshot.accumulated_gas_fees,
                accumulated_name_fees: snapshot.accumulated_name_fees,
                accumulated_compute_fees_trth: snapshot.accumulated_compute_fees_trth,
                accumulated_treasury_fees: snapshot.accumulated_treasury_fees,
                params: snapshot.params.clone(),
                name_registry: snapshot.name_registry.clone(),
                pending_names: snapshot.pending_names.clone(),
                token_authority_proposals: snapshot.token_authority_proposals.clone(),
                executed_tx_hashes: snapshot.executed_tx_hashes.iter().copied().collect(),
                airdrop_claims: snapshot.airdrop_claims.clone(),
                total_minted: snapshot.total_minted,
                foundation_mint_authority: snapshot.foundation_mint_authority,
                pending_oracle_requests: snapshot.pending_oracle_requests.clone(),
                oracle_pending: snapshot.oracle_pending.clone(),
                oracle_results: snapshot.oracle_results.clone(),
                url_proposals: snapshot.url_proposals.clone(),
                schema_proposals: snapshot.schema_proposals.clone(),
                schema_registry: snapshot.schema_registry.clone(),
                cell_visibility: snapshot.cell_visibility.clone(),
                accumulated_epoch_fees: snapshot.accumulated_epoch_fees,
                last_emission_epoch: snapshot.last_emission_epoch,
                chain_age_years: snapshot.chain_age_years,
            });
        if computed_root != snapshot.state_root {
            return Err(format!(
                "Local snapshot state root mismatch at height {}: stored={}, computed={}",
                snapshot.height,
                hex::encode(snapshot.state_root),
                hex::encode(computed_root)
            ));
        }
        tracing::info!(
            " Local snapshot integrity verified at height {}",
            snapshot.height
        );

        // Apply snapshot directly (skip peer signature check for local snapshots)
        self.apply_snapshot_state(snapshot).await?;

        tracing::info!(" Fast sync complete");
        Ok(())
    }

    /// Serve snapshot to peer
    pub async fn serve_snapshot(
        &self,
        height: Option<u64>,
    ) -> Result<crate::StateSnapshot, String> {
        let storage = self.storage.as_ref().ok_or("Storage not initialized")?;

        let snapshot = if let Some(h) = height {
            // Specific height requested
            storage
                .load_snapshot(h)
                .map_err(|e| format!("Failed to load snapshot: {}", e))?
                .ok_or(format!("Snapshot at height {} not found", h))?
        } else {
            // Latest snapshot
            storage
                .load_latest_snapshot()
                .map_err(|e| format!("Failed to load snapshot: {}", e))?
                .ok_or("No snapshot found")?
        };

        if snapshot.compute_state_root() != snapshot.state_root {
            return Err(format!(
                "Stored snapshot at height {} failed full-state root validation",
                snapshot.height
            ));
        }

        tracing::info!(" Serving snapshot at height {}", snapshot.height);
        Ok(snapshot)
    }

    /// Handle snapshot signature request (coordinator asks validators to sign)
    pub async fn handle_snapshot_signature_request(
        &self,
        height: u64,
        state_root: [u8; 32],
    ) -> Result<Vec<u8>, String> {
        // Verify we have this state
        let current_height = self.get_finalized_height();
        if height > current_height {
            return Err(format!(
                "Height {} not finalized yet (current: {})",
                height, current_height
            ));
        }

        // Load state at this height
        let state = self.load_state_at_height(height).await?;

        // Verify state root matches
        let computed_root = self.compute_state_root(&state);
        if computed_root != state_root {
            return Err(format!(
                "State root mismatch at height {}: expected {}, got {}",
                height,
                hex::encode(state_root),
                hex::encode(computed_root)
            ));
        }

        // Sign snapshot
        let snapshot = crate::StateSnapshot::from_state(height, &state);

        let message = snapshot.compute_message();
        let signature = self
            .keypair
            .dilithium_sk
            .try_sign(&message, b"truthlinked-snapshot-v1")
            .map_err(|e| format!("Signing failed: {}", e))?;

        tracing::info!("  Signed snapshot at height {}", height);
        Ok(signature.to_vec())
    }

    // ========== SYNC SYSTEM ==========

    async fn validate_sync_header_with_batch(
        &self,
        header: &crate::BatchHeader,
        batch: &[Transaction],
    ) -> Result<(), String> {
        self.verify_header_leader(header)
            .map_err(|e| format!("Invalid leader signature/selection: {:?}", e))?;

        let state = self.state.load();

        let local_commitment = self
            .compute_batch_commitment(batch, &header.parent_hash, header.height)
            .map_err(|e| format!("Failed to compute batch commitment: {}", e))?;
        if header.batch_hash != local_commitment {
            return Err(format!(
                "Batch commitment mismatch at height {}: expected {}, got {}",
                header.height,
                hex::encode(local_commitment),
                hex::encode(header.batch_hash)
            ));
        }

        let mut batch_copy = batch.to_vec();
        let local_order = self
            .compute_execution_order(&mut batch_copy, &header.batch_hash)
            .map_err(|e| format!("Failed to compute execution order: {}", e))?;
        let local_order_root = Self::merkle_root(&local_order);
        if header.execution_order_root != local_order_root {
            return Err(format!(
                "Execution order mismatch at height {}: expected {}, got {}",
                header.height,
                hex::encode(local_order_root),
                hex::encode(header.execution_order_root)
            ));
        }

        let stake_map = Self::stake_map_from_state(&state);
        let active_attesters = Self::attesters_for_header(&state, header);
        // Historical sync must validate against the canonical active_attesters for the
        // header epoch. Tip-local liveness filtering is only valid for live
        // block production; applying it to old blocks can erase the historical
        // quorum and make valid stored blocks unverifiable by lagging nodes.
        let required = Self::required_non_leader_stake_for_attesters(
            &stake_map,
            &active_attesters,
            &header.leader_pubkey,
        );
        if let Err(e) = self.verify_historical_sync_attestation_set(
            header,
            &active_attesters,
            &stake_map,
            required,
        ) {
            return Err(format!("Attestation verification failed: {}", e));
        }

        Ok(())
    }

    /// Apply historical batch during sync
    pub async fn apply_sync_batch(
        &self,
        header: crate::BatchHeader,
        batch: crate::Batch,
    ) -> Result<(), String> {
        // Sync sequencing must follow the canonical tip/current height, not only
        // finalized height. During catch-up a node can have current=N while
        // finalized=N-1; using finalized here makes the real next block N+1
        // look out-of-order and can deadlock sync at N.
        let current_height = self.get_current_height();

        // Serialize sync intake from sequence check through state/canonical-tip update.
        // Multiple concurrent sync responses can carry the same next height. Without
        // this guard, two tasks can both validate against the same parent before the
        // first task advances the tip, causing duplicate application followed by
        // parent-hash or state-root divergence.
        let mut sync_apply_guard = self.sync_buffer.write().await;

        if header.height <= current_height {
            tracing::debug!(
                "Ignoring stale sync batch at height {} (current: {})",
                header.height,
                current_height
            );
            return Ok(());
        }

        // Validate header content (leader sig/selection, commitment, execution order).
        self.validate_sync_header_with_batch(&header, &batch)
            .await?;

        // Check if batch is next in sequence
        if header.height != current_height + 1 {
            // Check buffer size limit
            if sync_apply_guard.len() >= gp::get_usize(gp::PARAM_STREAMING_MAX_SYNC_BUFFER_SIZE) {
                // Remove oldest entry to make room
                if let Some(oldest_height) = sync_apply_guard.keys().min().copied() {
                    sync_apply_guard.remove(&oldest_height);
                    tracing::warn!(
                        "  Sync buffer full, dropped batch at height {}",
                        oldest_height
                    );
                }
            }

            // Reject batches that are too old (more than 100 blocks behind)
            if header.height
                < current_height
                    .saturating_sub(gp::get_usize(gp::PARAM_STREAMING_MAX_SYNC_BUFFER_SIZE) as u64)
            {
                tracing::warn!(
                    " Rejecting old batch at height {} (current: {})",
                    header.height,
                    current_height
                );
                return Err(format!(
                    "Batch too old: height {} < {}",
                    header.height,
                    current_height.saturating_sub(gp::get_usize(
                        gp::PARAM_STREAMING_MAX_SYNC_BUFFER_SIZE
                    ) as u64)
                ));
            }

            // Buffer the batch
            tracing::debug!(
                "Buffering out-of-order batch at height {} (buffer size: {})",
                header.height,
                sync_apply_guard.len() + 1
            );
            sync_apply_guard.insert(header.height, (header, batch));
            return Ok(());
        }

        // Parent hash must match current canonical tip.
        let expected_parent = {
            let blockchain = self.blockchain.read().await;
            blockchain
                .get_canonical_tip()
                .map(|tip| tip.batch_hash)
                .map_err(|e| format!("Canonical tip missing: {}", e))?
        };
        if header.parent_hash != expected_parent {
            return Err(format!(
                "Parent hash mismatch at height {}: expected {}, got {}",
                header.height,
                hex::encode(expected_parent),
                hex::encode(header.parent_hash)
            ));
        }

        // Execute batch
        let state = self.state.load();
        let new_state = self.execute_batch(&state, &batch).await?;

        // Verify state root
        let computed_root = self.compute_state_root(&new_state);
        if computed_root != header.state_root {
            return Err(format!(
                "State root mismatch at height {}: expected {}, got {}",
                header.height,
                hex::encode(header.state_root),
                hex::encode(computed_root)
            ));
        }

        // Get active validators before moving new_state
        let active_validators = new_state.staking.get_active_validators();
        let total_stake: u64 = active_validators.values().sum();

        // Apply state
        self.state.store(Arc::new(new_state));
        self.set_finalized_height(header.height);
        self.set_current_height_monotonic(header.height);

        // Add header to blockchain
        {
            let mut blockchain = self.blockchain.write().await;
            blockchain.add_header(header.clone())?;
            // Use seed_canonical_tip to bypass fork choice - sync applies known-good
            // finalized blocks sequentially, attestation count is irrelevant here.
            blockchain.seed_canonical_tip(header.clone(), total_stake);
        }

        // Persist synchronously before treating this height as a usable sync anchor.
        if let Some(ref storage) = self.storage {
            let empty_registry = std::collections::HashMap::new();
            let results = vec!["success".to_string(); batch.len()];
            if let Err(e) = storage.save_block(&header, &batch, &results, &empty_registry) {
                tracing::error!("Failed to save sync block: {}", e);
            }
        }

        self.prune_committed_from_mempool(&batch, &[]).await;

        let state_snapshot = self.state.load();
        self.prune_ineligible_from_mempool(&state_snapshot).await;
        self.maybe_persist_snapshot(header.height, &state_snapshot);

        tracing::info!(" Applied sync batch at height {}", header.height);

        // Release the intake guard before draining buffered batches; the buffer
        // processor takes the same lock while removing sequential entries.
        drop(sync_apply_guard);

        // Process buffered batches
        self.process_sync_buffer().await?;

        Ok(())
    }

    /// Process buffered out-of-order batches
    pub async fn process_sync_buffer(&self) -> Result<(), String> {
        loop {
            // Buffered sync batches also chain from the canonical tip/current
            // height. Finalized height can lag by one during catch-up.
            let current_height = self.get_current_height();
            let next_height = current_height + 1;

            // Check if we have the next batch
            let next_batch = self.sync_buffer.write().await.remove(&next_height);

            if let Some((header, batch)) = next_batch {
                tracing::debug!("Processing buffered batch at height {}", next_height);

                // Validate header content before applying.
                self.validate_sync_header_with_batch(&header, &batch)
                    .await?;

                // Parent hash must match current canonical tip.
                let expected_parent = {
                    let blockchain = self.blockchain.read().await;
                    blockchain
                        .get_canonical_tip()
                        .map(|tip| tip.batch_hash)
                        .map_err(|e| format!("Canonical tip missing: {}", e))?
                };
                if header.parent_hash != expected_parent {
                    return Err(format!(
                        "Parent hash mismatch at height {}: expected {}, got {}",
                        header.height,
                        hex::encode(expected_parent),
                        hex::encode(header.parent_hash)
                    ));
                }

                // Execute batch
                let state = self.state.load();
                let new_state = self.execute_batch(&state, &batch).await?;

                // Verify state root
                let computed_root = self.compute_state_root(&new_state);
                if computed_root != header.state_root {
                    return Err(format!(
                        "State root mismatch at height {}: expected {}, got {}",
                        header.height,
                        hex::encode(header.state_root),
                        hex::encode(computed_root)
                    ));
                }

                // Get active validators before moving new_state
                let active_validators = new_state.staking.get_active_validators();
                let total_stake: u64 = active_validators.values().sum();

                // Apply state
                self.state.store(Arc::new(new_state));
                self.set_finalized_height(header.height);
                self.set_current_height_monotonic(header.height);

                // Add to blockchain
                {
                    let mut blockchain = self.blockchain.write().await;
                    blockchain.add_header(header.clone())?;
                    blockchain.seed_canonical_tip(header.clone(), total_stake);
                }

                // Persist synchronously before treating this height as a usable sync anchor.
                if let Some(ref storage) = self.storage {
                    let empty_registry = std::collections::HashMap::new();
                    let results = vec!["success".to_string(); batch.len()];
                    if let Err(e) = storage.save_block(&header, &batch, &results, &empty_registry) {
                        tracing::error!("Failed to save sync block: {}", e);
                    }
                }

                self.prune_committed_from_mempool(&batch, &[]).await;
                let state_snapshot = self.state.load();
                self.prune_ineligible_from_mempool(&state_snapshot).await;

                tracing::info!(" Applied buffered batch at height {}", header.height);
            } else {
                // No more sequential batches
                break;
            }
        }

        Ok(())
    }

    /// Sync from snapshot (fast sync)
    pub async fn sync_from_snapshot(&self) -> Result<(), String> {
        *self.is_syncing.write().await = true;
        let result = async {
            // Load and apply latest snapshot
            self.fast_sync_from_snapshot().await?;

            let snapshot_height = self.get_finalized_height();
            tracing::info!(" Synced to snapshot at height {}", snapshot_height);

            // Sync remaining blocks
            let tip_height = self.blockchain.read().await.get_current_height();
            self.sync_remaining_blocks(snapshot_height, tip_height)
                .await?;
            Ok(())
        }
        .await;
        *self.is_syncing.write().await = false;
        result
    }

    /// Sync remaining blocks from snapshot to tip
    /// First tries local storage, then requests from peers if blocks are missing
    pub async fn sync_remaining_blocks(
        &self,
        from_height: u64,
        target_height: u64,
    ) -> Result<(), String> {
        if from_height >= target_height {
            tracing::info!("Already at tip");
            return Ok(());
        }

        tracing::info!(" Syncing blocks {} to {}", from_height + 1, target_height);

        let storage = self.storage.as_ref();
        let mut current = from_height;
        let mut bad_local_sync_heights = HashSet::new();

        while current < target_height {
            // First, try to load from local storage unless this height already
            // failed to extend the current canonical anchor during this sync pass.
            let next_height = current + 1;
            let local_block = if bad_local_sync_heights.contains(&next_height) {
                None
            } else if let Some(ref storage) = storage {
                let header = storage
                    .load_batch_header_by_height(next_height)
                    .ok()
                    .flatten();
                let batch = storage.load_batch(next_height).ok().flatten();
                header.and_then(|h| batch.map(|b| (h, b)))
            } else {
                None
            };

            if let Some((header, batch)) = local_block {
                // Apply from local storage. If local replay diverges from the
                // canonical state root, do not remain stuck replaying the same
                // stale local block forever. Request a corroborated peer
                // snapshot, wait for the async SnapshotResponse handler to
                // apply it, then continue from the new finalized height.
                match self.apply_sync_batch(header, batch).await {
                    Ok(()) => {
                        current = self.get_finalized_height();
                    }
                    Err(e)
                        if e.contains("Parent hash mismatch")
                            || e.contains("Timestamp must be >= parent timestamp") =>
                    {
                        let failed_height = current + 1;
                        bad_local_sync_heights.insert(failed_height);
                        tracing::warn!(
                            " Local sync replay rejected stored block at height {}: {} - quarantining for this sync pass and requesting anchored peer blocks",
                            failed_height,
                            e
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                    Err(e) if e.contains("State root mismatch") => {
                        let failed_height = current + 1;
                        tracing::warn!(
                            " Local sync replay diverged at height {}: {} - requesting peer snapshot recovery",
                            failed_height,
                            e
                        );
                        self.request_snapshot_from_peer(failed_height).await?;

                        let before_snapshot = self.get_finalized_height();
                        let start = std::time::Instant::now();
                        let timeout = tokio::time::Duration::from_secs(20);
                        loop {
                            let recovered_height = self.get_finalized_height();
                            if recovered_height > before_snapshot {
                                tracing::info!(
                                    " Peer snapshot recovery advanced sync from {} to {}",
                                    before_snapshot,
                                    recovered_height
                                );
                                current = recovered_height;
                                break;
                            }
                            if start.elapsed() > timeout {
                                return Err(format!(
                                    "Peer snapshot recovery timed out after local replay divergence at height {}",
                                    failed_height
                                ));
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                        }
                    }
                    Err(e) => return Err(e),
                }
            } else {
                // Block not in local storage - request from peers
                // Request in chunks to avoid huge messages
                let chunk_size = 100u64;
                let chunk_end = (current + 1 + chunk_size).min(target_height);

                tracing::info!(
                    " Requesting blocks {}-{} from peers",
                    current + 1,
                    chunk_end
                );

                if let Err(e) = self.request_blocks_from_peer(current + 1, chunk_end).await {
                    tracing::warn!(" Failed to request blocks from peer: {}", e);
                    if e.contains("exceeds raw retention") {
                        let before_snapshot = self.get_finalized_height();
                        let start = std::time::Instant::now();
                        let timeout = tokio::time::Duration::from_secs(20);
                        loop {
                            let recovered_height = self.get_finalized_height();
                            if recovered_height > before_snapshot {
                                tracing::info!(
                                    " Peer snapshot recovery advanced sync from {} to {} after stale anchor fallback",
                                    before_snapshot,
                                    recovered_height
                                );
                                current = recovered_height;
                                break;
                            }
                            if start.elapsed() > timeout {
                                return Err(format!(
                                    "Peer snapshot recovery timed out after stale anchor fallback at height {}",
                                    current + 1
                                ));
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                        }
                    } else {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                    continue;
                }

                // Wait for response to be processed (blocks are applied in handle_sync_response)
                // Poll until we've advanced or timed out
                let start = std::time::Instant::now();
                let timeout = tokio::time::Duration::from_secs(30);

                loop {
                    let new_height = self.get_finalized_height();
                    if new_height >= chunk_end {
                        current = new_height;
                        break;
                    }
                    if start.elapsed() > timeout {
                        tracing::warn!(
                            " Sync timeout waiting for blocks {}-{}; requesting verified snapshot recovery",
                            current + 1,
                            chunk_end
                        );
                        self.request_snapshot_from_peer(target_height).await?;

                        let before_snapshot = self.get_finalized_height();
                        let snapshot_start = std::time::Instant::now();
                        let snapshot_timeout = tokio::time::Duration::from_secs(20);
                        loop {
                            let recovered_height = self.get_finalized_height();
                            if recovered_height > before_snapshot {
                                tracing::info!(
                                    " Peer snapshot recovery advanced sync from {} to {} after block wait timeout",
                                    before_snapshot,
                                    recovered_height
                                );
                                current = recovered_height;
                                break;
                            }
                            if snapshot_start.elapsed() > snapshot_timeout {
                                return Err(format!(
                                    "Sync timeout at height {} and peer snapshot recovery did not advance",
                                    current
                                ));
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                        }
                        break;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }

            if current % 100 == 0 {
                tracing::info!("Synced to height {}/{}", current, target_height);
            }
        }

        tracing::info!(" Sync complete at height {}", target_height);
        Ok(())
    }

    /// Handle batch request from peer (serve historical batches)
    pub async fn handle_batch_request(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<(crate::BatchHeader, crate::Batch)>, String> {
        let storage = self.storage.as_ref().ok_or("Storage not initialized")?;

        // Limit range
        let range = end_height.saturating_sub(start_height);
        if range > gp::get_u64(gp::PARAM_MAX_BATCH_RANGE) {
            return Err(format!(
                "Range too large: {} (max {})",
                range,
                gp::get_u64(gp::PARAM_MAX_BATCH_RANGE)
            ));
        }

        let mut batches = Vec::new();

        for height in start_height..=end_height {
            let header = storage
                .load_batch_header_by_height(height)
                .map_err(|e| format!("Failed to load header: {}", e))?
                .ok_or(format!("Header at height {} not found", height))?;

            let batch = storage
                .load_batch(height)
                .map_err(|e| format!("Failed to load batch: {}", e))?
                .ok_or(format!("Batch at height {} not found", height))?;

            batches.push((header, batch));
        }

        tracing::info!(
            " Serving {} batches ({} to {})",
            batches.len(),
            start_height,
            end_height
        );
        Ok(batches)
    }

    /// Handle sync request from peer (serve blocks by height range)
    pub async fn handle_sync_request(
        &self,
        from_height: u64,
        to_height: u64,
        anchor_height: u64,
        anchor_hash: [u8; 32],
    ) -> Result<Vec<(crate::BatchHeader, Vec<Transaction>, Vec<String>)>, String> {
        let storage = self.storage.as_ref().ok_or("Storage not initialized")?;

        if from_height == 0 || anchor_height.saturating_add(1) != from_height {
            return Err(format!(
                "Invalid sync anchor: anchor height {} does not precede request {}-{}",
                anchor_height, from_height, to_height
            ));
        }

        let range = to_height.saturating_sub(from_height);
        let max_range = gp::get_u64(gp::PARAM_MAX_BATCH_RANGE).max(100);
        if range > max_range {
            return Err(format!("Range too large: {} (max {})", range, max_range));
        }

        let my_height = self.get_finalized_height();
        if from_height > my_height {
            return Err(format!(
                "Requested height {} > my finalized height {}",
                from_height, my_height
            ));
        }

        let local_anchor = if anchor_height == 0 {
            Some([0u8; 32])
        } else {
            let blockchain = self.blockchain.read().await;
            storage
                .load_anchor_hash(anchor_height)
                .ok()
                .flatten()
                .or_else(|| {
                    blockchain
                        .get_batch_by_height_from_storage(anchor_height, storage)
                        .map(|h| h.batch_hash)
                })
                .or_else(|| {
                    blockchain
                        .get_batch_by_height(anchor_height)
                        .map(|h| h.batch_hash)
                })
                .or_else(|| {
                    blockchain
                        .get_canonical_tip()
                        .ok()
                        .filter(|tip| tip.height == anchor_height)
                        .map(|h| h.batch_hash)
                })
        };
        let Some(local_anchor_hash) = local_anchor else {
            return Err(format!(
                "Missing requested sync anchor at height {}",
                anchor_height
            ));
        };
        if local_anchor_hash != anchor_hash {
            return Err(format!(
                "Sync anchor mismatch at height {}: requested {}, local {}",
                anchor_height,
                hex::encode(anchor_hash),
                hex::encode(local_anchor_hash)
            ));
        }

        let actual_to = to_height.min(my_height);
        if actual_to < to_height {
            return Err(format!(
                "Cannot serve full sync range {}-{}: finalized height is {}",
                from_height, to_height, my_height
            ));
        }

        let mut blocks = Vec::new();
        let mut expected_parent = anchor_hash;

        for height in from_height..=actual_to {
            match storage.load_batch_header_by_height(height) {
                Ok(Some(header)) => {
                    if header.parent_hash != expected_parent {
                        return Err(format!(
                            "Stored block {} does not extend requested anchor/chain: expected parent {}, got {}",
                            height,
                            hex::encode(expected_parent),
                            hex::encode(header.parent_hash)
                        ));
                    }
                    let batch = storage
                        .load_batch(height)
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let results = storage
                        .load_block_results(height)
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| vec!["unknown".to_string(); batch.len()]);
                    expected_parent = header.batch_hash;
                    blocks.push((header, batch, results));
                }
                _ => {
                    return Err(format!(
                        "Cannot serve sync range {}-{}: missing block {}",
                        from_height, to_height, height
                    ));
                }
            }
        }

        let expected_len = actual_to.saturating_sub(from_height).saturating_add(1) as usize;
        if blocks.len() != expected_len {
            return Err(format!(
                "Cannot serve complete sync range {}-{}: have {} of {} blocks",
                from_height,
                to_height,
                blocks.len(),
                expected_len
            ));
        }

        tracing::info!(
            " Serving anchored sync request: {} blocks ({} to {}, anchor {}:{})",
            blocks.len(),
            from_height,
            actual_to,
            anchor_height,
            hex::encode(&anchor_hash[..8])
        );
        Ok(blocks)
    }

    /// Spawn the autonomous block repairer background loop.
    pub fn spawn_block_repairer(self: &Arc<Self>) {
        if let Some(ref repairer) = self.block_repairer {
            repairer.set_consensus(Arc::downgrade(self));
            repairer.clone().spawn(self.finalized_height.clone());
        }
    }

    /// Handle sync response from peer (apply received blocks)
    pub async fn handle_sync_response_from_peer(
        &self,
        peer_pubkey: Vec<u8>,
        request_from_height: u64,
        request_to_height: u64,
        request_anchor_height: u64,
        request_anchor_hash: [u8; 32],
        responder_height: u64,
        blocks: Vec<(crate::BatchHeader, Vec<Transaction>, Vec<String>)>,
    ) {
        if blocks.is_empty() {
            return;
        }

        let first_height = blocks.first().map(|(h, _, _)| h.height).unwrap_or(0);
        let last_height = blocks
            .last()
            .map(|(h, _, _)| h.height)
            .unwrap_or(first_height);
        self.update_peer_height(peer_pubkey.clone(), responder_height)
            .await;

        let response_headers: Vec<_> = blocks.iter().map(|(header, _, _)| header.clone()).collect();
        if let Err(e) = validate_sync_response_shape(
            request_from_height,
            request_to_height,
            request_anchor_height,
            request_anchor_hash,
            responder_height,
            &response_headers,
        ) {
            tracing::warn!(
                " Dropping malformed SyncResponse {}-{} from {} for request {}-{}: {}",
                first_height,
                last_height,
                hex::encode(&peer_pubkey[..8]),
                request_from_height,
                request_to_height,
                e
            );
            return;
        }

        let local_anchor_hash = if request_anchor_height == 0 {
            Some([0u8; 32])
        } else {
            let blockchain = self.blockchain.read().await;
            self.storage
                .as_ref()
                .and_then(|storage| {
                    storage
                        .load_anchor_hash(request_anchor_height)
                        .ok()
                        .flatten()
                })
                .or_else(|| {
                    self.storage.as_ref().and_then(|storage| {
                        blockchain
                            .get_batch_by_height_from_storage(request_anchor_height, storage)
                            .map(|h| h.batch_hash)
                    })
                })
                .or_else(|| {
                    blockchain
                        .get_batch_by_height(request_anchor_height)
                        .map(|h| h.batch_hash)
                })
                .or_else(|| {
                    blockchain
                        .get_canonical_tip()
                        .ok()
                        .filter(|tip| tip.height == request_anchor_height)
                        .map(|h| h.batch_hash)
                })
        };
        if let Some(hash) = local_anchor_hash {
            if hash != request_anchor_hash {
                tracing::warn!(
                    " Dropping SyncResponse {}-{} from {}: echoed anchor {} at height {} is not local canonical {}",
                    first_height,
                    last_height,
                    hex::encode(&peer_pubkey[..8]),
                    hex::encode(&request_anchor_hash[..8]),
                    request_anchor_height,
                    hex::encode(&hash[..8])
                );
                return;
            }
        } else {
            tracing::warn!(
                " Dropping SyncResponse {}-{} from {}: local anchor height {} is missing",
                first_height,
                last_height,
                hex::encode(&peer_pubkey[..8]),
                request_anchor_height
            );
            return;
        }

        let current_height = self.get_finalized_height();
        if current_height > request_anchor_height {
            tracing::debug!(
                " Dropping obsolete SyncResponse {}-{} from {}: local height advanced to {} past requested anchor {}",
                first_height,
                last_height,
                hex::encode(&peer_pubkey[..8]),
                current_height,
                request_anchor_height
            );
            return;
        }

        if current_height == request_anchor_height && request_anchor_height > 0 {
            let canonical_tip = self
                .blockchain
                .read()
                .await
                .get_canonical_tip()
                .ok()
                .map(|tip| tip.batch_hash);
            if canonical_tip != Some(request_anchor_hash) {
                let anchor_header = self.storage.as_ref().and_then(|storage| {
                    storage
                        .load_batch_header_by_height(request_anchor_height)
                        .ok()
                        .flatten()
                });
                if let Some(anchor_header) = anchor_header {
                    if anchor_header.batch_hash == request_anchor_hash {
                        let total_stake: u64 = self
                            .state
                            .load()
                            .staking
                            .get_active_validators()
                            .values()
                            .sum();
                        self.blockchain
                            .write()
                            .await
                            .seed_canonical_tip(anchor_header, total_stake);
                        tracing::warn!(
                            " Reseeded canonical sync anchor at height {} ({}) before applying response {}-{}",
                            request_anchor_height,
                            hex::encode(&request_anchor_hash[..8]),
                            first_height,
                            last_height
                        );
                    }
                }
            }
        }

        if first_height == current_height.saturating_add(1) {
            let canonical_tip = self
                .blockchain
                .read()
                .await
                .get_canonical_tip()
                .ok()
                .map(|tip| tip.batch_hash);
            if let Some(local_tip_hash) = canonical_tip {
                let first_parent = blocks[0].0.parent_hash;
                if first_parent != local_tip_hash {
                    tracing::warn!(
                        " Dropping SyncResponse {}-{} from {}: first parent {} does not extend local tip {} at height {}",
                        first_height,
                        last_height,
                        hex::encode(&peer_pubkey[..8]),
                        hex::encode(&first_parent[..8]),
                        hex::encode(&local_tip_hash[..8]),
                        current_height
                    );
                    return;
                }
            }
        } else if first_height > current_height.saturating_add(1) {
            tracing::warn!(
                " Dropping SyncResponse {}-{} from {}: gap from local height {}",
                first_height,
                last_height,
                hex::encode(&peer_pubkey[..8]),
                current_height
            );
            return;
        }

        tracing::info!(
            " Received {} sync blocks {}-{} from {} (peer height {})",
            blocks.len(),
            first_height,
            last_height,
            hex::encode(&peer_pubkey[..8]),
            responder_height
        );

        for (header, batch, results) in blocks {
            let height = header.height;
            let current = self.get_finalized_height();

            if let Some(ref repairer) = self.block_repairer {
                if repairer.has_pending(height).await {
                    let repairer = repairer.clone();
                    let h = header.clone();
                    let b = batch.clone();
                    let r = results.clone();
                    tokio::spawn(async move {
                        repairer.deliver_repaired_block(h, b, r).await;
                    });
                }
            }

            if height < current {
                tracing::debug!(
                    " Ignoring stale sync block {} from {}; finalized height is {}",
                    height,
                    hex::encode(&peer_pubkey[..8]),
                    current
                );
                continue;
            }

            if height == current {
                let canonical_hash = self
                    .blockchain
                    .read()
                    .await
                    .get_canonical_tip()
                    .ok()
                    .map(|tip| tip.batch_hash);
                if let Some(hash) = canonical_hash {
                    if hash != header.batch_hash {
                        tracing::warn!(
                            " Ignoring conflicting anchor at height {} from {} (local {}, peer {})",
                            height,
                            hex::encode(&peer_pubkey[..8]),
                            hex::encode(&hash[..8]),
                            hex::encode(&header.batch_hash[..8])
                        );
                        continue;
                    }
                }

                let total_stake: u64 = self
                    .state
                    .load()
                    .staking
                    .get_active_validators()
                    .values()
                    .sum();
                self.blockchain
                    .write()
                    .await
                    .seed_canonical_tip(header.clone(), total_stake);
                if let Some(ref storage) = self.storage {
                    let _ = storage.save_batch_header(&header);
                }
                tracing::info!(" Seeded anchor header at height {}", height);
                continue;
            }

            let peer_batch_hash = header.batch_hash;
            match self.apply_sync_batch(header, batch).await {
                Ok(()) => {
                    tracing::debug!(" Applied sync block at height {}", height);
                }
                Err(e) => {
                    tracing::warn!(
                        " Failed to apply sync block from {}: {}",
                        hex::encode(&peer_pubkey[..8]),
                        e
                    );
                    if e.contains("State root mismatch")
                        || e.contains("Timestamp must be >= parent timestamp")
                    {
                        tracing::warn!(
                            " Local sync divergence at height {} - requesting peer snapshot recovery",
                            height
                        );
                        if let Err(snapshot_err) = self.request_snapshot_from_peer(height).await {
                            tracing::warn!(
                                " Peer snapshot recovery request failed: {}",
                                snapshot_err
                            );
                        }
                    } else if e.contains("commitment mismatch")
                        || e.contains("Parent hash mismatch")
                    {
                        tracing::warn!(
                            " Local state diverged at height {} - handing off to block repairer",
                            height
                        );
                        if let Some(ref repairer) = self.block_repairer {
                            let our_tip = {
                                self.blockchain
                                    .read()
                                    .await
                                    .get_canonical_tip()
                                    .map(|h| h.batch_hash)
                                    .unwrap_or([0u8; 32])
                            };
                            repairer.recover_divergence(our_tip, peer_batch_hash).await;
                        }
                    }
                    break;
                }
            }
        }
    }

    async fn request_blocks_from_peer(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<(), String> {
        let max_range = gp::get_u64(gp::PARAM_MAX_BATCH_RANGE).max(100);
        let requested_to_height = to_height;
        if from_height == 0 {
            return Err(
                "Cannot request sync blocks from height 0 without a parent anchor".to_string(),
            );
        }
        let (anchor_height, anchor_hash) = if from_height == 1 {
            (0, [0u8; 32])
        } else {
            let blockchain = self.blockchain.read().await;
            let mut candidate = from_height - 1;
            loop {
                let hash = self
                    .storage
                    .as_ref()
                    .and_then(|storage| storage.load_anchor_hash(candidate).ok().flatten())
                    .or_else(|| {
                        self.storage
                            .as_ref()
                            .and_then(|storage| {
                                blockchain.get_batch_by_height_from_storage(candidate, storage)
                            })
                            .map(|h| h.batch_hash)
                    })
                    .or_else(|| {
                        blockchain
                            .get_batch_by_height(candidate)
                            .map(|h| h.batch_hash)
                    })
                    .or_else(|| {
                        blockchain
                            .get_canonical_tip()
                            .ok()
                            .filter(|tip| tip.height == candidate)
                            .map(|h| h.batch_hash)
                    });
                if let Some(hash) = hash {
                    break (candidate, hash);
                }
                if candidate == 0 {
                    break (0, [0u8; 32]);
                }
                candidate -= 1;
            }
        };
        let request_from_height = anchor_height + 1;
        if request_from_height != from_height {
            let fallback_gap = from_height.saturating_sub(request_from_height);
            if fallback_gap > RAW_BLOCK_RETENTION {
                tracing::info!(
                    " Local sync anchor fallback gap {} exceeds raw retention {}; requesting snapshot recovery to {}",
                    fallback_gap,
                    RAW_BLOCK_RETENTION,
                    requested_to_height
                );
                if let Err(e) = self.request_snapshot_from_peer(requested_to_height).await {
                    tracing::warn!(" Failed to request snapshot recovery: {}", e);
                }
                return Err(format!(
                    "Local sync anchor fallback gap {} exceeds raw retention {}",
                    fallback_gap, RAW_BLOCK_RETENTION
                ));
            }
            tracing::warn!(
                "Falling back sync anchor from height {} to {}; requesting {}-{}",
                from_height.saturating_sub(1),
                anchor_height,
                request_from_height,
                requested_to_height
            );
        }
        let to_height = request_from_height
            .saturating_add(max_range)
            .min(requested_to_height);
        if to_height < requested_to_height {
            tracing::info!(
                " Capping sync request {}-{} to {}-{} (max range {})",
                request_from_height,
                requested_to_height,
                request_from_height,
                to_height,
                max_range
            );
        }

        let msg = P2PMessage::SyncRequest {
            from_height: request_from_height,
            to_height,
            anchor_height,
            anchor_hash,
        };
        let data = postcard::to_allocvec(&msg)
            .map_err(|e| format!("Failed to serialize sync request: {}", e))?;

        let peer_senders = self.peer_senders.read().await;
        if peer_senders.is_empty() {
            return Err(format!(
                "No connected peers available for block sync {}-{}",
                request_from_height, to_height
            ));
        }

        let sync_mgr = self.sync_manager.read().await;
        let mut height_counts: HashMap<u64, usize> = HashMap::new();
        for info in sync_mgr
            .peer_heights
            .values()
            .filter(|info| info.height >= to_height)
        {
            *height_counts.entry(info.height).or_default() += 1;
        }
        let corroborated_height = height_counts
            .iter()
            .filter(|(_, count)| **count >= 2)
            .map(|(height, _)| *height)
            .max();

        let mut candidates: Vec<(Vec<u8>, tokio::sync::mpsc::Sender<Vec<u8>>, u64)> = Vec::new();
        let mut seen = HashSet::new();
        if let Some(height) = corroborated_height {
            for (pk, info) in sync_mgr
                .peer_heights
                .iter()
                .filter(|(_, info)| info.height == height)
            {
                if let Some(sender) = peer_senders.get(pk) {
                    candidates.push((pk.clone(), sender.clone(), info.height));
                    seen.insert(pk.clone());
                }
            }
        }

        let mut remaining: Vec<_> = sync_mgr
            .peer_heights
            .iter()
            .filter(|(_, info)| info.height >= to_height)
            .filter_map(|(pk, info)| {
                if seen.contains(pk) {
                    None
                } else {
                    peer_senders
                        .get(pk)
                        .map(|sender| (pk.clone(), sender.clone(), info.height))
                }
            })
            .collect();
        remaining.sort_by(|a, b| b.2.cmp(&a.2));
        candidates.extend(remaining);

        if candidates.is_empty() {
            candidates.extend(
                peer_senders
                    .iter()
                    .map(|(pk, sender)| (pk.clone(), sender.clone(), 0)),
            );
        }
        drop(sync_mgr);
        drop(peer_senders);

        let max_fanout = 3usize;
        let mut sent = 0usize;
        let mut full = 0usize;
        let mut targets = Vec::new();
        for (peer_pk, sender, height) in candidates.into_iter().take(max_fanout) {
            match sender.try_send(data.clone()) {
                Ok(()) => {
                    sent += 1;
                    targets.push(format!("{}@{}", hex::encode(&peer_pk[..8]), height));
                }
                Err(_) => {
                    full += 1;
                }
            }
        }

        if sent == 0 {
            return Err(format!(
                "Failed to send sync request {}-{}: {} selected peer queues full",
                request_from_height, to_height, full
            ));
        }

        tracing::info!(
            " Requesting blocks {}-{} from {} peer(s): {}",
            request_from_height,
            to_height,
            sent,
            targets.join(",")
        );
        Ok(())
    }

    /// Check if node is syncing
    pub async fn is_syncing(&self) -> bool {
        *self.is_syncing.read().await
    }

    // ========== SLASHING SYSTEM ==========

    /// Detect and slash validators who signed both sides of a fork (equivocation)
    async fn detect_and_slash_equivocation(
        &self,
        blockchain: &crate::BlockChain,
        old_tip: [u8; 32],
        new_tip: [u8; 32],
        common_ancestor: [u8; 32],
    ) {
        // Get both chains from common ancestor
        let old_chain = blockchain.get_chain_between(common_ancestor, old_tip);
        let new_chain = blockchain.get_chain_between(common_ancestor, new_tip);

        // Build map of height -> (batch_hash, header) for each chain
        let mut old_blocks: std::collections::HashMap<u64, ([u8; 32], crate::BatchHeader)> =
            std::collections::HashMap::new();
        let mut new_blocks: std::collections::HashMap<u64, ([u8; 32], crate::BatchHeader)> =
            std::collections::HashMap::new();

        for header in old_chain {
            old_blocks.insert(header.height, (header.batch_hash, header));
        }

        for header in new_chain {
            new_blocks.insert(header.height, (header.batch_hash, header));
        }

        // Find heights where both chains have different blocks (equivocation)
        for (height, (old_hash, old_header)) in &old_blocks {
            if let Some((new_hash, new_header)) = new_blocks.get(height) {
                if old_hash != new_hash {
                    // Equivocation detected!
                    tracing::warn!(
                        "  Equivocation at height {}: {} vs {}",
                        height,
                        hex::encode(&old_hash[..8]),
                        hex::encode(&new_hash[..8])
                    );

                    // Check if same validator signed both
                    if old_header.leader_pubkey == new_header.leader_pubkey
                        && !old_header.leader_pubkey.is_empty()
                    {
                        tracing::error!(
                            " DOUBLE-SIGN DETECTED: Validator {} signed both forks at height {}",
                            hex::encode(&old_header.leader_pubkey[..8]),
                            height
                        );

                        // Create evidence
                        let evidence = DoubleSignEvidence {
                            height: *height,
                            batch_hash_1: *old_hash,
                            batch_hash_2: *new_hash,
                            signature_1: old_header.leader_signature.clone(),
                            signature_2: new_header.leader_signature.clone(),
                            validator_pubkey: old_header.leader_pubkey.clone(),
                        };

                        // Slash the validator
                        if let Err(e) = self.detect_and_slash_misbehavior(evidence).await {
                            tracing::error!("Failed to slash equivocating validator: {}", e);
                        }
                    }
                }
            }
        }
    }

    fn slash_validator(
        &self,
        validator_pubkey: &[u8],
        reason: SlashReason,
        evidence: Option<DoubleSignEvidence>,
    ) -> Result<u64, String> {
        let mut state = self.state.load_full();
        let state_mut = Arc::make_mut(&mut state);
        let outcome = state_mut
            .staking
            .slash_validator(validator_pubkey, reason, evidence)?;
        self.state.store(state);
        Ok(outcome.amount)
    }

    /// Slash validator for double-signing.
    pub fn slash_for_double_sign(
        &self,
        validator_pubkey: &[u8],
        evidence: DoubleSignEvidence,
    ) -> Result<u64, String> {
        let slashed =
            self.slash_validator(validator_pubkey, SlashReason::DoubleSign, Some(evidence))?;
        tracing::warn!(
            "  Slashed {} for double-signing ({}%)",
            hex::encode(&validator_pubkey[..8]),
            gp::get_u64(gp::PARAM_SLASH_PERCENTAGE)
        );
        Ok(slashed)
    }

    /// Slash validator for invalid state root.
    ///
    /// The caller MUST supply the validator's own signed attestation that contains
    /// the wrong state root as `evidence_attestation`.  This prevents a malicious
    /// leader from slashing a validator that never attested or attested correctly.
    /// The attestation signature was already verified during attestation collection,
    /// so it serves as cryptographic proof that the validator committed to the wrong root.
    pub fn slash_for_invalid_state(
        &self,
        validator_pubkey: &[u8],
        evidence_attestation: &Attestation,
        finalized_state_root: &[u8; 32],
    ) -> Result<u64, String> {
        // Guard: only slash if the attestation belongs to this validator.
        if evidence_attestation.validator_pubkey != validator_pubkey {
            return Err("Attestation does not belong to the validator being slashed".to_string());
        }
        // Guard: only slash if the attestation actually contains a wrong state root.
        if &evidence_attestation.state_root == finalized_state_root {
            return Err("Attestation state root matches finalized root - no slash".to_string());
        }
        let slashed =
            self.slash_validator(validator_pubkey, SlashReason::InvalidStateRoot, None)?;
        tracing::warn!(
            "  Slashed {} for invalid state root ({}%)",
            hex::encode(&validator_pubkey[..8]),
            gp::get_u64(gp::PARAM_SLASH_PERCENTAGE)
        );
        Ok(slashed)
    }

    /// Iterate collected attestations and slash every validator whose signed
    /// attestation contains a state root that differs from `finalized_state_root`.
    /// Validators that did not attest are NOT slashed here (downtime is separate).
    pub fn slash_validators_with_wrong_state_root(
        &self,
        _attestations: &[Attestation],
        _finalized_state_root: &[u8; 32],
    ) {
        // Disabled on devnet - state root divergence is a known bug under investigation
    }

    /// Slash validator for invalid snapshot.
    pub fn slash_for_invalid_snapshot(&self, validator_pubkey: &[u8]) -> Result<u64, String> {
        let slashed = self.slash_validator(validator_pubkey, SlashReason::InvalidSnapshot, None)?;
        tracing::warn!(
            "  Slashed {} for invalid snapshot ({}%)",
            hex::encode(&validator_pubkey[..8]),
            gp::get_u64(gp::PARAM_SLASH_PERCENTAGE)
        );
        Ok(slashed)
    }

    /// Slash validator for censorship.
    pub fn slash_for_censorship(&self, validator_pubkey: &[u8]) -> Result<u64, String> {
        let slashed = self.slash_validator(validator_pubkey, SlashReason::Censorship, None)?;
        tracing::warn!(
            "  Slashed {} for censorship ({}%)",
            hex::encode(&validator_pubkey[..8]),
            gp::get_u64(gp::PARAM_CENSORSHIP_SLASH_PERCENTAGE)
        );
        Ok(slashed)
    }

    /// Detect and slash misbehavior.
    /// Evidence verification is delegated to `staking::slash_validator` so all
    /// slashing paths use one canonical verifier.
    pub async fn detect_and_slash_misbehavior(
        &self,
        evidence: DoubleSignEvidence,
    ) -> Result<(), String> {
        if evidence.batch_hash_1 == evidence.batch_hash_2 {
            return Err("Evidence must show two different batches".to_string());
        }

        let validator_pubkey = evidence.validator_pubkey.clone();
        let _ = self.slash_for_double_sign(&validator_pubkey, evidence)?;

        tracing::warn!(
            "  Double-sign evidence verified and slashed: {}",
            hex::encode(&validator_pubkey[..8])
        );

        Ok(())
    }
}
