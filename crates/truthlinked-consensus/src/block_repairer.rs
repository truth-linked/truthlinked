//! Autonomous Block Repairer
//!
//! Runs as a background task. Continuously scans finalized storage for:
//!   1. Missing blocks  - batch or header key absent
//!   2. Corrupt blocks  - batch present but fails deserialization
//!   3. Corrupt headers - header present but fails deserialization
//!   4. Incomplete index - tx index count mismatch
//!   5. Missing anchor  - snapshot loaded but no header at that height
//!      (causes parent_hash mismatch when the next block arrives)
//!
//! For each problem it:
//!   a. Deletes the corrupt/incomplete data
//!   b. Requests the block from a peer that has height >= that block
//!   c. Waits for the SyncResponse (with timeout + retry on different peer)
//!   d. Re-stores atomically via save_block
//!
//! The loop runs every SCAN_INTERVAL_SECS, scanning only finalized blocks newer
//! than the latest trusted snapshot. Snapshot-covered history is intentionally
//! allowed to be absent and must not be treated as corruption.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::{oneshot, RwLock};
use tracing::{debug, error, info, warn};

use crate::persistence::Storage;
use crate::streaming_consensus::P2PMessage;
use truthlinked_core::pq_execution::Transaction;

const SCAN_INTERVAL_SECS: u64 = 30;
/// How many blocks behind finalized tip to scan on each pass.
const LOOKBACK: u64 = 2000;
/// How long to wait for a peer to respond with blocks.
const FETCH_TIMEOUT_SECS: u64 = 15;
/// Max retries per corrupt block before giving up this pass.
const MAX_RETRIES: usize = 3;

pub struct BlockRepairer {
    storage: Arc<Storage>,
    peer_senders: Arc<RwLock<HashMap<Vec<u8>, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    sync_manager: Arc<RwLock<crate::sync::SyncManager>>,
    /// Per-height oneshot channels: repair_block registers a sender before issuing
    /// the SyncRequest; the SyncResponse handler calls deliver_repaired_block to
    /// resolve it. This eliminates the shared-channel race where concurrent repairs
    /// could steal each other's responses.
    pending: tokio::sync::Mutex<
        HashMap<
            u64,
            oneshot::Sender<(
                crate::blockchain::BatchHeader,
                Vec<Transaction>,
                Vec<String>,
            )>,
        >,
    >,
    /// Weak reference to consensus - set after construction to avoid circular Arc.
    consensus: std::sync::RwLock<Option<Weak<crate::streaming_consensus::StreamingConsensus>>>,
}

impl BlockRepairer {
    pub fn new(
        storage: Arc<Storage>,
        peer_senders: Arc<RwLock<HashMap<Vec<u8>, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
        sync_manager: Arc<RwLock<crate::sync::SyncManager>>,
    ) -> Self {
        Self {
            storage,
            peer_senders,
            sync_manager,
            pending: tokio::sync::Mutex::new(HashMap::new()),
            consensus: std::sync::RwLock::new(None),
        }
    }

    /// Wire the consensus reference after construction (avoids circular Arc).
    pub fn set_consensus(&self, consensus: Weak<crate::streaming_consensus::StreamingConsensus>) {
        if let Ok(mut guard) = self.consensus.write() {
            *guard = Some(consensus);
        }
    }

    /// Returns true if a repair is actively waiting for this height.
    pub async fn has_pending(&self, height: u64) -> bool {
        self.pending.lock().await.contains_key(&height)
    }

    /// Called by the SyncResponse handler to deliver a repaired block.
    /// Routes to the correct waiter by height - no cross-repair interference.
    pub async fn deliver_repaired_block(
        &self,
        header: crate::blockchain::BatchHeader,
        batch: Vec<Transaction>,
        results: Vec<String>,
    ) {
        let mut pending = self.pending.lock().await;
        if let Some(tx) = pending.remove(&header.height) {
            let _ = tx.send((header, batch, results));
        }
    }

    /// Called by the sync loop when a parent hash mismatch is detected.
    ///
    /// Implements the Geth `reorg()` + `recoverAncestors()` pattern:
    ///   1. Walk back our stored headers to find the common ancestor with the peer's chain
    ///   2. Call handle_fork_switch(our_tip, peer_tip) - rolls back state and re-executes
    ///      from the common ancestor using blocks already in storage. No wipe, no re-download.
    ///
    /// This is fully autonomous - the node heals itself silently. Only logged.
    pub async fn recover_divergence(&self, our_tip_hash: [u8; 32], peer_tip_hash: [u8; 32]) {
        let consensus = match self
            .consensus
            .read()
            .ok()
            .and_then(|g| g.as_ref().and_then(|w| w.upgrade()))
        {
            Some(c) => c,
            None => {
                warn!(
                    "BlockRepairer: divergence detected but consensus not wired - cannot self-heal"
                );
                return;
            }
        };

        info!(
            "BlockRepairer: state divergence detected - our_tip={} peer_tip={} - attempting self-heal (Geth reorg pattern)",
            hex::encode(&our_tip_hash[..8]),
            hex::encode(&peer_tip_hash[..8])
        );

        match consensus
            .handle_fork_switch(our_tip_hash, peer_tip_hash)
            .await
        {
            Ok(()) => {
                info!("BlockRepairer: self-heal complete - state restored to canonical chain")
            }
            Err(e) => {
                warn!("BlockRepairer: self-heal via fork switch failed: {} - falling back to snapshot sync", e);
                let our_height = consensus.get_finalized_height();
                if let Err(e2) = consensus.request_snapshot_from_peer(our_height).await {
                    error!("BlockRepairer: snapshot fallback also failed: {}", e2);
                }
            }
        }
    }

    /// Spawn the background repair loop. Returns immediately.
    pub fn spawn(self: Arc<Self>, finalized_height: Arc<std::sync::atomic::AtomicU64>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(SCAN_INTERVAL_SECS)).await;
                let tip = finalized_height.load(std::sync::atomic::Ordering::SeqCst);
                if tip < 2 {
                    continue;
                }
                let snapshot_height = self.latest_snapshot_height();
                if snapshot_height.is_some_and(|height| height >= tip) {
                    debug!(
                        "Block repair skipped: latest snapshot covers finalized tip {}",
                        tip
                    );
                    continue;
                }
                let snapshot_floor = snapshot_height
                    .and_then(|height| height.checked_add(1))
                    .unwrap_or(1);
                let from = tip.saturating_sub(LOOKBACK).max(snapshot_floor).max(1);
                self.run_pass(from, tip).await;
            }
        });
    }

    fn latest_snapshot_height(&self) -> Option<u64> {
        self.storage
            .load_latest_snapshot()
            .ok()
            .flatten()
            .map(|snapshot| snapshot.height)
    }

    /// One repair pass over [from, tip].
    async fn run_pass(&self, from: u64, tip: u64) {
        let problems = self.detect_problems(from, tip);
        if problems.is_empty() {
            debug!("Block repair [{}-{}]: all healthy", from, tip);
            return;
        }
        info!(
            "Block repair [{}-{}]: {} problems detected",
            from,
            tip,
            problems.len()
        );

        for height in problems {
            self.repair_block(height).await;
        }
    }

    /// Scan [from, tip] and return heights that need repair.
    /// Uses storage key scans plus one deserialize attempt per block - no bulk RAM load.
    fn detect_problems(&self, from: u64, tip: u64) -> Vec<u64> {
        let mut bad = Vec::new();

        let presence = self.storage.introspect_block_range(from, tip);
        for p in presence {
            if !p.has_header || !p.has_batch {
                bad.push(p.height);
                continue;
            }
            // Try to deserialize the header - catches truncated header writes
            if let Err(_) = self.storage.load_batch_header_by_height(p.height) {
                warn!("Corrupt header at height {} - will re-fetch", p.height);
                bad.push(p.height);
                continue;
            }
            // Try to deserialize the batch - catches truncated batch writes
            if let Err(_) = self.storage.load_batch(p.height) {
                warn!("Corrupt batch at height {} - will re-fetch", p.height);
                bad.push(p.height);
                continue;
            }
            // Tx index integrity (key count only)
            let (stored, indexed, ok) = self.storage.verify_tx_index_integrity(p.height);
            if !ok {
                warn!(
                    "Block {} tx index mismatch (stored={} indexed={}) - will re-index",
                    p.height, stored, indexed
                );
                bad.push(p.height);
            }
        }
        bad
    }

    /// Delete corrupt data for `height` and re-fetch from a peer.
    async fn repair_block(&self, height: u64) {
        if self
            .latest_snapshot_height()
            .is_some_and(|snapshot_height| height <= snapshot_height)
        {
            debug!(
                "Skipping repair for block {} covered by latest snapshot",
                height
            );
            return;
        }

        // Do not delete canonical records before a verified replacement is ready.
        // A failed repair must leave the local anchor intact so later checkpoint
        // recovery still has something to compare against.

        let mut requested_repair = false;
        for attempt in 0..MAX_RETRIES {
            let peer = self.pick_peer(height, attempt).await;
            let Some(sender) = peer else {
                debug!(
                    "Deferring repair for block {}: no peer has reached that height yet (attempt {})",
                    height,
                    attempt + 1
                );
                break;
            };

            // Register a oneshot receiver *before* sending the request so the
            // response can never arrive before we're ready to receive it.
            let (tx, rx) = oneshot::channel();
            self.pending.lock().await.insert(height, tx);

            let Some(anchor_height) = height.checked_sub(1) else {
                warn!("Cannot repair genesis block via anchored sync request");
                self.pending.lock().await.remove(&height);
                break;
            };
            let anchor_hash = if anchor_height == 0 {
                Some([0u8; 32])
            } else {
                self.storage
                    .load_batch_header_by_height(anchor_height)
                    .ok()
                    .flatten()
                    .map(|header| header.batch_hash)
            };
            let Some(anchor_hash) = anchor_hash else {
                warn!(
                    "Cannot repair block {}: missing local anchor at height {}",
                    height, anchor_height
                );
                self.pending.lock().await.remove(&height);
                break;
            };
            let msg = P2PMessage::SyncRequest {
                from_height: height,
                to_height: height,
                anchor_height,
                anchor_hash,
            };
            let Ok(data) = postcard::to_allocvec(&msg) else {
                self.pending.lock().await.remove(&height);
                break;
            };
            if sender.try_send(data).is_err() {
                self.pending.lock().await.remove(&height);
                continue;
            }
            requested_repair = true;

            match tokio::time::timeout(Duration::from_secs(FETCH_TIMEOUT_SECS), rx).await {
                Ok(Ok((header, batch, results))) => {
                    let name_registry = std::collections::HashMap::new();
                    match self
                        .storage
                        .save_block(&header, &batch, &results, &name_registry)
                    {
                        Ok(_) => {
                            info!("Repaired block {}", height);
                            return;
                        }
                        Err(e) => error!("Failed to store repaired block {}: {}", height, e),
                    }
                }
                Ok(Err(_)) => warn!("Repair channel closed for height {}", height),
                Err(_) => {
                    // Timeout - clean up the pending entry so it does not leak
                    self.pending.lock().await.remove(&height);
                    warn!(
                        "Timeout waiting for block {} (attempt {})",
                        height,
                        attempt + 1
                    );
                }
            }
        }
        if !requested_repair {
            debug!(
                "Deferred repair for block {} until an eligible peer is available",
                height
            );
            return;
        }
        warn!(
            "Failed to repair block {} after {} attempts",
            height, MAX_RETRIES
        );
    }

    /// Pick a peer with height >= needed_height, rotating on retries.
    async fn pick_peer(
        &self,
        needed_height: u64,
        skip: usize,
    ) -> Option<tokio::sync::mpsc::Sender<Vec<u8>>> {
        let peer_senders = self.peer_senders.read().await;
        let sync_mgr = self.sync_manager.read().await;

        let mut candidates: Vec<_> = sync_mgr
            .peer_heights
            .iter()
            .filter(|(_, info)| info.height >= needed_height)
            .filter_map(|(pk, _)| peer_senders.get(pk).cloned())
            .collect();

        if candidates.is_empty() {
            return None;
        }
        Some(candidates.remove(skip % candidates.len()))
    }
}
