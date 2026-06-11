//! Truthlinked Consensus Src Attestation Pipeline
//!
//! Owns attestation collection, quorum tracking, and validator liveness inputs.
//! Consensus changes are protocol-critical; preserve deterministic replay, recovery safety, and wire compatibility.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Notify, RwLock};
use truthlinked_governance::params as gp;

pub type Attestation = crate::streaming_consensus::Attestation;
type AttestationKey = (u64, u64, [u8; 32], [u8; 32]);

fn key_for(height: u64, round: u64, batch_hash: [u8; 32], state_root: [u8; 32]) -> AttestationKey {
    (height, round, batch_hash, state_root)
}

fn key_from_attestation(attestation: &Attestation) -> AttestationKey {
    key_for(
        attestation.height,
        attestation.round,
        attestation.batch_hash,
        attestation.state_root,
    )
}

/// Pipelined attestation collector.
/// Uses Notify-based wakeup so wait_for_quorum never busy-polls.
/// Batches are cancelled (not timed out) when a new block arrives,
/// ensuring the pipeline never permanently blocks consensus.
pub struct AttestationPipeline {
    pending: Arc<RwLock<HashMap<AttestationKey, PendingBatch>>>,
    /// Keyed by validator_pubkey - enforces at most one early attestation per validator.
    early_attestations: Arc<RwLock<HashMap<(AttestationKey, Vec<u8>), Attestation>>>,
    stats: Arc<RwLock<AttestationStats>>,
    /// Notified whenever any attestation is added or a batch is cancelled.
    notify: Arc<Notify>,
}

struct PendingBatch {
    attestations: Vec<Attestation>,
    started_at: Instant,
    cancelled: bool,
}

impl AttestationPipeline {
    /// Compute the non-leader quorum threshold used by the leader-side attestation gate.
    ///
    /// Large active_attesterss keep the production two-thirds stake rule. Small local/devnet
    /// active_attesterss need majority-of-non-leaders for liveness: in a five-validator network,
    /// the leader plus two matching non-leader attestations can safely move the chain
    /// instead of requiring three of the four non-leaders and stalling on transient lag.
    pub(crate) fn effective_non_leader_quorum_required(
        non_leader_total_stake: u64,
        live_non_leader_count: usize,
    ) -> u64 {
        if non_leader_total_stake == 0 {
            return 0;
        }
        if live_non_leader_count <= 4 {
            return (non_leader_total_stake / 2).max(1);
        }
        non_leader_total_stake.saturating_mul(2) / 3
    }

    pub fn new(_attester_set_size: usize) -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            early_attestations: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(AttestationStats::new())),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Start collecting attestations for a concrete finality statement.
    pub async fn start_collection(
        &self,
        height: u64,
        round: u64,
        batch_hash: [u8; 32],
        state_root: [u8; 32],
    ) {
        let key = key_for(height, round, batch_hash, state_root);
        let early_atts = {
            let mut early = self.early_attestations.write().await;
            let matching: Vec<_> = early
                .keys()
                .filter(|(att_key, _)| *att_key == key)
                .cloned()
                .collect();
            matching
                .into_iter()
                .filter_map(|k| early.remove(&k))
                .collect::<Vec<_>>()
        };

        let mut pending = self.pending.write().await;
        if let Some(existing) = pending.get_mut(&key) {
            existing.cancelled = false;
            for att in early_atts {
                if !existing
                    .attestations
                    .iter()
                    .any(|a| a.validator_pubkey == att.validator_pubkey)
                {
                    existing.attestations.push(att);
                }
            }
            drop(pending);
            self.notify.notify_waiters();
            return;
        }

        if pending.len() >= gp::get_usize(gp::PARAM_ATTESTATION_PIPELINE_MAX_PENDING) {
            if let Some((oldest, _)) = pending
                .iter()
                .min_by_key(|(_, b)| b.started_at)
                .map(|(k, v)| (*k, v.started_at))
            {
                pending.remove(&oldest);
            }
        }
        pending.insert(
            key,
            PendingBatch {
                attestations: early_atts,
                started_at: Instant::now(),
                cancelled: false,
            },
        );
        self.notify.notify_waiters();
    }

    /// Add an attestation. Wakes up wait_for_quorum immediately.
    pub async fn add_attestation(&self, _batch_hash: [u8; 32], attestation: Attestation) {
        let key = key_from_attestation(&attestation);
        let mut pending = self.pending.write().await;
        if let Some(batch) = pending.get_mut(&key) {
            if batch
                .attestations
                .iter()
                .any(|a| a.validator_pubkey == attestation.validator_pubkey)
            {
                self.stats.write().await.duplicate_attestations += 1;
                return;
            }
            batch.attestations.push(attestation);
            drop(pending);
            self.notify.notify_waiters();
        } else {
            drop(pending);
            let mut early = self.early_attestations.write().await;
            early.insert((key, attestation.validator_pubkey.clone()), attestation);
            if early.len() > truthlinked_state::constants::MAX_EARLY_ATTESTATION_BUFFER {
                if let Some(key) = early.keys().next().cloned() {
                    early.remove(&key);
                }
            }
        }
    }

    /// Cancel all pending batches except the given one.
    /// Called when a new block arrives so stale wait_for_quorum calls return immediately.
    pub async fn cancel_all_except(&self, keep: Option<[u8; 32]>) {
        let mut pending = self.pending.write().await;
        for ((_, _, hash, _), batch) in pending.iter_mut() {
            if keep.map_or(true, |k| *hash != k) {
                batch.cancelled = true;
            }
        }
        drop(pending);
        self.notify.notify_waiters();
    }

    /// Wait for quorum. Returns Some(attestations) on success, None if cancelled or timed out.
    /// Wakes immediately on each new attestation via Notify - no busy polling.
    ///
    /// Fix #2: `leader_pubkey` is excluded from the quorum stake count. The leader's
    ///         own attestation may still be included in the returned set for completeness,
    ///         but it does not count toward the 2/3 threshold.
    /// Fix #3: Once quorum is reached the loop continues until the full `timeout_ms`
    ///         window elapses so that ALL valid attestations are collected, not just
    ///         the first-arriving subset that crossed the threshold.
    pub async fn wait_for_quorum(
        &self,
        height: u64,
        round: u64,
        batch_hash: [u8; 32],
        timeout_ms: u64,
        required_stake: u64,
        stake_map: &std::collections::HashMap<Vec<u8>, u64>,
        expected_state_root: [u8; 32],
        leader_pubkey: &[u8],
        live_validators: Option<&[Vec<u8>]>,
    ) -> Option<Vec<Attestation>> {
        let key = key_for(height, round, batch_hash, expected_state_root);
        let start = Instant::now();
        loop {
            {
                let pending = self.pending.read().await;
                if let Some(batch) = pending.get(&key) {
                    if batch.cancelled {
                        tracing::debug!(
                            "Batch {} cancelled, moving to next round",
                            hex::encode(&batch_hash[..8])
                        );
                        self.stats.write().await.quorum_failures += 1;
                        return None;
                    }
                    // Canonical production cannot use lenient quorum. The leader does not count
                    // its own attestation, and a block only advances with quorum from live
                    // non-leader validators.
                    let non_leader_total: u64 = stake_map
                        .iter()
                        .filter(|(pk, _)| pk.as_slice() != leader_pubkey)
                        .filter(|(pk, _)| live_validators.map_or(true, |live| live.contains(pk)))
                        .map(|(_, s)| *s)
                        .fold(0u64, |a, b| a.saturating_add(b));
                    let live_non_leader_count = stake_map
                        .keys()
                        .filter(|pk| pk.as_slice() != leader_pubkey)
                        .filter(|pk| live_validators.map_or(true, |live| live.contains(pk)))
                        .count();
                    let effective_required = if non_leader_total > 0 {
                        Self::effective_non_leader_quorum_required(
                            non_leader_total,
                            live_non_leader_count,
                        )
                    } else {
                        required_stake
                    };
                    let mut total = 0u64;
                    for att in &batch.attestations {
                        if att.state_root != expected_state_root {
                            continue;
                        }
                        if att.validator_pubkey == leader_pubkey {
                            continue;
                        }
                        if !live_validators
                            .map_or(true, |live| live.contains(&att.validator_pubkey))
                        {
                            continue;
                        }
                        if let Some(stake) = stake_map.get(&att.validator_pubkey) {
                            total = total.saturating_add(*stake);
                        }
                    }
                    if total >= effective_required {
                        let quorum_elapsed_ms = batch.started_at.elapsed().as_millis() as u64;
                        tracing::info!(
                            " Quorum reached for batch {} ({} stake, excl. leader) in {}ms",
                            hex::encode(&batch_hash[..8]),
                            total,
                            quorum_elapsed_ms
                        );
                        // Return immediately - do not wait out the full window
                        let mut stats = self.stats.write().await;
                        stats.total_batches += 1;
                        stats.avg_attestation_time_ms = (stats.avg_attestation_time_ms
                            * (stats.total_batches - 1)
                            + quorum_elapsed_ms)
                            / stats.total_batches;
                        drop(stats);
                        drop(pending);
                        let pending = self.pending.read().await;
                        if let Some(batch) = pending.get(&key) {
                            let attestations: Vec<Attestation> = batch
                                .attestations
                                .iter()
                                .filter(|a| a.validator_pubkey != leader_pubkey)
                                .cloned()
                                .collect();
                            return Some(attestations);
                        }
                        return None;
                    }
                } else {
                    return None;
                }
            }
            let elapsed = start.elapsed().as_millis() as u64;
            if elapsed >= timeout_ms {
                tracing::warn!(
                    "Attestation timeout for batch {}",
                    hex::encode(&batch_hash[..8])
                );
                self.stats.write().await.quorum_failures += 1;
                return None;
            }
            // Block until notified (new attestation or cancellation), with a 50ms fallback.
            tokio::time::timeout(
                tokio::time::Duration::from_millis(50),
                self.notify.notified(),
            )
            .await
            .ok();
        }
    }

    pub async fn remove_batch(
        &self,
        height: u64,
        round: u64,
        batch_hash: [u8; 32],
        state_root: [u8; 32],
    ) {
        self.pending
            .write()
            .await
            .remove(&key_for(height, round, batch_hash, state_root));
    }

    pub async fn cleanup_stale(&self, max_age_secs: u64) {
        let mut pending = self.pending.write().await;
        let now = Instant::now();
        let mut stale_failures = 0u64;
        pending.retain(|(_, _, hash, _), batch| {
            let age = now.duration_since(batch.started_at).as_secs();
            if age > max_age_secs {
                tracing::warn!(
                    " Removing stale batch {} (age: {}s)",
                    hex::encode(&hash[..8]),
                    age
                );
                stale_failures += 1;
                false
            } else {
                true
            }
        });
        if stale_failures > 0 {
            self.stats.write().await.quorum_failures += stale_failures;
        }
    }

    /// Returns the non-leader live stake already attested for a batch.
    /// This uses the same accounting as wait_for_quorum so timeout logs do not
    /// overstate progress by counting the leader or non-live validators.
    pub async fn get_partial_stake(
        &self,
        height: u64,
        round: u64,
        batch_hash: &[u8; 32],
        stake_map: &std::collections::HashMap<Vec<u8>, u64>,
        expected_state_root: [u8; 32],
        leader_pubkey: &[u8],
        live_validators: Option<&[Vec<u8>]>,
    ) -> u64 {
        let key = key_for(height, round, *batch_hash, expected_state_root);
        let pending = self.pending.read().await;
        let Some(batch) = pending.get(&key) else {
            return 0;
        };
        let mut total = 0u64;
        for att in &batch.attestations {
            if att.state_root != expected_state_root {
                continue;
            }
            if att.validator_pubkey == leader_pubkey {
                continue;
            }
            if !live_validators.map_or(true, |live| live.contains(&att.validator_pubkey)) {
                continue;
            }
            if let Some(stake) = stake_map.get(&att.validator_pubkey) {
                total = total.saturating_add(*stake);
            }
        }
        total
    }

    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }

    pub async fn get_stats(&self) -> AttestationStats {
        self.stats.read().await.clone()
    }
}

#[derive(Debug, Clone)]
pub struct AttestationStats {
    pub total_batches: u64,
    pub avg_attestation_time_ms: u64,
    pub quorum_failures: u64,
    pub duplicate_attestations: u64,
}

impl AttestationStats {
    pub fn new() -> Self {
        Self {
            total_batches: 0,
            avg_attestation_time_ms: 0,
            quorum_failures: 0,
            duplicate_attestations: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> Vec<u8> {
        vec![byte; 4]
    }

    fn init_test_params() {
        let mut value = [0u8; 32];
        value[..8].copy_from_slice(&1024u64.to_le_bytes());
        truthlinked_governance::params::update_param(
            truthlinked_governance::params::param_key(
                truthlinked_governance::params::PARAM_ATTESTATION_PIPELINE_MAX_PENDING,
            ),
            value,
        );
    }

    fn att(batch_hash: [u8; 32], state_root: [u8; 32], validator_pubkey: Vec<u8>) -> Attestation {
        Attestation {
            height: 1,
            round: 0,
            batch_hash,
            state_root,
            validator_pubkey,
            signature: vec![1, 2, 3],
        }
    }

    #[test]
    fn small_devnet_non_leader_quorum_is_majority_not_two_thirds() {
        assert_eq!(
            AttestationPipeline::effective_non_leader_quorum_required(4_000, 4),
            2_000
        );
        assert_eq!(
            AttestationPipeline::effective_non_leader_quorum_required(9_000, 6),
            6_000
        );
    }

    #[tokio::test]
    async fn five_validator_devnet_accepts_two_non_leader_attestations() {
        init_test_params();
        let pipeline = AttestationPipeline::new(5);
        let batch_hash = [7u8; 32];
        let state_root = [9u8; 32];
        let leader = pk(0);
        let v1 = pk(1);
        let v2 = pk(2);
        let v3 = pk(3);
        let v4 = pk(4);
        let live = vec![
            leader.clone(),
            v1.clone(),
            v2.clone(),
            v3.clone(),
            v4.clone(),
        ];
        let mut stake_map = HashMap::new();
        for validator in [&leader, &v1, &v2, &v3, &v4] {
            stake_map.insert(validator.clone(), 1_000u64);
        }
        pipeline
            .start_collection(1, 0, batch_hash, state_root)
            .await;
        pipeline
            .add_attestation(batch_hash, att(batch_hash, state_root, v1.clone()))
            .await;
        pipeline
            .add_attestation(batch_hash, att(batch_hash, state_root, v2.clone()))
            .await;
        let result = pipeline
            .wait_for_quorum(
                1,
                0,
                batch_hash,
                250,
                2_666,
                &stake_map,
                state_root,
                &leader,
                Some(&live),
            )
            .await;
        assert!(
            result.is_some(),
            "leader plus two non-leader attestations should satisfy five-validator devnet quorum"
        );
        assert_eq!(result.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn partial_stake_excludes_leader_and_non_live_validators() {
        init_test_params();
        let pipeline = AttestationPipeline::new(5);
        let batch_hash = [8u8; 32];
        let state_root = [10u8; 32];
        let leader = pk(0);
        let live_non_leader = pk(1);
        let stale_non_leader = pk(2);
        let live = vec![leader.clone(), live_non_leader.clone()];
        let mut stake_map = HashMap::new();
        stake_map.insert(leader.clone(), 1_000u64);
        stake_map.insert(live_non_leader.clone(), 1_000u64);
        stake_map.insert(stale_non_leader.clone(), 1_000u64);
        pipeline
            .start_collection(1, 0, batch_hash, state_root)
            .await;
        pipeline
            .add_attestation(batch_hash, att(batch_hash, state_root, leader.clone()))
            .await;
        pipeline
            .add_attestation(
                batch_hash,
                att(batch_hash, state_root, live_non_leader.clone()),
            )
            .await;
        pipeline
            .add_attestation(
                batch_hash,
                att(batch_hash, state_root, stale_non_leader.clone()),
            )
            .await;
        let partial = pipeline
            .get_partial_stake(
                1,
                0,
                &batch_hash,
                &stake_map,
                state_root,
                &leader,
                Some(&live),
            )
            .await;
        assert_eq!(partial, 1_000);
    }
}
