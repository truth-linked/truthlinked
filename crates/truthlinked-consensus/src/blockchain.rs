//! Truthlinked Consensus Src Blockchain
//!
//! Owns canonical header indexing, fork tracking, and chain-tip selection.
//! Consensus changes are protocol-critical; preserve deterministic replay, recovery safety, and wire compatibility.

use crate::persistence::Storage;
use crate::streaming_consensus::Attestation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use truthlinked_core::pq_execution::Transaction;
use truthlinked_state::constants::MAX_HEADER_HISTORY;

// Moved to constants.rs

// Batch is just a list of transactions
pub type Batch = Vec<Transaction>;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PqFinalitySignature {
    pub validator_index: u32,
    pub validator_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqFinalityCertificate {
    pub version: u16,
    pub height: u64,
    pub round: u64,
    pub batch_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub signer_bitmap: Vec<u8>,
    pub signatures: Vec<PqFinalitySignature>,
    pub signature_root: [u8; 32],
    pub signed_stake: u64,
}

impl Default for PqFinalityCertificate {
    fn default() -> Self {
        Self::empty(0, 0, [0u8; 32], [0u8; 32])
    }
}

impl PqFinalityCertificate {
    pub const VERSION: u16 = 1;

    pub fn empty(height: u64, round: u64, batch_hash: [u8; 32], state_root: [u8; 32]) -> Self {
        Self {
            version: Self::VERSION,
            height,
            round,
            batch_hash,
            state_root,
            signer_bitmap: Vec::new(),
            signatures: Vec::new(),
            signature_root: Self::signature_root_for(&[]),
            signed_stake: 0,
        }
    }

    pub fn signer_count(&self) -> usize {
        self.signer_bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    pub fn compact_for_gossip(&self) -> Self {
        let mut compact = self.clone();
        compact.signatures.clear();
        compact
    }

    pub fn has_full_signatures(&self) -> bool {
        !self.signatures.is_empty()
    }

    pub fn bitmap_signed_stake(
        &self,
        active_attesters: &[Vec<u8>],
        stake_map: &HashMap<Vec<u8>, u64>,
        leader_pubkey: &[u8],
    ) -> Result<(usize, u64), String> {
        let mut canonical_attesters = active_attesters.to_vec();
        canonical_attesters.sort();
        canonical_attesters.dedup();

        let expected_bitmap_len = (canonical_attesters.len() + 7) / 8;
        if self.signer_bitmap.len() != expected_bitmap_len {
            return Err("PQ finality certificate bitmap length mismatch".to_string());
        }
        if canonical_attesters.len() % 8 != 0 && !self.signer_bitmap.is_empty() {
            let valid_bits = canonical_attesters.len() % 8;
            let tail_mask = (1u8 << valid_bits) - 1;
            if self.signer_bitmap[self.signer_bitmap.len() - 1] & !tail_mask != 0 {
                return Err(
                    "PQ finality certificate bitmap has out-of-range signer bits".to_string(),
                );
            }
        }

        let mut signer_count = 0usize;
        let mut signed_stake = 0u64;
        for (idx, pk) in canonical_attesters.iter().enumerate() {
            let byte = self.signer_bitmap[idx / 8];
            if (byte & (1u8 << (idx % 8))) == 0 {
                continue;
            }
            signer_count += 1;
            if pk.as_slice() != leader_pubkey {
                signed_stake = signed_stake.saturating_add(stake_map.get(pk).copied().unwrap_or(0));
            }
        }

        Ok((signer_count, signed_stake))
    }

    pub fn validate_compact_metadata(
        &self,
        active_attesters: &[Vec<u8>],
        stake_map: &HashMap<Vec<u8>, u64>,
        leader_pubkey: &[u8],
        required_stake: u64,
    ) -> Result<(), String> {
        let (signer_count, bitmap_stake) =
            self.bitmap_signed_stake(active_attesters, stake_map, leader_pubkey)?;
        if signer_count == 0 {
            return Err("Missing PQ finality certificate signers".to_string());
        }
        if bitmap_stake != self.signed_stake {
            return Err(format!(
                "PQ finality certificate signed stake mismatch: bitmap {}, header {}",
                bitmap_stake, self.signed_stake
            ));
        }
        if bitmap_stake < required_stake {
            return Err(format!(
                "PQ finality certificate stake below quorum: {}/{}",
                bitmap_stake, required_stake
            ));
        }
        Ok(())
    }

    pub fn signature_root_for(signatures: &[PqFinalitySignature]) -> [u8; 32] {
        let mut sorted = signatures.to_vec();
        sorted.sort_by(|a, b| {
            a.validator_index
                .cmp(&b.validator_index)
                .then_with(|| a.validator_pubkey.cmp(&b.validator_pubkey))
                .then_with(|| a.signature.cmp(&b.signature))
        });
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"truthlinked-pq-finality-signature-root-v1");
        hasher.update(&(sorted.len() as u32).to_le_bytes());
        for sig in sorted {
            hasher.update(&sig.validator_index.to_le_bytes());
            hasher.update(&(sig.validator_pubkey.len() as u32).to_le_bytes());
            hasher.update(&sig.validator_pubkey);
            hasher.update(&(sig.signature.len() as u32).to_le_bytes());
            hasher.update(&sig.signature);
        }
        *hasher.finalize().as_bytes()
    }

    pub fn from_attestations(
        height: u64,
        round: u64,
        batch_hash: [u8; 32],
        state_root: [u8; 32],
        active_attesters: &[Vec<u8>],
        stake_map: &HashMap<Vec<u8>, u64>,
        leader_pubkey: &[u8],
        attestations: &[Attestation],
    ) -> Result<Self, String> {
        let mut attesters = active_attesters.to_vec();
        attesters.sort();
        attesters.dedup();

        let mut index_by_pk = HashMap::new();
        for (idx, pk) in attesters.iter().enumerate() {
            index_by_pk.insert(pk.clone(), idx);
        }

        let mut signer_bitmap = vec![0u8; (attesters.len() + 7) / 8];
        let mut seen = std::collections::HashSet::new();
        let mut signatures = Vec::new();
        let mut signed_stake = 0u64;

        for att in attestations {
            if att.height != height
                || att.round != round
                || att.batch_hash != batch_hash
                || att.state_root != state_root
            {
                continue;
            }
            let Some(index) = index_by_pk.get(&att.validator_pubkey).copied() else {
                continue;
            };
            if !seen.insert(att.validator_pubkey.clone()) {
                continue;
            }
            signer_bitmap[index / 8] |= 1u8 << (index % 8);
            if att.validator_pubkey.as_slice() != leader_pubkey {
                signed_stake = signed_stake
                    .saturating_add(stake_map.get(&att.validator_pubkey).copied().unwrap_or(0));
            }
            signatures.push(PqFinalitySignature {
                validator_index: index as u32,
                validator_pubkey: att.validator_pubkey.clone(),
                signature: att.signature.clone(),
            });
        }

        signatures.sort_by(|a, b| a.validator_index.cmp(&b.validator_index));
        let signature_root = Self::signature_root_for(&signatures);
        Ok(Self {
            version: Self::VERSION,
            height,
            round,
            batch_hash,
            state_root,
            signer_bitmap,
            signatures,
            signature_root,
            signed_stake,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchHeader {
    pub height: u64,
    pub parent_hash: [u8; 32],
    pub batch_hash: [u8; 32], // Batch commitment (order-independent)
    pub execution_order_root: [u8; 32], // Merkle root of execution order
    pub state_root: [u8; 32],
    pub timestamp: u64,
    pub total_fees: u128,
    pub finality_certificate: PqFinalityCertificate,
    pub leader_pubkey: Vec<u8>,
    pub leader_signature: Vec<u8>,
    pub leader_round: u64,
}

impl BatchHeader {
    pub fn genesis() -> Self {
        Self {
            height: 0,
            parent_hash: [0u8; 32],
            batch_hash: [0u8; 32],
            execution_order_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
            total_fees: 0,
            finality_certificate: PqFinalityCertificate::empty(0, 0, [0u8; 32], [0u8; 32]),
            leader_pubkey: vec![],
            leader_signature: vec![],
            leader_round: 0,
        }
    }

    pub fn new(
        height: u64,
        parent_hash: [u8; 32],
        batch_hash: [u8; 32],
        execution_order_root: [u8; 32],
        state_root: [u8; 32],
        timestamp: u64,
        total_fees: u128,
        finality_certificate: PqFinalityCertificate,
        leader_pubkey: Vec<u8>,
        leader_signature: Vec<u8>,
        leader_round: u64,
    ) -> Self {
        Self {
            height,
            parent_hash,
            batch_hash,
            execution_order_root,
            state_root,
            timestamp,
            total_fees,
            finality_certificate,
            leader_pubkey,
            leader_signature,
            leader_round,
        }
    }

    pub fn compute_block_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.parent_hash);
        hasher.update(&self.batch_hash);
        hasher.update(&self.execution_order_root);
        hasher.update(&self.state_root);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.total_fees.to_le_bytes());
        hasher.update(&self.finality_certificate.version.to_le_bytes());
        hasher.update(&self.finality_certificate.height.to_le_bytes());
        hasher.update(&self.finality_certificate.round.to_le_bytes());
        hasher.update(&self.finality_certificate.batch_hash);
        hasher.update(&self.finality_certificate.state_root);
        hasher.update(&(self.finality_certificate.signer_bitmap.len() as u32).to_le_bytes());
        hasher.update(&self.finality_certificate.signer_bitmap);
        hasher.update(&self.finality_certificate.signature_root);
        hasher.update(&self.finality_certificate.signed_stake.to_le_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone)]
pub struct BlockChain {
    headers: HashMap<[u8; 32], BatchHeader>,
    height_index: HashMap<u64, Vec<[u8; 32]>>,
    stake_weight: HashMap<[u8; 32], u64>,
    canonical_tip: [u8; 32],
    current_height: u64,
    last_finalized_height: u64,
}

impl BlockChain {
    pub fn new() -> Self {
        let genesis = BatchHeader::genesis();
        let mut headers = HashMap::new();
        let mut height_index = HashMap::new();
        let mut stake_weight = HashMap::new();

        headers.insert(genesis.batch_hash, genesis.clone());
        height_index.insert(0, vec![genesis.batch_hash]);
        stake_weight.insert(genesis.batch_hash, 0);

        Self {
            headers,
            height_index,
            stake_weight,
            canonical_tip: genesis.batch_hash,
            current_height: 0,
            last_finalized_height: 0,
        }
    }

    /// Seed the chain with an anchor header at a given height, bypassing parent checks.
    /// Used during fast restore to establish the window base.
    pub fn seed_anchor(&mut self, header: BatchHeader) {
        self.headers.insert(header.batch_hash, header.clone());
        self.height_index
            .entry(header.height)
            .or_insert_with(Vec::new)
            .push(header.batch_hash);
        self.stake_weight.insert(header.batch_hash, 0);
        self.canonical_tip = header.batch_hash;
        self.current_height = header.height;
        self.last_finalized_height = header.height;
    }

    pub fn add_header(&mut self, header: BatchHeader) -> Result<(), String> {
        if header.height == 0 {
            return Err("Cannot add genesis header".to_string());
        }

        if !self.headers.contains_key(&header.parent_hash) {
            return Err(format!(
                "Parent not found: {}",
                hex::encode(&header.parent_hash)
            ));
        }

        let parent = self
            .headers
            .get(&header.parent_hash)
            .ok_or("Parent header missing")?;
        if header.height != parent.height + 1 {
            return Err(format!(
                "Invalid height: expected {}, got {}",
                parent.height + 1,
                header.height
            ));
        }

        if header.timestamp < parent.timestamp {
            return Err("Timestamp must be >= parent timestamp".to_string());
        }

        self.headers.insert(header.batch_hash, header.clone());
        self.height_index
            .entry(header.height)
            .or_insert_with(Vec::new)
            .push(header.batch_hash);

        Ok(())
    }

    pub fn set_canonical_tip(
        &mut self,
        tip: [u8; 32],
        total_stake: u64,
    ) -> Result<(bool, Option<[u8; 32]>), String> {
        let header = self.headers.get(&tip).ok_or("Header not found")?;

        if header.height < self.last_finalized_height {
            return Err(format!(
                "Cannot reorg past finalized height {}",
                self.last_finalized_height
            ));
        }

        self.stake_weight.insert(tip, total_stake);

        let current_stake = self
            .stake_weight
            .get(&self.canonical_tip)
            .copied()
            .unwrap_or(0);

        // DETERMINISTIC fork choice - attestation-anchored finality:
        //
        // Primary:  Most embedded ML-DSA-65 attestations wins.  Each attestation
        //           is a PQ signature over (batch_hash, state_root).  An attacker
        //           cannot forge a heavier chain without breaking ML-DSA-65 for
        //           every validator they impersonate - cryptographically infeasible.
        //
        // Secondary:  Highest height (liveness).
        // Tertiary:   Highest stake (economic security).
        // Quaternary: Smaller parent hash (deterministic, unmanipulable tiebreaker).
        //
        // A block with 2/3+ attestations is FINALIZED; reorgs past it are
        // rejected by the last_finalized_height guard above.
        let new_att_count = header.finality_certificate.signer_count();
        let current_att_count = self
            .headers
            .get(&self.canonical_tip)
            .map(|h| h.finality_certificate.signer_count())
            .unwrap_or(0);
        let current_tip_header = self
            .headers
            .get(&self.canonical_tip)
            .ok_or("Current canonical tip header missing")?;
        let current_signed_stake = current_tip_header.finality_certificate.signed_stake;
        let current_leader_round = current_tip_header.leader_round;

        // Fork choice: Prefer more attestations, then higher height, then higher stake
        // Allow progression even if attestation count drops slightly (liveness)
        tracing::info!(
            "Fork choice: new_att={} cur_att={} new_h={} cur_h={} new_stake={} cur_stake={}",
            new_att_count,
            current_att_count,
            header.height,
            self.current_height,
            total_stake,
            current_stake
        );

        if new_att_count > current_att_count
            || header.height > self.current_height  // Always accept higher height for liveness
            || (header.height == self.current_height && total_stake > current_stake)
            || (header.height == self.current_height && total_stake == current_stake && {
                header.finality_certificate.signed_stake > current_signed_stake
                    || (header.finality_certificate.signed_stake == current_signed_stake
                        && header.leader_round < current_leader_round)
                    || (header.finality_certificate.signed_stake == current_signed_stake
                        && header.leader_round == current_leader_round
                        && tip < self.canonical_tip)
            })
        {
            let old_tip = self.canonical_tip;
            let switched = old_tip != tip && header.height == self.current_height;

            self.current_height = header.height;
            self.canonical_tip = tip;

            if switched {
                tracing::warn!(
                    "Fork switch: height={}, stake={}, hash={}",
                    header.height,
                    total_stake,
                    hex::encode(&tip[..8])
                );
                return Ok((true, Some(old_tip)));
            } else {
                tracing::info!(
                    "New canonical tip: height={}, stake={}, hash={}",
                    header.height,
                    total_stake,
                    hex::encode(&tip[..8])
                );
            }
        }

        Ok((false, None))
    }

    pub fn finalize_height(&mut self, height: u64) {
        if height > self.last_finalized_height {
            self.last_finalized_height = height;
            tracing::info!("Finalized height: {}", height);

            if height > MAX_HEADER_HISTORY {
                self.prune_old_headers(height - MAX_HEADER_HISTORY);
            }
        }
    }

    pub fn prune_old_headers(&mut self, keep_from_height: u64) {
        let mut pruned_count = 0;

        self.headers.retain(|hash, header| {
            if header.height < keep_from_height {
                self.stake_weight.remove(hash);
                pruned_count += 1;
                false
            } else {
                true
            }
        });

        self.height_index.retain(|height, hashes| {
            if *height < keep_from_height {
                false
            } else {
                hashes.retain(|hash| self.headers.contains_key(hash));
                !hashes.is_empty()
            }
        });

        if pruned_count > 0 {
            tracing::info!(
                "  Pruned {} old headers (kept from height {})",
                pruned_count,
                keep_from_height
            );
        }
    }

    pub fn last_finalized_height(&self) -> u64 {
        self.last_finalized_height
    }

    pub fn get_header(&self, hash: &[u8; 32]) -> Option<&BatchHeader> {
        self.headers.get(hash)
    }

    pub fn get_hashes_at_height(&self, height: u64) -> Option<&Vec<[u8; 32]>> {
        self.height_index.get(&height)
    }

    pub fn get_current_height(&self) -> u64 {
        self.current_height
    }

    pub fn get_headers_at_height(&self, height: u64) -> Vec<&BatchHeader> {
        self.height_index
            .get(&height)
            .map(|hashes| hashes.iter().filter_map(|h| self.headers.get(h)).collect())
            .unwrap_or_default()
    }

    pub fn get_canonical_tip(&self) -> Result<&BatchHeader, String> {
        self.headers.get(&self.canonical_tip).ok_or_else(|| {
            format!(
                "Canonical tip header missing: {}",
                hex::encode(&self.canonical_tip)
            )
        })
    }

    /// Directly seed a header as the canonical tip, bypassing parent chain checks.
    /// Used during fast restore to set the tip from storage without replaying all headers.
    pub fn seed_canonical_tip(&mut self, header: BatchHeader, total_stake: u64) {
        let hash = header.batch_hash;
        let height = header.height;
        self.headers.insert(hash, header);
        self.height_index.entry(height).or_default().push(hash);
        self.stake_weight.insert(hash, total_stake);
        self.canonical_tip = hash;
        self.current_height = height;
        self.last_finalized_height = height.saturating_sub(1);
    }

    pub fn get_batch_by_height(&self, height: u64) -> Option<&BatchHeader> {
        if height > self.current_height {
            return None;
        }

        // Walk back from canonical tip to find the block at this height
        let mut current = self.canonical_tip;
        while let Some(header) = self.headers.get(&current) {
            if header.height == height {
                return Some(header);
            }
            if header.height < height {
                return None;
            }
            current = header.parent_hash;
        }
        None
    }

    pub fn get_batch_by_height_from_storage(
        &self,
        height: u64,
        storage: &Storage,
    ) -> Option<BatchHeader> {
        // Try memory first
        if let Some(header) = self.get_batch_by_height(height) {
            return Some(header.clone());
        }

        // Fall back to storage
        if let Ok(Some(header)) = storage.load_batch_header_by_height(height) {
            return Some(header);
        }

        None
    }

    pub fn get_canonical_chain(&self, from_height: u64, to_height: u64) -> Vec<BatchHeader> {
        let mut chain = Vec::new();
        let mut current = self.canonical_tip;

        while let Some(header) = self.headers.get(&current) {
            if header.height <= to_height && header.height >= from_height {
                chain.push(header.clone());
            }
            if header.height <= from_height {
                break;
            }
            current = header.parent_hash;
        }

        chain.reverse();
        chain
    }

    pub fn find_common_ancestor(&self, hash_a: [u8; 32], hash_b: [u8; 32]) -> Option<[u8; 32]> {
        let mut chain_a = std::collections::HashSet::new();
        let mut current = hash_a;

        while let Some(header) = self.headers.get(&current) {
            chain_a.insert(current);
            if header.height == 0 {
                break;
            }
            current = header.parent_hash;
        }

        current = hash_b;
        while let Some(header) = self.headers.get(&current) {
            if chain_a.contains(&current) {
                return Some(current);
            }
            if header.height == 0 {
                break;
            }
            current = header.parent_hash;
        }

        None
    }

    pub fn get_chain_between(&self, from: [u8; 32], to: [u8; 32]) -> Vec<BatchHeader> {
        let mut chain = Vec::new();
        let mut current = to;

        while current != from {
            if let Some(header) = self.headers.get(&current) {
                chain.push(header.clone());
                current = header.parent_hash;
            } else {
                break;
            }
        }

        chain.reverse();
        chain
    }

    pub fn is_on_canonical_chain(&self, hash: &[u8; 32]) -> bool {
        let mut current = self.canonical_tip;

        while let Some(header) = self.headers.get(&current) {
            if current == *hash {
                return true;
            }
            if header.height == 0 {
                break;
            }
            current = header.parent_hash;
        }

        false
    }

    pub fn get_stake_weight(&self, hash: &[u8; 32]) -> u64 {
        self.stake_weight.get(hash).copied().unwrap_or(0)
    }

    pub fn add_stake_weight(&mut self, hash: &[u8; 32], stake: u64) {
        *self.stake_weight.entry(*hash).or_insert(0) += stake;
    }

    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    pub fn has_fork_at_height(&self, height: u64) -> bool {
        self.height_index
            .get(&height)
            .map(|hashes| hashes.len() > 1)
            .unwrap_or(false)
    }

    pub fn verify_chain(&self, tip: [u8; 32]) -> Result<(), String> {
        let mut current = tip;
        let mut visited = std::collections::HashSet::new();

        loop {
            if !visited.insert(current) {
                return Err("Cycle detected in chain".to_string());
            }

            let header = self
                .headers
                .get(&current)
                .ok_or("Missing header in chain")?;

            if header.height == 0 {
                break;
            }

            let parent = self
                .headers
                .get(&header.parent_hash)
                .ok_or("Missing parent in chain")?;

            if parent.height + 1 != header.height {
                return Err("Height mismatch in chain".to_string());
            }

            current = header.parent_hash;
        }

        Ok(())
    }
}

#[cfg(test)]
mod pq_finality_tests {
    use super::*;

    fn att(
        height: u64,
        round: u64,
        batch_hash: [u8; 32],
        state_root: [u8; 32],
        pk: Vec<u8>,
        sig: Vec<u8>,
    ) -> Attestation {
        Attestation {
            height,
            round,
            batch_hash,
            state_root,
            validator_pubkey: pk,
            signature: sig,
        }
    }

    #[test]
    fn pq_finality_certificate_is_canonical_and_stake_weighted() {
        let height = 42;
        let round = 3;
        let batch_hash = [7u8; 32];
        let state_root = [9u8; 32];
        let leader = vec![1u8; 4];
        let v2 = vec![2u8; 4];
        let v3 = vec![3u8; 4];
        let active = vec![leader.clone(), v2.clone(), v3.clone()];
        let mut stake = HashMap::new();
        stake.insert(leader.clone(), 100);
        stake.insert(v2.clone(), 200);
        stake.insert(v3.clone(), 300);

        let unordered = vec![
            att(
                height,
                round,
                batch_hash,
                state_root,
                v3.clone(),
                vec![3u8; 8],
            ),
            att(
                height,
                round,
                batch_hash,
                state_root,
                leader.clone(),
                vec![1u8; 8],
            ),
            att(
                height,
                round,
                batch_hash,
                state_root,
                v2.clone(),
                vec![2u8; 8],
            ),
        ];

        let cert = PqFinalityCertificate::from_attestations(
            height, round, batch_hash, state_root, &active, &stake, &leader, &unordered,
        )
        .unwrap();

        assert_eq!(cert.signer_count(), 3);
        assert_eq!(cert.signer_bitmap, vec![0b0000_0111]);
        assert_eq!(cert.signed_stake, 500);
        assert_eq!(cert.signatures[0].validator_pubkey, leader);
        assert_eq!(cert.signatures[1].validator_pubkey, v2);
        assert_eq!(cert.signatures[2].validator_pubkey, v3);
        assert_eq!(
            cert.signature_root,
            PqFinalityCertificate::signature_root_for(&cert.signatures)
        );
    }

    #[test]
    fn compact_certificate_keeps_header_hash_but_strips_signature_blobs() {
        let leader = vec![1u8; 4];
        let v2 = vec![2u8; 4];
        let active = vec![leader.clone(), v2.clone()];
        let mut stake = HashMap::new();
        stake.insert(leader.clone(), 100);
        stake.insert(v2.clone(), 200);

        let cert = PqFinalityCertificate::from_attestations(
            7,
            0,
            [3u8; 32],
            [4u8; 32],
            &active,
            &stake,
            &leader,
            &[att(7, 0, [3u8; 32], [4u8; 32], v2.clone(), vec![9u8; 8])],
        )
        .unwrap();
        let compact = cert.compact_for_gossip();
        assert!(cert.has_full_signatures());
        assert!(!compact.has_full_signatures());
        assert_eq!(cert.signer_count(), compact.signer_count());

        let full_header = BatchHeader::new(
            7,
            [1u8; 32],
            [3u8; 32],
            [2u8; 32],
            [4u8; 32],
            99,
            12,
            cert,
            leader.clone(),
            vec![5u8; 8],
            0,
        );
        let mut compact_header = full_header.clone();
        compact_header.finality_certificate = compact;
        assert_eq!(
            full_header.compute_block_hash(),
            compact_header.compute_block_hash()
        );
    }

    #[test]
    fn compact_certificate_rejects_forged_signed_stake() {
        let leader = vec![1u8; 4];
        let v2 = vec![2u8; 4];
        let active = vec![leader.clone(), v2.clone()];
        let mut stake = HashMap::new();
        stake.insert(leader.clone(), 100);
        stake.insert(v2.clone(), 200);

        let mut cert = PqFinalityCertificate::empty(9, 0, [8u8; 32], [7u8; 32]);
        cert.signer_bitmap = vec![0b0000_0010];
        cert.signed_stake = 999;

        let err = cert
            .validate_compact_metadata(&active, &stake, &leader, 100)
            .unwrap_err();
        assert!(err.contains("signed stake mismatch"));
    }

    #[test]
    fn compact_certificate_rejects_below_quorum_bitmap() {
        let leader = vec![1u8; 4];
        let v2 = vec![2u8; 4];
        let active = vec![leader.clone(), v2.clone()];
        let mut stake = HashMap::new();
        stake.insert(leader.clone(), 100);
        stake.insert(v2.clone(), 200);

        let mut cert = PqFinalityCertificate::empty(9, 0, [8u8; 32], [7u8; 32]);
        cert.signer_bitmap = vec![0b0000_0010];
        cert.signed_stake = 200;

        let err = cert
            .validate_compact_metadata(&active, &stake, &leader, 250)
            .unwrap_err();
        assert!(err.contains("stake below quorum"));
    }

    #[test]
    fn certificate_bitmap_uses_canonical_active_validator_indices() {
        let height = 11;
        let round = 0;
        let batch_hash = [6u8; 32];
        let state_root = [7u8; 32];
        let leader = vec![1u8; 4];
        let lagging = vec![2u8; 4];
        let v3 = vec![3u8; 4];
        let v4 = vec![4u8; 4];
        let active = vec![leader.clone(), lagging.clone(), v3.clone(), v4.clone()];
        let mut stake = HashMap::new();
        stake.insert(leader.clone(), 100);
        stake.insert(lagging, 100);
        stake.insert(v3.clone(), 200);
        stake.insert(v4.clone(), 300);

        let cert = PqFinalityCertificate::from_attestations(
            height,
            round,
            batch_hash,
            state_root,
            &active,
            &stake,
            &leader,
            &[
                att(height, round, batch_hash, state_root, v3, vec![3u8; 8]),
                att(height, round, batch_hash, state_root, v4, vec![4u8; 8]),
            ],
        )
        .unwrap();

        assert_eq!(cert.signer_bitmap, vec![0b0000_1100]);
        assert_eq!(cert.signed_stake, 500);
        cert.validate_compact_metadata(&active, &stake, &leader, 500)
            .unwrap();
    }

    #[test]
    fn compact_certificate_rejects_out_of_range_bitmap_bits() {
        let leader = vec![1u8; 4];
        let v2 = vec![2u8; 4];
        let active = vec![leader.clone(), v2.clone()];
        let mut stake = HashMap::new();
        stake.insert(leader.clone(), 100);
        stake.insert(v2.clone(), 200);

        let mut cert = PqFinalityCertificate::empty(9, 0, [8u8; 32], [7u8; 32]);
        cert.signer_bitmap = vec![0b1000_0010];
        cert.signed_stake = 200;

        let err = cert
            .validate_compact_metadata(&active, &stake, &leader, 100)
            .unwrap_err();
        assert!(err.contains("out-of-range"));
    }
}
