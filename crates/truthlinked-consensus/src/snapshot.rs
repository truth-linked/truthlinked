//! Truthlinked Consensus Src Snapshot
//!
//! Owns state snapshot encoding, verification, and checkpoint metadata.
//! Consensus changes are protocol-critical; preserve deterministic replay, recovery safety, and wire compatibility.

use im::HashMap as ImHashMap;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::OnceLock;
use truthlinked_core::pq_execution::AccountId;
use truthlinked_governance;
use truthlinked_governance::{NameRegistration, PendingNameRegistration, TokenAuthorityProposal};
use truthlinked_runtime::types::{AccountRecord, NFTRecord};
use truthlinked_staking::StakingState;
use truthlinked_state::constants::{
    SNAPSHOT_MAX_FUTURE_DRIFT, SNAPSHOT_MAX_PAST_AGE, SNAPSHOT_MAX_SIGNATURES,
    SNAPSHOT_SIGN_CONTEXT,
};

static SNAPSHOT_INTERVAL: OnceLock<u64> = OnceLock::new();

pub fn set_snapshot_interval(interval: u64) {
    let _ = SNAPSHOT_INTERVAL.set(interval);
}

pub fn get_snapshot_interval() -> u64 {
    *SNAPSHOT_INTERVAL.get().unwrap_or(&10_000)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub height: u64,
    pub state_root: [u8; 32],
    pub accounts: ImHashMap<AccountId, AccountRecord>,
    pub staking: StakingState,
    #[serde(default)]
    pub nfts: ImHashMap<[u8; 32], NFTRecord>,
    #[serde(default)]
    pub cells: truthlinked_runtime::cells::CellState,
    #[serde(default)]
    pub accumulated_gas_fees: u128,
    #[serde(default)]
    pub accumulated_name_fees: u128,
    #[serde(default)]
    pub accumulated_compute_fees_tlkd: u128,
    #[serde(default)]
    pub accumulated_treasury_fees: u128,
    #[serde(default)]
    pub accumulated_epoch_fees: u128,
    #[serde(default)]
    pub last_emission_epoch: u64,
    #[serde(default)]
    pub chain_age_years: u64,
    #[serde(default)]
    pub executed_tx_hashes: Vec<[u8; 32]>,
    #[serde(default)]
    pub params: ImHashMap<[u8; 32], [u8; 32]>,
    #[serde(default)]
    pub name_registry: ImHashMap<String, NameRegistration>,
    #[serde(default)]
    pub pending_names: ImHashMap<String, PendingNameRegistration>,
    #[serde(default)]
    pub token_authority_proposals: ImHashMap<AccountId, TokenAuthorityProposal>,
    #[serde(default)]
    pub airdrop_claims: ImHashMap<AccountId, u64>,
    #[serde(default)]
    pub total_minted: u128,
    #[serde(default)]
    pub foundation_mint_authority: Option<AccountId>,
    #[serde(default)]
    pub pending_oracle_requests:
        ImHashMap<[u8; 32], truthlinked_oracle::http_oracle::OracleRequest>,
    #[serde(default)]
    pub oracle_pending: ImHashMap<[u8; 32], truthlinked_oracle::http_oracle::OracleTally>,
    #[serde(default)]
    pub oracle_results: ImHashMap<[u8; 32], truthlinked_oracle::http_oracle::OracleResult>,
    #[serde(default)]
    pub url_proposals: ImHashMap<String, truthlinked_governance::UrlProposal>,
    #[serde(default)]
    pub schema_proposals: ImHashMap<[u8; 32], truthlinked_governance::SchemaProposal>,
    #[serde(default)]
    pub schema_registry: ImHashMap<[u8; 32], truthlinked_governance::SchemaEntry>,
    #[serde(default)]
    pub cell_visibility: ImHashMap<AccountId, truthlinked_governance::CellVisibility>,
    pub validator_signatures: Vec<ValidatorSignature>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub snapshot: StateSnapshot,
    pub proof: CheckpointProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointProof {
    pub finalized_height: u64,
    pub total_stake: u64,
    pub signed_stake: u64,
}

impl StateSnapshot {
    pub fn new(
        height: u64,
        state_root: [u8; 32],
        accounts: ImHashMap<AccountId, AccountRecord>,
        staking: StakingState,
    ) -> Self {
        Self {
            height,
            state_root,
            accounts,
            staking,
            nfts: ImHashMap::new(),
            cells: truthlinked_runtime::cells::CellState::new(),
            accumulated_gas_fees: 0,
            accumulated_name_fees: 0,
            accumulated_compute_fees_tlkd: 0,
            accumulated_treasury_fees: 0,
            accumulated_epoch_fees: 0,
            last_emission_epoch: 0,
            chain_age_years: 0,
            executed_tx_hashes: Vec::new(),
            params: ImHashMap::new(),
            name_registry: ImHashMap::new(),
            pending_names: ImHashMap::new(),
            token_authority_proposals: ImHashMap::new(),
            airdrop_claims: ImHashMap::new(),
            total_minted: 0,
            foundation_mint_authority: None,
            pending_oracle_requests: ImHashMap::new(),
            oracle_pending: ImHashMap::new(),
            oracle_results: ImHashMap::new(),
            url_proposals: ImHashMap::new(),
            schema_proposals: ImHashMap::new(),
            schema_registry: ImHashMap::new(),
            cell_visibility: ImHashMap::new(),
            validator_signatures: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn from_state(height: u64, state: &truthlinked_state::State) -> Self {
        let mut executed_tx_hashes: Vec<[u8; 32]> =
            state.executed_tx_hashes.iter().copied().collect();
        executed_tx_hashes.sort_unstable();
        let state_root = Self::compute_state_root_from_state(state);

        Self {
            height,
            state_root,
            accounts: state.accounts.clone(),
            staking: state.staking.clone(),
            nfts: state.nfts.clone(),
            cells: state.cells.clone(),
            accumulated_gas_fees: state.accumulated_gas_fees,
            accumulated_name_fees: state.accumulated_name_fees,
            accumulated_compute_fees_tlkd: state.accumulated_compute_fees_tlkd,
            accumulated_treasury_fees: state.accumulated_treasury_fees,
            accumulated_epoch_fees: state.accumulated_epoch_fees,
            last_emission_epoch: state.last_emission_epoch,
            chain_age_years: state.chain_age_years,
            executed_tx_hashes,
            params: state.params.clone(),
            name_registry: state.name_registry.clone(),
            pending_names: state.pending_names.clone(),
            token_authority_proposals: state.token_authority_proposals.clone(),
            airdrop_claims: state.airdrop_claims.clone(),
            total_minted: state.total_minted,
            foundation_mint_authority: state.foundation_mint_authority,
            pending_oracle_requests: state.pending_oracle_requests.clone(),
            oracle_pending: state.oracle_pending.clone(),
            oracle_results: state.oracle_results.clone(),
            url_proposals: state.url_proposals.clone(),
            schema_proposals: state.schema_proposals.clone(),
            schema_registry: state.schema_registry.clone(),
            cell_visibility: state.cell_visibility.clone(),
            validator_signatures: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn add_signature(&mut self, validator_pubkey: Vec<u8>, signature: Vec<u8>) {
        self.validator_signatures.push(ValidatorSignature {
            validator_pubkey,
            signature,
        });
    }

    pub fn compute_message(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.state_root);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Compute actual state root from snapshot data
    pub fn compute_state_root(&self) -> [u8; 32] {
        Self::compute_state_root_from_parts(
            &self.accounts,
            &self.staking,
            &self.nfts,
            &self.cells,
            self.accumulated_gas_fees,
            self.accumulated_name_fees,
            self.accumulated_compute_fees_tlkd,
            self.accumulated_treasury_fees,
            self.accumulated_epoch_fees,
            self.last_emission_epoch,
            self.chain_age_years,
            &self.executed_tx_hashes,
            &self.params,
            &self.name_registry,
            &self.pending_names,
            &self.token_authority_proposals,
            &self.airdrop_claims,
            &self.foundation_mint_authority,
            &self.pending_oracle_requests,
            &self.oracle_pending,
            &self.oracle_results,
            &self.url_proposals,
            &self.schema_proposals,
            &self.schema_registry,
            &self.cell_visibility,
        )
    }

    pub fn compute_state_root_from_state(state: &truthlinked_state::State) -> [u8; 32] {
        let mut executed_tx_hashes: Vec<[u8; 32]> =
            state.executed_tx_hashes.iter().copied().collect();
        executed_tx_hashes.sort_unstable();
        tracing::debug!(
            "🔍 Computing state root: accounts={}, executed_txs={}",
            state.accounts.len(),
            executed_tx_hashes.len()
        );
        Self::compute_state_root_from_parts(
            &state.accounts,
            &state.staking,
            &state.nfts,
            &state.cells,
            state.accumulated_gas_fees,
            state.accumulated_name_fees,
            state.accumulated_compute_fees_tlkd,
            state.accumulated_treasury_fees,
            state.accumulated_epoch_fees,
            state.last_emission_epoch,
            state.chain_age_years,
            &executed_tx_hashes,
            &state.params,
            &state.name_registry,
            &state.pending_names,
            &state.token_authority_proposals,
            &state.airdrop_claims,
            &state.foundation_mint_authority,
            &state.pending_oracle_requests,
            &state.oracle_pending,
            &state.oracle_results,
            &state.url_proposals,
            &state.schema_proposals,
            &state.schema_registry,
            &state.cell_visibility,
        )
    }

    fn compute_state_root_from_parts(
        accounts: &ImHashMap<AccountId, AccountRecord>,
        staking: &StakingState,
        nfts: &ImHashMap<[u8; 32], NFTRecord>,
        cells: &truthlinked_runtime::cells::CellState,
        accumulated_gas_fees: u128,
        accumulated_name_fees: u128,
        accumulated_compute_fees_tlkd: u128,
        accumulated_treasury_fees: u128,
        accumulated_epoch_fees: u128,
        last_emission_epoch: u64,
        chain_age_years: u64,
        executed_tx_hashes: &[[u8; 32]],
        params: &ImHashMap<[u8; 32], [u8; 32]>,
        name_registry: &ImHashMap<String, NameRegistration>,
        pending_names: &ImHashMap<String, PendingNameRegistration>,
        token_authority_proposals: &ImHashMap<AccountId, TokenAuthorityProposal>,
        airdrop_claims: &ImHashMap<AccountId, u64>,
        foundation_mint_authority: &Option<AccountId>,
        pending_oracle_requests: &ImHashMap<
            [u8; 32],
            truthlinked_oracle::http_oracle::OracleRequest,
        >,
        oracle_pending: &ImHashMap<[u8; 32], truthlinked_oracle::http_oracle::OracleTally>,
        oracle_results: &ImHashMap<[u8; 32], truthlinked_oracle::http_oracle::OracleResult>,
        url_proposals: &ImHashMap<String, truthlinked_governance::UrlProposal>,
        schema_proposals: &ImHashMap<[u8; 32], truthlinked_governance::SchemaProposal>,
        schema_registry: &ImHashMap<[u8; 32], truthlinked_governance::SchemaEntry>,
        cell_visibility: &ImHashMap<AccountId, truthlinked_governance::CellVisibility>,
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        hash_tag(&mut hasher, b"accounts");
        hash_accounts(&mut hasher, accounts);

        hash_tag(&mut hasher, b"staking");
        hash_staking_state(&mut hasher, staking);

        hash_tag(&mut hasher, b"nfts");
        hash_nfts(&mut hasher, nfts);

        hash_tag(&mut hasher, b"cells");
        hash_cell_state(&mut hasher, cells);

        hash_tag(&mut hasher, b"accumulated_gas_fees");
        hash_u128(&mut hasher, accumulated_gas_fees);

        hash_tag(&mut hasher, b"accumulated_name_fees");
        hash_u128(&mut hasher, accumulated_name_fees);

        hash_tag(&mut hasher, b"accumulated_compute_fees_tlkd");
        hash_u128(&mut hasher, accumulated_compute_fees_tlkd);

        hash_tag(&mut hasher, b"accumulated_treasury_fees");
        hash_u128(&mut hasher, accumulated_treasury_fees);

        hash_tag(&mut hasher, b"accumulated_epoch_fees");
        hash_u128(&mut hasher, accumulated_epoch_fees);

        hash_tag(&mut hasher, b"last_emission_epoch");
        hash_u64(&mut hasher, last_emission_epoch);

        hash_tag(&mut hasher, b"chain_age_years");
        hash_u64(&mut hasher, chain_age_years);

        hash_tag(&mut hasher, b"executed_tx_hashes");
        hash_vec_fixed_32(&mut hasher, executed_tx_hashes);

        hash_tag(&mut hasher, b"params");
        hash_params(&mut hasher, params);

        hash_tag(&mut hasher, b"name_registry");
        hash_name_registry(&mut hasher, name_registry);

        hash_tag(&mut hasher, b"pending_names");
        hash_pending_names(&mut hasher, pending_names);

        hash_tag(&mut hasher, b"token_authority_proposals");
        hash_token_authority_proposals(&mut hasher, token_authority_proposals);

        hash_tag(&mut hasher, b"airdrop_claims");
        hash_airdrop_claims(&mut hasher, airdrop_claims);

        hash_tag(&mut hasher, b"foundation_mint_authority");
        if let Some(id) = foundation_mint_authority {
            hash_bytes(&mut hasher, id);
        } else {
            hash_bytes(&mut hasher, &[0u8; 32]);
        }

        hash_tag(&mut hasher, b"pending_oracle_requests");
        hash_oracle_requests(&mut hasher, pending_oracle_requests);

        hash_tag(&mut hasher, b"oracle_pending");
        hash_oracle_pending(&mut hasher, oracle_pending);

        hash_tag(&mut hasher, b"oracle_results");
        hash_oracle_results(&mut hasher, oracle_results);

        hash_tag(&mut hasher, b"url_proposals");
        hash_url_proposals(&mut hasher, url_proposals);

        hash_tag(&mut hasher, b"schema_proposals");
        hash_schema_proposals(&mut hasher, schema_proposals);

        hash_tag(&mut hasher, b"schema_registry");
        hash_schema_registry(&mut hasher, schema_registry);

        hash_tag(&mut hasher, b"cell_visibility");
        hash_cell_visibility(&mut hasher, cell_visibility);

        hasher.finalize().into()
    }

    /// Verify snapshot integrity and signatures
    pub fn verify(&self, min_stake_threshold: f64) -> Result<(), String> {
        // 1. Verify state root matches data
        let computed_root = self.compute_state_root();
        if computed_root != self.state_root {
            return Err(format!(
                "State root mismatch: expected {}, computed {}",
                hex::encode(self.state_root),
                hex::encode(computed_root)
            ));
        }

        // 2. Verify timestamp is reasonable
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if self.timestamp > now + SNAPSHOT_MAX_FUTURE_DRIFT {
            return Err(format!(
                "Snapshot timestamp too far in future: {} > {}",
                self.timestamp,
                now + SNAPSHOT_MAX_FUTURE_DRIFT
            ));
        }

        if self.timestamp + SNAPSHOT_MAX_PAST_AGE < now {
            return Err(format!(
                "Snapshot timestamp too old: {} < {}",
                self.timestamp,
                now - SNAPSHOT_MAX_PAST_AGE
            ));
        }

        // 3. Verify signatures
        let message = self.compute_message();
        let active_validators = self.staking.get_active_validators();
        let total_stake: u64 = active_validators.values().sum();

        if total_stake == 0 {
            return Err("No active validators in snapshot".to_string());
        }

        // Limit signature verification to prevent DoS (max 1000 signatures)
        if self.validator_signatures.len() > SNAPSHOT_MAX_SIGNATURES {
            return Err(format!(
                "Too many signatures: {} (max {})",
                self.validator_signatures.len(),
                SNAPSHOT_MAX_SIGNATURES
            ));
        }

        let mut signed_stake = 0u64;
        let mut verified_count = 0;
        let required_stake = (total_stake * 2) / 3; // 2/3 threshold

        use fips204::ml_dsa_65;
        use fips204::traits::{SerDes, Verifier};

        for sig_entry in &self.validator_signatures {
            // CRITICAL: Early exit after reaching 2/3+ threshold to prevent DoS
            if signed_stake >= required_stake {
                tracing::debug!(
                    " Early exit: 2/3+ threshold reached ({}/{})",
                    signed_stake,
                    total_stake
                );
                break;
            }

            // Check if validator is active
            let stake = match active_validators.get(&sig_entry.validator_pubkey) {
                Some(s) => *s,
                None => {
                    tracing::warn!(
                        "Signature from non-active validator: {}",
                        hex::encode(&sig_entry.validator_pubkey[..8])
                    );
                    continue;
                }
            };

            // Find validator's Dilithium public key from accounts
            let validator_account = self
                .accounts
                .values()
                .find(|acc| acc.pubkey_bytes == sig_entry.validator_pubkey);

            let pubkey_bytes = match validator_account {
                Some(acc) => &acc.pubkey_bytes,
                None => {
                    tracing::warn!("Validator account not found in snapshot");
                    continue;
                }
            };

            // Verify signature
            let pk_bytes: [u8; 1952] = match pubkey_bytes.as_slice().try_into() {
                Ok(b) => b,
                Err(_) => {
                    tracing::warn!("Invalid public key length");
                    continue;
                }
            };

            let sig_bytes: [u8; 3309] = match sig_entry.signature.as_slice().try_into() {
                Ok(b) => b,
                Err(_) => {
                    tracing::warn!("Invalid signature length");
                    continue;
                }
            };

            if let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes) {
                if pk.verify(&message, &sig_bytes, SNAPSHOT_SIGN_CONTEXT) {
                    signed_stake += stake;
                    verified_count += 1;
                } else {
                    tracing::warn!(
                        "Invalid signature from validator: {}",
                        hex::encode(&sig_entry.validator_pubkey[..8])
                    );
                }
            }
        }

        // 4. Check stake threshold
        let stake_ratio = signed_stake as f64 / total_stake as f64;

        if stake_ratio < min_stake_threshold {
            return Err(format!(
                "Insufficient stake signed: {:.2}% < {:.2}% (stake: {}/{})",
                stake_ratio * 100.0,
                min_stake_threshold * 100.0,
                signed_stake,
                total_stake
            ));
        }

        tracing::info!(
            "Snapshot verified: height={}, signatures={}, stake={}/{} ({:.2}%)",
            self.height,
            verified_count,
            signed_stake,
            total_stake,
            stake_ratio * 100.0
        );

        Ok(())
    }
}

impl Checkpoint {
    pub fn from_snapshot(snapshot: StateSnapshot) -> Self {
        let total_stake: u64 = snapshot.staking.get_active_validators().values().sum();

        let mut signed_stake = 0u64;
        for sig in &snapshot.validator_signatures {
            if let Some(stake) = snapshot
                .staking
                .get_active_validators()
                .get(&sig.validator_pubkey)
            {
                signed_stake += stake;
            }
        }

        Self {
            snapshot: snapshot.clone(),
            proof: CheckpointProof {
                finalized_height: snapshot.height,
                total_stake,
                signed_stake,
            },
        }
    }

    /// Verify checkpoint with 2/3+ stake threshold
    pub fn verify(&self) -> Result<(), String> {
        // Verify snapshot integrity first
        self.snapshot.verify(2.0 / 3.0)?;

        // Verify proof matches snapshot
        if self.proof.finalized_height != self.snapshot.height {
            return Err("Proof height mismatch".to_string());
        }

        // Verify 2/3+ stake threshold
        if self.proof.signed_stake * 3 < self.proof.total_stake * 2 {
            return Err(format!(
                "Insufficient stake in proof: {}/{} (need 2/3+)",
                self.proof.signed_stake, self.proof.total_stake
            ));
        }

        tracing::info!(
            "Checkpoint verified: height={}, stake={}/{} ({:.2}%)",
            self.proof.finalized_height,
            self.proof.signed_stake,
            self.proof.total_stake,
            (self.proof.signed_stake as f64 / self.proof.total_stake as f64) * 100.0
        );

        Ok(())
    }
}

fn hash_tag(hasher: &mut sha2::Sha256, tag: &[u8]) {
    hasher.update(tag);
    hasher.update(&[0u8]);
}

fn hash_bytes(hasher: &mut sha2::Sha256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

fn hash_string(hasher: &mut sha2::Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bool(hasher: &mut sha2::Sha256, value: bool) {
    hasher.update(&[value as u8]);
}

fn hash_u8(hasher: &mut sha2::Sha256, value: u8) {
    hasher.update(&[value]);
}

fn hash_u16(hasher: &mut sha2::Sha256, value: u16) {
    hasher.update(&value.to_le_bytes());
}

fn hash_u64(hasher: &mut sha2::Sha256, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn hash_u128(hasher: &mut sha2::Sha256, value: u128) {
    hasher.update(&value.to_le_bytes());
}

fn hash_vec_fixed_32(hasher: &mut sha2::Sha256, values: &[[u8; 32]]) {
    hasher.update(&(values.len() as u32).to_le_bytes());
    for v in values {
        hasher.update(v);
    }
}

fn hash_account_record(hasher: &mut sha2::Sha256, account: &AccountRecord) {
    hash_bytes(hasher, &account.pubkey_bytes);
    hash_u128(hasher, account.balance);
    hash_u128(hasher, account.compute_escrow_tlkd);
    hasher.update(&(account.nfts.len() as u32).to_le_bytes());
    for nft in &account.nfts {
        hasher.update(nft);
    }
}

fn hash_accounts(hasher: &mut sha2::Sha256, accounts: &ImHashMap<AccountId, AccountRecord>) {
    let mut items: Vec<_> = accounts.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    hasher.update(&(items.len() as u32).to_le_bytes());
    tracing::debug!(
        "🔍 Hashing {} accounts, first: {:?}",
        items.len(),
        items
            .first()
            .map(|(id, acc)| (hex::encode(&id[..8]), acc.balance))
    );
    for (account_id, account) in items {
        hasher.update(account_id);
        hash_account_record(hasher, account);
    }
}

fn hash_nft_record(hasher: &mut sha2::Sha256, record: &NFTRecord) {
    hasher.update(&record.nft_id);
    hasher.update(&record.owner);
    hash_string(hasher, &record.metadata_uri);
    hash_u64(hasher, record.minted_at);
    match record.collection {
        Some(id) => {
            hash_bool(hasher, true);
            hasher.update(&id);
        }
        None => hash_bool(hasher, false),
    }
    hash_u16(hasher, record.royalty_bps);
    match record.royalty_recipient {
        Some(id) => {
            hash_bool(hasher, true);
            hasher.update(&id);
        }
        None => hash_bool(hasher, false),
    }
    match record.approved {
        Some(id) => {
            hash_bool(hasher, true);
            hasher.update(&id);
        }
        None => hash_bool(hasher, false),
    }
}

fn hash_nfts(hasher: &mut sha2::Sha256, nfts: &ImHashMap<[u8; 32], NFTRecord>) {
    let mut items: Vec<_> = nfts.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (nft_id, record) in items {
        hasher.update(nft_id);
        hash_nft_record(hasher, record);
    }
}

fn hash_name_registry(hasher: &mut sha2::Sha256, registry: &ImHashMap<String, NameRegistration>) {
    let mut items: Vec<_> = registry.iter().collect();
    items.sort_by_key(|(name, _)| name.as_str());
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (name, reg) in items {
        hash_string(hasher, name);
        hasher.update(&reg.owner);
        hasher.update(&reg.target);
        hash_u64(hasher, reg.registered_at);
        hash_u64(hasher, reg.expires_at);
        hash_bool(hasher, reg.is_cell);
    }
}

fn hash_pending_names(
    hasher: &mut sha2::Sha256,
    pending: &ImHashMap<String, PendingNameRegistration>,
) {
    let mut items: Vec<_> = pending.iter().collect();
    items.sort_by_key(|(name, _)| name.as_str());
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (name, reg) in items {
        hash_string(hasher, name);
        hasher.update(&reg.cell_id);
        hasher.update(&reg.owner);
        hash_bool(hasher, reg.is_cell);
        hash_bytes(hasher, &reg.proposer);
        let mut voters: Vec<Vec<u8>> = reg.votes.iter().cloned().collect();
        voters.sort();
        hasher.update(&(voters.len() as u32).to_le_bytes());
        for v in voters {
            hash_bytes(hasher, &v);
        }
        hash_u64(hasher, reg.total_stake_voted);
        hash_u64(hasher, reg.proposed_at);
    }
}

fn hash_token_authority_proposals(
    hasher: &mut sha2::Sha256,
    proposals: &ImHashMap<AccountId, TokenAuthorityProposal>,
) {
    let mut entries: Vec<(&AccountId, &TokenAuthorityProposal)> = proposals.iter().collect();
    entries.sort_by_key(|(id, _)| *id);
    for (token_cell, proposal) in entries {
        hash_bytes(hasher, token_cell);
        hash_bytes(hasher, &proposal.proposer);
        hash_u64(hasher, proposal.votes_for_stake);
        hash_u64(hasher, proposal.created_at);
        hash_u64(hasher, proposal.voting_ends_at);
        hash_bool(hasher, proposal.set_mint_authority);
        if let Some(mint) = proposal.new_mint_authority {
            hash_bool(hasher, true);
            hash_bytes(hasher, &mint);
        } else {
            hash_bool(hasher, false);
        }
        hash_bool(hasher, proposal.set_freeze_authority);
        if let Some(freeze) = proposal.new_freeze_authority {
            hash_bool(hasher, true);
            hash_bytes(hasher, &freeze);
        } else {
            hash_bool(hasher, false);
        }
    }
}

fn hash_airdrop_claims(hasher: &mut sha2::Sha256, claims: &ImHashMap<AccountId, u64>) {
    let mut items: Vec<_> = claims.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (account_id, ts) in items {
        hasher.update(account_id);
        hash_u64(hasher, *ts);
    }
}

fn hash_params(hasher: &mut sha2::Sha256, params: &ImHashMap<[u8; 32], [u8; 32]>) {
    let mut items: Vec<_> = params.iter().collect();
    items.sort_by_key(|(key, _)| *key);
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (key, value) in items {
        hasher.update(key);
        hasher.update(value);
    }
}

fn hash_oracle_requests(
    hasher: &mut sha2::Sha256,
    requests: &ImHashMap<[u8; 32], truthlinked_oracle::http_oracle::OracleRequest>,
) {
    let mut items: Vec<_> = requests.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (request_id, req) in items {
        hasher.update(request_id);
        hash_string(hasher, &req.url);
        hash_string(hasher, &req.method);
        hash_bytes(hasher, &req.body);
        hash_u8(hasher, req.response_format as u8);
        if let Some(schema_id) = req.schema_id {
            hasher.update(&schema_id);
        } else {
            hasher.update(&[0u8; 32]);
        }
        hash_u64(hasher, req.requested_at);
        hash_u64(hasher, req.expires_at);
        hasher.update(&req.requesting_cell);
    }
}

fn hash_oracle_pending(
    hasher: &mut sha2::Sha256,
    pending: &ImHashMap<[u8; 32], truthlinked_oracle::http_oracle::OracleTally>,
) {
    let mut items: Vec<_> = pending.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (request_id, tally) in items {
        hasher.update(request_id);
        let mut commits: Vec<_> = tally.commits.iter().collect();
        commits.sort_by_key(|(k, _)| (*k).clone());
        hasher.update(&(commits.len() as u32).to_le_bytes());
        for (val_pk, commit_hash) in commits {
            hash_bytes(hasher, val_pk);
            hasher.update(commit_hash);
        }
        let mut reveals: Vec<_> = tally.reveals.iter().collect();
        reveals.sort_by_key(|(k, _)| (*k).clone());
        hasher.update(&(reveals.len() as u32).to_le_bytes());
        for (val_pk, (body, status)) in reveals {
            hash_bytes(hasher, val_pk);
            hash_bytes(hasher, body);
            hash_u16(hasher, *status);
        }
        hash_u64(hasher, tally.committed_stake);
        hash_u64(hasher, tally.total_stake);
        hash_bool(hasher, tally.commit_phase_closed);
    }
}

fn hash_oracle_results(
    hasher: &mut sha2::Sha256,
    results: &ImHashMap<[u8; 32], truthlinked_oracle::http_oracle::OracleResult>,
) {
    let mut items: Vec<_> = results.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (request_id, res) in items {
        hasher.update(request_id);
        hash_string(hasher, &res.url);
        hash_string(hasher, &res.method);
        hash_bytes(hasher, &res.response_body);
        hash_u16(hasher, res.response_status);
        hasher.update(&res.body_hash);
        hash_u64(hasher, res.finalized_at);
        hash_u64(hasher, res.expires_at);
        hash_u64(hasher, res.quorum_stake_num);
        hash_u64(hasher, res.quorum_stake_den);
    }
}

fn hash_url_proposals(
    hasher: &mut sha2::Sha256,
    proposals: &ImHashMap<String, truthlinked_governance::UrlProposal>,
) {
    let mut items: Vec<_> = proposals.iter().collect();
    items.sort_by_key(|(url, _)| url.as_str());
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (url, proposal) in items {
        hash_string(hasher, url);
        hash_string(hasher, &proposal.url_pattern);
        hasher.update(&proposal.proposer);
        hash_u128(hasher, proposal.bond_amount);
        let mut voters: Vec<Vec<u8>> = proposal.voters.iter().cloned().collect();
        voters.sort();
        hasher.update(&(voters.len() as u32).to_le_bytes());
        for v in voters {
            hash_bytes(hasher, &v);
        }
        hash_u64(hasher, proposal.votes_for_stake);
        hash_u64(hasher, proposal.votes_against_stake);
        hash_u64(hasher, proposal.created_at);
        hash_u64(hasher, proposal.voting_ends_at);
        hash_bool(hasher, proposal.approved);
        hash_bool(hasher, proposal.rejected);
        hash_bool(hasher, proposal.slashed);
        let fmt_tag = match proposal.response_format {
            truthlinked_governance::UrlResponseFormat::Raw => 0u8,
            truthlinked_governance::UrlResponseFormat::JsonCanonical => 1u8,
            truthlinked_governance::UrlResponseFormat::PriceUsd => 2u8,
        };
        hash_u8(hasher, fmt_tag);
        if let Some(id) = proposal.schema_id {
            hasher.update(&id);
        } else {
            hasher.update(&[0u8; 32]);
        }
    }
}

fn hash_schema_proposals(
    hasher: &mut sha2::Sha256,
    proposals: &ImHashMap<[u8; 32], truthlinked_governance::SchemaProposal>,
) {
    let mut items: Vec<_> = proposals.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (schema_id, proposal) in items {
        hasher.update(schema_id);
        let mut keys = proposal.keys.clone();
        keys.sort();
        hasher.update(&(keys.len() as u32).to_le_bytes());
        for key in keys {
            hash_string(hasher, &key);
        }
        hasher.update(&proposal.proposer);
        let mut voters: Vec<Vec<u8>> = proposal.voters.iter().cloned().collect();
        voters.sort();
        hasher.update(&(voters.len() as u32).to_le_bytes());
        for v in voters {
            hash_bytes(hasher, &v);
        }
        hash_u64(hasher, proposal.votes_for_stake);
        hash_u64(hasher, proposal.votes_against_stake);
        hash_u64(hasher, proposal.created_at);
        hash_u64(hasher, proposal.voting_ends_at);
        hash_bool(hasher, proposal.approved);
        hash_bool(hasher, proposal.rejected);
    }
}

fn hash_schema_registry(
    hasher: &mut sha2::Sha256,
    registry: &ImHashMap<[u8; 32], truthlinked_governance::SchemaEntry>,
) {
    let mut items: Vec<_> = registry.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (schema_id, entry) in items {
        hasher.update(schema_id);
        let mut keys = entry.keys.clone();
        keys.sort();
        hasher.update(&(keys.len() as u32).to_le_bytes());
        for key in keys {
            hash_string(hasher, &key);
        }
        hash_u64(hasher, entry.created_at);
        hash_bool(hasher, entry.approved);
    }
}

fn hash_cell_visibility(
    hasher: &mut sha2::Sha256,
    visibility: &ImHashMap<AccountId, truthlinked_governance::CellVisibility>,
) {
    let mut items: Vec<_> = visibility.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    hasher.update(&(items.len() as u32).to_le_bytes());
    for (account_id, tier) in items {
        hasher.update(account_id);
        let tag = match tier {
            truthlinked_governance::CellVisibility::Private => 0u8,
            truthlinked_governance::CellVisibility::Public => 1u8,
        };
        hash_u8(hasher, tag);
    }
}

fn hash_cell_state(hasher: &mut sha2::Sha256, state: &truthlinked_runtime::cells::CellState) {
    let mut cells: Vec<_> = state.cells.iter().collect();
    cells.sort_by_key(|(id, _)| *id);
    hasher.update(&(cells.len() as u32).to_le_bytes());
    for (cell_id, account) in cells {
        hasher.update(cell_id);
        hash_cell_account(hasher, account);
    }

    let mut balances: Vec<_> = state.token_balances.iter().collect();
    balances.sort_by_key(|((c, a), _)| (*c, *a));
    hasher.update(&(balances.len() as u32).to_le_bytes());
    for ((cell_id, account_id), amount) in balances {
        hasher.update(cell_id);
        hasher.update(account_id);
        hash_u128(hasher, *amount);
    }

    let mut frozen: Vec<_> = state.frozen_accounts.iter().collect();
    frozen.sort_by_key(|((c, a), _)| (*c, *a));
    hasher.update(&(frozen.len() as u32).to_le_bytes());
    for ((cell_id, account_id), frozen_flag) in frozen {
        hasher.update(cell_id);
        hasher.update(account_id);
        hash_bool(hasher, *frozen_flag);
    }
}

fn hash_cell_account(hasher: &mut sha2::Sha256, account: &truthlinked_runtime::cells::CellAccount) {
    hasher.update(&account.cell_id);
    hasher.update(&account.owner);
    hash_bytes(hasher, &account.bytecode);

    let mut storage: Vec<_> = account.storage.iter().collect();
    storage.sort_by_key(|(k, _)| *k);
    hasher.update(&(storage.len() as u32).to_le_bytes());
    for (key, value) in storage {
        hasher.update(key);
        hasher.update(value);
    }

    hash_u128(hasher, account.balance);
    hash_bool(hasher, account.is_token);
    if let Some(cfg) = &account.token_config {
        hash_bool(hasher, true);
        hash_token_config(hasher, cfg);
    } else {
        hash_bool(hasher, false);
    }
    hash_u64(hasher, account.created_at);
    match account.upgraded_at {
        Some(ts) => {
            hash_bool(hasher, true);
            hash_u64(hasher, ts);
        }
        None => hash_bool(hasher, false),
    }
    hash_u64(hasher, account.last_rent_paid_height);
    hash_u64(hasher, account.rent_grace_blocks);
    match account.pending_owner {
        Some(id) => {
            hash_bool(hasher, true);
            hasher.update(&id);
        }
        None => hash_bool(hasher, false),
    }
    hash_bool(hasher, account.is_immutable);

    let mut declared_reads = account.declared_reads.clone();
    declared_reads.sort_unstable();
    hash_vec_fixed_32(hasher, &declared_reads);

    let mut declared_writes = account.declared_writes.clone();
    declared_writes.sort_unstable();
    hash_vec_fixed_32(hasher, &declared_writes);

    let mut commutative_keys = account.commutative_keys.clone();
    commutative_keys.sort_unstable();
    hash_vec_fixed_32(hasher, &commutative_keys);

    let mut key_specs = account.storage_key_specs.clone();
    key_specs.sort_by_key(|s| (s.offset, s.len));
    hasher.update(&(key_specs.len() as u32).to_le_bytes());
    for spec in key_specs {
        hash_u64(hasher, spec.offset as u64);
        hash_u64(hasher, spec.len as u64);
    }
    let mut schema_ids = account.oracle_schema_ids.clone();
    schema_ids.sort_unstable();
    hash_vec_fixed_32(hasher, &schema_ids);

    match &account.governance_proposal {
        Some(p) => {
            hash_bool(hasher, true);
            hash_governance_proposal(hasher, p);
        }
        None => hash_bool(hasher, false),
    }

    hash_u64(hasher, account.manifest_version);
    hasher.update(&account.manifest_hash);
}

fn hash_token_config(hasher: &mut sha2::Sha256, cfg: &truthlinked_runtime::cells::TokenConfig) {
    hash_string(hasher, &cfg.name);
    hash_string(hasher, &cfg.symbol);
    hash_u8(hasher, cfg.decimals);
    hash_u128(hasher, cfg.total_supply);
    match cfg.mint_authority {
        Some(id) => {
            hash_bool(hasher, true);
            hasher.update(&id);
        }
        None => hash_bool(hasher, false),
    }
    match cfg.freeze_authority {
        Some(id) => {
            hash_bool(hasher, true);
            hasher.update(&id);
        }
        None => hash_bool(hasher, false),
    }
    hash_u16(hasher, cfg.transfer_fee_bps);
    match cfg.transfer_fee_recipient {
        Some(id) => {
            hash_bool(hasher, true);
            hasher.update(&id);
        }
        None => hash_bool(hasher, false),
    }
    match cfg.transfer_hook {
        Some(id) => {
            hash_bool(hasher, true);
            hasher.update(&id);
        }
        None => hash_bool(hasher, false),
    }
    hash_bool(hasher, cfg.non_transferable);
    match &cfg.metadata_uri {
        Some(uri) => {
            hash_bool(hasher, true);
            hash_string(hasher, uri);
        }
        None => hash_bool(hasher, false),
    }
    match cfg.permanent_delegate {
        Some(id) => {
            hash_bool(hasher, true);
            hasher.update(&id);
        }
        None => hash_bool(hasher, false),
    }
}

fn hash_governance_proposal(
    hasher: &mut sha2::Sha256,
    proposal: &truthlinked_runtime::cells::GovernanceProposal,
) {
    match &proposal.proposal_type {
        truthlinked_runtime::cells::ProposalType::OwnershipTransfer { new_owner } => {
            hash_u8(hasher, 0);
            hasher.update(new_owner);
        }
        truthlinked_runtime::cells::ProposalType::Upgrade {
            new_bytecode,
            declared_reads,
            declared_writes,
            commutative_keys,
            storage_key_specs,
            oracle_schema_ids,
        } => {
            hash_u8(hasher, 1);
            hash_bytes(hasher, new_bytecode);
            let mut reads = declared_reads.clone();
            reads.sort_unstable();
            hash_vec_fixed_32(hasher, &reads);
            let mut writes = declared_writes.clone();
            writes.sort_unstable();
            hash_vec_fixed_32(hasher, &writes);
            let mut comm = commutative_keys.clone();
            comm.sort_unstable();
            hash_vec_fixed_32(hasher, &comm);
            let mut specs = storage_key_specs.clone();
            specs.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.len.cmp(&b.len)));
            hash_u64(hasher, specs.len() as u64);
            for spec in specs {
                hash_u64(hasher, spec.offset as u64);
                hash_u64(hasher, spec.len as u64);
            }
            let mut schema_ids = oracle_schema_ids.clone();
            schema_ids.sort_unstable();
            hash_vec_fixed_32(hasher, &schema_ids);
        }
        truthlinked_runtime::cells::ProposalType::MakeImmutable => {
            hash_u8(hasher, 2);
        }
    }

    hasher.update(&proposal.proposer);
    hash_u64(hasher, proposal.created_at_height);
    hash_u64(hasher, proposal.timelock_blocks);
    hash_bool(hasher, proposal.require_vote);
    hash_u64(hasher, proposal.votes_for);
    hash_u64(hasher, proposal.votes_against);
    let mut voters: Vec<AccountId> = proposal.voters.iter().cloned().collect();
    voters.sort_unstable();
    hasher.update(&(voters.len() as u32).to_le_bytes());
    for v in voters {
        hasher.update(&v);
    }
    hash_bool(hasher, proposal.executed);
}

fn hash_staking_state(hasher: &mut sha2::Sha256, staking: &truthlinked_staking::StakingState) {
    // Hash validators in sorted order for determinism
    let mut validators: Vec<_> = staking.validators.iter().collect();
    validators.sort_by(|a, b| a.0.cmp(b.0));

    tracing::debug!("🔍 Hashing {} validators", validators.len());
    if let Some((first_pk, first_stake)) = validators.first() {
        tracing::info!(
            "  First validator: {}... stake={}",
            hex::encode(&first_pk[..8]),
            first_stake.active_stake
        );
    }

    hasher.update(&(validators.len() as u32).to_le_bytes());
    for (pubkey, stake) in validators {
        hasher.update(&(pubkey.len() as u32).to_le_bytes());
        hasher.update(pubkey);

        // Manually hash ValidatorStake fields for determinism
        hash_u64(hasher, stake.active_stake);

        // Hash unbonding entries in order
        hasher.update(&(stake.unbonding.len() as u32).to_le_bytes());
        for entry in &stake.unbonding {
            hash_u64(hasher, entry.amount);
            hash_u64(hasher, entry.completion_tick);
        }

        // Hash jailed_until
        if let Some(jail_height) = stake.jailed_until {
            hash_bool(hasher, true);
            hash_u64(hasher, jail_height);
        } else {
            hash_bool(hasher, false);
        }
    }

    hash_u64(hasher, staking.current_height);
}
