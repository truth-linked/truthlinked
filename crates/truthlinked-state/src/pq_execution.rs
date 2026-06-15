//! Truthlinked State Src Pq Execution
//!
//! Owns post-quantum transaction types, execution rules, and state transitions.
//! State changes are consensus-sensitive and must preserve deterministic execution and serialization.

// Post-Quantum Execution - FIPS 204 ML-DSA-65 signatures
// This module is consensus-critical. Any state change MUST be deterministic
// across nodes given the same inputs.
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use im::HashMap as ImHashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use truthlinked_core::constants::{ONE_TLKD, TX_SIGN_CONTEXT};
use truthlinked_core::pq_execution::{
    governance_system_cell_id, name_registry_system_cell_id, oracle_governance_system_cell_id,
    staking_system_cell_id, token_governance_system_cell_id, treasury_system_cell_id,
    wtrth_system_cell_id, AccountId, BatchTransferEntry, CellCall, Transaction, TransactionIntent,
};
use truthlinked_governance::params as gp;
use truthlinked_governance::{
    CellVisibility, NameRegistration, PendingNameRegistration, SchemaEntry, SchemaProposal,
    TokenAuthorityProposal, UrlProposal,
};
use truthlinked_oracle::http_oracle::{
    OracleCommit, OracleRequest, OracleResult, OracleReveal, OracleTally,
};
use truthlinked_runtime::cells::CellAccount;
use truthlinked_runtime::types::{
    AccountRecord, CellUpdate, NFTRecord, OracleUpdate, StakingUpdate, StateDiff,
};
use truthlinked_staking::StakingState;

// Immutable state snapshot for parallel execution
pub struct StateSnapshot {
    pub accounts: Arc<ImHashMap<AccountId, AccountRecord>>,
    pub cells: Arc<truthlinked_runtime::cells::CellState>,
    pub params: Arc<ImHashMap<[u8; 32], [u8; 32]>>,
}

impl StateSnapshot {
    pub fn from_state(state: &State) -> Self {
        Self {
            accounts: Arc::new(state.accounts.clone()),
            cells: Arc::new(state.cells.clone()),
            params: Arc::new(state.params.clone()),
        }
    }

    pub fn get_balance(&self, account: &AccountId) -> u128 {
        self.accounts.get(account).map(|a| a.balance).unwrap_or(0)
    }

    pub fn get_cell(&self, cell_id: &AccountId) -> Option<truthlinked_runtime::cells::CellAccount> {
        self.cells.cells.get(cell_id).cloned()
    }
}

// Global snapshot registry - Arc for zero-cost clones
lazy_static::lazy_static! {
    static ref SNAPSHOT_REGISTRY: std::sync::RwLock<Option<Arc<StateSnapshot>>> = std::sync::RwLock::new(None);
}

pub fn set_snapshot(snapshot: StateSnapshot) {
    *SNAPSHOT_REGISTRY.write().unwrap() = Some(Arc::new(snapshot));
}

pub fn get_snapshot() -> Option<Arc<StateSnapshot>> {
    SNAPSHOT_REGISTRY.read().unwrap().clone()
}

//
// GLOBAL ORACLE STATE ACCESSORS
// Written by apply_diff when FinalizeResult / SetVisibility / etc. are processed.
// Read by the Axiom VM http_call host function during execution (read-only, lock-free).
//

lazy_static::lazy_static! {
    /// Finalized oracle results keyed by request_id.
    static ref GLOBAL_ORACLE_RESULTS: std::sync::RwLock<std::collections::HashMap<[u8; 32], truthlinked_oracle::http_oracle::OracleResult>> =
        std::sync::RwLock::new(std::collections::HashMap::new());

    /// Per-cell visibility tier, set by SetCellVisibility.
    static ref GLOBAL_CONTRACT_VISIBILITY: std::sync::RwLock<std::collections::HashMap<AccountId, CellVisibility>> =
        std::sync::RwLock::new(std::collections::HashMap::new());

    /// Approved URL proposals for public-cell access checks.
    static ref GLOBAL_URL_PROPOSALS: std::sync::RwLock<im::HashMap<String, UrlProposal>> =
        std::sync::RwLock::new(im::HashMap::new());
}

/// Called by apply_diff when an OracleResult is finalized.
pub fn register_oracle_result(result: truthlinked_oracle::http_oracle::OracleResult) {
    let mut map = GLOBAL_ORACLE_RESULTS.write().unwrap();
    if map.len() >= crate::constants::MAX_ORACLE_RESULTS {
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, v)| v.expires_at)
            .map(|(k, _)| *k)
        {
            map.remove(&oldest);
        }
    }
    map.insert(result.request_id, result);
}

// ── Auto-settle queue ─────────────────────────────────────────────────────────
// The oracle loop in node.rs tracks newly finalized results and submits
// CallCell(settle) transactions. No global state needed here.

/// Called by maintenance when an oracle result expires.
pub fn remove_oracle_result(request_id: &[u8; 32]) {
    GLOBAL_ORACLE_RESULTS.write().unwrap().remove(request_id);
}

/// Called by apply_diff when a URL proposal is approved.
pub fn register_url_proposal(proposal: UrlProposal) {
    GLOBAL_URL_PROPOSALS
        .write()
        .unwrap()
        .insert(proposal.url_pattern.clone(), proposal);
}

/// Called by apply_diff when cell visibility is set.
pub fn register_cell_visibility(cell_id: AccountId, vis: CellVisibility) {
    GLOBAL_CONTRACT_VISIBILITY
        .write()
        .unwrap()
        .insert(cell_id, vis);
}

/// Used by Axiom VM host to look up a finalized oracle result by request_id.
pub fn get_oracle_result(
    req_id: &[u8; 32],
) -> Option<truthlinked_oracle::http_oracle::OracleResult> {
    GLOBAL_ORACLE_RESULTS.read().unwrap().get(req_id).cloned()
}

/// Used by Axiom VM host to look up cell visibility tier.
pub fn get_cell_visibility(cell_id: &AccountId) -> CellVisibility {
    GLOBAL_CONTRACT_VISIBILITY
        .read()
        .unwrap()
        .get(cell_id)
        .copied()
        .unwrap_or(CellVisibility::Private)
}

/// Used by Axiom VM host to check approved URL proposals.
pub fn get_url_proposals() -> Option<im::HashMap<String, UrlProposal>> {
    Some(GLOBAL_URL_PROPOSALS.read().unwrap().clone())
}

/// Rebuild global oracle/visibility caches from canonical state.
pub fn rehydrate_oracle_globals_from_state(state: &State) {
    {
        let mut results = GLOBAL_ORACLE_RESULTS.write().unwrap();
        results.clear();
        for (k, v) in state.oracle_results.iter() {
            results.insert(*k, v.clone());
        }
    }
    {
        let mut vis = GLOBAL_CONTRACT_VISIBILITY.write().unwrap();
        vis.clear();
        for (k, v) in state.cell_visibility.iter() {
            vis.insert(*k, *v);
        }
    }
    {
        let mut proposals = GLOBAL_URL_PROPOSALS.write().unwrap();
        *proposals = state.url_proposals.clone();
    }
}

/// Rebuild global caches (oracle + governance params) from canonical state.
pub fn rehydrate_runtime_globals_from_state(state: &State) {
    crate::set_current_height(state.staking.current_height);
    rehydrate_oracle_globals_from_state(state);
    truthlinked_governance::params::rehydrate_from_state(state);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub accounts: ImHashMap<AccountId, AccountRecord>,
    pub staking: StakingState,
    pub nfts: ImHashMap<[u8; 32], NFTRecord>, // nft_id -> NFT data
    pub cells: truthlinked_runtime::cells::CellState, // Isolated cell state
    pub accumulated_gas_fees: u128, // Gas fees collected since last distribution (stake-weighted)
    pub accumulated_name_fees: u128, // Name registration fees (equal distribution)
    pub accumulated_compute_fees_tlkd: u128, // TLKD collected from compute escrow (CU-metered)
    pub accumulated_treasury_fees: u128, // TLKD protocol receipts (non-CU; currently unused)
    pub executed_tx_hashes: std::collections::HashSet<[u8; 32]>, // Replay protection
    pub params: ImHashMap<[u8; 32], [u8; 32]>, // On-chain governance parameters
    pub name_registry: ImHashMap<String, NameRegistration>, // name -> registration info
    pub pending_names: ImHashMap<String, PendingNameRegistration>, // Pending validator votes
    pub token_authority_proposals: ImHashMap<AccountId, TokenAuthorityProposal>,
    pub airdrop_claims: ImHashMap<AccountId, u64>, // account_id -> last_claim_timestamp (testnet only)
    pub total_minted: u128,                        // cumulative devnet faucet minted
    pub foundation_mint_authority: Option<AccountId>,
    //  HTTP Oracle consensus state
    /// Pending fetch requests queued by Axiom VM cells this block.
    pub pending_oracle_requests: ImHashMap<[u8; 32], OracleRequest>,
    /// Per-request tally of validator commits and reveals.
    pub oracle_pending: ImHashMap<[u8; 32], OracleTally>,
    /// Finalized oracle results readable by Axiom VM cells.
    pub oracle_results: ImHashMap<[u8; 32], OracleResult>,
    /// URL governance proposals (public cell access control).
    pub url_proposals: ImHashMap<String, UrlProposal>,
    pub schema_proposals: ImHashMap<[u8; 32], SchemaProposal>,
    pub schema_registry: ImHashMap<[u8; 32], SchemaEntry>,
    /// Per-cell visibility tier (Private = any URL, Public = approved only).
    pub cell_visibility: ImHashMap<AccountId, CellVisibility>,
    /// Fees collected in the current emission epoch (reset each epoch).
    pub accumulated_epoch_fees: u128,
    /// Last epoch number that received a treasury emission payout.
    pub last_emission_epoch: u64,
    /// Chain age in whole years (incremented annually for decay calculation).
    pub chain_age_years: u64,
}

impl truthlinked_governance::params::ParamState for State {
    fn params(&self) -> &im::HashMap<[u8; 32], [u8; 32]> {
        &self.params
    }

    fn params_mut(&mut self) -> &mut im::HashMap<[u8; 32], [u8; 32]> {
        &mut self.params
    }
}

impl truthlinked_mcp::McpStateView for State {
    fn cells(&self) -> &truthlinked_runtime::cells::CellState {
        &self.cells
    }

    fn accounts(&self) -> &im::HashMap<AccountId, AccountRecord> {
        &self.accounts
    }
}

impl truthlinked_mcp::private_balance::PrivateBalanceStateView for State {
    fn staking(&self) -> &truthlinked_staking::StakingState {
        &self.staking
    }
}

impl State {
    fn tx_byte_fee(tx: &Transaction) -> Result<u128, String> {
        let byte_weight = tx
            .byte_weight()
            .map_err(|e| format!("Failed to compute tx byte weight: {}", e))?;
        Ok((byte_weight as u128).saturating_mul(gp::get_u64(gp::PARAM_TX_BYTE_FEE) as u128))
    }

    fn verify_transaction_signature(
        &self,
        tx: &Transaction,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        let pk_bytes: [u8; 1952] = match sender_account.pubkey_bytes.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return Err("Invalid public key length".to_string()),
        };

        let sig_bytes: [u8; 3309] = match tx.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return Err("Invalid signature length".to_string()),
        };

        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
            .map_err(|_| "Invalid public key".to_string())?;

        let mut msg = Vec::new();
        // Domain separation with length prefixes
        msg.extend_from_slice(&(tx.genesis_fingerprint.len() as u32).to_le_bytes());
        msg.extend_from_slice(&tx.genesis_fingerprint);
        msg.extend_from_slice(&(tx.sender.len() as u32).to_le_bytes());
        msg.extend_from_slice(&tx.sender);
        msg.extend_from_slice(&tx.nonce.to_le_bytes());
        msg.extend_from_slice(&tx.timestamp.to_le_bytes());
        msg.extend_from_slice(&tx.expiration_height.to_le_bytes());

        let intent_bytes =
            postcard::to_allocvec(&tx.intent).map_err(|_| "Failed to serialize intent")?;
        msg.extend_from_slice(&(intent_bytes.len() as u32).to_le_bytes());
        msg.extend_from_slice(&intent_bytes);

        if !pk.verify(&msg, &sig_bytes, TX_SIGN_CONTEXT) {
            return Err("Signature verification failed".to_string());
        }

        Ok(())
    }

    pub fn validate_transaction_for_mempool(
        &self,
        tx: &Transaction,
        lookahead: u64,
    ) -> Result<(), String> {
        // Verify genesis fingerprint (replay protection)
        let genesis_hash = crate::get_genesis_hash();
        if tx.genesis_fingerprint != genesis_hash {
            return Err(format!(
                "Invalid genesis fingerprint: expected {}, got {}",
                hex::encode(genesis_hash),
                hex::encode(tx.genesis_fingerprint)
            ));
        }

        // Check transaction expiration
        let current_height = crate::get_current_height().unwrap_or(0);
        if tx.expiration_height <= current_height {
            return Err(format!(
                "Transaction expired: height {} <= current {}",
                tx.expiration_height, current_height
            ));
        }

        let sender_account = match self.accounts.get(&tx.sender) {
            Some(account) => account,
            None => return Err("Sender account does not exist".to_string()),
        };

        let min_nonce = sender_account.nonce.saturating_add(1);
        let max_nonce = sender_account.nonce.saturating_add(1 + lookahead);
        if tx.nonce < min_nonce || tx.nonce > max_nonce {
            return Err(format!(
                "Invalid nonce window: expected {}..={}, got {}",
                min_nonce, max_nonce, tx.nonce
            ));
        }

        self.verify_transaction_signature(tx, sender_account)?;
        Ok(())
    }
    fn cu_fee_to_tlkd(cu_fee: u128) -> Result<u128, String> {
        let cu_per_tlkd = gp::get_u64(gp::PARAM_CU_PER_TLKD) as u128;
        if cu_per_tlkd == 0 {
            return Err("cu_per_tlkd is zero".to_string());
        }
        // Convert CU cost into TLKD base units, rounding up.
        Ok(cu_fee
            .checked_mul(ONE_TLKD)
            .ok_or("CU fee overflow")?
            .saturating_add(cu_per_tlkd - 1)
            / cu_per_tlkd)
    }

    fn staking_namespace_positions() -> [u8; 32] {
        hash32(b"truthlinked.staking.positions")
    }

    fn staking_namespace_holders() -> [u8; 32] {
        hash32(b"truthlinked.staking.holders")
    }

    fn staking_map_exists_slot(key: &[u8; 32]) -> [u8; 32] {
        let ns = Self::staking_namespace_positions();
        derive_slot(&ns, &[b"map:exists", key])
    }

    fn staking_map_value_slot(key: &[u8; 32]) -> [u8; 32] {
        let ns = Self::staking_namespace_positions();
        derive_slot(&ns, &[b"map:value", key])
    }

    fn staking_holders_len_slot() -> [u8; 32] {
        let ns = Self::staking_namespace_holders();
        derive_slot(&ns, &[b"vec:len"])
    }

    fn staking_holders_elem_slot(index: u64) -> [u8; 32] {
        let ns = Self::staking_namespace_holders();
        let idx = index.to_le_bytes();
        derive_slot(&ns, &[b"vec:elem", &idx])
    }

    fn decode_u64(raw: &[u8; 32]) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&raw[..8]);
        u64::from_le_bytes(bytes)
    }

    fn decode_staking_position(raw: &[u8; 32]) -> (u128, u64) {
        let mut amount_bytes = [0u8; 16];
        amount_bytes.copy_from_slice(&raw[0..16]);
        let amount = u128::from_le_bytes(amount_bytes);
        let mut end_bytes = [0u8; 8];
        end_bytes.copy_from_slice(&raw[24..32]);
        let lock_end = u64::from_le_bytes(end_bytes);
        (amount, lock_end)
    }

    fn load_staking_holders(&self) -> Vec<[u8; 32]> {
        let cell_id = staking_system_cell_id();
        let cell = match self.cells.cells.get(&cell_id) {
            Some(c) => c,
            None => return vec![],
        };
        let len_slot = Self::staking_holders_len_slot();
        let len_raw = cell.storage.get(&len_slot).cloned().unwrap_or([0u8; 32]);
        let len = Self::decode_u64(&len_raw);
        let mut holders = Vec::new();
        for i in 0..len {
            let slot = Self::staking_holders_elem_slot(i);
            if let Some(raw) = cell.storage.get(&slot) {
                holders.push(*raw);
            }
        }
        holders
    }

    pub fn staking_balance_of(&self, account: &[u8; 32]) -> Option<u64> {
        let cell_id = staking_system_cell_id();
        let cell = self.cells.cells.get(&cell_id)?;
        let exists_slot = Self::staking_map_exists_slot(account);
        let exists = cell.storage.get(&exists_slot).cloned().unwrap_or([0u8; 32]);
        if exists[0] != 1 {
            return None;
        }
        let value_slot = Self::staking_map_value_slot(account);
        let raw = cell.storage.get(&value_slot).cloned().unwrap_or([0u8; 32]);
        let (amount, lock_end) = Self::decode_staking_position(&raw);
        let current_height = self.staking.current_height;
        if current_height >= lock_end {
            return None;
        }
        let remaining = lock_end.saturating_sub(current_height);
        let max_lock = crate::constants::STAKED_TRTH_MAX_LOCK_BLOCKS;
        let remaining = remaining.min(max_lock);
        let staking_balance = amount.saturating_mul(remaining as u128) / (max_lock as u128);
        if staking_balance == 0 {
            None
        } else {
            Some(staking_balance as u64)
        }
    }

    fn split_revenue(amount: u128) -> (u128, u128, u128) {
        use crate::constants::{FEE_SPLIT_STAKERS_BPS, FEE_SPLIT_VALIDATORS_BPS};
        let validators = amount.saturating_mul(FEE_SPLIT_VALIDATORS_BPS) / 10_000;
        let staking = amount.saturating_mul(FEE_SPLIT_STAKERS_BPS) / 10_000;
        let burn = amount.saturating_sub(validators).saturating_sub(staking);
        (validators, staking, burn)
    }
    pub fn genesis() -> Self {
        let mut staking = StakingState::new();
        staking.treasury_account_id = Some(treasury_system_cell_id());
        let mut state = Self {
            accounts: ImHashMap::new(),
            staking,
            nfts: ImHashMap::new(),
            cells: truthlinked_runtime::cells::CellState::new(),
            accumulated_gas_fees: 0,
            accumulated_name_fees: 0,
            accumulated_compute_fees_tlkd: 0,
            accumulated_treasury_fees: 0,
            executed_tx_hashes: std::collections::HashSet::new(),
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
            accumulated_epoch_fees: 0,
            last_emission_epoch: 0,
            chain_age_years: 0,
        };
        truthlinked_governance::params::insert_genesis_params(&mut state);
        truthlinked_governance::params::rehydrate_from_state(&state);
        state
    }

    pub fn lookup_cell(
        &self,
        cell_id: &AccountId,
    ) -> Option<&truthlinked_runtime::cells::CellAccount> {
        self.cells.cells.get(cell_id)
    }

    pub fn compute_transaction_diff(&self, tx: &Transaction) -> Result<StateDiff, String> {
        self.compute_transaction_diff_internal(tx, true)
    }

    pub fn compute_transaction_diff_skip_sig(&self, tx: &Transaction) -> Result<StateDiff, String> {
        self.compute_transaction_diff_internal(tx, false)
    }

    // Core tx validation + diff computation.
    // Note: timestamp validation is intentionally NOT performed here to keep
    // consensus deterministic. Admission-layer checks should handle wall-clock rules.
    fn compute_transaction_diff_internal(
        &self,
        tx: &Transaction,
        verify_sig: bool,
    ) -> Result<StateDiff, String> {
        let mut diff = StateDiff::default();

        // Check replay protection
        let tx_hash = {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            hasher.update(
                &postcard::to_allocvec(tx).map_err(|e| format!("Failed to serialize tx: {}", e))?,
            );
            let hash_bytes: [u8; 32] = *hasher.finalize().as_bytes();
            hash_bytes
        };

        if self.executed_tx_hashes.contains(&tx_hash) {
            return Err("Transaction already executed (replay detected)".to_string());
        }

        // Verify genesis fingerprint (replay protection)
        let genesis_hash = crate::get_genesis_hash();
        if tx.genesis_fingerprint != genesis_hash {
            return Err(format!(
                "Invalid genesis fingerprint: expected {}, got {}",
                hex::encode(genesis_hash),
                hex::encode(tx.genesis_fingerprint)
            ));
        }

        // Check transaction expiration
        let current_height = crate::get_current_height().unwrap_or(0);
        if tx.expiration_height <= current_height {
            return Err(format!(
                "Transaction expired: height {} <= current {}",
                tx.expiration_height, current_height
            ));
        }

        // Get sender account (must exist for all tx types)
        let sender_account = match self.accounts.get(&tx.sender) {
            Some(account) => Cow::Borrowed(account),
            None => return Err("Sender account does not exist".to_string()),
        };
        let sender_account = sender_account.as_ref();

        // Enforce strict per-account nonce.
        if tx.nonce != sender_account.nonce.saturating_add(1) {
            return Err(format!(
                "Invalid nonce: expected {}, got {}",
                sender_account.nonce.saturating_add(1),
                tx.nonce
            ));
        }
        diff.nonce_updates.push((tx.sender, tx.nonce));

        // Verify signature (if not already verified in parallel batch)
        if verify_sig {
            self.verify_transaction_signature(tx, sender_account)?;
            diff.gas_breakdown
                .push(("Signature verify (ML-DSA-65)".to_string(), 500));
        } else {
            diff.gas_breakdown
                .push(("Signature verify (ML-DSA-65)".to_string(), 500));
        }

        let tx_byte_fee = if matches!(tx.intent, TransactionIntent::Claim { .. }) {
            0
        } else {
            Self::tx_byte_fee(tx)?
        };
        if tx_byte_fee > 0 {
            diff.gas_breakdown
                .push(("Serialized tx byte fee".to_string(), tx_byte_fee));
        }

        // Validate minimum fee for spam prevention
        // TLKD fees apply only to Transfer / BatchTransfer. All other intents use CU.
        let (required_trth_fee, required_cu_fee) = match &tx.intent {
            // ── TLKD-fee intents ─────────────────────────────────────────
            TransactionIntent::Transfer { .. } => {
                (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128 + tx_byte_fee, 0)
            }
            TransactionIntent::TransferToName { .. } => {
                (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128 + tx_byte_fee, 0)
            }
            TransactionIntent::BatchTransfer { transfers } => (
                (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
                    .saturating_mul(transfers.len() as u128)
                    .saturating_add(tx_byte_fee),
                0,
            ),
            TransactionIntent::BatchTransferToName { transfers } => (
                (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
                    .saturating_mul(transfers.len() as u128)
                    .saturating_add(tx_byte_fee),
                0,
            ),
            // ── CU-fee intents ───────────────────────────────────────────
            TransactionIntent::Stake { .. } => (0, gp::get_u64(gp::PARAM_GAS_STAKE)),
            TransactionIntent::Unstake { .. } => (0, gp::get_u64(gp::PARAM_GAS_UNSTAKE)),
            TransactionIntent::WithdrawStake => (0, gp::get_u64(gp::PARAM_GAS_WITHDRAW)),
            TransactionIntent::Unjail => (0, gp::get_u64(gp::PARAM_GAS_UNJAIL)),
            TransactionIntent::TokenTransfer { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TOKEN_TRANSFER))
            }
            TransactionIntent::TokenMint { .. } => (0, gp::get_u64(gp::PARAM_GAS_TOKEN_MINT)),
            TransactionIntent::TokenBurn { .. } => (0, gp::get_u64(gp::PARAM_GAS_TOKEN_BURN)),
            TransactionIntent::TokenFreeze { .. } => (0, gp::get_u64(gp::PARAM_GAS_TOKEN_TRANSFER)),
            TransactionIntent::TokenThaw { .. } => (0, gp::get_u64(gp::PARAM_GAS_TOKEN_TRANSFER)),
            TransactionIntent::MintNFT { .. } => (0, gp::get_u64(gp::PARAM_GAS_MINT_NFT)),
            TransactionIntent::TransferNFT { .. } => (0, gp::get_u64(gp::PARAM_GAS_TRANSFER_NFT)),
            TransactionIntent::BurnNFT { .. } => (0, gp::get_u64(gp::PARAM_GAS_BURN_NFT)),
            TransactionIntent::ApproveNFT { .. } => (0, gp::get_u64(gp::PARAM_GAS_APPROVE_NFT)),
            TransactionIntent::RotateKey { .. } => (0, gp::get_u64(gp::PARAM_GAS_ROTATE_KEY)),
            TransactionIntent::WrapTLKD { .. } | TransactionIntent::UnwrapTLKD { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER))
            }
            TransactionIntent::DepositCompute { .. } => (0, gp::get_u64(gp::PARAM_GAS_TRANSFER)),
            TransactionIntent::WithdrawCompute { .. } => (0, gp::get_u64(gp::PARAM_GAS_TRANSFER)),
            TransactionIntent::DeployCell { .. } => (0, gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL)),
            TransactionIntent::DeployToken { .. } => (0, gp::get_u64(gp::PARAM_GAS_DEPLOY_TOKEN)),
            TransactionIntent::UpgradeCell { .. } => (0, gp::get_u64(gp::PARAM_GAS_UPGRADE_CELL)),
            TransactionIntent::TransferOwnership { .. }
            | TransactionIntent::AcceptOwnership { .. }
            | TransactionIntent::MakeImmutable { .. }
            | TransactionIntent::CloseCell { .. }
            | TransactionIntent::ProposeCellUpgrade { .. }
            | TransactionIntent::ProposeCellOwnershipTransfer { .. }
            | TransactionIntent::ProposeCellMakeImmutable { .. }
            | TransactionIntent::VoteCellProposal { .. }
            | TransactionIntent::ExecuteCellProposal { .. }
            | TransactionIntent::ProposeTokenAuthority { .. }
            | TransactionIntent::VoteTokenAuthority { .. }
            | TransactionIntent::CallSystem { .. }
            | TransactionIntent::ProposeUrl { .. }
            | TransactionIntent::VoteUrl { .. }
            | TransactionIntent::ReportMaliciousUrl { .. }
            | TransactionIntent::SetCellVisibility { .. }
            | TransactionIntent::SubmitOracleCommit { .. }
            | TransactionIntent::SubmitOracleReveal { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER))
            }
            TransactionIntent::CallCell { gas_limit, .. } => (0, *gas_limit),
            TransactionIntent::CallCellChain { gas_limit, .. } => (0, *gas_limit),
            TransactionIntent::McpToolCall { .. } => (0, gp::get_u64(gp::PARAM_GAS_TRANSFER) * 2),
            TransactionIntent::PrivateBalanceInit { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL))
            }
            TransactionIntent::PrivateBalanceDeposit { .. }
            | TransactionIntent::PrivateBalanceWithdraw { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER))
            }
            TransactionIntent::PrivateBalanceConfidentialTransfer { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER) * 3)
            }
            TransactionIntent::RegisterMcpTool { .. }
            | TransactionIntent::RegisterMcpResource { .. }
            | TransactionIntent::RegisterMcpPrompt { .. }
            | TransactionIntent::RegisterAgent { .. }
            | TransactionIntent::SuspendAgent { .. }
            | TransactionIntent::ReinstateAgent { .. } => (0, 0),
            // ── Free ─────────────────────────────────────────────────────
            TransactionIntent::Claim { .. } => (0, 0),
        };

        // Store tx_hash in diff for replay protection
        diff.tx_hash = tx_hash;

        // Process intent
        match &tx.intent {
            TransactionIntent::Transfer {
                recipient,
                recipient_pubkey,
                amount,
            } => {
                self.compute_transfer_diff(
                    &mut diff,
                    tx.sender,
                    *recipient,
                    recipient_pubkey.as_deref().unwrap_or(&[]),
                    *amount,
                    sender_account,
                )?;
            }
            TransactionIntent::TransferToName { name, amount } => {
                let recipient = self.resolve_name_to_account(name, self.staking.current_height)?;
                self.compute_transfer_diff(
                    &mut diff,
                    tx.sender,
                    recipient,
                    &[],
                    *amount,
                    sender_account,
                )?;
            }
            TransactionIntent::BatchTransfer { transfers } => {
                self.compute_batch_transfer_diff(&mut diff, tx.sender, transfers, sender_account)?;
            }
            TransactionIntent::BatchTransferToName { transfers } => {
                let mut resolved = Vec::with_capacity(transfers.len());
                for entry in transfers {
                    let recipient =
                        self.resolve_name_to_account(&entry.name, self.staking.current_height)?;
                    resolved.push(BatchTransferEntry {
                        recipient,
                        recipient_pubkey: None,
                        amount: entry.amount,
                    });
                }
                self.compute_batch_transfer_diff(&mut diff, tx.sender, &resolved, sender_account)?;
            }
            TransactionIntent::Claim {
                recipient,
                recipient_pubkey,
                amount,
            } => {
                tracing::info!(
                    "💰 Executing Claim: recipient={}, amount={}",
                    hex::encode(recipient),
                    amount
                );
                self.compute_claim_diff(
                    &mut diff,
                    tx.sender,
                    *recipient,
                    recipient_pubkey.as_deref().unwrap_or(&[]),
                    *amount,
                    tx.timestamp,
                )?;
                tracing::info!("💰 Claim executed successfully");
            }
            TransactionIntent::RotateKey { new_pubkey } => {
                self.compute_rotate_key_diff(&mut diff, tx.sender, new_pubkey, sender_account)?;
            }
            TransactionIntent::WrapTLKD { amount } => {
                self.compute_wrap_trth_diff(&mut diff, tx.sender, *amount, sender_account)?;
            }
            TransactionIntent::UnwrapTLKD { amount } => {
                self.compute_unwrap_trth_diff(&mut diff, tx.sender, *amount, sender_account)?;
            }
            TransactionIntent::DepositCompute { amount } => {
                self.compute_deposit_compute_diff(&mut diff, tx.sender, *amount, sender_account)?;
            }
            TransactionIntent::WithdrawCompute { amount } => {
                self.compute_withdraw_compute_diff(&mut diff, tx.sender, *amount, sender_account)?;
            }
            TransactionIntent::Stake { .. } => {
                return Err("Staking intents disabled: use staking controller cell".to_string());
            }
            TransactionIntent::Unstake { .. } => {
                return Err("Unstake intents disabled: use staking controller cell".to_string());
            }
            TransactionIntent::WithdrawStake => {
                return Err("Withdraw intents disabled: use staking controller cell".to_string());
            }
            TransactionIntent::Unjail => {
                return Err("Unjail intents disabled: use staking controller cell".to_string());
            }
            TransactionIntent::ProposeTokenAuthority { .. }
            | TransactionIntent::VoteTokenAuthority { .. }
            | TransactionIntent::CallSystem { .. } => {
                return Err("Intent disabled: use the corresponding system cell".to_string());
            }
            TransactionIntent::ProposeUrl {
                url_pattern,
                bond_amount,
                voting_period_blocks,
            } => {
                self.compute_propose_url_diff(
                    &mut diff,
                    tx.sender,
                    url_pattern,
                    *bond_amount,
                    *voting_period_blocks,
                    tx.timestamp,
                    sender_account,
                )?;
            }
            TransactionIntent::VoteUrl {
                url_pattern,
                approve,
            } => {
                self.compute_vote_url_diff(&mut diff, url_pattern, *approve, sender_account)?;
            }
            TransactionIntent::ReportMaliciousUrl {
                url_pattern,
                evidence,
            } => {
                self.compute_report_malicious_url_diff(&mut diff, url_pattern, evidence)?;
            }
            TransactionIntent::MintNFT {
                nft_id,
                name,
                metadata_uri,
                collection,
                royalty_bps,
                royalty_recipient,
            } => {
                self.compute_mint_nft_diff(
                    &mut diff,
                    tx.sender,
                    *nft_id,
                    name,
                    metadata_uri,
                    *collection,
                    *royalty_bps,
                    *royalty_recipient,
                    tx.timestamp,
                )?;
            }
            TransactionIntent::TransferNFT {
                nft_id,
                recipient,
                recipient_pubkey,
                sale_price,
            } => {
                self.compute_transfer_nft_diff(
                    &mut diff,
                    tx.sender,
                    *nft_id,
                    *recipient,
                    recipient_pubkey.as_deref().unwrap_or(&[]),
                    *sale_price,
                    sender_account,
                )?;
            }
            TransactionIntent::BurnNFT { nft_id } => {
                self.compute_burn_nft_diff(&mut diff, tx.sender, *nft_id, sender_account)?;
            }
            TransactionIntent::ApproveNFT { nft_id, approved } => {
                self.compute_approve_nft_diff(
                    &mut diff,
                    tx.sender,
                    *nft_id,
                    *approved,
                    sender_account,
                )?;
            }

            // Cell transactions
            TransactionIntent::DeployCell {
                cell_id,
                bytecode,
                initial_balance,
                declared_reads,
                declared_writes,
                commutative_keys,
                storage_key_specs,
                oracle_schema_ids,
            } => {
                self.compute_deploy_cell_diff(
                    &mut diff,
                    tx.sender,
                    *cell_id,
                    bytecode,
                    *initial_balance,
                    tx.timestamp,
                    declared_reads,
                    declared_writes,
                    commutative_keys,
                    storage_key_specs,
                    oracle_schema_ids,
                    sender_account,
                )?;
            }
            TransactionIntent::DeployToken {
                cell_id,
                name,
                symbol,
                decimals,
                total_supply,
                transfer_fee_bps,
                transfer_fee_recipient,
                non_transferable,
            } => {
                self.compute_deploy_token_diff(
                    &mut diff,
                    tx.sender,
                    *cell_id,
                    name,
                    symbol,
                    *decimals,
                    *total_supply,
                    *transfer_fee_bps,
                    *transfer_fee_recipient,
                    *non_transferable,
                    tx.timestamp,
                    sender_account,
                )?;
            }
            TransactionIntent::CallCell {
                cell_id,
                calldata,
                value,
                gas_limit,
            } => {
                let current_height = self.staking.current_height;
                self.compute_call_cell_diff(
                    &mut diff,
                    tx.sender,
                    *cell_id,
                    calldata,
                    *value,
                    *gas_limit,
                    tx.timestamp,
                    current_height,
                    sender_account,
                )?;
            }
            TransactionIntent::CallCellChain { calls, gas_limit } => {
                self.compute_call_chain_diff(
                    &mut diff,
                    tx.sender,
                    calls,
                    *gas_limit,
                    sender_account,
                    false,
                )?;
            }
            TransactionIntent::UpgradeCell {
                cell_id,
                new_bytecode,
                new_declared_reads,
                new_declared_writes,
                new_commutative_keys,
                new_storage_key_specs,
                new_oracle_schema_ids,
            } => {
                self.compute_upgrade_cell_diff(
                    &mut diff,
                    tx.sender,
                    *cell_id,
                    new_bytecode,
                    new_declared_reads,
                    new_declared_writes,
                    new_commutative_keys,
                    new_storage_key_specs,
                    new_oracle_schema_ids,
                    tx.timestamp,
                    sender_account,
                )?;
            }
            TransactionIntent::TransferOwnership { cell_id, new_owner } => {
                self.compute_transfer_ownership_diff(&mut diff, tx.sender, *cell_id, *new_owner)?;
            }
            TransactionIntent::AcceptOwnership { cell_id } => {
                diff.cell_updates.push(CellUpdate::AcceptOwnership {
                    cell_id: *cell_id,
                    caller: tx.sender,
                });
                diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
            }
            TransactionIntent::MakeImmutable { cell_id } => {
                self.compute_make_immutable_diff(&mut diff, tx.sender, *cell_id)?;
            }
            TransactionIntent::CloseCell { cell_id } => {
                self.compute_close_cell_diff(&mut diff, tx.sender, *cell_id, sender_account)?;
            }
            TransactionIntent::ProposeCellUpgrade {
                cell_id,
                new_bytecode,
                new_declared_reads,
                new_declared_writes,
                new_commutative_keys,
                new_storage_key_specs,
                new_oracle_schema_ids,
                timelock_blocks,
            } => {
                self.compute_propose_cell_upgrade_diff(
                    &mut diff,
                    tx.sender,
                    *cell_id,
                    new_bytecode,
                    new_declared_reads,
                    new_declared_writes,
                    new_commutative_keys,
                    new_storage_key_specs,
                    new_oracle_schema_ids,
                    *timelock_blocks,
                    sender_account,
                )?;
            }
            TransactionIntent::ProposeCellOwnershipTransfer {
                cell_id,
                new_owner,
                timelock_blocks,
            } => {
                self.compute_propose_cell_ownership_transfer_diff(
                    &mut diff,
                    tx.sender,
                    *cell_id,
                    *new_owner,
                    *timelock_blocks,
                    sender_account,
                )?;
            }
            TransactionIntent::ProposeCellMakeImmutable {
                cell_id,
                timelock_blocks,
            } => {
                self.compute_propose_cell_make_immutable_diff(
                    &mut diff,
                    tx.sender,
                    *cell_id,
                    *timelock_blocks,
                    sender_account,
                )?;
            }
            TransactionIntent::VoteCellProposal { cell_id, approve } => {
                self.compute_vote_cell_proposal_diff(
                    &mut diff,
                    tx.sender,
                    *cell_id,
                    *approve,
                    sender_account,
                )?;
            }
            TransactionIntent::ExecuteCellProposal { cell_id } => {
                self.compute_execute_cell_proposal_diff(
                    &mut diff,
                    tx.sender,
                    *cell_id,
                    sender_account,
                )?;
            }
            TransactionIntent::TokenTransfer {
                token_cell,
                recipient,
                amount,
            } => {
                self.compute_token_transfer_diff(
                    &mut diff,
                    tx.sender,
                    *token_cell,
                    *recipient,
                    *amount,
                    tx.timestamp,
                )?;
            }
            TransactionIntent::TokenMint {
                token_cell,
                recipient,
                amount,
            } => {
                self.compute_token_mint_diff(
                    &mut diff,
                    tx.sender,
                    *token_cell,
                    *recipient,
                    *amount,
                )?;
            }
            TransactionIntent::TokenBurn { token_cell, amount } => {
                self.compute_token_burn_diff(&mut diff, tx.sender, *token_cell, *amount)?;
            }
            TransactionIntent::TokenFreeze {
                token_cell,
                account,
            } => {
                self.compute_token_freeze_diff(&mut diff, tx.sender, *token_cell, *account)?;
            }
            TransactionIntent::TokenThaw {
                token_cell,
                account,
            } => {
                self.compute_token_thaw_diff(&mut diff, tx.sender, *token_cell, *account)?;
            }
            //  ON-CHAIN MCP INTENTS
            TransactionIntent::RegisterMcpTool {
                tool_id,
                bytecode,
                name,
                input_schema_json,
                category,
                declared_reads,
                declared_writes,
                commutative_keys,
                oracle_schema_ids,
                registry_id,
            } => {
                if tx.sender != system_authority_id() {
                    return Err("RegisterMcpTool is protocol-governance only".to_string());
                }
                let mcp_intent = truthlinked_mcp::McpIntent::RegisterMcpTool {
                    tool_id: *tool_id,
                    bytecode: bytecode.clone(),
                    name: name.clone(),
                    input_schema_json: input_schema_json.clone(),
                    category: *category,
                    declared_reads: declared_reads.clone(),
                    declared_writes: declared_writes.clone(),
                    commutative_keys: commutative_keys.clone(),
                    oracle_schema_ids: oracle_schema_ids.clone(),
                    registry_id: *registry_id,
                };
                let mcp_diff = truthlinked_mcp::diff_register_tool(
                    self,
                    tx.sender,
                    &mcp_intent,
                    tx.timestamp,
                )?;
                diff.cell_updates.extend(mcp_diff.cell_updates);
                diff.cu_fee = mcp_diff.cu_fee;
            }

            TransactionIntent::RegisterMcpResource {
                resource_id,
                bytecode,
                name,
                uri_scheme,
                mime_type,
                initial_data,
                declared_reads,
                declared_writes,
                oracle_schema_ids,
                registry_id,
            } => {
                // Resources are deployed as standard cells via the existing DeployCell path.
                // Registry update is handled by diff_register_tool's resource variant.
                // For now: deploy the resource cell + update registry storage.
                let mcp_intent = truthlinked_mcp::McpIntent::RegisterMcpResource {
                    resource_id: *resource_id,
                    bytecode: bytecode.clone(),
                    name: name.clone(),
                    uri_scheme: uri_scheme.clone(),
                    mime_type: mime_type.clone(),
                    initial_data: initial_data.clone(),
                    declared_reads: declared_reads.clone(),
                    declared_writes: declared_writes.clone(),
                    oracle_schema_ids: oracle_schema_ids.clone(),
                    registry_id: *registry_id,
                };
                let mcp_diff = truthlinked_mcp::diff_register_resource(
                    self,
                    tx.sender,
                    &mcp_intent,
                    tx.timestamp,
                )?;
                diff.cell_updates.extend(mcp_diff.cell_updates);
                diff.cu_fee = mcp_diff.cu_fee;
            }

            TransactionIntent::RegisterMcpPrompt {
                prompt_id,
                name,
                template_bytes,
                arguments,
                registry_id,
            } => {
                let mcp_intent = truthlinked_mcp::McpIntent::RegisterMcpPrompt {
                    prompt_id: *prompt_id,
                    name: name.clone(),
                    template_bytes: template_bytes.clone(),
                    arguments: arguments.clone(),
                    registry_id: *registry_id,
                };
                let mcp_diff = truthlinked_mcp::diff_register_prompt(
                    self,
                    tx.sender,
                    &mcp_intent,
                    tx.timestamp,
                )?;
                diff.cell_updates.extend(mcp_diff.cell_updates);
                diff.cu_fee = mcp_diff.cu_fee;
            }

            TransactionIntent::RegisterAgent {
                agent_id,
                policy_cell_id,
                agent_registry_id,
            } => {
                let mcp_intent = truthlinked_mcp::McpIntent::RegisterAgent {
                    agent_id: *agent_id,
                    policy_cell_id: *policy_cell_id,
                    agent_registry_id: *agent_registry_id,
                };
                let mcp_diff = truthlinked_mcp::diff_register_agent(
                    self,
                    tx.sender,
                    &mcp_intent,
                    tx.timestamp,
                )?;
                diff.cell_updates.extend(mcp_diff.cell_updates);
                diff.cu_fee = mcp_diff.cu_fee;
            }

            TransactionIntent::SuspendAgent { .. } | TransactionIntent::ReinstateAgent { .. } => {
                let mcp_intent = match &tx.intent {
                    TransactionIntent::SuspendAgent {
                        agent_id,
                        agent_registry_id,
                        reason,
                    } => truthlinked_mcp::McpIntent::SuspendAgent {
                        agent_id: *agent_id,
                        agent_registry_id: *agent_registry_id,
                        reason: reason.clone(),
                    },
                    TransactionIntent::ReinstateAgent {
                        agent_id,
                        agent_registry_id,
                    } => truthlinked_mcp::McpIntent::ReinstateAgent {
                        agent_id: *agent_id,
                        agent_registry_id: *agent_registry_id,
                    },
                    _ => unreachable!(),
                };
                let mcp_diff =
                    truthlinked_mcp::diff_set_agent_status(self, tx.sender, &mcp_intent)?;
                diff.cell_updates.extend(mcp_diff.cell_updates);
                diff.cu_fee = mcp_diff.cu_fee;
            }

            TransactionIntent::McpToolCall {
                agent_id,
                tool_id,
                tool_calldata,
                value,
                gas_limit,
                policy_cell_id,
                action_log_id,
                timestamp,
            } => {
                let mcp_intent = truthlinked_mcp::McpIntent::McpToolCall {
                    agent_id: *agent_id,
                    tool_id: *tool_id,
                    tool_calldata: tool_calldata.clone(),
                    value: *value,
                    gas_limit: *gas_limit,
                    policy_cell_id: *policy_cell_id,
                    action_log_id: *action_log_id,
                    timestamp: *timestamp,
                };
                let chain_intent = truthlinked_mcp::compile_tool_call_to_chain(&mcp_intent)
                    .map_err(|e| format!("McpToolCall compile error: {}", e))?;
                if let TransactionIntent::CallCellChain {
                    calls,
                    gas_limit: gl,
                } = chain_intent
                {
                    self.compute_call_chain_diff(
                        &mut diff,
                        tx.sender,
                        &calls,
                        gl,
                        sender_account,
                        true,
                    )?;
                } else {
                    return Err("McpToolCall did not compile to CallCellChain".into());
                }
            }

            TransactionIntent::PrivateBalanceInit {
                cell_id,
                agent_id,
                encrypted_balance,
                commitment,
                commit_nonce,
            } => {
                let pb_intent =
                    truthlinked_mcp::private_balance::PrivateBalanceIntent::InitPrivateBalance {
                        cell_id: *cell_id,
                        agent_id: *agent_id,
                        encrypted_balance: encrypted_balance.clone(),
                        commitment: *commitment,
                        commit_nonce: *commit_nonce,
                    };
                let pb_diff = truthlinked_mcp::private_balance::circuit_init_private_balance(
                    self,
                    tx.sender,
                    &pb_intent,
                    tx.timestamp,
                )?;
                diff.account_updates.extend(pb_diff.account_updates);
                diff.cell_updates.extend(pb_diff.cell_updates);
                diff.native_debits.extend(pb_diff.native_debits);
                diff.native_transfers.extend(pb_diff.native_transfers);
                diff.cu_fee = pb_diff.cu_fee;
            }
            TransactionIntent::PrivateBalanceDeposit {
                cell_id,
                agent_id,
                amount,
                new_encrypted_balance,
                new_commitment,
                new_commit_nonce,
                old_commitment,
            } => {
                let pb_intent = truthlinked_mcp::private_balance::PrivateBalanceIntent::Deposit {
                    cell_id: *cell_id,
                    agent_id: *agent_id,
                    amount: *amount,
                    new_encrypted_balance: new_encrypted_balance.clone(),
                    new_commitment: *new_commitment,
                    new_commit_nonce: *new_commit_nonce,
                    old_commitment: *old_commitment,
                };
                let pb_diff = truthlinked_mcp::private_balance::circuit_deposit(
                    self,
                    tx.sender,
                    &pb_intent,
                    tx.timestamp,
                )?;
                diff.account_updates.extend(pb_diff.account_updates);
                diff.cell_updates.extend(pb_diff.cell_updates);
                diff.native_debits.extend(pb_diff.native_debits);
                diff.native_transfers.extend(pb_diff.native_transfers);
                diff.cu_fee = pb_diff.cu_fee;
            }
            TransactionIntent::PrivateBalanceWithdraw {
                cell_id,
                agent_id,
                amount,
                recipient,
                new_encrypted_balance,
                new_commitment,
                new_commit_nonce,
                old_commitment,
            } => {
                let pb_intent = truthlinked_mcp::private_balance::PrivateBalanceIntent::Withdraw {
                    cell_id: *cell_id,
                    agent_id: *agent_id,
                    amount: *amount,
                    recipient: *recipient,
                    new_encrypted_balance: new_encrypted_balance.clone(),
                    new_commitment: *new_commitment,
                    new_commit_nonce: *new_commit_nonce,
                    old_commitment: *old_commitment,
                };
                let pb_diff = truthlinked_mcp::private_balance::circuit_withdraw(
                    self,
                    tx.sender,
                    &pb_intent,
                    tx.timestamp,
                )?;
                diff.account_updates.extend(pb_diff.account_updates);
                diff.cell_updates.extend(pb_diff.cell_updates);
                diff.native_debits.extend(pb_diff.native_debits);
                diff.native_transfers.extend(pb_diff.native_transfers);
                diff.cu_fee = pb_diff.cu_fee;
            }

            TransactionIntent::PrivateBalanceConfidentialTransfer {
                sender_cell_id,
                sender_agent_id,
                recipient_cell_id,
                amount_commitment,
                stark_proof,
                sender_new_encrypted,
                sender_new_commitment,
                sender_new_commit_nonce,
                sender_old_commitment,
                recipient_new_encrypted,
                recipient_new_commitment,
                recipient_new_commit_nonce,
                recipient_old_commitment,
            } => {
                let pb_intent =
                    truthlinked_mcp::private_balance::PrivateBalanceIntent::ConfidentialTransfer {
                        sender_cell_id: *sender_cell_id,
                        sender_agent_id: *sender_agent_id,
                        recipient_cell_id: *recipient_cell_id,
                        amount_commitment: *amount_commitment,
                        stark_proof: stark_proof.clone(),
                        sender_new_encrypted: sender_new_encrypted.clone(),
                        sender_new_commitment: *sender_new_commitment,
                        sender_new_commit_nonce: *sender_new_commit_nonce,
                        sender_old_commitment: *sender_old_commitment,
                        recipient_new_encrypted: recipient_new_encrypted.clone(),
                        recipient_new_commitment: *recipient_new_commitment,
                        recipient_new_commit_nonce: *recipient_new_commit_nonce,
                        recipient_old_commitment: *recipient_old_commitment,
                    };
                let pb_diff = truthlinked_mcp::private_balance::circuit_confidential_transfer(
                    self,
                    tx.sender,
                    &pb_intent,
                    tx.timestamp,
                )?;
                diff.account_updates.extend(pb_diff.account_updates);
                diff.cell_updates.extend(pb_diff.cell_updates);
                diff.native_debits.extend(pb_diff.native_debits);
                diff.native_transfers.extend(pb_diff.native_transfers);
                diff.cu_fee = pb_diff.cu_fee;
            }

            TransactionIntent::SetCellVisibility {
                cell_id,
                visibility,
            } => {
                self.compute_set_cell_visibility_diff(&mut diff, tx.sender, *cell_id, *visibility)?;
            }
            TransactionIntent::SubmitOracleCommit {
                request_id,
                commit_hash,
            } => {
                self.compute_oracle_commit_diff(
                    &mut diff,
                    tx.sender,
                    *request_id,
                    *commit_hash,
                    sender_account,
                )?;
            }
            TransactionIntent::SubmitOracleReveal {
                request_id,
                response_body,
                response_status,
            } => {
                self.compute_oracle_reveal_diff(
                    &mut diff,
                    tx.sender,
                    *request_id,
                    response_body,
                    *response_status,
                    sender_account,
                )?;
            }
        }

        // Enforce strict fee domains: TLKD-fee intents must not consume CU.
        // Some intent handlers set diff.cu_fee internally - set it from required fee if missing.
        if required_trth_fee > 0 {
            diff.cu_fee = 0;
            if diff.gas_fee < required_trth_fee {
                diff.gas_fee = required_trth_fee;
            }
        } else if required_cu_fee > 0 && diff.cu_fee == 0 {
            diff.cu_fee = required_cu_fee as u128;
        }
        if required_trth_fee == 0 && tx_byte_fee > 0 && diff.gas_fee < tx_byte_fee {
            diff.gas_fee = tx_byte_fee;
        }

        // Validate fee AFTER processing
        if required_trth_fee > 0 && diff.gas_fee < required_trth_fee {
            return Err(format!(
                "Insufficient TLKD fee: {} < {}",
                diff.gas_fee, required_trth_fee
            ));
        }
        if required_cu_fee > 0 && diff.cu_fee < required_cu_fee as u128 {
            return Err(format!(
                "Insufficient CU fee: {} < {}",
                diff.cu_fee, required_cu_fee
            ));
        }

        // Debit gas from sender unless already included in a native debit.
        let gas_already_debited = matches!(
            tx.intent,
            TransactionIntent::Transfer { .. }
                | TransactionIntent::TransferToName { .. }
                | TransactionIntent::BatchTransfer { .. }
                | TransactionIntent::BatchTransferToName { .. }
        );
        if diff.gas_fee > 0 {
            if gas_already_debited {
                let embedded_fee = match &tx.intent {
                    TransactionIntent::BatchTransfer { transfers } => {
                        (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
                            .saturating_mul(transfers.len() as u128)
                    }
                    TransactionIntent::BatchTransferToName { transfers } => {
                        (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
                            .saturating_mul(transfers.len() as u128)
                    }
                    _ => gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128,
                };
                if diff.gas_fee > embedded_fee {
                    let extra_fee = diff.gas_fee.saturating_sub(embedded_fee);
                    let existing_debits: u128 = diff
                        .native_debits
                        .iter()
                        .filter(|(id, _)| *id == tx.sender)
                        .map(|(_, amount)| *amount)
                        .sum();
                    let total_debit = existing_debits
                        .checked_add(extra_fee)
                        .ok_or("Gas fee overflow")?;
                    if sender_account.balance < total_debit {
                        return Err("Insufficient balance for byte-weighted gas fee".to_string());
                    }
                    diff.native_debits.push((tx.sender, extra_fee));
                }
            } else {
                let sender_balance_after = diff
                    .account_updates
                    .get(&tx.sender)
                    .map(|acc| acc.balance)
                    .unwrap_or(sender_account.balance);
                if sender_balance_after < diff.gas_fee {
                    return Err("Insufficient balance for gas fee".to_string());
                }
                diff.native_debits.push((tx.sender, diff.gas_fee));
            }
        }

        // Debit compute escrow (TLKD) for CU-metered fees.
        if diff.cu_fee > 0 {
            let escrow_credits: u128 = diff
                .compute_escrow_credits
                .iter()
                .filter(|(id, _)| *id == tx.sender)
                .map(|(_, amt)| *amt)
                .sum();
            let escrow_debits: u128 = diff
                .compute_escrow_debits
                .iter()
                .filter(|(id, _)| *id == tx.sender)
                .map(|(_, amt)| *amt)
                .sum();
            let escrow_base = sender_account.compute_escrow_tlkd;
            let escrow_after = escrow_base
                .checked_add(escrow_credits)
                .ok_or("Escrow overflow")?
                .checked_sub(escrow_debits)
                .ok_or("Escrow underflow")?;

            let trth_fee = Self::cu_fee_to_tlkd(diff.cu_fee)?;
            if escrow_after < trth_fee {
                return Err("Insufficient compute escrow".to_string());
            }
            diff.compute_escrow_debits.push((tx.sender, trth_fee));
            diff.compute_fee_tlkd = trth_fee;
        }

        // Always store sender pubkey in diff (airdrop accounts start with empty pubkey_bytes)
        {
            let entry = diff
                .account_updates
                .entry(tx.sender)
                .or_insert_with(|| sender_account.clone());
            if entry.pubkey_bytes.is_empty() && !sender_account.pubkey_bytes.is_empty() {
                entry.pubkey_bytes = sender_account.pubkey_bytes.clone();
            }
        }

        Ok(diff)
    }

    fn compute_transfer_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        recipient: AccountId,
        recipient_pubkey: &[u8],
        amount: u128,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("Transfer amount must be > 0".to_string());
        }

        let total_cost = amount
            .checked_add(gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
            .ok_or("Amount overflow")?;

        if sender_account.balance < total_cost {
            return Err("Insufficient balance for transfer + gas".to_string());
        }

        if recipient_pubkey.is_empty() {
            let existing = self
                .accounts
                .get(&recipient)
                .ok_or("Recipient account not found; pubkey required")?;
            if existing.pubkey_bytes.is_empty() {
                return Err("Recipient account missing pubkey; pubkey required".to_string());
            }
        } else {
            let derived_id = account_id_from_pubkey(recipient_pubkey);
            if derived_id != recipient {
                return Err("Recipient pubkey does not match recipient AccountId".to_string());
            }
        }

        // COMMUTATIVE: Use native_debits for sender (allows parallel execution)
        diff.native_debits.push((sender, total_cost));

        if !self.accounts.contains_key(&recipient) {
            let new_account = AccountRecord {
                pubkey_bytes: recipient_pubkey.to_vec(),
                balance: 0,
                compute_escrow_tlkd: 0,
                nonce: 0,
                nfts: vec![],
            };
            diff.account_updates.insert(recipient, new_account);
        }

        // Add to native_transfers for commutative accumulation
        diff.native_transfers.push((recipient, amount));

        let gas = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        diff.gas_breakdown
            .push(("Balance debit".to_string(), gas / 2));
        diff.gas_breakdown
            .push(("Balance credit".to_string(), gas - gas / 2));
        diff.gas_fee = gas;
        Ok(())
    }

    fn compute_batch_transfer_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        transfers: &[BatchTransferEntry],
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if transfers.is_empty() {
            return Err("BatchTransfer must include at least one recipient".to_string());
        }
        if transfers.len() > gp::get_usize(gp::PARAM_MAX_BATCH_TRANSFER_RECIPIENTS) {
            return Err(format!(
                "BatchTransfer too large: {} recipients (max: {})",
                transfers.len(),
                gp::get_usize(gp::PARAM_MAX_BATCH_TRANSFER_RECIPIENTS)
            ));
        }

        let mut total_amount: u128 = 0;
        for (idx, transfer) in transfers.iter().enumerate() {
            if transfer.amount == 0 {
                return Err(format!("BatchTransfer amount at index {} must be > 0", idx));
            }
            match transfer.recipient_pubkey.as_deref() {
                None | Some(&[]) => {
                    let existing = self.accounts.get(&transfer.recipient).ok_or_else(|| {
                        format!(
                            "Recipient account not found at index {}; pubkey required",
                            idx
                        )
                    })?;
                    if existing.pubkey_bytes.is_empty() {
                        return Err(format!(
                            "Recipient account missing pubkey at index {}; pubkey required",
                            idx
                        ));
                    }
                }
                Some(pk) => {
                    let derived_id = account_id_from_pubkey(pk);
                    if derived_id != transfer.recipient {
                        return Err(format!(
                            "Recipient pubkey does not match recipient AccountId at index {}",
                            idx
                        ));
                    }
                }
            }
            total_amount = total_amount
                .checked_add(transfer.amount)
                .ok_or("BatchTransfer amount overflow")?;
        }

        let gas_fee = (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
            .checked_mul(transfers.len() as u128)
            .ok_or("BatchTransfer gas overflow")?;
        let total_cost = total_amount
            .checked_add(gas_fee)
            .ok_or("BatchTransfer total overflow")?;
        if sender_account.balance < total_cost {
            return Err("Insufficient balance for batch transfer + gas".to_string());
        }

        // COMMUTATIVE: single debit from sender for total amount + gas.
        diff.native_debits.push((sender, total_cost));

        for transfer in transfers {
            if !self.accounts.contains_key(&transfer.recipient) {
                let new_account = AccountRecord {
                    pubkey_bytes: transfer.recipient_pubkey.clone().unwrap_or_default(),
                    balance: 0,
                    compute_escrow_tlkd: 0,
                    nonce: 0,
                    nfts: vec![],
                };
                diff.account_updates.insert(transfer.recipient, new_account);
            }
            diff.native_transfers
                .push((transfer.recipient, transfer.amount));
        }

        diff.gas_fee = gas_fee;
        Ok(())
    }

    fn resolve_name_to_account(
        &self,
        name: &str,
        current_height: u64,
    ) -> Result<AccountId, String> {
        let reg = self
            .name_registry
            .get(name)
            .ok_or("Name not found".to_string())?;
        if current_height >= reg.expires_at {
            return Err("Name expired".to_string());
        }
        Ok(reg.target)
    }

    fn compute_claim_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        recipient: AccountId,
        recipient_pubkey: &[u8],
        amount: u128,
        timestamp: u64,
    ) -> Result<(), String> {
        // TESTNET ONLY: Airdrop/faucet functionality
        if !crate::is_testnet() {
            return Err("Airdrop is only available on testnet".to_string());
        }

        // Only foundation authority can mint devnet faucet claims.
        match self.foundation_mint_authority {
            Some(authority) if authority == sender => {}
            _ => return Err("Airdrop requires foundation mint authority".to_string()),
        }

        if recipient_pubkey.is_empty() {
            let existing = self
                .accounts
                .get(&recipient)
                .ok_or("Recipient account not found; pubkey required")?;
            if existing.pubkey_bytes.is_empty() {
                return Err("Recipient account missing pubkey; pubkey required".to_string());
            }
        } else {
            let derived_id = account_id_from_pubkey(recipient_pubkey);
            if derived_id != recipient {
                return Err("Recipient pubkey does not match recipient AccountId".to_string());
            }
        }

        // Check aggregate mint cap
        if self
            .total_minted
            .checked_add(amount)
            .ok_or("Mint overflow")?
            > crate::constants::MAX_TESTNET_MINT
        {
            return Err("Airdrop would exceed testnet mint cap of 100M TLKD".to_string());
        }

        // Enforce the active devnet faucet policy. Existing devnet state can
        // carry an older governance value, so the compiled devnet ceiling is a
        // floor for this faucet path until the chain parameter is migrated.
        let max_airdrop_amount = gp::get_u128(gp::PARAM_MAX_AIRDROP_AMOUNT)
            .max(truthlinked_core::constants::MAX_AIRDROP_AMOUNT);
        if amount > max_airdrop_amount {
            return Err(format!(
                "Airdrop amount exceeds maximum of {} TLKD (requested: {} TLKD)",
                max_airdrop_amount / ONE_TLKD,
                amount / ONE_TLKD
            ));
        }

        // Check if recipient has claimed recently
        if let Some(last_claim) = self.airdrop_claims.get(&recipient) {
            let time_since_claim = timestamp.saturating_sub(*last_claim);
            if time_since_claim < gp::get_u64(gp::PARAM_AIRDROP_COOLDOWN_SECS) {
                let remaining = gp::get_u64(gp::PARAM_AIRDROP_COOLDOWN_SECS) - time_since_claim;
                let hours = remaining / 3600;
                let minutes = (remaining % 3600) / 60;
                return Err(format!(
                    "Airdrop cooldown active. Try again in {}h {}m",
                    hours, minutes
                ));
            }
        }

        if let Some(account) = self.accounts.get(&recipient) {
            let mut updated_account = account.clone();
            updated_account.balance = updated_account
                .balance
                .checked_add(amount)
                .ok_or("Balance overflow")?;
            // Always store pubkey if missing
            if updated_account.pubkey_bytes.is_empty() {
                if recipient_pubkey.is_empty() {
                    return Err("Recipient account missing pubkey; pubkey required".to_string());
                }
                updated_account.pubkey_bytes = recipient_pubkey.to_vec();
            }
            tracing::info!(
                "💰 Updating existing account: old_balance={}, new_balance={}",
                account.balance,
                updated_account.balance
            );
            diff.account_updates.insert(recipient, updated_account);
        } else {
            if recipient_pubkey.is_empty() {
                return Err("Recipient account not found; pubkey required".to_string());
            }
            let new_account = AccountRecord {
                pubkey_bytes: recipient_pubkey.to_vec(),
                balance: amount,
                compute_escrow_tlkd: 0,
                nonce: 0,
                nfts: vec![],
            };
            tracing::info!("💰 Creating new account with balance={}", amount);
            diff.account_updates.insert(recipient, new_account);
        }

        diff.airdrop_claims.push((recipient, timestamp));
        diff.minted_amount = amount;
        diff.gas_fee = 0;

        Ok(())
    }

    fn compute_rotate_key_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        new_pubkey: &[u8],
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if new_pubkey.len() != 1952 {
            return Err("Invalid new public key length".to_string());
        }

        let pk_bytes: [u8; 1952] = new_pubkey
            .try_into()
            .map_err(|_| "Invalid public key format")?;
        ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
            .map_err(|_| "Invalid ML-DSA-65 public key")?;

        let mut updated_account = sender_account.clone();
        updated_account.pubkey_bytes = new_pubkey.to_vec();
        if let Some(prev) = diff.account_updates.get(&sender) {
            updated_account.nonce = prev.nonce;
        }

        diff.account_updates.insert(sender, updated_account);

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_ROTATE_KEY) as u128;
        Ok(())
    }

    fn compute_deposit_compute_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        amount: u128,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("Deposit amount must be > 0".to_string());
        }
        if sender_account.balance < amount {
            return Err("Insufficient balance for compute escrow deposit".to_string());
        }
        diff.native_debits.push((sender, amount));
        diff.compute_escrow_credits.push((sender, amount));
        Ok(())
    }

    fn compute_withdraw_compute_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        amount: u128,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("Withdraw amount must be > 0".to_string());
        }
        let escrow = sender_account.compute_escrow_tlkd;
        if escrow < amount {
            return Err("Insufficient compute escrow balance".to_string());
        }
        diff.compute_escrow_debits.push((sender, amount));
        diff.native_transfers.push((sender, amount));
        Ok(())
    }
    fn compute_wrap_trth_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        amount: u128,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("Wrap amount must be > 0".into());
        }
        if sender_account.balance < amount {
            return Err("Insufficient TLKD balance to wrap".into());
        }
        // Debit TLKD, credit wTLKD token balance
        diff.native_debits.push((sender, amount));
        diff.token_credits
            .push((wtrth_system_cell_id(), sender, amount));
        Ok(())
    }

    fn compute_unwrap_trth_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        amount: u128,
        _sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("Unwrap amount must be > 0".into());
        }
        // Burn wTLKD, credit TLKD
        let wtrth_bal = self
            .cells
            .token_balances
            .get(&(wtrth_system_cell_id(), sender))
            .copied()
            .unwrap_or(0);
        if wtrth_bal < amount {
            return Err("Insufficient wTLKD balance".into());
        }
        diff.token_balance_updates
            .push(((wtrth_system_cell_id(), sender), wtrth_bal - amount));
        diff.native_transfers.push((sender, amount));
        Ok(())
    }

    pub fn apply_diff(&mut self, diff: StateDiff) -> Result<(), String> {
        // Record transaction hash for replay protection
        if !diff.is_system {
            self.executed_tx_hashes.insert(diff.tx_hash);

            // Prune deterministically when over cap. We sort and drop the oldest
            // (lexicographically smallest) hashes so every node prunes identically.
            if self.executed_tx_hashes.len() > crate::constants::MAX_EXECUTED_TX_HASHES {
                let mut hashes: Vec<[u8; 32]> = self.executed_tx_hashes.iter().copied().collect();
                hashes.sort_unstable();
                self.executed_tx_hashes = hashes
                    .into_iter()
                    .rev()
                    .take(crate::constants::KEEP_EXECUTED_TX_HASHES)
                    .collect();
            }

            // Accumulate gas fees (native TLKD)
            self.accumulated_gas_fees += diff.gas_fee;
            // Accumulate compute fees (TLKD collected from escrow)
            self.accumulated_compute_fees_tlkd += diff.compute_fee_tlkd;
            // Accumulate treasury fees (direct protocol receipts)
            self.accumulated_treasury_fees += diff.treasury_fee;
            // Track fees for emission subsidy calculation
            self.accumulated_epoch_fees = self
                .accumulated_epoch_fees
                .saturating_add(diff.gas_fee)
                .saturating_add(diff.compute_fee_tlkd)
                .saturating_add(diff.treasury_fee);
        }

        // Apply native transfers FIRST (before account_updates)
        for (recipient, amount) in diff.native_transfers {
            let recipient_account =
                self.accounts
                    .entry(recipient)
                    .or_insert_with(|| AccountRecord {
                        pubkey_bytes: vec![], // Will be set by account_updates
                        balance: 0,
                        compute_escrow_tlkd: 0,
                        nonce: 0,
                        nfts: vec![],
                    });
            recipient_account.balance = recipient_account
                .balance
                .checked_add(amount)
                .ok_or("Recipient balance overflow")?;
        }

        for (sender, amount) in diff.native_debits {
            let sender_account = self
                .accounts
                .get_mut(&sender)
                .ok_or("Sender account not found")?;
            sender_account.balance = sender_account
                .balance
                .checked_sub(amount)
                .ok_or("Sender balance underflow")?;
        }

        for (recipient, amount) in diff.compute_escrow_credits {
            let recipient_account =
                self.accounts
                    .entry(recipient)
                    .or_insert_with(|| AccountRecord {
                        pubkey_bytes: vec![],
                        balance: 0,
                        compute_escrow_tlkd: 0,
                        nonce: 0,
                        nfts: vec![],
                    });
            recipient_account.compute_escrow_tlkd = recipient_account
                .compute_escrow_tlkd
                .checked_add(amount)
                .ok_or("Recipient escrow overflow")?;
        }

        for (sender, amount) in diff.compute_escrow_debits {
            let sender_account = self
                .accounts
                .get_mut(&sender)
                .ok_or("Sender account not found")?;
            sender_account.compute_escrow_tlkd = sender_account
                .compute_escrow_tlkd
                .checked_sub(amount)
                .ok_or("Sender escrow underflow")?;
        }

        // Then apply account updates (sets pubkey_bytes for new accounts)
        for (id, record) in diff.account_updates {
            if let Some(existing) = self.accounts.get_mut(&id) {
                // Account exists - update pubkey if it's empty (was created by native_transfers)
                if existing.pubkey_bytes.is_empty() {
                    existing.pubkey_bytes = record.pubkey_bytes;
                }
                // Always update nfts
                existing.nfts = record.nfts;
                // Do not touch balance or compute_escrow_tlkd - they were already set by transfers
            } else {
                // New account - insert it (shouldn't happen if native_transfers ran first)
                self.accounts.insert(id, record);
            }
        }

        for (id, nonce) in diff.nonce_updates {
            if let Some(existing) = self.accounts.get_mut(&id) {
                if nonce > existing.nonce {
                    existing.nonce = nonce;
                }
            }
        }

        for update in diff.staking_updates {
            match update {
                StakingUpdate::Stake { validator, amount } => {
                    self.staking.stake(validator, amount)?;
                }
                StakingUpdate::Unstake { validator, amount } => {
                    self.staking.unstake(&validator, amount)?;
                }
                StakingUpdate::Withdraw { validator } => {
                    let withdrawn = self.staking.withdraw(&validator)?;
                    let account_id = account_id_from_pubkey(&validator);
                    let account = self
                        .accounts
                        .get_mut(&account_id)
                        .ok_or("Account not found for withdrawal")?;
                    account.balance = account
                        .balance
                        .checked_add(withdrawn as u128)
                        .ok_or("Balance overflow")?;
                }
                StakingUpdate::Slash {
                    validator,
                    reason,
                    amount,
                    redistribution,
                } => {
                    let outcome = truthlinked_staking::SlashOutcome {
                        amount,
                        redistribution,
                    };
                    self.staking
                        .apply_slash_outcome(&validator, reason, &outcome, None)?;
                }
                StakingUpdate::Unjail { validator } => {
                    self.staking.unjail(&validator)?;
                }
            }
        }

        for (key, value) in diff.param_updates {
            self.params.insert(key, value);
            truthlinked_governance::params::update_param(key, value);
        }

        for (nft_id, nft_opt) in diff.nft_updates {
            match nft_opt {
                Some(nft) => self.nfts.insert(nft_id, nft),
                None => self.nfts.remove(&nft_id),
            };
        }

        // Apply cell updates (strict: missing cell is an error).
        for update in diff.cell_updates {
            match update {
                CellUpdate::Deploy { cell_id, cell } => {
                    self.cells.cells.insert(cell_id, cell);
                }
                CellUpdate::StorageChange {
                    cell_id,
                    storage_diff,
                } => {
                    let cell = self
                        .cells
                        .cells
                        .get_mut(&cell_id)
                        .ok_or("Cell not found for storage update")?;
                    for (key, value_opt) in storage_diff {
                        match value_opt {
                            Some(value) => cell.storage.insert(key, value),
                            None => cell.storage.remove(&key),
                        };
                    }
                }
                CellUpdate::BalanceChange {
                    cell_id,
                    new_balance,
                } => {
                    let cell = self
                        .cells
                        .cells
                        .get_mut(&cell_id)
                        .ok_or("Cell not found for balance update")?;
                    cell.balance = new_balance;
                }
                CellUpdate::Remove { cell_id } => {
                    if self.cells.cells.remove(&cell_id).is_some() {
                        self.cells
                            .token_balances
                            .retain(|(token_id, _), _| token_id != &cell_id);
                        self.cells
                            .frozen_accounts
                            .retain(|(token_id, _), _| token_id != &cell_id);
                    }
                }
                CellUpdate::Upgrade {
                    cell_id,
                    new_bytecode,
                    new_declared_reads,
                    new_declared_writes,
                    new_commutative_keys,
                    new_storage_key_specs,
                    new_oracle_schema_ids,
                    timestamp,
                } => {
                    let cell = self
                        .cells
                        .cells
                        .get_mut(&cell_id)
                        .ok_or("Cell not found for upgrade")?;
                    // Update manifest fields
                    cell.bytecode = new_bytecode;
                    cell.declared_reads = new_declared_reads;
                    cell.declared_writes = new_declared_writes;
                    cell.commutative_keys = new_commutative_keys;
                    cell.storage_key_specs = new_storage_key_specs;
                    cell.oracle_schema_ids = new_oracle_schema_ids;

                    // Recompute manifest hash
                    cell.manifest_hash =
                        truthlinked_runtime::cells::CellAccount::compute_manifest_hash(
                            &cell.bytecode,
                            &cell.declared_reads,
                            &cell.declared_writes,
                            &cell.commutative_keys,
                            &cell.oracle_schema_ids,
                        );

                    // Increment manifest version (invalidates cached conflict profiles)
                    cell.manifest_version = cell.manifest_version.saturating_add(1);
                    cell.upgraded_at = Some(timestamp);
                }
                CellUpdate::TransferOwnership { cell_id, new_owner } => {
                    let cell = self
                        .cells
                        .cells
                        .get_mut(&cell_id)
                        .ok_or("Cell not found for ownership transfer")?;
                    cell.pending_owner = Some(new_owner);
                }
                CellUpdate::AcceptOwnership { cell_id, caller } => {
                    self.cells.accept_ownership(cell_id, caller)?;
                }
                CellUpdate::MakeImmutable { cell_id, caller } => {
                    self.cells.make_immutable(cell_id, caller)?;
                }
            }
        }

        // native_transfers and native_debits already applied above (before account_updates)

        // Token credits are commutative increments (e.g., rewards).
        for (token_cell, recipient, amount) in diff.token_credits {
            if self.cells.cells.contains_key(&token_cell) {
                let current = self
                    .cells
                    .token_balances
                    .get(&(token_cell, recipient))
                    .copied()
                    .unwrap_or(0);
                let new_balance = current
                    .checked_add(amount)
                    .ok_or("Token balance overflow")?;
                self.cells
                    .token_balances
                    .insert((token_cell, recipient), new_balance);
            }
        }

        // Token balance updates are authoritative sets (used for transfers/mint/burn).
        for ((token_cell, account), balance) in diff.token_balance_updates {
            if self.cells.cells.contains_key(&token_cell) {
                self.cells
                    .token_balances
                    .insert((token_cell, account), balance);
            }
        }

        for (validator_account, reward) in diff.staking_rewards {
            let validator_key = self
                .staking
                .validators
                .keys()
                .find(|pk| account_id_from_pubkey(pk) == validator_account)
                .cloned();
            if let Some(validator_key) = validator_key {
                if let Some(stake_info) = self.staking.validators.get_mut(&validator_key) {
                    stake_info.active_stake = stake_info
                        .active_stake
                        .checked_add(reward as u64)
                        .ok_or("Staking reward overflow")?;
                }
            }
        }

        for (cell_id, payment) in diff.cell_credits {
            if let Some(cell) = self.cells.cells.get_mut(&cell_id) {
                cell.balance = cell
                    .balance
                    .checked_add(payment)
                    .ok_or("Cell balance overflow")?;
            }
        }

        for (cell_id, debit) in diff.cell_debits {
            let cell = self
                .cells
                .cells
                .get_mut(&cell_id)
                .ok_or("Cell not found for debit")?;
            cell.balance = cell
                .balance
                .checked_sub(debit)
                .ok_or("Cell balance underflow")?;
        }

        for (cell_id, delta) in diff.storage_deltas {
            if let Some(cell) = self.cells.cells.get_mut(&cell_id) {
                for (storage_key, delta_op) in delta.deltas {
                    let current_bytes =
                        cell.storage.get(&storage_key).cloned().unwrap_or([0u8; 32]);
                    let new_bytes_vec = delta_op.apply(&current_bytes);
                    let mut new_bytes = [0u8; 32];
                    let copy_len = new_bytes_vec.len().min(32);
                    new_bytes[..copy_len].copy_from_slice(&new_bytes_vec[..copy_len]);
                    cell.storage.insert(storage_key, new_bytes);
                }
            }
        }

        // Name fees go directly to the treasury cell balance.
        if diff.name_fee > 0 {
            let treasury_id = treasury_system_cell_id();
            if let Some(cell) = self.cells.cells.get_mut(&treasury_id) {
                cell.balance = cell.balance.saturating_add(diff.name_fee);
            } else {
                // Treasury cell not yet deployed (e.g., early genesis); fall back to accumulator.
                self.accumulated_name_fees =
                    self.accumulated_name_fees.saturating_add(diff.name_fee);
            }
        }

        if diff.gas_fee_spent > 0 {
            if diff.gas_fee_spent > self.accumulated_gas_fees {
                return Err("Gas fee distribution exceeds accumulated fees".to_string());
            }
            self.accumulated_gas_fees =
                self.accumulated_gas_fees.saturating_sub(diff.gas_fee_spent);
        }
        if diff.name_fee_spent > 0 {
            if diff.name_fee_spent > self.accumulated_name_fees {
                return Err("Name fee distribution exceeds accumulated fees".to_string());
            }
            self.accumulated_name_fees = self
                .accumulated_name_fees
                .saturating_sub(diff.name_fee_spent);
        }
        if diff.compute_fee_spent > 0 {
            if diff.compute_fee_spent > self.accumulated_compute_fees_tlkd {
                return Err("Compute fee distribution exceeds accumulated fees".to_string());
            }
            self.accumulated_compute_fees_tlkd = self
                .accumulated_compute_fees_tlkd
                .saturating_sub(diff.compute_fee_spent);
        }
        if diff.treasury_fee_spent > 0 {
            if diff.treasury_fee_spent > self.accumulated_treasury_fees {
                return Err("Treasury fee distribution exceeds accumulated fees".to_string());
            }
            self.accumulated_treasury_fees = self
                .accumulated_treasury_fees
                .saturating_sub(diff.treasury_fee_spent);
        }

        // Apply name registrations immediately (no separate validator vote).
        for (name, pending, _owner, _is_cell) in diff.pending_name_proposals {
            let registration = NameRegistration {
                name: pending.name.clone(),
                owner: pending.owner,
                target: pending.cell_id,
                registered_at: pending.proposed_at,
                expires_at: pending.proposed_at + gp::get_u64(gp::PARAM_NAME_EXPIRATION_BLOCKS),
                is_cell: pending.is_cell,
            };
            if !self.name_registry.contains_key(&name) {
                self.name_registry.insert(name, registration);
            }
        }

        // Add pending token authority proposals
        for (token_cell, proposal) in diff.pending_token_authority_proposals {
            self.token_authority_proposals.insert(token_cell, proposal);
        }

        // Name votes are unused (registrations are finalized at propose time).

        // Process token authority votes
        let current_height = self.staking.current_height;
        let total_stake: u64 = self
            .staking
            .validators
            .values()
            .filter(|v| v.is_active(current_height))
            .map(|v| v.active_stake)
            .sum();
        let mut approved_tokens: Vec<AccountId> = Vec::new();
        for (token_cell, validator_pk, stake) in diff.token_authority_votes {
            let proposal = match self.token_authority_proposals.get_mut(&token_cell) {
                Some(p) => p,
                None => continue,
            };
            if approved_tokens.contains(&token_cell) {
                continue;
            }
            if !proposal.voters.insert(validator_pk) {
                continue;
            }
            proposal.votes_for_stake = proposal.votes_for_stake.saturating_add(stake);
            if total_stake == 0 {
                continue;
            }
            let approval_percentage = (proposal.votes_for_stake * 100) / total_stake;
            if approval_percentage >= gp::get_u64(gp::PARAM_TOKEN_AUTHORITY_APPROVAL_THRESHOLD) {
                if let Some(cell) = self.cells.cells.get_mut(&token_cell) {
                    if cell.is_token {
                        if let Some(cfg) = cell.token_config.as_mut() {
                            if proposal.set_mint_authority {
                                cfg.mint_authority = proposal.new_mint_authority;
                            }
                            if proposal.set_freeze_authority {
                                cfg.freeze_authority = proposal.new_freeze_authority;
                            }
                        }
                    }
                }
                approved_tokens.push(token_cell);
                tracing::info!(
                    " Token authority for {} approved by validators ({}% stake)",
                    hex::encode(&token_cell[..8.min(token_cell.len())]),
                    approval_percentage
                );
            }
        }
        for token_cell in approved_tokens {
            self.token_authority_proposals.remove(&token_cell);
        }

        // Process name renewals
        for (name, timestamp) in diff.name_renewals {
            if let Some(registration) = self.name_registry.get_mut(&name) {
                registration.expires_at = timestamp + gp::get_u64(gp::PARAM_NAME_EXPIRATION_BLOCKS);
            }
        }

        // Process name transfers
        for (name, new_owner) in diff.name_transfers {
            if let Some(registration) = self.name_registry.get_mut(&name) {
                registration.owner = new_owner;
                registration.is_cell = self.cells.cells.contains_key(&new_owner);
            }
        }

        // Process airdrop claims (testnet only)
        for (account_id, timestamp) in diff.airdrop_claims {
            self.airdrop_claims.insert(account_id, timestamp);
        }
        if diff.minted_amount > 0 {
            self.total_minted = self.total_minted.saturating_add(diff.minted_amount);
        }

        // Freeze/thaw changes are part of the canonical token state.
        for ((token_cell, account), frozen) in diff.frozen_account_updates {
            if frozen {
                self.cells
                    .frozen_accounts
                    .insert((token_cell, account), true);
            } else {
                self.cells.frozen_accounts.remove(&(token_cell, account));
            }
        }

        self.apply_oracle_updates(diff.oracle_updates)?;

        Ok(())
    }

    /// Apply multiple diffs in batch (faster than applying one by one)
    pub fn apply_diffs_batch(&mut self, diffs: Vec<StateDiff>) -> Result<(), String> {
        for diff in diffs {
            self.apply_diff(diff)?;
        }
        Ok(())
    }

    fn distribute_url_slash_equally(&mut self, total_slashed: u128, excluded_account: AccountId) {
        if total_slashed == 0 {
            return;
        }

        let current_height = self.staking.current_height;
        let mut recipients: Vec<Vec<u8>> = self
            .staking
            .validators
            .iter()
            .filter(|(pk, vs)| {
                let account_id = account_id_from_pubkey(pk);
                account_id != excluded_account && vs.is_active(current_height)
            })
            .map(|(pk, _)| pk.clone())
            .collect();

        if recipients.is_empty() {
            tracing::warn!(
                "  No active validators to receive URL slash redistribution - tokens burned"
            );
            return;
        }

        recipients.sort();

        let n = recipients.len() as u128;
        let share_each = total_slashed / n;
        let mut dust = total_slashed % n;

        for pk in recipients {
            let mut payout = share_each;
            if dust > 0 {
                payout = payout.saturating_add(1);
                dust -= 1;
            }
            if payout == 0 {
                continue;
            }

            let account_id = account_id_from_pubkey(&pk);
            let entry = self
                .accounts
                .entry(account_id)
                .or_insert_with(|| AccountRecord {
                    pubkey_bytes: pk.clone(),
                    balance: 0,
                    compute_escrow_tlkd: 0,
                    nonce: 0,
                    nfts: vec![],
                });
            entry.balance = entry.balance.saturating_add(payout);
        }
    }

    fn slash_url_proposer_bond(&mut self, url_pattern: &str) -> Result<(), String> {
        let (proposer, original_bond) = {
            let proposal = self
                .url_proposals
                .get_mut(url_pattern)
                .ok_or_else(|| format!("No proposal for URL pattern '{}'", url_pattern))?;

            if proposal.slashed {
                return Ok(());
            }

            proposal.slashed = true;
            proposal.approved = false;
            proposal.rejected = true;

            let proposer = proposal.proposer;
            let bond = proposal.bond_amount;
            proposal.bond_amount = 0;
            (proposer, bond)
        };

        let slash_amount =
            (original_bond * gp::get_u64(gp::PARAM_MALICIOUS_SLASH_BPS) as u128) / 10_000;
        let returned = original_bond.saturating_sub(slash_amount);

        if let Some(owner_account) = self.accounts.get_mut(&proposer) {
            owner_account.balance = owner_account.balance.saturating_add(returned);
        }

        self.distribute_url_slash_equally(slash_amount, proposer);

        if let Some(proposal) = self.url_proposals.get(url_pattern) {
            crate::pq_execution::register_url_proposal(proposal.clone());
        }

        Ok(())
    }

    fn finalize_oracle_request_if_ready(&mut self, request_id: [u8; 32]) -> bool {
        let req = match self.pending_oracle_requests.get(&request_id).cloned() {
            Some(req) => req,
            None => return false,
        };

        let (body, status, agreeing_stake, total_stake) =
            match self.oracle_pending.get(&request_id).and_then(|tally| {
                tally.try_finalize_with_format(&self.staking, req.response_format)
            }) {
                Some(finalized) => finalized,
                None => return false,
            };

        self.pending_oracle_requests.remove(&request_id);

        self.oracle_pending.remove(&request_id);

        let current_height = self.staking.current_height;
        let body_hash: [u8; 32] = (*blake3::hash(&body).as_bytes()).into();
        let result = OracleResult {
            request_id,
            url: req.url,
            method: req.method,
            response_body: body,
            response_status: status,
            body_hash,
            finalized_at: current_height,
            expires_at: current_height + gp::get_u64(gp::PARAM_ORACLE_CACHE_EXPIRY_BLOCKS),
            quorum_stake_num: agreeing_stake,
            quorum_stake_den: total_stake,
            requesting_cell: req.requesting_cell,
        };

        crate::pq_execution::register_oracle_result(result.clone());
        self.oracle_results.insert(request_id, result);
        true
    }

    pub(crate) fn apply_oracle_updates(
        &mut self,
        oracle_updates: Vec<OracleUpdate>,
    ) -> Result<(), String> {
        for oracle_update in oracle_updates {
            self.apply_oracle_update(oracle_update)?;
        }
        Ok(())
    }

    pub(crate) fn apply_oracle_update(
        &mut self,
        oracle_update: OracleUpdate,
    ) -> Result<(), String> {
        match oracle_update {
            OracleUpdate::QueueRequest(req) => {
                self.pending_oracle_requests.insert(req.request_id, req);
            }
            OracleUpdate::AddCommit { request_id, commit } => {
                let tally = self.oracle_pending.entry(request_id).or_insert_with(|| {
                    let total_stake = self
                        .staking
                        .validators
                        .values()
                        .map(|v| v.active_stake)
                        .sum();
                    truthlinked_oracle::http_oracle::OracleTally {
                        request_id,
                        total_stake,
                        ..Default::default()
                    }
                });

                // Duplicate commits in the same block can appear under parallel execution.
                // Count stake exactly once per validator pubkey.
                let was_new = tally
                    .commits
                    .insert(commit.validator_pk.clone(), commit.commit_hash)
                    .is_none();
                if was_new {
                    let val_stake = self
                        .staking
                        .validators
                        .get(&commit.validator_pk)
                        .map(|v| v.active_stake)
                        .unwrap_or(0);
                    tally.committed_stake = tally.committed_stake.saturating_add(val_stake);
                }

                if tally.commit_quorum_reached() {
                    tally.commit_phase_closed = true;
                }
            }
            OracleUpdate::AddReveal { request_id, reveal } => {
                if let Some(tally) = self.oracle_pending.get_mut(&request_id) {
                    tally
                        .reveals
                        .entry(reveal.validator_pk.clone())
                        .or_insert((reveal.response_body, reveal.response_status));
                }
                self.finalize_oracle_request_if_ready(request_id);
            }
            OracleUpdate::FinalizeResult(result) => {
                self.pending_oracle_requests.remove(&result.request_id);
                self.oracle_pending.remove(&result.request_id);
                crate::pq_execution::register_oracle_result(result.clone());
                self.oracle_results.insert(result.request_id, result);
            }
            OracleUpdate::AddUrlProposal(proposal) => {
                if !self.url_proposals.contains_key(&proposal.url_pattern) {
                    self.url_proposals
                        .insert(proposal.url_pattern.clone(), proposal);
                }
            }
            OracleUpdate::VoteUrlProposal {
                url_pattern,
                voter_pk,
                stake_for_delta,
                stake_against_delta,
            } => {
                let mut trigger_slash = false;
                if let Some(proposal) = self.url_proposals.get_mut(&url_pattern) {
                    if proposal.approved || proposal.rejected || proposal.slashed {
                        return Ok(());
                    }

                    // Duplicate votes (same validator) can coexist in a composed block.
                    // Apply at-most-once per validator to keep state deterministic.
                    if !proposal.voters.insert(voter_pk) {
                        return Ok(());
                    }

                    proposal.votes_for_stake =
                        proposal.votes_for_stake.saturating_add(stake_for_delta);
                    proposal.votes_against_stake = proposal
                        .votes_against_stake
                        .saturating_add(stake_against_delta);

                    let total_stake: u64 = self
                        .staking
                        .validators
                        .values()
                        .map(|v| v.active_stake)
                        .sum();
                    if total_stake > 0 {
                        let threshold = total_stake.saturating_mul(2);
                        if proposal.votes_for_stake.saturating_mul(3) >= threshold {
                            proposal.approved = true;
                            proposal.rejected = false;
                            crate::pq_execution::register_url_proposal(proposal.clone());
                        } else if proposal.votes_against_stake.saturating_mul(3) >= threshold {
                            proposal.rejected = true;
                            proposal.approved = false;
                            trigger_slash = true;
                        }
                    }
                }
                if trigger_slash {
                    self.slash_url_proposer_bond(&url_pattern)?;
                }
            }
            OracleUpdate::SlashUrlProposer { url_pattern } => {
                self.slash_url_proposer_bond(&url_pattern)?;
            }
            OracleUpdate::AddSchemaProposal(proposal) => {
                if !self.schema_proposals.contains_key(&proposal.schema_id) {
                    self.schema_proposals.insert(proposal.schema_id, proposal);
                }
            }
            OracleUpdate::VoteSchemaProposal {
                schema_id,
                voter_pk,
                stake_for_delta,
                stake_against_delta,
            } => {
                if let Some(proposal) = self.schema_proposals.get_mut(&schema_id) {
                    if proposal.approved || proposal.rejected {
                        return Ok(());
                    }
                    if !proposal.voters.insert(voter_pk) {
                        return Ok(());
                    }
                    proposal.votes_for_stake =
                        proposal.votes_for_stake.saturating_add(stake_for_delta);
                    proposal.votes_against_stake = proposal
                        .votes_against_stake
                        .saturating_add(stake_against_delta);

                    let total_stake: u64 = self
                        .staking
                        .validators
                        .values()
                        .map(|v| v.active_stake)
                        .sum();
                    if total_stake > 0 {
                        let threshold = total_stake.saturating_mul(2);
                        if proposal.votes_for_stake.saturating_mul(3) >= threshold {
                            proposal.approved = true;
                            proposal.rejected = false;
                            self.schema_registry.insert(
                                proposal.schema_id,
                                SchemaEntry {
                                    schema_id: proposal.schema_id,
                                    keys: proposal.keys.clone(),
                                    created_at: proposal.created_at,
                                    approved: true,
                                },
                            );
                        } else if proposal.votes_against_stake.saturating_mul(3) >= threshold {
                            proposal.rejected = true;
                            proposal.approved = false;
                        }
                    }
                }
            }
            OracleUpdate::SetVisibility {
                cell_id,
                visibility,
            } => {
                crate::pq_execution::register_cell_visibility(cell_id, visibility);
                self.cell_visibility.insert(cell_id, visibility);
            }
        }

        Ok(())
    }

    /// Advance staking time counters once per finalized block.
    pub fn advance_block_counters(&mut self) {
        self.staking.current_height = self.staking.current_height.saturating_add(1);
    }

    /// Expire stale oracle requests and slash validators that committed but never revealed.
    pub fn process_oracle_timeouts(&mut self, current_height: u64) {
        let mut expired_request_ids: Vec<[u8; 32]> = self
            .pending_oracle_requests
            .iter()
            .filter_map(|(request_id, req)| {
                if current_height >= req.expires_at {
                    Some(*request_id)
                } else {
                    None
                }
            })
            .collect();
        expired_request_ids.sort_unstable();

        for request_id in expired_request_ids {
            if self.finalize_oracle_request_if_ready(request_id) {
                continue;
            }

            self.pending_oracle_requests.remove(&request_id);

            if let Some(tally) = self.oracle_pending.remove(&request_id) {
                let mut committed_validators: Vec<Vec<u8>> =
                    tally.commits.keys().cloned().collect();
                committed_validators.sort();
                let mut revealed_validators: Vec<Vec<u8>> = tally.reveals.keys().cloned().collect();
                revealed_validators.sort();

                let slashed = self.staking.slash_silent_oracle_validators(
                    request_id,
                    &committed_validators,
                    &revealed_validators,
                );

                if !slashed.is_empty() {
                    tracing::warn!(
                        "  Oracle timeout {} slashed {} silent validators",
                        hex::encode(request_id),
                        slashed.len()
                    );
                }
            }
        }
    }

    /// Remove expired oracle results to keep state bounded.
    pub fn prune_expired_oracle_results(&mut self, current_height: u64) {
        let mut expired_result_ids: Vec<[u8; 32]> = self
            .oracle_results
            .iter()
            .filter_map(|(request_id, result)| {
                if result.is_expired(current_height) {
                    Some(*request_id)
                } else {
                    None
                }
            })
            .collect();
        expired_result_ids.sort_unstable();

        for request_id in expired_result_ids {
            self.oracle_results.remove(&request_id);
            crate::pq_execution::remove_oracle_result(&request_id);
        }
    }

    /// End-of-block maintenance hooks.
    pub fn run_end_of_block_maintenance(&mut self, current_height: u64) {
        self.process_oracle_timeouts(current_height);
        self.prune_expired_oracle_results(current_height);
        self.prune_state_collections(current_height);

        // Distribute accumulated gas fees to validators every block.
        if self.accumulated_gas_fees > 0 {
            match self.compute_gas_fee_distribution_diff() {
                Ok(diff) => {
                    if let Err(e) = self.apply_diff(diff) {
                        tracing::warn!("Gas fee distribution failed: {}", e);
                    }
                }
                Err(e) => tracing::warn!("Gas fee distribution diff error: {}", e),
            }
        }

        // Epoch boundary: pay treasury emission if fees do not cover it.
        use crate::constants::EMISSION_EPOCH_BLOCKS;
        if current_height > 0 && current_height % EMISSION_EPOCH_BLOCKS == 0 {
            self.pay_epoch_emission(current_height);
        }
    }

    /// Compute how much the treasury must emit this epoch (0 if fees already cover it).
    pub fn compute_epoch_emission(&self, current_height: u64) -> u128 {
        use crate::constants::{
            BLOCKS_PER_YEAR, EMISSION_DECAY_BPS_PER_YEAR, EMISSION_EPOCH_BLOCKS,
            EMISSION_YEAR1_TLKD,
        };
        use truthlinked_core::constants::ONE_TLKD;

        let epoch_number = current_height / EMISSION_EPOCH_BLOCKS;
        let year_number = (epoch_number * EMISSION_EPOCH_BLOCKS / BLOCKS_PER_YEAR) as u32;

        // year_emission = EMISSION_YEAR1_TLKD * ONE_TLKD * (10000 - decay)^year / 10000^year
        let base: u128 = (10_000 - EMISSION_DECAY_BPS_PER_YEAR as u128).pow(year_number);
        let denom: u128 = 10_000u128.pow(year_number);
        let year_emission = EMISSION_YEAR1_TLKD
            .saturating_mul(ONE_TLKD)
            .saturating_mul(base)
            / denom;

        let epochs_per_year = BLOCKS_PER_YEAR / EMISSION_EPOCH_BLOCKS;
        let epoch_emission = year_emission / epochs_per_year as u128;

        if self.accumulated_epoch_fees >= epoch_emission {
            0
        } else {
            epoch_emission - self.accumulated_epoch_fees
        }
    }

    /// Transfer treasury emission to validators at epoch boundaries.
    fn pay_epoch_emission(&mut self, current_height: u64) {
        use crate::constants::EMISSION_EPOCH_BLOCKS;

        let epoch_number = current_height / EMISSION_EPOCH_BLOCKS;
        if epoch_number <= self.last_emission_epoch {
            return;
        }

        let emission = self.compute_epoch_emission(current_height);
        if emission == 0 {
            self.accumulated_epoch_fees = 0;
            self.last_emission_epoch = epoch_number;
            return;
        }

        let treasury_id = treasury_system_cell_id();
        let treasury_balance = self
            .cells
            .cells
            .get(&treasury_id)
            .map(|c| c.balance)
            .unwrap_or(0);
        let actual_emission = emission.min(treasury_balance);
        if actual_emission == 0 {
            self.last_emission_epoch = epoch_number;
            return;
        }

        // Debit treasury cell.
        if let Some(cell) = self.cells.cells.get_mut(&treasury_id) {
            cell.balance = cell.balance.saturating_sub(actual_emission);
        }

        // Distribute to active validators proportional to stake.
        let current_staking_height = self.staking.current_height;
        let active: Vec<(Vec<u8>, u64)> = self
            .staking
            .validators
            .iter()
            .filter(|(_, v)| v.is_active(current_staking_height) && v.active_stake > 0)
            .map(|(pk, v)| (pk.clone(), v.active_stake))
            .collect();
        let total_stake: u64 = active.iter().map(|(_, s)| s).sum();

        if total_stake > 0 {
            let mut allocated = 0u128;
            let mut sorted = active;
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            let n = sorted.len();
            for (i, (pk, stake)) in sorted.iter().enumerate() {
                let share = if i == n - 1 {
                    actual_emission.saturating_sub(allocated)
                } else {
                    actual_emission.saturating_mul(*stake as u128) / total_stake as u128
                };
                if share == 0 {
                    continue;
                }
                let account_id = account_id_from_pubkey(pk);
                let entry = self
                    .accounts
                    .entry(account_id)
                    .or_insert_with(|| AccountRecord {
                        pubkey_bytes: pk.clone(),
                        balance: 0,
                        compute_escrow_tlkd: 0,
                        nonce: 0,
                        nfts: vec![],
                    });
                entry.balance = entry.balance.saturating_add(share);
                allocated = allocated.saturating_add(share);
            }
        }

        self.accumulated_epoch_fees = 0;
        self.last_emission_epoch = epoch_number;
    }

    fn prune_state_collections(&mut self, current_height: u64) {
        use crate::constants::*;

        // Prune expired name registrations (expires_at is block height)
        let expired_names: Vec<String> = self
            .name_registry
            .iter()
            .filter(|(_, r)| current_height > r.expires_at)
            .map(|(k, _)| k.clone())
            .collect();
        for n in expired_names {
            self.name_registry.remove(&n);
        }
        if self.name_registry.len() > MAX_NAME_REGISTRY {
            let mut e: Vec<(String, u64)> = self
                .name_registry
                .iter()
                .map(|(k, v)| (k.clone(), v.registered_at))
                .collect();
            e.sort_by(|(ka, ta), (kb, tb)| ta.cmp(tb).then_with(|| ka.cmp(kb)));
            for (k, _) in e
                .into_iter()
                .take(self.name_registry.len() - MAX_NAME_REGISTRY)
            {
                self.name_registry.remove(&k);
            }
        }

        if self.oracle_results.len() > MAX_ORACLE_RESULTS {
            let mut e: Vec<([u8; 32], u64)> = self
                .oracle_results
                .iter()
                .map(|(k, v)| (*k, v.expires_at))
                .collect();
            e.sort_by_key(|(k, t)| (*t, *k));
            for (k, _) in e
                .into_iter()
                .take(self.oracle_results.len() - MAX_ORACLE_RESULTS)
            {
                self.oracle_results.remove(&k);
                crate::pq_execution::remove_oracle_result(&k);
            }
        }

        if self.schema_registry.len() > MAX_SCHEMA_REGISTRY {
            let mut e: Vec<([u8; 32], u64)> = self
                .schema_registry
                .iter()
                .map(|(k, v)| (*k, v.created_at))
                .collect();
            e.sort_by_key(|(k, t)| (*t, *k));
            for (k, _) in e
                .into_iter()
                .take(self.schema_registry.len() - MAX_SCHEMA_REGISTRY)
            {
                self.schema_registry.remove(&k);
            }
        }

        if self.pending_names.len() > MAX_PENDING_NAMES {
            let mut e: Vec<(String, u64)> = self
                .pending_names
                .iter()
                .map(|(k, v)| (k.clone(), v.proposed_at))
                .collect();
            e.sort_by(|(ka, ta), (kb, tb)| ta.cmp(tb).then_with(|| ka.cmp(kb)));
            for (k, _) in e
                .into_iter()
                .take(self.pending_names.len() - MAX_PENDING_NAMES)
            {
                self.pending_names.remove(&k);
            }
        }

        if self.token_authority_proposals.len() > MAX_TOKEN_AUTHORITY_PROPOSALS {
            let mut e: Vec<(AccountId, u64)> = self
                .token_authority_proposals
                .iter()
                .map(|(k, v)| (*k, v.created_at))
                .collect();
            e.sort_by_key(|(k, t)| (*t, *k));
            for (k, _) in e
                .into_iter()
                .take(self.token_authority_proposals.len() - MAX_TOKEN_AUTHORITY_PROPOSALS)
            {
                self.token_authority_proposals.remove(&k);
            }
        }

        if self.url_proposals.len() > MAX_URL_PROPOSALS {
            let mut e: Vec<(String, u64)> = self
                .url_proposals
                .iter()
                .map(|(k, v)| (k.clone(), v.created_at))
                .collect();
            e.sort_by(|(ka, ta), (kb, tb)| ta.cmp(tb).then_with(|| ka.cmp(kb)));
            for (k, _) in e
                .into_iter()
                .take(self.url_proposals.len() - MAX_URL_PROPOSALS)
            {
                self.url_proposals.remove(&k);
            }
        }

        if self.schema_proposals.len() > MAX_SCHEMA_PROPOSALS {
            let mut e: Vec<([u8; 32], u64)> = self
                .schema_proposals
                .iter()
                .map(|(k, v)| (*k, v.created_at))
                .collect();
            e.sort_by_key(|(k, t)| (*t, *k));
            for (k, _) in e
                .into_iter()
                .take(self.schema_proposals.len() - MAX_SCHEMA_PROPOSALS)
            {
                self.schema_proposals.remove(&k);
            }
        }

        if self.airdrop_claims.len() > MAX_AIRDROP_CLAIMS {
            let mut e: Vec<(AccountId, u64)> =
                self.airdrop_claims.iter().map(|(k, v)| (*k, *v)).collect();
            e.sort_by_key(|(k, t)| (*t, *k));
            for (k, _) in e
                .into_iter()
                .take(self.airdrop_claims.len() - MAX_AIRDROP_CLAIMS)
            {
                self.airdrop_claims.remove(&k);
            }
        }
    }
}

pub fn account_id_from_pubkey(pubkey: &[u8]) -> AccountId {
    truthlinked_core::account_id_from_pubkey(pubkey)
}

pub fn system_authority_id() -> AccountId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"truthlinked-system-authority-v1");
    let hash = hasher.finalize();
    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&hash);
    account_id
}

pub fn is_system_cell(cell_id: &AccountId) -> bool {
    [
        staking_system_cell_id(),
        staking_system_cell_id(),
        wtrth_system_cell_id(),
        treasury_system_cell_id(),
        governance_system_cell_id(),
        name_registry_system_cell_id(),
        token_governance_system_cell_id(),
        oracle_governance_system_cell_id(),
    ]
    .contains(cell_id)
}

fn hash32(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&out);
    slot
}

fn derive_slot(namespace: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"trth:sdk:slot:v1");
    h.update([0u8]);
    h.update(namespace);
    for part in parts {
        h.update([0xFF]);
        h.update(part);
    }
    let out = h.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&out);
    slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use truthlinked_core::constants::MIN_VALIDATOR_STAKE;
    use truthlinked_oracle::http_oracle::compute_commit_hash;
    use truthlinked_runtime::cells::{CellAccount, TokenConfig};
    use truthlinked_staking::ValidatorStake;

    static TEST_NONCE: AtomicU64 = AtomicU64::new(1);

    fn make_pubkey(seed: u8) -> Vec<u8> {
        vec![seed; 1952]
    }

    fn make_account(seed: u8, balance: u128) -> (AccountId, AccountRecord, Vec<u8>) {
        let pk = make_pubkey(seed);
        let id = account_id_from_pubkey(&pk);
        let rec = AccountRecord {
            pubkey_bytes: pk.clone(),
            balance,
            compute_escrow_tlkd: 0,
            nonce: 0,
            nfts: vec![],
        };
        (id, rec, pk)
    }

    fn make_tx(sender: AccountId, intent: TransactionIntent) -> Transaction {
        let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
        Transaction {
            sender,
            intent,
            signature: vec![0u8; 3309],
            nonce: n,
            timestamp: n,
            genesis_fingerprint: crate::get_genesis_hash(),
            expiration_height: crate::get_current_height().unwrap_or(0) + 100,
        }
    }

    fn make_token_cell(owner: AccountId) -> CellAccount {
        let manifest_hash = CellAccount::compute_manifest_hash(&[], &[], &[], &[], &[]);
        CellAccount {
            cell_id: owner,
            owner,
            bytecode: vec![],
            storage: HashMap::new(),
            balance: 0,
            rent_deposit: 0,
            is_token: true,
            token_config: Some(TokenConfig {
                name: "Token".into(),
                symbol: "TKN".into(),
                decimals: 6,
                total_supply: 0,
                mint_authority: Some(owner),
                freeze_authority: Some(owner),
                transfer_fee_bps: 0,
                transfer_fee_recipient: None,
                transfer_hook: None,
                transfer_hook_gas: 0,
                max_supply: None,
                non_transferable: false,
                metadata_uri: None,
                permanent_delegate: None,
            }),
            created_at: 0,
            upgraded_at: None,
            last_rent_paid_height: 0,
            rent_grace_blocks: gp::get_u64(gp::PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS),
            pending_owner: None,
            is_immutable: false,
            declared_reads: Vec::new(),
            declared_writes: Vec::new(),
            commutative_keys: Vec::new(),
            storage_key_specs: Vec::new(),
            oracle_schema_ids: Vec::new(),
            governance_proposal: None,
            manifest_version: 1,
            manifest_hash,
        }
    }

    fn make_system_cell(
        cell_id: AccountId,
        balance: u128,
        storage: HashMap<[u8; 32], [u8; 32]>,
    ) -> CellAccount {
        let manifest_hash = CellAccount::compute_manifest_hash(&[], &[], &[], &[], &[]);
        CellAccount {
            cell_id,
            owner: system_authority_id(),
            bytecode: vec![],
            storage,
            balance,
            rent_deposit: 0,
            is_token: false,
            token_config: None,
            created_at: 0,
            upgraded_at: None,
            last_rent_paid_height: 0,
            rent_grace_blocks: gp::get_u64(gp::PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS),
            pending_owner: None,
            is_immutable: false,
            declared_reads: Vec::new(),
            declared_writes: Vec::new(),
            commutative_keys: Vec::new(),
            storage_key_specs: Vec::new(),
            oracle_schema_ids: Vec::new(),
            governance_proposal: None,
            manifest_version: 1,
            manifest_hash,
        }
    }

    fn empty_test_state_at_height(height: u64) -> State {
        let mut state = State::genesis();
        state.staking.current_height = height;
        state
    }

    fn test_url_proposal(name: String, created_at: u64) -> UrlProposal {
        UrlProposal {
            url_pattern: name,
            proposer: [7u8; 32],
            bond_amount: 0,
            voters: std::collections::HashSet::new(),
            votes_for_stake: 0,
            votes_against_stake: 0,
            created_at,
            voting_ends_at: created_at + 100,
            approved: false,
            rejected: false,
            slashed: false,
            response_format: Default::default(),
            schema_id: None,
        }
    }

    #[test]
    fn rehydrate_runtime_globals_sets_canonical_height() {
        crate::set_current_height(999);
        let state = empty_test_state_at_height(42);

        rehydrate_runtime_globals_from_state(&state);

        assert_eq!(crate::get_current_height(), Some(42));
    }

    #[test]
    fn maintenance_pruning_is_deterministic_for_equal_timestamps() {
        let mut forward = empty_test_state_at_height(10);
        let mut reverse = empty_test_state_at_height(10);
        let total = crate::constants::MAX_URL_PROPOSALS + 1;

        for i in 0..total {
            let key = format!("url-{i:03}");
            forward
                .url_proposals
                .insert(key.clone(), test_url_proposal(key, 7));
        }

        for i in (0..total).rev() {
            let key = format!("url-{i:03}");
            reverse
                .url_proposals
                .insert(key.clone(), test_url_proposal(key, 7));
        }

        forward.prune_state_collections(10);
        reverse.prune_state_collections(10);

        let mut forward_keys: Vec<_> = forward.url_proposals.keys().cloned().collect();
        let mut reverse_keys: Vec<_> = reverse.url_proposals.keys().cloned().collect();
        forward_keys.sort();
        reverse_keys.sort();

        assert_eq!(forward_keys, reverse_keys);
        assert_eq!(forward_keys.len(), crate::constants::MAX_URL_PROPOSALS);
        assert!(!forward_keys.contains(&"url-000".to_string()));
    }

    #[test]
    fn claim_creates_account_without_gas() {
        crate::set_current_height(1);
        let mut state = State::genesis();

        let (foundation_id, foundation_rec, _foundation_pk) = make_account(9, 0);
        state.accounts.insert(foundation_id, foundation_rec);
        state.foundation_mint_authority = Some(foundation_id);

        let (id, _rec, pk) = make_account(1, 0);
        let tx = make_tx(
            foundation_id,
            TransactionIntent::Claim {
                recipient: id,
                recipient_pubkey: Some(pk.clone()),
                amount: 10 * ONE_TLKD,
            },
        );

        let diff = state
            .compute_transaction_diff_skip_sig(&tx)
            .expect("claim diff");
        state.apply_diff(diff).expect("apply diff");

        let account = state.accounts.get(&id).expect("account created");
        assert_eq!(account.balance, 10 * ONE_TLKD);
        assert_eq!(state.accumulated_gas_fees, 0);
    }

    #[test]
    fn apply_diffs_batch_matches_sequential() {
        crate::set_current_height(1);
        let mut state_a = State::genesis();
        let mut state_b = State::genesis();

        let (sender_id, sender_rec, _sender_pk) = make_account(2, 1_000_000);
        let (recipient_id, recipient_rec, recipient_pk) = make_account(3, 0);
        state_a.accounts.insert(sender_id, sender_rec.clone());
        state_a.accounts.insert(recipient_id, recipient_rec.clone());
        state_b.accounts.insert(sender_id, sender_rec);
        state_b.accounts.insert(recipient_id, recipient_rec);

        let tx1 = make_tx(
            sender_id,
            TransactionIntent::Transfer {
                recipient: recipient_id,
                recipient_pubkey: Some(recipient_pk.clone()),
                amount: 100,
            },
        );
        let tx2 = make_tx(
            sender_id,
            TransactionIntent::Transfer {
                recipient: recipient_id,
                recipient_pubkey: Some(recipient_pk),
                amount: 200,
            },
        );

        let d1 = state_a.compute_transaction_diff_skip_sig(&tx1).unwrap();
        let d2 = state_a.compute_transaction_diff_skip_sig(&tx2).unwrap();

        state_a
            .apply_diffs_batch(vec![d1.clone(), d2.clone()])
            .unwrap();
        state_b.apply_diff(d1).unwrap();
        state_b.apply_diff(d2).unwrap();

        assert_eq!(state_a.accounts, state_b.accounts);
        assert_eq!(state_a.executed_tx_hashes, state_b.executed_tx_hashes);
    }

    #[test]
    fn batch_transfer_updates_balances_and_gas() {
        crate::set_current_height(1);
        let mut state = State::genesis();

        let (sender_id, sender_rec, _sender_pk) = make_account(11, 1_000_000);
        let (r1_id, r1_rec, r1_pk) = make_account(12, 0);
        let (r2_id, _r2_rec, r2_pk) = make_account(13, 0);

        state.accounts.insert(sender_id, sender_rec);
        state.accounts.insert(r1_id, r1_rec);

        let transfers = vec![
            BatchTransferEntry {
                recipient: r1_id,
                recipient_pubkey: Some(r1_pk),
                amount: 100,
            },
            BatchTransferEntry {
                recipient: r2_id,
                recipient_pubkey: Some(r2_pk),
                amount: 200,
            },
        ];

        let tx = make_tx(sender_id, TransactionIntent::BatchTransfer { transfers });
        let diff = state.compute_transaction_diff_skip_sig(&tx).unwrap();
        state.apply_diff(diff).unwrap();

        let gas_fee = (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128) * 2;
        let sender_balance = state.accounts.get(&sender_id).unwrap().balance;
        assert_eq!(sender_balance, 1_000_000 - 300 - gas_fee);
        assert_eq!(state.accounts.get(&r1_id).unwrap().balance, 100);
        assert_eq!(state.accounts.get(&r2_id).unwrap().balance, 200);
    }

    #[test]
    fn batch_transfer_is_atomic_on_invalid_recipient() {
        crate::set_current_height(1);
        let mut state = State::genesis();

        let (sender_id, sender_rec, _sender_pk) = make_account(14, 1_000_000);
        let (r1_id, r1_rec, _r1_pk) = make_account(15, 0);
        let bad_pubkey = make_pubkey(99);

        state.accounts.insert(sender_id, sender_rec);
        state.accounts.insert(r1_id, r1_rec);

        let transfers = vec![BatchTransferEntry {
            recipient: r1_id,
            recipient_pubkey: Some(bad_pubkey),
            amount: 100,
        }];

        let tx = make_tx(sender_id, TransactionIntent::BatchTransfer { transfers });
        let err = state
            .compute_transaction_diff_skip_sig(&tx)
            .expect_err("invalid recipient should fail");
        assert!(err.contains("Recipient pubkey does not match"));

        // State must remain unchanged because diff was not applied.
        assert_eq!(state.accounts.get(&sender_id).unwrap().balance, 1_000_000);
        assert_eq!(state.accounts.get(&r1_id).unwrap().balance, 0);
    }

    #[test]
    fn token_transfer_updates_balances_and_fees() {
        crate::set_current_height(1);
        let mut state = State::genesis();

        let (sender_id, mut sender_rec, _sender_pk) = make_account(4, 10_000);
        let (recipient_id, recipient_rec, _recipient_pk) = make_account(5, 0);
        let (fee_id, fee_rec, _fee_pk) = make_account(6, 0);

        sender_rec.compute_escrow_tlkd = 10 * ONE_TLKD;
        state.accounts.insert(sender_id, sender_rec);
        state.accounts.insert(recipient_id, recipient_rec);
        state.accounts.insert(fee_id, fee_rec);

        let mut cell = make_token_cell(sender_id);
        if let Some(cfg) = cell.token_config.as_mut() {
            cfg.transfer_fee_bps = 100; // 1%
            cfg.transfer_fee_recipient = Some(fee_id);
        }
        state.cells.cells.insert(sender_id, cell);
        state
            .cells
            .token_balances
            .insert((sender_id, sender_id), 1_000);

        let tx = make_tx(
            sender_id,
            TransactionIntent::TokenTransfer {
                token_cell: sender_id,
                recipient: recipient_id,
                amount: 100,
            },
        );
        let diff = state.compute_transaction_diff_skip_sig(&tx).unwrap();
        state.apply_diff(diff).unwrap();

        assert_eq!(
            state
                .cells
                .token_balances
                .get(&(sender_id, sender_id))
                .copied()
                .unwrap_or(0),
            900
        );
        assert_eq!(
            state
                .cells
                .token_balances
                .get(&(sender_id, recipient_id))
                .copied()
                .unwrap_or(0),
            99
        );
        assert_eq!(
            state
                .cells
                .token_balances
                .get(&(sender_id, fee_id))
                .copied()
                .unwrap_or(0),
            1
        );
    }

    #[test]
    fn token_transfer_respects_frozen_accounts() {
        crate::set_current_height(1);
        let mut state = State::genesis();

        let (sender_id, sender_rec, _sender_pk) = make_account(7, 10_000);
        let (recipient_id, recipient_rec, _recipient_pk) = make_account(8, 0);
        state.accounts.insert(sender_id, sender_rec);
        state.accounts.insert(recipient_id, recipient_rec);

        let cell = make_token_cell(sender_id);
        state.cells.cells.insert(sender_id, cell);
        state
            .cells
            .token_balances
            .insert((sender_id, sender_id), 1_000);
        state
            .cells
            .frozen_accounts
            .insert((sender_id, recipient_id), true);

        let tx = make_tx(
            sender_id,
            TransactionIntent::TokenTransfer {
                token_cell: sender_id,
                recipient: recipient_id,
                amount: 10,
            },
        );
        let err = state
            .compute_transaction_diff_skip_sig(&tx)
            .expect_err("frozen recipient should fail");
        assert!(err.contains("frozen"));
    }

    #[test]
    fn token_mint_and_burn_update_balances() {
        crate::set_current_height(1);
        let mut state = State::genesis();

        let (owner_id, mut owner_rec, _owner_pk) = make_account(9, 10_000);
        let (recipient_id, mut recipient_rec, _recipient_pk) = make_account(10, 10_000);
        owner_rec.compute_escrow_tlkd = 10 * ONE_TLKD;
        recipient_rec.compute_escrow_tlkd = 10 * ONE_TLKD;
        state.accounts.insert(owner_id, owner_rec);
        state.accounts.insert(recipient_id, recipient_rec);

        let cell = make_token_cell(owner_id);
        state.cells.cells.insert(owner_id, cell.clone());

        let mint_tx = make_tx(
            owner_id,
            TransactionIntent::TokenMint {
                token_cell: owner_id,
                recipient: recipient_id,
                amount: 500,
            },
        );
        let mint_diff = state.compute_transaction_diff_skip_sig(&mint_tx).unwrap();
        state.apply_diff(mint_diff).unwrap();

        assert_eq!(
            state
                .cells
                .token_balances
                .get(&(owner_id, recipient_id))
                .copied()
                .unwrap_or(0),
            500
        );
        let total_supply = state
            .cells
            .cells
            .get(&owner_id)
            .and_then(|c| c.token_config.as_ref())
            .map(|c| c.total_supply)
            .unwrap_or(0);
        assert_eq!(total_supply, 500);

        let burn_tx = make_tx(
            recipient_id,
            TransactionIntent::TokenBurn {
                token_cell: owner_id,
                amount: 200,
            },
        );
        let burn_diff = state.compute_transaction_diff_skip_sig(&burn_tx).unwrap();
        state.apply_diff(burn_diff).unwrap();

        assert_eq!(
            state
                .cells
                .token_balances
                .get(&(owner_id, owner_id))
                .copied()
                .unwrap_or(0),
            0
        );
        assert_eq!(
            state
                .cells
                .token_balances
                .get(&(owner_id, recipient_id))
                .copied()
                .unwrap_or(0),
            300
        );
        let total_supply = state
            .cells
            .cells
            .get(&owner_id)
            .and_then(|c| c.token_config.as_ref())
            .map(|c| c.total_supply)
            .unwrap_or(0);
        assert_eq!(total_supply, 300);
    }

    #[test]
    fn transfer_to_name_resolves_and_updates_balances() {
        crate::set_current_height(1);
        let mut state = State::genesis();

        let gas_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        let amount = 500u128;

        let (sender_id, sender_rec, _sender_pk) = make_account(20, amount + gas_fee);
        let (recipient_id, recipient_rec, _recipient_pk) = make_account(21, 0);

        state.accounts.insert(sender_id, sender_rec.clone());
        state.accounts.insert(recipient_id, recipient_rec);

        let name = "alice.tl".to_string();
        state.name_registry.insert(
            name.clone(),
            NameRegistration {
                name: name.clone(),
                owner: sender_id,
                target: recipient_id,
                registered_at: 0,
                expires_at: 100,
                is_cell: false,
            },
        );

        let tx = make_tx(
            sender_id,
            TransactionIntent::TransferToName { name, amount },
        );
        let diff = state.compute_transaction_diff_skip_sig(&tx).unwrap();
        state.apply_diff(diff).unwrap();

        assert_eq!(state.accounts.get(&sender_id).unwrap().balance, 0);
        assert_eq!(state.accounts.get(&recipient_id).unwrap().balance, amount);
    }

    #[test]
    fn transfer_to_name_rejects_expired_name() {
        crate::set_current_height(1);
        let mut state = State::genesis();

        let gas_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        let amount = 10u128;

        let (sender_id, sender_rec, _sender_pk) = make_account(22, amount + gas_fee);
        let (recipient_id, recipient_rec, _recipient_pk) = make_account(23, 0);
        state.accounts.insert(sender_id, sender_rec);
        state.accounts.insert(recipient_id, recipient_rec);

        let name = "expired.tl".to_string();
        state.name_registry.insert(
            name.clone(),
            NameRegistration {
                name: name.clone(),
                owner: sender_id,
                target: recipient_id,
                registered_at: 0,
                expires_at: 1,
                is_cell: false,
            },
        );

        let tx = make_tx(
            sender_id,
            TransactionIntent::TransferToName { name, amount },
        );
        let err = state
            .compute_transaction_diff_skip_sig(&tx)
            .expect_err("expired name should fail");
        assert!(err.contains("Name expired"));
    }

    #[test]
    fn token_authority_proposal_updates_config_after_quorum() {
        crate::set_current_height(1);
        let mut state = State::genesis();

        let (v1_id, v1_rec, v1_pk) = make_account(30, 1_000_000);
        let (v2_id, v2_rec, v2_pk) = make_account(31, 1_000_000);
        let (v3_id, v3_rec, v3_pk) = make_account(32, 1_000_000);

        state.accounts.insert(v1_id, v1_rec);
        state.accounts.insert(v2_id, v2_rec);
        state.accounts.insert(v3_id, v3_rec);

        let v1_stake = MIN_VALIDATOR_STAKE * 40;
        let v2_stake = MIN_VALIDATOR_STAKE * 30;
        let v3_stake = MIN_VALIDATOR_STAKE * 30;

        state
            .staking
            .validators
            .insert(v1_pk.clone(), ValidatorStake::new(v1_stake));
        state
            .staking
            .validators
            .insert(v2_pk.clone(), ValidatorStake::new(v2_stake));
        state
            .staking
            .validators
            .insert(v3_pk.clone(), ValidatorStake::new(v3_stake));

        let token_cell = v1_id;
        let cell = make_token_cell(token_cell);
        state.cells.cells.insert(token_cell, cell);

        let proposal = TokenAuthorityProposal {
            token_cell,
            proposer: v1_pk.clone(),
            voters: std::collections::HashSet::new(),
            votes_for_stake: 0,
            created_at: 1,
            voting_ends_at: 101,
            set_mint_authority: true,
            new_mint_authority: Some(v2_id),
            set_freeze_authority: true,
            new_freeze_authority: Some(v3_id),
        };
        let diff = StateDiff {
            pending_token_authority_proposals: vec![(token_cell, proposal)],
            tx_hash: [1u8; 32],
            ..StateDiff::default()
        };
        state.apply_diff(diff).unwrap();
        assert!(state.token_authority_proposals.contains_key(&token_cell));

        let diff = StateDiff {
            token_authority_votes: vec![(token_cell, v1_pk.clone(), v1_stake)],
            tx_hash: [2u8; 32],
            ..StateDiff::default()
        };
        state.apply_diff(diff).unwrap();

        let cfg = state
            .cells
            .cells
            .get(&token_cell)
            .and_then(|c| c.token_config.as_ref())
            .unwrap();
        assert_eq!(cfg.mint_authority, Some(token_cell));
        assert_eq!(cfg.freeze_authority, Some(token_cell));

        let diff = StateDiff {
            token_authority_votes: vec![(token_cell, v2_pk.clone(), v2_stake)],
            tx_hash: [3u8; 32],
            ..StateDiff::default()
        };
        state.apply_diff(diff).unwrap();

        let cfg = state
            .cells
            .cells
            .get(&token_cell)
            .and_then(|c| c.token_config.as_ref())
            .unwrap();
        assert_eq!(cfg.mint_authority, Some(v2_id));
        assert_eq!(cfg.freeze_authority, Some(v3_id));
        assert!(!state.token_authority_proposals.contains_key(&token_cell));
    }

    #[test]
    fn gas_fee_distribution_is_deterministic() {
        let mut state_a = State::genesis();
        let mut state_b = State::genesis();

        let (v1_id, v1_rec, v1_pk) = make_account(11, 0);
        let (v2_id, v2_rec, v2_pk) = make_account(12, 0);

        state_a.accounts.insert(v1_id, v1_rec.clone());
        state_a.accounts.insert(v2_id, v2_rec.clone());
        state_b.accounts.insert(v2_id, v2_rec);
        state_b.accounts.insert(v1_id, v1_rec);

        state_a
            .staking
            .validators
            .insert(v1_pk.clone(), truthlinked_staking::ValidatorStake::new(10));
        state_a
            .staking
            .validators
            .insert(v2_pk.clone(), truthlinked_staking::ValidatorStake::new(30));

        state_b
            .staking
            .validators
            .insert(v2_pk, truthlinked_staking::ValidatorStake::new(30));
        state_b
            .staking
            .validators
            .insert(v1_pk, truthlinked_staking::ValidatorStake::new(10));

        state_a.accumulated_gas_fees = 1000;
        state_b.accumulated_gas_fees = 1000;

        let diff_a = state_a.compute_gas_fee_distribution_diff().unwrap();
        let diff_b = state_b.compute_gas_fee_distribution_diff().unwrap();
        state_a.apply_diff(diff_a).unwrap();
        state_b.apply_diff(diff_b).unwrap();

        assert_eq!(state_a.accounts, state_b.accounts);
    }

    #[test]
    fn replay_pruning_is_deterministic() {
        let mut state_a = State::genesis();
        let mut state_b = State::genesis();

        for i in 0..300_001u32 {
            let mut h = blake3::Hasher::new();
            h.update(&i.to_le_bytes());
            let hash: [u8; 32] = (*h.finalize().as_bytes()).into();
            state_a.executed_tx_hashes.insert(hash);
        }
        // Insert in reverse order to simulate non-deterministic HashSet iteration.
        for i in (0..300_001u32).rev() {
            let mut h = blake3::Hasher::new();
            h.update(&i.to_le_bytes());
            let hash: [u8; 32] = (*h.finalize().as_bytes()).into();
            state_b.executed_tx_hashes.insert(hash);
        }

        let diff = StateDiff {
            tx_hash: [7u8; 32],
            ..StateDiff::default()
        };
        state_a.apply_diff(diff.clone()).unwrap();
        state_b.apply_diff(diff).unwrap();

        assert_eq!(state_a.executed_tx_hashes, state_b.executed_tx_hashes);
    }

    #[test]
    fn treasury_distribution_splits_and_debits() {
        let mut state = State::genesis();

        // Validators
        let v1_pk = make_pubkey(41);
        let v2_pk = make_pubkey(42);
        state
            .staking
            .stake(v1_pk.clone(), MIN_VALIDATOR_STAKE * 10)
            .unwrap();
        state
            .staking
            .stake(v2_pk.clone(), MIN_VALIDATOR_STAKE * 30)
            .unwrap();
        state.staking.current_height = 1;
        let active = state.staking.get_active_validators();
        assert_eq!(active.len(), 2);
        let total_stake: u64 = active.values().copied().sum();
        assert_eq!(total_stake, MIN_VALIDATOR_STAKE * 40);

        // staking holder
        let (holder_id, holder_rec, _holder_pk) = make_account(50, 0);
        state.accounts.insert(holder_id, holder_rec);

        // Build staking system cell storage
        let mut staking_storage = HashMap::new();
        let exists_slot = State::staking_map_exists_slot(&holder_id);
        staking_storage.insert(exists_slot, {
            let mut v = [0u8; 32];
            v[0] = 1;
            v
        });
        let value_slot = State::staking_map_value_slot(&holder_id);
        let mut value = [0u8; 32];
        value[0..16].copy_from_slice(&(ONE_TLKD as u128).to_le_bytes()); // amount
        value[24..32].copy_from_slice(
            &(state.staking.current_height + crate::constants::STAKED_TRTH_MAX_LOCK_BLOCKS)
                .to_le_bytes(),
        ); // lock end
        staking_storage.insert(value_slot, value);
        let len_slot = State::staking_holders_len_slot();
        let mut len_raw = [0u8; 32];
        len_raw[..8].copy_from_slice(&1u64.to_le_bytes());
        staking_storage.insert(len_slot, len_raw);
        let elem_slot = State::staking_holders_elem_slot(0);
        staking_storage.insert(elem_slot, holder_id);

        let staking_cell = make_system_cell(staking_system_cell_id(), 0, staking_storage);
        state
            .cells
            .cells
            .insert(staking_system_cell_id(), staking_cell);

        // Treasury system cell with balance for treasury revenue.
        let treasury_cell =
            make_system_cell(treasury_system_cell_id(), 20 * ONE_TLKD, HashMap::new());
        state
            .cells
            .cells
            .insert(treasury_system_cell_id(), treasury_cell);

        // Accumulated revenues (large enough to avoid rounding to zero).
        state.accumulated_gas_fees = 10 * ONE_TLKD;
        state.accumulated_name_fees = 10 * ONE_TLKD;
        state.accumulated_treasury_fees = 10 * ONE_TLKD;
        state.accumulated_compute_fees_tlkd = 10 * ONE_TLKD;
        let protocol_revenue = state
            .accumulated_gas_fees
            .saturating_add(state.accumulated_name_fees)
            .saturating_add(state.accumulated_compute_fees_tlkd);
        assert_eq!(protocol_revenue, 30 * ONE_TLKD);

        let diff = state.compute_treasury_distribution_diff().unwrap();

        let validator_total: u128 = diff.staking_rewards.iter().map(|(_, amt)| *amt).sum();
        let staking_total: u128 = diff.native_transfers.iter().map(|(_, amt)| *amt).sum();

        assert_eq!(validator_total, 24 * ONE_TLKD);
        assert_eq!(staking_total, 8 * ONE_TLKD);
        assert_eq!(diff.fee_burned, 8 * ONE_TLKD);
        assert_eq!(diff.treasury_fee_spent, 10 * ONE_TLKD);
        assert_eq!(diff.gas_fee_spent, 10 * ONE_TLKD);
        assert_eq!(diff.name_fee_spent, 10 * ONE_TLKD);
        assert_eq!(diff.compute_fee_spent, 10 * ONE_TLKD);

        let active_stake_before: u128 = state
            .staking
            .validators
            .values()
            .map(|v| v.active_stake as u128)
            .sum();
        state.apply_diff(diff).unwrap();
        let active_stake_after: u128 = state
            .staking
            .validators
            .values()
            .map(|v| v.active_stake as u128)
            .sum();
        assert_eq!(active_stake_after, active_stake_before + 24 * ONE_TLKD);
        let treasury_balance = state
            .cells
            .cells
            .get(&treasury_system_cell_id())
            .unwrap()
            .balance;
        assert_eq!(treasury_balance, 10 * ONE_TLKD);
    }

    #[test]
    fn treasury_distribution_burns_when_no_recipients_exist() {
        let mut state = State::genesis();
        state.accumulated_gas_fees = 5 * ONE_TLKD;
        state.accumulated_name_fees = 5 * ONE_TLKD;
        state.accumulated_compute_fees_tlkd = 5 * ONE_TLKD;

        let diff = state.compute_treasury_distribution_diff().unwrap();

        assert!(diff.staking_rewards.is_empty());
        assert!(diff.native_transfers.is_empty());
        assert_eq!(diff.fee_burned, 15 * ONE_TLKD);
        assert_eq!(diff.gas_fee_spent, 5 * ONE_TLKD);
        assert_eq!(diff.name_fee_spent, 5 * ONE_TLKD);
        assert_eq!(diff.compute_fee_spent, 5 * ONE_TLKD);
    }

    #[test]
    fn oracle_commit_hash_binds_status() {
        let validator_pk = vec![1u8; 32];
        let request_id = [2u8; 32];
        let body = b"ok";
        let h1 = compute_commit_hash(&validator_pk, &request_id, body, 200);
        let h2 = compute_commit_hash(&validator_pk, &request_id, body, 500);
        assert_ne!(h1, h2);
    }

    #[test]
    fn rehydrate_oracle_globals_from_state_populates_globals() {
        let mut state = State::genesis();
        let req_id = [9u8; 32];
        let result = OracleResult {
            request_id: req_id,
            url: "https://example.com".into(),
            method: "GET".into(),
            response_body: vec![1, 2, 3],
            response_status: 200,
            body_hash: [0u8; 32],
            finalized_at: 1,
            expires_at: 10,
            quorum_stake_num: 1,
            quorum_stake_den: 1,
            requesting_cell: [0u8; 32],
        };
        state.oracle_results.insert(req_id, result.clone());
        state
            .cell_visibility
            .insert([1u8; 32], CellVisibility::Public);
        state.url_proposals.insert(
            "https://example.com/*".into(),
            UrlProposal {
                url_pattern: "https://example.com/*".into(),
                proposer: [0u8; 32],
                bond_amount: 1,
                voters: std::collections::HashSet::new(),
                votes_for_stake: 1,
                votes_against_stake: 0,
                created_at: 0,
                voting_ends_at: 10,
                approved: true,
                rejected: false,
                slashed: false,
                response_format: truthlinked_governance::UrlResponseFormat::Raw,
                schema_id: None,
            },
        );

        crate::pq_execution::rehydrate_oracle_globals_from_state(&state);

        assert_eq!(get_oracle_result(&req_id), Some(result));
        assert_eq!(get_cell_visibility(&[1u8; 32]), CellVisibility::Public);
        let proposals = get_url_proposals().unwrap();
        assert!(proposals.contains_key("https://example.com/*"));
    }
}

// NFT transaction diff functions
impl State {
    fn compute_mint_nft_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        nft_id: [u8; 32],
        name: &str,
        metadata_uri: &str,
        collection: Option<[u8; 32]>,
        royalty_bps: u16,
        royalty_recipient: Option<AccountId>,
        timestamp: u64,
    ) -> Result<(), String> {
        // Validate name (max 64 chars)
        if name.is_empty() {
            return Err("NFT name cannot be empty".to_string());
        }
        if name.len() > 64 {
            return Err("NFT name too long (max 64 chars)".to_string());
        }

        // Validate metadata URI (max 512 chars, must start with valid scheme)
        if metadata_uri.len() > 512 {
            return Err("Metadata URI too long (max 512 chars)".to_string());
        }
        if !metadata_uri.starts_with("ipfs://")
            && !metadata_uri.starts_with("ar://")
            && !metadata_uri.starts_with("https://")
        {
            return Err(
                "Invalid metadata URI scheme (must be ipfs://, ar://, or https://)".to_string(),
            );
        }

        // Validate royalty
        if royalty_bps > 10000 {
            return Err("Royalty exceeds 100% (max 10000 bps)".to_string());
        }

        if self.nfts.contains_key(&nft_id) {
            return Err("NFT already exists".to_string());
        }

        let mut sender_account = self
            .accounts
            .get(&sender)
            .ok_or("Sender not found")?
            .clone();
        sender_account.nfts.push(nft_id);
        diff.account_updates.insert(sender, sender_account);

        diff.nft_updates.insert(
            nft_id,
            Some(NFTRecord {
                nft_id,
                owner: sender,
                name: name.to_string(),
                metadata_uri: metadata_uri.to_string(),
                minted_at: timestamp,
                collection,
                royalty_bps,
                royalty_recipient,
                approved: None,
            }),
        );

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_MINT_NFT) as u128;
        Ok(())
    }

    fn compute_transfer_nft_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        nft_id: [u8; 32],
        recipient: AccountId,
        recipient_pubkey: &[u8],
        sale_price: Option<u128>,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        let nft = self.nfts.get(&nft_id).ok_or("NFT not found")?;

        // Check ownership or approval
        if nft.owner != sender && nft.approved != Some(sender) {
            return Err("Not owner or approved operator".to_string());
        }

        // Handle royalty payment if this is a sale
        if let Some(price) = sale_price {
            if let Some(royalty_recipient) = nft.royalty_recipient {
                if nft.royalty_bps > 0 && royalty_recipient != sender {
                    let royalty = (price
                        .checked_mul(nft.royalty_bps as u128)
                        .ok_or("Royalty calculation overflow")?)
                        / 10000;

                    // Deduct royalty from sender
                    let mut sender_updated = sender_account.clone();
                    sender_updated.balance = sender_updated
                        .balance
                        .checked_sub(royalty)
                        .ok_or("Insufficient balance for royalty")?;
                    if let Some(prev) = diff.account_updates.get(&sender) {
                        sender_updated.nonce = prev.nonce;
                    }
                    diff.account_updates.insert(sender, sender_updated);

                    // Pay royalty recipient
                    let mut royalty_account = self
                        .accounts
                        .get(&royalty_recipient)
                        .ok_or("Royalty recipient not found")?
                        .clone();
                    royalty_account.balance = royalty_account
                        .balance
                        .checked_add(royalty)
                        .ok_or("Royalty recipient balance overflow")?;
                    diff.account_updates
                        .insert(royalty_recipient, royalty_account);
                }
            }
        }

        // Remove from current owner
        let owner = nft.owner;
        match diff.account_updates.entry(owner) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                let mut owner_account = self.accounts.get(&owner).ok_or("Owner not found")?.clone();
                owner_account.nfts.retain(|id| id != &nft_id);
                entry.insert(owner_account);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().nfts.retain(|id| id != &nft_id);
            }
        }

        // Add to recipient
        match diff.account_updates.entry(recipient) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                let mut recipient_account = if let Some(existing) = self.accounts.get(&recipient) {
                    existing.clone()
                } else {
                    if recipient_pubkey.is_empty() {
                        return Err("Recipient account not found; pubkey required".to_string());
                    }
                    AccountRecord {
                        pubkey_bytes: recipient_pubkey.to_vec(),
                        balance: 0,
                        compute_escrow_tlkd: 0,
                        nonce: 0,
                        nfts: vec![],
                    }
                };
                if recipient_account.pubkey_bytes.is_empty() {
                    if recipient_pubkey.is_empty() {
                        return Err("Recipient account missing pubkey; pubkey required".to_string());
                    }
                    recipient_account.pubkey_bytes = recipient_pubkey.to_vec();
                }
                recipient_account.nfts.push(nft_id);
                entry.insert(recipient_account);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().nfts.push(nft_id);
            }
        }

        let mut nft = self.nfts.get(&nft_id).ok_or("NFT not found")?.clone();
        nft.owner = recipient;
        nft.approved = None;
        diff.nft_updates.insert(nft_id, Some(nft));

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER_NFT) as u128;
        Ok(())
    }

    fn compute_burn_nft_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        nft_id: [u8; 32],
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if !sender_account.nfts.contains(&nft_id) {
            return Err("Sender does not own this NFT".to_string());
        }

        let mut sender_updated = sender_account.clone();
        sender_updated.nfts.retain(|id| id != &nft_id);
        if let Some(prev) = diff.account_updates.get(&sender) {
            sender_updated.nonce = prev.nonce;
        }
        diff.account_updates.insert(sender, sender_updated);

        diff.nft_updates.insert(nft_id, None);

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_BURN_NFT) as u128;
        Ok(())
    }

    fn compute_approve_nft_diff(
        &self,
        diff: &mut StateDiff,
        _sender: AccountId,
        nft_id: [u8; 32],
        approved: Option<AccountId>,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if !sender_account.nfts.contains(&nft_id) {
            return Err("Sender does not own this NFT".to_string());
        }

        let mut nft = self.nfts.get(&nft_id).ok_or("NFT not found")?.clone();
        nft.approved = approved;
        diff.nft_updates.insert(nft_id, Some(nft));

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_APPROVE_NFT) as u128;
        Ok(())
    }

    fn compute_deploy_cell_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        bytecode: &[u8],
        initial_balance: u128,
        timestamp: u64,
        declared_reads: &[[u8; 32]],
        declared_writes: &[[u8; 32]],
        commutative_keys: &[[u8; 32]],
        storage_key_specs: &[truthlinked_core::cells::StorageKeySpec],
        oracle_schema_ids: &[[u8; 32]],
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if self.cells.cells.contains_key(&cell_id) {
            return Err("Cell already exists".to_string());
        }

        if bytecode.len() > gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE) {
            return Err(format!(
                "Bytecode too large: {} bytes (max: {})",
                bytecode.len(),
                gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE)
            ));
        }

        if bytecode.len() < 4 || &bytecode[0..4] != b"AXIO" {
            return Err("Invalid bytecode: must be Axiom bytecode (magic: AXIO)".to_string());
        }

        let rent_deposit = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
        let required = initial_balance.saturating_add(rent_deposit);
        if sender_account.balance < required {
            return Err("Insufficient balance".to_string());
        }

        let (final_reads, final_writes) = (declared_reads.to_vec(), declared_writes.to_vec());

        // All cells (Axiom) go through manifest verification
        truthlinked_runtime::cells::CellAccount::verify_manifest_against_bytecode(
            bytecode,
            &final_reads,
            &final_writes,
            storage_key_specs,
        )?;

        let manifest_hash = truthlinked_runtime::cells::CellAccount::compute_manifest_hash(
            bytecode,
            &final_reads,
            &final_writes,
            commutative_keys,
            oracle_schema_ids,
        );
        let cell = truthlinked_runtime::cells::CellAccount {
            cell_id,
            owner: sender,
            bytecode: bytecode.to_vec(),
            storage: HashMap::new(),
            balance: initial_balance,
            rent_deposit,
            is_token: false,
            token_config: None,
            created_at: timestamp,
            upgraded_at: None,
            last_rent_paid_height: 0,
            rent_grace_blocks: gp::get_u64(gp::PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS),
            pending_owner: None,
            is_immutable: false,
            governance_proposal: None,
            declared_reads: final_reads,
            declared_writes: final_writes,
            commutative_keys: commutative_keys.to_vec(),
            storage_key_specs: storage_key_specs.to_vec(),
            oracle_schema_ids: oracle_schema_ids.to_vec(),
            manifest_version: 1,
            manifest_hash,
        };

        diff.cell_updates.push(CellUpdate::Deploy { cell_id, cell });

        let mut sender_updated = sender_account.clone();
        sender_updated.balance = sender_updated.balance.saturating_sub(required);
        if let Some(prev) = diff.account_updates.get(&sender) {
            sender_updated.nonce = prev.nonce;
        }
        diff.account_updates.insert(sender, sender_updated);

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL) as u128;
        Ok(())
    }
    fn compute_deploy_token_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        name: &str,
        symbol: &str,
        decimals: u8,
        total_supply: u128,
        transfer_fee_bps: u16,
        transfer_fee_recipient: Option<AccountId>,
        non_transferable: bool,
        timestamp: u64,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if self.cells.cells.contains_key(&cell_id) {
            return Err("Cell already exists".to_string());
        }

        let rent_deposit = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
        if sender_account.balance < rent_deposit {
            return Err("Insufficient balance".to_string());
        }

        let config = truthlinked_runtime::cells::TokenConfig {
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            total_supply,
            mint_authority: Some(sender),
            freeze_authority: Some(sender),
            transfer_fee_bps,
            transfer_fee_recipient,
            max_supply: None,
            non_transferable,
            transfer_hook_gas: 0,
            metadata_uri: None,
            transfer_hook: None,
            permanent_delegate: None,
        };

        let manifest_hash =
            truthlinked_runtime::cells::CellAccount::compute_manifest_hash(&[], &[], &[], &[], &[]);

        let cell = truthlinked_runtime::cells::CellAccount {
            cell_id,
            owner: system_authority_id(),
            bytecode: vec![],
            storage: HashMap::new(),
            balance: 0,
            rent_deposit,
            is_token: true,
            token_config: Some(config),
            created_at: timestamp,
            upgraded_at: None,
            last_rent_paid_height: 0,
            rent_grace_blocks: gp::get_u64(gp::PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS),
            pending_owner: None,
            is_immutable: false,
            governance_proposal: None,
            declared_reads: Vec::new(),
            declared_writes: Vec::new(),
            commutative_keys: Vec::new(),
            storage_key_specs: Vec::new(),
            oracle_schema_ids: Vec::new(),
            manifest_version: 1,
            manifest_hash,
        };

        diff.cell_updates.push(CellUpdate::Deploy { cell_id, cell });

        // Credit initial supply to the deployer
        if total_supply > 0 {
            diff.token_credits.push((cell_id, sender, total_supply));
        }

        let mut sender_updated = sender_account.clone();
        sender_updated.balance = sender_updated.balance.saturating_sub(rent_deposit);
        if let Some(prev) = diff.account_updates.get(&sender) {
            sender_updated.nonce = prev.nonce;
        }
        diff.account_updates.insert(sender, sender_updated);

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_DEPLOY_TOKEN) as u128;
        Ok(())
    }

    fn compute_call_cell_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        calldata: &[u8],
        value: u128,
        gas_limit: u64,
        timestamp: u64,
        height: u64,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        // Enforce per-transaction gas limit
        let max_gas_per_tx = gp::get_u64(gp::PARAM_MAX_GAS_PER_TX);
        if gas_limit > max_gas_per_tx {
            return Err(format!(
                "Gas limit {} exceeds maximum {}",
                gas_limit, max_gas_per_tx
            ));
        }
        let cu_fee = gas_limit as u128;

        if calldata.len() > gp::get_usize(gp::PARAM_MAX_CALLDATA_SIZE) {
            return Err(format!(
                "Calldata too large: {} bytes (max: {})",
                calldata.len(),
                gp::get_usize(gp::PARAM_MAX_CALLDATA_SIZE)
            ));
        }

        let cell = self
            .cells
            .cells
            .get(&cell_id)
            .ok_or("Cell not found")?
            .clone();

        if self.is_mcp_tool_cell(&cell_id) {
            return Err("Direct calls to MCP tools are not permitted".to_string());
        }

        if sender_account.balance < value {
            return Err("Insufficient balance".to_string());
        }

        // System cells: native Rust dispatch (no sandbox needed)
        if is_system_cell(&cell_id) {
            let result = crate::system_cells::dispatch(
                &cell_id,
                calldata,
                sender,
                &cell.storage,
                height,
                value,
                gas_limit,
                self,
            );
            if !result.success {
                return Err(result
                    .error
                    .unwrap_or_else(|| "System cell failed".to_string()));
            }
            for (key, value) in result.param_updates {
                diff.param_updates.push((key, value));
            }
            for (r, a) in result.native_credits {
                diff.native_transfers.push((r, a));
            }
            for (sender, amount) in result.native_debits {
                diff.native_debits.push((sender, amount));
            }
            for (cell_id, amount) in result.cell_debits {
                diff.cell_debits.push((cell_id, amount));
            }
            diff.staking_updates.extend(result.staking_updates);
            diff.pending_name_proposals
                .extend(result.pending_name_proposals);
            diff.name_votes.extend(result.name_votes);
            diff.name_renewals.extend(result.name_renewals);
            diff.name_transfers.extend(result.name_transfers);
            // apply storage diff via StateDiff
            if !result.storage_diff.is_empty() {
                diff.cell_updates
                    .push(truthlinked_runtime::types::CellUpdate::StorageChange {
                        cell_id,
                        storage_diff: result.storage_diff.into_iter().collect(),
                    });
            }
            if value > 0 {
                let mut sender_updated = sender_account.clone();
                sender_updated.balance = sender_updated
                    .balance
                    .checked_sub(value)
                    .ok_or("Sender balance underflow")?;
                if let Some(prev) = diff.account_updates.get(&sender) {
                    sender_updated.nonce = prev.nonce;
                }
                diff.account_updates.insert(sender, sender_updated);
                diff.cell_credits.push((cell_id, value));
            }
            return Ok(());
        }

        let cell_state_arc = Arc::new(std::sync::RwLock::new(self.cells.clone()));
        let global_state = Arc::new(self.clone());

        let result = crate::vm::axiom_runtime::execute_axiom(
            &cell.bytecode,
            cell.storage.clone(),
            cell.cell_id,
            cell.owner,
            sender,
            height,
            timestamp,
            calldata,
            value,
            gas_limit,
            1,
            Some(global_state),
            Some(cell_state_arc.clone()),
        );

        if !result.success {
            return Err(result
                .error
                .unwrap_or_else(|| "Cell execution failed".to_string()));
        }

        for (key, value) in result.param_updates {
            diff.param_updates.push((key, value));
        }
        for (recipient, amount) in result.native_credits {
            diff.native_transfers.push((recipient, amount));
        }
        for (sender, amount) in result.native_debits {
            diff.native_debits.push((sender, amount));
        }
        for (cell_id, amount) in result.cell_debits {
            diff.cell_debits.push((cell_id, amount));
        }
        if result.name_fee > 0 {
            diff.name_fee = diff.name_fee.saturating_add(result.name_fee);
        }
        diff.pending_name_proposals
            .extend(result.pending_name_proposals);
        diff.name_votes.extend(result.name_votes);
        diff.name_renewals.extend(result.name_renewals);
        diff.name_transfers.extend(result.name_transfers);
        diff.pending_token_authority_proposals
            .extend(result.pending_token_authority_proposals);
        diff.token_authority_votes
            .extend(result.token_authority_votes);
        diff.oracle_updates.extend(result.oracle_updates);

        let mut final_cell_state = cell_state_arc
            .read()
            .map_err(|_| "Failed to read cell state".to_string())?
            .clone();

        if let Some(root_cell) = final_cell_state.cells.get_mut(&cell_id) {
            for (key, value_opt) in &result.storage_diff {
                match value_opt {
                    Some(value) => {
                        root_cell.storage.insert(*key, *value);
                    }
                    None => {
                        root_cell.storage.remove(key);
                    }
                }
            }

            if value > 0 {
                root_cell.balance = root_cell
                    .balance
                    .checked_add(value)
                    .ok_or("Cell balance overflow")?;
            }
        } else {
            return Err("Root cell missing from execution state".to_string());
        }

        for (cid, after_cell) in &final_cell_state.cells {
            let Some(before_cell) = self.cells.cells.get(cid) else {
                continue;
            };

            let mut storage_diff = HashMap::new();
            for (key, value) in &after_cell.storage {
                if before_cell.storage.get(key) != Some(value) {
                    storage_diff.insert(*key, Some(*value));
                }
            }
            for key in before_cell.storage.keys() {
                if !after_cell.storage.contains_key(key) {
                    storage_diff.insert(*key, None);
                }
            }
            if !storage_diff.is_empty() {
                diff.cell_updates.push(CellUpdate::StorageChange {
                    cell_id: *cid,
                    storage_diff,
                });
            }

            if before_cell.balance != after_cell.balance {
                diff.cell_updates.push(CellUpdate::BalanceChange {
                    cell_id: *cid,
                    new_balance: after_cell.balance,
                });
            }

            if before_cell.is_token && before_cell.token_config != after_cell.token_config {
                diff.cell_updates.push(CellUpdate::Deploy {
                    cell_id: *cid,
                    cell: after_cell.clone(),
                });
            }
        }

        for (key, after_balance) in &final_cell_state.token_balances {
            let before_balance = self.cells.token_balances.get(key).copied().unwrap_or(0);
            if *after_balance != before_balance {
                diff.token_balance_updates.push((*key, *after_balance));
            }
        }
        for key in self.cells.token_balances.keys() {
            if !final_cell_state.token_balances.contains_key(key) {
                diff.token_balance_updates.push((*key, 0));
            }
        }

        for (key, after_frozen) in &final_cell_state.frozen_accounts {
            let before_frozen = self
                .cells
                .frozen_accounts
                .get(key)
                .copied()
                .unwrap_or(false);
            if *after_frozen != before_frozen {
                diff.frozen_account_updates.push((*key, *after_frozen));
            }
        }

        // Flush any oracle requests queued by Axiom VM during this execution.
        for req in result.queued_oracle_requests {
            diff.oracle_updates.push(OracleUpdate::QueueRequest(req));
        }
        for update in result.staking_updates {
            diff.staking_updates.push(update);
        }

        if value > 0 {
            let mut sender_updated = sender_account.clone();
            sender_updated.balance = sender_updated
                .balance
                .checked_sub(value)
                .ok_or("Sender balance underflow")?;
            if let Some(prev) = diff.account_updates.get(&sender) {
                sender_updated.nonce = prev.nonce;
            }
            diff.account_updates.insert(sender, sender_updated);
        }

        diff.cu_fee = cu_fee;

        Ok(())
    }

    fn compute_call_chain_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        calls: &[CellCall],
        gas_limit: u64,
        sender_account: &AccountRecord,
        allow_mcp_tools: bool,
    ) -> Result<(), String> {
        if calls.len() > gp::get_usize(gp::PARAM_MAX_CALL_CHAIN_CALLS) {
            return Err(format!(
                "Call chain too large: {} calls (max: {})",
                calls.len(),
                gp::get_usize(gp::PARAM_MAX_CALL_CHAIN_CALLS)
            ));
        }

        if !allow_mcp_tools {
            for call in calls {
                if self.is_mcp_tool_cell(&call.cell_id) {
                    return Err("Direct calls to MCP tools are not permitted".to_string());
                }
            }
        }

        let mut total_calldata = 0usize;
        for call in calls {
            if call.calldata.len() > gp::get_usize(gp::PARAM_MAX_CALLDATA_SIZE) {
                return Err(format!(
                    "Calldata too large in call chain: {} bytes (max: {})",
                    call.calldata.len(),
                    gp::get_usize(gp::PARAM_MAX_CALLDATA_SIZE)
                ));
            }
            total_calldata = total_calldata.saturating_add(call.calldata.len());
            if total_calldata > gp::get_usize(gp::PARAM_MAX_CALL_CHAIN_TOTAL_CALLDATA) {
                return Err(format!(
                    "Call chain total calldata too large: {} bytes (max: {})",
                    total_calldata,
                    gp::get_usize(gp::PARAM_MAX_CALL_CHAIN_TOTAL_CALLDATA)
                ));
            }
        }

        let total_value: u128 = calls.iter().map(|c| c.value).sum();
        if sender_account.balance < total_value {
            return Err("Insufficient balance for call chain".to_string());
        }
        let cu_fee = gas_limit as u128;

        let mut cells_clone = self.cells.clone();
        let global_state = Arc::new(self.clone());
        let results = crate::cells::ComposabilityEngine::execute_call_chain(
            &mut cells_clone,
            calls,
            sender,
            0,
            gas_limit,
            Some(global_state),
        )?;

        for result in &results {
            for req in &result.queued_oracle_requests {
                diff.oracle_updates
                    .push(OracleUpdate::QueueRequest(req.clone()));
            }
            for update in &result.staking_updates {
                diff.staking_updates.push(update.clone());
            }
            for (key, value) in &result.param_updates {
                diff.param_updates.push((*key, *value));
            }
            for (recipient, amount) in &result.native_credits {
                diff.native_transfers.push((*recipient, *amount));
            }
            for (sender, amount) in &result.native_debits {
                diff.native_debits.push((*sender, *amount));
            }
            for (cell_id, amount) in &result.cell_debits {
                diff.cell_debits.push((*cell_id, *amount));
            }
            if result.name_fee > 0 {
                diff.name_fee = diff.name_fee.saturating_add(result.name_fee);
            }
            diff.pending_name_proposals
                .extend(result.pending_name_proposals.clone());
            diff.name_votes.extend(result.name_votes.clone());
            diff.name_renewals.extend(result.name_renewals.clone());
            diff.name_transfers.extend(result.name_transfers.clone());
            diff.pending_token_authority_proposals
                .extend(result.pending_token_authority_proposals.clone());
            diff.token_authority_votes
                .extend(result.token_authority_votes.clone());
            diff.oracle_updates.extend(result.oracle_updates.clone());
        }

        for (cid, after_cell) in &cells_clone.cells {
            let Some(before_cell) = self.cells.cells.get(cid) else {
                continue;
            };

            let mut storage_diff = HashMap::new();
            for (key, value) in &after_cell.storage {
                if before_cell.storage.get(key) != Some(value) {
                    storage_diff.insert(*key, Some(*value));
                }
            }
            for key in before_cell.storage.keys() {
                if !after_cell.storage.contains_key(key) {
                    storage_diff.insert(*key, None);
                }
            }
            if !storage_diff.is_empty() {
                diff.cell_updates.push(CellUpdate::StorageChange {
                    cell_id: *cid,
                    storage_diff,
                });
            }

            if before_cell.balance != after_cell.balance {
                diff.cell_updates.push(CellUpdate::BalanceChange {
                    cell_id: *cid,
                    new_balance: after_cell.balance,
                });
            }

            if before_cell.is_token && before_cell.token_config != after_cell.token_config {
                diff.cell_updates.push(CellUpdate::Deploy {
                    cell_id: *cid,
                    cell: after_cell.clone(),
                });
            }
        }

        for (key, after_balance) in &cells_clone.token_balances {
            let before_balance = self.cells.token_balances.get(key).copied().unwrap_or(0);
            if *after_balance != before_balance {
                diff.token_balance_updates.push((*key, *after_balance));
            }
        }
        for key in self.cells.token_balances.keys() {
            if !cells_clone.token_balances.contains_key(key) {
                diff.token_balance_updates.push((*key, 0));
            }
        }

        for (key, after_frozen) in &cells_clone.frozen_accounts {
            let before_frozen = self
                .cells
                .frozen_accounts
                .get(key)
                .copied()
                .unwrap_or(false);
            if *after_frozen != before_frozen {
                diff.frozen_account_updates.push((*key, *after_frozen));
            }
        }

        if total_value > 0 {
            let mut sender_updated = sender_account.clone();
            sender_updated.balance = sender_updated
                .balance
                .checked_sub(total_value)
                .ok_or("Sender balance underflow")?;
            if let Some(prev) = diff.account_updates.get(&sender) {
                sender_updated.nonce = prev.nonce;
            }
            diff.account_updates.insert(sender, sender_updated);
        }

        diff.cu_fee = cu_fee;
        Ok(())
    }

    fn is_mcp_tool_cell(&self, cell_id: &AccountId) -> bool {
        use truthlinked_mcp::{protocol_addresses, registry_keys};
        let registry_id = protocol_addresses::mcp_registry();
        let registry = match self.cells.cells.get(&registry_id) {
            Some(c) => c,
            None => return false,
        };
        let tool_count = registry
            .storage
            .get(&registry_keys::TOOL_COUNT)
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0u8; 8])))
            .unwrap_or(0);
        for i in 0..tool_count {
            if registry.storage.get(&registry_keys::tool_entry(i)).copied() == Some(*cell_id) {
                return true;
            }
        }
        false
    }

    fn compute_upgrade_cell_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        new_bytecode: &[u8],
        new_declared_reads: &[[u8; 32]],
        new_declared_writes: &[[u8; 32]],
        new_commutative_keys: &[[u8; 32]],
        new_storage_key_specs: &[truthlinked_core::cells::StorageKeySpec],
        new_oracle_schema_ids: &[[u8; 32]],
        timestamp: u64,
        _sender_account: &AccountRecord,
    ) -> Result<(), String> {
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        let system_id = system_authority_id();
        if cell.owner == system_id {
            return Err("System-owned cell: use governance proposal".to_string());
        }
        if cell.owner != sender {
            return Err("Not cell owner".to_string());
        }
        if cell.is_immutable {
            return Err("Cell is immutable".to_string());
        }

        if new_bytecode.len() > gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE) {
            return Err("Bytecode too large".to_string());
        }

        // PHASE 1: Verify manifest against bytecode
        CellAccount::verify_manifest_against_bytecode(
            new_bytecode,
            new_declared_reads,
            new_declared_writes,
            new_storage_key_specs,
        )?;
        CellAccount::require_inferable(new_bytecode, new_storage_key_specs)?;

        diff.cell_updates.push(CellUpdate::Upgrade {
            cell_id,
            new_bytecode: new_bytecode.to_vec(),
            new_declared_reads: new_declared_reads.to_vec(),
            new_declared_writes: new_declared_writes.to_vec(),
            new_commutative_keys: new_commutative_keys.to_vec(),
            new_storage_key_specs: new_storage_key_specs.to_vec(),
            new_oracle_schema_ids: new_oracle_schema_ids.to_vec(),
            timestamp,
        });

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_UPGRADE_CELL) as u128;
        Ok(())
    }

    fn compute_token_transfer_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        token_cell: AccountId,
        recipient: AccountId,
        amount: u128,
        timestamp: u64,
    ) -> Result<(), String> {
        let cell = self
            .cells
            .cells
            .get(&token_cell)
            .ok_or("Token cell not found")?;

        if !cell.is_token {
            return Err("Not a token cell".to_string());
        }

        let mut balances = HashMap::new();
        let sender_bal = self
            .cells
            .token_balances
            .get(&(token_cell, sender))
            .copied()
            .unwrap_or(0);
        let recipient_bal = self
            .cells
            .token_balances
            .get(&(token_cell, recipient))
            .copied()
            .unwrap_or(0);
        balances.insert(sender, sender_bal);
        balances.insert(recipient, recipient_bal);

        if let Some(config) = &cell.token_config {
            if let Some(fee_recipient) = config.transfer_fee_recipient {
                let fee_bal = self
                    .cells
                    .token_balances
                    .get(&(token_cell, fee_recipient))
                    .copied()
                    .unwrap_or(0);
                balances.insert(fee_recipient, fee_bal);
            }
        }

        let height = crate::get_current_height().unwrap_or(0);
        let result = crate::cells::TokenExecutor::transfer(
            cell,
            sender,
            recipient,
            amount,
            &mut balances,
            Some(&self.cells),
            height,
            timestamp,
        )?;

        if !result.success {
            return Err(result
                .error
                .unwrap_or_else(|| "Token transfer failed".to_string()));
        }

        // Enforce transfer hook gas budget deterministically.
        let hook_gas_budget = cell
            .token_config
            .as_ref()
            .map(|c| c.transfer_hook_gas)
            .unwrap_or(0);
        if result.gas_used > hook_gas_budget && hook_gas_budget > 0 {
            return Err("Transfer hook gas exceeded configured limit".to_string());
        }

        for (account, balance) in balances {
            diff.token_balance_updates
                .push(((token_cell, account), balance));
        }

        let hook_gas = cell
            .token_config
            .as_ref()
            .map(|c| c.transfer_hook_gas)
            .unwrap_or(0);
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TOKEN_TRANSFER) as u128 + (hook_gas as u128);
        Ok(())
    }

    fn compute_token_mint_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        token_cell: AccountId,
        recipient: AccountId,
        amount: u128,
    ) -> Result<(), String> {
        let mut cell = self
            .cells
            .cells
            .get(&token_cell)
            .ok_or("Token cell not found")?
            .clone();

        let mut balances = HashMap::new();
        let recipient_bal = self
            .cells
            .token_balances
            .get(&(token_cell, recipient))
            .copied()
            .unwrap_or(0);
        balances.insert(recipient, recipient_bal);

        crate::cells::TokenExecutor::mint(&mut cell, sender, recipient, amount, &mut balances)?;

        for (account, balance) in balances {
            diff.token_balance_updates
                .push(((token_cell, account), balance));
        }

        // Update cell with new total_supply
        diff.cell_updates.push(CellUpdate::Deploy {
            cell_id: token_cell,
            cell,
        });

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TOKEN_MINT) as u128;
        Ok(())
    }

    fn compute_token_burn_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        token_cell: AccountId,
        amount: u128,
    ) -> Result<(), String> {
        let mut cell = self
            .cells
            .cells
            .get(&token_cell)
            .ok_or("Token cell not found")?
            .clone();

        let mut balances = HashMap::new();
        let sender_bal = self
            .cells
            .token_balances
            .get(&(token_cell, sender))
            .copied()
            .unwrap_or(0);
        balances.insert(sender, sender_bal);

        crate::cells::TokenExecutor::burn(&mut cell, sender, amount, &mut balances)?;

        for (account, balance) in balances {
            diff.token_balance_updates
                .push(((token_cell, account), balance));
        }

        // Update cell with new total_supply
        diff.cell_updates.push(CellUpdate::Deploy {
            cell_id: token_cell,
            cell,
        });

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TOKEN_BURN) as u128;
        Ok(())
    }

    fn compute_token_freeze_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        token_cell: AccountId,
        account: AccountId,
    ) -> Result<(), String> {
        let cell = self
            .cells
            .cells
            .get(&token_cell)
            .ok_or("Token cell not found")?;

        crate::cells::TokenExecutor::freeze(cell, sender, account)?;

        // Update frozen_accounts in CellState
        diff.frozen_account_updates
            .push(((token_cell, account), true));

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TOKEN_TRANSFER) as u128;
        Ok(())
    }

    fn compute_token_thaw_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        token_cell: AccountId,
        account: AccountId,
    ) -> Result<(), String> {
        let cell = self
            .cells
            .cells
            .get(&token_cell)
            .ok_or("Token cell not found")?;

        crate::cells::TokenExecutor::thaw(cell, sender, account)?;

        // Update frozen_accounts in CellState
        diff.frozen_account_updates
            .push(((token_cell, account), false));

        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TOKEN_TRANSFER) as u128;
        Ok(())
    }

    fn compute_transfer_ownership_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        new_owner: AccountId,
    ) -> Result<(), String> {
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        let system_id = system_authority_id();
        if cell.owner == system_id {
            return Err("System-owned cell: use governance proposal".to_string());
        }
        if cell.owner != sender {
            return Err("Not cell owner".to_string());
        }
        if cell.is_immutable {
            return Err("Cell is immutable".to_string());
        }
        diff.cell_updates
            .push(CellUpdate::TransferOwnership { cell_id, new_owner });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    fn compute_make_immutable_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
    ) -> Result<(), String> {
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        let system_id = system_authority_id();
        if cell.owner == system_id {
            return Err("System-owned cell: use governance proposal".to_string());
        }
        if cell.owner != sender {
            return Err("Not cell owner".to_string());
        }
        diff.cell_updates.push(CellUpdate::MakeImmutable {
            cell_id,
            caller: sender,
        });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    fn compute_propose_cell_upgrade_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        new_bytecode: &[u8],
        new_declared_reads: &[[u8; 32]],
        new_declared_writes: &[[u8; 32]],
        new_commutative_keys: &[[u8; 32]],
        new_storage_key_specs: &[truthlinked_core::cells::StorageKeySpec],
        new_oracle_schema_ids: &[[u8; 32]],
        timelock_blocks: u64,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if !self
            .staking
            .validators
            .contains_key(&sender_account.pubkey_bytes)
        {
            return Err("Only validators can propose upgrades".to_string());
        }
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        let system_id = system_authority_id();
        if cell.owner != system_id {
            return Err("Cell is not system-owned".to_string());
        }
        if cell.is_immutable {
            return Err("Cell is immutable".to_string());
        }
        if cell.governance_proposal.is_some() {
            return Err("Cell already has an active proposal".to_string());
        }

        if new_bytecode.len() > gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE) {
            return Err("Bytecode too large".to_string());
        }
        CellAccount::verify_manifest_against_bytecode(
            new_bytecode,
            new_declared_reads,
            new_declared_writes,
            new_storage_key_specs,
        )?;
        CellAccount::require_inferable(new_bytecode, new_storage_key_specs)?;

        let mut updated = cell.clone();
        let current_height = crate::get_current_height().unwrap_or(0);
        updated.governance_proposal = Some(truthlinked_runtime::cells::GovernanceProposal {
            proposal_type: truthlinked_runtime::cells::ProposalType::Upgrade {
                new_bytecode: new_bytecode.to_vec(),
                declared_reads: new_declared_reads.to_vec(),
                declared_writes: new_declared_writes.to_vec(),
                commutative_keys: new_commutative_keys.to_vec(),
                storage_key_specs: new_storage_key_specs.to_vec(),
                oracle_schema_ids: new_oracle_schema_ids.to_vec(),
            },
            proposer: sender,
            created_at_height: current_height,
            timelock_blocks,
            require_vote: true,
            votes_for: 0,
            votes_against: 0,
            voters: std::collections::HashSet::new(),
            executed: false,
        });

        diff.cell_updates.push(CellUpdate::Deploy {
            cell_id,
            cell: updated,
        });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    fn compute_propose_cell_ownership_transfer_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        new_owner: AccountId,
        timelock_blocks: u64,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if !self
            .staking
            .validators
            .contains_key(&sender_account.pubkey_bytes)
        {
            return Err("Only validators can propose ownership transfer".to_string());
        }
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        let system_id = system_authority_id();
        if cell.owner != system_id {
            return Err("Cell is not system-owned".to_string());
        }
        if cell.is_immutable {
            return Err("Cell is immutable".to_string());
        }
        if cell.governance_proposal.is_some() {
            return Err("Cell already has an active proposal".to_string());
        }

        let mut updated = cell.clone();
        let current_height = crate::get_current_height().unwrap_or(0);
        updated.governance_proposal = Some(truthlinked_runtime::cells::GovernanceProposal {
            proposal_type: truthlinked_runtime::cells::ProposalType::OwnershipTransfer {
                new_owner,
            },
            proposer: sender,
            created_at_height: current_height,
            timelock_blocks,
            require_vote: true,
            votes_for: 0,
            votes_against: 0,
            voters: std::collections::HashSet::new(),
            executed: false,
        });
        diff.cell_updates.push(CellUpdate::Deploy {
            cell_id,
            cell: updated,
        });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    fn compute_propose_cell_make_immutable_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        timelock_blocks: u64,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if !self
            .staking
            .validators
            .contains_key(&sender_account.pubkey_bytes)
        {
            return Err("Only validators can propose make-immutable".to_string());
        }
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        let system_id = system_authority_id();
        if cell.owner != system_id {
            return Err("Cell is not system-owned".to_string());
        }
        if cell.is_immutable {
            return Err("Cell is immutable".to_string());
        }
        if cell.governance_proposal.is_some() {
            return Err("Cell already has an active proposal".to_string());
        }

        let mut updated = cell.clone();
        let current_height = crate::get_current_height().unwrap_or(0);
        updated.governance_proposal = Some(truthlinked_runtime::cells::GovernanceProposal {
            proposal_type: truthlinked_runtime::cells::ProposalType::MakeImmutable,
            proposer: sender,
            created_at_height: current_height,
            timelock_blocks,
            require_vote: true,
            votes_for: 0,
            votes_against: 0,
            voters: std::collections::HashSet::new(),
            executed: false,
        });
        diff.cell_updates.push(CellUpdate::Deploy {
            cell_id,
            cell: updated,
        });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    fn compute_vote_cell_proposal_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        approve: bool,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if !self
            .staking
            .validators
            .contains_key(&sender_account.pubkey_bytes)
        {
            return Err("Only validators can vote".to_string());
        }
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        let system_id = system_authority_id();
        if cell.owner != system_id {
            return Err("Cell is not system-owned".to_string());
        }
        let mut updated = cell.clone();
        let proposal = updated
            .governance_proposal
            .as_mut()
            .ok_or("No active proposal")?;
        if proposal.executed {
            return Err("Proposal already executed".to_string());
        }
        let current_height = crate::get_current_height().unwrap_or(0);
        let voting_ends_at = proposal
            .created_at_height
            .checked_add(proposal.timelock_blocks)
            .ok_or("Timelock calculation overflow")?;
        if current_height > voting_ends_at {
            return Err("Voting period closed".to_string());
        }
        if proposal.voters.contains(&sender) {
            return Err("Already voted".to_string());
        }
        proposal.voters.insert(sender);
        let stake = self
            .staking
            .validators
            .get(&sender_account.pubkey_bytes)
            .map(|v| v.active_stake)
            .unwrap_or(0);
        if approve {
            proposal.votes_for = proposal.votes_for.saturating_add(stake);
        } else {
            proposal.votes_against = proposal.votes_against.saturating_add(stake);
        }
        diff.cell_updates.push(CellUpdate::Deploy {
            cell_id,
            cell: updated,
        });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    fn compute_execute_cell_proposal_diff(
        &self,
        diff: &mut StateDiff,
        _sender: AccountId,
        cell_id: AccountId,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        if !self
            .staking
            .validators
            .contains_key(&sender_account.pubkey_bytes)
        {
            return Err("Only validators can execute proposals".to_string());
        }
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        let system_id = system_authority_id();
        if cell.owner != system_id {
            return Err("Cell is not system-owned".to_string());
        }
        let mut updated = cell.clone();
        let proposal = updated
            .governance_proposal
            .as_mut()
            .ok_or("No active proposal")?;
        if proposal.executed {
            return Err("Proposal already executed".to_string());
        }
        let current_height = crate::get_current_height().unwrap_or(0);
        let unlock_height = proposal
            .created_at_height
            .checked_add(proposal.timelock_blocks)
            .ok_or("Timelock calculation overflow")?;
        if current_height < unlock_height {
            return Err("Timelock not expired".to_string());
        }
        let total_stake: u64 = self
            .staking
            .validators
            .values()
            .filter(|v| v.is_active(current_height))
            .map(|v| v.active_stake)
            .sum();
        let approval_threshold = total_stake
            .checked_mul(67)
            .and_then(|t| t.checked_div(100))
            .ok_or("Approval threshold calculation overflow")?;
        if proposal.votes_for < approval_threshold {
            return Err("Insufficient votes for approval".to_string());
        }

        match &proposal.proposal_type {
            truthlinked_runtime::cells::ProposalType::OwnershipTransfer { new_owner } => {
                updated.pending_owner = Some(*new_owner);
            }
            truthlinked_runtime::cells::ProposalType::Upgrade {
                new_bytecode,
                declared_reads,
                declared_writes,
                commutative_keys,
                storage_key_specs,
                oracle_schema_ids,
            } => {
                if new_bytecode.len() > gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE) {
                    return Err("Bytecode too large".to_string());
                }
                CellAccount::verify_manifest_against_bytecode(
                    new_bytecode,
                    declared_reads,
                    declared_writes,
                    storage_key_specs,
                )?;
                CellAccount::require_inferable(new_bytecode, storage_key_specs)?;

                let new_manifest_hash = CellAccount::compute_manifest_hash(
                    new_bytecode,
                    declared_reads,
                    declared_writes,
                    commutative_keys,
                    oracle_schema_ids,
                );

                updated.manifest_version = updated.manifest_version.saturating_add(1);
                updated.bytecode = new_bytecode.clone();
                updated.declared_reads = declared_reads.clone();
                updated.declared_writes = declared_writes.clone();
                updated.commutative_keys = commutative_keys.clone();
                updated.storage_key_specs = storage_key_specs.clone();
                updated.oracle_schema_ids = oracle_schema_ids.clone();
                updated.manifest_hash = new_manifest_hash;
                updated.upgraded_at = Some(current_height);
            }
            truthlinked_runtime::cells::ProposalType::MakeImmutable => {
                updated.is_immutable = true;
                updated.pending_owner = None;
            }
        }

        proposal.executed = true;
        updated.governance_proposal = None;
        diff.cell_updates.push(CellUpdate::Deploy {
            cell_id,
            cell: updated,
        });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    fn compute_close_cell_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        _sender_account: &AccountRecord,
    ) -> Result<(), String> {
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        let system_id = system_authority_id();
        if cell.owner == system_id {
            return Err("System-owned cell: use governance proposal".to_string());
        }
        if cell.owner != sender {
            return Err("Only the cell owner can close the cell".to_string());
        }
        if cell.is_token {
            if let Some(cfg) = cell.token_config.as_ref() {
                if cfg.total_supply > 0 {
                    return Err("Cannot close token cell with non-zero supply".to_string());
                }
            }
        }

        let mut owner_account = self
            .accounts
            .get(&cell.owner)
            .ok_or("Cell owner account not found")?
            .clone();
        owner_account.balance = owner_account
            .balance
            .saturating_add(cell.balance)
            .saturating_add(cell.rent_deposit);
        diff.account_updates.insert(cell.owner, owner_account);

        diff.cell_updates.push(CellUpdate::Remove { cell_id });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    /// Collect storage rent from all cells
    pub fn collect_storage_rent(&mut self, current_height: u64) -> u128 {
        let _ = current_height;
        0
    }

    /// Gas-only distribution helper retained for focused determinism tests.
    ///
    /// Live consensus uses `compute_treasury_distribution_diff`, which applies
    /// the protocol-wide validator, Staked TLKD holder, and burn split.
    pub fn compute_gas_fee_distribution_diff(&self) -> Result<StateDiff, String> {
        let mut diff = StateDiff::default();
        diff.is_system = true;
        let fees_to_distribute = self.accumulated_gas_fees;
        if fees_to_distribute == 0 {
            return Ok(diff);
        }

        let current_height = self.staking.current_height;
        let total_stake: u64 = self
            .staking
            .validators
            .values()
            .filter(|v| v.is_active(current_height))
            .map(|v| v.active_stake)
            .sum();

        diff.gas_fee_spent = fees_to_distribute;
        if total_stake == 0 {
            return Ok(diff);
        }

        let mut updates: Vec<(AccountId, u128, u64)> = Vec::new();
        let mut unmatched_share: u128 = 0;

        let mut sorted_pks: Vec<Vec<u8>> = self.staking.validators.keys().cloned().collect();
        sorted_pks.sort();
        for validator_pk in &sorted_pks {
            let validator = match self.staking.validators.get(validator_pk) {
                Some(v) => v,
                None => continue,
            };
            if !validator.is_active(current_height) || validator.active_stake == 0 {
                continue;
            }
            let share =
                (fees_to_distribute as u128 * validator.active_stake as u128) / total_stake as u128;
            if share == 0 {
                continue;
            }
            let account_id = account_id_from_pubkey(validator_pk);
            if self.accounts.contains_key(&account_id) {
                updates.push((account_id, share, validator.active_stake));
            } else {
                unmatched_share = unmatched_share.saturating_add(share);
                tracing::warn!(
                    "Validator {} has no account - gas share {} redistributed to active validators",
                    hex::encode(&validator_pk[..8.min(validator_pk.len())]),
                    share
                );
            }
        }

        if unmatched_share > 0 && !updates.is_empty() {
            let matched_total_stake: u64 = updates.iter().map(|(_, _, s)| *s).sum();
            if matched_total_stake > 0 {
                let mut redistributed: Vec<(usize, u128)> = updates
                    .iter()
                    .enumerate()
                    .map(|(i, (_, _, s))| {
                        let extra =
                            (unmatched_share as u128 * *s as u128) / matched_total_stake as u128;
                        (i, extra)
                    })
                    .collect();
                let extra_allocated: u128 = redistributed.iter().map(|(_, e)| e).sum();
                let dust = unmatched_share.saturating_sub(extra_allocated);
                if dust > 0 {
                    let best = redistributed
                        .iter()
                        .max_by_key(|(i, _)| updates[*i].2)
                        .map(|(i, _)| *i)
                        .unwrap_or(0);
                    redistributed[best].1 = redistributed[best].1.saturating_add(dust);
                }
                for (i, extra) in redistributed {
                    updates[i].1 = updates[i].1.saturating_add(extra);
                }
            }
        }

        updates.sort_by_key(|(id, _, _)| *id);
        for (account_id, share, stake) in updates {
            tracing::info!(
                "   Validator {}: +{} (stake: {})",
                hex::encode(&account_id[..8]),
                share,
                stake
            );
            diff.native_transfers.push((account_id, share));
        }

        Ok(diff)
    }

    /// Name-only distribution helper retained for focused distribution tests.
    ///
    /// Live consensus uses `compute_treasury_distribution_diff`, which applies
    /// the protocol-wide validator, Staked TLKD holder, and burn split.
    pub fn compute_name_fee_distribution_diff(&self) -> Result<StateDiff, String> {
        let mut diff = StateDiff::default();
        diff.is_system = true;
        let fees_to_distribute = self.accumulated_name_fees;
        if fees_to_distribute == 0 {
            return Ok(diff);
        }

        let current_height = self.staking.current_height;
        let active_validators: Vec<Vec<u8>> = self
            .staking
            .validators
            .iter()
            .filter(|(_, stake)| stake.is_active(current_height))
            .map(|(pk, _)| pk.clone())
            .collect();
        let validator_count = active_validators.len();
        diff.name_fee_spent = fees_to_distribute;
        if validator_count == 0 {
            return Ok(diff);
        }

        let share_per_validator = fees_to_distribute / validator_count as u128;

        let mut sorted_pks: Vec<Vec<u8>> = active_validators;
        sorted_pks.sort();

        let mut shares: Vec<([u8; 32], u128)> = sorted_pks
            .iter()
            .map(|pk| (account_id_from_pubkey(pk), share_per_validator))
            .collect();
        let allocated: u128 = share_per_validator * validator_count as u128;
        let mut dust = fees_to_distribute.saturating_sub(allocated);

        if dust > 0 {
            let n = shares.len();
            let mut i = 0usize;
            while dust > 0 {
                shares[i % n].1 = shares[i % n].1.saturating_add(1);
                dust -= 1;
                i = i.saturating_add(1);
            }
        }

        tracing::info!(
            " Distributing {} TLKD name fees equally to {} validators ({} TLKD each)",
            fees_to_distribute / ONE_TLKD,
            validator_count,
            share_per_validator / ONE_TLKD
        );

        for (account_id, share) in shares {
            if share == 0 {
                continue;
            }
            diff.native_transfers.push((account_id, share));
        }

        Ok(diff)
    }

    /// Distribute accumulated TLKD revenue: 60% validators, 20% staking holders, 20% burn.
    pub fn compute_treasury_distribution_diff(&self) -> Result<StateDiff, String> {
        let protocol_revenue = self
            .accumulated_gas_fees
            .saturating_add(self.accumulated_name_fees)
            .saturating_add(self.accumulated_compute_fees_tlkd);
        let treasury_revenue = self.accumulated_treasury_fees;
        let total_revenue = protocol_revenue.saturating_add(treasury_revenue);
        if total_revenue == 0 {
            return Ok(StateDiff::default());
        }

        let (validator_p, staking_p, burn_p) = Self::split_revenue(protocol_revenue);
        let (validator_t, staking_t, burn_t) = Self::split_revenue(treasury_revenue);
        let mut validator_share = validator_p.saturating_add(validator_t);
        let mut staking_share = staking_p.saturating_add(staking_t);
        let mut burn_share = burn_p.saturating_add(burn_t);

        let mut diff = StateDiff::default();
        diff.is_system = true;
        diff.gas_fee_spent = self.accumulated_gas_fees;
        diff.name_fee_spent = self.accumulated_name_fees;
        diff.treasury_fee_spent = self.accumulated_treasury_fees;
        diff.compute_fee_spent = self.accumulated_compute_fees_tlkd;

        // Validator distribution (active stake only).
        let active_validators = self.staking.get_active_validators();
        let total_stake: u64 = active_validators.values().copied().sum();
        if validator_share > 0 && total_stake > 0 {
            let mut allocated = 0u128;
            for (pubkey, stake) in active_validators {
                let share = validator_share.saturating_mul(stake as u128) / total_stake as u128;
                if share > 0 {
                    diff.staking_rewards
                        .push((account_id_from_pubkey(&pubkey), share));
                    allocated = allocated.saturating_add(share);
                }
            }
            let dust = validator_share.saturating_sub(allocated);
            burn_share = burn_share.saturating_add(dust);
        } else {
            burn_share = burn_share.saturating_add(validator_share);
            validator_share = 0;
        }

        // staking distribution (holders list).
        if staking_share > 0 {
            let holders = self.load_staking_holders();
            let mut total_ve: u128 = 0;
            let mut balances: Vec<([u8; 32], u64)> = Vec::new();
            for holder in holders {
                if let Some(ve) = self.staking_balance_of(&holder) {
                    total_ve = total_ve.saturating_add(ve as u128);
                    balances.push((holder, ve));
                }
            }
            if total_ve == 0 {
                burn_share = burn_share.saturating_add(staking_share);
                staking_share = 0;
            } else {
                let mut allocated = 0u128;
                for (holder, ve) in balances {
                    let share = staking_share.saturating_mul(ve as u128) / total_ve;
                    if share > 0 {
                        diff.native_transfers.push((holder, share));
                        allocated = allocated.saturating_add(share);
                    }
                }
                let dust = staking_share.saturating_sub(allocated);
                burn_share = burn_share.saturating_add(dust);
            }
        }

        // Debit treasury system cell for treasury-sourced funds.
        if treasury_revenue > 0 {
            let treasury_cell = treasury_system_cell_id();
            let cell = self
                .cells
                .cells
                .get(&treasury_cell)
                .ok_or("Treasury cell not found")?;
            if cell.balance < treasury_revenue {
                return Err("Treasury balance insufficient for distribution".to_string());
            }
            diff.cell_updates.push(CellUpdate::BalanceChange {
                cell_id: treasury_cell,
                new_balance: cell.balance.saturating_sub(treasury_revenue),
            });
        }
        diff.fee_burned = burn_share;

        tracing::info!(
            "Treasury distribution: total={} TLKD, validators={}, staking={}, burn={}",
            total_revenue / ONE_TLKD,
            validator_share / ONE_TLKD,
            staking_share / ONE_TLKD,
            burn_share / ONE_TLKD
        );

        Ok(diff)
    }

    fn compute_set_cell_visibility_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        cell_id: AccountId,
        visibility: u8,
    ) -> Result<(), String> {
        let cell = self.cells.cells.get(&cell_id).ok_or("Cell not found")?;
        if cell.owner != sender {
            return Err("Only cell owner can set visibility".to_string());
        }
        let vis = match visibility {
            0 => CellVisibility::Private,
            1 => CellVisibility::Public,
            _ => return Err("visibility must be 0 (Private) or 1 (Public)".to_string()),
        };
        if vis == CellVisibility::Public {
            let has_approved_bonded_link = self
                .url_proposals
                .values()
                .any(|p| p.proposer == sender && p.approved && !p.slashed);
            if !has_approved_bonded_link {
                return Err(
                    "Public visibility requires at least one approved bonded URL proposal by owner"
                        .to_string(),
                );
            }
        }
        diff.oracle_updates.push(OracleUpdate::SetVisibility {
            cell_id,
            visibility: vis,
        });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    fn compute_propose_url_diff(
        &self,
        diff: &mut StateDiff,
        sender: AccountId,
        url_pattern: &str,
        bond_amount: u128,
        voting_period_blocks: u64,
        created_at: u64,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        let url_pattern = url_pattern.trim();
        if url_pattern.is_empty() {
            return Err("url_pattern must not be empty".to_string());
        }
        if bond_amount == 0 {
            return Err("URL proposal bond must be greater than zero".to_string());
        }
        if sender_account.balance < bond_amount {
            return Err("Insufficient balance for URL proposal bond".to_string());
        }
        if self.url_proposals.contains_key(url_pattern) {
            return Err(format!(
                "URL proposal already exists for pattern '{}'",
                url_pattern
            ));
        }

        let proposal = UrlProposal {
            url_pattern: url_pattern.to_string(),
            proposer: sender,
            bond_amount,
            voters: std::collections::HashSet::new(),
            votes_for_stake: 0,
            votes_against_stake: 0,
            created_at,
            voting_ends_at: self
                .staking
                .current_height
                .saturating_add(voting_period_blocks),
            approved: false,
            rejected: false,
            slashed: false,
            response_format: Default::default(),
            schema_id: None,
        };

        // URL governance bonds are held by protocol state until voting,
        // rejection, or a malicious-report path resolves the proposal.
        diff.native_debits.push((sender, bond_amount));
        diff.oracle_updates
            .push(OracleUpdate::AddUrlProposal(proposal));
        Ok(())
    }

    fn compute_vote_url_diff(
        &self,
        diff: &mut StateDiff,
        url_pattern: &str,
        approve: bool,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        let url_pattern = url_pattern.trim();
        if url_pattern.is_empty() {
            return Err("url_pattern must not be empty".to_string());
        }
        let proposal = self
            .url_proposals
            .get(url_pattern)
            .ok_or_else(|| format!("No proposal for URL pattern '{}'", url_pattern))?;
        if !proposal.voting_open(self.staking.current_height) {
            return Err(format!(
                "Voting is closed for URL pattern '{}'",
                url_pattern
            ));
        }

        let active_stake = self
            .staking
            .validators
            .get(&sender_account.pubkey_bytes)
            .map(|validator| validator.active_stake)
            .unwrap_or(0);
        if active_stake == 0 {
            return Err("Only active validators can vote on URL proposals".to_string());
        }

        diff.oracle_updates.push(OracleUpdate::VoteUrlProposal {
            url_pattern: url_pattern.to_string(),
            voter_pk: sender_account.pubkey_bytes.clone(),
            stake_for_delta: if approve { active_stake } else { 0 },
            stake_against_delta: if approve { 0 } else { active_stake },
        });
        Ok(())
    }

    fn compute_report_malicious_url_diff(
        &self,
        diff: &mut StateDiff,
        url_pattern: &str,
        evidence: &str,
    ) -> Result<(), String> {
        let url_pattern = url_pattern.trim();
        if url_pattern.is_empty() {
            return Err("url_pattern must not be empty".to_string());
        }
        if evidence.trim().is_empty() {
            return Err("evidence must not be empty".to_string());
        }
        if !self.url_proposals.contains_key(url_pattern) {
            return Err(format!("No proposal for URL pattern '{}'", url_pattern));
        }

        diff.oracle_updates.push(OracleUpdate::SlashUrlProposer {
            url_pattern: url_pattern.to_string(),
        });
        Ok(())
    }

    //  ORACLE COMMIT-REVEAL

    fn compute_oracle_commit_diff(
        &self,
        diff: &mut StateDiff,
        _sender: AccountId,
        request_id: [u8; 32],
        commit_hash: [u8; 32],
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        // Only registered validators may commit.
        if !self
            .staking
            .validators
            .contains_key(&sender_account.pubkey_bytes)
        {
            return Err("Only validators can submit oracle commits".to_string());
        }
        // Request must be pending.
        if !self.pending_oracle_requests.contains_key(&request_id) {
            return Err("Unknown oracle request_id".to_string());
        }
        // Prevent double-commit for same validator.
        if let Some(tally) = self.oracle_pending.get(&request_id) {
            if tally.commits.contains_key(&sender_account.pubkey_bytes) {
                return Err("Validator already committed for this request".to_string());
            }
        }
        let current_height = crate::get_current_height().unwrap_or(0);
        let commit = OracleCommit {
            request_id,
            commit_hash,
            validator_pk: sender_account.pubkey_bytes.clone(),
            committed_at: current_height,
        };
        diff.oracle_updates
            .push(OracleUpdate::AddCommit { request_id, commit });
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
        Ok(())
    }

    fn compute_oracle_reveal_diff(
        &self,
        diff: &mut StateDiff,
        _sender: AccountId,
        request_id: [u8; 32],
        response_body: &[u8],
        response_status: u16,
        sender_account: &AccountRecord,
    ) -> Result<(), String> {
        use truthlinked_oracle::http_oracle::compute_commit_hash;
        // Only registered validators may reveal.
        if !self
            .staking
            .validators
            .contains_key(&sender_account.pubkey_bytes)
        {
            return Err("Only validators can submit oracle reveals".to_string());
        }
        // Request must be pending.
        let req = self
            .pending_oracle_requests
            .get(&request_id)
            .ok_or("Unknown oracle request_id")?;
        // Tally must exist (commit phase happened first).
        let tally = self
            .oracle_pending
            .get(&request_id)
            .ok_or("No commit tally for this request_id - commit phase must precede reveal")?;
        if !tally.commit_quorum_reached() {
            return Err("Commit quorum not reached for this request".to_string());
        }
        // Validator must have previously committed.
        let stored_commit = tally
            .commits
            .get(&sender_account.pubkey_bytes)
            .ok_or("Validator has not committed for this request")?;
        // Prevent double-reveal.
        if tally.reveals.contains_key(&sender_account.pubkey_bytes) {
            return Err("Validator already revealed for this request".to_string());
        }
        // Enforce response size limit.
        let max_response_bytes = gp::get_usize(gp::PARAM_MAX_RESPONSE_BYTES);
        if response_body.len() > max_response_bytes {
            return Err(format!(
                "Response body exceeds {} byte limit",
                max_response_bytes
            ));
        }
        // Verify reveal matches commit.
        let expected_hash = compute_commit_hash(
            &sender_account.pubkey_bytes,
            &request_id,
            response_body,
            response_status,
        );
        if expected_hash != *stored_commit {
            // The reveal is cryptographically inconsistent with the commit.
            // This is an on-chain provable oracle lie. Slash immediately.
            // We emit a staking update so apply_diff can call slash_validator.
            // The reveal itself is NOT recorded - the bad data never reaches OracleResult.
            let outcome = self.staking.compute_slash_outcome(
                &sender_account.pubkey_bytes,
                truthlinked_staking::SlashReason::OracleLie,
                None,
            )?;
            diff.staking_updates
                .push(crate::pq_execution::StakingUpdate::Slash {
                    validator: sender_account.pubkey_bytes.clone(),
                    reason: truthlinked_staking::SlashReason::OracleLie,
                    amount: outcome.amount,
                    redistribution: outcome.redistribution,
                });
            diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128 * 2;
            return Ok(());
        }
        let current_height = crate::get_current_height().unwrap_or(0);
        let reveal = OracleReveal {
            request_id,
            response_body: response_body.to_vec(),
            response_status,
            validator_pk: sender_account.pubkey_bytes.clone(),
            revealed_at: current_height,
        };
        diff.oracle_updates
            .push(OracleUpdate::AddReveal { request_id, reveal });

        // Build a provisional tally with this new reveal included to test quorum.
        let mut provisional_tally = tally.clone();
        provisional_tally.reveals.insert(
            sender_account.pubkey_bytes.clone(),
            (response_body.to_vec(), response_status),
        );
        // Also ensure the commit is registered (it already is, but tally.try_finalize needs it).
        if let Some((body, status, agreeing_stake, total_stake)) =
            provisional_tally.try_finalize_with_format(&self.staking, req.response_format)
        {
            // Quorum reached - emit OracleResult.
            let body_hash: [u8; 32] = (*blake3::hash(&body).as_bytes()).into();
            let result = OracleResult {
                request_id,
                url: req.url.clone(),
                method: req.method.clone(),
                response_body: body,
                response_status: status,
                body_hash,
                finalized_at: current_height,
                expires_at: current_height + gp::get_u64(gp::PARAM_ORACLE_CACHE_EXPIRY_BLOCKS),
                quorum_stake_num: agreeing_stake,
                quorum_stake_den: total_stake,
                requesting_cell: req.requesting_cell,
            };
            diff.oracle_updates
                .push(OracleUpdate::FinalizeResult(result));
        }
        diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128 * 2;
        Ok(())
    }
}
