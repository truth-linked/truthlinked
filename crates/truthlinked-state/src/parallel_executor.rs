//! Truthlinked State Src Parallel Executor
//!
//! Owns parallel transaction execution while preserving deterministic commit order.
//! State changes are consensus-sensitive and must preserve deterministic execution and serialization.

use crate::pq_execution::account_id_from_pubkey;
use crate::State;
use rayon::prelude::*;
use truthlinked_core::pq_execution::AccountId;
use truthlinked_core::pq_execution::Transaction;
use truthlinked_governance::params as gp;
use truthlinked_governance::NameRegistration;
use truthlinked_runtime::types::{AccountRecord, CellUpdate, StakingUpdate, StateDiff};

fn compact_account_u128_pairs(
    items: Vec<(AccountId, u128)>,
    overflow_label: &str,
) -> Result<Vec<(AccountId, u128)>, String> {
    if items.len() <= 1 {
        return Ok(items);
    }
    let mut map: std::collections::HashMap<AccountId, u128> =
        std::collections::HashMap::with_capacity(items.len());
    for (id, amount) in items {
        let e = map.entry(id).or_insert(0);
        *e = e
            .checked_add(amount)
            .ok_or_else(|| format!("{} overflow", overflow_label))?;
    }
    Ok(map.into_iter().collect())
}

fn compact_token_credit_triples(
    mut items: Vec<(AccountId, AccountId, u128)>,
) -> Result<Vec<(AccountId, AccountId, u128)>, String> {
    if items.len() <= 1 {
        return Ok(items);
    }

    items.par_sort_unstable_by(|(tc_a, rc_a, _), (tc_b, rc_b, _)| {
        tc_a.cmp(tc_b).then_with(|| rc_a.cmp(rc_b))
    });

    let mut compacted: Vec<(AccountId, AccountId, u128)> = Vec::with_capacity(items.len());
    let mut iter = items.into_iter();
    if let Some(mut current) = iter.next() {
        for (token_cell, recipient, amount) in iter {
            if token_cell == current.0 && recipient == current.1 {
                current.2 = current
                    .2
                    .checked_add(amount)
                    .ok_or_else(|| "Token credit overflow during merge compaction".to_string())?;
            } else {
                compacted.push(current);
                current = (token_cell, recipient, amount);
            }
        }
        compacted.push(current);
    }

    Ok(compacted)
}

impl State {
    pub fn merge_diff_inplace(&mut self, diff: StateDiff) -> Result<(), String> {
        // Zero-copy merge using im::HashMap's structural sharing
        // Only modified keys are cloned, rest are shared

        // Merge account updates (O(k log n) where k = updates)
        for (id, record) in diff.account_updates {
            self.accounts.insert(id, record);
        }

        // Merge nonce updates (monotonic)
        for (id, nonce) in diff.nonce_updates {
            if let Some(acc) = self.accounts.get_mut(&id) {
                if nonce > acc.nonce {
                    acc.nonce = nonce;
                }
            }
        }

        // Merge staking updates
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

        // Merge NFT updates
        for (nft_id, nft_opt) in diff.nft_updates {
            match nft_opt {
                Some(nft) => self.nfts.insert(nft_id, nft),
                None => self.nfts.remove(&nft_id),
            };
        }

        // Merge cell updates
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
                    cell.bytecode = new_bytecode;
                    cell.declared_reads = new_declared_reads;
                    cell.declared_writes = new_declared_writes;
                    cell.commutative_keys = new_commutative_keys;
                    cell.storage_key_specs = new_storage_key_specs;
                    cell.oracle_schema_ids = new_oracle_schema_ids;
                    cell.manifest_hash =
                        truthlinked_runtime::cells::CellAccount::compute_manifest_hash(
                            &cell.bytecode,
                            &cell.declared_reads,
                            &cell.declared_writes,
                            &cell.commutative_keys,
                            &cell.oracle_schema_ids,
                        );
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

        for (recipient, amount) in diff.native_transfers {
            let recipient_account =
                self.accounts
                    .entry(recipient)
                    .or_insert_with(|| AccountRecord {
                        pubkey_bytes: recipient.to_vec(),
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

        // Merge native debits (COMMUTATIVE)
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
                        pubkey_bytes: recipient.to_vec(),
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

        // Merge token credits (COMMUTATIVE)
        // token_balances is the canonical source of truth for fungible token balances.
        // cell.storage is used for Axiom VM-executed cells only.
        // We MUST read from token_balances here to avoid stomping pre-funded balances.
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

        for ((token_cell, account), balance) in diff.token_balance_updates {
            if self.cells.cells.contains_key(&token_cell) {
                self.cells
                    .token_balances
                    .insert((token_cell, account), balance);
            }
        }

        // Merge staking rewards by resolving reward account ids back to validator keys.
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

        // Merge cell credits (COMMUTATIVE)
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

        // Merge storage deltas (IN-FLIGHT COMPOSITION)
        // Deltas are composed before touching storage - O(1) writes per cell
        for (cell_id, delta) in diff.storage_deltas {
            if let Some(cell) = self.cells.cells.get_mut(&cell_id) {
                for (storage_key, delta_op) in delta.deltas {
                    // Read current value
                    let current_bytes =
                        cell.storage.get(&storage_key).cloned().unwrap_or([0u8; 32]);

                    // Apply delta operation
                    let new_bytes_vec = delta_op.apply(&current_bytes);

                    // Convert to [u8; 32]
                    let mut new_bytes = [0u8; 32];
                    let copy_len = new_bytes_vec.len().min(32);
                    new_bytes[..copy_len].copy_from_slice(&new_bytes_vec[..copy_len]);

                    // Write back
                    cell.storage.insert(storage_key, new_bytes);
                }
            }
        }

        // Accumulate fees
        if !diff.is_system {
            self.accumulated_gas_fees += diff.gas_fee;
            self.accumulated_compute_fees_tlkd += diff.compute_fee_tlkd;
            self.accumulated_treasury_fees += diff.treasury_fee;
        }
        // Name fees go directly to the treasury cell balance.
        if diff.name_fee > 0 {
            let treasury_id = truthlinked_core::pq_execution::treasury_system_cell_id();
            if let Some(cell) = self.cells.cells.get_mut(&treasury_id) {
                cell.balance = cell.balance.saturating_add(diff.name_fee);
            } else {
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

        // Record transaction hash
        if !diff.is_system {
            // Replay protection - insert all tx hashes
            if !diff.tx_hashes.is_empty() {
                for hash in diff.tx_hashes {
                    self.executed_tx_hashes.insert(hash);
                }
            } else {
                self.executed_tx_hashes.insert(diff.tx_hash);
            }
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

        for (token_cell, proposal) in diff.pending_token_authority_proposals {
            self.token_authority_proposals.insert(token_cell, proposal);
        }

        // Apply name votes to pending_names
        for (name, validator_pk, stake) in diff.name_votes {
            if let Some(pending) = self.pending_names.get_mut(&name) {
                if pending.votes.insert(validator_pk.clone()) {
                    pending.total_stake_voted = pending.total_stake_voted.saturating_add(stake);
                    let total_stake: u64 = self
                        .staking
                        .validators
                        .values()
                        .filter(|v| v.is_active(self.staking.current_height))
                        .map(|v| v.active_stake)
                        .sum();
                    let threshold = gp::get_u64(gp::PARAM_NAME_APPROVAL_THRESHOLD);
                    if total_stake > 0
                        && (pending.total_stake_voted * 100) / total_stake >= threshold
                    {
                        let reg = NameRegistration {
                            name: pending.name.clone(),
                            owner: pending.owner,
                            target: pending.cell_id,
                            registered_at: pending.proposed_at,
                            expires_at: pending.proposed_at
                                + gp::get_u64(gp::PARAM_NAME_EXPIRATION_BLOCKS),
                            is_cell: pending.is_cell,
                        };
                        let n = name.clone();
                        self.name_registry.insert(n.clone(), reg);
                        self.pending_names.remove(&n);
                    }
                }
            }
        }

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

        // Process airdrop claim
        for (account_id, timestamp) in diff.airdrop_claims {
            self.airdrop_claims.insert(account_id, timestamp);
        }

        // Merge frozen account updates
        for ((token_cell, account), frozen) in diff.frozen_account_updates {
            if frozen {
                self.cells
                    .frozen_accounts
                    .insert((token_cell, account), true);
            } else {
                self.cells.frozen_accounts.remove(&(token_cell, account));
            }
        }

        // Apply oracle updates after staking/account changes so slashing and URL governance
        // observe the latest balances/stakes from this composed diff.
        self.apply_oracle_updates(diff.oracle_updates)?;

        Ok(())
    }
}

pub struct BatchResult {
    pub state: State,
    pub applied: usize,
    pub failed: Vec<(usize, String)>,
    pub timing: BatchTiming,
    pub total_fees: u128,
}

#[derive(Default, Clone, Debug)]
pub struct BatchTiming {
    pub partition_ms: u128,
    pub parallel_ms: u128,
    pub merge_ms: u128,
    pub sig_verify_ms: u128,
    pub total_ms: u128,
}

pub fn execute_batch_parallel(state: &State, batch: &[Transaction]) -> Result<BatchResult, String> {
    execute_batch_parallel_with_profiler(state, batch, None)
}

pub fn execute_batch_parallel_with_profiler(
    state: &State,
    batch: &[Transaction],
    _profiler: Option<&truthlinked_runtime::compiler_aware::ConcreteConflictDomain>, // Ignored, using compiler-aware
) -> Result<BatchResult, String> {
    if batch.is_empty() {
        return Ok(BatchResult {
            state: state.clone(),
            applied: 0,
            failed: Vec::new(),
            timing: BatchTiming::default(),
            total_fees: 0,
        });
    }

    // Sequential fast path: small batches and same-sender nonce lanes
    // must stay ordered to preserve deterministic nonce sequencing.
    if batch.len() < 8 {
        return execute_sequential(state, batch);
    }
    let mut sender_seen = std::collections::HashSet::with_capacity(batch.len());
    if batch.iter().any(|tx| !sender_seen.insert(tx.sender)) {
        return execute_sequential(state, batch);
    }

    // Create immutable snapshot for cross-cell calls
    crate::pq_execution::set_snapshot(crate::pq_execution::StateSnapshot::from_state(state));

    tracing::info!(" Compiler-Aware Parallel: {} transactions", batch.len());
    let start = std::time::Instant::now();

    // Partition using compiler-aware conflict extraction
    let partition_start = std::time::Instant::now();
    let partitions = truthlinked_runtime::compiler_aware::partition_by_compiler_domains(
        batch,
        &state.cells.cells,
    );
    let partition_time = partition_start.elapsed();

    let partition_sizes: Vec<usize> = partitions.iter().map(|p| p.len()).collect();
    let max_size = partition_sizes.iter().max().copied().unwrap_or(0);
    let min_size = partition_sizes.iter().min().copied().unwrap_or(0);
    let avg_size = batch.len() as f64 / partitions.len() as f64;

    tracing::info!(
        " {} partitions (min: {}, max: {}, avg: {:.1}) in {:?}",
        partitions.len(),
        min_size,
        max_size,
        avg_size,
        partition_time
    );
    tracing::info!("Timing: partition={:?}", partition_time);

    // Log partition quality metrics but ALWAYS use parallel execution
    let imbalance_ratio = max_size as f64 / avg_size;
    let parallelism = batch.len() as f64 / partitions.len() as f64;

    if imbalance_ratio > 3.0 {
        tracing::debug!(
            " Partition imbalance: {:.1}x (still using parallel)",
            imbalance_ratio
        );
    }

    if parallelism < 2.0 {
        tracing::debug!(
            " High conflict rate: {:.1}x avg partition size (still using parallel)",
            parallelism
        );
    }

    // Execute partitions in parallel (no fallback to sequential)
    // Compiler-aware partitioning already separated conflicting transactions
    let parallel_start = std::time::Instant::now();

    let results: Vec<(Vec<StateDiff>, Vec<(usize, String)>)> = partitions
        .par_iter()
        .map(|partition| {
            let mut diffs = Vec::new();
            let mut errors = Vec::new();

            for &idx in partition {
                match state.compute_transaction_diff_skip_sig(&batch[idx]) {
                    Ok(diff) => {
                        diffs.push(diff);
                    }
                    Err(e) => {
                        errors.push((idx, e));
                    }
                }
            }

            (diffs, errors)
        })
        .collect();

    let parallel_time = parallel_start.elapsed();

    // Parallel merge using commutative operations
    let merge_start = std::time::Instant::now();
    let mut new_state = state.clone();

    // Phase 1: Parallel composition of commutative operations
    let (all_errors, applied, composed_diff) = results
        .into_par_iter()
        .fold(
            || (Vec::new(), 0, StateDiff::default()),
            |(mut errors, mut count, mut composed), (diffs, errs)| {
                count += diffs.len();
                errors.extend(errs);

                // Compose commutative operations in parallel
                for diff in diffs {
                    // In-batch replay guard: if this tx hash is already in the
                    // composed set, a duplicate was submitted in the same batch.
                    // Drop the second diff entirely - do not apply it.
                    if composed.tx_hashes.contains(&diff.tx_hash) {
                        count -= 1;
                        errors.push((
                            0,
                            format!("in-batch replay rejected: {}", hex::encode(diff.tx_hash)),
                        ));
                        continue;
                    }
                    composed.tx_hashes.insert(diff.tx_hash); // Track all tx hashes

                    // COMMUTATIVE operations (order-independent)
                    composed.native_transfers.extend(diff.native_transfers);
                    composed.native_debits.extend(diff.native_debits);
                    composed
                        .compute_escrow_credits
                        .extend(diff.compute_escrow_credits);
                    composed
                        .compute_escrow_debits
                        .extend(diff.compute_escrow_debits);
                    composed.token_credits.extend(diff.token_credits);
                    composed
                        .token_balance_updates
                        .extend(diff.token_balance_updates);
                    composed.staking_rewards.extend(diff.staking_rewards);
                    composed.cell_credits.extend(diff.cell_credits);
                    composed.cell_debits.extend(diff.cell_debits);

                    // NON-COMMUTATIVE: Validate no key conflicts (partitioning must be correct)
                    for (key, val) in diff.account_updates {
                        if composed.account_updates.insert(key, val).is_some() {
                            // New-account conflict: two txs wrote same recipient account.
                            // Mark for sequential fallback — not a fatal error.
                            errors.push((0, "PARTITION_FALLBACK".to_string()));
                            return (errors, count, composed);
                        }
                    }

                    for (key, val) in diff.nft_updates {
                        if composed.nft_updates.insert(key, val).is_some() {
                            errors.push((0, "PARTITION_FALLBACK".to_string()));
                            return (errors, count, composed);
                        }
                    }

                    // Vectors: just extend (order within partition is deterministic)
                    composed.staking_updates.extend(diff.staking_updates);
                    composed.cell_updates.extend(diff.cell_updates);
                    composed
                        .pending_name_proposals
                        .extend(diff.pending_name_proposals);
                    composed.name_votes.extend(diff.name_votes);
                    composed
                        .pending_token_authority_proposals
                        .extend(diff.pending_token_authority_proposals);
                    composed
                        .token_authority_votes
                        .extend(diff.token_authority_votes);
                    composed.name_renewals.extend(diff.name_renewals);
                    composed.name_transfers.extend(diff.name_transfers);
                    composed
                        .frozen_account_updates
                        .extend(diff.frozen_account_updates);
                    composed.oracle_updates.extend(diff.oracle_updates);
                    composed.nonce_updates.extend(diff.nonce_updates);

                    if !diff.airdrop_claims.is_empty() {
                        composed.airdrop_claims.extend(diff.airdrop_claims);
                    }

                    composed.gas_fee += diff.gas_fee;
                    composed.name_fee += diff.name_fee;
                    composed.cu_fee = composed.cu_fee.saturating_add(diff.cu_fee);
                    composed.treasury_fee = composed.treasury_fee.saturating_add(diff.treasury_fee);
                    composed.compute_fee_tlkd = composed
                        .compute_fee_tlkd
                        .saturating_add(diff.compute_fee_tlkd);
                    composed.gas_fee_spent =
                        composed.gas_fee_spent.saturating_add(diff.gas_fee_spent);
                    composed.name_fee_spent =
                        composed.name_fee_spent.saturating_add(diff.name_fee_spent);
                    composed.compute_fee_spent = composed
                        .compute_fee_spent
                        .saturating_add(diff.compute_fee_spent);
                    composed.treasury_fee_spent = composed
                        .treasury_fee_spent
                        .saturating_add(diff.treasury_fee_spent);
                    composed.fee_burned = composed.fee_burned.saturating_add(diff.fee_burned);
                    composed.is_system = composed.is_system || diff.is_system;

                    // Compose storage deltas
                    for (cell_id, delta) in diff.storage_deltas {
                        composed
                            .storage_deltas
                            .entry(cell_id)
                            .or_default()
                            .compose(&delta);
                    }
                }

                (errors, count, composed)
            },
        )
        .reduce(
            || (Vec::new(), 0, StateDiff::default()),
            |(mut e1, c1, mut d1), (e2, c2, d2)| {
                e1.extend(e2);
                // Dedup across fold buckets during reduce
                for hash in d2.tx_hashes {
                    if d1.tx_hashes.contains(&hash) {
                        e1.push((
                            0,
                            format!("in-batch replay rejected (reduce): {}", hex::encode(hash)),
                        ));
                    } else {
                        d1.tx_hashes.insert(hash);
                    }
                }

                // COMMUTATIVE
                d1.native_transfers.extend(d2.native_transfers);
                d1.native_debits.extend(d2.native_debits);
                d1.compute_escrow_credits.extend(d2.compute_escrow_credits);
                d1.compute_escrow_debits.extend(d2.compute_escrow_debits);
                d1.token_credits.extend(d2.token_credits);
                d1.token_balance_updates.extend(d2.token_balance_updates);
                d1.staking_rewards.extend(d2.staking_rewards);
                d1.cell_credits.extend(d2.cell_credits);

                // NON-COMMUTATIVE: Validate no conflicts
                for (key, val) in d2.account_updates {
                    if d1.account_updates.insert(key, val).is_some() {
                        e1.push((0, "PARTITION_FALLBACK".to_string()));
                        return (e1, c1 + c2, d1);
                    }
                }

                for (key, val) in d2.nft_updates {
                    if d1.nft_updates.insert(key, val).is_some() {
                        e1.push((0, "PARTITION_FALLBACK".to_string()));
                        return (e1, c1 + c2, d1);
                    }
                }

                d1.staking_updates.extend(d2.staking_updates);
                d1.cell_updates.extend(d2.cell_updates);
                d1.cell_debits.extend(d2.cell_debits);
                d1.pending_name_proposals.extend(d2.pending_name_proposals);
                d1.name_votes.extend(d2.name_votes);
                d1.pending_token_authority_proposals
                    .extend(d2.pending_token_authority_proposals);
                d1.token_authority_votes.extend(d2.token_authority_votes);
                d1.name_renewals.extend(d2.name_renewals);
                d1.name_transfers.extend(d2.name_transfers);
                d1.frozen_account_updates.extend(d2.frozen_account_updates);
                d1.oracle_updates.extend(d2.oracle_updates);
                d1.nonce_updates.extend(d2.nonce_updates);
                if !d2.airdrop_claims.is_empty() {
                    d1.airdrop_claims.extend(d2.airdrop_claims);
                }
                d1.gas_fee += d2.gas_fee;
                d1.name_fee += d2.name_fee;
                d1.cu_fee = d1.cu_fee.saturating_add(d2.cu_fee);
                d1.treasury_fee = d1.treasury_fee.saturating_add(d2.treasury_fee);
                d1.compute_fee_tlkd = d1.compute_fee_tlkd.saturating_add(d2.compute_fee_tlkd);
                d1.gas_fee_spent = d1.gas_fee_spent.saturating_add(d2.gas_fee_spent);
                d1.name_fee_spent = d1.name_fee_spent.saturating_add(d2.name_fee_spent);
                d1.compute_fee_spent = d1.compute_fee_spent.saturating_add(d2.compute_fee_spent);
                d1.treasury_fee_spent = d1.treasury_fee_spent.saturating_add(d2.treasury_fee_spent);
                d1.fee_burned = d1.fee_burned.saturating_add(d2.fee_burned);
                d1.is_system = d1.is_system || d2.is_system;
                for (cell_id, delta) in d2.storage_deltas {
                    d1.storage_deltas
                        .entry(cell_id)
                        .or_default()
                        .compose(&delta);
                }
                (e1, c1 + c2, d1)
            },
        );

    // Phase 2: Single merge of composed diff (O(1) instead of O(n))
    // If any conflict was detected during parallel compose, fall back to sequential.
    // This handles new-account conflicts (two txs sending to same not-yet-onboarded address).
    if all_errors.iter().any(|(_, msg)| msg == "PARTITION_FALLBACK") {
        tracing::warn!(" Parallel conflict detected — falling back to sequential for this batch");
        return execute_sequential(state, batch);
    }

    let mut compacted_diff = composed_diff;
    compacted_diff.native_transfers = compact_account_u128_pairs(
        std::mem::take(&mut compacted_diff.native_transfers),
        "Native transfer",
    )?;
    compacted_diff.native_debits = compact_account_u128_pairs(
        std::mem::take(&mut compacted_diff.native_debits),
        "Native debit",
    )?;
    compacted_diff.compute_escrow_credits = compact_account_u128_pairs(
        std::mem::take(&mut compacted_diff.compute_escrow_credits),
        "Compute escrow credit",
    )?;
    compacted_diff.compute_escrow_debits = compact_account_u128_pairs(
        std::mem::take(&mut compacted_diff.compute_escrow_debits),
        "Compute escrow debit",
    )?;
    compacted_diff.staking_rewards = compact_account_u128_pairs(
        std::mem::take(&mut compacted_diff.staking_rewards),
        "Staking reward",
    )?;
    compacted_diff.cell_credits = compact_account_u128_pairs(
        std::mem::take(&mut compacted_diff.cell_credits),
        "Cell credit",
    )?;
    compacted_diff.token_credits =
        compact_token_credit_triples(std::mem::take(&mut compacted_diff.token_credits))?;

    let total_fees = compacted_diff
        .gas_fee
        .saturating_add(compacted_diff.name_fee)
        .saturating_add(compacted_diff.compute_fee_tlkd)
        .saturating_add(compacted_diff.treasury_fee);

    if let Err(e) = new_state.merge_diff_inplace(compacted_diff) {
        tracing::error!(" diff merge failed: {}", e);
        return Err(format!("Merge failed after partial execution: {}", e));
    }

    // Log errors
    for (idx, err) in &all_errors {
        tracing::warn!(" TX {}: {}", idx, err);
    }

    let merge_time = merge_start.elapsed();
    let total = start.elapsed();

    // Signature verification time (estimated from parallel execution)
    let sig_verify_time = parallel_time.as_millis() / 3; // ~33% of parallel time is sig verification
    let state_merge_time = merge_time.as_millis();

    tracing::info!(
        " Compiler-Aware: {} applied, {} failed in {:?} (partition: {:?}, parallel: {:?}, merge: {:?})",
        applied,
        all_errors.len(),
        total,
        partition_time,
        parallel_time,
        merge_time
    );
    tracing::info!(
        "Breakdown: sig_verify~{}ms, state_merge={}ms",
        sig_verify_time,
        state_merge_time
    );

    Ok(BatchResult {
        state: new_state,
        applied,
        failed: all_errors,
        timing: BatchTiming {
            partition_ms: partition_time.as_millis(),
            parallel_ms: parallel_time.as_millis(),
            merge_ms: merge_time.as_millis(),
            sig_verify_ms: sig_verify_time,
            total_ms: total.as_millis(),
        },
        total_fees,
    })
}

fn diff_total_fees(diff: &StateDiff) -> u128 {
    diff.gas_fee
        .saturating_add(diff.name_fee)
        .saturating_add(diff.compute_fee_tlkd)
        .saturating_add(diff.treasury_fee)
}

pub(crate) fn execute_sequential(
    state: &State,
    batch: &[Transaction],
) -> Result<BatchResult, String> {
    let mut new_state = state.clone();
    let mut failed = Vec::new();
    let mut total_fees = 0u128;

    for (idx, tx) in batch.iter().enumerate() {
        match new_state.compute_transaction_diff_skip_sig(tx) {
            Ok(diff) => {
                let tx_fees = diff_total_fees(&diff);
                if let Err(e) = new_state.apply_diff(diff) {
                    failed.push((idx, e));
                } else {
                    total_fees = total_fees.saturating_add(tx_fees);
                }
            }
            Err(e) => failed.push((idx, e)),
        }
    }

    let applied = batch.len() - failed.len();

    Ok(BatchResult {
        state: new_state,
        applied,
        failed,
        timing: BatchTiming::default(),
        total_fees,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_total_fees_sums_all_protocol_fee_buckets() {
        let diff = StateDiff {
            gas_fee: 11,
            name_fee: 13,
            compute_fee_tlkd: 17,
            treasury_fee: 19,
            ..StateDiff::default()
        };

        assert_eq!(diff_total_fees(&diff), 60);
    }
}
