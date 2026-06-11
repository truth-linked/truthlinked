//! Compiler-aware conflict domain extraction.
//!
//! Extracts conflict domains from cell metadata at compile time.

use std::collections::HashSet;

use truthlinked_core::pq_execution::{AccountId, Transaction, TransactionIntent};

use crate::cells::CellAccount;

#[derive(Debug, Clone)]
pub struct ConcreteConflictDomain {
    pub reads: HashSet<StorageKey>,
    pub writes: HashSet<StorageKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StorageKey {
    Account(AccountId),
    CellStorage(AccountId, [u8; 32]),
    Global(String),
    Unknown([u8; 32]),
}

impl ConcreteConflictDomain {
    pub fn conflicts_with(&self, other: &Self) -> bool {
        if self.writes.iter().any(|w| other.writes.contains(w)) {
            return true;
        }
        if self.reads.iter().any(|r| other.writes.contains(r)) {
            return true;
        }
        if self.writes.iter().any(|w| other.reads.contains(w)) {
            return true;
        }
        false
    }

    pub fn from_transaction(
        tx: &Transaction,
        cell: Option<&CellAccount>,
        cells: &std::collections::HashMap<AccountId, CellAccount>,
    ) -> Self {
        let mut reads = HashSet::new();
        let mut writes = HashSet::new();

        match &tx.intent {
            TransactionIntent::Transfer { recipient, .. }
            | TransactionIntent::Claim { recipient, .. } => {
                writes.insert(StorageKey::Account(tx.sender));
                writes.insert(StorageKey::Account(*recipient));
            }
            TransactionIntent::BatchTransfer { transfers } => {
                writes.insert(StorageKey::Account(tx.sender));
                for t in transfers {
                    writes.insert(StorageKey::Account(t.recipient));
                }
            }
            TransactionIntent::TransferToName { .. }
            | TransactionIntent::BatchTransferToName { .. } => {
                // Name resolution is runtime - conservatively mark sender + global
                writes.insert(StorageKey::Account(tx.sender));
                writes.insert(StorageKey::Global("name_registry".to_string()));
            }
            TransactionIntent::DepositCompute { .. }
            | TransactionIntent::WithdrawCompute { .. }
            | TransactionIntent::WrapTRTH { .. }
            | TransactionIntent::UnwrapTRTH { .. } => {
                writes.insert(StorageKey::Account(tx.sender));
            }

            TransactionIntent::TokenTransfer { token_cell, .. } => {
                writes.insert(StorageKey::CellStorage(*token_cell, tx.sender));
            }
            TransactionIntent::CloseCell { cell_id } => {
                writes.insert(StorageKey::CellStorage(*cell_id, *cell_id));
            }
            TransactionIntent::ProposeCellUpgrade { cell_id, .. }
            | TransactionIntent::ProposeCellOwnershipTransfer { cell_id, .. }
            | TransactionIntent::ProposeCellMakeImmutable { cell_id, .. }
            | TransactionIntent::VoteCellProposal { cell_id, .. }
            | TransactionIntent::ExecuteCellProposal { cell_id, .. } => {
                writes.insert(StorageKey::CellStorage(*cell_id, *cell_id));
            }
            TransactionIntent::ProposeTokenAuthority { .. }
            | TransactionIntent::VoteTokenAuthority { .. }
            | TransactionIntent::CallSystem { .. }
            | TransactionIntent::ProposeUrl { .. }
            | TransactionIntent::VoteUrl { .. }
            | TransactionIntent::ReportMaliciousUrl { .. } => {
                writes.insert(StorageKey::Global("system".to_string()));
            }

            TransactionIntent::CallCell {
                cell_id, calldata, ..
            } => {
                if let Some(cell) = cell {
                    for read_key in &cell.declared_reads {
                        reads.insert(StorageKey::CellStorage(*cell_id, *read_key));
                    }
                    for write_key in &cell.declared_writes {
                        if !cell.commutative_keys.contains(write_key) {
                            writes.insert(StorageKey::CellStorage(*cell_id, *write_key));
                        }
                    }

                    if !cell.storage_key_specs.is_empty() {
                        for spec in &cell.storage_key_specs {
                            let end = match spec.offset.checked_add(spec.len) {
                                Some(v) => v,
                                None => continue,
                            };
                            if spec.len == 32 && calldata.len() >= end {
                                let mut user_key = [0u8; 32];
                                user_key.copy_from_slice(&calldata[spec.offset..end]);
                                if !cell.commutative_keys.contains(&user_key) {
                                    writes.insert(StorageKey::CellStorage(*cell_id, user_key));
                                }
                            }
                        }
                    }
                } else {
                    writes.insert(StorageKey::Global("global".to_string()));
                }
            }

            TransactionIntent::CallCellChain { calls, .. } => {
                for call in calls {
                    if let Some(c) = cells.get(&call.cell_id) {
                        for read_key in &c.declared_reads {
                            reads.insert(StorageKey::CellStorage(call.cell_id, *read_key));
                        }
                        for write_key in &c.declared_writes {
                            if !c.commutative_keys.contains(write_key) {
                                writes.insert(StorageKey::CellStorage(call.cell_id, *write_key));
                            }
                        }
                        if !c.storage_key_specs.is_empty() {
                            for spec in &c.storage_key_specs {
                                let end = match spec.offset.checked_add(spec.len) {
                                    Some(v) => v,
                                    None => continue,
                                };
                                if spec.len == 32 && call.calldata.len() >= end {
                                    let mut user_key = [0u8; 32];
                                    user_key.copy_from_slice(&call.calldata[spec.offset..end]);
                                    if !c.commutative_keys.contains(&user_key) {
                                        writes.insert(StorageKey::CellStorage(
                                            call.cell_id,
                                            user_key,
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        // Unknown cell - conservatively block the whole batch slot
                        writes.insert(StorageKey::Global("global".to_string()));
                    }
                }
            }

            // MCP intents and any unknowns serialize to a global conflict domain for safety.
            TransactionIntent::RegisterMcpTool { .. }
            | TransactionIntent::RegisterMcpResource { .. }
            | TransactionIntent::RegisterMcpPrompt { .. }
            | TransactionIntent::RegisterAgent { .. }
            | TransactionIntent::SuspendAgent { .. }
            | TransactionIntent::ReinstateAgent { .. }
            | TransactionIntent::McpToolCall { .. }
            | TransactionIntent::PrivateBalanceInit { .. }
            | TransactionIntent::PrivateBalanceDeposit { .. }
            | TransactionIntent::PrivateBalanceWithdraw { .. }
            | TransactionIntent::PrivateBalanceConfidentialTransfer { .. }
            | TransactionIntent::SubmitOracleCommit { .. }
            | TransactionIntent::SubmitOracleReveal { .. }
            | TransactionIntent::SetCellVisibility { .. }
            | TransactionIntent::MintNFT { .. }
            | TransactionIntent::TransferNFT { .. }
            | TransactionIntent::BurnNFT { .. }
            | TransactionIntent::ApproveNFT { .. }
            | TransactionIntent::DeployCell { .. }
            | TransactionIntent::DeployToken { .. }
            | TransactionIntent::UpgradeCell { .. }
            | TransactionIntent::TransferOwnership { .. }
            | TransactionIntent::AcceptOwnership { .. }
            | TransactionIntent::MakeImmutable { .. }
            | TransactionIntent::TokenMint { .. }
            | TransactionIntent::TokenBurn { .. }
            | TransactionIntent::TokenFreeze { .. }
            | TransactionIntent::TokenThaw { .. }
            | TransactionIntent::Stake { .. }
            | TransactionIntent::Unstake { .. }
            | TransactionIntent::WithdrawStake
            | TransactionIntent::Unjail
            | TransactionIntent::RotateKey { .. } => {
                writes.insert(StorageKey::Global("global".to_string()));
            }
        }

        ConcreteConflictDomain { reads, writes }
    }
}

pub fn partition_by_compiler_domains(
    batch: &[Transaction],
    cells: &std::collections::HashMap<AccountId, CellAccount>,
) -> Vec<Vec<usize>> {
    let mut partitions: Vec<Vec<usize>> = Vec::new();
    let mut domains: Vec<ConcreteConflictDomain> = Vec::new();

    for (tx_idx, tx) in batch.iter().enumerate() {
        let cell = match &tx.intent {
            TransactionIntent::CallCell { cell_id, .. } => cells.get(cell_id),
            TransactionIntent::CallCellChain { calls, .. } => {
                calls.get(0).and_then(|c| cells.get(&c.cell_id))
            }
            _ => None,
        };
        let domain = ConcreteConflictDomain::from_transaction(tx, cell, cells);

        let mut placed = false;
        for (part_idx, part_domain) in domains.iter_mut().enumerate() {
            if !domain.conflicts_with(part_domain) {
                part_domain.reads.extend(domain.reads.iter().cloned());
                part_domain.writes.extend(domain.writes.iter().cloned());
                partitions[part_idx].push(tx_idx);
                placed = true;
                break;
            }
        }
        if !placed {
            partitions.push(vec![tx_idx]);
            domains.push(domain);
        }
    }

    partitions
}
