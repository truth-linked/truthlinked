//! Axiom cell state, addressing, and execution-facing helpers.
//!
//! Cell records describe deterministic bytecode state, storage declarations, rent
//! metadata, token configuration, and governance-managed lifecycle changes.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use truthlinked_governance::params as gp;

use truthlinked_core::cells::{ManifestAnalysis, StorageKeySpec};
pub type AccountId = truthlinked_core::pq_execution::AccountId;

/// Cell account - stores bytecode and state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellAccount {
    pub cell_id: AccountId,
    pub owner: AccountId,
    pub bytecode: Vec<u8>,
    pub storage: HashMap<[u8; 32], [u8; 32]>,
    pub balance: u128,
    pub rent_deposit: u128,
    pub is_token: bool,
    pub token_config: Option<TokenConfig>,
    pub created_at: u64,
    pub upgraded_at: Option<u64>,
    pub last_rent_paid_height: u64,
    pub rent_grace_blocks: u64,
    pub pending_owner: Option<AccountId>,
    pub is_immutable: bool,
    pub declared_reads: Vec<[u8; 32]>,
    pub declared_writes: Vec<[u8; 32]>,
    pub commutative_keys: Vec<[u8; 32]>,
    pub storage_key_specs: Vec<StorageKeySpec>,
    pub oracle_schema_ids: Vec<[u8; 32]>,
    pub governance_proposal: Option<GovernanceProposal>,
    pub manifest_version: u64,
    pub manifest_hash: [u8; 32],
}

/// Governance proposal for cell upgrades
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub proposal_type: ProposalType,
    pub proposer: AccountId,
    pub created_at_height: u64,
    pub timelock_blocks: u64,
    pub require_vote: bool,
    pub votes_for: u64,
    pub votes_against: u64,
    pub voters: HashSet<AccountId>,
    pub executed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalType {
    OwnershipTransfer {
        new_owner: AccountId,
    },
    Upgrade {
        new_bytecode: Vec<u8>,
        declared_reads: Vec<[u8; 32]>,
        declared_writes: Vec<[u8; 32]>,
        commutative_keys: Vec<[u8; 32]>,
        storage_key_specs: Vec<StorageKeySpec>,
        oracle_schema_ids: Vec<[u8; 32]>,
    },
    MakeImmutable,
}

impl crate::ConflictAwareCell for CellAccount {
    fn rw_set(
        &self,
        intent: &truthlinked_core::pq_execution::TransactionIntent,
    ) -> (Vec<AccountId>, Vec<AccountId>) {
        use truthlinked_core::pq_execution::TransactionIntent;

        if let TransactionIntent::CallCell { calldata, .. } = intent {
            if !self.storage_key_specs.is_empty() {
                let mut writes = Vec::new();
                for spec in &self.storage_key_specs {
                    let end = match spec.offset.checked_add(spec.len) {
                        Some(e) => e,
                        None => continue,
                    };
                    if calldata.len() >= end {
                        let slot_bytes = &calldata[spec.offset..end];
                        let key = blake3::hash(&[self.cell_id.as_ref(), slot_bytes].concat());
                        let mut conflict_key = [0u8; 32];
                        conflict_key.copy_from_slice(key.as_bytes());
                        writes.push(conflict_key);
                    }
                }
                if !writes.is_empty() {
                    return (vec![], writes);
                }
            }
        }

        if !self.declared_reads.is_empty() || !self.declared_writes.is_empty() {
            return (self.declared_reads.clone(), self.declared_writes.clone());
        }

        if !self.bytecode.is_empty() {
            if let Ok(analysis) =
                truthlinked_core::cells::CellAccount::analyze_bytecode(&self.bytecode)
            {
                let reads = if analysis.static_read_slots.is_empty() {
                    vec![self.cell_id]
                } else {
                    analysis.static_read_slots
                };
                let writes = if analysis.static_write_slots.is_empty() {
                    vec![self.cell_id]
                } else {
                    analysis.static_write_slots
                };
                return (reads, writes);
            }
        }

        (vec![self.cell_id], vec![self.cell_id])
    }
}

impl CellAccount {
    pub fn compute_manifest_hash(
        bytecode: &[u8],
        declared_reads: &[[u8; 32]],
        declared_writes: &[[u8; 32]],
        commutative_keys: &[[u8; 32]],
        oracle_schema_ids: &[[u8; 32]],
    ) -> [u8; 32] {
        truthlinked_core::cells::CellAccount::compute_manifest_hash(
            bytecode,
            declared_reads,
            declared_writes,
            commutative_keys,
            oracle_schema_ids,
        )
    }

    pub fn analyze_bytecode(bytecode: &[u8]) -> Result<ManifestAnalysis, String> {
        truthlinked_core::cells::CellAccount::analyze_bytecode(bytecode)
    }

    pub fn require_inferable(
        bytecode: &[u8],
        storage_key_specs: &[StorageKeySpec],
    ) -> Result<(), String> {
        let analysis = Self::analyze_bytecode(bytecode)?;
        if analysis.fully_resolved {
            return Ok(());
        }
        if !storage_key_specs.is_empty() {
            return Ok(());
        }
        Err(
            "Storage slots are not inferable. Provide storage_key_specs via the SDK manifest."
                .to_string(),
        )
    }

    pub fn verify_manifest_against_bytecode(
        bytecode: &[u8],
        declared_reads: &[[u8; 32]],
        declared_writes: &[[u8; 32]],
        storage_key_specs: &[StorageKeySpec],
    ) -> Result<(), String> {
        truthlinked_core::cells::CellAccount::verify_manifest_against_bytecode(
            bytecode,
            declared_reads,
            declared_writes,
            storage_key_specs,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenConfig {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u128,
    pub mint_authority: Option<AccountId>,
    pub freeze_authority: Option<AccountId>,
    pub transfer_fee_bps: u16,
    pub transfer_fee_recipient: Option<AccountId>,
    pub transfer_hook: Option<AccountId>,
    pub transfer_hook_gas: u64,
    pub max_supply: Option<u128>,
    pub non_transferable: bool,
    pub metadata_uri: Option<String>,
    pub permanent_delegate: Option<AccountId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellState {
    pub cells: HashMap<AccountId, CellAccount>,
    pub token_balances: HashMap<(AccountId, AccountId), u128>,
    pub frozen_accounts: HashMap<(AccountId, AccountId), bool>,
}

impl CellState {
    pub fn new() -> Self {
        Self {
            cells: HashMap::new(),
            token_balances: HashMap::new(),
            frozen_accounts: HashMap::new(),
        }
    }

    pub fn deploy_cell(
        &mut self,
        cell_id: AccountId,
        owner: AccountId,
        bytecode: Vec<u8>,
        initial_storage: HashMap<[u8; 32], [u8; 32]>,
        initial_balance: u128,
        timestamp: u64,
        declared_reads: Vec<[u8; 32]>,
        declared_writes: Vec<[u8; 32]>,
        commutative_keys: Vec<[u8; 32]>,
        storage_key_specs: Vec<StorageKeySpec>,
        oracle_schema_ids: Vec<[u8; 32]>,
    ) -> Result<(), String> {
        if self.cells.contains_key(&cell_id) {
            return Err("Cell already exists".to_string());
        }

        if bytecode.len() > gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE) {
            return Err(format!(
                "Bytecode too large: {} bytes (max: {})",
                bytecode.len(),
                gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE)
            ));
        }

        let storage_size: u64 = initial_storage
            .iter()
            .map(|(k, v)| k.len() as u64 + v.len() as u64)
            .sum();

        if storage_size > gp::get_u64(gp::PARAM_MAX_CELL_STORAGE_BYTES) {
            return Err(format!("Initial storage too large: {} bytes", storage_size));
        }

        CellAccount::verify_manifest_against_bytecode(
            &bytecode,
            &declared_reads,
            &declared_writes,
            &storage_key_specs,
        )?;
        CellAccount::require_inferable(&bytecode, &storage_key_specs)?;

        let manifest_hash = CellAccount::compute_manifest_hash(
            &bytecode,
            &declared_reads,
            &declared_writes,
            &commutative_keys,
            &oracle_schema_ids,
        );

        self.cells.insert(
            cell_id,
            CellAccount {
                cell_id,
                owner,
                bytecode,
                storage: initial_storage,
                balance: initial_balance,
                rent_deposit: gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE),
                is_token: false,
                token_config: None,
                created_at: timestamp,
                upgraded_at: None,
                last_rent_paid_height: 0,
                rent_grace_blocks: gp::get_u64(gp::PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS),
                pending_owner: None,
                is_immutable: false,
                declared_reads,
                declared_writes,
                commutative_keys,
                storage_key_specs,
                oracle_schema_ids,
                governance_proposal: None,
                manifest_version: 1,
                manifest_hash,
            },
        );

        Ok(())
    }

    pub fn deploy_token(
        &mut self,
        cell_id: AccountId,
        owner: AccountId,
        config: TokenConfig,
        initial_balance: u128,
        timestamp: u64,
    ) -> Result<(), String> {
        if self.cells.contains_key(&cell_id) {
            return Err("Cell already exists".to_string());
        }

        self.token_balances
            .insert((cell_id, owner), config.total_supply);

        let manifest_hash = CellAccount::compute_manifest_hash(&[], &[], &[], &[], &[]);

        self.cells.insert(
            cell_id,
            CellAccount {
                cell_id,
                owner,
                bytecode: vec![],
                storage: HashMap::new(),
                balance: initial_balance,
                rent_deposit: gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE),
                is_token: true,
                token_config: Some(config),
                created_at: timestamp,
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
            },
        );

        Ok(())
    }

    pub fn accept_ownership(
        &mut self,
        cell_id: AccountId,
        caller: AccountId,
    ) -> Result<(), String> {
        let cell = self.cells.get_mut(&cell_id).ok_or("Cell not found")?;
        if cell.pending_owner != Some(caller) {
            return Err("Not pending owner".to_string());
        }
        cell.owner = caller;
        cell.pending_owner = None;
        Ok(())
    }

    pub fn make_immutable(&mut self, cell_id: AccountId, caller: AccountId) -> Result<(), String> {
        let cell = self.cells.get_mut(&cell_id).ok_or("Cell not found")?;
        if cell.owner != caller {
            return Err("Not cell owner".to_string());
        }
        cell.is_immutable = true;
        cell.pending_owner = None;
        Ok(())
    }

    pub fn upgrade_cell(
        &mut self,
        cell_id: AccountId,
        caller: AccountId,
        new_bytecode: Vec<u8>,
        timestamp: u64,
        new_declared_reads: Vec<[u8; 32]>,
        new_declared_writes: Vec<[u8; 32]>,
        new_commutative_keys: Vec<[u8; 32]>,
        new_storage_key_specs: Vec<StorageKeySpec>,
        new_oracle_schema_ids: Vec<[u8; 32]>,
    ) -> Result<(), String> {
        let cell = self.cells.get_mut(&cell_id).ok_or("Cell not found")?;

        if cell.owner != caller {
            return Err("Not cell owner".to_string());
        }
        if cell.is_immutable {
            return Err("Cell is immutable, cannot upgrade".to_string());
        }
        if new_bytecode.len() > gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE) {
            return Err(format!(
                "Bytecode too large: {} bytes (max: {})",
                new_bytecode.len(),
                gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE)
            ));
        }

        CellAccount::verify_manifest_against_bytecode(
            &new_bytecode,
            &new_declared_reads,
            &new_declared_writes,
            &new_storage_key_specs,
        )?;
        CellAccount::require_inferable(&new_bytecode, &new_storage_key_specs)?;

        let new_manifest_hash = CellAccount::compute_manifest_hash(
            &new_bytecode,
            &new_declared_reads,
            &new_declared_writes,
            &new_commutative_keys,
            &new_oracle_schema_ids,
        );

        cell.manifest_version = cell
            .manifest_version
            .checked_add(1)
            .ok_or("Manifest version overflow")?;
        cell.bytecode = new_bytecode;
        cell.declared_reads = new_declared_reads;
        cell.declared_writes = new_declared_writes;
        cell.commutative_keys = new_commutative_keys;
        cell.storage_key_specs = new_storage_key_specs;
        cell.oracle_schema_ids = new_oracle_schema_ids;
        cell.manifest_hash = new_manifest_hash;
        cell.upgraded_at = Some(timestamp);

        Ok(())
    }
}

impl Default for CellState {
    fn default() -> Self {
        Self::new()
    }
}
