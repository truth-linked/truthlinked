//! Runtime domain types shared across state, execution, and protocol services.
//!
//! These records represent account state, NFTs, staking deltas, oracle state, and
//! execution deltas that must serialize consistently across validator processes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use truthlinked_core::pq_execution::AccountId;
use truthlinked_governance::{
    CellVisibility, PendingNameRegistration, SchemaProposal, TokenAuthorityProposal, UrlProposal,
};
use truthlinked_oracle::http_oracle::{OracleCommit, OracleRequest, OracleResult, OracleReveal};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRecord {
    pub pubkey_bytes: Vec<u8>,
    pub balance: u128,
    #[serde(default)]
    pub compute_escrow_trth: u128,
    #[serde(default)]
    pub nonce: u64,
    pub nfts: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTRecord {
    pub nft_id: [u8; 32],
    pub owner: AccountId,
    pub name: String,
    pub metadata_uri: String,
    pub minted_at: u64,
    pub collection: Option<[u8; 32]>,
    pub royalty_bps: u16,
    pub royalty_recipient: Option<AccountId>,
    pub approved: Option<AccountId>,
}

#[derive(Debug, Clone)]
pub enum StakingUpdate {
    Stake {
        validator: Vec<u8>,
        amount: u64,
    },
    Unstake {
        validator: Vec<u8>,
        amount: u64,
    },
    Withdraw {
        validator: Vec<u8>,
    },
    Slash {
        validator: Vec<u8>,
        reason: truthlinked_staking::SlashReason,
        amount: u64,
        redistribution: Vec<(Vec<u8>, u64)>,
    },
    Unjail {
        validator: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeltaOp {
    Add(i128),
    Max(u128),
    Or(bool),
    Append(Vec<u8>),
}

impl DeltaOp {
    pub fn compose(&self, other: &DeltaOp) -> Result<DeltaOp, String> {
        match (self, other) {
            (DeltaOp::Add(a), DeltaOp::Add(b)) => Ok(DeltaOp::Add(a + b)),
            (DeltaOp::Max(a), DeltaOp::Max(b)) => Ok(DeltaOp::Max(*a.max(b))),
            (DeltaOp::Or(a), DeltaOp::Or(b)) => Ok(DeltaOp::Or(*a || *b)),
            (DeltaOp::Append(a), DeltaOp::Append(b)) => {
                let mut result = a.clone();
                result.extend_from_slice(b);
                Ok(DeltaOp::Append(result))
            }
            _ => Err("Cannot compose different delta types".to_string()),
        }
    }

    pub fn apply(&self, base: &[u8]) -> Vec<u8> {
        match self {
            DeltaOp::Add(delta) => {
                let current = if base.len() >= 16 {
                    i128::from_le_bytes(base[..16].try_into().unwrap_or([0u8; 16]))
                } else {
                    0
                };
                let new_val = current.saturating_add(*delta);
                new_val.to_le_bytes().to_vec()
            }
            DeltaOp::Max(value) => {
                let current = if base.len() >= 16 {
                    u128::from_le_bytes(base[..16].try_into().unwrap_or([0u8; 16]))
                } else {
                    0
                };
                let new_val = current.max(*value);
                new_val.to_le_bytes().to_vec()
            }
            DeltaOp::Or(value) => {
                let current = !base.is_empty() && base[0] != 0;
                let new_val = current || *value;
                vec![if new_val { 1 } else { 0 }]
            }
            DeltaOp::Append(data) => {
                let mut result = base.to_vec();
                result.extend_from_slice(data);
                result
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StorageDelta {
    pub deltas: HashMap<[u8; 32], DeltaOp>,
}

impl StorageDelta {
    pub fn add_delta(&mut self, key: [u8; 32], delta: i128) {
        let op = DeltaOp::Add(delta);
        if let Some(existing) = self.deltas.get(&key) {
            if let Ok(composed) = existing.compose(&op) {
                self.deltas.insert(key, composed);
            }
        } else {
            self.deltas.insert(key, op);
        }
    }

    pub fn set_max(&mut self, key: [u8; 32], value: u128) {
        let op = DeltaOp::Max(value);
        if let Some(existing) = self.deltas.get(&key) {
            if let Ok(composed) = existing.compose(&op) {
                self.deltas.insert(key, composed);
            }
        } else {
            self.deltas.insert(key, op);
        }
    }

    pub fn set_flag(&mut self, key: [u8; 32], value: bool) {
        let op = DeltaOp::Or(value);
        if let Some(existing) = self.deltas.get(&key) {
            if let Ok(composed) = existing.compose(&op) {
                self.deltas.insert(key, composed);
            }
        } else {
            self.deltas.insert(key, op);
        }
    }

    pub fn append_log(&mut self, key: [u8; 32], data: Vec<u8>) {
        let op = DeltaOp::Append(data);
        if let Some(existing) = self.deltas.get(&key) {
            if let Ok(composed) = existing.compose(&op) {
                self.deltas.insert(key, composed);
            }
        } else {
            self.deltas.insert(key, op);
        }
    }

    pub fn compose(&mut self, other: &StorageDelta) {
        for (key, delta) in &other.deltas {
            if let Some(existing) = self.deltas.get(key) {
                if let Ok(composed) = existing.compose(delta) {
                    self.deltas.insert(*key, composed);
                }
            } else {
                self.deltas.insert(*key, delta.clone());
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum OracleUpdate {
    QueueRequest(OracleRequest),
    AddCommit {
        request_id: [u8; 32],
        commit: OracleCommit,
    },
    AddReveal {
        request_id: [u8; 32],
        reveal: OracleReveal,
    },
    FinalizeResult(OracleResult),
    AddUrlProposal(UrlProposal),
    VoteUrlProposal {
        url_pattern: String,
        voter_pk: Vec<u8>,
        stake_for_delta: u64,
        stake_against_delta: u64,
    },
    SlashUrlProposer {
        url_pattern: String,
    },
    AddSchemaProposal(SchemaProposal),
    VoteSchemaProposal {
        schema_id: [u8; 32],
        voter_pk: Vec<u8>,
        stake_for_delta: u64,
        stake_against_delta: u64,
    },
    SetVisibility {
        cell_id: AccountId,
        visibility: CellVisibility,
    },
}

#[derive(Debug, Clone)]
pub enum CellUpdate {
    Deploy {
        cell_id: AccountId,
        cell: crate::cells::CellAccount,
    },
    StorageChange {
        cell_id: AccountId,
        storage_diff: HashMap<[u8; 32], Option<[u8; 32]>>,
    },
    BalanceChange {
        cell_id: AccountId,
        new_balance: u128,
    },
    Remove {
        cell_id: AccountId,
    },
    Upgrade {
        cell_id: AccountId,
        new_bytecode: Vec<u8>,
        new_declared_reads: Vec<[u8; 32]>,
        new_declared_writes: Vec<[u8; 32]>,
        new_commutative_keys: Vec<[u8; 32]>,
        new_storage_key_specs: Vec<truthlinked_core::cells::StorageKeySpec>,
        new_oracle_schema_ids: Vec<[u8; 32]>,
        timestamp: u64,
    },
    TransferOwnership {
        cell_id: AccountId,
        new_owner: AccountId,
    },
    AcceptOwnership {
        cell_id: AccountId,
        caller: AccountId,
    },
    MakeImmutable {
        cell_id: AccountId,
        caller: AccountId,
    },
}

#[derive(Debug, Clone, Default)]
pub struct StateDiff {
    pub account_updates: HashMap<AccountId, AccountRecord>,
    pub staking_updates: Vec<StakingUpdate>,
    pub nft_updates: HashMap<[u8; 32], Option<NFTRecord>>,
    pub cell_updates: Vec<CellUpdate>,
    pub gas_fee: u128,
    pub name_fee: u128,
    pub cu_fee: u128,
    pub treasury_fee: u128,
    pub compute_fee_trth: u128,
    pub tx_hash: [u8; 32],
    pub tx_hashes: std::collections::HashSet<[u8; 32]>,
    pub pending_name_proposals: Vec<(String, PendingNameRegistration, AccountId, bool)>,
    pub name_votes: Vec<(String, Vec<u8>, u64)>,
    pub pending_token_authority_proposals: Vec<(AccountId, TokenAuthorityProposal)>,
    pub token_authority_votes: Vec<(AccountId, Vec<u8>, u64)>,
    pub name_renewals: Vec<(String, u64)>,
    pub name_transfers: Vec<(String, AccountId)>,
    pub native_transfers: Vec<(AccountId, u128)>,
    pub native_debits: Vec<(AccountId, u128)>,
    pub compute_escrow_credits: Vec<(AccountId, u128)>,
    pub compute_escrow_debits: Vec<(AccountId, u128)>,
    pub token_credits: Vec<(AccountId, AccountId, u128)>,
    pub token_balance_updates: Vec<((AccountId, AccountId), u128)>,
    pub staking_rewards: Vec<(AccountId, u128)>,
    pub cell_credits: Vec<(AccountId, u128)>,
    pub cell_debits: Vec<(AccountId, u128)>,
    pub storage_deltas: HashMap<AccountId, StorageDelta>,
    pub airdrop_claims: Vec<(AccountId, u64)>,
    pub minted_amount: u128,
    pub frozen_account_updates: Vec<((AccountId, AccountId), bool)>,
    pub oracle_updates: Vec<OracleUpdate>,
    pub param_updates: Vec<([u8; 32], [u8; 32])>,
    pub nonce_updates: Vec<(AccountId, u64)>,
    pub gas_fee_spent: u128,
    pub name_fee_spent: u128,
    pub compute_fee_spent: u128,
    pub treasury_fee_spent: u128,
    /// Fee revenue permanently removed during a system distribution.
    ///
    /// This is an audit field: balances are not credited here. The amount is
    /// represented by spent fee accumulators that are intentionally not paid to
    /// validators or Staked TRTH holders.
    pub fee_burned: u128,
    pub is_system: bool,
    pub gas_breakdown: Vec<(String, u128)>,
}
