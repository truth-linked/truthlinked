//! Governance domain types shared across protocol boundaries.
//!
//! These records describe proposals, registrations, visibility policy, schema
//! approvals, and authority transitions that must remain serializable and stable
//! across node, runtime, and explorer components.

use serde::{Deserialize, Serialize};
use truthlinked_core::pq_execution::AccountId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingNameRegistration {
    pub name: String,
    pub cell_id: AccountId,
    pub owner: AccountId,
    pub is_cell: bool,
    pub proposer: Vec<u8>,
    pub votes: std::collections::HashSet<Vec<u8>>,
    pub total_stake_voted: u64,
    pub proposed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAuthorityProposal {
    pub token_cell: AccountId,
    pub proposer: Vec<u8>,
    pub voters: std::collections::HashSet<Vec<u8>>,
    pub votes_for_stake: u64,
    pub created_at: u64,
    pub voting_ends_at: u64,
    pub set_mint_authority: bool,
    pub new_mint_authority: Option<AccountId>,
    pub set_freeze_authority: bool,
    pub new_freeze_authority: Option<AccountId>,
}

impl TokenAuthorityProposal {
    pub fn voting_open(&self, current_height: u64) -> bool {
        current_height <= self.voting_ends_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameRegistration {
    pub name: String,
    pub owner: AccountId,
    pub target: AccountId,
    pub registered_at: u64,
    pub expires_at: u64,
    pub is_cell: bool,
}

/// URL approval proposal for public cells. Lives in State::url_proposals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlResponseFormat {
    Raw,
    JsonCanonical,
    PriceUsd,
}

impl Default for UrlResponseFormat {
    fn default() -> Self {
        Self::Raw
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlProposal {
    pub url_pattern: String,
    pub proposer: [u8; 32],
    pub bond_amount: u128,
    #[serde(default)]
    pub voters: std::collections::HashSet<Vec<u8>>,
    pub votes_for_stake: u64,
    pub votes_against_stake: u64,
    pub created_at: u64,
    pub voting_ends_at: u64,
    pub approved: bool,
    pub rejected: bool,
    pub slashed: bool,
    #[serde(default)]
    pub response_format: UrlResponseFormat,
    #[serde(default)]
    pub schema_id: Option<[u8; 32]>,
}

impl UrlProposal {
    pub fn voting_open(&self, current_height: u64) -> bool {
        !self.approved && !self.rejected && current_height <= self.voting_ends_at
    }
}

/// Cell visibility - controls HTTP request access tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellVisibility {
    Private,
    Public,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaProposal {
    pub schema_id: [u8; 32],
    pub keys: Vec<String>,
    pub proposer: [u8; 32],
    pub voters: std::collections::HashSet<Vec<u8>>,
    pub votes_for_stake: u64,
    pub votes_against_stake: u64,
    pub created_at: u64,
    pub voting_ends_at: u64,
    pub approved: bool,
    pub rejected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaEntry {
    pub schema_id: [u8; 32],
    pub keys: Vec<String>,
    pub created_at: u64,
    pub approved: bool,
}
