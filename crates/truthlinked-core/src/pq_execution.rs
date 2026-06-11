//! Transaction and execution intent types for TruthLinked.
//!
//! This module owns the canonical transaction wire shape. Any change to these
//! structures can affect transaction hashes, signing payloads, storage indexing,
//! and client compatibility.

use crate::cells::StorageKeySpec;
use serde::{Deserialize, Serialize};

pub type AccountId = [u8; 32];

pub fn system_authority_id() -> AccountId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"truthlinked-system-authority-v1");
    let hash = hasher.finalize();
    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&hash);
    account_id
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransferEntry {
    pub recipient: AccountId,
    /// Omit for accounts already known on-chain (saves 1,952 bytes per recipient).
    pub recipient_pubkey: Option<Vec<u8>>,
    pub amount: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameTransferEntry {
    pub name: String,
    pub amount: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellCall {
    pub cell_id: AccountId,
    pub calldata: Vec<u8>,
    pub value: u128,
    pub use_result_from: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: AccountId,
    pub intent: TransactionIntent,
    pub signature: Vec<u8>,
    #[serde(default)]
    pub nonce: u64,
    pub timestamp: u64,
    pub genesis_fingerprint: [u8; 32],
    pub expiration_height: u64,
}

impl Transaction {
    /// Serialized payload size used for byte-weighted fees and mempool limits.
    pub fn byte_weight(&self) -> Result<usize, postcard::Error> {
        postcard::to_allocvec(self).map(|bytes| bytes.len())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum TransactionIntent {
    Transfer {
        recipient: AccountId,
        /// Omit for accounts already known on-chain (saves 1,952 bytes).
        recipient_pubkey: Option<Vec<u8>>,
        amount: u128,
    },
    TransferToName {
        name: String,
        amount: u128,
    },
    BatchTransfer {
        transfers: Vec<BatchTransferEntry>,
    },
    BatchTransferToName {
        transfers: Vec<NameTransferEntry>,
    },
    Claim {
        recipient: AccountId,
        /// Omit for accounts already known on-chain (saves 1,952 bytes).
        recipient_pubkey: Option<Vec<u8>>,
        amount: u128,
    },
    RotateKey {
        new_pubkey: Vec<u8>,
    },
    DepositCompute {
        amount: u128,
    },
    WithdrawCompute {
        amount: u128,
    },
    /// Wrap TRTH into wTRTH (1:1). Deducts TRTH, mints wTRTH token balance.
    WrapTRTH {
        amount: u128,
    },
    /// Unwrap wTRTH back to TRTH (1:1). Burns wTRTH token balance, credits TRTH.
    UnwrapTRTH {
        amount: u128,
    },
    Stake {
        amount: u128,
    },
    Unstake {
        amount: u128,
    },
    WithdrawStake,
    Unjail,
    MintNFT {
        nft_id: [u8; 32],
        name: String,
        metadata_uri: String,
        collection: Option<[u8; 32]>,
        royalty_bps: u16,
        royalty_recipient: Option<AccountId>,
    },
    TransferNFT {
        nft_id: [u8; 32],
        recipient: AccountId,
        /// Omit for accounts already known on-chain (saves 1,952 bytes).
        recipient_pubkey: Option<Vec<u8>>,
        sale_price: Option<u128>,
    },
    BurnNFT {
        nft_id: [u8; 32],
    },
    ApproveNFT {
        nft_id: [u8; 32],
        approved: Option<AccountId>,
    },
    DeployCell {
        cell_id: AccountId,
        bytecode: Vec<u8>,
        initial_balance: u128,
        declared_reads: Vec<[u8; 32]>,
        declared_writes: Vec<[u8; 32]>,
        commutative_keys: Vec<[u8; 32]>,
        storage_key_specs: Vec<StorageKeySpec>,
        oracle_schema_ids: Vec<[u8; 32]>,
    },
    DeployToken {
        cell_id: AccountId,
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: u128,
        transfer_fee_bps: u16,
        transfer_fee_recipient: Option<AccountId>,
        non_transferable: bool,
    },
    CallCell {
        cell_id: AccountId,
        calldata: Vec<u8>,
        value: u128,
        gas_limit: u64,
    },
    CallCellChain {
        calls: Vec<CellCall>,
        gas_limit: u64,
    },
    UpgradeCell {
        cell_id: AccountId,
        new_bytecode: Vec<u8>,
        new_declared_reads: Vec<[u8; 32]>,
        new_declared_writes: Vec<[u8; 32]>,
        new_commutative_keys: Vec<[u8; 32]>,
        new_storage_key_specs: Vec<StorageKeySpec>,
        new_oracle_schema_ids: Vec<[u8; 32]>,
    },
    TransferOwnership {
        cell_id: AccountId,
        new_owner: AccountId,
    },
    AcceptOwnership {
        cell_id: AccountId,
    },
    MakeImmutable {
        cell_id: AccountId,
    },
    CloseCell {
        cell_id: AccountId,
    },
    ProposeCellUpgrade {
        cell_id: AccountId,
        new_bytecode: Vec<u8>,
        new_declared_reads: Vec<[u8; 32]>,
        new_declared_writes: Vec<[u8; 32]>,
        new_commutative_keys: Vec<[u8; 32]>,
        new_storage_key_specs: Vec<StorageKeySpec>,
        new_oracle_schema_ids: Vec<[u8; 32]>,
        timelock_blocks: u64,
    },
    ProposeCellOwnershipTransfer {
        cell_id: AccountId,
        new_owner: AccountId,
        timelock_blocks: u64,
    },
    ProposeCellMakeImmutable {
        cell_id: AccountId,
        timelock_blocks: u64,
    },
    VoteCellProposal {
        cell_id: AccountId,
        approve: bool,
    },
    ExecuteCellProposal {
        cell_id: AccountId,
    },
    TokenTransfer {
        token_cell: AccountId,
        recipient: AccountId,
        amount: u128,
    },
    TokenMint {
        token_cell: AccountId,
        recipient: AccountId,
        amount: u128,
    },
    TokenBurn {
        token_cell: AccountId,
        amount: u128,
    },
    TokenFreeze {
        token_cell: AccountId,
        account: AccountId,
    },
    TokenThaw {
        token_cell: AccountId,
        account: AccountId,
    },
    ProposeTokenAuthority {
        token_cell: AccountId,
        set_mint_authority: bool,
        new_mint_authority: AccountId,
        set_freeze_authority: bool,
        new_freeze_authority: AccountId,
        voting_period_blocks: u64,
    },
    VoteTokenAuthority {
        token_cell: AccountId,
        approve: bool,
    },
    CallSystem {
        controller: AccountId,
        calldata: Vec<u8>,
    },
    ProposeUrl {
        url_pattern: String,
        bond_amount: u128,
        voting_period_blocks: u64,
    },
    VoteUrl {
        url_pattern: String,
        approve: bool,
    },
    ReportMaliciousUrl {
        url_pattern: String,
        evidence: String,
    },
    SetCellVisibility {
        cell_id: AccountId,
        visibility: u8,
    },
    // MCP intents
    RegisterMcpTool {
        tool_id: AccountId,
        bytecode: Vec<u8>,
        name: String,
        input_schema_json: Vec<u8>,
        category: u8,
        declared_reads: Vec<[u8; 32]>,
        declared_writes: Vec<[u8; 32]>,
        commutative_keys: Vec<[u8; 32]>,
        oracle_schema_ids: Vec<[u8; 32]>,
        registry_id: AccountId,
    },
    RegisterMcpResource {
        resource_id: AccountId,
        bytecode: Vec<u8>,
        name: String,
        uri_scheme: String,
        mime_type: String,
        initial_data: Vec<(Vec<u8>, Vec<u8>)>,
        declared_reads: Vec<[u8; 32]>,
        declared_writes: Vec<[u8; 32]>,
        oracle_schema_ids: Vec<[u8; 32]>,
        registry_id: AccountId,
    },
    RegisterMcpPrompt {
        prompt_id: AccountId,
        name: String,
        template_bytes: Vec<u8>,
        arguments: Vec<(String, String, bool)>,
        registry_id: AccountId,
    },
    RegisterAgent {
        agent_id: AccountId,
        policy_cell_id: AccountId,
        agent_registry_id: AccountId,
    },
    SuspendAgent {
        agent_id: AccountId,
        agent_registry_id: AccountId,
        reason: String,
    },
    ReinstateAgent {
        agent_id: AccountId,
        agent_registry_id: AccountId,
    },
    McpToolCall {
        agent_id: AccountId,
        tool_id: AccountId,
        tool_calldata: Vec<u8>,
        value: u128,
        gas_limit: u64,
        policy_cell_id: AccountId,
        action_log_id: Option<AccountId>,
        timestamp: u64,
    },
    PrivateBalanceInit {
        cell_id: AccountId,
        agent_id: AccountId,
        encrypted_balance: Vec<u8>,
        commitment: [u8; 32],
        commit_nonce: [u8; 16],
    },
    PrivateBalanceDeposit {
        cell_id: AccountId,
        agent_id: AccountId,
        amount: u128,
        new_encrypted_balance: Vec<u8>,
        new_commitment: [u8; 32],
        new_commit_nonce: [u8; 16],
        old_commitment: [u8; 32],
    },
    PrivateBalanceWithdraw {
        cell_id: AccountId,
        agent_id: AccountId,
        amount: u128,
        recipient: AccountId,
        new_encrypted_balance: Vec<u8>,
        new_commitment: [u8; 32],
        new_commit_nonce: [u8; 16],
        old_commitment: [u8; 32],
    },
    PrivateBalanceConfidentialTransfer {
        sender_cell_id: AccountId,
        sender_agent_id: AccountId,
        recipient_cell_id: AccountId,
        amount_commitment: [u8; 32],
        stark_proof: Vec<u8>,
        sender_new_encrypted: Vec<u8>,
        sender_new_commitment: [u8; 32],
        sender_new_commit_nonce: [u8; 16],
        sender_old_commitment: [u8; 32],
        recipient_new_encrypted: Vec<u8>,
        recipient_new_commitment: [u8; 32],
        recipient_new_commit_nonce: [u8; 16],
        recipient_old_commitment: [u8; 32],
    },
    // Oracle commit/reveal
    SubmitOracleCommit {
        request_id: [u8; 32],
        commit_hash: [u8; 32],
    },
    SubmitOracleReveal {
        request_id: [u8; 32],
        response_body: Vec<u8>,
        response_status: u16,
    },
}

pub fn system_cell_id(label: &str) -> AccountId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

pub fn staking_system_cell_id() -> AccountId {
    system_cell_id("truthlinked-staking-v1")
}

pub fn treasury_system_cell_id() -> AccountId {
    system_cell_id("truthlinked-treasury-v1")
}

pub fn governance_system_cell_id() -> AccountId {
    system_cell_id("truthlinked-governance-v1")
}

pub fn name_registry_system_cell_id() -> AccountId {
    system_cell_id("truthlinked-name-registry-v1")
}

pub fn token_governance_system_cell_id() -> AccountId {
    system_cell_id("truthlinked-token-governance-v1")
}

pub fn oracle_governance_system_cell_id() -> AccountId {
    system_cell_id("truthlinked-oracle-governance-v1")
}

pub fn usdc_system_cell_id() -> AccountId {
    system_cell_id("truthlinked-usdc-controller-v1")
}

pub fn wtrth_system_cell_id() -> AccountId {
    system_cell_id("truthlinked-wtrth-v1")
}

pub fn usdt_system_cell_id() -> AccountId {
    system_cell_id("truthlinked-usdt-controller-v1")
}

impl Transaction {
    pub fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl TransactionIntent {
    pub fn cell_id_option(&self) -> Option<AccountId> {
        match self {
            TransactionIntent::DeployCell { cell_id, .. }
            | TransactionIntent::DeployToken { cell_id, .. }
            | TransactionIntent::CallCell { cell_id, .. }
            | TransactionIntent::UpgradeCell { cell_id, .. }
            | TransactionIntent::TransferOwnership { cell_id, .. }
            | TransactionIntent::AcceptOwnership { cell_id }
            | TransactionIntent::MakeImmutable { cell_id }
            | TransactionIntent::CloseCell { cell_id }
            | TransactionIntent::ProposeCellUpgrade { cell_id, .. }
            | TransactionIntent::ProposeCellOwnershipTransfer { cell_id, .. }
            | TransactionIntent::ProposeCellMakeImmutable { cell_id, .. }
            | TransactionIntent::VoteCellProposal { cell_id, .. }
            | TransactionIntent::ExecuteCellProposal { cell_id, .. }
            | TransactionIntent::TokenTransfer {
                token_cell: cell_id,
                ..
            }
            | TransactionIntent::TokenMint {
                token_cell: cell_id,
                ..
            }
            | TransactionIntent::TokenBurn {
                token_cell: cell_id,
                ..
            } => Some(*cell_id),
            TransactionIntent::CallCellChain { calls, .. } => calls.first().map(|c| c.cell_id),
            _ => None,
        }
    }
}
