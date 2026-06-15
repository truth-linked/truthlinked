//! Agent Private Balance v2 - Full Confidential System
//!
//! ## Privacy model
//!
//! On-chain storage per agent cell:
//!   COMMITMENT   = blake3(balance_le16 || nonce_le16 || blake3(ciphertext)[..16])
//!                  - binds balance, nonce, AND ciphertext together
//!   CIPHER_LO/HI = AES-256-GCM(balance, owner_aes_key, random_nonce)
//!   TOTAL_DEPOSITED, TOTAL_WITHDRAWN, TOTAL_FEES - monotonic u128 counters
//!   STAKE_VERIFIED - u8 flag set at init, re-checked every circuit
//!
//! Deposit:  public TLKD → private balance. Amount revealed (it's a public tx).
//!           Balance before/after hidden. Commitment + ciphertext updated.
//!
//! Withdraw: private balance → public TLKD. Amount revealed.
//!           Balance before/after hidden.
//!
//! Confidential Transfer: amount AND balances hidden.
//!           A Winterfell STARK proof is submitted with the tx.
//!           The proof attests: old_balance - amount = new_balance,
//!           all three in [0, MAX_PRIVATE_BALANCE], using a public
//!           Pedersen-style commitment to amount (so verifier checks
//!           the commitment without learning the value).
//!
//! ## Staking gate
//!
//! Owner must have ≥ PRIVATE_BALANCE_MIN_STAKE TLKD staked at init time.
//! The stake requirement is re-checked on every circuit call.
//! If the owner unstakes below the threshold, all circuits revert.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use truthlinked_core::pq_execution::AccountId;
use truthlinked_governance::params as gp;
use truthlinked_runtime::types::{CellUpdate, StateDiff};
use truthlinked_staking::StakingState;

use crate::McpStateView;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 100,000 TLKD in base units (ONE_TLKD = 1_000_000_000)
pub const PRIVATE_BALANCE_MIN_STAKE: u64 = 100_000 * 1_000_000_000u64;

pub const MAX_PRIVATE_BALANCE: u128 = (1u128 << 96) - 1;
pub const MAX_TRANSFER_AMOUNT: u128 = (1u128 << 64) - 1;
pub const MAX_FEE_AMOUNT: u128 = (1u128 << 32) - 1;

const AES_NONCE_LEN: usize = 12;
/// nonce(12) + ct(16) + tag(16) = 44 bytes
pub const CIPHERTEXT_LEN: usize = 44;

// ---------------------------------------------------------------------------
// Extended McpStateView - adds staking access
// ---------------------------------------------------------------------------

/// Extended view trait that includes staking state.
/// Implement this alongside McpStateView for private balance circuits.
pub trait PrivateBalanceStateView: McpStateView {
    fn staking(&self) -> &StakingState;
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

pub mod pb_keys {
    use crate::registry_keys::blake3_key;

    /// Commitment: blake3(balance_le16 || nonce_le16 || ct_hash_lo16)
    pub const COMMITMENT: [u8; 32] = key(b"pb:c");
    /// AES-GCM ciphertext bytes 0..32
    pub const CIPHER_LO: [u8; 32] = key(b"pb:l");
    /// AES-GCM ciphertext bytes 32..44 (12 bytes used)
    pub const CIPHER_HI: [u8; 32] = key(b"pb:h");
    /// Commitment nonce (u128 LE in slot[0..16])
    pub const COMMIT_NONCE: [u8; 32] = key(b"pb:n");
    /// Owner AccountId
    pub const OWNER: [u8; 32] = key(b"pb:o");
    /// Agent AccountId
    pub const AGENT: [u8; 32] = key(b"pb:a");
    /// Locked flag: 1 = initialized
    pub const LOCKED: [u8; 32] = key(b"pb:L");
    /// Stake verified flag: 1 = stake was sufficient at init
    pub const STAKE_VERIFIED: [u8; 32] = key(b"pb:sv");
    /// Total deposited (u128 LE, monotonic)
    pub const TOTAL_DEPOSITED: [u8; 32] = key(b"pb:td");
    /// Total withdrawn (u128 LE, monotonic)
    pub const TOTAL_WITHDRAWN: [u8; 32] = key(b"pb:tw");
    /// Total fees deducted (u128 LE, monotonic)
    pub const TOTAL_FEES: [u8; 32] = key(b"pb:tf");
    /// Total confidential transfers out (u128 LE, monotonic)
    pub const TOTAL_CT_OUT: [u8; 32] = key(b"pb:to");

    /// Canonical cell address for an agent
    pub fn cell_for_agent(agent_id: &[u8; 32]) -> [u8; 32] {
        blake3_key(b"pb:cell:", agent_id)
    }

    const fn key(tag: &[u8]) -> [u8; 32] {
        let mut k = [0u8; 32];
        let mut i = 0;
        while i < tag.len() && i < 32 {
            k[i] = tag[i];
            i += 1;
        }
        k
    }
}

// ---------------------------------------------------------------------------
// Commitment (now binds ciphertext too)
// ---------------------------------------------------------------------------

/// Commitment = Rescue(balance || nonce || ct_hash_lo16), serialized as 32 bytes.
///
/// Private-balance state commitments intentionally use the same Rescue-Prime
/// digest format as the confidential-transfer STARK. That keeps init, deposit,
/// withdraw, and confidential transfer on one commitment scheme and avoids a
/// proof path that can never match cells created by the normal CLI flow.
pub fn compute_commitment(balance: u128, nonce: u128, ciphertext: &[u8]) -> [u8; 32] {
    let ct_hash = blake3::hash(ciphertext);
    let mut ct_hash_lo16 = [0u8; 16];
    ct_hash_lo16.copy_from_slice(&ct_hash.as_bytes()[..16]);
    let digest = crate::zk_transfer::rescue_commit(balance, nonce, &ct_hash_lo16);
    crate::zk_transfer::digest_to_bytes(&digest)
}

pub fn verify_commitment(
    commitment: &[u8; 32],
    balance: u128,
    nonce: u128,
    ciphertext: &[u8],
) -> Result<(), String> {
    let expected = compute_commitment(balance, nonce, ciphertext);
    if expected != *commitment {
        return Err("Commitment mismatch: balance, nonce, or ciphertext does not match".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encryption helpers
// ---------------------------------------------------------------------------

pub fn derive_aes_key(seed: &[u8]) -> [u8; 32] {
    blake3::derive_key("truthlinked:private_balance:aes256gcm:v2", seed)
}

pub fn encrypt_balance(
    balance: u128,
    aes_key: &[u8; 32],
    enc_nonce: &[u8; AES_NONCE_LEN],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key));
    let ct = cipher
        .encrypt(Nonce::from_slice(enc_nonce), balance.to_le_bytes().as_ref())
        .map_err(|e| format!("Encryption failed: {e}"))?;
    let mut out = Vec::with_capacity(CIPHERTEXT_LEN);
    out.extend_from_slice(enc_nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_balance(ciphertext: &[u8], aes_key: &[u8; 32]) -> Result<u128, String> {
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(format!(
            "Ciphertext must be {CIPHERTEXT_LEN} bytes, got {}",
            ciphertext.len()
        ));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[..AES_NONCE_LEN]),
            &ciphertext[AES_NONCE_LEN..],
        )
        .map_err(|_| "Decryption failed: wrong key or corrupted ciphertext".to_string())?;
    if pt.len() != 16 {
        return Err("Decrypted plaintext wrong length".into());
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&pt);
    Ok(u128::from_le_bytes(buf))
}

pub fn read_and_decrypt_balance(
    cell: &truthlinked_runtime::cells::CellAccount,
    aes_key: &[u8; 32],
) -> Result<u128, String> {
    let lo = cell
        .storage
        .get(&pb_keys::CIPHER_LO)
        .copied()
        .unwrap_or([0u8; 32]);
    let hi = cell
        .storage
        .get(&pb_keys::CIPHER_HI)
        .copied()
        .unwrap_or([0u8; 32]);
    let mut ct = Vec::with_capacity(CIPHERTEXT_LEN);
    ct.extend_from_slice(&lo);
    ct.extend_from_slice(&hi[..12]);
    decrypt_balance(&ct, aes_key)
}

// ---------------------------------------------------------------------------
// Storage packing
// ---------------------------------------------------------------------------

fn pack_ciphertext(ct: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    if ct.len() != CIPHERTEXT_LEN {
        return Err(format!(
            "Ciphertext must be {CIPHERTEXT_LEN} bytes, got {}",
            ct.len()
        ));
    }
    let mut lo = [0u8; 32];
    let mut hi = [0u8; 32];
    lo.copy_from_slice(&ct[..32]);
    hi[..12].copy_from_slice(&ct[32..44]);
    Ok((lo, hi))
}

fn read_commit_nonce(cell: &truthlinked_runtime::cells::CellAccount) -> u128 {
    let s = cell
        .storage
        .get(&pb_keys::COMMIT_NONCE)
        .copied()
        .unwrap_or([0u8; 32]);
    let mut b = [0u8; 16];
    b.copy_from_slice(&s[..16]);
    u128::from_le_bytes(b)
}

fn read_u128_slot(cell: &truthlinked_runtime::cells::CellAccount, key: &[u8; 32]) -> u128 {
    let s = cell.storage.get(key).copied().unwrap_or([0u8; 32]);
    let mut b = [0u8; 16];
    b.copy_from_slice(&s[..16]);
    u128::from_le_bytes(b)
}

fn pack_u128(v: u128) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..16].copy_from_slice(&v.to_le_bytes());
    s
}

fn pack_nonce(n: &[u8; 16]) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..16].copy_from_slice(n);
    s
}

// ---------------------------------------------------------------------------
// Range checks
// ---------------------------------------------------------------------------

fn check_balance(v: u128, label: &str) -> Result<(), String> {
    if v > MAX_PRIVATE_BALANCE {
        return Err(format!("{label} ({v}) exceeds MAX_PRIVATE_BALANCE"));
    }
    Ok(())
}

fn check_amount(v: u128, label: &str) -> Result<(), String> {
    if v == 0 {
        return Err(format!("{label} must be > 0"));
    }
    if v > MAX_TRANSFER_AMOUNT {
        return Err(format!("{label} ({v}) exceeds MAX_TRANSFER_AMOUNT"));
    }
    Ok(())
}

fn check_fee(v: u128) -> Result<(), String> {
    if v == 0 {
        return Err("Fee must be > 0".into());
    }
    if v > MAX_FEE_AMOUNT {
        return Err(format!("Fee ({v}) exceeds MAX_FEE_AMOUNT"));
    }
    Ok(())
}

fn check_nonce(n: &[u8; 16]) -> Result<(), String> {
    if n == &[0u8; 16] {
        return Err("Commit nonce must be non-zero".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Staking gate
// ---------------------------------------------------------------------------

/// Check that the owner has >= PRIVATE_BALANCE_MIN_STAKE staked.
/// Called at the top of every circuit.
fn check_stake_gate(staking: &StakingState, owner_pubkey_bytes: &[u8]) -> Result<(), String> {
    let stake = staking
        .validators
        .get(owner_pubkey_bytes)
        .map(|v| v.active_stake)
        .unwrap_or(0);
    if stake < PRIVATE_BALANCE_MIN_STAKE {
        return Err(format!(
            "Insufficient stake: owner has {} staked, minimum required is {} (100,000 TLKD)",
            stake, PRIVATE_BALANCE_MIN_STAKE
        ));
    }
    Ok(())
}

/// Resolve owner pubkey bytes from AccountRecord for stake lookup.
fn owner_pubkey<'a>(state: &'a impl McpStateView, owner: &AccountId) -> Result<Vec<u8>, String> {
    let acc = state
        .accounts()
        .get(owner)
        .ok_or("Owner account not found")?;
    if acc.pubkey_bytes.is_empty() {
        return Err("Owner account has no registered pubkey".into());
    }
    Ok(acc.pubkey_bytes.clone())
}

// ---------------------------------------------------------------------------
// Common cell guards (used by all circuits after init)
// ---------------------------------------------------------------------------

struct CellGuard<'a> {
    cell: &'a truthlinked_runtime::cells::CellAccount,
    stored_owner: AccountId,
    _stored_agent: AccountId,
    _on_chain_commitment: [u8; 32],
    old_nonce: u128,
}

fn load_and_guard<'a>(
    state: &'a impl McpStateView,
    cell_id: &AccountId,
    agent_id: &AccountId,
    sender: &AccountId,
    old_commitment: &[u8; 32],
) -> Result<CellGuard<'a>, String> {
    let cell = state
        .cells()
        .cells
        .get(cell_id)
        .ok_or_else(|| format!("Private balance cell {} not found", hex::encode(cell_id)))?;

    if cell
        .storage
        .get(&pb_keys::LOCKED)
        .map(|b| b[0])
        .unwrap_or(0)
        != 1
    {
        return Err("Cell not initialized".into());
    }

    let stored_owner = cell
        .storage
        .get(&pb_keys::OWNER)
        .copied()
        .unwrap_or([0u8; 32]);
    let stored_agent = cell
        .storage
        .get(&pb_keys::AGENT)
        .copied()
        .unwrap_or([0u8; 32]);

    if sender != &stored_owner && sender != &stored_agent {
        return Err("Unauthorized: sender is neither owner nor agent".into());
    }
    if agent_id != &stored_agent {
        return Err("agent_id does not match cell's registered agent".into());
    }

    let on_chain_commitment = cell
        .storage
        .get(&pb_keys::COMMITMENT)
        .copied()
        .unwrap_or([0u8; 32]);
    if old_commitment != &on_chain_commitment {
        return Err("old_commitment mismatch: stale or replayed transaction".into());
    }

    let old_nonce = read_commit_nonce(cell);

    Ok(CellGuard {
        cell,
        stored_owner,
        _stored_agent: stored_agent,
        _on_chain_commitment: on_chain_commitment,
        old_nonce,
    })
}

fn check_new_nonce(new_nonce_bytes: &[u8; 16], old_nonce: u128) -> Result<u128, String> {
    check_nonce(new_nonce_bytes)?;
    let mut b = [0u8; 16];
    b.copy_from_slice(new_nonce_bytes);
    let new_nonce = u128::from_le_bytes(b);
    if new_nonce == old_nonce {
        return Err("new_commit_nonce must differ from current nonce".into());
    }
    Ok(new_nonce)
}

// ---------------------------------------------------------------------------
// Intent enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivateBalanceIntent {
    /// Owner deploys private balance cell. Requires 100k TLKD staked.
    InitPrivateBalance {
        cell_id: AccountId,
        agent_id: AccountId,
        encrypted_balance: Vec<u8>,
        commitment: [u8; 32],
        commit_nonce: [u8; 16],
    },

    /// Deposit public TLKD into private balance.
    /// Amount is revealed (it's a public debit). Balance before/after hidden.
    Deposit {
        cell_id: AccountId,
        agent_id: AccountId,
        amount: u128,
        new_encrypted_balance: Vec<u8>,
        new_commitment: [u8; 32],
        new_commit_nonce: [u8; 16],
        old_commitment: [u8; 32],
    },

    /// Withdraw from private balance to public on-chain balance.
    /// Amount is revealed. Balance before/after hidden.
    Withdraw {
        cell_id: AccountId,
        agent_id: AccountId,
        amount: u128,
        recipient: AccountId,
        new_encrypted_balance: Vec<u8>,
        new_commitment: [u8; 32],
        new_commit_nonce: [u8; 16],
        old_commitment: [u8; 32],
    },

    /// Confidential transfer: amount and private balances stay hidden.
    ///
    /// The submitted STARK proof binds sender, recipient, and amount commitments
    /// while proving the private balance conservation equations inside the AIR.
    /// The recipient receives a new encrypted balance and commitment without
    /// revealing the transferred amount on-chain.
    ConfidentialTransfer {
        sender_cell_id: AccountId,
        sender_agent_id: AccountId,
        recipient_cell_id: AccountId,
        /// Commitment to the transfer amount (hides the amount)
        amount_commitment: [u8; 32],
        /// Winterfell STARK proof bytes
        stark_proof: Vec<u8>,
        /// Sender's new encrypted balance
        sender_new_encrypted: Vec<u8>,
        sender_new_commitment: [u8; 32],
        sender_new_commit_nonce: [u8; 16],
        sender_old_commitment: [u8; 32],
        /// Recipient's new encrypted balance
        recipient_new_encrypted: Vec<u8>,
        recipient_new_commitment: [u8; 32],
        recipient_new_commit_nonce: [u8; 16],
        recipient_old_commitment: [u8; 32],
    },

    /// Fee deduction by fee authority only.
    FeeDeduct {
        cell_id: AccountId,
        agent_id: AccountId,
        fee_amount: u128,
        fee_recipient: AccountId,
        new_encrypted_balance: Vec<u8>,
        new_commitment: [u8; 32],
        new_commit_nonce: [u8; 16],
        old_commitment: [u8; 32],
    },
}

// ---------------------------------------------------------------------------
// ZK circuits moved to zk_transfer module
use crate::zk_transfer::{bytes_to_digest, verify_ct_proof, CtPublicInputs};

// ---------------------------------------------------------------------------
// Circuit 1: InitPrivateBalance
// ---------------------------------------------------------------------------

pub fn circuit_init_private_balance(
    state: &impl PrivateBalanceStateView,
    sender: AccountId,
    intent: &PrivateBalanceIntent,
    timestamp: u64,
) -> Result<StateDiff, String> {
    let (cell_id, agent_id, encrypted_balance, commitment, commit_nonce) = match intent {
        PrivateBalanceIntent::InitPrivateBalance {
            cell_id,
            agent_id,
            encrypted_balance,
            commitment,
            commit_nonce,
        } => (
            cell_id,
            agent_id,
            encrypted_balance,
            commitment,
            commit_nonce,
        ),
        _ => return Err("Wrong intent".into()),
    };

    // --- Staking gate ---
    let pubkey = owner_pubkey(state, &sender)?;
    check_stake_gate(state.staking(), &pubkey)?;

    // --- Guards ---
    if sender == *agent_id {
        return Err("Owner and agent must be different accounts".into());
    }
    if state.cells().cells.contains_key(cell_id) {
        return Err(format!("Cell {} already exists", hex::encode(cell_id)));
    }
    let expected = pb_keys::cell_for_agent(agent_id);
    if *cell_id != expected {
        return Err(format!(
            "cell_id mismatch: expected {}",
            hex::encode(expected)
        ));
    }
    if commitment == &[0u8; 32] {
        return Err("Commitment must be non-zero".into());
    }
    check_nonce(commit_nonce)?;
    if encrypted_balance.len() != CIPHERTEXT_LEN {
        return Err(format!("encrypted_balance must be {CIPHERTEXT_LEN} bytes"));
    }

    let rent = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
    let sender_acc = state.accounts().get(&sender).ok_or("Sender not found")?;
    if sender_acc.balance < rent {
        return Err("Insufficient balance for rent".into());
    }

    let (cipher_lo, cipher_hi) = pack_ciphertext(encrypted_balance)?;

    let mut storage: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    storage.insert(pb_keys::COMMITMENT, *commitment);
    storage.insert(pb_keys::CIPHER_LO, cipher_lo);
    storage.insert(pb_keys::CIPHER_HI, cipher_hi);
    storage.insert(pb_keys::COMMIT_NONCE, pack_nonce(commit_nonce));
    storage.insert(pb_keys::OWNER, sender);
    storage.insert(pb_keys::AGENT, *agent_id);
    storage.insert(pb_keys::TOTAL_DEPOSITED, [0u8; 32]);
    storage.insert(pb_keys::TOTAL_WITHDRAWN, [0u8; 32]);
    storage.insert(pb_keys::TOTAL_FEES, [0u8; 32]);
    storage.insert(pb_keys::TOTAL_CT_OUT, [0u8; 32]);
    let mut locked = [0u8; 32];
    locked[0] = 1;
    storage.insert(pb_keys::LOCKED, locked);
    let mut sv = [0u8; 32];
    sv[0] = 1;
    storage.insert(pb_keys::STAKE_VERIFIED, sv);

    let manifest_hash =
        truthlinked_runtime::cells::CellAccount::compute_manifest_hash(&[], &[], &[], &[], &[]);

    let cell = truthlinked_runtime::cells::CellAccount {
        cell_id: *cell_id,
        owner: truthlinked_core::pq_execution::system_authority_id(),
        bytecode: vec![],
        storage,
        balance: 0,
        rent_deposit: rent,
        is_token: false,
        token_config: None,
        created_at: timestamp,
        upgraded_at: None,
        last_rent_paid_height: 0,
        rent_grace_blocks: gp::get_u64(gp::PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS),
        pending_owner: None,
        is_immutable: false,
        declared_reads: vec![
            pb_keys::COMMITMENT,
            pb_keys::COMMIT_NONCE,
            pb_keys::OWNER,
            pb_keys::AGENT,
            pb_keys::LOCKED,
            pb_keys::STAKE_VERIFIED,
        ],
        declared_writes: vec![
            pb_keys::COMMITMENT,
            pb_keys::CIPHER_LO,
            pb_keys::CIPHER_HI,
            pb_keys::COMMIT_NONCE,
            pb_keys::TOTAL_DEPOSITED,
            pb_keys::TOTAL_WITHDRAWN,
            pb_keys::TOTAL_FEES,
            pb_keys::TOTAL_CT_OUT,
        ],
        commutative_keys: vec![],
        storage_key_specs: vec![],
        oracle_schema_ids: vec![],
        governance_proposal: None,
        manifest_version: 2,
        manifest_hash,
    };

    let mut diff = StateDiff::default();
    let mut sa = sender_acc.clone();
    sa.balance = sa
        .balance
        .checked_sub(rent)
        .ok_or("Balance underflow on rent")?;
    diff.account_updates.insert(sender, sa);
    diff.native_debits.push((sender, rent));
    diff.cell_updates.push(CellUpdate::Deploy {
        cell_id: *cell_id,
        cell,
    });
    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL) as u128;
    Ok(diff)
}

// ---------------------------------------------------------------------------
// Circuit 2: Deposit
// ---------------------------------------------------------------------------

pub fn circuit_deposit(
    state: &impl PrivateBalanceStateView,
    sender: AccountId,
    intent: &PrivateBalanceIntent,
    _ts: u64,
) -> Result<StateDiff, String> {
    let (cell_id, agent_id, amount, new_enc, new_comm, new_nonce, old_comm) = match intent {
        PrivateBalanceIntent::Deposit {
            cell_id,
            agent_id,
            amount,
            new_encrypted_balance,
            new_commitment,
            new_commit_nonce,
            old_commitment,
        } => (
            cell_id,
            agent_id,
            *amount,
            new_encrypted_balance,
            new_commitment,
            new_commit_nonce,
            old_commitment,
        ),
        _ => return Err("Wrong intent".into()),
    };

    let g = load_and_guard(state, cell_id, agent_id, &sender, old_comm)?;

    // The owner stakes for the private balance cell; the authorized agent may submit withdrawals.
    let pubkey = owner_pubkey(state, &g.stored_owner)?;
    check_stake_gate(state.staking(), &pubkey)?;

    // Only owner can deposit (it's a public debit from their account)
    if sender != g.stored_owner {
        return Err("Only the owner can deposit into a private balance cell".into());
    }

    check_amount(amount, "deposit amount")?;

    let sender_acc = state.accounts().get(&sender).ok_or("Sender not found")?;
    if sender_acc.balance < amount {
        return Err("Insufficient on-chain balance for deposit".into());
    }

    check_new_nonce(new_nonce, g.old_nonce)?;
    if new_comm == &[0u8; 32] {
        return Err("new_commitment must be non-zero".into());
    }
    if new_enc.len() != CIPHERTEXT_LEN {
        return Err(format!(
            "new_encrypted_balance must be {CIPHERTEXT_LEN} bytes"
        ));
    }

    let old_deposited = read_u128_slot(g.cell, &pb_keys::TOTAL_DEPOSITED);
    let new_deposited = old_deposited
        .checked_add(amount)
        .ok_or("TOTAL_DEPOSITED overflow")?;
    check_balance(new_deposited, "total_deposited")?;

    let (cipher_lo, cipher_hi) = pack_ciphertext(new_enc)?;

    let mut diff = StateDiff::default();

    // Debit sender's on-chain balance
    let mut sa = sender_acc.clone();
    sa.balance = sa
        .balance
        .checked_sub(amount)
        .ok_or("Sender balance underflow")?;
    diff.account_updates.insert(sender, sa);
    diff.native_debits.push((sender, amount));

    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *cell_id,
        storage_diff: {
            let mut m = HashMap::new();
            m.insert(pb_keys::COMMITMENT, Some(*new_comm));
            m.insert(pb_keys::CIPHER_LO, Some(cipher_lo));
            m.insert(pb_keys::CIPHER_HI, Some(cipher_hi));
            m.insert(pb_keys::COMMIT_NONCE, Some(pack_nonce(new_nonce)));
            m.insert(pb_keys::TOTAL_DEPOSITED, Some(pack_u128(new_deposited)));
            m
        },
    });

    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
    Ok(diff)
}

// ---------------------------------------------------------------------------
// Circuit 3: Withdraw
// ---------------------------------------------------------------------------

pub fn circuit_withdraw(
    state: &impl PrivateBalanceStateView,
    sender: AccountId,
    intent: &PrivateBalanceIntent,
    _ts: u64,
) -> Result<StateDiff, String> {
    let (cell_id, agent_id, amount, recipient, new_enc, new_comm, new_nonce, old_comm) =
        match intent {
            PrivateBalanceIntent::Withdraw {
                cell_id,
                agent_id,
                amount,
                recipient,
                new_encrypted_balance,
                new_commitment,
                new_commit_nonce,
                old_commitment,
            } => (
                cell_id,
                agent_id,
                *amount,
                recipient,
                new_encrypted_balance,
                new_commitment,
                new_commit_nonce,
                old_commitment,
            ),
            _ => return Err("Wrong intent".into()),
        };

    let g = load_and_guard(state, cell_id, agent_id, &sender, old_comm)?;

    // The owner stakes for the private balance cell; the authorized agent may submit withdrawals.
    let pubkey = owner_pubkey(state, &g.stored_owner)?;
    check_stake_gate(state.staking(), &pubkey)?;

    check_amount(amount, "withdrawal amount")?;
    check_new_nonce(new_nonce, g.old_nonce)?;
    if new_comm == &[0u8; 32] {
        return Err("new_commitment must be non-zero".into());
    }
    if new_enc.len() != CIPHERTEXT_LEN {
        return Err(format!(
            "new_encrypted_balance must be {CIPHERTEXT_LEN} bytes"
        ));
    }

    let recipient_acc = state
        .accounts()
        .get(recipient)
        .ok_or("Recipient not found")?;
    let new_recipient_balance = recipient_acc
        .balance
        .checked_add(amount)
        .ok_or("Recipient balance overflow")?;
    check_balance(new_recipient_balance, "recipient new balance")?;

    let old_withdrawn = read_u128_slot(g.cell, &pb_keys::TOTAL_WITHDRAWN);
    let new_withdrawn = old_withdrawn
        .checked_add(amount)
        .ok_or("TOTAL_WITHDRAWN overflow")?;
    check_balance(new_withdrawn, "total_withdrawn")?;

    let (cipher_lo, cipher_hi) = pack_ciphertext(new_enc)?;

    let mut diff = StateDiff::default();

    // Credit recipient on-chain
    let mut ra = recipient_acc.clone();
    ra.balance = new_recipient_balance;
    diff.account_updates.insert(*recipient, ra);
    diff.native_transfers.push((*recipient, amount));

    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *cell_id,
        storage_diff: {
            let mut m = HashMap::new();
            m.insert(pb_keys::COMMITMENT, Some(*new_comm));
            m.insert(pb_keys::CIPHER_LO, Some(cipher_lo));
            m.insert(pb_keys::CIPHER_HI, Some(cipher_hi));
            m.insert(pb_keys::COMMIT_NONCE, Some(pack_nonce(new_nonce)));
            m.insert(pb_keys::TOTAL_WITHDRAWN, Some(pack_u128(new_withdrawn)));
            m
        },
    });

    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
    Ok(diff)
}

// ---------------------------------------------------------------------------
// Circuit 4: ConfidentialTransfer (ZK)
// ---------------------------------------------------------------------------

pub fn circuit_confidential_transfer(
    state: &impl PrivateBalanceStateView,
    sender: AccountId,
    intent: &PrivateBalanceIntent,
    _ts: u64,
) -> Result<StateDiff, String> {
    let (
        sender_cell_id,
        sender_agent_id,
        recipient_cell_id,
        amount_commitment,
        stark_proof,
        s_new_enc,
        s_new_comm,
        s_new_nonce,
        s_old_comm,
        r_new_enc,
        r_new_comm,
        r_new_nonce,
        r_old_comm,
    ) = match intent {
        PrivateBalanceIntent::ConfidentialTransfer {
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
        } => (
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
        ),
        _ => return Err("Wrong intent".into()),
    };

    // --- Load and guard sender cell ---
    let sg = load_and_guard(state, sender_cell_id, sender_agent_id, &sender, s_old_comm)?;

    // The owner stakes for the private balance cell; the authorized agent may relay the transfer.
    let pubkey = owner_pubkey(state, &sg.stored_owner)?;
    check_stake_gate(state.staking(), &pubkey)?;

    // --- Load recipient cell ---
    let r_cell = state.cells().cells.get(recipient_cell_id).ok_or_else(|| {
        format!(
            "Recipient cell {} not found",
            hex::encode(recipient_cell_id)
        )
    })?;
    if r_cell
        .storage
        .get(&pb_keys::LOCKED)
        .map(|b| b[0])
        .unwrap_or(0)
        != 1
    {
        return Err("Recipient cell not initialized".into());
    }
    let r_on_chain_comm = r_cell
        .storage
        .get(&pb_keys::COMMITMENT)
        .copied()
        .unwrap_or([0u8; 32]);
    if r_old_comm != &r_on_chain_comm {
        return Err("recipient_old_commitment mismatch".into());
    }
    let r_old_nonce = read_commit_nonce(r_cell);

    // --- Sender != recipient ---
    if sender_cell_id == recipient_cell_id {
        return Err("Sender and recipient cells must be different".into());
    }

    // --- Nonce checks ---
    check_new_nonce(s_new_nonce, sg.old_nonce)?;
    check_new_nonce(r_new_nonce, r_old_nonce)?;

    // --- Commitment non-zero ---
    if s_new_comm == &[0u8; 32] {
        return Err("sender new_commitment must be non-zero".into());
    }
    if r_new_comm == &[0u8; 32] {
        return Err("recipient new_commitment must be non-zero".into());
    }
    if amount_commitment == &[0u8; 32] {
        return Err("amount_commitment must be non-zero".into());
    }

    // --- Ciphertext lengths ---
    if s_new_enc.len() != CIPHERTEXT_LEN {
        return Err(format!(
            "sender new_encrypted must be {CIPHERTEXT_LEN} bytes"
        ));
    }
    if r_new_enc.len() != CIPHERTEXT_LEN {
        return Err(format!(
            "recipient new_encrypted must be {CIPHERTEXT_LEN} bytes"
        ));
    }

    // --- Proof size sanity (prevent DoS via huge proof) ---
    const MAX_PROOF_BYTES: usize = 512 * 1024; // 512 KB
    if stark_proof.is_empty() {
        return Err("STARK proof is empty".into());
    }
    if stark_proof.len() > MAX_PROOF_BYTES {
        return Err(format!(
            "STARK proof too large: {} bytes (max {MAX_PROOF_BYTES})",
            stark_proof.len()
        ));
    }

    // --- Verify STARK proof (full Rescue-Prime AIR) ---
    let pub_inputs = CtPublicInputs {
        s_old: bytes_to_digest(s_old_comm),
        s_new: bytes_to_digest(s_new_comm),
        r_old: bytes_to_digest(r_old_comm),
        r_new: bytes_to_digest(r_new_comm),
        amt: bytes_to_digest(amount_commitment),
    };
    verify_ct_proof(stark_proof, &pub_inputs)?;

    // --- Update TOTAL_CT_OUT (monotonic) ---
    // We do not know the amount (it's hidden), so we increment by 1 (tx count).
    // The actual amount is proven correct by the ZK proof.
    let old_ct_out = read_u128_slot(sg.cell, &pb_keys::TOTAL_CT_OUT);
    let new_ct_out = old_ct_out.checked_add(1).ok_or("TOTAL_CT_OUT overflow")?;

    let (s_cipher_lo, s_cipher_hi) = pack_ciphertext(s_new_enc)?;
    let (r_cipher_lo, r_cipher_hi) = pack_ciphertext(r_new_enc)?;

    let mut diff = StateDiff::default();

    // Update sender cell
    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *sender_cell_id,
        storage_diff: {
            let mut m = HashMap::new();
            m.insert(pb_keys::COMMITMENT, Some(*s_new_comm));
            m.insert(pb_keys::CIPHER_LO, Some(s_cipher_lo));
            m.insert(pb_keys::CIPHER_HI, Some(s_cipher_hi));
            m.insert(pb_keys::COMMIT_NONCE, Some(pack_nonce(s_new_nonce)));
            m.insert(pb_keys::TOTAL_CT_OUT, Some(pack_u128(new_ct_out)));
            m
        },
    });

    // Update recipient cell
    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *recipient_cell_id,
        storage_diff: {
            let mut m = HashMap::new();
            m.insert(pb_keys::COMMITMENT, Some(*r_new_comm));
            m.insert(pb_keys::CIPHER_LO, Some(r_cipher_lo));
            m.insert(pb_keys::CIPHER_HI, Some(r_cipher_hi));
            m.insert(pb_keys::COMMIT_NONCE, Some(pack_nonce(r_new_nonce)));
            m
        },
    });

    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128 * 3;
    Ok(diff)
}

// ---------------------------------------------------------------------------
// Circuit 5: FeeDeduct
// ---------------------------------------------------------------------------

pub fn circuit_fee_deduct(
    state: &impl PrivateBalanceStateView,
    sender: AccountId,
    intent: &PrivateBalanceIntent,
    _ts: u64,
) -> Result<StateDiff, String> {
    let (cell_id, agent_id, fee_amount, fee_recipient, new_enc, new_comm, new_nonce, old_comm) =
        match intent {
            PrivateBalanceIntent::FeeDeduct {
                cell_id,
                agent_id,
                fee_amount,
                fee_recipient,
                new_encrypted_balance,
                new_commitment,
                new_commit_nonce,
                old_commitment,
            } => (
                cell_id,
                agent_id,
                *fee_amount,
                fee_recipient,
                new_encrypted_balance,
                new_commitment,
                new_commit_nonce,
                old_commitment,
            ),
            _ => return Err("Wrong intent".into()),
        };

    // Fee authority check
    let fee_authority = gp::get_bytes32(gp::PARAM_FEE_AUTHORITY);
    if sender != fee_authority {
        return Err("Only the fee authority can deduct private fees".into());
    }

    let g = load_and_guard(state, cell_id, agent_id, &sender, old_comm)?;

    check_fee(fee_amount)?;
    let gov_max = gp::get_u128(gp::PARAM_MAX_PRIVATE_FEE);
    if fee_amount > gov_max {
        return Err(format!("Fee {fee_amount} exceeds governance max {gov_max}"));
    }

    check_new_nonce(new_nonce, g.old_nonce)?;
    if new_comm == &[0u8; 32] {
        return Err("new_commitment must be non-zero".into());
    }
    if new_enc.len() != CIPHERTEXT_LEN {
        return Err(format!(
            "new_encrypted_balance must be {CIPHERTEXT_LEN} bytes"
        ));
    }

    let fee_rec_acc = state
        .accounts()
        .get(fee_recipient)
        .ok_or("Fee recipient not found")?;
    let new_fee_rec_bal = fee_rec_acc
        .balance
        .checked_add(fee_amount)
        .ok_or("Fee recipient overflow")?;
    check_balance(new_fee_rec_bal, "fee recipient balance")?;

    let old_fees = read_u128_slot(g.cell, &pb_keys::TOTAL_FEES);
    let new_fees = old_fees
        .checked_add(fee_amount)
        .ok_or("TOTAL_FEES overflow")?;
    check_balance(new_fees, "total_fees")?;

    let (cipher_lo, cipher_hi) = pack_ciphertext(new_enc)?;

    let mut diff = StateDiff::default();

    let mut fra = fee_rec_acc.clone();
    fra.balance = new_fee_rec_bal;
    diff.account_updates.insert(*fee_recipient, fra);

    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *cell_id,
        storage_diff: {
            let mut m = HashMap::new();
            m.insert(pb_keys::COMMITMENT, Some(*new_comm));
            m.insert(pb_keys::CIPHER_LO, Some(cipher_lo));
            m.insert(pb_keys::CIPHER_HI, Some(cipher_hi));
            m.insert(pb_keys::COMMIT_NONCE, Some(pack_nonce(new_nonce)));
            m.insert(pb_keys::TOTAL_FEES, Some(pack_u128(new_fees)));
            m
        },
    });

    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
    Ok(diff)
}

// ---------------------------------------------------------------------------
// Conflict domain
// ---------------------------------------------------------------------------

pub fn conflict_domain(
    intent: &PrivateBalanceIntent,
) -> (
    Vec<truthlinked_runtime::compiler_aware::StorageKey>,
    Vec<truthlinked_runtime::compiler_aware::StorageKey>,
) {
    use truthlinked_runtime::compiler_aware::StorageKey;

    let cell_reads = |cid: &AccountId| {
        vec![
            StorageKey::CellStorage(*cid, pb_keys::COMMITMENT),
            StorageKey::CellStorage(*cid, pb_keys::COMMIT_NONCE),
            StorageKey::CellStorage(*cid, pb_keys::LOCKED),
            StorageKey::CellStorage(*cid, pb_keys::OWNER),
            StorageKey::CellStorage(*cid, pb_keys::AGENT),
        ]
    };
    let cell_writes = |cid: &AccountId| {
        vec![
            StorageKey::CellStorage(*cid, pb_keys::COMMITMENT),
            StorageKey::CellStorage(*cid, pb_keys::CIPHER_LO),
            StorageKey::CellStorage(*cid, pb_keys::CIPHER_HI),
            StorageKey::CellStorage(*cid, pb_keys::COMMIT_NONCE),
        ]
    };

    match intent {
        PrivateBalanceIntent::InitPrivateBalance { cell_id, .. } => (vec![], cell_writes(cell_id)),

        PrivateBalanceIntent::Deposit { cell_id, .. } => {
            let mut w = cell_writes(cell_id);
            w.push(StorageKey::CellStorage(*cell_id, pb_keys::TOTAL_DEPOSITED));
            (cell_reads(cell_id), w)
        }

        PrivateBalanceIntent::Withdraw { cell_id, .. } => {
            let mut w = cell_writes(cell_id);
            w.push(StorageKey::CellStorage(*cell_id, pb_keys::TOTAL_WITHDRAWN));
            (cell_reads(cell_id), w)
        }

        PrivateBalanceIntent::ConfidentialTransfer {
            sender_cell_id,
            recipient_cell_id,
            ..
        } => {
            let mut r = cell_reads(sender_cell_id);
            r.extend(cell_reads(recipient_cell_id));
            let mut w = cell_writes(sender_cell_id);
            w.extend(cell_writes(recipient_cell_id));
            w.push(StorageKey::CellStorage(
                *sender_cell_id,
                pb_keys::TOTAL_CT_OUT,
            ));
            (r, w)
        }

        PrivateBalanceIntent::FeeDeduct { cell_id, .. } => {
            let mut w = cell_writes(cell_id);
            w.push(StorageKey::CellStorage(*cell_id, pb_keys::TOTAL_FEES));
            (cell_reads(cell_id), w)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use im::HashMap as ImHashMap;
    use truthlinked_runtime::cells::CellState;
    use truthlinked_runtime::types::AccountRecord;
    use truthlinked_staking::{StakingState, ValidatorStake};

    struct TestState {
        cells: CellState,
        accounts: ImHashMap<AccountId, AccountRecord>,
        params: ImHashMap<[u8; 32], [u8; 32]>,
        staking: StakingState,
    }

    impl McpStateView for TestState {
        fn cells(&self) -> &CellState {
            &self.cells
        }
        fn accounts(&self) -> &ImHashMap<AccountId, AccountRecord> {
            &self.accounts
        }
    }

    impl PrivateBalanceStateView for TestState {
        fn staking(&self) -> &StakingState {
            &self.staking
        }
    }

    impl truthlinked_governance::params::ParamState for TestState {
        fn params(&self) -> &ImHashMap<[u8; 32], [u8; 32]> {
            &self.params
        }
        fn params_mut(&mut self) -> &mut ImHashMap<[u8; 32], [u8; 32]> {
            &mut self.params
        }
    }

    fn make_state() -> TestState {
        let mut s = TestState {
            cells: CellState::new(),
            accounts: ImHashMap::new(),
            params: ImHashMap::new(),
            staking: StakingState::new(),
        };
        truthlinked_governance::params::insert_genesis_params(&mut s);
        truthlinked_governance::params::rehydrate_from_state(&s);
        s
    }

    fn add_account(s: &mut TestState, id: AccountId, balance: u128) {
        s.accounts.insert(
            id,
            AccountRecord {
                pubkey_bytes: id.to_vec(), // pubkey = id bytes for test simplicity
                balance,
                compute_escrow_tlkd: 0,
                nonce: 0,
                nfts: vec![],
            },
        );
    }

    fn stake_owner(s: &mut TestState, owner: AccountId) {
        // pubkey_bytes = owner id bytes (set in add_account)
        s.staking.validators.insert(
            owner.to_vec(),
            ValidatorStake {
                active_stake: PRIVATE_BALANCE_MIN_STAKE,
                unbonding: vec![],
                jailed_until: None,
            },
        );
    }

    fn dummy_ct() -> Vec<u8> {
        vec![0xABu8; CIPHERTEXT_LEN]
    }
    fn dummy_comm() -> [u8; 32] {
        [0x01u8; 32]
    }
    fn dummy_nonce() -> [u8; 16] {
        [0x02u8; 16]
    }

    fn do_init(s: &mut TestState, owner: AccountId, agent: AccountId) -> AccountId {
        let cell_id = pb_keys::cell_for_agent(&agent);
        let rent = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
        add_account(s, owner, rent * 10 + 1_000_000_000_000);
        stake_owner(s, owner);

        let intent = PrivateBalanceIntent::InitPrivateBalance {
            cell_id,
            agent_id: agent,
            encrypted_balance: dummy_ct(),
            commitment: dummy_comm(),
            commit_nonce: dummy_nonce(),
        };
        let diff = circuit_init_private_balance(s, owner, &intent, 0).unwrap();
        for u in diff.cell_updates {
            if let CellUpdate::Deploy { cell_id: cid, cell } = u {
                s.cells.cells.insert(cid, cell);
            }
        }
        for (id, acc) in diff.account_updates {
            s.accounts.insert(id, acc);
        }
        cell_id
    }

    // --- Staking gate ---

    #[test]
    fn init_rejects_unstaked_owner() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let rent = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
        add_account(&mut s, owner, rent * 10);
        // no stake_owner call

        let cell_id = pb_keys::cell_for_agent(&agent);
        let intent = PrivateBalanceIntent::InitPrivateBalance {
            cell_id,
            agent_id: agent,
            encrypted_balance: dummy_ct(),
            commitment: dummy_comm(),
            commit_nonce: dummy_nonce(),
        };
        let err = circuit_init_private_balance(&s, owner, &intent, 0).unwrap_err();
        assert!(err.contains("Insufficient stake"), "got: {err}");
    }

    #[test]
    fn deposit_rejects_unstaked_owner() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let cell_id = do_init(&mut s, owner, agent);

        // Remove stake
        s.staking.validators.remove(&owner.to_vec());

        let intent = PrivateBalanceIntent::Deposit {
            cell_id,
            agent_id: agent,
            amount: 1000,
            new_encrypted_balance: dummy_ct(),
            new_commitment: [0x03u8; 32],
            new_commit_nonce: [0x05u8; 16],
            old_commitment: dummy_comm(),
        };
        let err = circuit_deposit(&s, owner, &intent, 0).unwrap_err();
        assert!(err.contains("Insufficient stake"), "got: {err}");
    }

    // --- Init guards ---

    #[test]
    fn init_rejects_self_register() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let rent = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
        add_account(&mut s, owner, rent * 10);
        stake_owner(&mut s, owner);

        let cell_id = pb_keys::cell_for_agent(&owner);
        let intent = PrivateBalanceIntent::InitPrivateBalance {
            cell_id,
            agent_id: owner,
            encrypted_balance: dummy_ct(),
            commitment: dummy_comm(),
            commit_nonce: dummy_nonce(),
        };
        let err = circuit_init_private_balance(&s, owner, &intent, 0).unwrap_err();
        assert!(err.contains("different accounts"), "got: {err}");
    }

    #[test]
    fn init_rejects_wrong_cell_id() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let rent = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
        add_account(&mut s, owner, rent * 10);
        stake_owner(&mut s, owner);

        let intent = PrivateBalanceIntent::InitPrivateBalance {
            cell_id: [0xFFu8; 32],
            agent_id: agent,
            encrypted_balance: dummy_ct(),
            commitment: dummy_comm(),
            commit_nonce: dummy_nonce(),
        };
        let err = circuit_init_private_balance(&s, owner, &intent, 0).unwrap_err();
        assert!(err.contains("cell_id mismatch"), "got: {err}");
    }

    #[test]
    fn init_succeeds() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let cell_id = do_init(&mut s, owner, agent);
        assert!(s.cells.cells.contains_key(&cell_id));
        let cell = &s.cells.cells[&cell_id];
        assert_eq!(cell.storage[&pb_keys::LOCKED][0], 1);
        assert_eq!(cell.storage[&pb_keys::STAKE_VERIFIED][0], 1);
    }

    // --- Deposit ---

    #[test]
    fn deposit_rejects_zero_amount() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let cell_id = do_init(&mut s, owner, agent);
        stake_owner(&mut s, owner);

        let intent = PrivateBalanceIntent::Deposit {
            cell_id,
            agent_id: agent,
            amount: 0,
            new_encrypted_balance: dummy_ct(),
            new_commitment: [0x03u8; 32],
            new_commit_nonce: [0x05u8; 16],
            old_commitment: dummy_comm(),
        };
        let err = circuit_deposit(&s, owner, &intent, 0).unwrap_err();
        assert!(err.contains("must be > 0"), "got: {err}");
    }

    #[test]
    fn deposit_rejects_stale_commitment() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let cell_id = do_init(&mut s, owner, agent);
        stake_owner(&mut s, owner);

        let intent = PrivateBalanceIntent::Deposit {
            cell_id,
            agent_id: agent,
            amount: 1000,
            new_encrypted_balance: dummy_ct(),
            new_commitment: [0x03u8; 32],
            new_commit_nonce: [0x05u8; 16],
            old_commitment: [0xFFu8; 32], // wrong
        };
        let err = circuit_deposit(&s, owner, &intent, 0).unwrap_err();
        assert!(err.contains("old_commitment mismatch"), "got: {err}");
    }

    #[test]
    fn deposit_rejects_insufficient_balance() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let cell_id = do_init(&mut s, owner, agent);
        stake_owner(&mut s, owner);
        // drain owner balance
        s.accounts.get_mut(&owner).unwrap().balance = 0;

        let intent = PrivateBalanceIntent::Deposit {
            cell_id,
            agent_id: agent,
            amount: 1_000_000,
            new_encrypted_balance: dummy_ct(),
            new_commitment: [0x03u8; 32],
            new_commit_nonce: [0x05u8; 16],
            old_commitment: dummy_comm(),
        };
        let err = circuit_deposit(&s, owner, &intent, 0).unwrap_err();
        assert!(err.contains("Insufficient"), "got: {err}");
    }

    #[test]
    fn deposit_succeeds_and_debits_sender() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let cell_id = do_init(&mut s, owner, agent);
        stake_owner(&mut s, owner);
        let before = s.accounts[&owner].balance;

        let amount = 500_000_000u128;
        let intent = PrivateBalanceIntent::Deposit {
            cell_id,
            agent_id: agent,
            amount,
            new_encrypted_balance: dummy_ct(),
            new_commitment: [0x03u8; 32],
            new_commit_nonce: [0x05u8; 16],
            old_commitment: dummy_comm(),
        };
        let diff = circuit_deposit(&s, owner, &intent, 0).unwrap();
        let new_bal = diff.account_updates[&owner].balance;
        assert_eq!(new_bal, before - amount);
    }

    // --- Withdraw ---

    #[test]
    fn withdraw_rejects_same_nonce() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let cell_id = do_init(&mut s, owner, agent);
        stake_owner(&mut s, owner);
        let recipient = [5u8; 32];
        add_account(&mut s, recipient, 0);

        let intent = PrivateBalanceIntent::Withdraw {
            cell_id,
            agent_id: agent,
            amount: 100,
            recipient,
            new_encrypted_balance: dummy_ct(),
            new_commitment: [0x03u8; 32],
            new_commit_nonce: dummy_nonce(), // same as init nonce
            old_commitment: dummy_comm(),
        };
        let err = circuit_withdraw(&s, owner, &intent, 0).unwrap_err();
        assert!(err.contains("nonce"), "got: {err}");
    }

    #[test]
    fn withdraw_credits_recipient() {
        let mut s = make_state();
        let owner = [1u8; 32];
        let agent = [2u8; 32];
        let cell_id = do_init(&mut s, owner, agent);
        stake_owner(&mut s, owner);
        let recipient = [5u8; 32];
        add_account(&mut s, recipient, 0);

        let amount = 999u128;
        let intent = PrivateBalanceIntent::Withdraw {
            cell_id,
            agent_id: agent,
            amount,
            recipient,
            new_encrypted_balance: dummy_ct(),
            new_commitment: [0x03u8; 32],
            new_commit_nonce: [0x05u8; 16],
            old_commitment: dummy_comm(),
        };
        let diff = circuit_withdraw(&s, owner, &intent, 0).unwrap();
        assert_eq!(diff.account_updates[&recipient].balance, amount);
    }

    // --- Encryption round-trip ---

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_aes_key(b"test_seed_32bytes_exactly_padded!");
        let balance = 123_456_789_000u128;
        let nonce = [0x42u8; AES_NONCE_LEN];
        let ct = encrypt_balance(balance, &key, &nonce).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        assert_eq!(decrypt_balance(&ct, &key).unwrap(), balance);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key = derive_aes_key(b"correct_seed_32bytes_exactly____");
        let bad = derive_aes_key(b"wrong___seed_32bytes_exactly____");
        let ct = encrypt_balance(42, &key, &[0x11u8; AES_NONCE_LEN]).unwrap();
        assert!(decrypt_balance(&ct, &bad).is_err());
    }

    // --- Commitment binding ---

    #[test]
    fn commitment_binds_ciphertext() {
        let ct1 = vec![0xAAu8; CIPHERTEXT_LEN];
        let ct2 = vec![0xBBu8; CIPHERTEXT_LEN];
        let c1 = compute_commitment(100, 1, &ct1);
        let c2 = compute_commitment(100, 1, &ct2);
        assert_ne!(
            c1, c2,
            "Different ciphertexts must produce different commitments"
        );
    }

    #[test]
    fn commitment_verify_ok() {
        let ct = dummy_ct();
        let c = compute_commitment(500, 7, &ct);
        verify_commitment(&c, 500, 7, &ct).unwrap();
    }

    #[test]
    fn commitment_verify_wrong_balance_fails() {
        let ct = dummy_ct();
        let c = compute_commitment(500, 7, &ct);
        assert!(verify_commitment(&c, 501, 7, &ct).is_err());
    }

    // --- Range checks ---

    #[test]
    fn range_check_balance_overflow() {
        assert!(check_balance(MAX_PRIVATE_BALANCE + 1, "x").is_err());
    }

    #[test]
    fn range_check_amount_zero() {
        assert!(check_amount(0, "x").is_err());
    }

    #[test]
    fn range_check_amount_overflow() {
        assert!(check_amount(MAX_TRANSFER_AMOUNT + 1, "x").is_err());
    }

    #[test]
    fn range_check_fee_overflow() {
        assert!(check_fee(MAX_FEE_AMOUNT + 1).is_err());
    }
}
