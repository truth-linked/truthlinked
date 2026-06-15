//! Native Rust handlers for system cells.
//! System cells are protocol-owned trusted code - no sandbox needed.
//! All logic that was previously in the Axiom VM host is here as direct Rust.

use crate::cells::ExecutionResult;
use crate::log::Log;
use std::collections::HashMap;
use truthlinked_core::pq_execution::{treasury_system_cell_id, AccountId};
use truthlinked_governance::PendingNameRegistration;
use truthlinked_runtime::types::StakingUpdate;

const PUBKEY_LEN: usize = 1952;

// ── Selector hash (FNV-1a 32-bit, matches SDK) ───────────────────────────────
fn sel(name: &str) -> [u8; 4] {
    let mut h: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h.to_le_bytes()
}

fn read_sel(cd: &[u8]) -> Option<[u8; 4]> {
    if cd.len() < 4 {
        return None;
    }
    Some([cd[0], cd[1], cd[2], cd[3]])
}

fn read32(cd: &[u8], off: usize) -> Option<[u8; 32]> {
    if cd.len() < off + 32 {
        return None;
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&cd[off..off + 32]);
    Some(b)
}

fn read_u64(cd: &[u8], off: usize) -> Option<u64> {
    if cd.len() < off + 8 {
        return None;
    }
    Some(u64::from_le_bytes(cd[off..off + 8].try_into().unwrap()))
}

fn read_u128(cd: &[u8], off: usize) -> Option<u128> {
    if cd.len() < off + 16 {
        return None;
    }
    Some(u128::from_le_bytes(cd[off..off + 16].try_into().unwrap()))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn account_id_from_pubkey(pk: &[u8]) -> [u8; 32] {
    let mut d = Vec::with_capacity(25 + pk.len());
    d.extend_from_slice(b"truthlinked-account-id-v1");
    d.extend_from_slice(pk);
    sha256(&d)
}

fn ns(name: &str) -> [u8; 32] {
    sha256(name.as_bytes())
}

fn storage_key(namespace: &[u8; 32], key: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 64];
    d[..32].copy_from_slice(namespace);
    d[32..].copy_from_slice(key);
    sha256(&d)
}

fn derive_slot(namespace: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"trth:sdk:slot:v1");
    h.update([0u8]);
    h.update(namespace);
    for part in parts {
        h.update([0xFF]);
        h.update(part);
    }
    h.finalize().into()
}

fn staking_positions_namespace() -> [u8; 32] {
    sha256(b"truthlinked.staking.positions")
}

fn staking_holders_namespace() -> [u8; 32] {
    sha256(b"truthlinked.staking.holders")
}

fn staking_exists_slot(owner: &[u8; 32]) -> [u8; 32] {
    derive_slot(&staking_positions_namespace(), &[b"map:exists", owner])
}

fn staking_value_slot(owner: &[u8; 32]) -> [u8; 32] {
    derive_slot(&staking_positions_namespace(), &[b"map:value", owner])
}

fn staking_holders_len_slot() -> [u8; 32] {
    derive_slot(&staking_holders_namespace(), &[b"vec:len"])
}

fn staking_holders_elem_slot(index: u64) -> [u8; 32] {
    let idx = index.to_le_bytes();
    derive_slot(&staking_holders_namespace(), &[b"vec:elem", &idx])
}

fn pack_staking_position(amount: u128, lock_end: u64) -> [u8; 32] {
    let mut raw = [0u8; 32];
    raw[0..16].copy_from_slice(&amount.to_le_bytes());
    raw[24..32].copy_from_slice(&lock_end.to_le_bytes());
    raw
}

fn unpack_staking_position(raw: &[u8; 32]) -> (u128, u64) {
    let mut amount = [0u8; 16];
    amount.copy_from_slice(&raw[0..16]);
    let mut lock_end = [0u8; 8];
    lock_end.copy_from_slice(&raw[24..32]);
    (u128::from_le_bytes(amount), u64::from_le_bytes(lock_end))
}

fn storage_u64(storage: &HashMap<[u8; 32], [u8; 32]>, key: [u8; 32]) -> u64 {
    storage
        .get(&key)
        .map(|v| u64::from_le_bytes(v[..8].try_into().unwrap()))
        .unwrap_or(0)
}

fn pack_u64_word(value: u64) -> [u8; 32] {
    let mut raw = [0u8; 32];
    raw[..8].copy_from_slice(&value.to_le_bytes());
    raw
}

fn ok(
    return_data: Vec<u8>,
    storage_diff: Vec<([u8; 32], Option<[u8; 32]>)>,
    staking_updates: Vec<StakingUpdate>,
    param_updates: Vec<([u8; 32], [u8; 32])>,
    native_credits: Vec<([u8; 32], u128)>,
    pending_name_proposals: Vec<(String, PendingNameRegistration, [u8; 32], bool)>,
    name_votes: Vec<(String, Vec<u8>, u64)>,
    name_renewals: Vec<(String, u64)>,
    name_transfers: Vec<(String, [u8; 32])>,
    logs: Vec<Log>,
    gas_used: u64,
) -> ExecutionResult {
    ExecutionResult {
        success: true,
        return_data,
        gas_used,
        storage_diff,
        staking_updates,
        param_updates,
        native_credits,
        pending_name_proposals,
        name_votes,
        name_renewals,
        name_transfers,
        logs,
        ..ExecutionResult::default()
    }
}

fn err(msg: &str, gas_used: u64) -> ExecutionResult {
    ExecutionResult {
        success: false,
        error: Some(msg.into()),
        gas_used,
        ..ExecutionResult::default()
    }
}

// ── Public dispatch ───────────────────────────────────────────────────────────

pub fn dispatch(
    cell_id: &AccountId,
    calldata: &[u8],
    caller: AccountId,
    storage: &HashMap<[u8; 32], [u8; 32]>,
    height: u64,
    value: u128,
    gas_limit: u64,
    global_state: &crate::pq_execution::State,
) -> ExecutionResult {
    use truthlinked_core::pq_execution::{
        governance_system_cell_id, name_registry_system_cell_id, staking_system_cell_id,
        treasury_system_cell_id,
    };

    if *cell_id == staking_system_cell_id() {
        return staking(
            calldata,
            caller,
            storage,
            global_state,
            height,
            value,
            gas_limit,
        );
    }
    if *cell_id == governance_system_cell_id() {
        return governance(calldata, caller, storage, height, global_state, gas_limit);
    }
    if *cell_id == treasury_system_cell_id() {
        return treasury(calldata, caller, storage, height, global_state, gas_limit);
    }
    if *cell_id == name_registry_system_cell_id() {
        return name_registry(calldata, caller, global_state, height, gas_limit);
    }
    err("Unknown system cell", gas_limit)
}

// ── Staking cell ─────────────────────────────────────────────────────────────

fn staking(
    cd: &[u8],
    caller: AccountId,
    storage: &HashMap<[u8; 32], [u8; 32]>,
    _state: &crate::pq_execution::State,
    height: u64,
    value: u128,
    gas_limit: u64,
) -> ExecutionResult {
    let s = read_sel(cd).unwrap_or_default();
    let mut diff: Vec<([u8; 32], Option<[u8; 32]>)> = vec![];
    let mut staking_updates = vec![];
    let logs = vec![];

    // delegate_add / delegate_remove - pure storage
    if s == sel("delegate_add") || s == sel("delegate_remove") {
        let Some(delegate) = read32(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        let allowed = s == sel("delegate_add");
        let ns_del = ns("truthlinked.staking.delegates");
        let key = storage_key(&ns_del, &{
            let mut d = [0u8; 64];
            d[..32].copy_from_slice(&caller);
            d[32..].copy_from_slice(&delegate);
            sha256(&d)
        });
        let mut v = [0u8; 32];
        v[0] = allowed as u8;
        diff.push((key, Some(v)));
        return ok(
            vec![],
            diff,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            logs,
            100,
        );
    }

    // staked-TLKD lock positions are stored inside the staking system cell.
    // The CLI sends the locked amount as CallCell.value and the owner/term in calldata.
    if s == sel("lock") || s == sel("extend") || s == sel("unlock") {
        let Some(owner) = read32(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        if caller != owner {
            return err("unauthorized", gas_limit);
        }

        let exists_slot = staking_exists_slot(&owner);
        let value_slot = staking_value_slot(&owner);
        let exists = storage.get(&exists_slot).map(|v| v[0]).unwrap_or(0) == 1;
        let current = storage
            .get(&value_slot)
            .map(unpack_staking_position)
            .unwrap_or((0, 0));

        if s == sel("lock") {
            let Some(lock_blocks) = read_u64(cd, 36) else {
                return err("bad calldata", gas_limit);
            };
            if value == 0 || lock_blocks == 0 {
                return err("zero lock", gas_limit);
            }
            let lock_end = height.saturating_add(lock_blocks);
            let amount = current.0.saturating_add(value);
            let lock_end = current.1.max(lock_end);
            let mut one = [0u8; 32];
            one[0] = 1;
            diff.push((exists_slot, Some(one)));
            diff.push((value_slot, Some(pack_staking_position(amount, lock_end))));
            if !exists {
                let len_slot = staking_holders_len_slot();
                let len = storage_u64(storage, len_slot);
                diff.push((staking_holders_elem_slot(len), Some(owner)));
                diff.push((len_slot, Some(pack_u64_word(len.saturating_add(1)))));
            }
            return ok(
                vec![],
                diff,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                logs,
                500,
            );
        }

        if !exists {
            return err("no staking lock", gas_limit);
        }

        if s == sel("extend") {
            let Some(lock_blocks) = read_u64(cd, 36) else {
                return err("bad calldata", gas_limit);
            };
            if lock_blocks == 0 {
                return err("zero extension", gas_limit);
            }
            let lock_end = current.1.max(height.saturating_add(lock_blocks));
            diff.push((value_slot, Some(pack_staking_position(current.0, lock_end))));
            return ok(
                vec![],
                diff,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                logs,
                500,
            );
        }

        if height < current.1 {
            return err("staking lock has not matured", gas_limit);
        }
        let mut result = ok(
            vec![],
            vec![(exists_slot, None), (value_slot, None)],
            vec![],
            vec![],
            vec![(owner, current.0)],
            vec![],
            vec![],
            vec![],
            vec![],
            logs,
            500,
        );
        result.cell_debits.push((
            truthlinked_core::pq_execution::staking_system_cell_id(),
            current.0,
        ));
        return result;
    }

    // stake / unstake / withdraw / unjail (self)
    if s == sel("stake") || s == sel("unstake") || s == sel("withdraw") || s == sel("unjail") {
        if cd.len() < 4 + PUBKEY_LEN {
            return err("bad calldata", gas_limit);
        }
        let pubkey = &cd[4..4 + PUBKEY_LEN];
        if account_id_from_pubkey(pubkey) != caller {
            return err("unauthorized", gas_limit);
        }
        return staking_op(
            s,
            pubkey,
            cd,
            4 + PUBKEY_LEN,
            caller,
            &mut staking_updates,
            logs,
            gas_limit,
        );
    }

    // stake_for / unstake_for / withdraw_for / unjail_for (delegated)
    if s == sel("stake_for")
        || s == sel("unstake_for")
        || s == sel("withdraw_for")
        || s == sel("unjail_for")
    {
        if cd.len() < 4 + 32 + PUBKEY_LEN {
            return err("bad calldata", gas_limit);
        }
        let owner = read32(cd, 4).unwrap();
        let pubkey = &cd[36..36 + PUBKEY_LEN];
        if account_id_from_pubkey(pubkey) != owner {
            return err("pubkey mismatch", gas_limit);
        }
        // check caller == owner or is delegate
        if caller != owner {
            let ns_del = ns("truthlinked.staking.delegates");
            let dkey = storage_key(&ns_del, &{
                let mut d = [0u8; 64];
                d[..32].copy_from_slice(&owner);
                d[32..].copy_from_slice(&caller);
                sha256(&d)
            });
            if storage.get(&dkey).map(|v| v[0]).unwrap_or(0) != 1 {
                return err("unauthorized", gas_limit);
            }
        }
        let base_sel = if s == sel("stake_for") {
            sel("stake")
        } else if s == sel("unstake_for") {
            sel("unstake")
        } else if s == sel("withdraw_for") {
            sel("withdraw")
        } else {
            sel("unjail")
        };
        return staking_op(
            base_sel,
            pubkey,
            cd,
            36 + PUBKEY_LEN,
            owner,
            &mut staking_updates,
            logs,
            gas_limit,
        );
    }

    err("unknown selector", gas_limit)
}

fn staking_op(
    s: [u8; 4],
    pubkey: &[u8],
    cd: &[u8],
    amount_off: usize,
    _actor: AccountId,
    updates: &mut Vec<StakingUpdate>,
    logs: Vec<Log>,
    gas_limit: u64,
) -> ExecutionResult {
    if s == sel("stake") {
        let Some(amount) = read_u64(cd, amount_off) else {
            return err("bad calldata", gas_limit);
        };
        if amount == 0 {
            return err("zero amount", gas_limit);
        }
        updates.push(StakingUpdate::Stake {
            validator: pubkey.to_vec(),
            amount,
        });
    } else if s == sel("unstake") {
        let Some(amount) = read_u64(cd, amount_off) else {
            return err("bad calldata", gas_limit);
        };
        if amount == 0 {
            return err("zero amount", gas_limit);
        }
        updates.push(StakingUpdate::Unstake {
            validator: pubkey.to_vec(),
            amount,
        });
    } else if s == sel("withdraw") {
        updates.push(StakingUpdate::Withdraw {
            validator: pubkey.to_vec(),
        });
    } else if s == sel("unjail") {
        updates.push(StakingUpdate::Unjail {
            validator: pubkey.to_vec(),
        });
    }
    ok(
        vec![],
        vec![],
        updates.drain(..).collect(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        logs,
        500,
    )
}

// ── Governance cell ───────────────────────────────────────────────────────────

const APPROVAL_NUM: u64 = 2;
const APPROVAL_DEN: u64 = 3;
const MIN_PART_NUM: u64 = 1;
const MIN_PART_DEN: u64 = 3;

fn gov_key(sub: &str, param_key: &[u8; 32]) -> [u8; 32] {
    storage_key(&ns(&format!("truthlinked.gov.{sub}")), param_key)
}

fn read_slot_u64(storage: &HashMap<[u8; 32], [u8; 32]>, key: [u8; 32]) -> u64 {
    storage
        .get(&key)
        .map(|v| u64::from_le_bytes(v[..8].try_into().unwrap()))
        .unwrap_or(0)
}

fn pack_u64(v: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&v.to_le_bytes());
    s
}

fn governance(
    cd: &[u8],
    caller: AccountId,
    storage: &HashMap<[u8; 32], [u8; 32]>,
    height: u64,
    state: &crate::pq_execution::State,
    gas_limit: u64,
) -> ExecutionResult {
    let s = read_sel(cd).unwrap_or_default();
    let mut diff: Vec<([u8; 32], Option<[u8; 32]>)> = vec![];

    if s == sel("get_param") {
        let Some(key) = read32(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        let value = state.params.get(&key).copied().unwrap_or([0u8; 32]);
        return ok(
            value.to_vec(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            50,
        );
    }

    if s == sel("propose_param") {
        let Some(key) = read32(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        if !truthlinked_governance::params::is_known_param_key(&key) {
            return err("unknown param key", gas_limit);
        }
        let Some(value) = read32(cd, 36) else {
            return err("bad calldata", gas_limit);
        };
        let Some(voting_period) = read_u64(cd, 68) else {
            return err("bad calldata", gas_limit);
        };
        let Some(timelock) = read_u64(cd, 76) else {
            return err("bad calldata", gas_limit);
        };
        if voting_period == 0 {
            return err("zero voting period", gas_limit);
        }
        if cd.len() < 84 + PUBKEY_LEN {
            return err("bad calldata", gas_limit);
        }
        let pubkey = &cd[84..84 + PUBKEY_LEN];
        if account_id_from_pubkey(pubkey) != caller {
            return err("unauthorized", gas_limit);
        }
        if state
            .staking
            .validators
            .get(pubkey)
            .map(|v| v.total_stake())
            .unwrap_or(0)
            == 0
        {
            return err("zero stake", gas_limit);
        }
        // reject if active proposal exists
        if storage
            .get(&gov_key("proposal.exists", &key))
            .map(|v| v[0])
            .unwrap_or(0)
            == 1
            && storage
                .get(&gov_key("proposal.executed", &key))
                .map(|v| v[0])
                .unwrap_or(0)
                == 0
        {
            return err("proposal exists", gas_limit);
        }
        let nonce = read_slot_u64(storage, gov_key("proposal.nonce", &key)).saturating_add(1);
        let voting_ends = height.saturating_add(voting_period);
        diff.extend([
            (
                gov_key("proposal.exists", &key),
                Some({
                    let mut v = [0u8; 32];
                    v[0] = 1;
                    v
                }),
            ),
            (gov_key("proposal.nonce", &key), Some(pack_u64(nonce))),
            (gov_key("proposal.value", &key), Some(value)),
            (gov_key("proposal.proposer", &key), Some(caller)),
            (gov_key("proposal.created", &key), Some(pack_u64(height))),
            (
                gov_key("proposal.voting_ends", &key),
                Some(pack_u64(voting_ends)),
            ),
            (gov_key("proposal.timelock", &key), Some(pack_u64(timelock))),
            (gov_key("proposal.votes_for", &key), Some([0u8; 32])),
            (gov_key("proposal.votes_against", &key), Some([0u8; 32])),
            (gov_key("proposal.executed", &key), Some([0u8; 32])),
        ]);
        return ok(
            vec![],
            diff,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            500,
        );
    }

    if s == sel("vote_param") {
        let Some(key) = read32(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        let Some(approve_u64) = read_u64(cd, 36) else {
            return err("bad calldata", gas_limit);
        };
        let approve = approve_u64 != 0;
        if cd.len() < 44 + PUBKEY_LEN {
            return err("bad calldata", gas_limit);
        }
        let pubkey = &cd[44..44 + PUBKEY_LEN];
        if account_id_from_pubkey(pubkey) != caller {
            return err("unauthorized", gas_limit);
        }
        let stake = state
            .staking
            .validators
            .get(pubkey)
            .map(|v| v.total_stake())
            .unwrap_or(0);
        if stake == 0 {
            return err("zero stake", gas_limit);
        }
        if storage
            .get(&gov_key("proposal.exists", &key))
            .map(|v| v[0])
            .unwrap_or(0)
            != 1
        {
            return err("no proposal", gas_limit);
        }
        if storage
            .get(&gov_key("proposal.executed", &key))
            .map(|v| v[0])
            .unwrap_or(0)
            == 1
        {
            return err("voting closed", gas_limit);
        }
        let voting_ends = read_slot_u64(storage, gov_key("proposal.voting_ends", &key));
        if height > voting_ends {
            return err("voting closed", gas_limit);
        }
        let nonce = read_slot_u64(storage, gov_key("proposal.nonce", &key));
        // vote dedup key
        let vkey = {
            let mut d = Vec::new();
            d.extend_from_slice(b"truthlinked.gov.vote.v1");
            d.extend_from_slice(&key);
            d.extend_from_slice(&nonce.to_le_bytes());
            d.extend_from_slice(pubkey);
            sha256(&d)
        };
        if storage.get(&vkey).map(|v| v[0]).unwrap_or(0) == 1 {
            return err("already voted", gas_limit);
        }
        diff.push((
            vkey,
            Some({
                let mut v = [0u8; 32];
                v[0] = 1;
                v
            }),
        ));
        if approve {
            let cur = read_slot_u64(storage, gov_key("proposal.votes_for", &key));
            diff.push((
                gov_key("proposal.votes_for", &key),
                Some(pack_u64(cur.saturating_add(stake))),
            ));
        } else {
            let cur = read_slot_u64(storage, gov_key("proposal.votes_against", &key));
            diff.push((
                gov_key("proposal.votes_against", &key),
                Some(pack_u64(cur.saturating_add(stake))),
            ));
        }
        return ok(
            vec![],
            diff,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            200,
        );
    }

    if s == sel("execute_param") {
        let Some(key) = read32(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        if !truthlinked_governance::params::is_known_param_key(&key) {
            return err("unknown param key", gas_limit);
        }
        if storage
            .get(&gov_key("proposal.exists", &key))
            .map(|v| v[0])
            .unwrap_or(0)
            != 1
        {
            return err("no proposal", gas_limit);
        }
        if storage
            .get(&gov_key("proposal.executed", &key))
            .map(|v| v[0])
            .unwrap_or(0)
            == 1
        {
            return err("already executed", gas_limit);
        }
        let voting_ends = read_slot_u64(storage, gov_key("proposal.voting_ends", &key));
        if height <= voting_ends {
            return err("voting open", gas_limit);
        }
        let created = read_slot_u64(storage, gov_key("proposal.created", &key));
        let timelock = read_slot_u64(storage, gov_key("proposal.timelock", &key));
        if height < created.saturating_add(timelock) {
            return err("timelock", gas_limit);
        }
        let total_stake: u64 = state.staking.get_active_validators().values().sum();
        if total_stake == 0 {
            return err("zero stake", gas_limit);
        }
        let votes_for = read_slot_u64(storage, gov_key("proposal.votes_for", &key));
        let votes_against = read_slot_u64(storage, gov_key("proposal.votes_against", &key));
        let votes_total = votes_for.saturating_add(votes_against);
        if votes_total.saturating_mul(MIN_PART_DEN) < total_stake.saturating_mul(MIN_PART_NUM) {
            return err("quorum not met", gas_limit);
        }
        if votes_for.saturating_mul(APPROVAL_DEN) < votes_total.saturating_mul(APPROVAL_NUM) {
            return err("approval not met", gas_limit);
        }
        if votes_for <= votes_against {
            return err("approval not met", gas_limit);
        }
        let new_value = storage
            .get(&gov_key("proposal.value", &key))
            .copied()
            .unwrap_or([0u8; 32]);
        diff.push((
            gov_key("proposal.executed", &key),
            Some({
                let mut v = [0u8; 32];
                v[0] = 1;
                v
            }),
        ));
        diff.push((gov_key("params", &key), Some(new_value)));
        return ok(
            vec![],
            diff,
            vec![],
            vec![(key, new_value)],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            1000,
        );
    }

    err("unknown selector", gas_limit)
}

// ── Treasury cell ─────────────────────────────────────────────────────────────

fn treas_key(sub: &str, id: &[u8; 32]) -> [u8; 32] {
    storage_key(&ns(&format!("truthlinked.treasury.{sub}")), id)
}

fn read_slot_u128(storage: &HashMap<[u8; 32], [u8; 32]>, key: [u8; 32]) -> u128 {
    storage
        .get(&key)
        .map(|v| u128::from_le_bytes(v[..16].try_into().unwrap()))
        .unwrap_or(0)
}

fn pack_u128(v: u128) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..16].copy_from_slice(&v.to_le_bytes());
    s
}

fn treasury(
    cd: &[u8],
    caller: AccountId,
    storage: &HashMap<[u8; 32], [u8; 32]>,
    height: u64,
    state: &crate::pq_execution::State,
    gas_limit: u64,
) -> ExecutionResult {
    let s = read_sel(cd).unwrap_or_default();
    let mut diff: Vec<([u8; 32], Option<[u8; 32]>)> = vec![];
    const VOTING_PERIOD: u64 = 432_000;

    if s == sel("propose_spend") {
        if cd.len() < 92 {
            return err("bad calldata", gas_limit);
        }
        let Some(proposal_id) = read32(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        let Some(recipient) = read32(cd, 36) else {
            return err("bad calldata", gas_limit);
        };
        let Some(amount) = read_u128(cd, 68) else {
            return err("bad calldata", gas_limit);
        };
        let Some(timelock) = read_u64(cd, 84) else {
            return err("bad calldata", gas_limit);
        };
        if amount == 0 {
            return err("zero amount", gas_limit);
        }
        if storage
            .get(&treas_key("proposal.exists", &proposal_id))
            .map(|v| v[0])
            .unwrap_or(0)
            == 1
        {
            return err("proposal exists", gas_limit);
        }
        let _voting_ends = height.saturating_add(VOTING_PERIOD);
        diff.extend([
            (
                treas_key("proposal.exists", &proposal_id),
                Some({
                    let mut v = [0u8; 32];
                    v[0] = 1;
                    v
                }),
            ),
            (
                treas_key("proposal.recipient", &proposal_id),
                Some(recipient),
            ),
            (
                treas_key("proposal.amount", &proposal_id),
                Some(pack_u128(amount)),
            ),
            (
                treas_key("proposal.created", &proposal_id),
                Some(pack_u64(height)),
            ),
            (
                treas_key("proposal.timelock", &proposal_id),
                Some(pack_u64(timelock)),
            ),
            (
                treas_key("proposal.votes_for", &proposal_id),
                Some([0u8; 32]),
            ),
            (
                treas_key("proposal.votes_against", &proposal_id),
                Some([0u8; 32]),
            ),
            (
                treas_key("proposal.executed", &proposal_id),
                Some([0u8; 32]),
            ),
        ]);
        return ok(
            vec![],
            diff,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            500,
        );
    }

    if s == sel("vote_spend") {
        if cd.len() < 37 {
            return err("bad calldata", gas_limit);
        }
        let Some(proposal_id) = read32(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        let approve = cd[36] != 0;
        if storage
            .get(&treas_key("proposal.exists", &proposal_id))
            .map(|v| v[0])
            .unwrap_or(0)
            != 1
        {
            return err("no proposal", gas_limit);
        }
        let created = read_slot_u64(storage, treas_key("proposal.created", &proposal_id));
        if height > created.saturating_add(VOTING_PERIOD) {
            return err("voting closed", gas_limit);
        }
        let vkey = sha256(&{
            let mut d = [0u8; 64];
            d[..32].copy_from_slice(&proposal_id);
            d[32..].copy_from_slice(&caller);
            d
        });
        if storage.get(&vkey).map(|v| v[0]).unwrap_or(0) == 1 {
            return err("already voted", gas_limit);
        }
        // caller must be a validator with stake
        let stake: u64 = state
            .staking
            .get_active_validators()
            .iter()
            .find(|(pk, _)| account_id_from_pubkey(pk) == caller)
            .map(|(_, s)| *s)
            .unwrap_or(0);
        if stake == 0 {
            return err("zero stake", gas_limit);
        }
        diff.push((
            vkey,
            Some({
                let mut v = [0u8; 32];
                v[0] = 1;
                v
            }),
        ));
        if approve {
            let cur = read_slot_u64(storage, treas_key("proposal.votes_for", &proposal_id));
            diff.push((
                treas_key("proposal.votes_for", &proposal_id),
                Some(pack_u64(cur.saturating_add(stake))),
            ));
        } else {
            let cur = read_slot_u64(storage, treas_key("proposal.votes_against", &proposal_id));
            diff.push((
                treas_key("proposal.votes_against", &proposal_id),
                Some(pack_u64(cur.saturating_add(stake))),
            ));
        }
        return ok(
            vec![],
            diff,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            200,
        );
    }

    if s == sel("execute_spend") {
        if cd.len() < 36 {
            return err("bad calldata", gas_limit);
        }
        let Some(proposal_id) = read32(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        if storage
            .get(&treas_key("proposal.exists", &proposal_id))
            .map(|v| v[0])
            .unwrap_or(0)
            != 1
        {
            return err("no proposal", gas_limit);
        }
        if storage
            .get(&treas_key("proposal.executed", &proposal_id))
            .map(|v| v[0])
            .unwrap_or(0)
            == 1
        {
            return err("already executed", gas_limit);
        }
        let created = read_slot_u64(storage, treas_key("proposal.created", &proposal_id));
        if height <= created.saturating_add(VOTING_PERIOD) {
            return err("voting open", gas_limit);
        }
        let timelock = read_slot_u64(storage, treas_key("proposal.timelock", &proposal_id));
        if height < created.saturating_add(timelock) {
            return err("timelock", gas_limit);
        }
        let total_stake: u64 = state.staking.get_active_validators().values().sum();
        if total_stake == 0 {
            return err("zero stake", gas_limit);
        }
        let votes_for = read_slot_u64(storage, treas_key("proposal.votes_for", &proposal_id));
        let votes_against =
            read_slot_u64(storage, treas_key("proposal.votes_against", &proposal_id));
        let votes_total = votes_for.saturating_add(votes_against);
        if votes_total.saturating_mul(MIN_PART_DEN) < total_stake.saturating_mul(MIN_PART_NUM) {
            return err("quorum not met", gas_limit);
        }
        if votes_for.saturating_mul(APPROVAL_DEN) < votes_total.saturating_mul(APPROVAL_NUM) {
            return err("approval not met", gas_limit);
        }
        let recipient = storage
            .get(&treas_key("proposal.recipient", &proposal_id))
            .copied()
            .unwrap_or([0u8; 32]);
        let amount = read_slot_u128(storage, treas_key("proposal.amount", &proposal_id));
        if amount == 0 {
            return err("zero amount", gas_limit);
        }
        diff.push((
            treas_key("proposal.executed", &proposal_id),
            Some({
                let mut v = [0u8; 32];
                v[0] = 1;
                v
            }),
        ));
        let mut result = ok(
            vec![],
            diff,
            vec![],
            vec![],
            vec![(recipient, amount)],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            1000,
        );
        result.cell_debits.push((treasury_system_cell_id(), amount));
        return result;
    }

    err("unknown selector", gas_limit)
}

// ── Name registry cell ────────────────────────────────────────────────────────

fn name_registry(
    cd: &[u8],
    caller: AccountId,
    state: &crate::pq_execution::State,
    height: u64,
    gas_limit: u64,
) -> ExecutionResult {
    let s = read_sel(cd).unwrap_or_default();

    fn read_name(cd: &[u8], off: usize) -> Option<(String, usize)> {
        let len = *cd.get(off)? as usize;
        let start = off + 1;
        let end = start + len;
        if cd.len() < end {
            return None;
        }
        let name = std::str::from_utf8(&cd[start..end]).ok()?.to_string();
        Some((name, end))
    }

    if s == sel("propose_name") {
        let Some((name, off)) = read_name(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        let Some(target) = read32(cd, off) else {
            return err("bad calldata", gas_limit);
        };
        let Some(owner) = read32(cd, off + 32) else {
            return err("bad calldata", gas_limit);
        };
        if state.name_registry.contains_key(&name) || state.pending_names.contains_key(&name) {
            return err("name already registered or pending", gas_limit);
        }
        let reg = PendingNameRegistration {
            name: name.clone(),
            cell_id: target,
            owner,
            is_cell: false,
            proposer: caller.to_vec(),
            votes: Default::default(),
            total_stake_voted: 0,
            proposed_at: height,
        };
        return ok(
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![(name, reg, caller, false)],
            vec![],
            vec![],
            vec![],
            vec![],
            300,
        );
    }

    if s == sel("vote_name") {
        let Some((name, off)) = read_name(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        if cd.len() <= off {
            return err("bad calldata", gas_limit);
        }
        let approve = cd[off] != 0;
        let stake: u64 = state
            .staking
            .get_active_validators()
            .iter()
            .find(|(pk, _)| account_id_from_pubkey(pk) == caller)
            .map(|(_, s)| *s)
            .unwrap_or(0);
        return ok(
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![(name, caller.to_vec(), if approve { stake } else { 0 })],
            vec![],
            vec![],
            vec![],
            100,
        );
    }

    if s == sel("renew_name") {
        let Some((name, _)) = read_name(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        return ok(
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![(name, height)],
            vec![],
            vec![],
            100,
        );
    }

    if s == sel("transfer_name") {
        let Some((name, off)) = read_name(cd, 4) else {
            return err("bad calldata", gas_limit);
        };
        let Some(new_owner) = read32(cd, off) else {
            return err("bad calldata", gas_limit);
        };
        // only current owner can transfer
        if let Some(reg) = state.name_registry.get(&name) {
            if reg.owner != caller {
                return err("unauthorized", gas_limit);
            }
        } else {
            return err("name not found", gas_limit);
        }
        return ok(
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![(name, new_owner)],
            vec![],
            100,
        );
    }

    err("unknown selector", gas_limit)
}
