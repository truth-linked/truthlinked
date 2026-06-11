//! Truthlinked State Src Cells
//!
//! Owns cell state, addressing, and execution-facing helpers.
//! State changes are consensus-sensitive and must preserve deterministic execution and serialization.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use truthlinked_core::pq_execution::AccountId;
use truthlinked_runtime::cells::{CellAccount, CellState};

use crate::log::Log;
use truthlinked_governance::{PendingNameRegistration, TokenAuthorityProposal};
use truthlinked_oracle::http_oracle::OracleRequest;
use truthlinked_runtime::types::{OracleUpdate, StakingUpdate};

/// Simple cell intent wrapper for host-invoked execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CellIntent {
    Call {
        calldata: Vec<u8>,
        value: u128,
        gas_limit: u64,
    },
}

/// Unified execution result for Axiom VM + token hooks.
#[derive(Debug, Clone, Default)]
pub struct ExecutionResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub storage_diff: Vec<([u8; 32], Option<[u8; 32]>)>,
    pub queued_oracle_requests: Vec<OracleRequest>,
    pub staking_updates: Vec<StakingUpdate>,
    pub native_credits: Vec<([u8; 32], u128)>,
    pub native_debits: Vec<([u8; 32], u128)>,
    pub cell_debits: Vec<([u8; 32], u128)>,
    pub name_fee: u128,
    pub pending_name_proposals: Vec<(String, PendingNameRegistration, [u8; 32], bool)>,
    pub name_votes: Vec<(String, Vec<u8>, u64)>,
    pub name_renewals: Vec<(String, u64)>,
    pub name_transfers: Vec<(String, [u8; 32])>,
    pub pending_token_authority_proposals: Vec<([u8; 32], TokenAuthorityProposal)>,
    pub token_authority_votes: Vec<([u8; 32], Vec<u8>, u64)>,
    pub oracle_updates: Vec<OracleUpdate>,
    pub param_updates: Vec<([u8; 32], [u8; 32])>,
    pub logs: Vec<Log>,
    pub error: Option<String>,
    pub accessed_reads: Vec<[u8; 32]>,
    pub accessed_writes: Vec<[u8; 32]>,
}

pub struct TokenExecutor;

impl TokenExecutor {
    pub fn transfer(
        token: &CellAccount,
        sender: AccountId,
        recipient: AccountId,
        amount: u128,
        balances: &mut HashMap<AccountId, u128>,
        cell_state: Option<&CellState>,
        _height: u64,
        _timestamp: u64,
    ) -> Result<ExecutionResult, String> {
        if !token.is_token {
            return Err("Not a token cell".to_string());
        }
        let config = token.token_config.as_ref().ok_or("Token config missing")?;
        if config.non_transferable {
            return Err("Token is non-transferable".to_string());
        }
        if let Some(state) = cell_state {
            if state
                .frozen_accounts
                .get(&(token.cell_id, sender))
                .copied()
                .unwrap_or(false)
            {
                return Err("Sender account is frozen".to_string());
            }
            if state
                .frozen_accounts
                .get(&(token.cell_id, recipient))
                .copied()
                .unwrap_or(false)
            {
                return Err("Recipient account is frozen".to_string());
            }
        }

        let sender_bal = balances.get(&sender).copied().unwrap_or(0);
        if sender_bal < amount {
            return Err("Insufficient token balance".to_string());
        }

        let fee = if config.transfer_fee_bps == 0 {
            0
        } else {
            amount
                .checked_mul(config.transfer_fee_bps as u128)
                .ok_or("Transfer fee overflow")?
                / 10_000u128
        };
        if fee > amount {
            return Err("Transfer fee exceeds amount".to_string());
        }
        let net = amount - fee;

        balances.insert(sender, sender_bal - amount);
        let recipient_bal = balances.get(&recipient).copied().unwrap_or(0);
        balances.insert(recipient, recipient_bal.saturating_add(net));

        if fee > 0 {
            if let Some(fee_recipient) = config.transfer_fee_recipient {
                let fee_bal = balances.get(&fee_recipient).copied().unwrap_or(0);
                balances.insert(fee_recipient, fee_bal.saturating_add(fee));
            }
        }

        Ok(ExecutionResult {
            success: true,
            ..ExecutionResult::default()
        })
    }

    pub fn mint(
        token: &mut CellAccount,
        sender: AccountId,
        recipient: AccountId,
        amount: u128,
        balances: &mut HashMap<AccountId, u128>,
    ) -> Result<ExecutionResult, String> {
        if !token.is_token {
            return Err("Not a token cell".to_string());
        }
        let config = token.token_config.as_ref().ok_or("Token config missing")?;
        if let Some(authority) = config.mint_authority {
            if authority != sender {
                return Err("Unauthorized mint".to_string());
            }
        } else {
            return Err("Token has no mint authority".to_string());
        }

        let recipient_bal = balances.get(&recipient).copied().unwrap_or(0);
        balances.insert(recipient, recipient_bal.saturating_add(amount));

        if let Some(cfg) = token.token_config.as_mut() {
            let new_supply = cfg
                .total_supply
                .checked_add(amount)
                .ok_or("Total supply overflow")?;
            // Hard cap: max_supply if set, otherwise 1B TLKD (1_000_000_000 * 10^9 xiom)
            const ABSOLUTE_MAX: u128 = 1_000_000_000 * 1_000_000_000u128;
            let cap = cfg.max_supply.unwrap_or(ABSOLUTE_MAX).min(ABSOLUTE_MAX);
            if new_supply > cap {
                return Err(format!("Mint would exceed max supply ({} xiom)", cap));
            }
            cfg.total_supply = new_supply;
        }

        Ok(ExecutionResult {
            success: true,
            ..ExecutionResult::default()
        })
    }

    pub fn burn(
        token: &mut CellAccount,
        sender: AccountId,
        amount: u128,
        balances: &mut HashMap<AccountId, u128>,
    ) -> Result<ExecutionResult, String> {
        if !token.is_token {
            return Err("Not a token cell".to_string());
        }
        let sender_bal = balances.get(&sender).copied().unwrap_or(0);
        if sender_bal < amount {
            return Err("Insufficient token balance".to_string());
        }
        balances.insert(sender, sender_bal - amount);
        if let Some(cfg) = token.token_config.as_mut() {
            cfg.total_supply = cfg
                .total_supply
                .checked_sub(amount)
                .ok_or("Total supply underflow")?;
        }
        Ok(ExecutionResult {
            success: true,
            ..ExecutionResult::default()
        })
    }

    pub fn freeze(
        token: &CellAccount,
        sender: AccountId,
        _account: AccountId,
    ) -> Result<(), String> {
        if !token.is_token {
            return Err("Not a token cell".to_string());
        }
        let config = token.token_config.as_ref().ok_or("Token config missing")?;
        if let Some(authority) = config.freeze_authority {
            if authority != sender {
                return Err("Unauthorized freeze".to_string());
            }
        } else {
            return Err("Token has no freeze authority".to_string());
        }
        Ok(())
    }

    pub fn thaw(token: &CellAccount, sender: AccountId, _account: AccountId) -> Result<(), String> {
        if !token.is_token {
            return Err("Not a token cell".to_string());
        }
        let config = token.token_config.as_ref().ok_or("Token config missing")?;
        if let Some(authority) = config.freeze_authority {
            if authority != sender {
                return Err("Unauthorized thaw".to_string());
            }
        } else {
            return Err("Token has no freeze authority".to_string());
        }
        Ok(())
    }
}

pub struct ComposabilityEngine;

impl ComposabilityEngine {
    pub fn execute_call_chain(
        cells: &mut CellState,
        calls: &[truthlinked_core::pq_execution::CellCall],
        sender: AccountId,
        height: u64,
        gas_limit: u64,
        global_state: Option<Arc<crate::State>>,
    ) -> Result<Vec<ExecutionResult>, String> {
        let mut results: Vec<ExecutionResult> = Vec::new();
        let mut remaining_gas = gas_limit;
        let cell_state = Arc::new(RwLock::new(cells.clone()));

        for (idx, call) in calls.iter().enumerate() {
            if remaining_gas == 0 {
                return Err("Insufficient gas for call chain".to_string());
            }

            let calldata = if let Some(prev) = call.use_result_from {
                if prev >= results.len() {
                    return Err("Invalid use_result_from index".to_string());
                }
                results[prev].return_data.clone()
            } else {
                call.calldata.clone()
            };

            let cell = {
                let guard = cell_state
                    .read()
                    .map_err(|_| "Cell state lock poisoned".to_string())?;
                guard
                    .cells
                    .get(&call.cell_id)
                    .cloned()
                    .ok_or_else(|| format!("Cell not found in call chain at index {}", idx))?
            };

            let result = crate::vm::axiom_runtime::execute_axiom(
                &cell.bytecode,
                cell.storage.clone(),
                cell.cell_id,
                cell.owner,
                sender,
                height,
                0,
                &calldata,
                call.value,
                remaining_gas,
                1,
                global_state.clone(),
                Some(cell_state.clone()),
            );

            if !result.success {
                return Err(result
                    .error
                    .unwrap_or_else(|| "Call chain failed".to_string()));
            }

            if result.gas_used > remaining_gas {
                return Err("Call chain gas limit exceeded".to_string());
            }
            remaining_gas = remaining_gas.saturating_sub(result.gas_used);

            {
                let mut guard = cell_state
                    .write()
                    .map_err(|_| "Cell state lock poisoned".to_string())?;
                let target = guard
                    .cells
                    .get_mut(&call.cell_id)
                    .ok_or("Cell missing during call chain apply")?;
                for (key, value_opt) in &result.storage_diff {
                    match value_opt {
                        Some(v) => {
                            target.storage.insert(*key, *v);
                        }
                        None => {
                            target.storage.remove(key);
                        }
                    }
                }
                if call.value > 0 {
                    target.balance = target
                        .balance
                        .checked_add(call.value)
                        .ok_or("Cell balance overflow")?;
                }
            }

            results.push(result);
        }

        let final_state = cell_state
            .read()
            .map_err(|_| "Cell state lock poisoned".to_string())?
            .clone();
        *cells = final_state;

        Ok(results)
    }
}
