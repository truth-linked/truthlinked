//! Axiom host bridge - connects AxiomVm to TruthLinked state.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};
use truthlinked_axiom::error::AxiomError;
use truthlinked_axiom::host::{CellLog, CrossCellResult, Host, NameOp, StakingOp};
use truthlinked_axiom::{CellBytecode, Vm};
use truthlinked_governance::PendingNameRegistration;
use truthlinked_runtime::cells::CellState;
use truthlinked_runtime::types::StakingUpdate;

use crate::cells::ExecutionResult;
use crate::log::Log;
use crate::pq_execution::State;

pub struct AxiomHost<'a> {
    pub storage: &'a mut HashMap<[u8; 32], [u8; 32]>,
    pub storage_diff: Vec<([u8; 32], Option<[u8; 32]>)>,
    pub caller: [u8; 32],
    pub owner: [u8; 32],
    pub cell_id: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub value: u128,
    pub calldata: Vec<u8>,
    pub return_data: Vec<u8>,
    pub logs: Vec<Log>,
    pub execution_depth: u32,
    pub gas_limit: u64,
    pub global_state: Option<Arc<State>>,
    pub cell_state: Option<Arc<RwLock<CellState>>>,
    // privileged side-effects
    pub staking_updates: Vec<StakingUpdate>,
    pub param_updates: Vec<([u8; 32], [u8; 32])>,
    pub native_credits: Vec<([u8; 32], u128)>,
    pub pending_name_proposals: Vec<(String, PendingNameRegistration, [u8; 32], bool)>,
    pub name_votes: Vec<(String, Vec<u8>, u64)>,
    pub name_renewals: Vec<(String, u64)>,
    pub name_transfers: Vec<(String, [u8; 32])>,
    pub is_system_cell: bool,
    pub oracle_updates: Vec<truthlinked_runtime::types::OracleUpdate>,
}

impl<'a> Host for AxiomHost<'a> {
    fn storage_read(&self, key: &[u8; 32]) -> Result<[u8; 32], AxiomError> {
        Ok(self.storage.get(key).copied().unwrap_or([0u8; 32]))
    }

    fn storage_write(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(), AxiomError> {
        self.storage.insert(*key, *value);
        self.storage_diff.push((*key, Some(*value)));
        Ok(())
    }

    fn storage_delete(&mut self, key: &[u8; 32]) -> Result<(), AxiomError> {
        self.storage.remove(key);
        self.storage_diff.push((*key, None));
        Ok(())
    }

    fn caller(&self) -> [u8; 32] {
        self.caller
    }
    fn owner(&self) -> [u8; 32] {
        self.owner
    }
    fn cell_id(&self) -> [u8; 32] {
        self.cell_id
    }
    fn height(&self) -> u64 {
        self.height
    }
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
    fn value(&self) -> u128 {
        self.value
    }
    fn calldata(&self) -> &[u8] {
        &self.calldata
    }

    fn set_return_data(&mut self, data: Vec<u8>) -> Result<(), AxiomError> {
        self.return_data = data;
        Ok(())
    }

    fn emit_log(&mut self, log: CellLog) -> Result<(), AxiomError> {
        self.logs.push(Log {
            topics: log.topics,
            data: log.data,
        });
        Ok(())
    }

    fn call_cell(
        &mut self,
        cell_id: &[u8; 32],
        calldata: &[u8],
        value: u128,
        gas_limit: u64,
    ) -> Result<CrossCellResult, AxiomError> {
        let gs = self
            .global_state
            .clone()
            .ok_or_else(|| AxiomError::CrossCellFailed("no global state".into()))?;
        let cs = self
            .cell_state
            .clone()
            .ok_or_else(|| AxiomError::CrossCellFailed("no cell state".into()))?;
        let cell = {
            let guard = cs
                .read()
                .map_err(|_| AxiomError::CrossCellFailed("lock poisoned".into()))?;
            guard
                .cells
                .get(cell_id)
                .cloned()
                .ok_or_else(|| AxiomError::CrossCellFailed("cell not found".into()))?
        };
        let result = execute_axiom(
            &cell.bytecode,
            cell.storage.clone(),
            cell.cell_id,
            cell.owner,
            self.caller,
            self.height,
            self.timestamp,
            calldata,
            value,
            gas_limit,
            self.execution_depth + 1,
            Some(gs),
            Some(cs),
        );
        Ok(CrossCellResult {
            success: result.success,
            return_data: result.return_data,
            gas_used: result.gas_used,
        })
    }

    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(input);
        h.finalize().into()
    }

    fn staking_op(&mut self, op: StakingOp) -> Result<(), AxiomError> {
        if !self.is_system_cell {
            return Err(AxiomError::Unauthorized);
        }
        let update = match op {
            StakingOp::Stake { pubkey, amount } => StakingUpdate::Stake {
                validator: pubkey,
                amount,
            },
            StakingOp::Unstake { pubkey, amount } => StakingUpdate::Unstake {
                validator: pubkey,
                amount,
            },
            StakingOp::Withdraw { pubkey } => StakingUpdate::Withdraw { validator: pubkey },
            StakingOp::Unjail { pubkey } => StakingUpdate::Unjail { validator: pubkey },
        };
        self.staking_updates.push(update);
        Ok(())
    }

    fn staking_validator_stake(&self, pubkey: &[u8]) -> Result<u64, AxiomError> {
        if !self.is_system_cell {
            return Err(AxiomError::Unauthorized);
        }
        let gs = self
            .global_state
            .as_ref()
            .ok_or_else(|| AxiomError::CrossCellFailed("no global state".into()))?;
        Ok(gs
            .staking
            .validators
            .get(pubkey)
            .map(|v| v.total_stake())
            .unwrap_or(0))
    }

    fn staking_total_stake(&self) -> Result<u64, AxiomError> {
        if !self.is_system_cell {
            return Err(AxiomError::Unauthorized);
        }
        let gs = self
            .global_state
            .as_ref()
            .ok_or_else(|| AxiomError::CrossCellFailed("no global state".into()))?;
        Ok(gs.staking.get_active_validators().values().sum())
    }

    fn governance_set_param(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(), AxiomError> {
        if !self.is_system_cell {
            return Err(AxiomError::Unauthorized);
        }
        self.param_updates.push((*key, *value));
        Ok(())
    }

    fn native_transfer(&mut self, to: &[u8; 32], amount: u128) -> Result<(), AxiomError> {
        if !self.is_system_cell {
            return Err(AxiomError::Unauthorized);
        }
        self.native_credits.push((*to, amount));
        Ok(())
    }

    fn name_op(&mut self, op: NameOp) -> Result<(), AxiomError> {
        if !self.is_system_cell {
            return Err(AxiomError::Unauthorized);
        }
        match op {
            NameOp::Propose {
                name,
                target,
                owner,
            } => {
                let name_str = String::from_utf8(name).map_err(|_| AxiomError::AssertFailed)?;
                let reg = PendingNameRegistration {
                    name: name_str.clone(),
                    cell_id: target,
                    owner,
                    is_cell: false,
                    proposer: self.caller.to_vec(),
                    votes: Default::default(),
                    total_stake_voted: 0,
                    proposed_at: self.height,
                };
                self.pending_name_proposals
                    .push((name_str, reg, self.caller, false));
            }
            NameOp::Vote { name, approve } => {
                let name_str = String::from_utf8(name).map_err(|_| AxiomError::AssertFailed)?;
                let stake = self.staking_validator_stake(&self.caller.clone())?;
                self.name_votes.push((
                    name_str,
                    self.caller.to_vec(),
                    if approve { stake } else { 0 },
                ));
            }
            NameOp::Renew { name } => {
                let name_str = String::from_utf8(name).map_err(|_| AxiomError::AssertFailed)?;
                self.name_renewals.push((name_str, self.height));
            }
            NameOp::Transfer { name, new_owner } => {
                let name_str = String::from_utf8(name).map_err(|_| AxiomError::AssertFailed)?;
                self.name_transfers.push((name_str, new_owner));
            }
        }
        Ok(())
    }

    fn accord_request(
        &mut self,
        url: &[u8],
        method: &[u8],
        body: &[u8],
    ) -> Result<[u8; 32], AxiomError> {
        use truthlinked_governance::CellVisibility;
        use truthlinked_oracle::http_oracle::{
            check_url_permitted, queue_oracle_request, url_response_format, url_schema_id,
        };

        let url_str = std::str::from_utf8(url).map_err(|_| AxiomError::InvalidBytecode)?;
        let method_str = std::str::from_utf8(method).map_err(|_| AxiomError::InvalidBytecode)?;

        // URL governance check for public cells
        let (_visibility, response_format, schema_id) = if let Some(ref gs) = self.global_state {
            let vis = gs
                .cell_visibility
                .get(&self.cell_id)
                .copied()
                .unwrap_or(CellVisibility::Private);
            if !check_url_permitted(url_str, vis, &gs.url_proposals) {
                return Err(AxiomError::Unauthorized);
            }

            // Rate limit: private (non-governance-approved) cells may have at most 5
            // pending accord requests at a time. Public cells have no per-cell cap
            // (governed by the URL approval process instead).
            if vis == CellVisibility::Private {
                const PRIVATE_ACCORD_LIMIT: usize = 5;
                let pending_for_cell = gs
                    .pending_oracle_requests
                    .values()
                    .filter(|r| r.requesting_cell == self.cell_id)
                    .count();
                if pending_for_cell >= PRIVATE_ACCORD_LIMIT {
                    return Err(AxiomError::Unauthorized);
                }
            }

            let mut fmt = url_response_format(url_str, vis, &gs.url_proposals);
            if url_str.contains("accord_format=price_usd") {
                fmt = truthlinked_governance::UrlResponseFormat::PriceUsd;
            }
            let sid = url_schema_id(url_str, vis, &gs.url_proposals);
            (vis, fmt, sid)
        } else {
            (
                CellVisibility::Private,
                truthlinked_governance::UrlResponseFormat::Raw,
                None,
            )
        };

        let req = queue_oracle_request(
            url_str.to_string(),
            method_str.to_string(),
            body.to_vec(),
            response_format,
            schema_id,
            self.cell_id,
            self.height,
        );
        let req_id = req.request_id;
        self.oracle_updates
            .push(truthlinked_runtime::types::OracleUpdate::QueueRequest(req));
        Ok(req_id)
    }

    fn accord_read(&self, request_id: &[u8; 32]) -> Result<Option<Vec<u8>>, AxiomError> {
        if let Some(gs) = &self.global_state {
            if let Some(result) = gs.oracle_results.get(request_id) {
                if !result.is_expired(self.height) {
                    return Ok(Some(result.response_body.clone()));
                }
            }
        }

        if let Some(result) = crate::pq_execution::get_oracle_result(request_id) {
            if !result.is_expired(self.height) {
                return Ok(Some(result.response_body));
            }
        }

        Ok(None)
    }

    fn max_call_depth(&self) -> u32 {
        500
    }
}

/// Execute a Axiom cell.
pub fn execute_axiom(
    bytecode: &[u8],
    mut storage: HashMap<[u8; 32], [u8; 32]>,
    cell_id: [u8; 32],
    owner: [u8; 32],
    caller: [u8; 32],
    height: u64,
    timestamp: u64,
    calldata: &[u8],
    value: u128,
    gas_limit: u64,
    execution_depth: u32,
    global_state: Option<Arc<State>>,
    cell_state: Option<Arc<RwLock<CellState>>>,
) -> ExecutionResult {
    let cell = match CellBytecode::decode(bytecode) {
        Ok(c) => c,
        Err(e) => {
            return ExecutionResult {
                success: false,
                error: Some(format!("Axiom decode error: {:?}", e)),
                ..ExecutionResult::default()
            }
        }
    };

    let is_system = crate::pq_execution::is_system_cell(&cell_id);

    let mut host = AxiomHost {
        storage: &mut storage,
        storage_diff: Vec::new(),
        caller,
        owner,
        cell_id,
        height,
        timestamp,
        value,
        calldata: calldata.to_vec(),
        return_data: Vec::new(),
        logs: Vec::new(),
        execution_depth,
        gas_limit,
        global_state,
        cell_state,
        staking_updates: Vec::new(),
        param_updates: Vec::new(),
        native_credits: Vec::new(),
        pending_name_proposals: Vec::new(),
        name_votes: Vec::new(),
        name_renewals: Vec::new(),
        name_transfers: Vec::new(),
        is_system_cell: is_system,
        oracle_updates: Vec::new(),
    };

    let mut vm = Vm::new(&mut host, gas_limit, execution_depth);
    let res = vm.execute(&cell);

    ExecutionResult {
        success: res.success,
        return_data: host.return_data,
        gas_used: res.gas_used,
        storage_diff: host.storage_diff,
        logs: host.logs,
        staking_updates: host.staking_updates,
        param_updates: host.param_updates,
        native_credits: host.native_credits,
        pending_name_proposals: host.pending_name_proposals,
        name_votes: host.name_votes,
        name_renewals: host.name_renewals,
        name_transfers: host.name_transfers,
        oracle_updates: host.oracle_updates,
        error: res.error.map(|e| format!("{:?}", e)),
        ..ExecutionResult::default()
    }
}
