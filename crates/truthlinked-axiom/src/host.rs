//! Truthlinked Axiom Src Host
//!
//! Owns host interfaces exposed to Axiom programs.
//! VM and bytecode changes are consensus-sensitive and must remain deterministic across platforms.

use crate::error::AxiomError;
use alloc::vec::Vec;

/// Log entry emitted by a cell.
#[derive(Debug, Clone)]
pub struct CellLog {
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Result of a cross-cell call.
#[derive(Debug, Clone)]
pub struct CrossCellResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub gas_used: u64,
}

/// Staking side-effect queued by a cell.
#[derive(Debug, Clone)]
pub enum StakingOp {
    Stake { pubkey: Vec<u8>, amount: u64 },
    Unstake { pubkey: Vec<u8>, amount: u64 },
    Withdraw { pubkey: Vec<u8> },
    Unjail { pubkey: Vec<u8> },
}

/// Name-registry side-effect queued by a cell.
#[derive(Debug, Clone)]
pub enum NameOp {
    Propose {
        name: Vec<u8>,
        target: [u8; 32],
        owner: [u8; 32],
    },
    Vote {
        name: Vec<u8>,
        approve: bool,
    },
    Renew {
        name: Vec<u8>,
    },
    Transfer {
        name: Vec<u8>,
        new_owner: [u8; 32],
    },
}

/// Everything the VM needs from the chain.
pub trait Host {
    // ── Storage ─────────────────────────────────────────────────────────────
    fn storage_read(&self, key: &[u8; 32]) -> Result<[u8; 32], AxiomError>;
    fn storage_write(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(), AxiomError>;
    fn storage_delete(&mut self, key: &[u8; 32]) -> Result<(), AxiomError>;

    // ── Context ──────────────────────────────────────────────────────────────
    fn caller(&self) -> [u8; 32];
    fn owner(&self) -> [u8; 32];
    fn cell_id(&self) -> [u8; 32];
    fn height(&self) -> u64;
    fn timestamp(&self) -> u64;
    fn value(&self) -> u128;
    fn calldata(&self) -> &[u8];

    // ── Output ───────────────────────────────────────────────────────────────
    fn set_return_data(&mut self, data: Vec<u8>) -> Result<(), AxiomError>;
    fn emit_log(&mut self, log: CellLog) -> Result<(), AxiomError>;

    // ── Cross-cell ───────────────────────────────────────────────────────────
    fn call_cell(
        &mut self,
        cell_id: &[u8; 32],
        calldata: &[u8],
        value: u128,
        gas_limit: u64,
    ) -> Result<CrossCellResult, AxiomError>;

    // ── Crypto ───────────────────────────────────────────────────────────────
    fn sha256(&self, input: &[u8]) -> [u8; 32];

    // ── Privileged: staking (system cells only) ──────────────────────────────
    fn staking_op(&mut self, _op: StakingOp) -> Result<(), AxiomError> {
        Err(AxiomError::Unauthorized)
    }
    /// Returns active stake for a validator pubkey (u64, little-endian in low 8 bytes).
    fn staking_validator_stake(&self, _pubkey: &[u8]) -> Result<u64, AxiomError> {
        Err(AxiomError::Unauthorized)
    }
    /// Returns total active stake across all validators.
    fn staking_total_stake(&self) -> Result<u64, AxiomError> {
        Err(AxiomError::Unauthorized)
    }

    // ── Privileged: governance params (system cells only) ────────────────────
    fn governance_set_param(
        &mut self,
        _key: &[u8; 32],
        _value: &[u8; 32],
    ) -> Result<(), AxiomError> {
        Err(AxiomError::Unauthorized)
    }

    // ── Privileged: native transfer (system cells only) ──────────────────────
    fn native_transfer(&mut self, _to: &[u8; 32], _amount: u128) -> Result<(), AxiomError> {
        Err(AxiomError::Unauthorized)
    }

    // ── Privileged: name registry (system cells only) ────────────────────────
    fn name_op(&mut self, _op: NameOp) -> Result<(), AxiomError> {
        Err(AxiomError::Unauthorized)
    }

    // ── Accord ───────────────────────────────────────────────────────────────
    /// Queue an accord request. Returns the request_id in dst.
    fn accord_request(
        &mut self,
        _url: &[u8],
        _method: &[u8],
        _body: &[u8],
    ) -> Result<[u8; 32], AxiomError> {
        Err(AxiomError::NotImplemented(
            crate::opcode::tag::ACCORD_REQUEST,
        ))
    }

    /// Read a finalized accord result by request_id.
    /// Returns Ok(Some(body_bytes)) if result is ready, Ok(None) if still pending.
    fn accord_read(&self, _request_id: &[u8; 32]) -> Result<Option<Vec<u8>>, AxiomError> {
        Err(AxiomError::NotImplemented(crate::opcode::tag::ACCORD_READ))
    }

    // ── Token ops (metered, sandboxed) ───────────────────────────────────────
    fn token_balance(&self, _token: &[u8; 32], _account: &[u8; 32]) -> Result<u128, AxiomError> {
        Err(AxiomError::Unauthorized)
    }
    fn token_transfer(
        &mut self,
        _token: &[u8; 32],
        _from: &[u8; 32],
        _to: &[u8; 32],
        _amount: u128,
    ) -> Result<(), AxiomError> {
        Err(AxiomError::Unauthorized)
    }
    fn token_mint(
        &mut self,
        _token: &[u8; 32],
        _recipient: &[u8; 32],
        _amount: u128,
    ) -> Result<(), AxiomError> {
        Err(AxiomError::Unauthorized)
    }
    fn token_burn(
        &mut self,
        _token: &[u8; 32],
        _owner: &[u8; 32],
        _amount: u128,
    ) -> Result<(), AxiomError> {
        Err(AxiomError::Unauthorized)
    }
    fn token_freeze(&mut self, _token: &[u8; 32], _account: &[u8; 32]) -> Result<(), AxiomError> {
        Err(AxiomError::Unauthorized)
    }
    fn token_thaw(&mut self, _token: &[u8; 32], _account: &[u8; 32]) -> Result<(), AxiomError> {
        Err(AxiomError::Unauthorized)
    }

    // ── Limits ───────────────────────────────────────────────────────────────
    fn max_return_data(&self) -> usize {
        262_144
    }
    fn max_log_data(&self) -> usize {
        65_536
    }
    fn max_log_topics(&self) -> usize {
        8
    }
    /// Call depth limit. Each nested call costs 1,000 gas minimum, so depth 500
    /// requires at least 500,000 gas - natural economic deterrent against abuse.
    fn max_call_depth(&self) -> u32 {
        500
    }
}
