//! Truthlinked Axiom Src Gas
//!
//! Owns gas accounting rules for Axiom execution.
//! VM and bytecode changes are consensus-sensitive and must remain deterministic across platforms.

use crate::error::AxiomError;
use crate::opcode::Op;

/// Gas cost per operation. Deducted BEFORE execution.
pub fn op_cost(op: &Op) -> u64 {
    match op {
        // Arithmetic
        Op::Add(..) | Op::Sub(..) | Op::AddSat(..) | Op::SubSat(..) => 3,
        Op::Mul(..) => 5,
        Op::Div(..) | Op::Mod(..) => 8,
        // Bitwise
        Op::And(..) | Op::Or(..) | Op::Xor(..) | Op::Not(..) | Op::Shl(..) | Op::Shr(..) => 2,
        // Comparison
        Op::Eq(..)
        | Op::Ne(..)
        | Op::Lt(..)
        | Op::Lte(..)
        | Op::Gt(..)
        | Op::Gte(..)
        | Op::IsZero(..) => 2,
        // Control flow
        Op::Jump(..) | Op::JumpIf(..) | Op::JumpIfNot(..) => 2,
        Op::Call(..) | Op::Return => 5,
        Op::Halt => 1,
        Op::Trap(..) => 1,
        // Data
        Op::LoadConst(..) | Op::LoadImm8(..) | Op::LoadImm64(..) | Op::Move(..) | Op::Swap(..) => 1,
        // Storage - most expensive, reflects state I/O cost
        Op::SLoad(..) => 200,
        Op::SStore(..) => 500,
        Op::SDelete(..) => 300,
        // Context reads - cheap
        Op::GetCaller(..)
        | Op::GetOwner(..)
        | Op::GetCellId(..)
        | Op::GetHeight(..)
        | Op::GetTimestamp(..)
        | Op::GetValue(..)
        | Op::GetCalldataLen(..)
        | Op::GetCalldata(..) => 3,
        // Output
        Op::SetReturn(..) | Op::SetReturnReg(..) => 10,
        Op::EmitLog(..) | Op::EmitLogReg(..) => 100,
        // Cross-cell - base cost, callee gas is additional
        Op::CallCell(..) => 1_000,
        // Call buffer
        Op::BufReset => 1,
        Op::BufWriteConst(..) => 2,
        Op::BufWriteReg(..) => 2,
        Op::BufCallCell(..) => 1_000,
        Op::BufSetReturn => 10,
        // Crypto - SHA-256 is ~50 cycles of work
        Op::Hash32(..) | Op::Hash32Const(..) => 50,
        // Access control - just comparisons
        Op::RequireOwner
        | Op::RequireCaller(..)
        | Op::RequireEq(..)
        | Op::RequireNe(..)
        | Op::RequireLt(..)
        | Op::RequireNonZero(..)
        | Op::RequireGas(..) => 2,
        // Token ops
        Op::TokenBalance(..) => 200,
        Op::TokenTransfer(..) | Op::TokenMint(..) | Op::TokenBurn(..) => 500,
        Op::TokenFreeze(..) | Op::TokenThaw(..) => 300,
        // Accord
        Op::AccordRequest(..) => 10_000,
        Op::AccordRead(..) => 500,
    }
}

pub struct GasMeter {
    remaining: u64,
    limit: u64,
}

impl GasMeter {
    pub fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            limit,
        }
    }

    /// Deduct gas for an op BEFORE executing it.
    /// Returns Err(OutOfGas) if insufficient.
    #[inline]
    pub fn charge(&mut self, op: &Op) -> Result<(), AxiomError> {
        let cost = op_cost(op);
        self.charge_raw(cost)
    }

    #[inline]
    pub fn charge_raw(&mut self, cost: u64) -> Result<(), AxiomError> {
        self.remaining = self
            .remaining
            .checked_sub(cost)
            .ok_or(AxiomError::OutOfGas)?;
        Ok(())
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub fn used(&self) -> u64 {
        self.limit - self.remaining
    }
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Check threshold without deducting (for RequireGas opcode).
    pub fn has_at_least(&self, amount: u64) -> bool {
        self.remaining >= amount
    }
}
