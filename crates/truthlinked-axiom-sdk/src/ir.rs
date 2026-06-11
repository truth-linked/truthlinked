//! Axiom IR - typed virtual instructions over virtual registers.
//!
//! The macro compiler emits IR; the regalloc pass assigns physical registers;
//! the codegen pass lowers IR + allocation to CellBuilder calls.
//!
//! Virtual register 0 is always the zero register (maps to physical r0).
//! Physical registers r1–r254 are allocatable. r255 is the scratch register
//! reserved for codegen (e.g. loading keys before sload/sstore).

/// A virtual register ID. 0 = zero reg (read-only).
pub type VReg = u32;

/// A label ID for forward/backward jumps.
pub type Label = u32;

/// Typed virtual instruction.
#[derive(Debug, Clone)]
pub enum Ir {
    // ── Arithmetic ───────────────────────────────────────────────────────────
    Add(VReg, VReg, VReg),
    Sub(VReg, VReg, VReg),
    Mul(VReg, VReg, VReg),
    Div(VReg, VReg, VReg),
    Mod(VReg, VReg, VReg),
    AddSat(VReg, VReg, VReg),
    SubSat(VReg, VReg, VReg),

    // ── Bitwise ──────────────────────────────────────────────────────────────
    And(VReg, VReg, VReg),
    Or(VReg, VReg, VReg),
    Xor(VReg, VReg, VReg),
    Not(VReg, VReg),
    Shl(VReg, VReg, u8),
    Shr(VReg, VReg, u8),

    // ── Comparison ───────────────────────────────────────────────────────────
    Eq(VReg, VReg, VReg),
    Ne(VReg, VReg, VReg),
    Lt(VReg, VReg, VReg),
    Lte(VReg, VReg, VReg),
    Gt(VReg, VReg, VReg),
    Gte(VReg, VReg, VReg),
    IsZero(VReg, VReg),

    // ── Control flow ─────────────────────────────────────────────────────────
    Label(Label),
    Jump(Label),
    JumpIf(VReg, Label),
    JumpIfNot(VReg, Label),
    /// Intra-cell subroutine call - pushes return address, jumps to label.
    Call(Label),
    /// Return from intra-cell subroutine.
    Return,
    Halt,
    Trap(u16),

    // ── Data ─────────────────────────────────────────────────────────────────
    /// Load a 32-byte constant value into a vreg.
    LoadConst(VReg, Vec<u8>),
    /// Load the const-pool INDEX of a blob into a vreg (low 2 bytes = u16 index).
    /// Used by ACCORD_REQUEST which reads url/body as const-pool indices.
    LoadConstIndex(VReg, Vec<u8>),
    LoadImm8(VReg, u8),
    LoadImm64(VReg, u64),
    Mov(VReg, VReg),

    // ── Storage ──────────────────────────────────────────────────────────────
    /// SLoad(dst, key_vreg)
    SLoad(VReg, VReg),
    /// SStore(key_vreg, val_vreg)
    SStore(VReg, VReg),
    SDelete(VReg),

    // ── Context ──────────────────────────────────────────────────────────────
    GetCaller(VReg),
    GetOwner(VReg),
    GetCellId(VReg),
    GetHeight(VReg),
    GetTimestamp(VReg),
    GetValue(VReg),
    GetCalldataLen(VReg),
    /// GetCalldata(dst, offset_vreg)
    GetCalldata(VReg, VReg),

    // ── Output ───────────────────────────────────────────────────────────────
    /// SetReturn(const_idx_vreg, len_vreg)
    SetReturn(VReg, VReg),
    SetReturnReg(VReg, VReg),
    /// EmitLog(topics_vreg, data_vreg)
    EmitLog(VReg, VReg),
    /// EmitLogReg(topic_vreg, data_vreg, len_vreg)
    EmitLogReg(VReg, VReg, VReg),

    // ── Cross-cell ───────────────────────────────────────────────────────────
    CallCell(VReg, VReg, VReg, VReg),
    /// Reset the call buffer.
    BufReset,
    /// Append a const-pool blob to the call buffer.
    BufWriteConst(Vec<u8>),
    /// Append 32 bytes from a register to the call buffer.
    BufWriteReg(VReg),
    /// Call a cell using the call buffer as calldata. Result flag → r1.
    BufCallCell(VReg, VReg),
    /// Set return data from the call buffer (multi-value return).
    BufSetReturn,

    // ── Crypto ───────────────────────────────────────────────────────────────
    Hash32(VReg, VReg),
    Hash32Const(VReg, Vec<u8>),

    // ── Access control ───────────────────────────────────────────────────────
    RequireOwner,
    RequireCaller(VReg),
    RequireEq(VReg, VReg),
    RequireNe(VReg, VReg),
    RequireLt(VReg, VReg),
    RequireNonZero(VReg),
    RequireGas(u64),

    // ── Token ops ────────────────────────────────────────────────────────────
    TokenBalance(VReg, VReg, VReg),
    TokenTransfer(VReg, VReg, VReg, VReg),
    TokenMint(VReg, VReg, VReg),
    TokenBurn(VReg, VReg, VReg),
    TokenFreeze(VReg, VReg),
    TokenThaw(VReg, VReg),

    // ── Accord ───────────────────────────────────────────────────────────────
    /// accord_request(dst, url_const_idx_reg, method_reg, body_const_idx_reg)
    AccordRequest(VReg, VReg, VReg, VReg),
    /// accord_read(dst, request_id_reg) → dst=body[0..32], r1=ready_bool
    AccordRead(VReg, VReg),
}

impl Ir {
    /// Returns the virtual register defined (written) by this instruction, if any.
    pub fn def(&self) -> Option<VReg> {
        match self {
            Ir::Add(d, _, _)
            | Ir::Sub(d, _, _)
            | Ir::Mul(d, _, _)
            | Ir::Div(d, _, _)
            | Ir::Mod(d, _, _)
            | Ir::AddSat(d, _, _)
            | Ir::SubSat(d, _, _)
            | Ir::And(d, _, _)
            | Ir::Or(d, _, _)
            | Ir::Xor(d, _, _)
            | Ir::Not(d, _)
            | Ir::Shl(d, _, _)
            | Ir::Shr(d, _, _)
            | Ir::Eq(d, _, _)
            | Ir::Ne(d, _, _)
            | Ir::Lt(d, _, _)
            | Ir::Lte(d, _, _)
            | Ir::Gt(d, _, _)
            | Ir::Gte(d, _, _)
            | Ir::IsZero(d, _)
            | Ir::LoadConst(d, _)
            | Ir::LoadConstIndex(d, _)
            | Ir::LoadImm8(d, _)
            | Ir::LoadImm64(d, _)
            | Ir::Mov(d, _)
            | Ir::SLoad(d, _)
            | Ir::GetCaller(d)
            | Ir::GetOwner(d)
            | Ir::GetCellId(d)
            | Ir::GetHeight(d)
            | Ir::GetTimestamp(d)
            | Ir::GetValue(d)
            | Ir::GetCalldataLen(d)
            | Ir::GetCalldata(d, _)
            | Ir::Hash32(d, _)
            | Ir::Hash32Const(d, _)
            | Ir::TokenBalance(d, _, _)
            | Ir::AccordRequest(d, _, _, _)
            | Ir::AccordRead(d, _) => {
                if *d != 0 {
                    Some(*d)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Returns all virtual registers used (read) by this instruction.
    pub fn uses(&self) -> Vec<VReg> {
        let mut v = Vec::new();
        let mut push = |r: VReg| {
            if r != 0 {
                v.push(r);
            }
        };
        match self {
            Ir::Add(_, a, b)
            | Ir::Sub(_, a, b)
            | Ir::Mul(_, a, b)
            | Ir::Div(_, a, b)
            | Ir::Mod(_, a, b)
            | Ir::AddSat(_, a, b)
            | Ir::SubSat(_, a, b)
            | Ir::And(_, a, b)
            | Ir::Or(_, a, b)
            | Ir::Xor(_, a, b)
            | Ir::Eq(_, a, b)
            | Ir::Ne(_, a, b)
            | Ir::Lt(_, a, b)
            | Ir::Lte(_, a, b)
            | Ir::Gt(_, a, b)
            | Ir::Gte(_, a, b) => {
                push(*a);
                push(*b);
            }
            Ir::Not(_, a)
            | Ir::IsZero(_, a)
            | Ir::Shl(_, a, _)
            | Ir::Shr(_, a, _)
            | Ir::Mov(_, a)
            | Ir::SLoad(_, a)
            | Ir::SDelete(a)
            | Ir::GetCalldata(_, a)
            | Ir::Hash32(_, a)
            | Ir::RequireCaller(a)
            | Ir::RequireNonZero(a) => {
                push(*a);
            }
            Ir::SStore(k, v2)
            | Ir::RequireEq(k, v2)
            | Ir::RequireNe(k, v2)
            | Ir::RequireLt(k, v2)
            | Ir::SetReturn(k, v2)
            | Ir::SetReturnReg(k, v2)
            | Ir::EmitLog(k, v2)
            | Ir::TokenFreeze(k, v2)
            | Ir::TokenThaw(k, v2) => {
                push(*k);
                push(*v2);
            }
            Ir::EmitLogReg(t, d, l) => {
                push(*t);
                push(*d);
                push(*l);
            }
            Ir::JumpIf(c, _) | Ir::JumpIfNot(c, _) => {
                push(*c);
            }
            Ir::TokenBalance(_, t, a) | Ir::TokenMint(_, t, a) | Ir::TokenBurn(_, t, a) => {
                push(*t);
                push(*a);
            }
            Ir::TokenTransfer(tok, f, t, a) => {
                push(*tok);
                push(*f);
                push(*t);
                push(*a);
            }
            Ir::AccordRequest(_, url, meth, body) => {
                push(*url);
                push(*meth);
                push(*body);
            }
            Ir::AccordRead(_, req) => {
                push(*req);
            }
            Ir::CallCell(cell, cd, len, val) => {
                push(*cell);
                push(*cd);
                push(*len);
                push(*val);
            }
            Ir::BufWriteReg(src) => {
                push(*src);
            }
            Ir::BufCallCell(cell, val) => {
                push(*cell);
                push(*val);
            }
            _ => {}
        }
        v
    }
}
