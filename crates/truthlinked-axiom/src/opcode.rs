//! Truthlinked Axiom Src Opcode
//!
//! Owns the canonical opcode set and instruction metadata.
//! VM and bytecode changes are consensus-sensitive and must remain deterministic across platforms.

/// Register index - 256 general-purpose registers, each holds a [u8; 32].
/// r0 is always zero (read-only). Writes to r0 are silently discarded.
pub type Reg = u8;

/// Wide register pair for u256 ops: (hi_reg, lo_reg).
pub type WideReg = (Reg, Reg);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    // ── Arithmetic ───────────────────────────────────────────────────────────
    Add(Reg, Reg, Reg),
    Sub(Reg, Reg, Reg),
    Mul(Reg, Reg, Reg),
    Div(Reg, Reg, Reg),
    Mod(Reg, Reg, Reg),
    AddSat(Reg, Reg, Reg),
    SubSat(Reg, Reg, Reg),

    // ── Bitwise ──────────────────────────────────────────────────────────────
    And(Reg, Reg, Reg),
    Or(Reg, Reg, Reg),
    Xor(Reg, Reg, Reg),
    Not(Reg, Reg),
    Shl(Reg, Reg, u8),
    Shr(Reg, Reg, u8),

    // ── Comparison ───────────────────────────────────────────────────────────
    Eq(Reg, Reg, Reg),
    Ne(Reg, Reg, Reg),
    Lt(Reg, Reg, Reg),
    Lte(Reg, Reg, Reg),
    Gt(Reg, Reg, Reg),
    Gte(Reg, Reg, Reg),
    IsZero(Reg, Reg),

    // ── Control flow ─────────────────────────────────────────────────────────
    Jump(u32),
    JumpIf(Reg, u32),
    JumpIfNot(Reg, u32),
    Call(u32),
    Return,
    Halt,
    Trap(u16),

    // ── Data ─────────────────────────────────────────────────────────────────
    LoadConst(Reg, u16),
    LoadImm8(Reg, u8),
    LoadImm64(Reg, u64),
    Move(Reg, Reg),
    Swap(Reg, Reg),

    // ── Storage ──────────────────────────────────────────────────────────────
    SLoad(Reg, Reg),
    SStore(Reg, Reg),
    SDelete(Reg),

    // ── Context ──────────────────────────────────────────────────────────────
    GetCaller(Reg),
    GetOwner(Reg),
    GetCellId(Reg),
    GetHeight(Reg),
    GetTimestamp(Reg),
    GetValue(Reg),
    GetCalldataLen(Reg),
    GetCalldata(Reg, Reg),

    // ── Output ───────────────────────────────────────────────────────────────
    SetReturn(Reg, Reg),
    /// set_return_data from register (data_reg holds ptr into calldata, len_reg holds length)
    SetReturnReg(Reg, Reg),
    EmitLog(Reg, Reg),
    /// emit_log with topic, data, and length from registers
    EmitLogReg(Reg, Reg, Reg),

    // ── Cross-cell ───────────────────────────────────────────────────────────
    CallCell(Reg, Reg, Reg, Reg),
    /// Reset the call buffer and set write cursor to 0.
    BufReset,
    /// Append a const-pool entry (arbitrary bytes) to the call buffer.
    BufWriteConst(u16),
    /// Append 32 bytes from a register to the call buffer.
    BufWriteReg(Reg),
    /// Call a cell using the call buffer as calldata.
    /// BufCallCell(cell_reg, value_reg) - result flag written to r1.
    BufCallCell(Reg, Reg),
    /// Set return data from the call buffer contents.
    BufSetReturn,

    // ── Crypto ───────────────────────────────────────────────────────────────
    Hash32(Reg, Reg),
    Hash32Const(Reg, u16),

    // ── Access control ───────────────────────────────────────────────────────
    RequireOwner,
    RequireCaller(Reg),
    RequireEq(Reg, Reg),
    RequireNe(Reg, Reg),
    RequireLt(Reg, Reg),
    RequireNonZero(Reg),
    RequireGas(u64),

    // ── Token ops ────────────────────────────────────────────────────────────
    /// dst = token_balance(token_reg, account_reg)  → u128 in low 16 bytes
    TokenBalance(Reg, Reg, Reg),
    /// token_transfer(token_reg, from_reg, to_reg, amount_reg)
    TokenTransfer(Reg, Reg, Reg, Reg),
    /// token_mint(token_reg, recipient_reg, amount_reg)
    TokenMint(Reg, Reg, Reg),
    /// token_burn(token_reg, owner_reg, amount_reg)
    TokenBurn(Reg, Reg, Reg),
    /// token_freeze(token_reg, account_reg)
    TokenFreeze(Reg, Reg),
    /// token_thaw(token_reg, account_reg)
    TokenThaw(Reg, Reg),

    // ── Accord (external data consensus) ─────────────────────────────────────
    /// Submit an accord request. Returns request_id in dst.
    /// accord_request(dst_reg, url_const_idx_reg, method_reg, body_const_idx_reg)
    AccordRequest(Reg, Reg, Reg, Reg),
    /// Read accord response into dst. Returns 0 if pending, 1 if ready.
    /// accord_read(dst_reg, request_id_reg)
    AccordRead(Reg, Reg),
}

/// Opcode byte tags for encoding/decoding.
pub mod tag {
    pub const ADD: u8 = 0x01;
    pub const SUB: u8 = 0x02;
    pub const MUL: u8 = 0x03;
    pub const DIV: u8 = 0x04;
    pub const MOD: u8 = 0x05;
    pub const ADD_SAT: u8 = 0x06;
    pub const SUB_SAT: u8 = 0x07;
    pub const AND: u8 = 0x10;
    pub const OR: u8 = 0x11;
    pub const XOR: u8 = 0x12;
    pub const NOT: u8 = 0x13;
    pub const SHL: u8 = 0x14;
    pub const SHR: u8 = 0x15;
    pub const EQ: u8 = 0x20;
    pub const NE: u8 = 0x21;
    pub const LT: u8 = 0x22;
    pub const LTE: u8 = 0x23;
    pub const GT: u8 = 0x24;
    pub const GTE: u8 = 0x25;
    pub const IS_ZERO: u8 = 0x26;
    pub const JUMP: u8 = 0x30;
    pub const JUMP_IF: u8 = 0x31;
    pub const JUMP_IF_NOT: u8 = 0x32;
    pub const CALL: u8 = 0x33;
    pub const RETURN: u8 = 0x34;
    pub const HALT: u8 = 0x35;
    pub const TRAP: u8 = 0x36;
    pub const LOAD_CONST: u8 = 0x40;
    pub const LOAD_IMM8: u8 = 0x41;
    pub const LOAD_IMM64: u8 = 0x42;
    pub const MOVE: u8 = 0x43;
    pub const SWAP: u8 = 0x44;
    pub const SLOAD: u8 = 0x50;
    pub const SSTORE: u8 = 0x51;
    pub const SDELETE: u8 = 0x52;
    pub const GET_CALLER: u8 = 0x60;
    pub const GET_OWNER: u8 = 0x61;
    pub const GET_CELL_ID: u8 = 0x62;
    pub const GET_HEIGHT: u8 = 0x63;
    pub const GET_TIMESTAMP: u8 = 0x64;
    pub const GET_VALUE: u8 = 0x65;
    pub const GET_CALLDATA_LEN: u8 = 0x66;
    pub const GET_CALLDATA: u8 = 0x67;
    pub const SET_RETURN: u8 = 0x70;
    pub const SET_RETURN_REG: u8 = 0x72;
    pub const EMIT_LOG: u8 = 0x71;
    pub const EMIT_LOG_REG: u8 = 0x73;
    pub const CALL_CELL: u8 = 0x80;
    pub const BUF_RESET: u8 = 0xD0;
    pub const BUF_WRITE_CONST: u8 = 0xD1;
    pub const BUF_WRITE_REG: u8 = 0xD2;
    pub const BUF_CALL_CELL: u8 = 0xD3;
    pub const BUF_SET_RETURN: u8 = 0xD4;
    pub const HASH32: u8 = 0x90;
    pub const HASH32_CONST: u8 = 0x91;
    pub const REQUIRE_OWNER: u8 = 0xA0;
    pub const REQUIRE_CALLER: u8 = 0xA1;
    pub const REQUIRE_EQ: u8 = 0xA2;
    pub const REQUIRE_NE: u8 = 0xA3;
    pub const REQUIRE_LT: u8 = 0xA4;
    pub const REQUIRE_NON_ZERO: u8 = 0xA5;
    pub const REQUIRE_GAS: u8 = 0xA6;
    // Token ops
    pub const TOKEN_BALANCE: u8 = 0xB0;
    pub const TOKEN_TRANSFER: u8 = 0xB1;
    pub const TOKEN_MINT: u8 = 0xB2;
    pub const TOKEN_BURN: u8 = 0xB3;
    pub const TOKEN_FREEZE: u8 = 0xB4;
    pub const TOKEN_THAW: u8 = 0xB5;
    // Accord
    pub const ACCORD_REQUEST: u8 = 0xC0;
    pub const ACCORD_READ: u8 = 0xC1;
}
