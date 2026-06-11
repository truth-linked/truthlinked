//! Codegen pass: IR + register allocation → Axiom bytecode.
//!
//! Takes the IR instruction sequence and the VReg→physical mapping from
//! regalloc, and emits the final bytecode via CellBuilder.

use crate::builder::CellBuilder;
use crate::ir::{Ir, VReg};
use crate::regalloc::{resolve, Allocation};

/// Lower IR + allocation to encoded Axiom bytecode bytes.
pub fn emit(instrs: &[Ir], alloc: &Allocation) -> Vec<u8> {
    let mut b = CellBuilder::new();

    // First pass: assign label names (Label IDs → string names for CellBuilder)
    // We use the label ID as the string to keep it simple.
    // Forward references are handled by CellBuilder's pending-jump mechanism.

    let r = |v: VReg| -> u8 { resolve(alloc, v) };

    for instr in instrs {
        match instr {
            // ── Labels & control flow ────────────────────────────────────────
            Ir::Label(id) => {
                b.label(&id.to_string());
            }
            Ir::Jump(lbl) => {
                b.jump_label(&lbl.to_string());
            }
            Ir::JumpIf(c, lbl) => {
                b.jump_if_label(r(*c), &lbl.to_string());
            }
            Ir::JumpIfNot(c, lbl) => {
                b.jump_if_not_label(r(*c), &lbl.to_string());
            }
            Ir::Call(lbl) => {
                b.call_label(&lbl.to_string());
            }
            Ir::Return => {
                b.ret();
            }
            Ir::Halt => {
                b.halt();
            }
            Ir::Trap(code) => {
                b.trap(*code);
            }

            // ── Arithmetic ───────────────────────────────────────────────────
            Ir::Add(d, a, b2) => {
                b.add(r(*d), r(*a), r(*b2));
            }
            Ir::Sub(d, a, b2) => {
                b.sub(r(*d), r(*a), r(*b2));
            }
            Ir::Mul(d, a, b2) => {
                b.mul(r(*d), r(*a), r(*b2));
            }
            Ir::Div(d, a, b2) => {
                b.div(r(*d), r(*a), r(*b2));
            }
            Ir::Mod(d, a, b2) => {
                b.modulo(r(*d), r(*a), r(*b2));
            }
            Ir::AddSat(d, a, b2) => {
                b.add_sat(r(*d), r(*a), r(*b2));
            }
            Ir::SubSat(d, a, b2) => {
                b.sub_sat(r(*d), r(*a), r(*b2));
            }

            // ── Bitwise ──────────────────────────────────────────────────────
            Ir::And(d, a, b2) => {
                b.and(r(*d), r(*a), r(*b2));
            }
            Ir::Or(d, a, b2) => {
                b.or(r(*d), r(*a), r(*b2));
            }
            Ir::Xor(d, a, b2) => {
                b.xor(r(*d), r(*a), r(*b2));
            }
            Ir::Not(d, a) => {
                b.not(r(*d), r(*a));
            }
            Ir::Shl(d, a, s) => {
                b.shl(r(*d), r(*a), *s);
            }
            Ir::Shr(d, a, s) => {
                b.shr(r(*d), r(*a), *s);
            }

            // ── Comparison ───────────────────────────────────────────────────
            Ir::Eq(d, a, b2) => {
                b.eq(r(*d), r(*a), r(*b2));
            }
            Ir::Ne(d, a, b2) => {
                b.ne(r(*d), r(*a), r(*b2));
            }
            Ir::Lt(d, a, b2) => {
                b.lt(r(*d), r(*a), r(*b2));
            }
            Ir::Lte(d, a, b2) => {
                b.lte(r(*d), r(*a), r(*b2));
            }
            Ir::Gt(d, a, b2) => {
                b.gt(r(*d), r(*a), r(*b2));
            }
            Ir::Gte(d, a, b2) => {
                b.gte(r(*d), r(*a), r(*b2));
            }
            Ir::IsZero(d, a) => {
                b.is_zero(r(*d), r(*a));
            }

            // ── Data ─────────────────────────────────────────────────────────
            Ir::LoadConst(d, data) => {
                let mut buf = [0u8; 32];
                let n = data.len().min(32);
                buf[..n].copy_from_slice(&data[..n]);
                b.load_bytes32(r(*d), buf);
            }
            Ir::LoadConstIndex(d, data) => {
                // Store data in const pool, load the index (not the value) into the register.
                // ACCORD_REQUEST reads reg[0..2] as a u16 const-pool index.
                let idx = b.add_const(data.clone());
                b.load_imm64(r(*d), idx as u64);
            }
            Ir::LoadImm8(d, v) => {
                b.load_imm8(r(*d), *v);
            }
            Ir::LoadImm64(d, v) => {
                b.load_imm64(r(*d), *v);
            }
            Ir::Mov(d, s) => {
                b.mov(r(*d), r(*s));
            }

            // ── Storage ──────────────────────────────────────────────────────
            Ir::SLoad(d, k) => {
                b.sload(r(*d), r(*k));
            }
            Ir::SStore(k, v) => {
                b.sstore(r(*k), r(*v));
            }
            Ir::SDelete(k) => {
                b.sdelete(r(*k));
            }

            // ── Context ──────────────────────────────────────────────────────
            Ir::GetCaller(d) => {
                b.get_caller(r(*d));
            }
            Ir::GetOwner(d) => {
                b.get_owner(r(*d));
            }
            Ir::GetCellId(d) => {
                b.get_cell_id(r(*d));
            }
            Ir::GetHeight(d) => {
                b.get_height(r(*d));
            }
            Ir::GetTimestamp(d) => {
                b.get_timestamp(r(*d));
            }
            Ir::GetValue(d) => {
                b.get_value(r(*d));
            }
            Ir::GetCalldataLen(d) => {
                b.get_calldata_len(r(*d));
            }
            Ir::GetCalldata(d, off) => {
                b.get_calldata(r(*d), r(*off));
            }

            // ── Output ───────────────────────────────────────────────────────
            Ir::SetReturn(i, l) => {
                b.set_return(r(*i), r(*l));
            }
            Ir::SetReturnReg(d, l) => {
                b.set_return_reg(r(*d), r(*l));
            }
            Ir::EmitLog(t, d) => {
                b.emit_log(r(*t), r(*d));
            }
            Ir::EmitLogReg(t, d, l) => {
                b.emit_log_reg(r(*t), r(*d), r(*l));
            }

            // ── Cross-cell ───────────────────────────────────────────────────
            Ir::CallCell(cell, cd, len, val) => {
                b.call_cell(r(*cell), r(*cd), r(*len), r(*val));
            }
            Ir::BufReset => {
                b.buf_reset();
            }
            Ir::BufWriteConst(data) => {
                let idx = b.add_const(data.clone());
                b.buf_write_const(idx);
            }
            Ir::BufWriteReg(src) => {
                b.buf_write_reg(r(*src));
            }
            Ir::BufCallCell(cell, val) => {
                b.buf_call_cell(r(*cell), r(*val));
            }

            // ── Crypto ───────────────────────────────────────────────────────
            Ir::Hash32(d, s) => {
                b.hash32(r(*d), r(*s));
            }
            Ir::Hash32Const(d, data) => {
                let mut buf = [0u8; 32];
                let n = data.len().min(32);
                buf[..n].copy_from_slice(&data[..n]);
                let idx = b.add_const(buf.to_vec());
                b.hash32_const(r(*d), idx);
            }

            // ── Access control ───────────────────────────────────────────────
            Ir::RequireOwner => {
                b.require_owner();
            }
            Ir::RequireCaller(reg) => {
                b.require_caller(r(*reg));
            }
            Ir::RequireEq(a, b2) => {
                b.require_eq(r(*a), r(*b2));
            }
            Ir::RequireNe(a, b2) => {
                b.require_ne(r(*a), r(*b2));
            }
            Ir::RequireLt(a, b2) => {
                b.require_lt(r(*a), r(*b2));
            }
            Ir::RequireNonZero(reg) => {
                b.require_non_zero(r(*reg));
            }
            Ir::RequireGas(t) => {
                b.require_gas(*t);
            }

            // ── Token ops ────────────────────────────────────────────────────
            Ir::TokenBalance(d, tok, acc) => {
                b.token_balance(r(*d), r(*tok), r(*acc));
            }
            Ir::TokenTransfer(tok, from, to, amt) => {
                b.token_transfer(r(*tok), r(*from), r(*to), r(*amt));
            }
            Ir::TokenMint(tok, rec, amt) => {
                b.token_mint(r(*tok), r(*rec), r(*amt));
            }
            Ir::TokenBurn(tok, own, amt) => {
                b.token_burn(r(*tok), r(*own), r(*amt));
            }
            Ir::TokenFreeze(tok, acc) => {
                b.token_freeze(r(*tok), r(*acc));
            }
            Ir::TokenThaw(tok, acc) => {
                b.token_thaw(r(*tok), r(*acc));
            }

            // ── Accord ───────────────────────────────────────────────────────
            Ir::AccordRequest(d, url, meth, body) => {
                b.accord_request(r(*d), r(*url), r(*meth), r(*body));
            }
            Ir::AccordRead(d, req) => {
                b.accord_read(r(*d), r(*req));
            }

            Ir::BufSetReturn => {
                b.buf_set_return();
            }
        }
    }

    b.build()
}
