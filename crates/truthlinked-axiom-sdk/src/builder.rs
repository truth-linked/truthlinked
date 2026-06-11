//! CellBuilder - fluent bytecode assembler for Axiom cells.

use truthlinked_axiom::bytecode::CellBytecode;
use truthlinked_axiom::opcode::tag;

struct PendingJump {
    patch_offset: usize,
    label: String,
}

pub struct CellBuilder {
    code: Vec<u8>,
    const_pool: Vec<Vec<u8>>,
    labels: std::collections::HashMap<String, u32>,
    pending: Vec<PendingJump>,
}

impl CellBuilder {
    pub fn new() -> Self {
        Self {
            code: Vec::new(),
            const_pool: Vec::new(),
            labels: std::collections::HashMap::new(),
            pending: Vec::new(),
        }
    }

    pub fn add_const(&mut self, data: Vec<u8>) -> u16 {
        let idx = self.const_pool.len() as u16;
        self.const_pool.push(data);
        idx
    }

    pub fn label(&mut self, name: &str) -> &mut Self {
        self.labels.insert(name.to_string(), self.code.len() as u32);
        self
    }

    pub fn offset(&self) -> u32 {
        self.code.len() as u32
    }

    fn e1(&mut self, op: u8) {
        self.code.push(op);
    }
    fn e2(&mut self, op: u8, a: u8) {
        self.code.push(op);
        self.code.push(a);
    }
    fn e3(&mut self, op: u8, a: u8, b: u8) {
        self.code.push(op);
        self.code.push(a);
        self.code.push(b);
    }
    fn e4(&mut self, op: u8, a: u8, b: u8, c: u8) {
        self.code.push(op);
        self.code.push(a);
        self.code.push(b);
        self.code.push(c);
    }
    fn eu16(&mut self, v: u16) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }
    fn eu32(&mut self, v: u32) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }
    fn eu64(&mut self, v: u64) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn jump_pending(&mut self, op: u8, cond: Option<u8>, label: &str) -> &mut Self {
        self.code.push(op);
        if let Some(c) = cond {
            self.code.push(c);
        }
        let patch = self.code.len();
        self.eu32(0);
        self.pending.push(PendingJump {
            patch_offset: patch,
            label: label.to_string(),
        });
        self
    }

    // Arithmetic
    pub fn add(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::ADD, d, a, b);
        self
    }
    pub fn sub(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::SUB, d, a, b);
        self
    }
    pub fn mul(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::MUL, d, a, b);
        self
    }
    pub fn div(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::DIV, d, a, b);
        self
    }
    pub fn modulo(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::MOD, d, a, b);
        self
    }
    pub fn add_sat(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::ADD_SAT, d, a, b);
        self
    }
    pub fn sub_sat(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::SUB_SAT, d, a, b);
        self
    }
    // Bitwise
    pub fn and(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::AND, d, a, b);
        self
    }
    pub fn or(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::OR, d, a, b);
        self
    }
    pub fn xor(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::XOR, d, a, b);
        self
    }
    pub fn not(&mut self, d: u8, a: u8) -> &mut Self {
        self.e3(tag::NOT, d, a);
        self
    }
    pub fn shl(&mut self, d: u8, a: u8, s: u8) -> &mut Self {
        self.e4(tag::SHL, d, a, s);
        self
    }
    pub fn shr(&mut self, d: u8, a: u8, s: u8) -> &mut Self {
        self.e4(tag::SHR, d, a, s);
        self
    }
    // Comparison
    pub fn eq(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::EQ, d, a, b);
        self
    }
    pub fn ne(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::NE, d, a, b);
        self
    }
    pub fn lt(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::LT, d, a, b);
        self
    }
    pub fn lte(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::LTE, d, a, b);
        self
    }
    pub fn gt(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::GT, d, a, b);
        self
    }
    pub fn gte(&mut self, d: u8, a: u8, b: u8) -> &mut Self {
        self.e4(tag::GTE, d, a, b);
        self
    }
    pub fn is_zero(&mut self, d: u8, a: u8) -> &mut Self {
        self.e3(tag::IS_ZERO, d, a);
        self
    }
    // Control flow
    pub fn jump(&mut self, t: u32) -> &mut Self {
        self.e1(tag::JUMP);
        self.eu32(t);
        self
    }
    pub fn jump_if(&mut self, c: u8, t: u32) -> &mut Self {
        self.e2(tag::JUMP_IF, c);
        self.eu32(t);
        self
    }
    pub fn jump_if_not(&mut self, c: u8, t: u32) -> &mut Self {
        self.e2(tag::JUMP_IF_NOT, c);
        self.eu32(t);
        self
    }
    pub fn jump_label(&mut self, l: &str) -> &mut Self {
        self.jump_pending(tag::JUMP, None, l)
    }
    pub fn jump_if_label(&mut self, c: u8, l: &str) -> &mut Self {
        self.jump_pending(tag::JUMP_IF, Some(c), l)
    }
    pub fn jump_if_not_label(&mut self, c: u8, l: &str) -> &mut Self {
        self.jump_pending(tag::JUMP_IF_NOT, Some(c), l)
    }
    pub fn call(&mut self, t: u32) -> &mut Self {
        self.e1(tag::CALL);
        self.eu32(t);
        self
    }
    pub fn call_label(&mut self, l: &str) -> &mut Self {
        self.jump_pending(tag::CALL, None, l)
    }
    pub fn ret(&mut self) -> &mut Self {
        self.e1(tag::RETURN);
        self
    }
    pub fn halt(&mut self) -> &mut Self {
        self.e1(tag::HALT);
        self
    }
    pub fn trap(&mut self, c: u16) -> &mut Self {
        self.e1(tag::TRAP);
        self.eu16(c);
        self
    }
    // Data
    pub fn load_const(&mut self, d: u8, i: u16) -> &mut Self {
        self.e2(tag::LOAD_CONST, d);
        self.eu16(i);
        self
    }
    pub fn load_imm8(&mut self, d: u8, v: u8) -> &mut Self {
        self.e3(tag::LOAD_IMM8, d, v);
        self
    }
    pub fn load_imm64(&mut self, d: u8, v: u64) -> &mut Self {
        self.e2(tag::LOAD_IMM64, d);
        self.eu64(v);
        self
    }
    pub fn load_bytes32(&mut self, d: u8, data: [u8; 32]) -> &mut Self {
        let i = self.add_const(data.to_vec());
        self.load_const(d, i)
    }
    pub fn mov(&mut self, d: u8, s: u8) -> &mut Self {
        self.e3(tag::MOVE, d, s);
        self
    }
    pub fn swap(&mut self, a: u8, b: u8) -> &mut Self {
        self.e3(tag::SWAP, a, b);
        self
    }
    // Storage
    pub fn sload(&mut self, d: u8, k: u8) -> &mut Self {
        self.e3(tag::SLOAD, d, k);
        self
    }
    pub fn sstore(&mut self, k: u8, v: u8) -> &mut Self {
        self.e3(tag::SSTORE, k, v);
        self
    }
    pub fn sdelete(&mut self, k: u8) -> &mut Self {
        self.e2(tag::SDELETE, k);
        self
    }
    // Context
    pub fn get_caller(&mut self, d: u8) -> &mut Self {
        self.e2(tag::GET_CALLER, d);
        self
    }
    pub fn get_owner(&mut self, d: u8) -> &mut Self {
        self.e2(tag::GET_OWNER, d);
        self
    }
    pub fn get_cell_id(&mut self, d: u8) -> &mut Self {
        self.e2(tag::GET_CELL_ID, d);
        self
    }
    pub fn get_height(&mut self, d: u8) -> &mut Self {
        self.e2(tag::GET_HEIGHT, d);
        self
    }
    pub fn get_timestamp(&mut self, d: u8) -> &mut Self {
        self.e2(tag::GET_TIMESTAMP, d);
        self
    }
    pub fn get_value(&mut self, d: u8) -> &mut Self {
        self.e2(tag::GET_VALUE, d);
        self
    }
    pub fn get_calldata_len(&mut self, d: u8) -> &mut Self {
        self.e2(tag::GET_CALLDATA_LEN, d);
        self
    }
    pub fn get_calldata(&mut self, d: u8, off: u8) -> &mut Self {
        self.e3(tag::GET_CALLDATA, d, off);
        self
    }
    // Output
    pub fn set_return(&mut self, i: u8, l: u8) -> &mut Self {
        self.e3(tag::SET_RETURN, i, l);
        self
    }
    pub fn set_return_reg(&mut self, d: u8, l: u8) -> &mut Self {
        self.e3(tag::SET_RETURN_REG, d, l);
        self
    }
    pub fn emit_log(&mut self, t: u8, d: u8) -> &mut Self {
        self.e3(tag::EMIT_LOG, t, d);
        self
    }
    pub fn emit_log_reg(&mut self, t: u8, d: u8, l: u8) -> &mut Self {
        self.e4(tag::EMIT_LOG_REG, t, d, l);
        self
    }
    // Cross-cell
    pub fn call_cell(&mut self, cell: u8, cd: u8, len: u8, val: u8) -> &mut Self {
        self.e1(tag::CALL_CELL);
        self.code.extend_from_slice(&[cell, cd, len, val]);
        self
    }
    // Call buffer
    pub fn buf_reset(&mut self) -> &mut Self {
        self.e1(tag::BUF_RESET);
        self
    }
    pub fn buf_write_const(&mut self, idx: u16) -> &mut Self {
        self.e1(tag::BUF_WRITE_CONST);
        self.eu16(idx);
        self
    }
    pub fn buf_write_reg(&mut self, src: u8) -> &mut Self {
        self.e2(tag::BUF_WRITE_REG, src);
        self
    }
    pub fn buf_call_cell(&mut self, cell: u8, val: u8) -> &mut Self {
        self.e3(tag::BUF_CALL_CELL, cell, val);
        self
    }
    pub fn buf_set_return(&mut self) -> &mut Self {
        self.e1(tag::BUF_SET_RETURN);
        self
    }
    // Crypto
    pub fn hash32(&mut self, d: u8, s: u8) -> &mut Self {
        self.e3(tag::HASH32, d, s);
        self
    }
    pub fn hash32_const(&mut self, d: u8, i: u16) -> &mut Self {
        self.e2(tag::HASH32_CONST, d);
        self.eu16(i);
        self
    }
    // Access control
    pub fn require_owner(&mut self) -> &mut Self {
        self.e1(tag::REQUIRE_OWNER);
        self
    }
    pub fn require_caller(&mut self, r: u8) -> &mut Self {
        self.e2(tag::REQUIRE_CALLER, r);
        self
    }
    pub fn require_eq(&mut self, a: u8, b: u8) -> &mut Self {
        self.e3(tag::REQUIRE_EQ, a, b);
        self
    }
    pub fn require_ne(&mut self, a: u8, b: u8) -> &mut Self {
        self.e3(tag::REQUIRE_NE, a, b);
        self
    }
    pub fn require_lt(&mut self, a: u8, b: u8) -> &mut Self {
        self.e3(tag::REQUIRE_LT, a, b);
        self
    }
    pub fn require_non_zero(&mut self, r: u8) -> &mut Self {
        self.e2(tag::REQUIRE_NON_ZERO, r);
        self
    }
    pub fn require_gas(&mut self, t: u64) -> &mut Self {
        self.e1(tag::REQUIRE_GAS);
        self.eu64(t);
        self
    }
    // Token
    pub fn token_balance(&mut self, d: u8, tok: u8, acc: u8) -> &mut Self {
        self.e4(tag::TOKEN_BALANCE, d, tok, acc);
        self
    }
    pub fn token_transfer(&mut self, tok: u8, from: u8, to: u8, amt: u8) -> &mut Self {
        self.e1(tag::TOKEN_TRANSFER);
        self.code.extend_from_slice(&[tok, from, to, amt]);
        self
    }
    pub fn token_mint(&mut self, tok: u8, rec: u8, amt: u8) -> &mut Self {
        self.e4(tag::TOKEN_MINT, tok, rec, amt);
        self
    }
    pub fn token_burn(&mut self, tok: u8, own: u8, amt: u8) -> &mut Self {
        self.e4(tag::TOKEN_BURN, tok, own, amt);
        self
    }
    pub fn token_freeze(&mut self, tok: u8, acc: u8) -> &mut Self {
        self.e3(tag::TOKEN_FREEZE, tok, acc);
        self
    }
    pub fn token_thaw(&mut self, tok: u8, acc: u8) -> &mut Self {
        self.e3(tag::TOKEN_THAW, tok, acc);
        self
    }
    // Accord
    pub fn accord_request(&mut self, dst: u8, url_r: u8, meth_r: u8, body_r: u8) -> &mut Self {
        self.e1(tag::ACCORD_REQUEST);
        self.code.extend_from_slice(&[dst, url_r, meth_r, body_r]);
        self
    }
    pub fn accord_read(&mut self, dst: u8, req_r: u8) -> &mut Self {
        self.e3(tag::ACCORD_READ, dst, req_r);
        self
    }

    /// Resolve labels and encode to Axiom bytecode bytes.
    pub fn build(&mut self) -> Vec<u8> {
        for jump in self.pending.drain(..) {
            let target = *self
                .labels
                .get(&jump.label)
                .unwrap_or_else(|| panic!("undefined label: {}", jump.label));
            self.code[jump.patch_offset..jump.patch_offset + 4]
                .copy_from_slice(&target.to_le_bytes());
        }
        CellBytecode {
            const_pool: self.const_pool.clone(),
            code: self.code.clone(),
        }
        .encode()
    }
}

impl Default for CellBuilder {
    fn default() -> Self {
        Self::new()
    }
}
