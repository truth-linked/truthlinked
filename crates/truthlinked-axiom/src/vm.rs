//! Truthlinked Axiom Src Vm
//!
//! Owns the deterministic Axiom virtual machine execution loop.
//! VM and bytecode changes are consensus-sensitive and must remain deterministic across platforms.

#![allow(unused_assignments)]
use crate::bytecode::CellBytecode;
use crate::error::AxiomError;
use crate::gas::GasMeter;
use crate::host::{CellLog, Host};
use crate::opcode::tag;
use alloc::string::ToString;
use alloc::vec::Vec;

const REG_COUNT: usize = 256;
const CALL_STACK_LIMIT: usize = 64;

/// Maximum call buffer size (4 KB). Enough for selector + 127 × 32-byte args.
pub const CALL_BUF_SIZE: usize = 4_096;

pub struct ExecResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub error: Option<AxiomError>,
    pub logs: Vec<CellLog>,
}

pub struct Vm<'h, H: Host> {
    host: &'h mut H,
    regs: [[u8; 32]; REG_COUNT],
    gas: GasMeter,
    call_stack: [usize; CALL_STACK_LIMIT],
    call_depth: usize,
    depth: u32,
    /// Runtime call buffer for BufWrite*/BufCallCell opcodes.
    call_buf: [u8; CALL_BUF_SIZE],
    call_buf_len: usize,
}

impl<'h, H: Host> Vm<'h, H> {
    pub fn new(host: &'h mut H, gas_limit: u64, depth: u32) -> Self {
        Self {
            host,
            regs: [[0u8; 32]; REG_COUNT],
            gas: GasMeter::new(gas_limit),
            call_stack: [0usize; CALL_STACK_LIMIT],
            call_depth: 0,
            depth,
            call_buf: [0u8; CALL_BUF_SIZE],
            call_buf_len: 0,
        }
    }

    #[inline(always)]
    fn reg(&self, r: u8) -> &[u8; 32] {
        &self.regs[r as usize]
    }
    #[inline(always)]
    fn set_reg(&mut self, r: u8, val: [u8; 32]) {
        if r != 0 {
            self.regs[r as usize] = val;
        }
    }

    #[inline(always)]
    fn u256(b: &[u8; 32]) -> [u64; 4] {
        [
            u64::from_le_bytes(b[0..8].try_into().unwrap()),
            u64::from_le_bytes(b[8..16].try_into().unwrap()),
            u64::from_le_bytes(b[16..24].try_into().unwrap()),
            u64::from_le_bytes(b[24..32].try_into().unwrap()),
        ]
    }
    #[inline(always)]
    fn to32(l: [u64; 4]) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[0..8].copy_from_slice(&l[0].to_le_bytes());
        o[8..16].copy_from_slice(&l[1].to_le_bytes());
        o[16..24].copy_from_slice(&l[2].to_le_bytes());
        o[24..32].copy_from_slice(&l[3].to_le_bytes());
        o
    }
    #[inline(always)]
    fn is_zero(b: &[u8; 32]) -> bool {
        b == &[0u8; 32]
    }
    #[inline(always)]
    fn bval(v: bool) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = v as u8;
        r
    }

    // fix #3: u64 fast path on all arithmetic
    #[inline(always)]
    fn add(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
        if a[1] == 0 && a[2] == 0 && a[3] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
            let (r, ov) = a[0].overflowing_add(b[0]);
            return if ov { None } else { Some([r, 0, 0, 0]) };
        }
        let (r0, c0) = a[0].overflowing_add(b[0]);
        let (r1, c1) = a[1].overflowing_add(b[1]);
        let (r1, c1b) = r1.overflowing_add(c0 as u64);
        let (r2, c2) = a[2].overflowing_add(b[2]);
        let (r2, c2b) = r2.overflowing_add((c1 || c1b) as u64);
        let (r3, c3) = a[3].overflowing_add(b[3]);
        let (r3, c3b) = r3.overflowing_add((c2 || c2b) as u64);
        if c3 || c3b {
            None
        } else {
            Some([r0, r1, r2, r3])
        }
    }
    #[inline(always)]
    fn add_sat(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        Self::add(a, b).unwrap_or([u64::MAX; 4])
    }

    #[inline(always)]
    fn sub(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
        if a[1] == 0 && a[2] == 0 && a[3] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
            let (r, ov) = a[0].overflowing_sub(b[0]);
            return if ov { None } else { Some([r, 0, 0, 0]) };
        }
        let (r0, c0) = a[0].overflowing_sub(b[0]);
        let (r1, c1) = a[1].overflowing_sub(b[1]);
        let (r1, c1b) = r1.overflowing_sub(c0 as u64);
        let (r2, c2) = a[2].overflowing_sub(b[2]);
        let (r2, c2b) = r2.overflowing_sub((c1 || c1b) as u64);
        let (r3, c3) = a[3].overflowing_sub(b[3]);
        let (r3, c3b) = r3.overflowing_sub((c2 || c2b) as u64);
        if c3 || c3b {
            None
        } else {
            Some([r0, r1, r2, r3])
        }
    }
    #[inline(always)]
    fn sub_sat(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        Self::sub(a, b).unwrap_or([0; 4])
    }

    #[inline(always)]
    fn mul(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
        // u64 fast path (most token math)
        if a[1] == 0 && a[2] == 0 && a[3] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
            let (r, ov) = a[0].overflowing_mul(b[0]);
            return if ov { None } else { Some([r, 0, 0, 0]) };
        }
        let a_hi = a[2] != 0 || a[3] != 0;
        let b_hi = b[2] != 0 || b[3] != 0;
        let a_nz = a[0] != 0 || a[1] != 0 || a_hi;
        let b_nz = b[0] != 0 || b[1] != 0 || b_hi;
        if (a_hi && b_nz) || (b_hi && a_nz) {
            return None;
        }
        let av = (a[0] as u128) | ((a[1] as u128) << 64);
        let bv = (b[0] as u128) | ((b[1] as u128) << 64);
        let (rv, ov) = av.overflowing_mul(bv);
        if ov {
            None
        } else {
            Some([rv as u64, (rv >> 64) as u64, 0, 0])
        }
    }

    #[inline(always)]
    fn cmp(a: [u64; 4], b: [u64; 4]) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match a[i].cmp(&b[i]) {
                core::cmp::Ordering::Equal => continue,
                o => return o,
            }
        }
        core::cmp::Ordering::Equal
    }
    fn shl(a: [u64; 4], s: u8) -> [u64; 4] {
        if s == 0 {
            return a;
        }
        let s = s as usize;
        let ws = s / 64;
        let bs = s % 64;
        let mut o = [0u64; 4];
        for i in ws..4 {
            o[i] = a[i - ws] << bs;
            if bs > 0 && i > ws {
                o[i] |= a[i - ws - 1].wrapping_shr((64 - bs) as u32);
            }
        }
        o
    }
    fn shr(a: [u64; 4], s: u8) -> [u64; 4] {
        if s == 0 {
            return a;
        }
        let s = s as usize;
        let ws = s / 64;
        let bs = s % 64;
        let mut o = [0u64; 4];
        for i in 0..(4 - ws) {
            o[i] = a[i + ws] >> bs;
            if bs > 0 && i + ws + 1 < 4 {
                o[i] |= a[i + ws + 1].wrapping_shl((64 - bs) as u32);
            }
        }
        o
    }
    fn lz(a: [u64; 4]) -> u32 {
        for i in (0..4).rev() {
            if a[i] != 0 {
                return (3 - i as u32) * 64 + a[i].leading_zeros();
            }
        }
        256
    }

    // fix #4: u64 fast path + existing u128 fast path
    fn divmod(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], [u64; 4]) {
        if a[1] == 0 && a[2] == 0 && a[3] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
            return ([a[0] / b[0], 0, 0, 0], [a[0] % b[0], 0, 0, 0]);
        }
        if a[2] == 0 && a[3] == 0 && b[2] == 0 && b[3] == 0 {
            let av = (a[0] as u128) | ((a[1] as u128) << 64);
            let bv = (b[0] as u128) | ((b[1] as u128) << 64);
            let q = av / bv;
            let r = av % bv;
            return (
                [q as u64, (q >> 64) as u64, 0, 0],
                [r as u64, (r >> 64) as u64, 0, 0],
            );
        }
        let b_bits = 256 - Self::lz(b);
        let a_bits = 256 - Self::lz(a);
        if a_bits < b_bits {
            return ([0; 4], a);
        }
        let mut rem = a;
        let mut quot = [0u64; 4];
        let mut shift = a_bits - b_bits;
        loop {
            let sb = Self::shl(b, shift as u8);
            if Self::cmp(rem, sb) != core::cmp::Ordering::Less {
                rem = Self::sub(rem, sb).unwrap_or([0; 4]);
                quot[(shift / 64) as usize] |= 1u64 << (shift % 64);
            }
            if shift == 0 {
                break;
            }
            shift -= 1;
        }
        (quot, rem)
    }
    #[inline(always)]
    fn and(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        [a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3]]
    }
    #[inline(always)]
    fn or(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        [a[0] | b[0], a[1] | b[1], a[2] | b[2], a[3] | b[3]]
    }
    #[inline(always)]
    fn xor(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
    }
    #[inline(always)]
    fn not(a: [u64; 4]) -> [u64; 4] {
        [!a[0], !a[1], !a[2], !a[3]]
    }

    pub fn execute(&mut self, cell: &CellBytecode) -> ExecResult {
        let code = &cell.code;
        let mut pc: usize = 0;
        let mut logs: Vec<CellLog> = Vec::new();

        macro_rules! bail {
            ($e:expr) => {
                return ExecResult {
                    success: false,
                    return_data: Vec::new(),
                    gas_used: self.gas.used(),
                    error: Some($e),
                    logs,
                }
            };
        }
        macro_rules! charge {
            ($cost:expr) => {
                if let Err(e) = self.gas.charge_raw($cost) {
                    bail!(e);
                }
            };
        }
        macro_rules! read8 {
            () => {
                if pc < code.len() {
                    let v = code[pc];
                    pc += 1;
                    v
                } else {
                    bail!(AxiomError::InvalidBytecode)
                }
            };
        }
        macro_rules! read16 {
            () => {
                if pc + 2 <= code.len() {
                    let v = u16::from_le_bytes([code[pc], code[pc + 1]]);
                    pc += 2;
                    v
                } else {
                    bail!(AxiomError::InvalidBytecode)
                }
            };
        }
        macro_rules! read32 {
            () => {
                if pc + 4 <= code.len() {
                    let v =
                        u32::from_le_bytes([code[pc], code[pc + 1], code[pc + 2], code[pc + 3]]);
                    pc += 4;
                    v
                } else {
                    bail!(AxiomError::InvalidBytecode)
                }
            };
        }
        macro_rules! read64 {
            () => {{
                if pc + 8 <= code.len() {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&code[pc..pc + 8]);
                    pc += 8;
                    u64::from_le_bytes(b)
                } else {
                    bail!(AxiomError::InvalidBytecode)
                }
            }};
        }
        macro_rules! get_const {
            ($idx:expr) => {
                match cell.const_pool.get($idx as usize) {
                    Some(v) => v,
                    None => bail!(AxiomError::InvalidConstIndex($idx)),
                }
            };
        }
        macro_rules! arith3 {
            ($cost:expr, $fn:expr) => {{
                charge!($cost);
                let dst = read8!();
                let a = read8!();
                let b = read8!();
                match $fn(Self::u256(self.reg(a)), Self::u256(self.reg(b))) {
                    Some(r) => self.set_reg(dst, Self::to32(r)),
                    None => bail!(AxiomError::ArithmeticOverflow),
                }
            }};
        }
        macro_rules! arith3_sat {
            ($cost:expr, $fn:expr) => {{
                charge!($cost);
                let dst = read8!();
                let a = read8!();
                let b = read8!();
                self.set_reg(
                    dst,
                    Self::to32($fn(Self::u256(self.reg(a)), Self::u256(self.reg(b)))),
                );
            }};
        }
        macro_rules! bitwise3 {
            ($fn:expr) => {{
                charge!(2);
                let dst = read8!();
                let a = read8!();
                let b = read8!();
                self.set_reg(
                    dst,
                    Self::to32($fn(Self::u256(self.reg(a)), Self::u256(self.reg(b)))),
                );
            }};
        }
        macro_rules! cmp3 {
            ($pred:expr) => {{
                charge!(2);
                let dst = read8!();
                let a = read8!();
                let b = read8!();
                self.set_reg(
                    dst,
                    Self::bval($pred(Self::u256(self.reg(a)), Self::u256(self.reg(b)))),
                );
            }};
        }

        loop {
            if pc >= code.len() {
                break;
            }
            let op = code[pc];
            pc += 1;
            match op {
                tag::ADD => arith3!(3, Self::add),
                tag::SUB => arith3!(3, Self::sub),
                tag::MUL => arith3!(5, Self::mul),
                tag::DIV => {
                    charge!(8);
                    let dst = read8!();
                    let a = read8!();
                    let b = read8!();
                    let bv = Self::u256(self.reg(b));
                    if bv == [0; 4] {
                        bail!(AxiomError::DivisionByZero);
                    }
                    self.set_reg(dst, Self::to32(Self::divmod(Self::u256(self.reg(a)), bv).0));
                }
                tag::MOD => {
                    charge!(8);
                    let dst = read8!();
                    let a = read8!();
                    let b = read8!();
                    let bv = Self::u256(self.reg(b));
                    if bv == [0; 4] {
                        bail!(AxiomError::DivisionByZero);
                    }
                    self.set_reg(dst, Self::to32(Self::divmod(Self::u256(self.reg(a)), bv).1));
                }
                tag::ADD_SAT => arith3_sat!(3, Self::add_sat),
                tag::SUB_SAT => arith3_sat!(3, Self::sub_sat),
                tag::AND => bitwise3!(Self::and),
                tag::OR => bitwise3!(Self::or),
                tag::XOR => bitwise3!(Self::xor),
                tag::NOT => {
                    charge!(2);
                    let dst = read8!();
                    let a = read8!();
                    self.set_reg(dst, Self::to32(Self::not(Self::u256(self.reg(a)))));
                }
                tag::SHL => {
                    charge!(2);
                    let dst = read8!();
                    let a = read8!();
                    let s = read8!();
                    self.set_reg(dst, Self::to32(Self::shl(Self::u256(self.reg(a)), s)));
                }
                tag::SHR => {
                    charge!(2);
                    let dst = read8!();
                    let a = read8!();
                    let s = read8!();
                    self.set_reg(dst, Self::to32(Self::shr(Self::u256(self.reg(a)), s)));
                }
                tag::EQ => {
                    charge!(2);
                    let dst = read8!();
                    let a = read8!();
                    let b = read8!();
                    self.set_reg(dst, Self::bval(self.reg(a) == self.reg(b)));
                }
                tag::NE => {
                    charge!(2);
                    let dst = read8!();
                    let a = read8!();
                    let b = read8!();
                    self.set_reg(dst, Self::bval(self.reg(a) != self.reg(b)));
                }
                tag::LT => cmp3!(|a, b| Self::cmp(a, b) == core::cmp::Ordering::Less),
                tag::LTE => cmp3!(|a, b| Self::cmp(a, b) != core::cmp::Ordering::Greater),
                tag::GT => cmp3!(|a, b| Self::cmp(a, b) == core::cmp::Ordering::Greater),
                tag::GTE => cmp3!(|a, b| Self::cmp(a, b) != core::cmp::Ordering::Less),
                tag::IS_ZERO => {
                    charge!(2);
                    let dst = read8!();
                    let a = read8!();
                    self.set_reg(dst, Self::bval(Self::is_zero(self.reg(a))));
                }
                tag::JUMP => {
                    charge!(2);
                    let t = read32!() as usize;
                    if t >= code.len() {
                        bail!(AxiomError::InvalidJumpTarget(t as u32));
                    }
                    pc = t;
                }
                tag::JUMP_IF => {
                    charge!(2);
                    let c = read8!();
                    let t = read32!() as usize;
                    if !Self::is_zero(self.reg(c)) {
                        if t >= code.len() {
                            bail!(AxiomError::InvalidJumpTarget(t as u32));
                        }
                        pc = t;
                    }
                }
                tag::JUMP_IF_NOT => {
                    charge!(2);
                    let c = read8!();
                    let t = read32!() as usize;
                    if Self::is_zero(self.reg(c)) {
                        if t >= code.len() {
                            bail!(AxiomError::InvalidJumpTarget(t as u32));
                        }
                        pc = t;
                    }
                }
                tag::CALL => {
                    charge!(5);
                    let t = read32!() as usize;
                    if t >= code.len() {
                        bail!(AxiomError::InvalidJumpTarget(t as u32));
                    }
                    if self.call_depth >= CALL_STACK_LIMIT {
                        bail!(AxiomError::CallDepthExceeded);
                    }
                    self.call_stack[self.call_depth] = pc;
                    self.call_depth += 1;
                    pc = t;
                }
                tag::RETURN => {
                    charge!(5);
                    if self.call_depth == 0 {
                        bail!(AxiomError::InvalidOpcode(tag::RETURN));
                    }
                    self.call_depth -= 1;
                    pc = self.call_stack[self.call_depth];
                }
                tag::HALT => {
                    charge!(1);
                    break;
                }
                tag::TRAP => {
                    charge!(1);
                    let c = read16!();
                    bail!(AxiomError::Trap(c));
                }
                tag::LOAD_CONST => {
                    charge!(1);
                    let dst = read8!();
                    let idx = read16!();
                    let e = get_const!(idx);
                    if e.len() > 32 {
                        bail!(AxiomError::InvalidConstIndex(idx));
                    }
                    let mut v = [0u8; 32];
                    v[..e.len()].copy_from_slice(e);
                    self.set_reg(dst, v);
                }
                tag::LOAD_IMM8 => {
                    charge!(1);
                    let dst = read8!();
                    let imm = read8!();
                    let mut v = [0u8; 32];
                    v[0] = imm;
                    self.set_reg(dst, v);
                }
                tag::LOAD_IMM64 => {
                    charge!(1);
                    let dst = read8!();
                    let imm = read64!();
                    let mut v = [0u8; 32];
                    v[..8].copy_from_slice(&imm.to_le_bytes());
                    self.set_reg(dst, v);
                }
                tag::MOVE => {
                    charge!(1);
                    let dst = read8!();
                    let src = read8!();
                    let v = *self.reg(src);
                    self.set_reg(dst, v);
                }
                tag::SWAP => {
                    charge!(1);
                    let a = read8!();
                    let b = read8!();
                    if a != b && a != 0 && b != 0 {
                        let va = self.regs[a as usize];
                        self.regs[a as usize] = self.regs[b as usize];
                        self.regs[b as usize] = va;
                    }
                }
                tag::SLOAD => {
                    charge!(200);
                    let dst = read8!();
                    let kr = read8!();
                    let key = *self.reg(kr);
                    match self.host.storage_read(&key) {
                        Ok(v) => self.set_reg(dst, v),
                        Err(e) => bail!(e),
                    }
                }
                tag::SSTORE => {
                    charge!(500);
                    let kr = read8!();
                    let vr = read8!();
                    let key = *self.reg(kr);
                    let val = *self.reg(vr);
                    if let Err(e) = self.host.storage_write(&key, &val) {
                        bail!(e);
                    }
                }
                tag::SDELETE => {
                    charge!(300);
                    let kr = read8!();
                    let key = *self.reg(kr);
                    if let Err(e) = self.host.storage_delete(&key) {
                        bail!(e);
                    }
                }
                tag::GET_CALLER => {
                    charge!(3);
                    let dst = read8!();
                    self.set_reg(dst, self.host.caller());
                }
                tag::GET_OWNER => {
                    charge!(3);
                    let dst = read8!();
                    self.set_reg(dst, self.host.owner());
                }
                tag::GET_CELL_ID => {
                    charge!(3);
                    let dst = read8!();
                    self.set_reg(dst, self.host.cell_id());
                }
                tag::GET_HEIGHT => {
                    charge!(3);
                    let dst = read8!();
                    let mut v = [0u8; 32];
                    v[..8].copy_from_slice(&self.host.height().to_le_bytes());
                    self.set_reg(dst, v);
                }
                tag::GET_TIMESTAMP => {
                    charge!(3);
                    let dst = read8!();
                    let mut v = [0u8; 32];
                    v[..8].copy_from_slice(&self.host.timestamp().to_le_bytes());
                    self.set_reg(dst, v);
                }
                tag::GET_VALUE => {
                    charge!(3);
                    let dst = read8!();
                    let mut v = [0u8; 32];
                    v[..16].copy_from_slice(&self.host.value().to_le_bytes());
                    self.set_reg(dst, v);
                }
                tag::GET_CALLDATA_LEN => {
                    charge!(3);
                    let dst = read8!();
                    let mut v = [0u8; 32];
                    v[..8].copy_from_slice(&(self.host.calldata().len() as u64).to_le_bytes());
                    self.set_reg(dst, v);
                }
                tag::GET_CALLDATA => {
                    charge!(3);
                    let dst = read8!();
                    let or = read8!();
                    let off = u64::from_le_bytes(self.reg(or)[..8].try_into().unwrap()) as usize;
                    let cd = self.host.calldata();
                    let mut val = [0u8; 32];
                    if off < cd.len() {
                        let end = off.saturating_add(32).min(cd.len());
                        val[..end - off].copy_from_slice(&cd[off..end]);
                    }
                    self.set_reg(dst, val);
                }
                tag::SET_RETURN => {
                    let ir = read8!();
                    let lr = read8!();
                    let idx = u16::from_le_bytes(self.reg(ir)[..2].try_into().unwrap());
                    let len = u64::from_le_bytes(self.reg(lr)[..8].try_into().unwrap()) as usize;
                    let e = get_const!(idx);
                    let len = len.min(e.len());
                    if len > self.host.max_return_data() {
                        bail!(AxiomError::ReturnDataTooLarge);
                    }
                    charge!(10 + len as u64 / 32); // scale with data size
                    if let Err(e) = self.host.set_return_data(e[..len].to_vec()) {
                        bail!(e);
                    }
                }
                tag::SET_RETURN_REG => {
                    let dr = read8!();
                    let lr = read8!();
                    let len = u64::from_le_bytes(self.reg(lr)[..8].try_into().unwrap()) as usize;
                    if len > 32 {
                        bail!(AxiomError::InvalidLength(len));
                    } // register is 32 bytes max
                    if len > self.host.max_return_data() {
                        bail!(AxiomError::ReturnDataTooLarge);
                    }
                    charge!(10 + len as u64 / 32);
                    let data = self.reg(dr)[..len].to_vec();
                    if let Err(e) = self.host.set_return_data(data) {
                        bail!(e);
                    }
                }
                tag::EMIT_LOG => {
                    let tr = read8!();
                    let dr = read8!();
                    let ti = u16::from_le_bytes(self.reg(tr)[..2].try_into().unwrap());
                    let di = u16::from_le_bytes(self.reg(dr)[..2].try_into().unwrap());
                    let traw = get_const!(ti).clone();
                    let draw = get_const!(di).clone();
                    if draw.len() > self.host.max_log_data() {
                        bail!(AxiomError::LogTooLarge);
                    }
                    if traw.len() % 32 != 0 {
                        bail!(AxiomError::InvalidBytecode);
                    }
                    let nt = traw.len() / 32;
                    if nt > self.host.max_log_topics() {
                        bail!(AxiomError::LogTooLarge);
                    }
                    charge!(100 + draw.len() as u64 / 32 + nt as u64 * 10); // scale with data+topics
                    let mut topics = Vec::with_capacity(nt);
                    for i in 0..nt {
                        let mut t = [0u8; 32];
                        t.copy_from_slice(&traw[i * 32..(i + 1) * 32]);
                        topics.push(t);
                    }
                    let log = CellLog { topics, data: draw };
                    if let Err(e) = self.host.emit_log(log.clone()) {
                        bail!(e);
                    }
                    logs.push(log);
                }
                tag::EMIT_LOG_REG => {
                    // EMIT_LOG_REG: topic_reg, data_reg, len_reg
                    let tr = read8!();
                    let dr = read8!();
                    let lr = read8!();
                    let topic = *self.reg(tr);
                    let len = u64::from_le_bytes(self.reg(lr)[..8].try_into().unwrap()) as usize;
                    if len > 32 {
                        bail!(AxiomError::LogTooLarge);
                    }
                    let data = self.reg(dr)[..len].to_vec();
                    if data.len() > self.host.max_log_data() {
                        bail!(AxiomError::LogTooLarge);
                    }
                    charge!(100 + len as u64 / 32 + 10);
                    let mut topics = Vec::with_capacity(1);
                    topics.push(topic);
                    let log = CellLog { topics, data };
                    if let Err(e) = self.host.emit_log(log.clone()) {
                        bail!(e);
                    }
                    logs.push(log);
                }
                tag::CALL_CELL => {
                    charge!(1_000);
                    let cr = read8!();
                    let cdr = read8!();
                    let lr = read8!();
                    let vr = read8!();
                    if self.depth >= self.host.max_call_depth() {
                        bail!(AxiomError::CallDepthExceeded);
                    }
                    let cell_id = *self.reg(cr);
                    let cdi = u16::from_le_bytes(self.reg(cdr)[..2].try_into().unwrap());
                    let cdlen = u64::from_le_bytes(self.reg(lr)[..8].try_into().unwrap()) as usize;
                    let value = u128::from_le_bytes(self.reg(vr)[..16].try_into().unwrap());
                    let cde = get_const!(cdi).clone();
                    let cdlen = cdlen.min(cde.len());
                    let sub_gas = self.gas.remaining();
                    match self.host.call_cell(&cell_id, &cde[..cdlen], value, sub_gas) {
                        Ok(res) => {
                            if let Err(e) = self.gas.charge_raw(res.gas_used) {
                                bail!(e);
                            }
                            self.set_reg(1, Self::bval(res.success));
                        }
                        Err(e) => bail!(AxiomError::CrossCellFailed(e.to_string())),
                    }
                }
                // ── Call buffer ──────────────────────────────────────────────────────
                tag::BUF_RESET => {
                    charge!(1);
                    self.call_buf_len = 0;
                }
                tag::BUF_WRITE_CONST => {
                    let idx = read16!();
                    let e = get_const!(idx).clone();
                    let n = e.len();
                    charge!(2 + n as u64 / 32);
                    if self.call_buf_len + n > CALL_BUF_SIZE {
                        bail!(AxiomError::BufOverflow);
                    }
                    self.call_buf[self.call_buf_len..self.call_buf_len + n].copy_from_slice(&e);
                    self.call_buf_len += n;
                }
                tag::BUF_WRITE_REG => {
                    charge!(2);
                    let src = read8!();
                    if self.call_buf_len + 32 > CALL_BUF_SIZE {
                        bail!(AxiomError::BufOverflow);
                    }
                    let v = *self.reg(src);
                    self.call_buf[self.call_buf_len..self.call_buf_len + 32].copy_from_slice(&v);
                    self.call_buf_len += 32;
                }
                tag::BUF_CALL_CELL => {
                    charge!(1_000);
                    let cr = read8!();
                    let vr = read8!();
                    if self.depth >= self.host.max_call_depth() {
                        bail!(AxiomError::CallDepthExceeded);
                    }
                    let cell_id = *self.reg(cr);
                    let value = u128::from_le_bytes(self.reg(vr)[..16].try_into().unwrap());
                    let sub_gas = self.gas.remaining();
                    let cd = self.call_buf[..self.call_buf_len].to_vec();
                    match self.host.call_cell(&cell_id, &cd, value, sub_gas) {
                        Ok(res) => {
                            if let Err(e) = self.gas.charge_raw(res.gas_used) {
                                bail!(e);
                            }
                            self.set_reg(1, Self::bval(res.success));
                        }
                        Err(e) => bail!(AxiomError::CrossCellFailed(e.to_string())),
                    }
                }
                tag::BUF_SET_RETURN => {
                    let len = self.call_buf_len;
                    if len > self.host.max_return_data() {
                        bail!(AxiomError::ReturnDataTooLarge);
                    }
                    charge!(10 + len as u64 / 32);
                    let data = self.call_buf[..len].to_vec();
                    if let Err(e) = self.host.set_return_data(data) {
                        bail!(e);
                    }
                }
                tag::HASH32 => {
                    charge!(50);
                    let dst = read8!();
                    let src = read8!();
                    let input = *self.reg(src);
                    self.set_reg(dst, self.host.sha256(&input));
                }
                tag::HASH32_CONST => {
                    charge!(50);
                    let dst = read8!();
                    let idx = read16!();
                    let e = get_const!(idx).clone();
                    self.set_reg(dst, self.host.sha256(&e));
                }
                tag::REQUIRE_OWNER => {
                    charge!(2);
                    if self.host.caller() != self.host.owner() {
                        bail!(AxiomError::Unauthorized);
                    }
                }
                tag::REQUIRE_CALLER => {
                    charge!(2);
                    let r = read8!();
                    if self.host.caller() != *self.reg(r) {
                        bail!(AxiomError::Unauthorized);
                    }
                }
                tag::REQUIRE_EQ => {
                    charge!(2);
                    let a = read8!();
                    let b = read8!();
                    if self.reg(a) != self.reg(b) {
                        bail!(AxiomError::AssertFailed);
                    }
                }
                tag::REQUIRE_NE => {
                    charge!(2);
                    let a = read8!();
                    let b = read8!();
                    if self.reg(a) == self.reg(b) {
                        bail!(AxiomError::AssertFailed);
                    }
                }
                tag::REQUIRE_LT => {
                    charge!(2);
                    let a = read8!();
                    let b = read8!();
                    if Self::cmp(Self::u256(self.reg(a)), Self::u256(self.reg(b)))
                        != core::cmp::Ordering::Less
                    {
                        bail!(AxiomError::AssertFailed);
                    }
                }
                tag::REQUIRE_NON_ZERO => {
                    charge!(2);
                    let r = read8!();
                    if Self::is_zero(self.reg(r)) {
                        bail!(AxiomError::AssertFailed);
                    }
                }
                tag::REQUIRE_GAS => {
                    charge!(2);
                    let t = read64!();
                    if !self.gas.has_at_least(t) {
                        bail!(AxiomError::OutOfGas);
                    }
                }
                // Token ops
                tag::TOKEN_BALANCE => {
                    charge!(200);
                    let dst = read8!();
                    let tr = read8!();
                    let ar = read8!();
                    let token = *self.reg(tr);
                    let account = *self.reg(ar);
                    match self.host.token_balance(&token, &account) {
                        Ok(b) => {
                            let mut v = [0u8; 32];
                            v[..16].copy_from_slice(&b.to_le_bytes());
                            self.set_reg(dst, v);
                        }
                        Err(e) => bail!(e),
                    }
                }
                tag::TOKEN_TRANSFER => {
                    charge!(500);
                    let tr = read8!();
                    let fr = read8!();
                    let tor = read8!();
                    let ar = read8!();
                    let token = *self.reg(tr);
                    let from = *self.reg(fr);
                    let to = *self.reg(tor);
                    let amount = u128::from_le_bytes(self.reg(ar)[..16].try_into().unwrap());
                    if let Err(e) = self.host.token_transfer(&token, &from, &to, amount) {
                        bail!(e);
                    }
                }
                tag::TOKEN_MINT => {
                    charge!(500);
                    let tr = read8!();
                    let rr = read8!();
                    let ar = read8!();
                    let token = *self.reg(tr);
                    let recipient = *self.reg(rr);
                    let amount = u128::from_le_bytes(self.reg(ar)[..16].try_into().unwrap());
                    if let Err(e) = self.host.token_mint(&token, &recipient, amount) {
                        bail!(e);
                    }
                }
                tag::TOKEN_BURN => {
                    charge!(500);
                    let tr = read8!();
                    let or = read8!();
                    let ar = read8!();
                    let token = *self.reg(tr);
                    let owner = *self.reg(or);
                    let amount = u128::from_le_bytes(self.reg(ar)[..16].try_into().unwrap());
                    if let Err(e) = self.host.token_burn(&token, &owner, amount) {
                        bail!(e);
                    }
                }
                tag::TOKEN_FREEZE => {
                    charge!(300);
                    let tr = read8!();
                    let ar = read8!();
                    let token = *self.reg(tr);
                    let account = *self.reg(ar);
                    if let Err(e) = self.host.token_freeze(&token, &account) {
                        bail!(e);
                    }
                }
                tag::TOKEN_THAW => {
                    charge!(300);
                    let tr = read8!();
                    let ar = read8!();
                    let token = *self.reg(tr);
                    let account = *self.reg(ar);
                    if let Err(e) = self.host.token_thaw(&token, &account) {
                        bail!(e);
                    }
                }
                // Accord opcodes
                tag::ACCORD_REQUEST => {
                    charge!(10_000);
                    let dst = read8!();
                    let url_r = read8!();
                    let meth_r = read8!();
                    let body_r = read8!();
                    let url_idx = u16::from_le_bytes(self.reg(url_r)[..2].try_into().unwrap());
                    let body_idx = u16::from_le_bytes(self.reg(body_r)[..2].try_into().unwrap());
                    let url_bytes = get_const!(url_idx).clone();
                    let body_bytes = get_const!(body_idx).clone();
                    let method_bytes = {
                        let r = self.reg(meth_r);
                        let end = r.iter().position(|&b| b == 0).unwrap_or(32);
                        r[..end].to_vec()
                    };
                    match self
                        .host
                        .accord_request(&url_bytes, &method_bytes, &body_bytes)
                    {
                        Ok(req_id) => self.set_reg(dst, req_id),
                        Err(e) => bail!(e),
                    }
                }
                tag::ACCORD_READ => {
                    charge!(500);
                    let dst = read8!();
                    let req_r = read8!();
                    let req_id = *self.reg(req_r);
                    match self.host.accord_read(&req_id) {
                        Ok(Some(body)) => {
                            let mut v = [0u8; 32];
                            let len = body.len().min(32);
                            v[..len].copy_from_slice(&body[..len]);
                            self.set_reg(dst, v);
                            self.set_reg(1, Self::bval(true));
                        }
                        Ok(None) => {
                            self.set_reg(dst, [0u8; 32]);
                            self.set_reg(1, Self::bval(false));
                        }
                        Err(e) => bail!(e),
                    }
                }

                other => bail!(AxiomError::InvalidOpcode(other)),
            }
        }
        ExecResult {
            success: true,
            return_data: Vec::new(),
            gas_used: self.gas.used(),
            error: None,
            logs,
        }
    }
}
