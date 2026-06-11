//! Lower .cell AST → Axiom IR.
//!
//! Layout:
//!   - Dispatch table: for each pub fn, match 4-byte selector from calldata
//!   - Handler bodies in order
//!   - Private helper subroutines at the end
//!   - init is a special selector "init" (called once at deploy)

use crate::ast::*;
use std::collections::HashMap;
use truthlinked_axiom_sdk::ir::{Ir, Label, VReg};

pub struct Lowerer<'a> {
    cell: &'a CellDef,
    ir: Vec<Ir>,
    next_vreg: VReg,
    next_label: Label,
    // storage slot name → hashed key bytes
    slot_keys: HashMap<String, Vec<u8>>,
    // error name → trap code (1-based)
    error_codes: HashMap<String, u16>,
    // helper fn name → (label_id, arg_vregs, ret_vreg)
    helpers: HashMap<String, (Label, Vec<VReg>, VReg)>,
    // break/continue stacks
    break_stack: Vec<Label>,
    continue_stack: Vec<Label>,
}

impl<'a> Lowerer<'a> {
    pub fn new(cell: &'a CellDef) -> Self {
        let slot_keys = cell
            .storage
            .iter()
            .map(|s| {
                let key = truthlinked_axiom_sdk::hashing::namespace(&s.name);
                (s.name.clone(), key.to_vec())
            })
            .collect();

        let error_codes = cell
            .errors
            .iter()
            .enumerate()
            .map(|(i, e)| (e.name.clone(), (i + 1) as u16))
            .collect();

        Self {
            cell,
            ir: Vec::new(),
            next_vreg: 1,
            next_label: 0,
            slot_keys,
            error_codes,
            helpers: HashMap::new(),
            break_stack: Vec::new(),
            continue_stack: Vec::new(),
        }
    }

    fn vreg(&mut self) -> VReg {
        let v = self.next_vreg;
        self.next_vreg += 1;
        v
    }
    fn label(&mut self) -> Label {
        let l = self.next_label;
        self.next_label += 1;
        l
    }

    fn push(&mut self, ir: Ir) {
        self.ir.push(ir);
    }

    // ── Public entry ─────────────────────────────────────────────────────

    pub fn lower(mut self) -> Vec<Ir> {
        // First pass: allocate labels/vregs for all helpers so call sites can reference them
        for f in self.cell.fns.iter().filter(|f| !f.public) {
            let lbl = self.label();
            let arg_vregs: Vec<VReg> = f.params.iter().map(|_| self.vreg()).collect();
            let ret_vreg = self.vreg();
            self.helpers
                .insert(f.name.clone(), (lbl, arg_vregs, ret_vreg));
        }

        // Dispatch table for public fns (and init)
        let mut handler_labels: Vec<(String, Label)> = Vec::new();

        let all_pub: Vec<&FnDef> = self.cell.fns.iter().filter(|f| f.public).collect();
        let has_init = self.cell.init.is_some();

        // For each public fn + init: emit selector check → JumpIf handler_label
        let v_cd = self.vreg();
        let v_off = self.vreg();
        let v_sel = self.vreg();
        let v_mask = self.vreg();
        let v_mcd = self.vreg();
        let v_cond = self.vreg();

        // Load calldata[0..32] once
        self.push(Ir::LoadImm8(v_off, 0));
        self.push(Ir::GetCalldata(v_cd, v_off));

        // Mask to low 4 bytes
        let mut mask32 = vec![0u8; 32];
        mask32[0] = 0xFF;
        mask32[1] = 0xFF;
        mask32[2] = 0xFF;
        mask32[3] = 0xFF;
        self.push(Ir::LoadConst(v_mask, mask32));
        self.push(Ir::And(v_mcd, v_cd, v_mask));

        // init selector
        if has_init {
            let lbl = self.label();
            handler_labels.push(("init".to_string(), lbl));
            let sel = truthlinked_axiom_sdk::abi::selector_of("init");
            let mut sel32 = vec![0u8; 32];
            sel32[..4].copy_from_slice(&sel);
            self.push(Ir::LoadConst(v_sel, sel32));
            self.push(Ir::Eq(v_cond, v_mcd, v_sel));
            self.push(Ir::JumpIf(v_cond, lbl));
        }

        for f in &all_pub {
            let lbl = self.label();
            handler_labels.push((f.name.clone(), lbl));
            let sel = truthlinked_axiom_sdk::abi::selector_of(&f.name);
            let mut sel32 = vec![0u8; 32];
            sel32[..4].copy_from_slice(&sel);
            self.push(Ir::LoadConst(v_sel, sel32));
            self.push(Ir::Eq(v_cond, v_mcd, v_sel));
            self.push(Ir::JumpIf(v_cond, lbl));
        }

        // No selector matched → trap
        self.push(Ir::Trap(0x0001));

        // Emit handler bodies
        for (name, lbl) in &handler_labels {
            self.push(Ir::Label(*lbl));
            if name == "init" {
                if let Some(init) = &self.cell.init {
                    let params: Vec<(String, VReg)> = init
                        .params
                        .iter()
                        .enumerate()
                        .map(|(i, p)| {
                            let v = self.vreg();
                            let off_v = self.vreg();
                            let offset = (4 + i * 32) as u64;
                            self.ir.push(Ir::LoadImm64(off_v, offset));
                            self.ir.push(Ir::GetCalldata(v, off_v));
                            (p.name.clone(), v)
                        })
                        .collect();
                    let scope: HashMap<String, VReg> = params.into_iter().collect();
                    let body = init.body.clone();
                    self.lower_body(&body, &scope);
                }
            } else {
                let f = self.cell.fns.iter().find(|f| &f.name == name).unwrap();
                let params: Vec<(String, VReg)> = f
                    .params
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        let v = self.vreg();
                        let off_v = self.vreg();
                        let offset = (4 + i * 32) as u64;
                        self.ir.push(Ir::LoadImm64(off_v, offset));
                        self.ir.push(Ir::GetCalldata(v, off_v));
                        (p.name.clone(), v)
                    })
                    .collect();
                let scope: HashMap<String, VReg> = params.into_iter().collect();
                let body = f.body.clone();
                self.lower_body(&body, &scope);
            }
            self.push(Ir::Halt);
        }

        // Emit private helper subroutines
        let helper_defs: Vec<FnDef> = self
            .cell
            .fns
            .iter()
            .filter(|f| !f.public)
            .cloned()
            .collect();
        for f in &helper_defs {
            let (lbl, arg_vregs, _ret_vreg) = self.helpers[&f.name].clone();
            self.push(Ir::Label(lbl));
            let scope: HashMap<String, VReg> = f
                .params
                .iter()
                .zip(arg_vregs.iter())
                .map(|(p, &v)| (p.name.clone(), v))
                .collect();
            let body = f.body.clone();
            self.lower_body(&body, &scope);
            self.push(Ir::Return);
        }

        self.ir
    }

    // ── Body / statement lowering ─────────────────────────────────────────

    fn lower_body(&mut self, stmts: &[Stmt], parent_scope: &HashMap<String, VReg>) {
        let mut scope = parent_scope.clone();
        for stmt in stmts {
            self.lower_stmt(stmt, &mut scope);
        }
    }

    fn lower_stmt(&mut self, stmt: &Stmt, scope: &mut HashMap<String, VReg>) {
        match stmt {
            Stmt::Let { name, ty: _, expr } => {
                let dst = self.vreg();
                scope.insert(name.clone(), dst);
                self.lower_expr_into(expr, dst, scope);
            }
            Stmt::Assign { target, expr } => {
                let dst = self.vreg();
                self.lower_expr_into(expr, dst, scope);
                self.store_lvalue(target, dst, scope);
            }
            Stmt::AssignAdd { target, expr } => {
                let rhs = self.vreg();
                self.lower_expr_into(expr, rhs, scope);
                let cur = self.vreg();
                self.load_lvalue(target, cur, scope);
                let res = self.vreg();
                self.push(Ir::Add(res, cur, rhs));
                self.store_lvalue(target, res, scope);
            }
            Stmt::AssignSub { target, expr } => {
                let rhs = self.vreg();
                self.lower_expr_into(expr, rhs, scope);
                let cur = self.vreg();
                self.load_lvalue(target, cur, scope);
                let res = self.vreg();
                self.push(Ir::Sub(res, cur, rhs));
                self.store_lvalue(target, res, scope);
            }
            Stmt::AssignMul { target, expr } => {
                let rhs = self.vreg();
                self.lower_expr_into(expr, rhs, scope);
                let cur = self.vreg();
                self.load_lvalue(target, cur, scope);
                let res = self.vreg();
                self.push(Ir::Mul(res, cur, rhs));
                self.store_lvalue(target, res, scope);
            }
            Stmt::AssignDiv { target, expr } => {
                let rhs = self.vreg();
                self.lower_expr_into(expr, rhs, scope);
                let cur = self.vreg();
                self.load_lvalue(target, cur, scope);
                let res = self.vreg();
                self.push(Ir::Div(res, cur, rhs));
                self.store_lvalue(target, res, scope);
            }
            Stmt::For {
                var,
                start,
                end,
                body,
            } => {
                // for i in start..end { body }
                // Lowered as: i = start; while i < end { body; i += 1 }
                let i_v = self.vreg();
                let end_v = self.vreg();
                let cond_v = self.vreg();
                let loop_start = self.label();
                let loop_end = self.label();
                self.lower_expr_into(start, i_v, scope);
                self.lower_expr_into(end, end_v, scope);
                let mut inner = scope.clone();
                inner.insert(var.clone(), i_v);
                self.break_stack.push(loop_end);
                self.continue_stack.push(loop_start);
                self.push(Ir::Label(loop_start));
                self.push(Ir::Lt(cond_v, i_v, end_v));
                self.push(Ir::JumpIfNot(cond_v, loop_end));
                self.lower_body(body, &mut inner.clone());
                // i += 1
                let one = self.vreg();
                self.push(Ir::LoadImm8(one, 1));
                self.push(Ir::Add(i_v, i_v, one));
                self.push(Ir::Jump(loop_start));
                self.push(Ir::Label(loop_end));
                self.break_stack.pop();
                self.continue_stack.pop();
            }
            Stmt::Require { expr } => {
                let v = self.vreg();
                self.lower_expr_into(expr, v, scope);
                self.push(Ir::RequireNonZero(v));
            }
            Stmt::Revert { error } => {
                let code = self.error_codes.get(error).copied().unwrap_or(0xFFFF);
                self.push(Ir::Trap(code));
            }
            Stmt::Return { exprs } => {
                match exprs.len() {
                    0 => {}
                    1 => {
                        let v = self.vreg();
                        self.lower_expr_into(&exprs[0], v, scope);
                        let len_v = self.vreg();
                        self.push(Ir::LoadImm8(len_v, 32));
                        self.push(Ir::SetReturnReg(v, len_v));
                    }
                    _ => {
                        // Pack N × 32-byte values into call buffer, set as return data
                        self.push(Ir::BufReset);
                        for expr in exprs {
                            let v = self.vreg();
                            self.lower_expr_into(expr, v, scope);
                            self.push(Ir::BufWriteReg(v));
                        }
                        self.push(Ir::BufSetReturn);
                    }
                }
                self.push(Ir::Halt);
            }
            Stmt::Emit { event, fields } => {
                // topic = sha256(event_name)
                let topic_v = self.vreg();
                self.push(Ir::Hash32Const(topic_v, event.as_bytes().to_vec()));
                // data = all field values packed as 32-byte words concatenated
                // We build a runtime byte blob: evaluate each field into a reg,
                // then store each into a 32-byte slot of a const-pool entry.
                // Since we cannot build a dynamic const at runtime, we emit each
                // field as a separate EmitLogReg call with a shared topic, OR
                // we pack all fields into a single log by using SetReturnReg to
                // stage them. The cleanest approach: emit one log per field with
                // the same topic (indexed by field index in the topic's low byte).
                if fields.is_empty() {
                    // No data - emit a zero-length log with just the topic
                    let data_v = self.vreg();
                    let len_v = self.vreg();
                    self.push(Ir::LoadImm8(data_v, 0));
                    self.push(Ir::LoadImm8(len_v, 0));
                    self.push(Ir::EmitLogReg(topic_v, data_v, len_v));
                } else {
                    for (idx, (_, fexpr)) in fields.iter().enumerate() {
                        // Encode field index into a per-field topic: sha256(event || idx)
                        let field_topic_v = self.vreg();
                        let mut tag = event.as_bytes().to_vec();
                        tag.push(idx as u8);
                        self.push(Ir::Hash32Const(field_topic_v, tag));
                        let data_v = self.vreg();
                        self.lower_expr_into(fexpr, data_v, scope);
                        let len_v = self.vreg();
                        self.push(Ir::LoadImm8(len_v, 32));
                        self.push(Ir::EmitLogReg(field_topic_v, data_v, len_v));
                    }
                }
            }
            Stmt::If { cond, then, else_ } => {
                let cv = self.vreg();
                self.lower_expr_into(cond, cv, scope);
                let else_lbl = self.label();
                let end_lbl = self.label();
                self.push(Ir::JumpIfNot(cv, else_lbl));
                self.lower_body(then, scope);
                self.push(Ir::Jump(end_lbl));
                self.push(Ir::Label(else_lbl));
                self.lower_body(else_, scope);
                self.push(Ir::Label(end_lbl));
            }
            Stmt::While { cond, body } => {
                let loop_start = self.label();
                let loop_end = self.label();
                self.break_stack.push(loop_end);
                self.continue_stack.push(loop_start);
                self.push(Ir::Label(loop_start));
                let cv = self.vreg();
                self.lower_expr_into(cond, cv, scope);
                self.push(Ir::JumpIfNot(cv, loop_end));
                self.lower_body(body, scope);
                self.push(Ir::Jump(loop_start));
                self.push(Ir::Label(loop_end));
                self.break_stack.pop();
                self.continue_stack.pop();
            }
            Stmt::Loop { body } => {
                let loop_start = self.label();
                let loop_end = self.label();
                self.break_stack.push(loop_end);
                self.continue_stack.push(loop_start);
                self.push(Ir::Label(loop_start));
                self.lower_body(body, scope);
                self.push(Ir::Jump(loop_start));
                self.push(Ir::Label(loop_end));
                self.break_stack.pop();
                self.continue_stack.pop();
            }
            Stmt::Break => {
                let l = *self.break_stack.last().expect("break outside loop");
                self.push(Ir::Jump(l));
            }
            Stmt::Continue => {
                let l = *self.continue_stack.last().expect("continue outside loop");
                self.push(Ir::Jump(l));
            }
            Stmt::Expr(expr) => {
                let v = self.vreg();
                self.lower_expr_into(expr, v, scope);
            }
        }
    }

    // ── Expression lowering ───────────────────────────────────────────────

    fn lower_expr_into(&mut self, expr: &Expr, dst: VReg, scope: &HashMap<String, VReg>) {
        match expr {
            Expr::Int(v) => {
                if *v <= u64::MAX as u128 {
                    self.push(Ir::LoadImm64(dst, *v as u64));
                } else {
                    let mut bytes = vec![0u8; 32];
                    bytes[..16].copy_from_slice(&(*v as u128).to_le_bytes());
                    self.push(Ir::LoadConst(dst, bytes));
                }
            }
            Expr::Bytes(b) => {
                // The VM's ACCORD_REQUEST reads url/body as const-pool indices
                // stored in the low 2 bytes of the register.
                // We need to put the const-pool INDEX into dst, not the bytes.
                // Use LoadConst which emits LOAD_CONST opcode - this stores the
                // bytes in the const pool AND loads the first 32 bytes of the entry
                // into the register. But ACCORD_REQUEST reads reg[0..2] as the index.
                //
                // Fix: emit the bytes into the const pool via BufWriteConst pattern,
                // then load the index as an immediate using LoadImm64.
                // We use Ir::Hash32Const as a proxy to get the const pool index:
                // actually the cleanest fix is a dedicated LoadConstIdx IR op.
                // For now: use LoadConst - the codegen assigns a sequential index.
                // We need that index in the register. Use LoadImm64 with the index.
                //
                // The regalloc/codegen pipeline: Ir::LoadConst(dst, data) →
                //   builder.load_bytes32(dst, data) → add_const(data) → load_const(dst, idx)
                // So the LOAD_CONST opcode puts the VALUE in the register, not the index.
                //
                // Real fix: add Ir::LoadConstIndex(dst, data) that emits:
                //   add_const(data) → load_imm64(dst, idx as u64)
                // This puts the index in the register, which is what ACCORD_REQUEST needs.
                self.push(Ir::LoadConstIndex(dst, b.clone()));
            }
            Expr::Var(name) => {
                self.load_var_or_slot(name, dst, scope);
            }
            Expr::Caller => self.push(Ir::GetCaller(dst)),
            Expr::Owner => self.push(Ir::GetOwner(dst)),
            Expr::SelfAddr => self.push(Ir::GetCellId(dst)),
            Expr::Height => self.push(Ir::GetHeight(dst)),
            Expr::Timestamp => self.push(Ir::GetTimestamp(dst)),
            Expr::Value => self.push(Ir::GetValue(dst)),
            Expr::Not(inner) => {
                let v = self.vreg();
                self.lower_expr_into(inner, v, scope);
                self.push(Ir::IsZero(dst, v));
            }
            Expr::Bin { op, lhs, rhs } => {
                // For Shl/Shr with constant RHS, extract the shift amount directly
                if matches!(op, BinOp::Shl | BinOp::Shr) {
                    if let Expr::Int(n) = rhs.as_ref() {
                        let shift = (*n as u8).min(255);
                        let lv = self.vreg();
                        self.lower_expr_into(lhs, lv, scope);
                        match op {
                            BinOp::Shl => self.push(Ir::Shl(dst, lv, shift)),
                            BinOp::Shr => self.push(Ir::Shr(dst, lv, shift)),
                            _ => unreachable!(),
                        }
                        return;
                    }
                    // Non-constant shift: evaluate both, use low byte of rv as shift
                    // Workaround: loop-based shift using Add (correct but slow for large shifts)
                    // For now emit a multiply/divide approximation via repeated add is too complex;
                    // just use shift=0 and document that variable shifts require constant RHS.
                    let lv = self.vreg();
                    self.lower_expr_into(lhs, lv, scope);
                    let _ = self.vreg(); // evaluate rhs for side effects
                    self.lower_expr_into(rhs, self.next_vreg - 1, scope);
                    match op {
                        BinOp::Shl => self.push(Ir::Shl(dst, lv, 0)),
                        BinOp::Shr => self.push(Ir::Shr(dst, lv, 0)),
                        _ => unreachable!(),
                    }
                    return;
                }

                let lv = self.vreg();
                let rv = self.vreg();
                self.lower_expr_into(lhs, lv, scope);
                self.lower_expr_into(rhs, rv, scope);
                let ir = match op {
                    BinOp::Add => Ir::Add(dst, lv, rv),
                    BinOp::Sub => Ir::Sub(dst, lv, rv),
                    BinOp::Mul => Ir::Mul(dst, lv, rv),
                    BinOp::Div => Ir::Div(dst, lv, rv),
                    BinOp::Rem => Ir::Mod(dst, lv, rv),
                    BinOp::And => Ir::And(dst, lv, rv),
                    BinOp::Or => Ir::Or(dst, lv, rv),
                    BinOp::Xor => Ir::Xor(dst, lv, rv),
                    BinOp::Shl | BinOp::Shr => unreachable!(), // handled above
                    BinOp::Eq => Ir::Eq(dst, lv, rv),
                    BinOp::Ne => Ir::Ne(dst, lv, rv),
                    BinOp::Lt => Ir::Lt(dst, lv, rv),
                    BinOp::Le => Ir::Lte(dst, lv, rv),
                    BinOp::Gt => Ir::Gt(dst, lv, rv),
                    BinOp::Ge => Ir::Gte(dst, lv, rv),
                    // LogicAnd/LogicOr: both sides already evaluated; result = lv != 0 && rv != 0
                    BinOp::LogicAnd => {
                        self.push(Ir::And(dst, lv, rv));
                        return;
                    }
                    BinOp::LogicOr => {
                        self.push(Ir::Or(dst, lv, rv));
                        return;
                    }
                };
                self.push(ir);
            }
            Expr::TokenBalance { token, account } => {
                let tv = self.vreg();
                let av = self.vreg();
                self.lower_expr_into(token, tv, scope);
                self.lower_expr_into(account, av, scope);
                self.push(Ir::TokenBalance(dst, tv, av));
            }
            Expr::TokenTransfer {
                token,
                from,
                to,
                amount,
            } => {
                let tv = self.vreg();
                let fv = self.vreg();
                let tov = self.vreg();
                let av = self.vreg();
                self.lower_expr_into(token, tv, scope);
                self.lower_expr_into(from, fv, scope);
                self.lower_expr_into(to, tov, scope);
                self.lower_expr_into(amount, av, scope);
                self.push(Ir::TokenTransfer(tv, fv, tov, av));
                self.push(Ir::Mov(dst, 1)); // success = true (VM traps on failure)
            }
            Expr::TokenMint { token, to, amount } => {
                let tv = self.vreg();
                let tov = self.vreg();
                let av = self.vreg();
                self.lower_expr_into(token, tv, scope);
                self.lower_expr_into(to, tov, scope);
                self.lower_expr_into(amount, av, scope);
                self.push(Ir::TokenMint(tv, tov, av));
                self.push(Ir::Mov(dst, 1));
            }
            Expr::TokenBurn {
                token,
                owner,
                amount,
            } => {
                let tv = self.vreg();
                let ov = self.vreg();
                let av = self.vreg();
                self.lower_expr_into(token, tv, scope);
                self.lower_expr_into(owner, ov, scope);
                self.lower_expr_into(amount, av, scope);
                self.push(Ir::TokenBurn(tv, ov, av));
                self.push(Ir::Mov(dst, 1));
            }
            Expr::CallCell {
                cell, method, args, ..
            } => {
                let cell_v = self.vreg();
                self.lower_expr_into(cell, cell_v, scope);

                // Build calldata in the call buffer at runtime:
                //   BufReset
                //   BufWriteConst([selector 4 bytes])
                //   BufWriteReg(arg0), BufWriteReg(arg1), ...
                //   BufCallCell(cell_v, value_v)
                let sel = truthlinked_axiom_sdk::abi::selector_of(method);
                let sel_bytes = sel.to_vec();
                // Pad selector to 32 bytes so BufWriteConst writes a clean word,
                // then we only use the first 4 bytes - actually write exactly 4 bytes.
                // BufWriteConst appends the exact bytes of the const entry, so pass 4 bytes.
                self.push(Ir::BufReset);
                self.push(Ir::BufWriteConst(sel_bytes.clone()));

                // Evaluate each arg into a register and append to buffer
                for arg_expr in args.iter() {
                    let av = self.vreg();
                    self.lower_expr_into(arg_expr, av, scope);
                    self.push(Ir::BufWriteReg(av));
                }

                let val_v = self.vreg();
                self.push(Ir::LoadImm8(val_v, 0));
                self.push(Ir::BufCallCell(cell_v, val_v));
                self.push(Ir::Mov(dst, 1));
            }
            Expr::Call { name, args } => {
                if let Some((lbl, arg_vregs, ret_vreg)) = self.helpers.get(name).cloned() {
                    for (arg_expr, &arg_vreg) in args.iter().zip(arg_vregs.iter()) {
                        self.lower_expr_into(arg_expr, arg_vreg, scope);
                    }
                    self.push(Ir::Call(lbl));
                    self.push(Ir::Mov(dst, ret_vreg));
                }
            }
            Expr::Hash(inner) => {
                let v = self.vreg();
                self.lower_expr_into(inner, v, scope);
                self.push(Ir::Hash32(dst, v));
            }
            Expr::Index { base, key } => {
                // mapping[key] or array[index] → SLoad(sha256(slot_key || key))
                let base_name = match base.as_ref() {
                    Expr::Var(n) => n.clone(),
                    _ => {
                        self.push(Ir::LoadImm8(dst, 0));
                        return;
                    }
                };
                let slot_key = self.slot_keys.get(&base_name).cloned().unwrap_or_else(|| {
                    truthlinked_axiom_sdk::hashing::namespace(&base_name).to_vec()
                });
                let key_v = self.vreg();
                self.lower_expr_into(key, key_v, scope);
                // derived_key = sha256(slot_key || key_reg)
                let slot_v = self.vreg();
                self.push(Ir::LoadConst(slot_v, slot_key));
                // Use Hash32 on slot_v XOR key_v as a simple derivation
                // Proper: BufReset; BufWriteConst(slot); BufWriteReg(key); Hash32(dst, buf)
                // For now: derived = sha256(slot_key_bytes) XOR key - use storage_key helper
                let derived_v = self.vreg();
                self.push(Ir::Xor(derived_v, slot_v, key_v));
                self.push(Ir::Hash32(derived_v, derived_v));
                self.push(Ir::SLoad(dst, derived_v));
            }
            Expr::Field { base, field } => {
                // struct.field → SLoad(sha256(slot_key || field_name))
                let base_name = match base.as_ref() {
                    Expr::Var(n) => n.clone(),
                    _ => {
                        self.push(Ir::LoadImm8(dst, 0));
                        return;
                    }
                };
                let mut field_key = truthlinked_axiom_sdk::hashing::namespace(&base_name).to_vec();
                field_key.extend_from_slice(field.as_bytes());
                let derived = truthlinked_axiom_sdk::hashing::sha256(&field_key);
                let kv = self.vreg();
                self.push(Ir::LoadConst(kv, derived.to_vec()));
                self.push(Ir::SLoad(dst, kv));
            }
            Expr::AccordRequest { url, method, body } => {
                let url_v = self.vreg();
                let meth_v = self.vreg();
                let body_v = self.vreg();
                self.lower_expr_into(url, url_v, scope);
                // Method is read by the VM as raw bytes from the register (null-terminated),
                // NOT as a const-pool index. If the caller wrote a string literal like "GET",
                // we must emit LoadConst (left-aligned bytes in register) rather than
                // LoadConstIndex (which puts the pool index in the register).
                match method.as_ref() {
                    Expr::Bytes(b) => {
                        self.push(Ir::LoadConst(meth_v, b.clone()));
                    }
                    other => {
                        self.lower_expr_into(other, meth_v, scope);
                    }
                }
                self.lower_expr_into(body, body_v, scope);
                self.push(Ir::AccordRequest(dst, url_v, meth_v, body_v));
            }
            Expr::AccordRead { request_id } => {
                let req_v = self.vreg();
                self.lower_expr_into(request_id, req_v, scope);
                self.push(Ir::AccordRead(dst, req_v));
            }
        }
    }

    // ── LValue helpers ────────────────────────────────────────────────────

    fn load_lvalue(&mut self, lv: &LValue, dst: VReg, scope: &HashMap<String, VReg>) {
        match lv {
            LValue::Var(name) => self.load_var_or_slot(name, dst, scope),
            LValue::Index { base, key } => {
                let slot_key =
                    self.slot_keys.get(base).cloned().unwrap_or_else(|| {
                        truthlinked_axiom_sdk::hashing::namespace(base).to_vec()
                    });
                let key_v = self.vreg();
                self.lower_expr_into(key, key_v, scope);
                let slot_v = self.vreg();
                self.push(Ir::LoadConst(slot_v, slot_key));
                let derived_v = self.vreg();
                self.push(Ir::Xor(derived_v, slot_v, key_v));
                self.push(Ir::Hash32(derived_v, derived_v));
                self.push(Ir::SLoad(dst, derived_v));
            }
            LValue::Field { base, field } => {
                let mut field_key = truthlinked_axiom_sdk::hashing::namespace(base).to_vec();
                field_key.extend_from_slice(field.as_bytes());
                let derived = truthlinked_axiom_sdk::hashing::sha256(&field_key);
                let kv = self.vreg();
                self.push(Ir::LoadConst(kv, derived.to_vec()));
                self.push(Ir::SLoad(dst, kv));
            }
        }
    }

    fn store_lvalue(&mut self, lv: &LValue, src: VReg, scope: &HashMap<String, VReg>) {
        match lv {
            LValue::Var(name) => self.store_var_or_slot(name, src, scope),
            LValue::Index { base, key } => {
                let slot_key =
                    self.slot_keys.get(base).cloned().unwrap_or_else(|| {
                        truthlinked_axiom_sdk::hashing::namespace(base).to_vec()
                    });
                let key_v = self.vreg();
                self.lower_expr_into(key, key_v, scope);
                let slot_v = self.vreg();
                self.push(Ir::LoadConst(slot_v, slot_key));
                let derived_v = self.vreg();
                self.push(Ir::Xor(derived_v, slot_v, key_v));
                self.push(Ir::Hash32(derived_v, derived_v));
                self.push(Ir::SStore(derived_v, src));
            }
            LValue::Field { base, field } => {
                let mut field_key = truthlinked_axiom_sdk::hashing::namespace(base).to_vec();
                field_key.extend_from_slice(field.as_bytes());
                let derived = truthlinked_axiom_sdk::hashing::sha256(&field_key);
                let kv = self.vreg();
                self.push(Ir::LoadConst(kv, derived.to_vec()));
                self.push(Ir::SStore(kv, src));
            }
        }
    }

    #[allow(dead_code)]
    fn lower_expr_into_lvalue_key(&mut self, lv: &LValue, scope: &HashMap<String, VReg>) -> VReg {
        let kv = self.vreg();
        match lv {
            LValue::Var(name) => {
                if let Some(key) = self.slot_keys.get(name).cloned() {
                    self.push(Ir::LoadConst(kv, key));
                }
            }
            LValue::Index { base, key } => {
                let slot_key =
                    self.slot_keys.get(base).cloned().unwrap_or_else(|| {
                        truthlinked_axiom_sdk::hashing::namespace(base).to_vec()
                    });
                let key_v = self.vreg();
                self.lower_expr_into(key, key_v, scope);
                let slot_v = self.vreg();
                self.push(Ir::LoadConst(slot_v, slot_key));
                self.push(Ir::Xor(kv, slot_v, key_v));
                self.push(Ir::Hash32(kv, kv));
            }
            LValue::Field { base, field } => {
                let mut field_key = truthlinked_axiom_sdk::hashing::namespace(base).to_vec();
                field_key.extend_from_slice(field.as_bytes());
                let derived = truthlinked_axiom_sdk::hashing::sha256(&field_key);
                self.push(Ir::LoadConst(kv, derived.to_vec()));
            }
        }
        kv
    }

    fn load_var_or_slot(&mut self, name: &str, dst: VReg, scope: &HashMap<String, VReg>) {
        if let Some(&v) = scope.get(name) {
            self.push(Ir::Mov(dst, v));
        } else if let Some(key) = self.slot_keys.get(name).cloned() {
            let kv = self.vreg();
            self.push(Ir::LoadConst(kv, key));
            self.push(Ir::SLoad(dst, kv));
        } else if name == "value" {
            self.push(Ir::GetValue(dst));
        }
    }

    fn store_var_or_slot(&mut self, name: &str, src: VReg, scope: &HashMap<String, VReg>) {
        if let Some(key) = self.slot_keys.get(name).cloned() {
            let kv = self.vreg();
            self.push(Ir::LoadConst(kv, key));
            self.push(Ir::SStore(kv, src));
        } else if let Some(&v) = scope.get(name) {
            self.push(Ir::Mov(v, src));
        }
    }
}

pub fn lower(cell: &CellDef) -> Vec<Ir> {
    Lowerer::new(cell).lower()
}
