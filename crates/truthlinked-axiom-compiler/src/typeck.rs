//! Type checker for .cell AST.
//!
//! Ownership / borrow rules enforced here:
//!
//! 1. Every `owned` param must be consumed **exactly once** - passed to a token op,
//!    cross-cell call, or returned.
//! 2. Consumption in only one branch of an `if` is an error (branch asymmetry).
//! 3. Consumption inside a loop body is an error (would consume N times).
//! 4. Aliasing an owned param through a `let` binding propagates ownership -
//!    the alias must be consumed instead of the original.
//! 5. Storage reads are never consuming positions - a storage slot is not owned.

use crate::ast::*;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
#[error("type error: {0}")]
pub struct TypeError(pub String);

fn e(msg: impl Into<String>) -> TypeError {
    TypeError(msg.into())
}

pub struct TypeChecker<'a> {
    cell: &'a CellDef,
    errors: HashMap<String, ()>,
    storage: HashMap<String, Type>,
    structs: HashMap<String, Vec<FieldDef>>,
}

impl<'a> TypeChecker<'a> {
    pub fn new(cell: &'a CellDef) -> Self {
        let errors = cell.errors.iter().map(|e| (e.name.clone(), ())).collect();
        let storage = cell
            .storage
            .iter()
            .map(|s| (s.name.clone(), s.ty.clone()))
            .collect();
        let structs = cell
            .structs
            .iter()
            .map(|s| (s.name.clone(), s.fields.clone()))
            .collect();
        Self {
            cell,
            errors,
            storage,
            structs,
        }
    }

    pub fn check(&self) -> Result<(), TypeError> {
        if let Some(init) = &self.cell.init {
            self.check_body(&init.body, &self.params_scope(&init.params), None)?;
            self.check_ownership(&init.body, &init.params)?;
        }
        for f in &self.cell.fns {
            self.check_body(&f.body, &self.params_scope(&f.params), f.ret.as_deref())?;
            self.check_ownership(&f.body, &f.params)?;
        }
        Ok(())
    }

    /// Ownership checker: every `owned` param must be consumed exactly once.
    fn check_ownership(&self, stmts: &[Stmt], params: &[Param]) -> Result<(), TypeError> {
        let owned: Vec<&str> = params
            .iter()
            .filter(|p| p.owned)
            .map(|p| p.name.as_str())
            .collect();
        if owned.is_empty() {
            return Ok(());
        }

        // consumed[name] = count. Special sentinel: 2 = branch asymmetry error.
        let mut consumed: HashMap<&str, usize> = owned.iter().map(|n| (*n, 0)).collect();
        // aliases: local let-bindings that alias an owned param
        let mut aliases: HashMap<String, String> = HashMap::new();
        self.count_consumptions(stmts, &mut consumed, &mut aliases, false)?;

        for name in &owned {
            let count = consumed[name];
            if count == 0 {
                // Check if it was consumed via an alias
                let alias_consumed = aliases.iter().any(|(alias, src)| {
                    src.as_str() == *name && consumed.get(alias.as_str()).copied().unwrap_or(0) > 0
                });
                if !alias_consumed {
                    return Err(e(format!(
                        "owned parameter '{}' is never consumed - must be passed to a token op, call, or returned",
                        name
                    )));
                }
            } else if count == 2 {
                return Err(e(format!(
                    "owned parameter '{}' is consumed in only one branch of an if - must be consumed in both branches or neither",
                    name
                )));
            } else if count > 1 {
                return Err(e(format!(
                    "owned parameter '{}' is consumed {} times - double-spend detected",
                    name, count
                )));
            }
        }
        Ok(())
    }

    fn count_consumptions<'b>(
        &self,
        stmts: &[Stmt],
        consumed: &mut HashMap<&'b str, usize>,
        aliases: &mut HashMap<String, String>,
        in_loop: bool,
    ) -> Result<(), TypeError>
    where
        'a: 'b,
    {
        for stmt in stmts {
            match stmt {
                Stmt::Let { name, expr, .. } => {
                    // Track aliasing: `let x = owned_param` propagates ownership to x
                    if let Expr::Var(src) = expr {
                        if consumed.contains_key(src.as_str()) {
                            aliases.insert(name.clone(), src.clone());
                        }
                    }
                    self.count_expr_consumptions(expr, consumed, aliases, in_loop)?;
                }
                Stmt::Assign { expr, .. } => {
                    self.count_expr_consumptions(expr, consumed, aliases, in_loop)?
                }
                Stmt::AssignAdd { expr, .. }
                | Stmt::AssignSub { expr, .. }
                | Stmt::AssignMul { expr, .. }
                | Stmt::AssignDiv { expr, .. } => {
                    self.count_expr_consumptions(expr, consumed, aliases, in_loop)?;
                }
                Stmt::Return { exprs } => {
                    for ex in exprs {
                        self.mark_if_owned(ex, consumed, aliases, in_loop)?;
                        self.count_expr_consumptions(ex, consumed, aliases, in_loop)?;
                    }
                }
                Stmt::If { cond, then, else_ } => {
                    self.count_expr_consumptions(cond, consumed, aliases, in_loop)?;
                    let mut then_c = consumed.clone();
                    let mut else_c = consumed.clone();
                    let mut then_a = aliases.clone();
                    let mut else_a = aliases.clone();
                    self.count_consumptions(then, &mut then_c, &mut then_a, in_loop)?;
                    self.count_consumptions(else_, &mut else_c, &mut else_a, in_loop)?;
                    for (k, v) in consumed.iter_mut() {
                        let in_then = then_c[k];
                        let in_else = else_c[k];
                        if in_then != in_else {
                            *v += 2; // asymmetry sentinel
                        } else {
                            *v += in_then;
                        }
                    }
                }
                Stmt::While { cond, body } => {
                    self.count_expr_consumptions(cond, consumed, aliases, in_loop)?;
                    let mut loop_c = consumed.clone();
                    let mut loop_a = aliases.clone();
                    self.count_consumptions(body, &mut loop_c, &mut loop_a, true)?;
                    for (k, v) in consumed.iter_mut() {
                        if loop_c[k] > *v {
                            return Err(e(format!(
                                "owned parameter '{}' consumed inside a loop - would be consumed multiple times",
                                k
                            )));
                        }
                    }
                }
                Stmt::Loop { body } => {
                    let mut loop_c = consumed.clone();
                    let mut loop_a = aliases.clone();
                    self.count_consumptions(body, &mut loop_c, &mut loop_a, true)?;
                    for (k, v) in consumed.iter_mut() {
                        if loop_c[k] > *v {
                            return Err(e(format!(
                                "owned parameter '{}' consumed inside a loop - would be consumed multiple times",
                                k
                            )));
                        }
                    }
                }
                Stmt::For {
                    start, end, body, ..
                } => {
                    self.count_expr_consumptions(start, consumed, aliases, in_loop)?;
                    self.count_expr_consumptions(end, consumed, aliases, in_loop)?;
                    let mut loop_c = consumed.clone();
                    let mut loop_a = aliases.clone();
                    self.count_consumptions(body, &mut loop_c, &mut loop_a, true)?;
                    for (k, v) in consumed.iter_mut() {
                        if loop_c[k] > *v {
                            return Err(e(format!(
                                "owned parameter '{}' consumed inside a for loop - would be consumed multiple times",
                                k
                            )));
                        }
                    }
                }
                Stmt::Emit { fields, .. } => {
                    for (_, ex) in fields {
                        self.count_expr_consumptions(ex, consumed, aliases, in_loop)?;
                    }
                }
                Stmt::Require { expr } => {
                    self.count_expr_consumptions(expr, consumed, aliases, in_loop)?
                }
                Stmt::Expr(expr) => {
                    self.count_expr_consumptions(expr, consumed, aliases, in_loop)?
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn count_expr_consumptions<'b>(
        &self,
        expr: &Expr,
        consumed: &mut HashMap<&'b str, usize>,
        aliases: &mut HashMap<String, String>,
        in_loop: bool,
    ) -> Result<(), TypeError>
    where
        'a: 'b,
    {
        match expr {
            Expr::TokenTransfer {
                token,
                from,
                to,
                amount,
            } => {
                self.mark_if_owned(amount, consumed, aliases, in_loop)?;
                self.count_expr_consumptions(token, consumed, aliases, in_loop)?;
                self.count_expr_consumptions(from, consumed, aliases, in_loop)?;
                self.count_expr_consumptions(to, consumed, aliases, in_loop)?;
            }
            Expr::TokenMint { token, to, amount } => {
                self.mark_if_owned(amount, consumed, aliases, in_loop)?;
                self.count_expr_consumptions(token, consumed, aliases, in_loop)?;
                self.count_expr_consumptions(to, consumed, aliases, in_loop)?;
            }
            Expr::TokenBurn {
                token,
                owner,
                amount,
            } => {
                self.mark_if_owned(amount, consumed, aliases, in_loop)?;
                self.count_expr_consumptions(token, consumed, aliases, in_loop)?;
                self.count_expr_consumptions(owner, consumed, aliases, in_loop)?;
            }
            Expr::CallCell { args, .. } => {
                for a in args {
                    self.mark_if_owned(a, consumed, aliases, in_loop)?;
                }
            }
            Expr::Call { args, .. } => {
                for a in args {
                    self.mark_if_owned(a, consumed, aliases, in_loop)?;
                }
            }
            Expr::Bin { lhs, rhs, .. } => {
                self.count_expr_consumptions(lhs, consumed, aliases, in_loop)?;
                self.count_expr_consumptions(rhs, consumed, aliases, in_loop)?;
            }
            Expr::Not(inner) | Expr::Hash(inner) => {
                self.count_expr_consumptions(inner, consumed, aliases, in_loop)?
            }
            Expr::Index { base, key } => {
                self.count_expr_consumptions(base, consumed, aliases, in_loop)?;
                self.count_expr_consumptions(key, consumed, aliases, in_loop)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn mark_if_owned<'b>(
        &self,
        expr: &Expr,
        consumed: &mut HashMap<&'b str, usize>,
        aliases: &HashMap<String, String>,
        in_loop: bool,
    ) -> Result<(), TypeError>
    where
        'a: 'b,
    {
        if let Expr::Var(name) = expr {
            // Direct owned param
            if let Some(count) = consumed.get_mut(name.as_str()) {
                if in_loop {
                    return Err(e(format!(
                        "owned parameter '{}' consumed inside a loop - would be consumed multiple times",
                        name
                    )));
                }
                *count += 1;
                return Ok(());
            }
            // Alias of an owned param
            if let Some(src) = aliases.get(name.as_str()) {
                if let Some(count) = consumed.get_mut(src.as_str()) {
                    if in_loop {
                        return Err(e(format!(
                            "owned parameter '{}' (via alias '{}') consumed inside a loop",
                            src, name
                        )));
                    }
                    *count += 1;
                }
            }
        }
        Ok(())
    }

    fn params_scope(&self, params: &[Param]) -> HashMap<String, Type> {
        params
            .iter()
            .map(|p| (p.name.clone(), p.ty.clone()))
            .collect()
    }

    fn check_body(
        &self,
        stmts: &[Stmt],
        scope: &HashMap<String, Type>,
        ret_ty: Option<&[Type]>,
    ) -> Result<(), TypeError> {
        let mut scope = scope.clone();
        for stmt in stmts {
            self.check_stmt(stmt, &mut scope, ret_ty)?;
        }
        Ok(())
    }

    fn lvalue_type(&self, lv: &LValue, scope: &HashMap<String, Type>) -> Result<Type, TypeError> {
        match lv {
            LValue::Var(name) => self
                .storage
                .get(name)
                .or_else(|| scope.get(name))
                .cloned()
                .ok_or_else(|| e(format!("undefined variable '{}'", name))),
            LValue::Index { base, .. } => {
                let base_ty = self
                    .storage
                    .get(base)
                    .or_else(|| scope.get(base))
                    .cloned()
                    .ok_or_else(|| e(format!("undefined variable '{}'", base)))?;
                match base_ty {
                    Type::Mapping(_, v) => Ok(*v),
                    Type::Array(v) => Ok(*v),
                    _ => Err(e(format!("'{}' is not indexable", base))),
                }
            }
            LValue::Field { base, field } => {
                let base_ty = self
                    .storage
                    .get(base)
                    .or_else(|| scope.get(base))
                    .cloned()
                    .ok_or_else(|| e(format!("undefined variable '{}'", base)))?;
                match base_ty {
                    Type::Struct(name) => {
                        let fields = self
                            .structs
                            .get(&name)
                            .ok_or_else(|| e(format!("unknown struct '{}'", name)))?;
                        fields
                            .iter()
                            .find(|f| &f.name == field)
                            .map(|f| f.ty.clone())
                            .ok_or_else(|| e(format!("struct '{}' has no field '{}'", name, field)))
                    }
                    _ => Err(e(format!("'{}' is not a struct", base))),
                }
            }
        }
    }

    fn check_stmt(
        &self,
        stmt: &Stmt,
        scope: &mut HashMap<String, Type>,
        ret_ty: Option<&[Type]>,
    ) -> Result<(), TypeError> {
        match stmt {
            Stmt::Let { name, ty, expr } => {
                let inferred = self.infer(expr, scope)?;
                let final_ty = if let Some(declared) = ty {
                    self.check_assignable(&inferred, declared, name)?;
                    declared.clone()
                } else {
                    inferred
                };
                scope.insert(name.clone(), final_ty);
            }
            Stmt::Assign { target, expr } => {
                let rhs_ty = self.infer(expr, scope)?;
                let target_ty = self.lvalue_type(target, scope)?;
                let name = match target {
                    LValue::Var(n) => n.as_str(),
                    _ => "target",
                };
                self.check_assignable(&rhs_ty, &target_ty, name)?;
            }
            Stmt::AssignAdd { target, expr }
            | Stmt::AssignSub { target, expr }
            | Stmt::AssignMul { target, expr }
            | Stmt::AssignDiv { target, expr } => {
                let rhs_ty = self.infer(expr, scope)?;
                let target_ty = self.lvalue_type(target, scope)?;
                let name = match target {
                    LValue::Var(n) => n.as_str(),
                    _ => "target",
                };
                self.check_assignable(&rhs_ty, &target_ty, name)?;
            }
            Stmt::Require { expr } => {
                self.infer(expr, scope)?;
            }
            Stmt::Revert { error } => {
                if !self.errors.contains_key(error) {
                    return Err(e(format!("revert '{}': error not declared", error)));
                }
            }
            Stmt::Return { exprs } => {
                if let Some(ret_types) = ret_ty {
                    if exprs.len() != ret_types.len() {
                        return Err(e(format!(
                            "return arity mismatch: expected {} values, got {}",
                            ret_types.len(),
                            exprs.len()
                        )));
                    }
                    for (expr, expected) in exprs.iter().zip(ret_types.iter()) {
                        let ty = self.infer(expr, scope)?;
                        self.check_assignable(&ty, expected, "return")?;
                    }
                }
            }
            Stmt::Emit { fields, .. } => {
                for (_, expr) in fields {
                    self.infer(expr, scope)?;
                }
            }
            Stmt::If { cond, then, else_ } => {
                self.infer(cond, scope)?;
                self.check_body(then, scope, ret_ty)?;
                self.check_body(else_, scope, ret_ty)?;
            }
            Stmt::While { cond, body } => {
                self.infer(cond, scope)?;
                self.check_body(body, scope, ret_ty)?;
            }
            Stmt::For {
                var,
                start,
                end,
                body,
            } => {
                self.infer(start, scope)?;
                self.infer(end, scope)?;
                let mut inner = scope.clone();
                inner.insert(var.clone(), Type::U64);
                self.check_body(body, &inner, ret_ty)?;
            }
            Stmt::Loop { body } => {
                self.check_body(body, scope, ret_ty)?;
            }
            Stmt::Break | Stmt::Continue => {}
            Stmt::Expr(expr) => {
                self.infer(expr, scope)?;
            }
        }
        Ok(())
    }

    fn check_assignable(&self, from: &Type, to: &Type, target: &str) -> Result<(), TypeError> {
        if from == to {
            return Ok(());
        }
        if from == &Type::U256 && matches!(to, Type::U64 | Type::U128 | Type::U256) {
            return Ok(());
        }
        if from == &Type::U64 && matches!(to, Type::U128 | Type::U256) {
            return Ok(());
        }
        if from == &Type::U128 && to == &Type::U256 {
            return Ok(());
        }
        // true/false are Int(1)/Int(0) → U64; allow assigning to bool and vice versa
        if matches!(from, Type::U64 | Type::U256) && to == &Type::Bool {
            return Ok(());
        }
        if from == &Type::Bool && matches!(to, Type::U64 | Type::U128 | Type::U256) {
            return Ok(());
        }
        Err(e(format!(
            "type mismatch for '{}': cannot assign {:?} to {:?}",
            target, from, to
        )))
    }

    fn infer(&self, expr: &Expr, scope: &HashMap<String, Type>) -> Result<Type, TypeError> {
        match expr {
            Expr::Int(v) => {
                if *v <= u64::MAX as u128 { Ok(Type::U64) }
                else if *v <= u128::MAX   { Ok(Type::U128) }
                else                      { Ok(Type::U256) }
            }
            Expr::Bytes(_)     => Ok(Type::U256),
            Expr::Caller       => Ok(Type::Address),
            Expr::Owner        => Ok(Type::Address),
            Expr::SelfAddr     => Ok(Type::Address),
            Expr::Height       => Ok(Type::U64),
            Expr::Timestamp    => Ok(Type::U64),
            Expr::Value        => Ok(Type::U128),
            Expr::Var(name) => {
                if let Some(ty) = scope.get(name) { return Ok(ty.clone()); }
                if let Some(ty) = self.storage.get(name) { return Ok(ty.clone()); }
                if name == "value" { return Ok(Type::U128); }
                Err(e(format!("undefined variable '{}'", name)))
            }
            Expr::Index { base, key } => {
                let base_ty = self.infer(base, scope)?;
                self.infer(key, scope)?;
                match base_ty {
                    Type::Mapping(_, v) => Ok(*v),
                    Type::Array(v)      => Ok(*v),
                    _ => Err(e("index operator requires mapping or array")),
                }
            }
            Expr::Field { base, field } => {
                let base_ty = self.infer(base, scope)?;
                match base_ty {
                    Type::Struct(name) => {
                        let fields = self.structs.get(&name)
                            .ok_or_else(|| e(format!("unknown struct '{}'", name)))?;
                        fields.iter().find(|f| &f.name == field)
                            .map(|f| f.ty.clone())
                            .ok_or_else(|| e(format!("struct '{}' has no field '{}'", name, field)))
                    }
                    _ => Err(e(format!("field access on non-struct type"))),
                }
            }
            Expr::Hash(_)          => Ok(Type::U256),
            Expr::Not(inner)       => { self.infer(inner, scope)?; Ok(Type::Bool) }
            Expr::Bin { lhs, rhs, op } => {
                let lt = self.infer(lhs, scope)?;
                let _rt = self.infer(rhs, scope)?;
                match op {
                    BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le |
                    BinOp::Gt | BinOp::Ge | BinOp::LogicAnd | BinOp::LogicOr => Ok(Type::Bool),
                    _ => Ok(lt),
                }
            }
            Expr::TokenBalance { .. }  => Ok(Type::U128),
            Expr::TokenTransfer { .. } | Expr::TokenMint { .. } | Expr::TokenBurn { .. } => Ok(Type::Bool),
            Expr::AccordRequest { .. } | Expr::AccordRead { .. } => Ok(Type::U256),
            Expr::CallCell { ret, method, .. } => {
                match ret {
                    Some(ty) => Ok(ty.clone()),
                    None => Err(e(format!(
                        "cross-cell call to '{}' has no declared return type - use `call x.{}(...) -> type`",
                        method, method
                    ))),
                }
            }
            Expr::Call { name, .. } => {
                if let Some(f) = self.cell.fns.iter().find(|f| &f.name == name) {
                    match &f.ret {
                        Some(types) if types.len() == 1 => Ok(types[0].clone()),
                        Some(types) if types.len() > 1  => Ok(Type::U256), // tuple - caller unpacks
                        _ => Ok(Type::Bool),
                    }
                } else {
                    Err(e(format!("call to undefined function '{}'", name)))
                }
            }
        }
    }
}

pub fn check(cell: &CellDef) -> Result<(), TypeError> {
    TypeChecker::new(cell).check()
}
