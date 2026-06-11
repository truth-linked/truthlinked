//! Procedural macro helpers for TruthLinked Axiom cell development.
//!
//! The macros in this crate provide a Rust-native authoring layer for Axiom
//! cells while keeping expansion explicit and deterministic. Generated code must
//! remain stable across compiler versions because cell artifacts are deployed and
//! audited on chain.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TS2;
use quote::quote;
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, BinOp, Expr, ExprCall, ExprMacro, Item, ItemFn,
    ItemMod, ItemStatic, Pat, Stmt, Type, UnOp,
};

#[proc_macro_attribute]
pub fn axiom_cell(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let module = parse_macro_input!(item as ItemMod);
    match expand_cell(module) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_cell(module: ItemMod) -> syn::Result<TS2> {
    let mod_name = &module.ident;
    let bytecode_fn = syn::Ident::new(&format!("{}_bytecode", mod_name), mod_name.span());
    let selectors_fn = syn::Ident::new(&format!("{}_selectors", mod_name), mod_name.span());

    let items = match &module.content {
        Some((_, items)) => items,
        None => {
            return Err(syn::Error::new(
                module.span(),
                "#[axiom_cell] requires an inline module body",
            ))
        }
    };

    let mut storage_slots: Vec<StorageSlot> = vec![];
    let mut selectors: Vec<SelectorFn> = vec![];
    let mut helpers: Vec<HelperFn> = vec![];

    for item in items {
        match item {
            Item::Static(s) if has_attr(&s.attrs, "storage") => {
                storage_slots.push(parse_storage(s)?)
            }
            Item::Fn(f) if has_attr(&f.attrs, "selector") => selectors.push(parse_selector(f)?),
            Item::Fn(f) if !has_attr(&f.attrs, "selector") && !has_attr(&f.attrs, "storage") => {
                helpers.push(parse_helper(f)?);
            }
            _ => {}
        }
    }

    let mut all_ir_code: Vec<TS2> = vec![];
    let mut selector_entries: Vec<TS2> = vec![];

    // Single monotonic counters - no magic-number offsets, no collision risk.
    // Each selector/helper draws a contiguous block at expansion time.
    let mut next_vreg: u32 = 1; // 0 = zero reg, reserved
    let mut next_label: u32 = 0;

    for (_sel_idx, sel) in selectors.iter().enumerate() {
        let sel_name = &sel.name;
        selector_entries.push(quote! {
            (#sel_name, truthlinked_sdk::abi::selector_of(#sel_name))
        });

        let handler_label = next_label;
        next_label += 1;

        // Allocate dispatch vregs
        let v_cd = next_vreg;
        next_vreg += 1;
        let v_sel = next_vreg;
        next_vreg += 1;
        let v_mask = next_vreg;
        next_vreg += 1;
        let v_mcd = next_vreg;
        next_vreg += 1;
        let v_cond = next_vreg;
        next_vreg += 1;

        let n_args = sel.args.len() as u32;
        let arg_base = next_vreg;
        next_vreg += n_args;
        let off_base = next_vreg;
        next_vreg += n_args;
        let body_vreg_start = next_vreg;
        next_vreg += 10_000; // 10k vregs per selector body - regalloc packs to physical regs
        let label_start = next_label;
        next_label += 10_000;

        all_ir_code.push(quote! {
            {
                // Load calldata word 0 into v_cd
                ir.push(Ir::LoadImm8(#v_cd, 0));
                ir.push(Ir::GetCalldata(#v_cd, #v_cd));
                // Load selector constant
                let sel_bytes = truthlinked_sdk::abi::selector_of(#sel_name);
                let mut sel32 = vec![0u8; 32];
                sel32[..4].copy_from_slice(&sel_bytes);
                ir.push(Ir::LoadConst(#v_sel, sel32));
                // Mask to low 4 bytes
                let mut mask32 = vec![0u8; 32];
                mask32[0]=0xFF; mask32[1]=0xFF; mask32[2]=0xFF; mask32[3]=0xFF;
                ir.push(Ir::LoadConst(#v_mask, mask32));
                ir.push(Ir::And(#v_mcd, #v_cd, #v_mask));
                ir.push(Ir::Eq(#v_cond, #v_mcd, #v_sel));
                ir.push(Ir::JumpIf(#v_cond, #handler_label));
            }
        });

        // Load args from calldata
        let mut arg_loads: Vec<TS2> = vec![];
        for i in 0..n_args {
            let vreg = arg_base + i;
            let off_vreg = off_base + i;
            let offset = (4 + i * 32) as u64;
            arg_loads.push(quote! {
                ir.push(Ir::LoadImm64(#off_vreg, #offset));
                ir.push(Ir::GetCalldata(#vreg, #off_vreg));
            });
        }

        // Build a name→vreg map for args
        let arg_names: Vec<String> = sel.args.iter().map(|(n, _)| n.to_string()).collect();
        let arg_vregs: Vec<u32> = (0..n_args).map(|i| arg_base + i).collect();

        // Lower body with a runtime vreg/label counter
        let body_code = lower_body_ir_full(
            &sel.body,
            &storage_slots,
            &helpers,
            &arg_names,
            &arg_vregs,
            body_vreg_start,
            label_start,
        );

        let vreg_ceiling = body_vreg_start + 10_000;
        let label_ceiling = label_start + 10_000;
        all_ir_code.push(quote! {
            ir.push(Ir::Label(#handler_label));
            #(#arg_loads)*
            {
                let mut _vreg: u32 = #body_vreg_start;
                let mut _label: u32 = #label_start + 1;
                let mut _break_stack: Vec<u32> = Vec::new();
                let mut _continue_stack: Vec<u32> = Vec::new();
                #body_code
                assert!(_vreg <= #vreg_ceiling,
                    "axiom_cell: selector '{}' used {} vregs, exceeds 500-slot limit (overflow into adjacent block)",
                    #sel_name, _vreg - #body_vreg_start);
                assert!(_label <= #label_ceiling,
                    "axiom_cell: selector '{}' used {} labels, exceeds 500-slot limit",
                    #sel_name, _label - #label_start);
            }
        });
    }

    all_ir_code.push(quote! { ir.push(Ir::Trap(0x0001)); });

    // Emit helper subroutines after the dispatch table.
    // Each helper gets a unique label: fn_<name>_<idx>.
    // Call convention: args in consecutive vregs starting at _fn_arg_base,
    // return value in _fn_ret_vreg. Both are passed by the caller.
    // First pass: allocate labels and vregs for all helpers so call sites can reference them
    for helper in helpers.iter_mut() {
        let fn_label_id = next_label;
        next_label += 1;
        let n_args = helper.args.len() as u32;
        let h_arg_base = next_vreg;
        next_vreg += n_args;
        let ret_vreg = next_vreg;
        next_vreg += 1;
        next_vreg += 10_000; // body locals
        next_label += 10_000;
        helper.label_id = fn_label_id;
        helper.arg_vregs = (0..n_args).map(|i| h_arg_base + i).collect();
        helper.ret_vreg = ret_vreg;
    }

    // Second pass: emit subroutine bodies
    for helper in helpers.iter() {
        let fn_label_id = helper.label_id;
        let _fn_name = &helper.name;
        let _n_args = helper.args.len() as u32;
        let ret_vreg = helper.ret_vreg;
        let body_vreg_start = helper.ret_vreg + 1;
        let h_label_start = helper.label_id + 1;

        let arg_names: Vec<String> = helper.args.iter().map(|(n, _)| n.to_string()).collect();
        let arg_vregs = &helper.arg_vregs;

        let body_code = lower_body_ir_full(
            &helper.body,
            &storage_slots,
            &helpers,
            &arg_names,
            arg_vregs,
            body_vreg_start,
            h_label_start,
        );

        let h_vreg_ceiling = body_vreg_start + 10_000u32;
        let h_label_ceiling = h_label_start + 10_000u32;
        let fn_name_str = &helper.name;

        all_ir_code.push(quote! {
            ir.push(Ir::Label(#fn_label_id));
            {
                let mut _vreg: u32 = #body_vreg_start;
                let mut _label: u32 = #h_label_start + 1;
                let mut _break_stack: Vec<u32> = Vec::new();
                let mut _continue_stack: Vec<u32> = Vec::new();
                let _fn_ret_vreg: u32 = #ret_vreg;
                #body_code
                assert!(_vreg <= #h_vreg_ceiling,
                    "axiom_cell: helper fn '{}' used {} vregs, exceeds 500-slot limit",
                    #fn_name_str, _vreg - #body_vreg_start);
                assert!(_label <= #h_label_ceiling,
                    "axiom_cell: helper fn '{}' used {} labels, exceeds 500-slot limit",
                    #fn_name_str, _label - #h_label_start);
            }
            ir.push(Ir::Return);
        });
    }

    let clean_items: Vec<TS2> = items
        .iter()
        .filter_map(|item| match item {
            Item::Static(s) if has_attr(&s.attrs, "storage") => None,
            Item::Fn(f) if has_attr(&f.attrs, "selector") => None,
            other => Some(quote! { #other }),
        })
        .collect();

    let vis = &module.vis;
    let mod_name2 = mod_name;

    Ok(quote! {
        #vis mod #mod_name2 {
            #(#clean_items)*
        }

        pub fn #bytecode_fn() -> Vec<u8> {
            use truthlinked_sdk::ir::Ir;
            use truthlinked_sdk::regalloc;
            use truthlinked_sdk::codegen;

            let mut ir: Vec<Ir> = Vec::new();
            #(#all_ir_code)*

            let alloc = regalloc::allocate(&ir);
            codegen::emit(&ir, &alloc)
        }

        pub fn #selectors_fn() -> Vec<(&'static str, [u8; 4])> {
            vec![ #(#selector_entries),* ]
        }
    })
}

// ── Lowering ─────────────────────────────────────────────────────────────────

struct StorageSlot {
    _name: syn::Ident,
    _ty: Box<Type>,
}
struct SelectorFn {
    name: String,
    body: Vec<Stmt>,
    args: Vec<(syn::Ident, Box<Type>)>,
}
struct HelperFn {
    name: String,
    body: Vec<Stmt>,
    args: Vec<(syn::Ident, Box<Type>)>,
    label_id: u32,
    arg_vregs: Vec<u32>,
    ret_vreg: u32,
}

fn has_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(name))
}

fn get_attr_str(attrs: &[Attribute], name: &str) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident(name) {
            if let Ok(list) = attr.meta.require_list() {
                if let Ok(lit) = syn::parse2::<syn::LitStr>(list.tokens.clone()) {
                    return Some(lit.value());
                }
            }
        }
    }
    None
}

fn parse_storage(s: &ItemStatic) -> syn::Result<StorageSlot> {
    Ok(StorageSlot {
        _name: s.ident.clone(),
        _ty: s.ty.clone(),
    })
}

fn parse_selector(f: &ItemFn) -> syn::Result<SelectorFn> {
    let name = get_attr_str(&f.attrs, "selector").ok_or_else(|| {
        syn::Error::new(f.span(), "#[selector(\"name\")] requires a string literal")
    })?;
    let args = f
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let syn::FnArg::Typed(pt) = arg {
                if let Pat::Ident(pi) = pt.pat.as_ref() {
                    return Some((pi.ident.clone(), pt.ty.clone()));
                }
            }
            None
        })
        .collect();
    Ok(SelectorFn {
        name,
        body: f.block.stmts.clone(),
        args,
    })
}

fn parse_helper(f: &ItemFn) -> syn::Result<HelperFn> {
    let name = f.sig.ident.to_string();
    let args = f
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let syn::FnArg::Typed(pt) = arg {
                if let Pat::Ident(pi) = pt.pat.as_ref() {
                    return Some((pi.ident.clone(), pt.ty.clone()));
                }
            }
            None
        })
        .collect();
    Ok(HelperFn {
        name,
        body: f.block.stmts.clone(),
        args,
        label_id: 0,
        arg_vregs: vec![],
        ret_vreg: 0,
    })
}

/// Lower a full selector body. Returns code that emits IR into `ir: Vec<Ir>`.
/// Uses `_vreg` and `_label` as runtime counters (declared by caller).
/// `arg_names`/`arg_vregs` map argument names to their pre-loaded vregs.
fn lower_body_ir_full(
    stmts: &[Stmt],
    slots: &[StorageSlot],
    helpers: &[HelperFn],
    arg_names: &[String],
    arg_vregs: &[u32],
    _vreg_start: u32,
    _label_start: u32,
) -> TS2 {
    // We build a name→vreg lookup as a runtime HashMap embedded in the emitted code.
    // Each `let x = ...` allocates a new vreg via `_vreg += 1`.
    let arg_inserts: Vec<TS2> = arg_names
        .iter()
        .zip(arg_vregs.iter())
        .map(|(name, vreg)| {
            quote! { _vars.insert(#name.to_string(), #vreg); }
        })
        .collect();

    let stmt_code: Vec<TS2> = stmts
        .iter()
        .map(|s| lower_stmt(s, slots, helpers))
        .collect();

    quote! {
        let mut _vars: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        #(#arg_inserts)*
        #(#stmt_code)*
    }
}

/// Lower a single statement to IR emission code.
fn lower_stmt(stmt: &Stmt, slots: &[StorageSlot], helpers: &[HelperFn]) -> TS2 {
    match stmt {
        // return Ok(()) → Halt
        Stmt::Expr(Expr::Return(r), _) => {
            if let Some(expr) = &r.expr {
                if is_ok_unit(expr) {
                    return quote! { ir.push(Ir::Halt); };
                }
                if let Some(code) = is_err_code(expr) {
                    return quote! { ir.push(Ir::Trap(#code)); };
                }
            }
            quote! { ir.push(Ir::Halt); }
        }
        // Macro calls
        Stmt::Expr(Expr::Macro(m), _) => lower_macro(m, helpers),
        // let x = expr
        Stmt::Local(local) => lower_local(local, slots, helpers),
        // bare expression
        Stmt::Expr(expr, _) => lower_expr_stmt(expr, slots, helpers),
        _ => quote! {},
    }
}

fn lower_macro(m: &ExprMacro, helpers: &[HelperFn]) -> TS2 {
    let path = m
        .mac
        .path
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default();
    match path.as_str() {
        "require_owner" => quote! { ir.push(Ir::RequireOwner); },
        "require" => {
            if let Ok(expr) = syn::parse2::<Expr>(m.mac.tokens.clone()) {
                let eval = lower_expr_to_vreg(&expr, quote! { _cond_r }, helpers);
                quote! {
                    // Allocate vreg first, then evaluate expr into it
                    let _cond_r = { _vreg += 1; _vreg };
                    #eval
                    ir.push(Ir::RequireNonZero(_cond_r));
                }
            } else {
                quote! { ir.push(Ir::RequireNonZero(3)); }
            }
        }
        _ => quote! {},
    }
}

/// Lower `let x = expr` - allocates a new vreg for x, evaluates expr into it.
fn lower_local(local: &syn::Local, _slots: &[StorageSlot], helpers: &[HelperFn]) -> TS2 {
    let var_name = match &local.pat {
        Pat::Ident(pi) => pi.ident.to_string(),
        Pat::Type(pt) => match pt.pat.as_ref() {
            Pat::Ident(pi) => pi.ident.to_string(),
            _ => return quote! {},
        },
        _ => return quote! {},
    };

    if let Some(init) = &local.init {
        let expr = &init.expr;
        let eval = lower_expr_to_vreg(expr, quote! { _dst }, helpers);
        quote! {
            let _dst = { _vreg += 1; _vreg };
            _vars.insert(#var_name.to_string(), _dst);
            #eval
        }
    } else {
        quote! {
            let _dst = { _vreg += 1; _vreg };
            _vars.insert(#var_name.to_string(), _dst);
        }
    }
}

fn lower_expr_stmt(expr: &Expr, slots: &[StorageSlot], helpers: &[HelperFn]) -> TS2 {
    match expr {
        // storage::set(&KEY, val)
        Expr::Call(call) if is_path_call(call, &["storage", "set"]) => {
            if let Some(key_name) = extract_ref_ident(&call.args) {
                let key_str = key_name.to_string();
                // second arg is the value variable name
                let val_vreg = if let Some(Expr::Path(p)) = call.args.iter().nth(1) {
                    if let Some(ident) = p.path.get_ident() {
                        let name = ident.to_string();
                        quote! { *_vars.get(#name).expect("undefined variable") }
                    } else {
                        quote! { 0u32 }
                    }
                } else {
                    quote! { 0u32 }
                };
                return quote! {
                    let _kv = { _vreg += 1; _vreg };
                    let key = truthlinked_sdk::hashing::namespace(#key_str);
                    ir.push(Ir::LoadConst(_kv, key.to_vec()));
                    ir.push(Ir::SStore(_kv, #val_vreg));
                };
            }
            quote! {}
        }
        // if/else as statement
        Expr::If(ei) => lower_if_expr(ei, slots, helpers, None),
        // while cond { body }
        Expr::While(w) => {
            let cond_eval = lower_expr_to_vreg(&w.cond, quote! { _while_cond }, helpers);
            let body: Vec<TS2> = w
                .body
                .stmts
                .iter()
                .map(|s| lower_stmt(s, slots, helpers))
                .collect();
            quote! {{
                let _while_cond = { _vreg += 1; _vreg };
                let _loop_start = { _label += 1; _label };
                let _loop_end   = { _label += 1; _label };
                // push loop_end onto break stack so break/continue can find it
                _break_stack.push(_loop_end);
                _continue_stack.push(_loop_start);
                ir.push(Ir::Label(_loop_start));
                #cond_eval
                ir.push(Ir::JumpIfNot(_while_cond, _loop_end));
                #(#body)*
                ir.push(Ir::Jump(_loop_start));
                ir.push(Ir::Label(_loop_end));
                _break_stack.pop();
                _continue_stack.pop();
            }}
        }
        // loop { body } - infinite loop, broken by break
        Expr::Loop(l) => {
            let body: Vec<TS2> = l
                .body
                .stmts
                .iter()
                .map(|s| lower_stmt(s, slots, helpers))
                .collect();
            quote! {{
                let _loop_start = { _label += 1; _label };
                let _loop_end   = { _label += 1; _label };
                _break_stack.push(_loop_end);
                _continue_stack.push(_loop_start);
                ir.push(Ir::Label(_loop_start));
                #(#body)*
                ir.push(Ir::Jump(_loop_start));
                ir.push(Ir::Label(_loop_end));
                _break_stack.pop();
                _continue_stack.pop();
            }}
        }
        // break → jump to innermost loop end
        Expr::Break(_) => quote! {
            ir.push(Ir::Jump(*_break_stack.last().expect("break outside loop")));
        },
        // continue → jump to innermost loop start
        Expr::Continue(_) => quote! {
            ir.push(Ir::Jump(*_continue_stack.last().expect("continue outside loop")));
        },
        // bare call
        Expr::Call(call) => {
            let dst = quote! { { _vreg += 1; _vreg } };
            lower_call_to_vreg(call, dst, slots, helpers)
        }
        _ => quote! {},
    }
}

/// Lower an expression into a vreg identified by `dst_expr` (a TokenStream that evaluates to u32).
fn lower_expr_to_vreg(expr: &Expr, dst_expr: TS2, helpers: &[HelperFn]) -> TS2 {
    match expr {
        // Variable reference
        Expr::Path(p) if p.path.get_ident().is_some() => {
            let name = p.path.get_ident().unwrap().to_string();
            quote! {
                {
                    let _src = *_vars.get(#name).expect(concat!("undefined variable: ", #name));
                    ir.push(Ir::Mov(#dst_expr, _src));
                }
            }
        }
        // Integer literal
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(i),
            ..
        }) => {
            if let Ok(v) = i.base10_parse::<u64>() {
                quote! { ir.push(Ir::LoadImm64(#dst_expr, #v)); }
            } else {
                quote! {}
            }
        }
        // context::caller() etc.
        Expr::Call(call) if is_path_call(call, &["context", "caller"]) => {
            quote! { ir.push(Ir::GetCaller(#dst_expr)); }
        }
        Expr::Call(call) if is_path_call(call, &["context", "owner"]) => {
            quote! { ir.push(Ir::GetOwner(#dst_expr)); }
        }
        Expr::Call(call) if is_path_call(call, &["context", "height"]) => {
            quote! { ir.push(Ir::GetHeight(#dst_expr)); }
        }
        Expr::Call(call) if is_path_call(call, &["context", "value"]) => {
            quote! { ir.push(Ir::GetValue(#dst_expr)); }
        }
        Expr::Call(call) if is_path_call(call, &["context", "timestamp"]) => {
            quote! { ir.push(Ir::GetTimestamp(#dst_expr)); }
        }
        // storage::get(&KEY)
        Expr::Call(call) if is_path_call(call, &["storage", "get"]) => {
            if let Some(key_name) = extract_ref_ident(&call.args) {
                let key_str = key_name.to_string();
                quote! {
                    {
                        let _kv = { _vreg += 1; _vreg };
                        let key = truthlinked_sdk::hashing::namespace(#key_str);
                        ir.push(Ir::LoadConst(_kv, key.to_vec()));
                        ir.push(Ir::SLoad(#dst_expr, _kv));
                    }
                }
            } else {
                quote! {}
            }
        }
        // Binary operations: a + b, a == b, a > b, etc.
        Expr::Binary(bin) => {
            let lhs_eval = lower_expr_to_vreg(&bin.left, quote! { _lhs_r }, helpers);
            let rhs_eval = lower_expr_to_vreg(&bin.right, quote! { _rhs_r }, helpers);
            let op_ir = match &bin.op {
                BinOp::Add(_) => quote! { ir.push(Ir::Add(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Sub(_) => quote! { ir.push(Ir::Sub(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Mul(_) => quote! { ir.push(Ir::Mul(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Div(_) => quote! { ir.push(Ir::Div(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Rem(_) => quote! { ir.push(Ir::Mod(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::BitAnd(_) => quote! { ir.push(Ir::And(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::BitOr(_) => quote! { ir.push(Ir::Or(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::BitXor(_) => quote! { ir.push(Ir::Xor(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Eq(_) => quote! { ir.push(Ir::Eq(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Ne(_) => quote! { ir.push(Ir::Ne(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Lt(_) => quote! { ir.push(Ir::Lt(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Le(_) => quote! { ir.push(Ir::Lte(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Gt(_) => quote! { ir.push(Ir::Gt(#dst_expr, _lhs_r, _rhs_r)); },
                BinOp::Ge(_) => quote! { ir.push(Ir::Gte(#dst_expr, _lhs_r, _rhs_r)); },
                _ => quote! {},
            };
            // Wrap in a block so nested binary ops do not shadow _lhs_r/_rhs_r
            quote! {{
                let _lhs_r = { _vreg += 1; _vreg };
                let _rhs_r = { _vreg += 1; _vreg };
                #lhs_eval
                #rhs_eval
                #op_ir
            }}
        }
        // Unary: !x → IsZero
        Expr::Unary(u) if matches!(u.op, UnOp::Not(_)) => {
            let inner_eval = lower_expr_to_vreg(&u.expr, quote! { _inner_r }, helpers);
            quote! {{
                let _inner_r = { _vreg += 1; _vreg };
                #inner_eval
                ir.push(Ir::IsZero(#dst_expr, _inner_r));
            }}
        }
        // if/else expression (ternary pattern: let x = if cond { a } else { b })
        Expr::If(ei) => lower_if_expr(ei, &[], helpers, Some(dst_expr)),
        // Parenthesised
        Expr::Paren(p) => lower_expr_to_vreg(&p.expr, dst_expr, helpers),
        _ => quote! {},
    }
}

/// Lower `if cond { then } else { else }` to JumpIfNot/Jump IR.
/// If `result_vreg` is Some, the result of each branch is moved into it (ternary).
fn lower_if_expr(
    ei: &syn::ExprIf,
    slots: &[StorageSlot],
    helpers: &[HelperFn],
    result_vreg: Option<TS2>,
) -> TS2 {
    let cond_eval = lower_expr_to_vreg(&ei.cond, quote! { _cond_if }, helpers);

    // For ternary (let x = if ...), each branch must move its last expression
    // into result_vreg. We lower branch stmts normally; if result_vreg is set
    // and the last stmt is an expression, we emit a Mov into result_vreg.
    let lower_branch = |stmts: &[Stmt], helpers: &[HelperFn]| -> TS2 {
        if stmts.is_empty() {
            return quote! {};
        }
        let (last, rest) = stmts.split_last().unwrap();
        let rest_code: Vec<TS2> = rest.iter().map(|s| lower_stmt(s, slots, helpers)).collect();
        let last_code = if let Some(ref rv) = result_vreg {
            // If last stmt is a bare expression, evaluate it into result_vreg
            match last {
                Stmt::Expr(expr, None) => {
                    let eval = lower_expr_to_vreg(expr, quote! { _branch_res }, helpers);
                    quote! {
                        let _branch_res = { _vreg += 1; _vreg };
                        #eval
                        ir.push(Ir::Mov(#rv, _branch_res));
                    }
                }
                _ => lower_stmt(last, slots, helpers),
            }
        } else {
            lower_stmt(last, slots, helpers)
        };
        quote! { #(#rest_code)* #last_code }
    };

    let then_code = lower_branch(&ei.then_branch.stmts, helpers);

    let else_code = if let Some((_, else_expr)) = &ei.else_branch {
        match else_expr.as_ref() {
            Expr::Block(b) => lower_branch(&b.block.stmts, helpers),
            Expr::If(nested) => lower_if_expr(nested, slots, helpers, result_vreg.clone()),
            _ => quote! {},
        }
    } else {
        quote! {}
    };

    quote! {{
        let _cond_if = { _vreg += 1; _vreg };
        #cond_eval
        let _else_lbl = { _label += 1; _label };
        let _end_lbl  = { _label += 1; _label };
        ir.push(Ir::JumpIfNot(_cond_if, _else_lbl));
        #then_code
        ir.push(Ir::Jump(_end_lbl));
        ir.push(Ir::Label(_else_lbl));
        #else_code
        ir.push(Ir::Label(_end_lbl));
    }}
}

fn lower_call_to_vreg(
    call: &ExprCall,
    dst: TS2,
    _slots: &[StorageSlot],
    helpers: &[HelperFn],
) -> TS2 {
    if is_path_call(call, &["context", "caller"]) {
        return quote! { let _d=#dst; ir.push(Ir::GetCaller(_d)); };
    }
    if is_path_call(call, &["context", "owner"]) {
        return quote! { let _d=#dst; ir.push(Ir::GetOwner(_d)); };
    }
    if is_path_call(call, &["context", "height"]) {
        return quote! { let _d=#dst; ir.push(Ir::GetHeight(_d)); };
    }
    if is_path_call(call, &["context", "value"]) {
        return quote! { let _d=#dst; ir.push(Ir::GetValue(_d)); };
    }
    if is_path_call(call, &["storage", "get"]) {
        if let Some(key_name) = extract_ref_ident(&call.args) {
            let key_str = key_name.to_string();
            return quote! {
                let _d = #dst;
                let _kv = { _vreg += 1; _vreg };
                let key = truthlinked_sdk::hashing::namespace(#key_str);
                ir.push(Ir::LoadConst(_kv, key.to_vec()));
                ir.push(Ir::SLoad(_d, _kv));
            };
        }
    }
    // Intra-cell helper fn call: foo(arg0, arg1, ...)
    if let Expr::Path(p) = call.func.as_ref() {
        if let Some(fn_ident) = p.path.get_ident() {
            let fn_name = fn_ident.to_string();
            if let Some(helper) = helpers.iter().find(|h| h.name == fn_name) {
                let fn_label_id = helper.label_id;
                let ret_vreg = helper.ret_vreg;
                let arg_loads: Vec<TS2> = call
                    .args
                    .iter()
                    .zip(helper.arg_vregs.iter())
                    .map(|(arg_expr, &arg_vreg)| {
                        let eval = lower_expr_to_vreg(arg_expr, quote! { #arg_vreg }, helpers);
                        quote! { #eval }
                    })
                    .collect();
                return quote! {
                    #(#arg_loads)*
                    ir.push(Ir::Call(#fn_label_id));
                    let _call_dst = #dst;
                    ir.push(Ir::Mov(_call_dst, #ret_vreg));
                };
            }
        }
    }
    quote! {}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_path_call(call: &ExprCall, path: &[&str]) -> bool {
    if let Expr::Path(p) = call.func.as_ref() {
        let segs: Vec<_> = p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        let want: Vec<String> = path.iter().map(|s| s.to_string()).collect();
        return segs.ends_with(&want);
    }
    false
}

fn extract_ref_ident(
    args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
) -> Option<&syn::Ident> {
    if let Some(Expr::Reference(r)) = args.first() {
        if let Expr::Path(p) = r.expr.as_ref() {
            return p.path.get_ident();
        }
    }
    None
}

fn is_ok_unit(expr: &Expr) -> bool {
    if let Expr::Call(c) = expr {
        if let Expr::Path(p) = c.func.as_ref() {
            if p.path.is_ident("Ok") {
                if let Some(Expr::Tuple(t)) = c.args.first() {
                    return t.elems.is_empty();
                }
            }
        }
    }
    false
}

fn is_err_code(expr: &Expr) -> Option<u16> {
    if let Expr::Call(c) = expr {
        if let Expr::Path(p) = c.func.as_ref() {
            if p.path.is_ident("Err") {
                if let Some(Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(i),
                    ..
                })) = c.args.first()
                {
                    // base10_parse handles decimal; for hex/octal use the token string directly
                    let s = i.to_string();
                    let v: Option<u16> = if s.starts_with("0x") || s.starts_with("0X") {
                        u16::from_str_radix(&s[2..], 16).ok()
                    } else {
                        s.parse().ok()
                    };
                    if let Some(code) = v {
                        return Some(code);
                    }
                }
                return Some(0x0002); // fallback for Err(non-literal)
            }
        }
    }
    None
}

#[proc_macro_attribute]
pub fn storage(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro_attribute]
pub fn selector(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
