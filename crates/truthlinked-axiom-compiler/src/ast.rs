//! AST for the .cell language.

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    U64,
    U128,
    U256,
    Address,
    Bool,
    /// mapping(K => V) - stored as sha256(slot_key || key)
    Mapping(Box<Type>, Box<Type>),
    /// array of T - stored as length slot + sha256(slot_key || index) per element
    Array(Box<Type>),
    /// user-defined struct
    Struct(String),
}

impl Type {
    pub fn is_scalar(&self) -> bool {
        matches!(
            self,
            Type::U64 | Type::U128 | Type::U256 | Type::Address | Type::Bool
        )
    }
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub ty: Type,
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone)]
pub struct StorageDecl {
    pub name: String,
    pub ty: Type,
    pub commutative: bool,
}

#[derive(Debug, Clone)]
pub struct ErrorDecl {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: Type,
    /// If true, this value must be consumed exactly once (passed to a token op,
    /// cross-cell call, or returned). Prevents double-spend and accidental drop.
    pub owned: bool,
}

#[derive(Debug, Clone)]
pub struct FnDef {
    pub name: String,
    pub public: bool,
    pub params: Vec<Param>,
    /// Single return: Some(vec![T])  Tuple return: Some(vec![T1,T2,...])  Void: None
    pub ret: Option<Vec<Type>>,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub struct InitDef {
    pub params: Vec<Param>,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub struct CellDef {
    pub name: String,
    pub structs: Vec<StructDef>,
    pub errors: Vec<ErrorDecl>,
    pub storage: Vec<StorageDecl>,
    pub init: Option<InitDef>,
    pub fns: Vec<FnDef>,
}

// ── Statements ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Stmt {
    /// let name = expr;
    Let {
        name: String,
        ty: Option<Type>,
        expr: Expr,
    },
    /// name = expr;
    Assign { target: LValue, expr: Expr },
    /// name += expr;
    AssignAdd { target: LValue, expr: Expr },
    /// name -= expr;
    AssignSub { target: LValue, expr: Expr },
    /// name *= expr;
    AssignMul { target: LValue, expr: Expr },
    /// name /= expr;
    AssignDiv { target: LValue, expr: Expr },
    /// require expr;  or  assert!(expr)
    Require { expr: Expr },
    /// revert ErrorName;
    Revert { error: String },
    /// return expr;  or  return (a, b, c);  or  return;
    Return { exprs: Vec<Expr> },
    /// emit EventName { field: expr, ... }
    Emit {
        event: String,
        fields: Vec<(String, Expr)>,
    },
    /// if expr { stmts } else { stmts }
    If {
        cond: Expr,
        then: Vec<Stmt>,
        else_: Vec<Stmt>,
    },
    /// while expr { stmts }
    While { cond: Expr, body: Vec<Stmt> },
    /// for name in start..end { stmts }
    For {
        var: String,
        start: Expr,
        end: Expr,
        body: Vec<Stmt>,
    },
    /// loop { stmts }
    Loop { body: Vec<Stmt> },
    /// break;
    Break,
    /// continue;
    Continue,
    /// bare expression statement
    Expr(Expr),
}

/// An assignable location.
#[derive(Debug, Clone)]
pub enum LValue {
    /// Simple variable or storage slot
    Var(String),
    /// mapping[key]
    Index { base: String, key: Box<Expr> },
    /// struct_var.field  or  storage_slot.field
    Field { base: String, field: String },
}

// ── Expressions ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Expr {
    /// Integer literal
    Int(u128),
    /// String/bytes literal "..."
    Bytes(Vec<u8>),
    /// Variable / storage slot reference
    Var(String),
    /// mapping[key] or array[index]
    Index {
        base: Box<Expr>,
        key: Box<Expr>,
    },
    /// expr.field
    Field {
        base: Box<Expr>,
        field: String,
    },
    /// context builtins
    Caller,
    Owner,
    Height,
    Timestamp,
    Value,
    /// Binary op
    Bin {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// Unary !
    Not(Box<Expr>),
    /// call cell_expr.method(args) -> ret_ty
    CallCell {
        cell: Box<Expr>,
        method: String,
        args: Vec<Expr>,
        ret: Option<Type>,
    },
    /// token::balance(token, account)
    TokenBalance {
        token: Box<Expr>,
        account: Box<Expr>,
    },
    /// token::transfer(token, from, to, amount)
    TokenTransfer {
        token: Box<Expr>,
        from: Box<Expr>,
        to: Box<Expr>,
        amount: Box<Expr>,
    },
    /// token::mint(token, to, amount)
    TokenMint {
        token: Box<Expr>,
        to: Box<Expr>,
        amount: Box<Expr>,
    },
    /// token::burn(token, owner, amount)
    TokenBurn {
        token: Box<Expr>,
        owner: Box<Expr>,
        amount: Box<Expr>,
    },
    /// hash(expr) → sha256 of the 32-byte register value
    Hash(Box<Expr>),
    /// Private helper call
    Call {
        name: String,
        args: Vec<Expr>,
    },
    /// accord::request(url, method, body)
    AccordRequest {
        url: Box<Expr>,
        method: Box<Expr>,
        body: Box<Expr>,
    },
    /// accord::read(request_id)
    AccordRead {
        request_id: Box<Expr>,
    },
    /// self
    SelfAddr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LogicAnd,
    LogicOr,
}
