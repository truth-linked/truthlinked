//! Recursive-descent parser for .cell source.

use crate::ast::*;
use crate::lexer::{Tok, Token};

#[derive(Debug, thiserror::Error)]
#[error("parse error at {line}:{col}: {msg}")]
pub struct ParseError {
    pub line: usize,
    pub col: usize,
    pub msg: String,
}

pub struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Tok>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos].token
    }
    fn span(&self) -> (usize, usize) {
        let s = &self.tokens[self.pos].span;
        (s.line, s.col)
    }

    fn err(&self, msg: impl Into<String>) -> ParseError {
        let (line, col) = self.span();
        ParseError {
            line,
            col,
            msg: msg.into(),
        }
    }

    fn advance(&mut self) -> &Token {
        let t = &self.tokens[self.pos].token;
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, expected: &Token) -> Result<(), ParseError> {
        if self.peek() == expected {
            self.advance();
            Ok(())
        } else {
            Err(self.err(format!("expected {:?}, got {:?}", expected, self.peek())))
        }
    }

    fn expect_ident(&mut self) -> Result<String, ParseError> {
        match self.peek().clone() {
            Token::Ident(s) => {
                self.advance();
                Ok(s)
            }
            other => Err(self.err(format!("expected identifier, got {:?}", other))),
        }
    }

    fn eat(&mut self, t: &Token) -> bool {
        if self.peek() == t {
            self.advance();
            true
        } else {
            false
        }
    }

    // ── Top level ─────────────────────────────────────────────────────────

    pub fn parse_cell(&mut self) -> Result<CellDef, ParseError> {
        self.expect(&Token::Cell)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut errors = vec![];
        let mut storage = vec![];
        let mut init = None;
        let mut fns = vec![];

        loop {
            match self.peek().clone() {
                Token::RBrace | Token::Eof => break,
                Token::Error => {
                    self.advance();
                    errors.push(self.parse_error_decl()?);
                }
                Token::Storage => {
                    self.advance();
                    storage.push(self.parse_storage_decl()?);
                }
                Token::Init => {
                    self.advance();
                    init = Some(self.parse_init()?);
                }
                Token::Pub => {
                    self.advance();
                    self.expect(&Token::Fn)?;
                    fns.push(self.parse_fn(true)?);
                }
                Token::Fn => {
                    self.advance();
                    fns.push(self.parse_fn(false)?);
                }
                other => return Err(self.err(format!("unexpected {:?} in cell body", other))),
            }
        }
        self.expect(&Token::RBrace)?;
        Ok(CellDef {
            name,
            structs: vec![],
            errors,
            storage,
            init,
            fns,
        })
    }

    fn parse_error_decl(&mut self) -> Result<ErrorDecl, ParseError> {
        let name = self.expect_ident()?;
        self.expect(&Token::Semicolon)?;
        Ok(ErrorDecl { name })
    }

    fn parse_storage_decl(&mut self) -> Result<StorageDecl, ParseError> {
        let name = self.expect_ident()?;
        self.expect(&Token::Colon)?;
        let ty = self.parse_type()?;
        let commutative = self.eat(&Token::Commutative);
        self.expect(&Token::Semicolon)?;
        Ok(StorageDecl {
            name,
            ty,
            commutative,
        })
    }

    fn parse_type(&mut self) -> Result<Type, ParseError> {
        match self.peek().clone() {
            Token::U64 => {
                self.advance();
                Ok(Type::U64)
            }
            Token::U128 => {
                self.advance();
                Ok(Type::U128)
            }
            Token::U256 => {
                self.advance();
                Ok(Type::U256)
            }
            Token::Address => {
                self.advance();
                Ok(Type::Address)
            }
            Token::Bool => {
                self.advance();
                Ok(Type::Bool)
            }
            Token::Mapping => {
                self.advance();
                self.expect(&Token::LParen)?;
                let k = self.parse_type()?;
                self.expect(&Token::FatArrow)?;
                let v = self.parse_type()?;
                self.expect(&Token::RParen)?;
                Ok(Type::Mapping(Box::new(k), Box::new(v)))
            }
            Token::LBracket => {
                // array<T> written as [T]
                self.advance();
                let inner = self.parse_type()?;
                self.expect(&Token::RBracket)?;
                Ok(Type::Array(Box::new(inner)))
            }
            other => Err(self.err(format!("expected type, got {:?}", other))),
        }
    }

    fn parse_params(&mut self) -> Result<Vec<Param>, ParseError> {
        self.expect(&Token::LParen)?;
        let mut params = vec![];
        while self.peek() != &Token::RParen {
            let owned = self.eat(&Token::Owned);
            let name = self.expect_ident()?;
            self.expect(&Token::Colon)?;
            let ty = self.parse_type()?;
            params.push(Param { name, ty, owned });
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen)?;
        Ok(params)
    }

    fn parse_init(&mut self) -> Result<InitDef, ParseError> {
        let params = self.parse_params()?;
        let body = self.parse_block()?;
        Ok(InitDef { params, body })
    }

    fn parse_fn(&mut self, public: bool) -> Result<FnDef, ParseError> {
        let name = self.expect_ident()?;
        let params = self.parse_params()?;
        let ret = if self.eat(&Token::Arrow) {
            if self.peek() == &Token::LParen {
                // tuple return: -> (T1, T2, ...)
                self.advance();
                let mut types = vec![];
                while self.peek() != &Token::RParen && self.peek() != &Token::Eof {
                    types.push(self.parse_type()?);
                    if !self.eat(&Token::Comma) {
                        break;
                    }
                }
                self.expect(&Token::RParen)?;
                Some(types)
            } else {
                Some(vec![self.parse_type()?])
            }
        } else {
            None
        };
        let body = self.parse_block()?;
        Ok(FnDef {
            name,
            public,
            params,
            ret,
            body,
        })
    }

    // ── Block & statements ────────────────────────────────────────────────

    fn parse_block(&mut self) -> Result<Vec<Stmt>, ParseError> {
        self.expect(&Token::LBrace)?;
        let mut stmts = vec![];
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
            stmts.push(self.parse_stmt()?);
        }
        self.expect(&Token::RBrace)?;
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        match self.peek().clone() {
            Token::Let => {
                self.advance();
                let name = self.expect_ident()?;
                // optional type annotation: let x: u256 = ...
                let ty = if self.eat(&Token::Colon) {
                    Some(self.parse_type()?)
                } else {
                    None
                };
                self.expect(&Token::Assign)?;
                let expr = self.parse_expr()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Let { name, ty, expr })
            }
            Token::Require => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Require { expr })
            }
            Token::Revert => {
                self.advance();
                let error = self.expect_ident()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Revert { error })
            }
            Token::Return => {
                self.advance();
                if self.peek() == &Token::Semicolon {
                    self.advance();
                    return Ok(Stmt::Return { exprs: vec![] });
                }
                // return (a, b, c);  or  return expr;
                let exprs = if self.peek() == &Token::LParen {
                    self.advance();
                    let mut v = vec![];
                    while self.peek() != &Token::RParen && self.peek() != &Token::Eof {
                        v.push(self.parse_expr()?);
                        if !self.eat(&Token::Comma) {
                            break;
                        }
                    }
                    self.expect(&Token::RParen)?;
                    v
                } else {
                    vec![self.parse_expr()?]
                };
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Return { exprs })
            }
            Token::Emit => {
                self.advance();
                let event = self.expect_ident()?;
                self.expect(&Token::LBrace)?;
                let mut fields = vec![];
                while self.peek() != &Token::RBrace {
                    let fname = self.expect_ident()?;
                    let fexpr = if self.eat(&Token::Colon) {
                        self.parse_expr()?
                    } else {
                        Expr::Var(fname.clone())
                    };
                    fields.push((fname, fexpr));
                    if !self.eat(&Token::Comma) {
                        break;
                    }
                }
                self.expect(&Token::RBrace)?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Emit { event, fields })
            }
            Token::If => {
                self.advance();
                let cond = self.parse_expr()?;
                let then = self.parse_block()?;
                let else_ = if self.eat(&Token::Else) {
                    self.parse_block()?
                } else {
                    vec![]
                };
                Ok(Stmt::If { cond, then, else_ })
            }
            Token::While => {
                self.advance();
                let cond = self.parse_expr()?;
                let body = self.parse_block()?;
                Ok(Stmt::While { cond, body })
            }
            Token::For => {
                self.advance();
                let var = self.expect_ident()?;
                self.expect(&Token::In)?;
                let start = self.parse_expr()?;
                self.expect(&Token::DotDot)?;
                let end = self.parse_expr()?;
                let body = self.parse_block()?;
                Ok(Stmt::For {
                    var,
                    start,
                    end,
                    body,
                })
            }
            Token::Loop => {
                self.advance();
                let body = self.parse_block()?;
                Ok(Stmt::Loop { body })
            }
            Token::Break => {
                self.advance();
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Break)
            }
            Token::Continue => {
                self.advance();
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Continue)
            }
            Token::Ident(_) => self.parse_assign_or_expr(),
            _ => {
                let expr = self.parse_expr()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Expr(expr))
            }
        }
    }

    fn parse_assign_or_expr(&mut self) -> Result<Stmt, ParseError> {
        let name = self.expect_ident()?;

        // Check for index: name[key] = ...
        let lvalue = if self.peek() == &Token::LBracket {
            self.advance();
            let key = self.parse_expr()?;
            self.expect(&Token::RBracket)?;
            LValue::Index {
                base: name.clone(),
                key: Box::new(key),
            }
        } else if self.peek() == &Token::Dot {
            self.advance();
            let field = self.expect_ident()?;
            LValue::Field {
                base: name.clone(),
                field,
            }
        } else {
            LValue::Var(name.clone())
        };

        match self.peek().clone() {
            Token::Assign => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Assign {
                    target: lvalue,
                    expr,
                })
            }
            Token::PlusEq => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::AssignAdd {
                    target: lvalue,
                    expr,
                })
            }
            Token::MinusEq => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::AssignSub {
                    target: lvalue,
                    expr,
                })
            }
            Token::StarEq => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::AssignMul {
                    target: lvalue,
                    expr,
                })
            }
            Token::SlashEq => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::AssignDiv {
                    target: lvalue,
                    expr,
                })
            }
            Token::LParen if matches!(lvalue, LValue::Var(_)) => {
                let args = self.parse_call_args()?;
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Expr(Expr::Call { name, args }))
            }
            Token::ColonColon => {
                // name::method(...) - put name back as ident and re-parse as expr
                // We already consumed name, so reconstruct the path expression
                self.advance(); // consume ::
                let method = self.expect_ident()?;
                let mut args = self.parse_call_args()?;
                let expr = match (name.as_str(), method.as_str()) {
                    (_, "balance") => {
                        if args.len() != 2 {
                            return Err(self.err("token::balance(token, account)"));
                        }
                        let account = args.remove(1);
                        let token = args.remove(0);
                        Expr::TokenBalance {
                            token: Box::new(token),
                            account: Box::new(account),
                        }
                    }
                    (_, "transfer") => {
                        if args.len() != 4 {
                            return Err(self.err("token::transfer(token, from, to, amount)"));
                        }
                        let amount = args.remove(3);
                        let to = args.remove(2);
                        let from = args.remove(1);
                        let token = args.remove(0);
                        Expr::TokenTransfer {
                            token: Box::new(token),
                            from: Box::new(from),
                            to: Box::new(to),
                            amount: Box::new(amount),
                        }
                    }
                    (_, "mint") => {
                        if args.len() != 3 {
                            return Err(self.err("token::mint(token, to, amount)"));
                        }
                        let amount = args.remove(2);
                        let to = args.remove(1);
                        let token = args.remove(0);
                        Expr::TokenMint {
                            token: Box::new(token),
                            to: Box::new(to),
                            amount: Box::new(amount),
                        }
                    }
                    (_, "burn") => {
                        if args.len() != 3 {
                            return Err(self.err("token::burn(token, owner, amount)"));
                        }
                        let amount = args.remove(2);
                        let owner = args.remove(1);
                        let token = args.remove(0);
                        Expr::TokenBurn {
                            token: Box::new(token),
                            owner: Box::new(owner),
                            amount: Box::new(amount),
                        }
                    }
                    ("accord", "request") => {
                        if args.len() != 3 {
                            return Err(self.err("accord::request(url, method, body)"));
                        }
                        let body = args.remove(2);
                        let method = args.remove(1);
                        let url = args.remove(0);
                        Expr::AccordRequest {
                            url: Box::new(url),
                            method: Box::new(method),
                            body: Box::new(body),
                        }
                    }
                    ("accord", "read") => {
                        if args.len() != 1 {
                            return Err(self.err("accord::read(request_id)"));
                        }
                        Expr::AccordRead {
                            request_id: Box::new(args.remove(0)),
                        }
                    }
                    _ => return Err(self.err(format!("unknown path {}::{}", name, method))),
                };
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Expr(expr))
            }
            _ => {
                self.expect(&Token::Semicolon)?;
                Ok(Stmt::Expr(Expr::Var(name)))
            }
        }
    }

    // ── Expressions (Pratt-style precedence) ─────────────────────────────

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_logic_or()
    }

    fn parse_logic_or(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_logic_and()?;
        while self.peek() == &Token::PipePipe {
            self.advance();
            let rhs = self.parse_logic_and()?;
            lhs = Expr::Bin {
                op: BinOp::LogicOr,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_logic_and(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_or()?;
        while self.peek() == &Token::AmpAmp {
            self.advance();
            let rhs = self.parse_or()?;
            lhs = Expr::Bin {
                op: BinOp::LogicAnd,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_and()?;
        while self.peek() == &Token::Pipe {
            self.advance();
            let rhs = self.parse_and()?;
            lhs = Expr::Bin {
                op: BinOp::Or,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_cmp()?;
        while self.peek() == &Token::Amp {
            self.advance();
            let rhs = self.parse_cmp()?;
            lhs = Expr::Bin {
                op: BinOp::And,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_cmp(&mut self) -> Result<Expr, ParseError> {
        let lhs = self.parse_add()?;
        let op = match self.peek() {
            Token::Eq => BinOp::Eq,
            Token::Ne => BinOp::Ne,
            Token::Lt => BinOp::Lt,
            Token::Le => BinOp::Le,
            Token::Gt => BinOp::Gt,
            Token::Ge => BinOp::Ge,
            _ => return Ok(lhs),
        };
        self.advance();
        let rhs = self.parse_add()?;
        Ok(Expr::Bin {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        })
    }

    fn parse_add(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                Token::Caret => BinOp::Xor,
                Token::Shl => BinOp::Shl,
                Token::Shr => BinOp::Shr,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_mul()?;
            lhs = Expr::Bin {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Star => BinOp::Mul,
                Token::Slash => BinOp::Div,
                Token::Percent => BinOp::Rem,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_unary()?;
            lhs = Expr::Bin {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if self.eat(&Token::Bang) {
            let e = self.parse_primary()?;
            return Ok(Expr::Not(Box::new(e)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary_base()?;
        // Postfix: expr[key] and expr.field
        loop {
            if self.peek() == &Token::LBracket {
                self.advance();
                let key = self.parse_expr()?;
                self.expect(&Token::RBracket)?;
                expr = Expr::Index {
                    base: Box::new(expr),
                    key: Box::new(key),
                };
            } else if self.peek() == &Token::Dot {
                self.advance();
                let field = self.expect_ident()?;
                expr = Expr::Field {
                    base: Box::new(expr),
                    field,
                };
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn parse_primary_base(&mut self) -> Result<Expr, ParseError> {
        match self.peek().clone() {
            Token::Int(v) => {
                self.advance();
                Ok(Expr::Int(v))
            }
            Token::Str(b) => {
                self.advance();
                Ok(Expr::Bytes(b))
            }
            Token::LParen => {
                self.advance();
                let e = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(e)
            }

            // call cell.method(args) [-> type]
            Token::Call => {
                self.advance();
                let cell_name = self.expect_ident()?;
                self.expect(&Token::Dot)?;
                let method = self.expect_ident()?;
                let args = self.parse_call_args()?;
                let ret = if self.eat(&Token::Arrow) {
                    Some(self.parse_type()?)
                } else {
                    None
                };
                Ok(Expr::CallCell {
                    cell: Box::new(Expr::Var(cell_name)),
                    method,
                    args,
                    ret,
                })
            }

            // context builtins & identifiers (includes accord:: and token:: paths)
            Token::Ident(s) => {
                self.advance();
                match s.as_str() {
                    "caller" => Ok(Expr::Caller),
                    "owner" => Ok(Expr::Owner),
                    "height" => Ok(Expr::Height),
                    "timestamp" => Ok(Expr::Timestamp),
                    "value" => Ok(Expr::Var(s)),
                    "self" => Ok(Expr::SelfAddr),
                    "true" => Ok(Expr::Int(1)),
                    "false" => Ok(Expr::Int(0)),
                    "hash" => {
                        // hash(expr) - sha256 of the 32-byte register value
                        self.expect(&Token::LParen)?;
                        let inner = self.parse_expr()?;
                        self.expect(&Token::RParen)?;
                        Ok(Expr::Hash(Box::new(inner)))
                    }
                    // path expressions: accord:: and token::
                    "accord" | "token" => {
                        let ns = s.clone();
                        self.expect(&Token::ColonColon)?;
                        let method = self.expect_ident()?;
                        let mut args = self.parse_call_args()?;
                        match (ns.as_str(), method.as_str()) {
                            ("accord", "request") => {
                                if args.len() != 3 {
                                    return Err(self.err("accord::request(url, method, body)"));
                                }
                                let body = args.remove(2);
                                let meth = args.remove(1);
                                let url = args.remove(0);
                                Ok(Expr::AccordRequest {
                                    url: Box::new(url),
                                    method: Box::new(meth),
                                    body: Box::new(body),
                                })
                            }
                            ("accord", "read") => {
                                if args.len() != 1 {
                                    return Err(self.err("accord::read(request_id)"));
                                }
                                Ok(Expr::AccordRead {
                                    request_id: Box::new(args.remove(0)),
                                })
                            }
                            (_, "balance") => {
                                if args.len() != 2 {
                                    return Err(self.err("token::balance(token, account)"));
                                }
                                let account = args.remove(1);
                                let token = args.remove(0);
                                Ok(Expr::TokenBalance {
                                    token: Box::new(token),
                                    account: Box::new(account),
                                })
                            }
                            (_, "transfer") => {
                                if args.len() != 4 {
                                    return Err(
                                        self.err("token::transfer(token, from, to, amount)")
                                    );
                                }
                                let amount = args.remove(3);
                                let to = args.remove(2);
                                let from = args.remove(1);
                                let token = args.remove(0);
                                Ok(Expr::TokenTransfer {
                                    token: Box::new(token),
                                    from: Box::new(from),
                                    to: Box::new(to),
                                    amount: Box::new(amount),
                                })
                            }
                            (_, "mint") => {
                                if args.len() != 3 {
                                    return Err(self.err("token::mint(token, to, amount)"));
                                }
                                let amount = args.remove(2);
                                let to = args.remove(1);
                                let token = args.remove(0);
                                Ok(Expr::TokenMint {
                                    token: Box::new(token),
                                    to: Box::new(to),
                                    amount: Box::new(amount),
                                })
                            }
                            (_, "burn") => {
                                if args.len() != 3 {
                                    return Err(self.err("token::burn(token, owner, amount)"));
                                }
                                let amount = args.remove(2);
                                let owner = args.remove(1);
                                let token = args.remove(0);
                                Ok(Expr::TokenBurn {
                                    token: Box::new(token),
                                    owner: Box::new(owner),
                                    amount: Box::new(amount),
                                })
                            }
                            _ => Err(self.err(format!("unknown path {}::{}", ns, method))),
                        }
                    }
                    name => {
                        if self.peek() == &Token::LParen {
                            let args = self.parse_call_args()?;
                            Ok(Expr::Call {
                                name: name.to_string(),
                                args,
                            })
                        } else {
                            Ok(Expr::Var(name.to_string()))
                        }
                    }
                }
            }

            other => Err(self.err(format!("unexpected {:?} in expression", other))),
        }
    }

    fn parse_call_args(&mut self) -> Result<Vec<Expr>, ParseError> {
        self.expect(&Token::LParen)?;
        let mut args = vec![];
        while self.peek() != &Token::RParen && self.peek() != &Token::Eof {
            args.push(self.parse_expr()?);
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen)?;
        Ok(args)
    }
}

pub fn parse(tokens: Vec<Tok>) -> Result<CellDef, ParseError> {
    Parser::new(tokens).parse_cell()
}
