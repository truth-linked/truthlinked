//! Lexer for the .cell language.

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Keywords
    Cell,
    Pub,
    Fn,
    Init,
    Let,
    If,
    Else,
    While,
    Loop,
    For,
    In,
    Break,
    Continue,
    Return,
    Revert,
    Emit,
    Call,
    Require,
    Storage,
    Error,
    Commutative,
    Struct,
    Mapping,
    Owned,
    // Types
    U64,
    U128,
    U256,
    Address,
    Bool,
    // Literals
    Int(u128),
    Str(Vec<u8>),
    Ident(String),
    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Amp,
    Pipe,
    Caret,
    Bang,
    Shl,
    Shr, // << >>
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    AmpAmp,
    PipePipe, // && ||
    Assign,
    PlusEq,
    MinusEq,
    StarEq,
    SlashEq,
    DotDot,   // ..
    Arrow,    // ->
    FatArrow, // =>
    Dot,
    ColonColon, // ::
    Colon,
    Semicolon,
    Comma,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket, // [ ]
    // Special
    Eof,
}

#[derive(Debug, Clone)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone)]
pub struct Tok {
    pub token: Token,
    pub span: Span,
}

#[derive(Debug, thiserror::Error)]
#[error("lex error at {line}:{col}: {msg}")]
pub struct LexError {
    pub line: usize,
    pub col: usize,
    pub msg: String,
}

pub fn lex(src: &str) -> Result<Vec<Tok>, LexError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut line = 1usize;
    let mut col = 1usize;

    macro_rules! span {
        () => {
            Span { line, col }
        };
    }
    macro_rules! push {
        ($t:expr) => {
            tokens.push(Tok {
                token: $t,
                span: span!(),
            });
        };
    }
    macro_rules! adv {
        () => {
            i += 1;
            col += 1;
        };
    }

    while i < chars.len() {
        let c = chars[i];

        // Newline
        if c == '\n' {
            line += 1;
            col = 1;
            i += 1;
            continue;
        }
        // Whitespace
        if c.is_whitespace() {
            adv!();
            continue;
        }
        // Line comment
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        let sp = span!();

        // Integer literal (decimal or 0x hex)
        if c.is_ascii_digit() {
            let start = i;
            if c == '0' && i + 1 < chars.len() && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
                i += 2;
                col += 2;
                let hs = i;
                while i < chars.len() && chars[i].is_ascii_hexdigit() {
                    adv!();
                }
                let hex: String = chars[hs..i].iter().collect();
                let v = u128::from_str_radix(&hex, 16).map_err(|_| LexError {
                    line: sp.line,
                    col: sp.col,
                    msg: format!("invalid hex literal"),
                })?;
                tokens.push(Tok {
                    token: Token::Int(v),
                    span: sp,
                });
            } else {
                while i < chars.len() && chars[i].is_ascii_digit() {
                    adv!();
                }
                let s: String = chars[start..i].iter().collect();
                let v: u128 = s.parse().map_err(|_| LexError {
                    line: sp.line,
                    col: sp.col,
                    msg: format!("integer too large"),
                })?;
                tokens.push(Tok {
                    token: Token::Int(v),
                    span: sp,
                });
            }
            continue;
        }

        // String literal "..."
        if c == '"' {
            i += 1;
            col += 1;
            let mut bytes = Vec::new();
            loop {
                if i >= chars.len() {
                    return Err(LexError {
                        line,
                        col,
                        msg: "unterminated string literal".into(),
                    });
                }
                let ch = chars[i];
                if ch == '"' {
                    i += 1;
                    col += 1;
                    break;
                }
                if ch == '\\' && i + 1 < chars.len() {
                    i += 1;
                    col += 1;
                    let esc = chars[i];
                    bytes.push(match esc {
                        'n' => b'\n',
                        't' => b'\t',
                        'r' => b'\r',
                        '"' => b'"',
                        '\\' => b'\\',
                        '0' => 0,
                        other => {
                            return Err(LexError {
                                line,
                                col,
                                msg: format!("unknown escape \\{}", other),
                            })
                        }
                    });
                } else {
                    // encode char as UTF-8
                    let mut buf = [0u8; 4];
                    let s = ch.encode_utf8(&mut buf);
                    bytes.extend_from_slice(s.as_bytes());
                }
                i += 1;
                col += 1;
            }
            tokens.push(Tok {
                token: Token::Str(bytes),
                span: sp,
            });
            continue;
        }

        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                adv!();
            }
            let word: String = chars[start..i].iter().collect();
            let tok = match word.as_str() {
                "cell" => Token::Cell,
                "pub" => Token::Pub,
                "fn" => Token::Fn,
                "init" => Token::Init,
                "let" => Token::Let,
                "if" => Token::If,
                "else" => Token::Else,
                "while" => Token::While,
                "loop" => Token::Loop,
                "for" => Token::For,
                "in" => Token::In,
                "break" => Token::Break,
                "continue" => Token::Continue,
                "return" => Token::Return,
                "revert" => Token::Revert,
                "emit" => Token::Emit,
                "call" => Token::Call,
                "require" => Token::Require,
                "assert" => Token::Require, // alias
                "storage" => Token::Storage,
                "error" => Token::Error,
                "commutative" => Token::Commutative,
                "struct" => Token::Struct,
                "mapping" => Token::Mapping,
                "owned" => Token::Owned,
                "accord" => Token::Ident("accord".to_string()),
                "u64" => Token::U64,
                "u128" => Token::U128,
                "u256" => Token::U256,
                "address" => Token::Address,
                "bool" => Token::Bool,
                _ => Token::Ident(word),
            };
            tokens.push(Tok {
                token: tok,
                span: sp,
            });
            continue;
        }

        // Two-char operators
        let next = if i + 1 < chars.len() {
            chars[i + 1]
        } else {
            '\0'
        };
        match (c, next) {
            ('-', '>') => {
                push!(Token::Arrow);
                i += 2;
                col += 2;
                continue;
            }
            ('=', '>') => {
                push!(Token::FatArrow);
                i += 2;
                col += 2;
                continue;
            }
            (':', ':') => {
                push!(Token::ColonColon);
                i += 2;
                col += 2;
                continue;
            }
            ('=', '=') => {
                push!(Token::Eq);
                i += 2;
                col += 2;
                continue;
            }
            ('!', '=') => {
                push!(Token::Ne);
                i += 2;
                col += 2;
                continue;
            }
            ('<', '=') => {
                push!(Token::Le);
                i += 2;
                col += 2;
                continue;
            }
            ('>', '=') => {
                push!(Token::Ge);
                i += 2;
                col += 2;
                continue;
            }
            ('+', '=') => {
                push!(Token::PlusEq);
                i += 2;
                col += 2;
                continue;
            }
            ('-', '=') => {
                push!(Token::MinusEq);
                i += 2;
                col += 2;
                continue;
            }
            ('*', '=') => {
                push!(Token::StarEq);
                i += 2;
                col += 2;
                continue;
            }
            ('/', '=') => {
                push!(Token::SlashEq);
                i += 2;
                col += 2;
                continue;
            }
            ('<', '<') => {
                push!(Token::Shl);
                i += 2;
                col += 2;
                continue;
            }
            ('>', '>') => {
                push!(Token::Shr);
                i += 2;
                col += 2;
                continue;
            }
            ('&', '&') => {
                push!(Token::AmpAmp);
                i += 2;
                col += 2;
                continue;
            }
            ('|', '|') => {
                push!(Token::PipePipe);
                i += 2;
                col += 2;
                continue;
            }
            ('.', '.') => {
                push!(Token::DotDot);
                i += 2;
                col += 2;
                continue;
            }
            _ => {}
        }

        // Single-char
        let tok = match c {
            '+' => Token::Plus,
            '-' => Token::Minus,
            '*' => Token::Star,
            '/' => Token::Slash,
            '%' => Token::Percent,
            '&' => Token::Amp,
            '|' => Token::Pipe,
            '^' => Token::Caret,
            '!' => Token::Bang,
            '<' => Token::Lt,
            '>' => Token::Gt,
            '=' => Token::Assign,
            '.' => Token::Dot,
            ':' => Token::Colon,
            ';' => Token::Semicolon,
            ',' => Token::Comma,
            '(' => Token::LParen,
            ')' => Token::RParen,
            '{' => Token::LBrace,
            '}' => Token::RBrace,
            '[' => Token::LBracket,
            ']' => Token::RBracket,
            other => {
                return Err(LexError {
                    line,
                    col,
                    msg: format!("unexpected char {:?}", other),
                })
            }
        };
        push!(tok);
        adv!();
    }

    tokens.push(Tok {
        token: Token::Eof,
        span: span!(),
    });
    Ok(tokens)
}
