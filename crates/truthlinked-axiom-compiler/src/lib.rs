//! Compiler pipeline for TruthLinked Axiom cell source files.
//!
//! The compiler turns `.cell` source into deterministic Axiom bytecode plus a
//! manifest describing declared reads, writes, and commutative storage keys.
//! Downstream tooling relies on this crate to produce stable artifacts for cell
//! deployment, local simulation, and conflict-aware scheduling.

pub mod ast;
pub mod lexer;
pub mod lower;
pub mod manifest;
pub mod parser;
pub mod typeck;

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("lex error: {0}")]
    Lex(#[from] lexer::LexError),
    #[error("parse error: {0}")]
    Parse(#[from] parser::ParseError),
    #[error("type error: {0}")]
    Type(#[from] typeck::TypeError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct CompileOutput {
    pub bytecode: Vec<u8>,
    pub manifest: manifest::Manifest,
}

pub fn compile(src: &str) -> Result<CompileOutput, CompileError> {
    let tokens = lexer::lex(src)?;
    let ast = parser::parse(tokens)?;
    typeck::check(&ast)?;
    let ir = lower::lower(&ast);
    let alloc = truthlinked_sdk::regalloc::allocate(&ir);
    let bytecode = truthlinked_sdk::codegen::emit(&ir, &alloc);
    let manifest = manifest::generate(&ast);
    Ok(CompileOutput { bytecode, manifest })
}

pub fn compile_file(path: &Path) -> Result<CompileOutput, CompileError> {
    let src = std::fs::read_to_string(path)?;
    compile(&src)
}
