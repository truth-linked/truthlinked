//! axiom-cc - .cell language compiler
//!
//! Usage:
//!   axiom-cc <source.cell> [--output <stem>]
//!
//! Produces:
//!   <stem>.axiom          - Axiom bytecode
//!   <stem>.manifest.json  - manifest for parallel executor

use std::path::PathBuf;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: axiom-cc <source.cell> [--output <stem>]");
        process::exit(1);
    }

    let source = PathBuf::from(&args[1]);
    let stem = if let Some(pos) = args.iter().position(|a| a == "--output") {
        args.get(pos + 1).cloned().unwrap_or_else(|| {
            source
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        })
    } else {
        source
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    };

    match truthlinked_axiom_compiler::compile_file(&source) {
        Ok(out) => {
            let bytecode_path = format!("{}.axiom", stem);
            let manifest_path = format!("{}.manifest.json", stem);

            std::fs::write(&bytecode_path, &out.bytecode).unwrap_or_else(|e| {
                eprintln!("Failed to write bytecode: {}", e);
                process::exit(1);
            });

            let manifest_json = serde_json::to_string_pretty(&out.manifest).unwrap();
            std::fs::write(&manifest_path, &manifest_json).unwrap_or_else(|e| {
                eprintln!("Failed to write manifest: {}", e);
                process::exit(1);
            });

            println!("✓ {} ({} bytes)", bytecode_path, out.bytecode.len());
            println!("✓ {}", manifest_path);
            println!("  reads:       {}", out.manifest.declared_reads.len());
            println!("  writes:      {}", out.manifest.declared_writes.len());
            println!("  commutative: {}", out.manifest.commutative_keys.len());
        }
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}
