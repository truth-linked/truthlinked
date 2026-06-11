//! Generate the cell manifest from the AST.
//! Statically derives declared_reads, declared_writes, commutative_keys,
//! and storage_key_specs (calldata byte ranges for dynamic key extraction).

use crate::ast::*;
use serde::Serialize;
use truthlinked_sdk::hashing::namespace;

/// Matches truthlinked_core::cells::StorageKeySpec exactly.
/// offset/len describe where in the calldata a 32-byte storage key argument lives.
#[derive(Debug, Serialize)]
pub struct StorageKeySpec {
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Serialize)]
pub struct Manifest {
    pub declared_reads: Vec<String>,
    pub declared_writes: Vec<String>,
    pub commutative_keys: Vec<String>,
    pub storage_key_specs: Vec<StorageKeySpec>,
}

pub fn generate(cell: &CellDef) -> Manifest {
    let mut reads: Vec<[u8; 32]> = Vec::new();
    let mut writes: Vec<[u8; 32]> = Vec::new();
    let mut commutative: Vec<[u8; 32]> = Vec::new();

    for slot in &cell.storage {
        let key = namespace(&slot.name);
        reads.push(key);
        writes.push(key);
        if slot.commutative {
            commutative.push(key);
        }
    }

    reads.sort();
    reads.dedup();
    writes.sort();
    writes.dedup();
    commutative.sort();
    commutative.dedup();

    // Emit storage_key_specs for address/u256 params of public fns.
    // Each such param at calldata offset (4 + i*32) is a potential storage key
    // (e.g. account address used as a per-user storage slot key).
    // The conflict extractor uses these to extract per-call user keys from calldata.
    let mut specs: Vec<StorageKeySpec> = Vec::new();
    for f in cell.fns.iter().filter(|f| f.public) {
        for (i, param) in f.params.iter().enumerate() {
            if matches!(param.ty, Type::Address | Type::U256) {
                specs.push(StorageKeySpec {
                    offset: 4 + i * 32,
                    len: 32,
                });
            }
        }
    }
    // Deduplicate by offset
    specs.sort_by_key(|s| s.offset);
    specs.dedup_by_key(|s| s.offset);

    Manifest {
        declared_reads: reads.iter().map(hex::encode).collect(),
        declared_writes: writes.iter().map(hex::encode).collect(),
        commutative_keys: commutative.iter().map(hex::encode).collect(),
        storage_key_specs: specs,
    }
}
