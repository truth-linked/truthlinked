//! Axiom Cell metadata and bytecode manifest helpers.
//!
//! The types in this module describe declared storage access and provide a small
//! static analyzer for Axiom bytecode. Consensus and tooling use this information
//! to reason about storage keys before execution.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageKeySpec {
    pub offset: usize,
    pub len: usize,
}

/// Static analysis result from scanning Axiom bytecode.
pub struct ManifestAnalysis {
    pub static_read_slots: Vec<[u8; 32]>,
    pub static_write_slots: Vec<[u8; 32]>,
    pub has_storage_reads: bool,
    pub has_storage_writes: bool,
    /// True if every storage access used a statically-known key.
    pub fully_resolved: bool,
}

// Axiom opcode tags mirrored from the bytecode encoder.
const MAGIC: &[u8; 4] = b"AXIO";
const LOAD_CONST: u8 = 0x40;
const LOAD_IMM8: u8 = 0x41;
const LOAD_IMM64: u8 = 0x42;
const SLOAD: u8 = 0x50;
const SSTORE: u8 = 0x51;
const SDELETE: u8 = 0x52;

pub struct CellAccount;

impl CellAccount {
    pub fn compute_manifest_hash(
        bytecode: &[u8],
        declared_reads: &[[u8; 32]],
        declared_writes: &[[u8; 32]],
        commutative_keys: &[[u8; 32]],
        oracle_schema_ids: &[[u8; 32]],
    ) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(bytecode);
        for slot in declared_reads {
            hasher.update(slot);
        }
        for slot in declared_writes {
            hasher.update(slot);
        }
        for slot in commutative_keys {
            hasher.update(slot);
        }
        for schema_id in oracle_schema_ids {
            hasher.update(schema_id);
        }
        *hasher.finalize().as_bytes()
    }

    /// Statically analyze Axiom bytecode to extract storage key access patterns.
    ///
    /// Strategy: scan the instruction stream. Track the last value loaded into
    /// each register via LOAD_CONST (32-byte key). When SLOAD/SSTORE/SDELETE
    /// is encountered, check if the key register has a known static value.
    /// If the register is known, record the static slot. Otherwise, mark
    /// the manifest as partially unresolved.
    pub fn analyze_bytecode(bytecode: &[u8]) -> Result<ManifestAnalysis, String> {
        if bytecode.is_empty() {
            return Ok(ManifestAnalysis {
                static_read_slots: vec![],
                static_write_slots: vec![],
                has_storage_reads: false,
                has_storage_writes: false,
                fully_resolved: true,
            });
        }

        // Validate the bytecode header before decoding the instruction stream.
        if bytecode.len() < 6 || &bytecode[0..4] != MAGIC {
            return Err("Not Axiom bytecode".to_string());
        }

        // Decode the constant pool using the same layout as the Axiom bytecode encoder.
        let mut pos = 6usize; // skip magic(4) + version(1) + reserved(1)
        if pos + 2 > bytecode.len() {
            return Err("Truncated bytecode: missing const pool count".to_string());
        }
        let pool_count = u16::from_le_bytes([bytecode[pos], bytecode[pos + 1]]) as usize;
        pos += 2;

        let mut const_pool: Vec<Vec<u8>> = Vec::with_capacity(pool_count);
        for _ in 0..pool_count {
            if pos + 4 > bytecode.len() {
                return Err("Truncated const pool".to_string());
            }
            let entry_len = u32::from_le_bytes([
                bytecode[pos],
                bytecode[pos + 1],
                bytecode[pos + 2],
                bytecode[pos + 3],
            ]) as usize;
            pos += 4;
            if pos + entry_len > bytecode.len() {
                return Err("Truncated const pool entry".to_string());
            }
            const_pool.push(bytecode[pos..pos + entry_len].to_vec());
            pos += entry_len;
        }

        if pos + 4 > bytecode.len() {
            return Err("Truncated bytecode: missing code length".to_string());
        }
        let code_len = u32::from_le_bytes([
            bytecode[pos],
            bytecode[pos + 1],
            bytecode[pos + 2],
            bytecode[pos + 3],
        ]) as usize;
        pos += 4;
        if pos + code_len > bytecode.len() {
            return Err("Truncated code section".to_string());
        }
        let code = &bytecode[pos..pos + code_len];

        // Scan the instruction stream.
        // reg_consts[r] = Some(key) if register r was last loaded with a known 32-byte const.
        let mut reg_consts: [Option<[u8; 32]>; 256] = [None; 256];
        let mut static_read_slots: Vec<[u8; 32]> = Vec::new();
        let mut static_write_slots: Vec<[u8; 32]> = Vec::new();
        let mut has_reads = false;
        let mut has_writes = false;
        let mut fully_resolved = true;

        let mut pc = 0usize;
        while pc < code.len() {
            let op = code[pc];
            pc += 1;
            match op {
                LOAD_CONST => {
                    if pc + 3 > code.len() {
                        break;
                    }
                    let dst = code[pc] as usize;
                    pc += 1;
                    let idx = u16::from_le_bytes([code[pc], code[pc + 1]]) as usize;
                    pc += 2;
                    if let Some(entry) = const_pool.get(idx) {
                        if entry.len() == 32 {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(entry);
                            reg_consts[dst] = Some(key);
                        } else {
                            reg_consts[dst] = None;
                        }
                    } else {
                        reg_consts[dst] = None;
                    }
                }
                LOAD_IMM8 => {
                    if pc + 2 > code.len() {
                        break;
                    }
                    let dst = code[pc] as usize;
                    pc += 2;
                    reg_consts[dst] = None;
                }
                LOAD_IMM64 => {
                    if pc + 9 > code.len() {
                        break;
                    }
                    let dst = code[pc] as usize;
                    pc += 9;
                    reg_consts[dst] = None;
                }
                SLOAD => {
                    if pc + 2 > code.len() {
                        break;
                    }
                    let _dst = code[pc] as usize;
                    pc += 1;
                    let key_reg = code[pc] as usize;
                    pc += 1;
                    has_reads = true;
                    match reg_consts[key_reg] {
                        Some(key) => static_read_slots.push(key),
                        None => fully_resolved = false,
                    }
                }
                SSTORE => {
                    if pc + 2 > code.len() {
                        break;
                    }
                    let key_reg = code[pc] as usize;
                    pc += 1;
                    let _val_reg = code[pc];
                    pc += 1;
                    has_writes = true;
                    match reg_consts[key_reg] {
                        Some(key) => static_write_slots.push(key),
                        None => fully_resolved = false,
                    }
                }
                SDELETE => {
                    if pc + 1 > code.len() {
                        break;
                    }
                    let key_reg = code[pc] as usize;
                    pc += 1;
                    has_writes = true;
                    match reg_consts[key_reg] {
                        Some(key) => static_write_slots.push(key),
                        None => fully_resolved = false,
                    }
                }
                // Skip all other opcodes by their known sizes
                0x01..=0x07 => {
                    pc += 3;
                } // ADD/SUB/MUL/DIV/MOD/ADD_SAT/SUB_SAT: op+dst+a+b = 4 bytes, already consumed op
                0x10..=0x12 => {
                    pc += 3;
                } // AND/OR/XOR
                0x13 => {
                    pc += 2;
                } // NOT: op+dst+a
                0x14..=0x15 => {
                    pc += 3;
                } // SHL/SHR: op+dst+a+s
                0x20..=0x25 => {
                    pc += 3;
                } // EQ/NE/LT/LTE/GT/GTE
                0x26 => {
                    pc += 2;
                } // IS_ZERO
                0x30 => {
                    pc += 4;
                } // JUMP: op+u32
                0x31..=0x32 => {
                    pc += 5;
                } // JUMP_IF/JUMP_IF_NOT: op+reg+u32
                0x33 => {
                    pc += 4;
                } // CALL: op+u32
                0x34 => {} // RETURN: op only
                0x35 => {} // HALT
                0x36 => {
                    pc += 2;
                } // TRAP: op+u16
                0x43 => {
                    pc += 2;
                } // MOVE: op+dst+src
                0x44 => {
                    pc += 2;
                } // SWAP: op+a+b
                0x60..=0x65 => {
                    pc += 1;
                } // GET_CALLER..GET_VALUE: op+dst
                0x66 => {
                    pc += 1;
                } // GET_CALLDATA_LEN: op+dst
                0x67 => {
                    pc += 2;
                } // GET_CALLDATA: op+dst+off
                0x70 => {
                    pc += 2;
                } // SET_RETURN: op+i+l
                0x71 => {
                    pc += 2;
                } // EMIT_LOG: op+t+d
                0x72 => {
                    pc += 2;
                } // SET_RETURN_REG: op+d+l
                0x73 => {
                    pc += 3;
                } // EMIT_LOG_REG: op+t+d+l
                0x80 => {
                    pc += 4;
                } // CALL_CELL: op+cell+cd+len+val
                0x90 => {
                    pc += 2;
                } // HASH32: op+dst+src
                0x91 => {
                    pc += 3;
                } // HASH32_CONST: op+dst+u16
                0xA0 => {} // REQUIRE_OWNER
                0xA1 => {
                    pc += 1;
                } // REQUIRE_CALLER: op+reg
                0xA2..=0xA4 => {
                    pc += 2;
                } // REQUIRE_EQ/NE/LT: op+a+b
                0xA5 => {
                    pc += 1;
                } // REQUIRE_NON_ZERO: op+reg
                0xA6 => {
                    pc += 8;
                } // REQUIRE_GAS: op+u64
                0xB0 => {
                    pc += 3;
                } // TOKEN_BALANCE: op+dst+tok+acc
                0xB1 => {
                    pc += 4;
                } // TOKEN_TRANSFER: op+tok+from+to+amt
                0xB2..=0xB3 => {
                    pc += 3;
                } // TOKEN_MINT/BURN: op+tok+rec+amt
                0xB4..=0xB5 => {
                    pc += 2;
                } // TOKEN_FREEZE/THAW: op+tok+acc
                0xC0 => {
                    pc += 4;
                } // ORACLE_REQUEST: op+dst+url+method+body
                0xC1 => {
                    pc += 2;
                } // ORACLE_READ: op+dst+req_id
                _ => {
                    break;
                } // unknown opcode - stop scanning
            }
        }

        static_read_slots.sort_unstable();
        static_read_slots.dedup();
        static_write_slots.sort_unstable();
        static_write_slots.dedup();

        Ok(ManifestAnalysis {
            static_read_slots,
            static_write_slots,
            has_storage_reads: has_reads,
            has_storage_writes: has_writes,
            fully_resolved,
        })
    }

    pub fn verify_manifest_against_bytecode(
        bytecode: &[u8],
        declared_reads: &[[u8; 32]],
        declared_writes: &[[u8; 32]],
        storage_key_specs: &[StorageKeySpec],
    ) -> Result<(), String> {
        if bytecode.is_empty() {
            return Ok(());
        }

        let analysis = Self::analyze_bytecode(bytecode)?;

        if analysis.has_storage_reads && declared_reads.is_empty() && storage_key_specs.is_empty() {
            return Err("Bytecode reads storage but declared_reads is empty.".to_string());
        }
        if analysis.has_storage_writes && declared_writes.is_empty() && storage_key_specs.is_empty()
        {
            return Err("Bytecode writes storage but declared_writes is empty.".to_string());
        }

        if analysis.fully_resolved {
            let declared_r: std::collections::HashSet<[u8; 32]> =
                declared_reads.iter().copied().collect();
            for slot in &analysis.static_read_slots {
                if !declared_r.contains(slot) {
                    return Err(format!(
                        "Bytecode reads slot {} not in declared_reads.",
                        hex::encode(slot)
                    ));
                }
            }
            let declared_w: std::collections::HashSet<[u8; 32]> =
                declared_writes.iter().copied().collect();
            for slot in &analysis.static_write_slots {
                if !declared_w.contains(slot) {
                    return Err(format!(
                        "Bytecode writes slot {} not in declared_writes.",
                        hex::encode(slot)
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn require_inferable(
        _bytecode: &[u8],
        storage_key_specs: &[StorageKeySpec],
    ) -> Result<(), String> {
        if !storage_key_specs.is_empty() {
            return Ok(());
        }
        // For Axiom cells, static analysis handles key extraction - no specs needed
        Ok(())
    }
}
