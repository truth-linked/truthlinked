//! Truthlinked Axiom Src Bytecode
//!
//! Owns bytecode encoding, decoding, and validation boundaries.
//! VM and bytecode changes are consensus-sensitive and must remain deterministic across platforms.

use crate::error::AxiomError;
use alloc::vec::Vec;

/// Magic bytes identifying Axiom bytecode: ASCII "AXIO"
pub const MAGIC: [u8; 4] = [0x41, 0x58, 0x49, 0x4F];
pub const VERSION: u8 = 2;

/// Maximum sizes enforced at decode time.
pub const MAX_CONST_POOL_ENTRIES: usize = 65_535;
pub const MAX_CONST_ENTRY_BYTES: usize = 65_536; // 64KB per constant
pub const MAX_CODE_BYTES: usize = 1_048_576; // 1MB bytecode

/// A decoded cell ready for execution.
pub struct CellBytecode {
    /// Constant pool: arbitrary byte blobs referenced by index.
    pub const_pool: Vec<Vec<u8>>,
    /// Raw encoded instruction stream.
    pub code: Vec<u8>,
}

impl CellBytecode {
    /// Decode from raw bytes. Validates magic, version, and size limits.
    pub fn decode(raw: &[u8]) -> Result<Self, AxiomError> {
        let mut pos = 0;

        // Magic
        if raw.len() < 6 {
            return Err(AxiomError::InvalidMagic);
        }
        if &raw[0..4] != &MAGIC {
            return Err(AxiomError::InvalidMagic);
        }
        pos += 4;

        // Version
        if raw[pos] != VERSION {
            return Err(AxiomError::InvalidBytecode);
        }
        pos += 1;

        // Reserved byte (must be 0)
        if raw[pos] != 0 {
            return Err(AxiomError::InvalidBytecode);
        }
        pos += 1;

        // Const pool count (u16 LE)
        if pos + 2 > raw.len() {
            return Err(AxiomError::InvalidBytecode);
        }
        let pool_count = u16::from_le_bytes([raw[pos], raw[pos + 1]]) as usize;
        pos += 2;
        if pool_count > MAX_CONST_POOL_ENTRIES {
            return Err(AxiomError::InvalidBytecode);
        }

        // Const pool entries: each prefixed with u32 LE length
        let mut const_pool = Vec::with_capacity(pool_count);
        for _ in 0..pool_count {
            if pos + 4 > raw.len() {
                return Err(AxiomError::InvalidBytecode);
            }
            let entry_len =
                u32::from_le_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]) as usize;
            pos += 4;
            if entry_len > MAX_CONST_ENTRY_BYTES {
                return Err(AxiomError::InvalidBytecode);
            }
            if pos + entry_len > raw.len() {
                return Err(AxiomError::InvalidBytecode);
            }
            const_pool.push(raw[pos..pos + entry_len].to_vec());
            pos += entry_len;
        }

        // Code length (u32 LE)
        if pos + 4 > raw.len() {
            return Err(AxiomError::InvalidBytecode);
        }
        let code_len =
            u32::from_le_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]) as usize;
        pos += 4;
        if code_len > MAX_CODE_BYTES {
            return Err(AxiomError::InvalidBytecode);
        }
        if pos + code_len > raw.len() {
            return Err(AxiomError::InvalidBytecode);
        }

        let code = raw[pos..pos + code_len].to_vec();

        Ok(Self { const_pool, code })
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(0); // reserved
        out.extend_from_slice(&(self.const_pool.len() as u16).to_le_bytes());
        for entry in &self.const_pool {
            out.extend_from_slice(&(entry.len() as u32).to_le_bytes());
            out.extend_from_slice(entry);
        }
        out.extend_from_slice(&(self.code.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.code);
        out
    }

    /// Returns true if raw bytes start with Axiom magic.
    pub fn is_axiom(raw: &[u8]) -> bool {
        raw.len() >= 4 && &raw[0..4] == &MAGIC
    }
}
