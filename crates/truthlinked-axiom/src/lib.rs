//! Axiom virtual machine and bytecode primitives for TruthLinked cells.
//!
//! This crate defines the bytecode format, opcode set, gas metering, host
//! interface, and interpreter used by TruthLinked Axiom cells. VM behavior is
//! consensus-sensitive: execution must remain deterministic across platforms and
//! releases.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod bytecode;
pub mod error;
pub mod gas;
pub mod host;
pub mod opcode;
pub mod vm;

pub use bytecode::{CellBytecode, MAGIC, VERSION};
pub use error::AxiomError;
pub use gas::GasMeter;
pub use host::{CellLog, CrossCellResult, Host};
pub use vm::{ExecResult, Vm};
