//! TruthLinked Axiom Cell SDK
//!
//! Build Cells using the IR pipeline or CellBuilder directly.
//! For high-level cell authoring, use the `axiom-cc` compiler with `.cell` source files.
//!
//! # Example (low-level)
//! ```rust
//! use truthlinked_sdk::CellBuilder;
//!
//! let bytecode = CellBuilder::new()
//!     .require_owner()
//!     .get_caller(1)
//!     .load_imm64(2, 1000)
//!     .sstore(1, 2)
//!     .halt()
//!     .build();
//! ```

pub mod abi;
pub mod builder;
pub mod codegen;
pub mod hashing;
pub mod ir;
pub mod op;
pub mod regalloc;

pub use builder::CellBuilder;
pub use truthlinked_axiom::bytecode::{CellBytecode, MAGIC, VERSION};
