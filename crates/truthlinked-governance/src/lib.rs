//! Governance primitives and protocol parameter exports for TruthLinked.
//!
//! This crate owns governance-controlled domain types and exposes the parameter
//! registry used by downstream protocol crates. Encoding must remain explicit so
//! protocol upgrades can be reviewed, reproduced, and audited.

pub mod params;
pub mod types;

pub use types::{
    CellVisibility, NameRegistration, PendingNameRegistration, SchemaEntry, SchemaProposal,
    TokenAuthorityProposal, UrlProposal, UrlResponseFormat,
};
