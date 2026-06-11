//! Deterministic HTTP oracle primitives for TruthLinked.
//!
//! Oracle requests, commits, reveals, and canonical results are modeled as
//! protocol data so Axiom cells can consume external facts without performing
//! network I/O during deterministic execution.

pub mod http_oracle;
