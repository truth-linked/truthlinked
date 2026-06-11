//! Deterministic Axiom cell runtime primitives for TruthLinked.
//!
//! This crate exposes runtime records and conflict-aware helpers used by nodes to
//! keep parallel execution deterministic, auditable, and aligned across validators.

pub mod cells;
pub mod compiler_aware;
pub mod types;

pub trait ConflictAwareCell {
    fn rw_set(
        &self,
        intent: &truthlinked_core::pq_execution::TransactionIntent,
    ) -> (
        Vec<truthlinked_core::pq_execution::AccountId>,
        Vec<truthlinked_core::pq_execution::AccountId>,
    );
}
