//! Truthlinked State Src Compiler Aware
//!
//! Owns runtime metadata consumed by the compiler and generated programs.
//! State changes are consensus-sensitive and must preserve deterministic execution and serialization.

// Deprecated: use truthlinked_runtime::compiler_aware directly.

#[cfg(test)]
mod tests {
    use super::*;
    use truthlinked_runtime::cells::CellAccount;
    use truthlinked_core::pq_execution::{Transaction, TransactionIntent};
    use std::collections::HashMap;

    #[test]
    fn compiler_aware_falls_back_to_whole_cell() {
        let cell_id = [7u8; 32];
        let sender = [1u8; 32];

        let tx = Transaction {
        nonce: 0,
            sender,
            intent: TransactionIntent::CallCell {
                cell_id,
                calldata: vec![0u8; 4],
                value: 0,
                gas_limit: 0,
            },
            signature: vec![],
            timestamp: 0,
            genesis_fingerprint: [0u8; 32],
            expiration_height: 1,
        };

        let cell = CellAccount {
            cell_id,
            owner: [0u8; 32],
            bytecode: vec![],
            storage: HashMap::new(),
            balance: 0,
            rent_deposit: 0,
            is_token: false,
            token_config: None,
            created_at: 0,
            upgraded_at: None,
            last_rent_paid_height: 0,
            rent_grace_blocks: 0,
            pending_owner: None,
            is_immutable: false,
            declared_reads: vec![],
            declared_writes: vec![],
            commutative_keys: vec![],
            storage_key_specs: vec![],
            oracle_schema_ids: vec![],
            governance_proposal: None,
            manifest_version: 0,
            manifest_hash: [0u8; 32],
        };

        let domain = ConcreteConflictDomain::from_transaction(&tx, Some(&cell));
        assert!(domain.writes.contains(&StorageKey::CellStorage(cell_id, [0u8; 32])));
    }
}
