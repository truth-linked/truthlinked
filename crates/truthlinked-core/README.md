# truthlinked-core

Shared protocol types and utilities for TruthLinked. This crate is the single source of truth for on-chain data structures, hashing/signing domains, and manifest analysis helpers used across the node, CLI, and SDKs.

This crate is intentionally small and stable. It contains no network code, no storage backends, and no runtime execution. It is safe to depend on from clients and tooling.

## What is inside

- Canonical transaction types and intent enums
- Account and identity primitives
- Protocol constants that must stay consistent across all components
- Axiom Cell manifest analysis helpers used by SDKs and tooling

## What is not inside

- Consensus, P2P, or RPC logic
- Database or snapshot code
- Runtime execution or host functions
- Node-only constants (ports, batch intervals, etc.)

## Design goals

- Single source of truth for protocol serialization
- Deterministic hashing and signing domains
- Minimal dependencies for downstream tooling
- No runtime side effects

## Usage

Add the crate to your workspace or `Cargo.toml` and re-use the canonical types.

```toml
[dependencies]
truthlinked-core = "0.1.0"
```

Example: construct and sign a transaction intent using shared types.

```rust
use fips204::traits::SerDes;
use truthlinked_core::pq_execution::{Transaction, TransactionIntent};
use truthlinked_core::pq_identity::{account_id_from_pubkey, DualKeypair};

fn build_example_tx(keys: &DualKeypair, genesis_fingerprint: [u8; 32]) -> Transaction {
    let sender = account_id_from_pubkey(&keys.dilithium_pk.into_bytes());
    let intent = TransactionIntent::Transfer {
        recipient: [0u8; 32],
        recipient_pubkey: None,
        amount: 1_000_000_000,
    };

    let tx = Transaction {
        sender,
        intent,
        signature: Vec::new(),
        nonce: 0,
        timestamp: Transaction::current_timestamp(),
        genesis_fingerprint,
        expiration_height: 0,
    };

    keys.sign_transaction(&tx).expect("sign tx")
}
```

## Versioning

This crate uses semantic versioning. Any breaking change to public types or constants will bump the major version.

## Security

The crate exposes post-quantum identity helpers and transaction signing primitives. Wallets, CLIs, and services that persist keys should handle encryption, access control, and secret lifecycle outside this crate.

## Contributing

Keep changes minimal and backwards compatible. If a change affects the wire format or hashing, update all downstream crates that rely on this crate.

