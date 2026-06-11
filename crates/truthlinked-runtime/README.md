# truthlinked-runtime

Deterministic Axiom cell runtime primitives for the TruthLinked post-quantum blockchain.

This crate defines the shared runtime-side data structures used by nodes, execution code, and protocol services. It focuses on deterministic cell state layout, declared read/write sets, governance proposals for cell lifecycle changes, token configuration, and conflict-domain extraction for parallel execution.

## What it provides

- Cell account records with bytecode, storage, balance, rent, ownership, and manifest metadata.
- Runtime governance proposal types for upgrades, ownership transfers, and immutability.
- Conflict-aware read/write set extraction used by the parallel executor.
- Shared state records for accounts, NFTs, staking updates, oracle requests, and execution deltas.

## Design notes

Axiom cells must execute against deterministic state. Network access, wall-clock behavior, and external data are modeled through protocol-managed services such as the oracle crate, then read from committed state in later execution. This keeps validators aligned and keeps execution auditable.

## License

Licensed under the MIT License.
