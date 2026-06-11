# truthlinked-governance

On-chain governance types and parameter rules for TruthLinked.

This crate owns the canonical governance data structures and parameter validation logic used by the node, SDKs, and tooling. It is intentionally free of networking, storage, or execution runtime code.

## What's inside
- Governance parameter keys, bounds, and validation rules
- Canonical governance data structures:
  - `PendingNameRegistration`
  - `NameRegistration`
  - `TokenAuthorityProposal`
  - `UrlProposal`
  - `CellVisibility`
- Cache helpers for fast parameter access

## What's not inside
- Proposal execution logic
- RPC/CLI handlers
- Consensus or networking code

## Usage
```toml
[dependencies]
truthlinked-governance = "0.1.0"
```

Example: validate a parameter update.
```rust
use truthlinked_governance::params::{param_key, validate_param_value};

let key = param_key("gas.transfer");
let mut value = [0u8; 32];
value[..8].copy_from_slice(&1_000u64.to_le_bytes());
validate_param_value(&key, value).expect("valid param value");
```

## Design goals
- One source of truth for governance types and parameter constraints
- No silent divergence across node and tooling
- Stable serialization for on-chain data

