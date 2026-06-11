# truthlinked-staking

Staking logic and data structures for TruthLinked.

This crate owns validator staking state, slashing rules, and unbonding logic. It is extracted from the node so staking behavior is stable and shared by all components.

## What's inside
- `StakingState`, `ValidatorStake`, `UnbondingEntry`
- Slashing rules and redistribution logic
- Unbonding and jail mechanics

## What's not inside
- Networking or consensus
- Storage backends
- RPC/CLI handling

## Usage
```toml
[dependencies]
truthlinked-staking = "0.1.0"
```

