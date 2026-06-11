# TruthLinked Consensus Recovery Research

Date: 2026-05-31

## Current Failure Signature

The validators were not primarily dying. The live failure is consensus divergence after restart:

- Some validators advance around `8698-8701`.
- Some validators expose only snapshot height `3000` or lag behind.
- Logs show `State root mismatch`, `Rejected malicious block`, `Parent hash mismatch`, `No common ancestor found`, and `snapshot fallback also failed`.
- The code has a devnet path that accepts sync blocks with partial stake when `TRUTHLINKED_SYNC_LENIENT=1`.

Local code references:

- `streaming_consensus.rs:2490` gates lenient quorum by `TRUTHLINKED_SYNC_LENIENT`.
- `streaming_consensus.rs:5414` accepts a sync header with any nonzero attested stake when lenient mode is enabled.
- `streaming_consensus.rs:3150` treats state-root mismatch as a rejected malicious block, but does not force canonical recovery.
- `streaming_consensus.rs:4519` asks the highest-height peer for a snapshot without requiring a quorum-certified checkpoint.
- `streaming_consensus.rs:4563` reorg recovery requires a common ancestor already present in local memory/storage.
- `block_repairer.rs:219` deletes local corrupt block records before repair, which can remove the only local anchor if the peer response cannot be applied.

My read: the final fix is not another timeout tweak. TruthLinked needs a strict canonicality model: finality certificates/checkpoints, deterministic replay, and recovery from a quorum-certified checkpoint. Partial sync can exist only as a temporary staging mode, never as finalized state.

## What Major L1s Do

### Ethereum

Primary references:

- Consensus fork choice: https://ethereum.github.io/consensus-specs/specs/phase0/fork-choice/
- Finality and checkpoints in the consensus specs: https://ethereum.github.io/consensus-specs/specs/phase0/beacon-chain/
- Sync committees/light client specs: https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/
- Weak subjectivity/checkpoint sync concept: https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/weak-subjectivity/

Pattern:

- Ethereum separates head choice from finalized checkpoint.
- Nodes may reorganize the head, but not finalized history.
- Sync from a checkpoint is not “trust any highest peer”; it is anchored to a known checkpoint/weak-subjectivity root and then verified forward.

TruthLinked implication:

- Do not call `set_finalized_height` unless the block has a valid finality certificate.
- Snapshot sync must be from a checkpoint hash/root accepted by local policy or by quorum signatures, not just the highest peer.

### CometBFT / Tendermint

Primary references:

- CometBFT light client verification: https://docs.cometbft.com/v1.0/spec/light-client/verification/
- Tendermint consensus algorithm: https://docs.tendermint.com/master/spec/consensus/consensus.html
- Tendermint fork accountability: https://github.com/cometbft/cometbft/blob/main/spec/light-client/accountability/README.md
- CometBFT state sync: https://docs.cometbft.com/main/explanation/core/state-sync

Pattern:

- Blocks are committed by `+2/3` validator voting power.
- Light clients verify signed headers and validator-set changes.
- State sync restores application state from snapshots, but verification remains anchored to trusted headers and commit signatures.

TruthLinked implication:

- A block repair response must include a commit certificate with enough voting power.
- Snapshot fallback must restore `(height, app_hash/state_root, validator_set, commit_certificate)` as one atomic checkpoint.
- If a node cannot find a common ancestor, it should rollback to the latest locally trusted checkpoint, not keep retrying arbitrary peer blocks.

### Solana

Primary references:

- Solana consensus overview: https://docs.solanalabs.com/consensus
- Solana validators and snapshots: https://docs.solanalabs.com/operations/guides/validator-start
- Solana source, replay stage: https://github.com/solana-labs/solana/blob/master/core/src/replay_stage.rs
- Solana Tower BFT implementation: https://github.com/solana-labs/solana/blob/master/core/src/consensus.rs

Pattern:

- Solana uses optimistic fork choice plus Tower BFT lockouts.
- Replay is central: banks/blocks are replayed deterministically and fork choice selects a heaviest voted fork.
- Snapshots are operational accelerators, not permission to accept unverifiable state.

TruthLinked implication:

- Keep candidate forks in a fork tree instead of overwriting/deleting local canonical data during repair.
- Only switch to a fork when the fork has stronger proof than the current head and does not violate finalized lockout/checkpoint rules.

### Polkadot / Substrate

Primary references:

- Substrate consensus: https://docs.substrate.io/fundamentals/consensus/
- GRANDPA finality: https://spec.polkadot.network/sect-finality
- BABE block production: https://spec.polkadot.network/sect-block-production
- Substrate fork choice rule: https://paritytech.github.io/substrate/master/sc_consensus/trait.ForkChoiceStrategy.html

Pattern:

- BABE produces blocks; GRANDPA finalizes chains.
- Fork choice/head production is separate from finality.
- Finality votes justify a chain, not a single peer’s local height.

TruthLinked implication:

- Split “proposed/head block” from “finalized block”.
- The explorer UI should use finalized height for safety, but the node should internally track best head separately.

### HotStuff / Aptos / Sui

Primary references:

- HotStuff paper: https://arxiv.org/abs/1803.05069
- Aptos consensus docs: https://aptos.dev/en/network/blockchain/consensus
- AptosBFT/Jolteon paper: https://arxiv.org/abs/2106.10362
- Sui consensus docs: https://docs.sui.io/concepts/sui-architecture/consensus

Pattern:

- Modern BFT systems advance using quorum certificates.
- Safety comes from chained QCs/commit rules, not from timeout retries alone.
- DAG-based systems still require certified availability and final ordering before execution is canonical.

TruthLinked implication:

- TruthLinked’s batch/header should carry an explicit QC/finality certificate.
- “Attestation stake below quorum” must be a hard failure for canonical application.

## Final Solution Design

### 1. Disable Lenient Canonical Sync

Immediate production rule:

- `TRUTHLINKED_SYNC_LENIENT` must default off and should not be used on public/testnet validators.
- `validate_sync_header_with_batch` must never return `Ok(())` for sub-quorum attestation when applying to canonical state.
- If devnet needs lenient repair, apply it only into a `CandidateBlock` store, not canonical chain/state.

### 2. Add Finality Certificates

Every finalized block/checkpoint should persist:

- `height`
- `block_hash`
- `parent_hash`
- `state_root`
- `validator_set_hash`
- `round`
- `attestations`
- `total_signed_stake`
- `required_stake`

The node must verify this certificate before:

- advancing finalized height
- saving a canonical block
- serving block as canonical over RPC
- using the block as snapshot base

### 3. Separate Head, Candidate, and Finalized State

Maintain three lanes:

- `candidate`: received from peers, fully verified syntactically, but not final.
- `best_head`: best available fork by fork-choice rule.
- `finalized`: irreversible checkpoint with QC.

Never write candidate data into finalized indexes like `height:<h>` until finality proof passes.

### 4. Replace Current Repair With Checkpoint Recovery

Current repair tries local reorg first, then asks highest peer for snapshot. That fails when no common ancestor exists or when the highest peer is itself on a conflicting fork.

Correct flow:

1. Freeze canonical writes.
2. Poll peers for `(height, block_hash, state_root, validator_set_hash, finality_certificate)`.
3. Pick the highest checkpoint certified by quorum, not highest peer height.
4. If local chain has common ancestor at or above last finalized checkpoint, replay forward.
5. If no ancestor, rollback to latest local certified checkpoint.
6. If local checkpoint is too old or missing, download snapshot matching the certified checkpoint.
7. Verify snapshot state root and validator-set hash before store swap.
8. Atomically swap canonical state, indexes, finalized height, and peer sync status.

### 5. Make Block Repair Non-Destructive

`block_repairer.rs` should not delete canonical entries before a verified replacement exists.

Safer flow:

1. Fetch replacement block into temporary storage.
2. Verify parent hash, batch hash, execution order, state root, and QC.
3. If valid, replace canonical records atomically.
4. If invalid, keep old local records and mark the peer as suspect.

### 6. Determinism Audit

State root mismatch can also come from nondeterministic execution. Audit:

- transaction ordering
- timestamp usage inside execution
- map iteration order
- floating/random/time calls
- validator liveness filtering affecting committee/quorum
- fee/reward/emission calculations
- snapshot serialization ordering

Any value included in state root must be deterministic from block input and prior state.

### 7. Peer Trust and Evidence

Peer height alone is not trust.

Track:

- peer advertised finalized checkpoint
- peer provided invalid block
- peer provided mismatching snapshot
- peer equivocation evidence
- failed repair counts

Quarantine peers that provide invalid canonical data.

## Concrete TruthLinked Patch Plan

### Phase A: Stop the Bleeding

- Remove lenient canonical acceptance from `validate_sync_header_with_batch`.
- Ensure sync blocks with short attestation return `Err`.
- Change snapshot request peer selection from “highest height” to “highest certified finalized checkpoint”.
- Stop `block_repairer` from deleting records before replacement verification.

### Phase B: Add Certified Checkpoints

- Introduce `FinalityCertificate` type.
- Persist it alongside every finalized block and snapshot.
- Add RPC endpoint for checkpoint proof.
- Make explorer/indexer consume finalized checkpoint data, not peer-local head guess.

### Phase C: Rebuild Recovery

- Implement checkpoint selection by quorum.
- Implement atomic recovery from snapshot only if snapshot root matches checkpoint root.
- Keep candidate forks in side storage.
- Add tests for:
  - 5 validators, one lagging
  - 5 validators, one divergent parent
  - partial attestation must not finalize
  - restart from snapshot and replay
  - no common ancestor recovery
  - invalid highest peer is rejected

## Decision

The final answer is: build TruthLinked around certified finality/checkpoint recovery, not lenient sync. This matches Ethereum checkpoint/finality, Tendermint signed commits, Solana replay/fork discipline, Substrate BABE/GRANDPA separation, and HotStuff-style QC safety.

The current chain can be made to move, but it will keep halting until sub-quorum sync, destructive repair, and highest-peer snapshot trust are removed from the canonical path.
