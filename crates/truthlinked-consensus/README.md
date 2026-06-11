# truthlinked-consensus

`truthlinked-consensus` contains the streaming consensus engine used by TruthLinked validators. It coordinates transaction admission, nonce reservation, block production, attestation handling, finality tracking, sync, repair, and snapshot recovery for the post-quantum TruthLinked chain.

The crate is intended for TruthLinked node integrations and protocol testing. Public APIs are conservative and are versioned with the wider TruthLinked protocol crates.
