# TruthLinked

Rust workspace for the TruthLinked chain: consensus, runtime (Axiom VM), networking, state, staking, governance, oracle, MCP, and the Axiom CLI.

## Repository layout

- `crates/` — Workspace crates
- `src/` — Top-level binaries (node, trth-keygen, bench, etc.)
- `Dockerfile.node`, `docker-compose.yml` — Single-node container deployment

## Axiom CLI (v0.1.5)

Primary user interface for accounts, value transfers (native, NFT, token), chain queries, key management, staking, and SDK workflows.

### Installation

From the repository root:

```bash
cargo build --release -p axiom-cli
# binary is at target/release/axiom

# Or install directly
cargo install --path crates/axiom-cli
```

### Quick Start

Generate an account:

```bash
axiom keygen --output ~/.truthlinked/default.keys
axiom account-id --from ~/.truthlinked/default.keys
```

Check status and balance:

```bash
axiom status --from ~/.truthlinked/default.keys
axiom balance <account_id>
```

Transfer native tokens:

```bash
axiom transfer --from ~/.truthlinked/default.keys --to <recipient> --amount <amount>
```

## Running the Node

```bash
cargo build --release --bin node
./target/release/node --help
```

## License

MIT
