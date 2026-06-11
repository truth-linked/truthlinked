# TruthLinked

Rust workspace for the TruthLinked chain: consensus, runtime (Axiom VM), networking, state, staking, governance, oracle, MCP, and the Axiom CLI.

## Repository layout

- `crates/` — workspace crates (truthlinked-core, truthlinked-state, truthlinked-axiom, axiom-cli, consensus, runtime, net, staking, governance, mcp, oracle, sdk, etc.)
- `src/` — top-level binaries (node, trth-keygen, bench, spammer, etc.)
- `Dockerfile.node`, `docker-compose.yml` — single-node container deployment
- `genesis_bootnode.json`, `genesis_validator.json` — example genesis files

## Version

This is the source for Axiom CLI v0.1.4 and the accompanying node/runtime.

## Axiom CLI (v0.1.4)

The `axiom` binary is the primary user interface for accounts, sending value (native, NFTs, tokens), querying chain state, key management, staking/validator operations, and submitting transactions.

### Build / install

```bash
git clone https://github.com/truth-linked/truthlinked.git
cd truthlinked
cargo build --release
```

Binaries are in `target/release/`:
- `node` — the full validator/consensus node
- `axiom` — the CLI

Install the Axiom CLI to your PATH:

```bash
cargo install --path crates/axiom-cli
```

Run the node directly after build: `./target/release/node`

See Docker single-node section for the easiest containerized deployment.

### Keys and configuration

Create a key (writes `~/.truthlinked/default.keys` and updates config):

```bash
axiom account-create
# or with password
axiom account-create --encrypt
```

The CLI looks for a default key via `~/.truthlinked/config.json` (field `default_keyfile` or `keypair`).

Override per-command with `--from <path-to-keys-file>` (or a config file).

### RPC and network

Default is the devnet RPC. Override:

```bash
axiom --rpc http://localhost:19941 chain-info
axiom --network local ...
```

### Output

Structured output for scripting:

```bash
axiom --output json chain-info
axiom --output json balance-by-pubkey <pubkey>
```

### Sending value (primary commands)

All value movement is under `axiom send`.

```bash
# Native token (TLKD)
axiom send value <recipient> <amount> [--from <keyfile>]

# Aliases also work:
axiom send native <recipient> <amount> [--from <keyfile>]
axiom send tlkd <recipient> <amount> [--from <keyfile>]
```

`<recipient>` accepts:
- Name ending in `.tl` (resolved via name service)
- 64-hex account ID
- 3904-hex full Dilithium public key (the "full pubkey" form)

`<amount>` accepts human numbers (decimals, k/m suffixes, etc.).

Examples:

```bash
# By .tl name
axiom send value alice.tl 10

# By full pubkey (3904 hex chars)
axiom send value 19ad048f973c00d3... 0.001 --from ~/.truthlinked/default.keys

# Explicit keyfile
axiom send value 64hexaccountid 5 --from /path/to/my.keys
```

NFT send:

```bash
axiom send nft <nft-id-hex> <recipient> [--price <amount>] [--from <keyfile>]
```

Token (fungible from a token cell):

```bash
axiom send token <token-cell-id> <recipient> <amount> [--from <keyfile>]
```

### Other common commands

```bash
axiom chain-info
axiom token-info
axiom status
axiom balance <account-id>
axiom balance-by-pubkey <pubkey-hex> [--full]
axiom resolve <name-or-id>
axiom tx-status <tx-hash>
axiom account-id [--from <keyfile>] [--pubkey <hex>]
axiom faucet --amount 10000   # devnet only
```

Validator / staking (use the appropriate keyfile):

```bash
axiom validator-init --output validator1.keys --allocation 100000000000000
# (then add the printed entry to your genesis)

axiom bond --from <validator-keys> --amount 100
axiom unbond --from <validator-keys> --amount 10
axiom withdraw --from <validator-keys>
axiom unjail --from <validator-keys>

# Delegation
axiom delegate-add --from <owner-keys> --delegate-pubkey <pubkey>
axiom stake-for --from <delegate-keys> --owner-pubkey <pubkey> --amount 10
```

### Transaction status

After submitting a send or other tx, use the returned hash:

```bash
axiom tx-status <hash>
```

### Docker single-node (easiest for new users)

See `docker-compose.yml` in the repo root.

Basic flow:

```bash
# 1. Generate a key on the host (or inside a container if you prefer)
cargo build --release -p axiom-cli
./target/release/axiom account-create

# 2. Prepare mounts next to docker-compose.yml
mkdir -p keys
cp ~/.truthlinked/default.keys keys/validator.keys
cp genesis_bootnode.json genesis.json

# 3. Run
docker compose up -d
```

The container builds the node from source and runs with `--single-node`. RPC is exposed on 19941 by default.

To let other nodes discover this one as a bootnode, run:

```bash
```

and pass the printed string to other nodes via `--bootnodes`.

### Notes

- All commands that sign use the post-quantum (Dilithium) key material from the `.keys` file.
- Recipient pubkeys in transfers are the full 1952-byte (3904-hex) form when you pass the long key.
- The CLI submits postcard-encoded intents to the RPC.
- For automation, prefer `--output json`.

## Building the node

```bash
cargo build --release --bin node
```

See `src/bin/node.rs` and the Dockerfiles for flags (`--validator-keys`, `--data-dir`, `--p2p-port`, `--rpc-port`, `--genesis-file`, `--single-node`, `--bootnodes`, etc.).

## License

MIT (see individual crate LICENSE files).
