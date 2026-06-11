# Axiom CLI v0.1.4

Command-line interface for TruthLinked accounts, value transfer (native, NFT, token), chain queries, key management, staking, governance, and SDK workflows.

It signs transactions (postcard + post-quantum signatures) and submits them to the chain RPC.

## Build / install

```bash
cargo build --release -p axiom-cli
# -> target/release/axiom

cargo install --path crates/axiom-cli
```

## Keys and defaults

Create a signing key (writes `~/.truthlinked/default.keys` and a `config.json`):

```bash
axiom account-create
axiom account-create --encrypt
```

The CLI resolves the default key from `~/.truthlinked/config.json` (`default_keyfile` or `keypair`).

Override for any command:

```bash
axiom ... --from /path/to/some.keys
axiom ... --from ./my-config.json   # if the file is a config pointing at a key
```

## Network / RPC

```bash
axiom chain-info
axiom --rpc http://localhost:19941 chain-info
axiom --network devnet ...
```

## Output

```bash
axiom --output json chain-info
axiom --output json balance-by-pubkey <pubkey>
```

## Sending (fresh paths only)

All value movement uses `axiom send <subcommand>`.

### Native token

```bash
axiom send value <recipient> <amount> [--from <keyfile>]
# aliases
axiom send native <recipient> <amount> [--from <keyfile>]
axiom send tlkd <recipient> <amount> [--from <keyfile>]
```

`recipient`:
- name ending `.tl`
- 64-hex account ID
- 3904-hex full Dilithium public key

`amount` accepts decimals and suffixes (e.g. `1.5`, `1000`, `2k`).

Examples:

```bash
axiom send value alice.tl 10
axiom send value 64hexaccountid 5 --from ~/.truthlinked/default.keys
axiom send value 19ad04...3904hexpubkey 0.001 --from /path/to/key
```

### NFT

```bash
axiom send nft <nft-id-32hex> <recipient> [--price <amount>] [--from <keyfile>]
```

### Token (fungible from a token cell)

```bash
axiom send token <token-cell-32hex> <recipient> <amount> [--from <keyfile>]
```

## Common queries

```bash
axiom chain-info
axiom token-info
axiom status
axiom balance <account-id-hex>
axiom balance-by-pubkey <pubkey-hex> [--full]
axiom resolve <name-or-hex>
axiom tx-status <tx-hash>
axiom account-id [--from <key>] [--pubkey <hex>]
```

## Faucet (devnet)

```bash
axiom faucet --amount 10000
axiom faucet --amount 10000 --from <key>
```

## Validator / staking operations

Use the validator keyfile for owner actions:

```bash
axiom bond --from <validator.keys> --amount 100
axiom unbond --from <validator.keys> --amount 10
axiom withdraw --from <validator.keys>
axiom unjail --from <validator.keys>
```

Delegation (delegate key vs owner key):

```bash
axiom delegate-add --from <owner.keys> --delegate-pubkey <hex>
axiom stake-for --from <delegate.keys> --owner-pubkey <ownerhex> --amount 10
axiom unstake-for ...
axiom withdraw-for ...
axiom unjail-for ...
```

## Transaction lifecycle

Submit returns a hash. Inspect settlement:

```bash
axiom tx-status <hash>
```

## Configuration files

A plain path to a `.keys` file or a JSON config file (with `default_keyfile`) can be passed to `--from`.

## Docker single-node example

See the root `docker-compose.yml` and `Dockerfile.node`.

Typical flow after key generation on the host:

```bash
mkdir -p keys
cp ~/.truthlinked/default.keys keys/validator.keys
cp genesis_bootnode.json genesis.json
docker compose up -d
```

The compose is intentionally generic (user supplies the key produced by `axiom account-create`).

## Notes

- Recipient public keys for transfers are passed and stored in their full 1952-byte (3904-hex) form when you supply the long key.
- The CLI never uses the legacy flat `transfer` / `mint-nft` etc. commands; everything goes through the `send` subcommands.
- All signing uses the Dilithium material from the key file.

Repository: https://github.com/truth-linked/truthlinked
CLI crate: crates/axiom-cli
CLI version: 0.1.4
