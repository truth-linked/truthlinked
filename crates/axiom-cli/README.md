# Axiom CLI v0.1.5

Command-line interface for TruthLinked accounts, value transfers (native, NFT, token), chain queries, key management, staking, governance, and SDK workflows.

It signs transactions using postcard encoding and post-quantum signatures before submitting them to the chain RPC.

## Build and Install

From the repository root:

```bash
cargo build --release -p axiom-cli
# binary is at target/release/axiom
```

## Configuration

Global options are available on every command:

```bash
axiom --rpc <url> <command>
axiom --config <path> <command>
```

Environment overrides:
- `TRUTHLINKED_RPC=<url>`
- `TRUTHLINKED_EXPLORER=<url>`

## Keys and Accounts

```bash
axiom keygen --output ~/.truthlinked/default.keys
axiom account-id --from ~/.truthlinked/default.keys
```

## Balances and Status

```bash
axiom balance <account_id_or_pubkey_hex>
axiom status --from ~/.truthlinked/default.keys
```

## Transfers

Supports account IDs, public keys, and .tl names.

```bash
axiom transfer --from <keyfile> --to <recipient> --amount <value>
# Examples
axiom transfer --to alice.tl --amount 10
axiom transfer --to <account_id> --amount 10.5
```

## Axiom Cells

```bash
axiom compile ./counter.cell
axiom deploy --from <keyfile> --bytecode ./counter.axiom --manifest ./counter.manifest.json
axiom call --from <keyfile> --cell <cell_id> --method <method> --args <hex_args>
axiom upgrade --from <keyfile> --cell <cell_id> --bytecode <new_bytecode> --manifest <new_manifest>
```

## Compute Escrow

```bash
axiom deposit-compute --from <keyfile> --amount <amount>
axiom withdraw-compute --from <keyfile> --amount <amount>
```

## Validators

```bash
axiom validator stake --from <keyfile> --amount <amount>
axiom validator unstake --from <keyfile> --amount <amount>
axiom validator withdraw --from <keyfile>
axiom validator unjail --from <keyfile>
axiom validator info --from <keyfile>
```

## Faucet

```bash
axiom faucet --from <keyfile>
```

Repository: https://github.com/truth-linked/truthlinked
CLI version: 0.1.5