# Axiom CLI

Axiom is the TruthLinked command-line tool for accounts, cells, validators, governance, and SDK workflows. It signs transactions, talks to the chain RPC, and prints structured output for automation.

## 1. Install

Install from the TruthLinked workspace.

```bash
cargo install --path crates/axiom-cli
```

## 2. Quick start

1. Create a key file.

```bash
axiom account-create --encrypt
```

2. Check the chain and token metadata.

```bash
axiom chain-info
axiom token-info
```

3. Get your account ID and balance.

```bash
axiom account-id --from ~/.truthlinked/default.keys
axiom balance-by-pubkey <pubkey-hex>
```

4. Request devnet faucet funds.

```bash
axiom faucet --amount 15000
```

The faucet uses `./axiom/config` when present, then the configured default keyfile, then `~/.truthlinked/default.keys`. You can also pass a keyfile directly with `--from`, or pass a local config file such as `--from ./axiom/config`. The faucet command defaults to `https://faucet.truthlinked.org`. Set `TLKD_FAUCET_URL` to target a local or private faucet.

5. Transfer the native token.

```bash
axiom transfer --from ~/.truthlinked/default.keys --to-pubkey <recipient-pubkey-hex> --amount 1
```

## 3. Output format

Use the output flag for automation.

```bash
axiom --output json chain-info
```

The JSON output mirrors the RPC response. The pretty output is the same data with indentation.

## 4. RPC endpoint

The default RPC is https://devnet.truthlinked.org. Override it as needed.

```bash
axiom chain-info
axiom --network local chain-info
axiom --rpc http://localhost:19944 chain-info
```

## 5. Transaction flow

The CLI signs transactions and submits postcard-encoded payloads to the RPC.

```bash
axiom transfer --from <keys> --to-pubkey <pubkey> --amount 10
```

Use the transaction hash with `tx-status` to inspect settlement.

```bash
axiom tx-status <tx-hash>
```

## 6. Staking and validator actions

Validator actions require the validator key file.

```bash
axiom validator-setup --keys <validator-keys> --amount 10
axiom unbond --from <validator-keys> --amount 1
axiom withdraw --from <validator-keys>
axiom unjail --from <validator-keys>
```

Delegation actions require a delegate key file.

```bash
axiom delegate-add --from <owner-keys> --delegate-pubkey <pubkey>
axiom stake-for --from <delegate-keys> --owner-pubkey <owner-pubkey> --amount 1
```

## 7. Cells, tokens, and names

Deploy a cell from source or a compiled `.axiom` bytecode file.

```bash
axiom deploy-cell --from <keys> --cell-id <hex32> --source path/to/lib.rs
```

Call a cell or a call chain.

```bash
axiom call-cell --from <keys> --cell-id <hex32> --calldata <hex>
axiom call-chain --from <keys> --calls path/to/calls.json
```

Use the name registry for proposals and transfers.

```bash
axiom propose-name --from <keys> --name example --target <cell-id> --owner <account-id>
axiom vote-name --from <keys> --name example --approve
axiom transfer-name --from <keys> --name example --new-owner <account-id>
```

## 8. NFTs

```bash
axiom mint-nft --from <keys> --nft-id <hex32> --name "My NFT" --metadata-uri ipfs://...
axiom transfer-nft --from <keys> --nft-id <hex32> --to-pubkey <pubkey>
```

## 9. SDK helpers

SDK commands create projects, build bytecode, generate manifests, and deploy cells.

```bash
axiom sdk-new --path my-cell
axiom sdk-build --path my-cell
axiom sdk-deploy --from <keys> --cell-id <hex32> --path my-cell
```

## 10. Notes on units

The native token uses 9 decimals. Pass whole-token values for user-facing amounts and raw base units only where the command asks for them.

## 11. Troubleshooting

An invalid genesis fingerprint error means the command was signed for a different network. Run `axiom chain-info` against the intended RPC before submitting transactions.

A signature verification failure means the signing key, account, or selected RPC network is inconsistent.
