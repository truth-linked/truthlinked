# Axiom CLI v0.1.7

Command-line interface for TruthLinked — accounts, value transfers, chain queries, key management, staking, governance, MCP agent workflows, NFTs, tokens, oracle, and SDK operations.

Signs transactions using postcard encoding and ML-DSA-65 post-quantum signatures before submitting to the chain RPC.

## Build and Install

From the repository root:

```bash
cargo build --release -p axiom-cli
# binary at target/release/axiom
```

## Configuration

Global options available on every command:

```bash
axiom --rpc <url> <command>
axiom --network devnet <command>   # devnet | testnet | mainnet
axiom --config <path> <command>
```

Environment overrides:
- `TRUTHLINKED_RPC=<url>`
- `TLKD_FAUCET_URL=<url>`

## Keys and Accounts

```bash
axiom account-create --output ~/.truthlinked/default.keys
axiom account-id --from ~/.truthlinked/default.keys
axiom key-info --from ~/.truthlinked/default.keys
```

## Balances and Chain Info

```bash
axiom balance <account_id>
axiom chain-info
axiom status --from ~/.truthlinked/default.keys
```

## Transfers

Supports account IDs, public keys, and .tl names.

```bash
axiom send native --from <keyfile> <recipient> <amount>
axiom send native --from <keyfile> alice.tl 10
axiom batch-transfer --from <keyfile> --recipients <id1,id2> --amounts <10,20>
```

## Axiom Cells

```bash
axiom deploy-cell --from <keyfile> --bytecode ./counter.axiom --manifest ./counter.manifest.json
axiom call --from <keyfile> --cell <cell_id> --calldata <hex>
axiom cell-info <cell_id>
```

## Compute Escrow (CU)

```bash
axiom deposit-compute --from <keyfile> --amount <tlkd>
axiom withdraw-compute --from <keyfile> --amount <tlkd>
```

## Staking

```bash
axiom stake --from <keyfile> --amount <tlkd>
axiom unstake --from <keyfile> --amount <tlkd>
axiom withdraw-stake --from <keyfile>
axiom unjail --from <keyfile>
```

## NFTs

```bash
axiom nft mint --from <keyfile> --name <name> --metadata-uri <uri>
axiom nft send --from <keyfile> --nft <nft_id> --to <recipient>
axiom nft burn --from <keyfile> --nft <nft_id>
```

## Faucet (Devnet)

```bash
axiom faucet --from <keyfile>
# Uses TLKD_FAUCET_URL env or defaults to https://faucet.truthlinked.org
# 15,000 TLKD per claim · 72-hour cooldown · ML-DSA-65 signed request
```

## MCP Agents

```bash
axiom mcp register-tool --from <keyfile> --name <name> --schema <path>
axiom mcp register-agent --from <keyfile> --policy <path>
axiom mcp tool-call --from <keyfile> --tool <tool_id> --args <json>
```

## Genesis

```bash
axiom genesis-validator --from <keyfile> --allocation <tlkd>
```

Network: https://devnet.truthlinked.org  
Explorer: https://explorer.truthlinked.org  
Repository: https://github.com/truth-linked/truthlinked  
CLI version: 0.1.7
