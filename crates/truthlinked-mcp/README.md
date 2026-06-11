# truthlinked-mcp

`truthlinked-mcp` provides TruthLinked's on-chain Model Context Protocol layer. It defines the registry, tool, resource, prompt, agent-policy, and private-balance state transitions used by validators and by MCP transports that submit agent activity to the chain.

## What This Crate Contains

- On-chain MCP registry primitives for tools, resources, prompts, and agents.
- Agent policy transitions for permissions, spending limits, rate limits, and suspension state.
- Tool-call accounting and state-diff generation for validator execution.
- Private-balance custody flows for initialization, deposits, withdrawals, fee deductions, and confidential transfers.
- A Winterfell STARK verifier/prover module for confidential private-balance transfers where public transaction data contains commitments and proof bytes, not balances or transfer amounts.

## Confidential Transfer Model

Confidential private-balance transfers expose sender and recipient cell identifiers, encrypted balance payloads, commitment updates, an amount commitment, and a STARK proof. The amount and private balances are witness values checked inside the AIR, so they are not serialized into `TransactionIntent` or consensus persistence JSON.

This is not a standalone payment network. The crate provides deterministic state-transition logic that the TruthLinked node executes inside the broader post-quantum transaction pipeline.

## Publishing Notes

This crate depends on other TruthLinked protocol crates. For crates.io publication, publish the compatible dependency set first, including `truthlinked-core = 0.1.1`, then publish `truthlinked-mcp`.
