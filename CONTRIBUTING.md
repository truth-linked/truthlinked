# Contributing to TruthLinked

Thank you for your interest in TruthLinked. This document describes how to contribute effectively to the project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Where Contributions Are Welcome](#where-contributions-are-welcome)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Commit Standards](#commit-standards)
- [Pull Request Process](#pull-request-process)
- [Testing Requirements](#testing-requirements)
- [Code Style](#code-style)
- [Developer Certificate of Origin](#developer-certificate-of-origin)
- [License](#license)

---

## Code of Conduct

This project follows a straightforward standard: be direct, be constructive, and focus on the work. Harassment, personal attacks, and bad-faith engagement will result in removal from the project.

---

## Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately to **security@truthlinked.org**. Include:

- A clear description of the vulnerability
- Steps to reproduce
- Affected crates and versions
- Your assessment of impact and exploitability

We target a first response within 48 hours and a coordinated disclosure timeline of 90 days unless a shorter window is warranted.

Post-quantum cryptographic issues (ML-DSA-65, ML-KEM, STARK circuits) are treated as critical severity by default.

---

## Where Contributions Are Welcome

| Area | Status | Notes |
| :--- | :--- | :--- |
| Axiom cell examples and templates | ✅ Open | Sample cells, DeFi primitives, oracle integrations |
| `axiom-cli` improvements | ✅ Open | UX, new commands, output formatting |
| `truthlinked-sdk` tooling | ✅ Open | Builder utilities, codegen, IR improvements |
| Documentation and guides | ✅ Open | Architecture docs, tutorials, whitepaper errata |
| Bug fixes (all crates) | ✅ Open | Must include a regression test |
| Oracle schema definitions | ✅ Open | New `AccordSchema` definitions and validators |
| Explorer and indexer | ✅ Open | UI improvements, new query endpoints |
| Core consensus (`truthlinked-consensus`) | 🔒 Invite only | Changes require core team review and formal spec update |
| State machine (`truthlinked-state`) | 🔒 Invite only | Breaking changes require governance proposal |
| Cryptographic primitives | 🔒 Invite only | All PQ cryptography changes require formal review |
| Genesis parameters | 🔒 Invite only | Mainnet genesis is locked at launch |

If you are uncertain whether a contribution fits, open a discussion issue before writing code.

---

## Getting Started

### Prerequisites

- Rust stable toolchain (`rustup update stable`)
- `cargo` and `rustfmt`
- For node development: Linux x86_64 recommended (tested on Ubuntu 22.04+)

### Build

```bash
# Clone
git clone https://github.com/truth-linked/truthlinked.git
cd truthlinked

# Build all crates
cargo build --release

# Build the CLI only
cargo build --release -p axiom-cli

# Run tests
cargo test --workspace
```

### Connect to Testnet

```bash
# Install CLI
cargo install axiom-cli

# Create a keypair
axiom account-create --output ~/.truthlinked/keys.json

# Claim testnet tokens
axiom faucet --from ~/.truthlinked/keys.json

# Query chain
axiom chain-info
```

Testnet RPC: `https://testnet.truthlinked.org`  
Explorer: `https://explorer.truthlinked.org`

---

## Development Workflow

1. Fork the repository and create a branch from `main`.
2. Branch naming: `fix/<short-description>`, `feat/<short-description>`, `docs/<short-description>`.
3. Keep branches focused — one logical change per PR.
4. Rebase onto `main` before submitting. Do not merge `main` into your branch.
5. All CI checks must pass before review.

---

## Commit Standards

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]

Signed-off-by: Your Name <you@example.com>
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`

**Scope examples:** `axiom-cli`, `consensus`, `state`, `runtime`, `oracle`, `mcp`, `sdk`

**Examples:**

```
feat(axiom-cli): add batch-transfer progress indicator

fix(consensus): correct bitmap boundary check for 8-validator sets

docs(sdk): add Axiom cell tutorial for counter example
```

Commits that touch consensus, state transitions, or cryptographic code must include a one-paragraph rationale in the body explaining why the change is correct.

---

## Pull Request Process

1. **Title**: follow commit convention above.
2. **Description**: include what changed, why, and how it was tested.
3. **Linked issue**: reference any related issue with `Fixes #N` or `Relates to #N`.
4. **Tests**: every bug fix must include a regression test. Every new feature must include unit tests.
5. **Documentation**: update relevant doc comments and `README.md` if the public API changes.
6. **Breaking changes**: mark with `!` in the commit type (e.g. `feat(state)!:`) and document the migration path.

PRs touching `truthlinked-consensus` or `truthlinked-state` require sign-off from at least one core team member in addition to CI.

PRs are squash-merged to keep `main` linear.

---

## Testing Requirements

```bash
# Run full test suite
cargo test --workspace

# Run tests for a specific crate
cargo test -p truthlinked-state

# Run with output for debugging
cargo test -p axiom-cli -- --nocapture
```

- All new code must have test coverage for the happy path and at least one failure path.
- Consensus and state machine changes require determinism tests: the same input must produce byte-identical output across multiple runs.
- Do not disable `#[deny(warnings)]` or add `#[allow(...)]` suppressions without a comment explaining why.

---

## Code Style

- Format with `rustfmt` before committing: `cargo fmt --all`
- Lint with `cargo clippy --workspace -- -D warnings`
- Prefer explicit error types over `Box<dyn Error>` in library crates.
- Post-quantum key material (`Vec<u8>` holding ML-DSA keys) must be clearly annotated with its expected length in comments.
- Do not log private key material, mnemonics, or raw signature bytes at any log level.
- All `unsafe` blocks require a `// SAFETY:` comment explaining the invariant being upheld.

---

## Developer Certificate of Origin

By contributing, you certify that:

> (a) The contribution was created in whole or in part by me and I have the right to submit it under the Apache 2.0 license; or  
> (b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the Apache 2.0 license.

Sign your commits with `-s`:

```bash
git commit -s -m "feat(sdk): add oracle schema builder"
```

This appends `Signed-off-by: Your Name <email>` to the commit message.

---

## License

TruthLinked is licensed under the [Apache License 2.0](LICENSE).

By submitting a contribution, you agree that your contribution is licensed under Apache 2.0 and that TruthLinked Labs may use, distribute, and sublicense your contribution as part of the TruthLinked protocol.
