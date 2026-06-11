# truthlinked-oracle

Deterministic HTTP oracle logic for TruthLinked.

This crate implements the commit-reveal oracle flow and related data structures. It is extracted from the node so oracle behavior is shared across validators, execution code, and protocol tooling.

## What's inside

- Oracle request, commit, reveal, and result types
- Commit-reveal tallying and finalization logic
- URL governance checks and visibility handling
- Response canonicalization for raw, canonical JSON, and USD price feeds
- Validator fetch helper (`validator_fetch_and_commit`)

## What's not inside

- Consensus networking
- RPC server handlers
- Storage backends
- Live execution of Axiom cells

## Usage

```toml
[dependencies]
truthlinked-oracle = "0.1.0"
```

## Example

```rust
use truthlinked_governance::UrlResponseFormat;
use truthlinked_oracle::http_oracle::{
    request_id, validator_fetch_and_commit, OracleRequest,
};

async fn example() {
    let format = UrlResponseFormat::Raw;
    let schema_id = None;
    let req = OracleRequest {
        request_id: request_id("https://example.com", "GET", b"", format, schema_id),
        url: "https://example.com".to_string(),
        method: "GET".to_string(),
        body: vec![],
        response_format: format,
        schema_id,
        requested_at: 100,
        expires_at: 200,
        requesting_cell: [0u8; 32],
    };

    let commits = validator_fetch_and_commit(&[req], b"validator-pubkey", 120).await;
    let _ = commits.len();
}
```

## Design goals

- Keep external data out of deterministic execution paths
- Require validators to commit before revealing oracle responses
- Canonicalize accepted results before they become cell-readable state
- Keep oracle request identity stable across validators

## License

Licensed under the MIT License.
