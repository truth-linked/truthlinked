//! Deterministic HTTP oracle commit-reveal consensus.
//!
//! Architecture - three-phase per-block oracle protocol:
//!
//!   PHASE 1 (fetch):   Each validator independently fetches URLs that Axiom
//!                      cells requested during the previous block's execution.
//!                      Requests are collected into OracleRequest records and
//!                      written to pending_oracle_requests on State.
//!
//!   PHASE 2 (commit):  Before proposing a block, each validator broadcasts
//!                      SubmitOracleCommit transactions:
//!                        commit_hash = blake3(validator_pk || request_id || response_body)
//!                      These land on-chain as OracleCommit records.
//!
//!   PHASE 3 (reveal):  Once >= ORACLE_QUORUM_PERCENT of stake has committed,
//!                      validators broadcast SubmitOracleReveal transactions
//!                      carrying the raw response_body. The chain verifies
//!                        blake3(validator_pk || request_id || revealed_body) == commit_hash
//!                      and adds the validator's response to the tally.
//!                      When quorum of IDENTICAL reveals is reached, the
//!                      canonical response is written to OracleResult on State.
//!                      Axiom cells can then read it synchronously in the next block.
//!
//! Non-determinism is eliminated because:
//!   - Axiom cells never call the network directly. `http_call` reads OracleResult.
//!   - Every validator signs their reveal with their validator key.
//!   - Divergent responses fail to reach quorum and produce no result.
//!   - Results are content-addressed by request_id (blake3 of url+method+body).
//!   - Results expire after gp::get_u64(gp::PARAM_ORACLE_CACHE_EXPIRY_BLOCKS) and are refetched.
//!
//! URL governance - public cells:
//!   - Anyone may propose a URL pattern with a bond via the oracle governance system cell.
//!   - Validators vote; 2/3 stake approval passes.
//!   - Owner may report malicious URL; 70% of bond slashed.
//!   - Private cells (SetCellVisibility = Private) bypass governance.

use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use truthlinked_governance::params as gp;
use truthlinked_governance::{CellVisibility, SchemaEntry, UrlProposal, UrlResponseFormat};
use truthlinked_staking::StakingState;

//
// CORE TYPES
//

/// Canonical identifier for an oracle request.
/// Derived deterministically from (url, method, body) - same request across
/// validators yields the same request_id with no coordination needed.
pub fn request_id(
    url: &str,
    method: &str,
    body: &[u8],
    format: UrlResponseFormat,
    schema_id: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"oracle:request:");
    h.update(url.as_bytes());
    h.update(b":");
    h.update(method.as_bytes());
    h.update(b":");
    h.update(body);
    h.update(b":");
    h.update(match format {
        UrlResponseFormat::Raw => b"raw",
        UrlResponseFormat::JsonCanonical => b"json",
        UrlResponseFormat::PriceUsd => b"price_usd",
    });
    if let Some(id) = schema_id {
        h.update(b":schema:");
        h.update(&id);
    }
    *h.finalize().as_bytes()
}

/// Commit hash: validator commits to their response without revealing it.
/// commit_hash = blake3("oracle:commit:" || validator_pk || request_id || response_body)
pub fn compute_commit_hash(
    validator_pk: &[u8],
    req_id: &[u8; 32],
    response_body: &[u8],
    response_status: u16,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"oracle:commit:");
    h.update(validator_pk);
    h.update(req_id);
    h.update(response_body);
    h.update(&response_status.to_le_bytes());
    *h.finalize().as_bytes()
}

/// An Axiom cell requested an HTTP fetch. Stored in State::pending_oracle_requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleRequest {
    /// Content-addressed request identifier.
    pub request_id: [u8; 32],
    pub url: String,
    pub method: String, // "GET" | "POST" | "PUT" | "DELETE"
    pub body: Vec<u8>,
    pub response_format: UrlResponseFormat,
    pub schema_id: Option<[u8; 32]>,
    /// Block height at which the request was created.
    pub requested_at: u64,
    /// Block height after which this request expires without result.
    pub expires_at: u64,
    /// Cell that requested this fetch.
    pub requesting_cell: [u8; 32],
}

/// A validator's commit to a specific oracle request response.
/// Written to State by SubmitOracleCommit transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleCommit {
    pub request_id: [u8; 32],
    /// blake3("oracle:commit:" || validator_pk || request_id || response_body)
    pub commit_hash: [u8; 32],
    /// Validator's Schnorrkel pubkey (used in commit hash).
    pub validator_pk: Vec<u8>,
    pub committed_at: u64,
}

/// A validator's reveal of their committed oracle response.
/// Written to State by SubmitOracleReveal transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleReveal {
    pub request_id: [u8; 32],
    pub response_body: Vec<u8>,
    pub response_status: u16,
    pub validator_pk: Vec<u8>,
    pub revealed_at: u64,
}

/// Payload produced by validator_fetch_and_commit - passed as SubmitOracleCommit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleCommitPayload {
    pub request_id: [u8; 32],
    pub commit_hash: [u8; 32],
    /// Held in validator memory until reveal phase. NOT written to chain at commit time.
    #[serde(skip)]
    pub response_body: Vec<u8>,
    /// HTTP status captured at commit time to bind the reveal.
    #[serde(skip)]
    pub response_status: u16,
}

/// The finalized oracle result after quorum of identical reveals.
/// Axiom cells read from this committed result, never from live HTTP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleResult {
    pub request_id: [u8; 32],
    pub url: String,
    pub method: String,
    pub response_body: Vec<u8>,
    pub response_status: u16,
    /// Blake3 of the canonical response body for Axiom integrity checks.
    pub body_hash: [u8; 32],
    /// Block height at which quorum was reached.
    pub finalized_at: u64,
    /// Block height after which this result expires.
    pub expires_at: u64,
    /// Fraction of stake that agreed (numerator, denominator).
    pub quorum_stake_num: u64,
    pub quorum_stake_den: u64,
    /// Cell that originally issued this request - used for auto-settle.
    pub requesting_cell: [u8; 32],
}

impl OracleResult {
    pub fn is_expired(&self, current_height: u64) -> bool {
        current_height >= self.expires_at
    }
}

/// Pending tally for a single oracle request - accumulates commits and reveals
/// as validators submit them. Lives in State::oracle_pending.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OracleTally {
    pub request_id: [u8; 32],
    /// validator_pk -> commit_hash
    pub commits: HashMap<Vec<u8>, [u8; 32]>,
    /// validator_pk -> (response_body, status)
    pub reveals: HashMap<Vec<u8>, (Vec<u8>, u16)>,
    /// Total stake committed so far (numerator, total stake denominator).
    pub committed_stake: u64,
    pub total_stake: u64,
    /// True once commit phase is open to reveals.
    pub commit_phase_closed: bool,
}

impl OracleTally {
    /// Try to find a response_body that has >= gp::get_u64(gp::PARAM_ORACLE_REVEAL_QUORUM_PERCENT) of stake.
    /// Returns Some((body, status, agreeing_stake, total_stake)) if quorum reached.
    pub fn try_finalize(&self, staking: &StakingState) -> Option<(Vec<u8>, u16, u64, u64)> {
        self.try_finalize_with_format(staking, UrlResponseFormat::Raw)
    }

    pub fn try_finalize_with_format(
        &self,
        staking: &StakingState,
        response_format: UrlResponseFormat,
    ) -> Option<(Vec<u8>, u16, u64, u64)> {
        if response_format == UrlResponseFormat::PriceUsd {
            return self.try_finalize_price_usd(staking);
        }

        // Tally stake per unique response body (content-addressed by blake3)
        let mut tally: HashMap<[u8; 32], (Vec<u8>, u16, u64)> = HashMap::new();

        for (val_pk, (body, status)) in &self.reveals {
            // Only count reveals that match their commit
            if let Some(commit_hash) = self.commits.get(val_pk.as_slice()) {
                let expected = compute_commit_hash(val_pk, &self.request_id, body, *status);
                if expected != *commit_hash {
                    continue; // Reveal does not match commit - ignore
                }
            } else {
                continue; // Revealed without committing first - ignore
            }

            let val_stake = staking
                .validators
                .get(val_pk.as_slice())
                .map(|v| v.active_stake)
                .unwrap_or(0);

            let body_hash: [u8; 32] = (*blake3::hash(body).as_bytes()).into();
            let entry = tally.entry(body_hash).or_insert((body.clone(), *status, 0));
            entry.2 += val_stake;
        }

        let current_height = staking.current_height;
        let total_stake: u64 = staking
            .validators
            .values()
            .filter(|v| v.is_active(current_height))
            .map(|v| v.active_stake)
            .sum();
        if total_stake == 0 {
            return None;
        }

        // Find the body_hash with enough stake
        for (_hash, (body, status, agreeing_stake)) in tally {
            let pct = (agreeing_stake * 100) / total_stake;
            if pct >= gp::get_u64(gp::PARAM_ORACLE_REVEAL_QUORUM_PERCENT) {
                return Some((body, status, agreeing_stake, total_stake));
            }
        }

        None
    }

    fn try_finalize_price_usd(&self, staking: &StakingState) -> Option<(Vec<u8>, u16, u64, u64)> {
        const PRICE_TOLERANCE_BPS: u64 = 10;

        let current_height = staking.current_height;
        let total_stake: u64 = staking
            .validators
            .values()
            .filter(|v| v.is_active(current_height))
            .map(|v| v.active_stake)
            .sum();
        if total_stake == 0 {
            return None;
        }

        let mut samples: Vec<(u64, u64, u16)> = Vec::new();
        for (val_pk, (body, status)) in &self.reveals {
            let commit_hash = self.commits.get(val_pk.as_slice())?;
            let expected = compute_commit_hash(val_pk, &self.request_id, body, *status);
            if expected != *commit_hash {
                continue;
            }
            let stake = staking
                .validators
                .get(val_pk.as_slice())
                .map(|v| v.active_stake)
                .unwrap_or(0);
            if stake == 0 {
                continue;
            }
            if let Some(price) = parse_price_usd_micros(body) {
                samples.push((price, stake, *status));
            }
        }
        samples.sort_by_key(|(price, _, _)| *price);

        let mut best: Option<(usize, usize, u64)> = None;
        for start in 0..samples.len() {
            let anchor = samples[start].0.max(1);
            let tolerance = ((anchor as u128) * PRICE_TOLERANCE_BPS as u128 / 10_000u128) as u64;
            let mut stake_sum = 0u64;
            let mut end = start;
            while end < samples.len() && samples[end].0.saturating_sub(anchor) <= tolerance {
                stake_sum = stake_sum.saturating_add(samples[end].1);
                end += 1;
            }
            if best
                .map(|(_, _, best_stake)| stake_sum > best_stake)
                .unwrap_or(true)
            {
                best = Some((start, end, stake_sum));
            }
        }

        let (start, end, agreeing_stake) = best?;
        if (agreeing_stake * 100) / total_stake
            < gp::get_u64(gp::PARAM_ORACLE_REVEAL_QUORUM_PERCENT)
        {
            return None;
        }

        let target = agreeing_stake.saturating_add(1) / 2;
        let mut cumulative = 0u64;
        let mut median = samples[start].0;
        for (price, stake, _) in &samples[start..end] {
            cumulative = cumulative.saturating_add(*stake);
            if cumulative >= target {
                median = *price;
                break;
            }
        }

        let status = samples[start..end]
            .iter()
            .find(|(price, _, _)| *price == median)
            .map(|(_, _, status)| *status)
            .unwrap_or(200);
        let body = serde_json::json!({
            "kind": "price_usd",
            "price_usd_micros": median,
            "tolerance_bps": PRICE_TOLERANCE_BPS,
            "samples": end - start
        });
        serde_json::to_vec(&body)
            .ok()
            .map(|body| (body, status, agreeing_stake, total_stake))
    }

    /// True if enough stake has committed to open the reveal window.
    pub fn commit_quorum_reached(&self) -> bool {
        if self.total_stake == 0 {
            return false;
        }
        (self.committed_stake * 100) / self.total_stake
            >= gp::get_u64(gp::PARAM_ORACLE_COMMIT_QUORUM_PERCENT)
    }
}

//
// URL GOVERNANCE
//

// UrlProposal and CellVisibility are defined in truthlinked-governance.

/// Return codes from the `http_call` host function.
pub mod return_codes {
    /// Success - response written to result_ptr.
    pub const OK: i32 = truthlinked_core::constants::HTTP_ORACLE_RC_OK;
    /// Memory error.
    pub const MEM_ERR: i32 = truthlinked_core::constants::HTTP_ORACLE_RC_MEM_ERR;
    /// Invalid UTF-8 in URL or method.
    pub const ENCODING_ERR: i32 = truthlinked_core::constants::HTTP_ORACLE_RC_ENCODING_ERR;
    /// URL not approved for this cell visibility tier.
    pub const URL_NOT_APPROVED: i32 = truthlinked_core::constants::HTTP_ORACLE_RC_URL_NOT_APPROVED;
    /// No oracle result yet - request queued, retry next block.
    pub const ORACLE_PENDING: i32 = truthlinked_core::constants::HTTP_ORACLE_RC_PENDING;
    /// Oracle result found but expired - request requeued.
    pub const ORACLE_EXPIRED: i32 = truthlinked_core::constants::HTTP_ORACLE_RC_EXPIRED;
    /// Response body exceeds gp::get_usize(gp::PARAM_MAX_RESPONSE_BYTES).
    pub const RESPONSE_TOO_LARGE: i32 =
        truthlinked_core::constants::HTTP_ORACLE_RC_RESPONSE_TOO_LARGE;
    /// Requesting cell exceeded its cell call stack depth limit.
    pub const DEPTH_LIMIT_EXCEEDED: i32 =
        truthlinked_core::constants::HTTP_ORACLE_RC_DEPTH_LIMIT_EXCEEDED;
    /// Invalid HTTP method.
    pub const INVALID_METHOD: i32 = truthlinked_core::constants::HTTP_ORACLE_RC_INVALID_METHOD;
}

/// Check if a URL is permitted for the given cell visibility.
/// Private cells: any URL.
/// Public cells: URL must match an approved pattern.
pub fn check_url_permitted(
    url: &str,
    visibility: CellVisibility,
    url_proposals: &im::HashMap<String, UrlProposal>,
) -> bool {
    match visibility {
        CellVisibility::Private => true,
        CellVisibility::Public => url_proposals
            .values()
            .any(|p| p.approved && url_matches_pattern(url, &p.url_pattern)),
    }
}

/// Check if URL matches an approved pattern (prefix match with wildcard).
pub fn url_matches_pattern(url: &str, pattern: &str) -> bool {
    if pattern.ends_with("/*") {
        url.starts_with(&pattern[..pattern.len() - 2])
    } else {
        url == pattern
    }
}

/// Queue an oracle request from an Axiom host call. Called by the `http_call` host function
/// when no finalized result is available. The request is added to
/// State::pending_oracle_requests so validators fetch it next block.
pub fn queue_oracle_request(
    url: String,
    method: String,
    body: Vec<u8>,
    response_format: UrlResponseFormat,
    schema_id: Option<[u8; 32]>,
    requesting_cell: [u8; 32],
    current_height: u64,
) -> OracleRequest {
    let req_id = request_id(&url, &method, &body, response_format, schema_id);
    OracleRequest {
        request_id: req_id,
        url,
        method,
        body,
        response_format,
        schema_id,
        requested_at: current_height,
        expires_at: current_height + gp::get_u64(gp::PARAM_ORACLE_REQUEST_TIMEOUT_BLOCKS),
        requesting_cell,
    }
}

//
// VALIDATOR ORACLE FETCH
// Called off-chain by each validator node BEFORE building a block proposal.
// Produces OracleCommit transactions to broadcast to peers.
//

/// Fetch all pending oracle requests and produce commit transactions.
/// validators call this after the previous block finalizes.
pub async fn validator_fetch_and_commit(
    pending_requests: &[OracleRequest],
    validator_pk: &[u8],
    current_height: u64,
    schema_registry: &im::HashMap<[u8; 32], SchemaEntry>,
) -> Vec<OracleCommitPayload> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(gp::get_u64(
            gp::PARAM_HTTP_TIMEOUT_MS,
        )))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut commits = Vec::new();

    for req in pending_requests {
        if req.expires_at < current_height {
            tracing::warn!(
                " Oracle: request {} expired ({} < {})",
                hex::encode(&req.request_id[..4]),
                req.expires_at,
                current_height
            );
            continue;
        }

        if req.body.len() > gp::get_usize(gp::PARAM_MAX_HTTP_BODY_BYTES) {
            tracing::warn!(
                " Oracle: request {} body too large",
                hex::encode(&req.request_id[..4])
            );
            continue;
        }

        let result = execute_http_fetch(&client, req).await;

        let (response_body, response_status) = match result {
            Ok((body, status)) if body.len() <= gp::get_usize(gp::PARAM_MAX_RESPONSE_BYTES) => {
                (body, status)
            }
            Ok((body, _)) => {
                tracing::warn!(" Oracle: response too large ({} bytes)", body.len());
                continue;
            }
            Err(e) => {
                tracing::warn!(" Oracle: fetch error for {}: {}", req.url, e);
                continue;
            }
        };

        let canonical_body = match canonicalize_response(req.response_format, &response_body) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(" Oracle: canonicalize failed: {}", e);
                continue;
            }
        };
        // If schema declared: project response to only declared keys (strips timestamps etc.)
        let canonical_body = if let Some(schema_id) = req.schema_id {
            match project_by_schema(schema_id, &canonical_body, schema_registry) {
                Ok(projected) => projected,
                Err(_) => continue, // Projection failed - fail closed, do not commit
            }
        } else {
            canonical_body
        };
        if canonical_body.len() > gp::get_usize(gp::PARAM_MAX_RESPONSE_BYTES) {
            continue;
        }
        let commit_hash = compute_commit_hash(
            validator_pk,
            &req.request_id,
            &canonical_body,
            response_status,
        );

        commits.push(OracleCommitPayload {
            request_id: req.request_id,
            commit_hash,
            response_body: canonical_body, // Held in memory for reveal phase
            response_status,
        });
    }

    commits
}

fn canonicalize_response(format: UrlResponseFormat, body: &[u8]) -> Result<Vec<u8>, String> {
    match format {
        UrlResponseFormat::Raw => {
            // Best-effort: if body looks like JSON, canonicalise it anyway.
            // This prevents non-deterministic JSON fields from breaking quorum
            // even for private cells that didn't explicitly request JsonCanonical.
            if body.first() == Some(&b'{') || body.first() == Some(&b'[') {
                canonicalize_json(body).or_else(|_| Ok(body.to_vec()))
            } else {
                Ok(body.to_vec())
            }
        }
        UrlResponseFormat::JsonCanonical => canonicalize_json(body),
        UrlResponseFormat::PriceUsd => canonicalize_price_usd(body),
    }
}

fn canonicalize_price_usd(body: &[u8]) -> Result<Vec<u8>, String> {
    let price = parse_price_usd_micros(body).ok_or("price_usd not found")?;
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let pair = value
        .get("symbol")
        .or_else(|| value.get("pair"))
        .or_else(|| value.get("market"))
        .and_then(|v| v.as_str())
        .unwrap_or("BTC-USD");
    serde_json::to_vec(&serde_json::json!({
        "kind": "price_usd_sample",
        "pair": pair,
        "price_usd_micros": price
    }))
    .map_err(|e| format!("json encode error: {}", e))
}

fn parse_price_usd_micros(body: &[u8]) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let candidates = [
        "price_usd_micros",
        "price_usd_cents",
        "price_usd",
        "price",
        "last",
        "rate",
        "amount",
        "data.price",
        "data.amount",
        "result.price",
    ];
    for path in candidates {
        if let Some(v) = json_path(&value, path) {
            let multiplier = match path {
                "price_usd_micros" => 1.0,
                "price_usd_cents" => 10_000.0,
                _ => 1_000_000.0,
            };
            if let Some(n) = json_number(v) {
                if n.is_finite() && n > 0.0 {
                    return Some((n * multiplier).round() as u64);
                }
            }
        }
    }
    None
}

fn json_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = value;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn json_number(value: &serde_json::Value) -> Option<f64> {
    match value {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.replace(',', "").parse::<f64>().ok(),
        _ => None,
    }
}

fn canonicalize_json(body: &[u8]) -> Result<Vec<u8>, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid json: {}", e))?;
    let normalized = normalize_json(value);
    serde_json::to_vec(&normalized).map_err(|e| format!("json encode error: {}", e))
}

/// Well-known non-deterministic field names stripped during JsonCanonical normalisation.
/// These fields vary per-request (timestamps, request IDs, nonces) and would prevent quorum.
/// Use schema projection (SchemaEntry.keys) for precise control.
const NON_DETERMINISTIC_FIELDS: &[&str] = &[
    "timestamp",
    "ts",
    "time",
    "date",
    "datetime",
    "created_at",
    "updated_at",
    "request_id",
    "requestId",
    "req_id",
    "reqId",
    "trace_id",
    "traceId",
    "nonce",
    "random",
    "seed",
    "session_id",
    "sessionId",
];

fn normalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<String> = map
                .keys()
                .filter(|k| !NON_DETERMINISTIC_FIELDS.contains(&k.as_str()))
                .cloned()
                .collect();
            keys.sort();
            let mut new_map = serde_json::Map::new();
            for key in keys {
                if let Some(v) = map.get(&key) {
                    new_map.insert(key, normalize_json(v.clone()));
                }
            }
            serde_json::Value::Object(new_map)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(normalize_json).collect())
        }
        other => other,
    }
}

/// Project a JSON response to only the declared schema keys.
/// Extra fields are dropped - this is the ICP-equivalent transform.
/// Returns the projected canonical JSON bytes.
fn project_by_schema(
    schema_id: [u8; 32],
    canonical_body: &[u8],
    schema_registry: &im::HashMap<[u8; 32], SchemaEntry>,
) -> Result<Vec<u8>, String> {
    let entry = match schema_registry.get(&schema_id) {
        Some(e) if e.approved => e,
        _ => return Err("schema not approved".into()),
    };
    let value: serde_json::Value =
        serde_json::from_slice(canonical_body).map_err(|e| format!("invalid json: {}", e))?;
    let obj = match value.as_object() {
        Some(o) => o,
        None => return Err("schema expects object at root".into()),
    };
    // Extract only declared keys, in sorted order (deterministic)
    let mut projected = serde_json::Map::new();
    let mut sorted_keys = entry.keys.clone();
    sorted_keys.sort();
    for key in &sorted_keys {
        // Support dot-notation for nested keys: data.price → obj[data][price]
        let val = resolve_path(obj, key);
        match val {
            Some(v) => {
                projected.insert(key.clone(), v.clone());
            }
            None => return Err(format!("schema key {} not found in response", key)),
        }
    }
    serde_json::to_vec(&serde_json::Value::Object(projected))
        .map_err(|e| format!("json encode error: {}", e))
}

/// Resolve a dot-notation path in a JSON object.
/// price → obj[price]
/// data.price → obj[data][price]
fn resolve_path<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut parts = path.splitn(2, '.');
    let key = parts.next()?;
    let val = obj.get(key)?;
    match parts.next() {
        None => Some(val),
        Some(rest) => val.as_object().and_then(|o| resolve_path(o, rest)),
    }
}

/// Resolve a public URL's response format from the approved proposal.
pub fn url_response_format(
    url: &str,
    visibility: CellVisibility,
    url_proposals: &im::HashMap<String, UrlProposal>,
) -> UrlResponseFormat {
    match visibility {
        CellVisibility::Private => UrlResponseFormat::Raw,
        CellVisibility::Public => url_proposals
            .values()
            .find(|p| p.approved && url_matches_pattern(url, &p.url_pattern))
            .map(|p| p.response_format)
            .unwrap_or(UrlResponseFormat::Raw),
    }
}

pub fn url_schema_id(
    url: &str,
    visibility: CellVisibility,
    url_proposals: &im::HashMap<String, UrlProposal>,
) -> Option<[u8; 32]> {
    match visibility {
        CellVisibility::Private => None,
        CellVisibility::Public => url_proposals
            .values()
            .find(|p| p.approved && url_matches_pattern(url, &p.url_pattern))
            .and_then(|p| p.schema_id),
    }
}

fn strip_accord_query_params(url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|part| !part.starts_with("accord_format="))
        .filter(|part| !part.is_empty())
        .collect();
    if kept.is_empty() {
        base.to_string()
    } else {
        format!("{}?{}", base, kept.join("&"))
    }
}

/// Execute a single HTTP fetch. Returns raw body bytes on success.
async fn execute_http_fetch(
    client: &reqwest::Client,
    req: &OracleRequest,
) -> Result<(Vec<u8>, u16), String> {
    let fetch_url = strip_accord_query_params(&req.url);
    let builder = match req.method.as_str() {
        "GET" => client.get(&fetch_url),
        "POST" => client.post(&fetch_url).body(req.body.clone()),
        "PUT" => client.put(&fetch_url).body(req.body.clone()),
        "DELETE" => client.delete(&fetch_url),
        _ => return Err(format!("Unsupported method: {}", req.method)),
    };

    let response = builder
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    let status = response.status().as_u16();

    if let Some(len) = response.content_length() {
        if len as usize > gp::get_usize(gp::PARAM_MAX_RESPONSE_BYTES) {
            return Err("Response too large".to_string());
        }
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| format!("Body read error: {}", e))?
        .to_vec();

    if body.len() > gp::get_usize(gp::PARAM_MAX_RESPONSE_BYTES) {
        return Err("Response too large".to_string());
    }

    Ok((body, status))
}

//
// STORAGE KEY NAMESPACES
//

pub mod storage_keys {
    /// Pending oracle request: blake3("oracle:req:" || request_id)
    pub fn oracle_request(req_id: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"oracle:req:");
        h.update(req_id);
        (*h.finalize().as_bytes()).into()
    }

    /// Oracle tally: blake3("oracle:tally:" || request_id)
    pub fn oracle_tally(req_id: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"oracle:tally:");
        h.update(req_id);
        (*h.finalize().as_bytes()).into()
    }

    /// Finalized oracle result: blake3("oracle:result:" || request_id)
    pub fn oracle_result(req_id: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"oracle:result:");
        h.update(req_id);
        (*h.finalize().as_bytes()).into()
    }

    /// URL proposal: blake3("url:proposal:" || url_pattern_bytes)
    pub fn url_proposal(pattern: &str) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"url:proposal:");
        h.update(pattern.as_bytes());
        (*h.finalize().as_bytes()).into()
    }

    /// Cell visibility: blake3("cell:vis:" || cell_id)
    pub fn cell_visibility(cell_id: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"cell:vis:");
        h.update(cell_id);
        (*h.finalize().as_bytes()).into()
    }
}
