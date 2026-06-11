use axum::{
    extract::State,
    http::header::{HeaderMap, HeaderName, HeaderValue},
    response::sse::{Event, KeepAlive},
    response::{IntoResponse, Response, Sse},
    routing::{get, post},
    Router,
};
use futures::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use fips204::ml_dsa_65::PublicKey;
use fips204::traits::{SerDes, Verifier};
use rand::RngCore;
use truthlinked_consensus::streaming_consensus::StreamingConsensus;

#[derive(Clone)]
pub struct OnChainMcpTransport {
    consensus: Arc<StreamingConsensus>,
    port: u16,
    registry_id: [u8; 32],
    agent_registry_id: [u8; 32],
    allowed_agents: Arc<RwLock<Vec<[u8; 32]>>>,
}

impl OnChainMcpTransport {
    pub fn new(
        consensus: Arc<StreamingConsensus>,
        port: u16,
        registry_id: [u8; 32],
        agent_registry_id: [u8; 32],
    ) -> Self {
        let allowed_agents = Arc::new(RwLock::new(load_allowed_agent_keys().0));
        Self {
            consensus,
            port,
            registry_id,
            agent_registry_id,
            allowed_agents,
        }
    }

    pub async fn start(&self) -> Result<(), String> {
        let state = Arc::new(TransportState {
            consensus: self.consensus.clone(),
            registry_id: self.registry_id,
            agent_registry_id: self.agent_registry_id,
            allowed_agents: self.allowed_agents.clone(),
            last_agent_reload: RwLock::new(Instant::now()),
            http_sessions: RwLock::new(HashMap::new()),
        });

        let app = Router::new()
            .route("/health", get(health))
            .route("/mcp", post(http_handler).get(sse_handler))
            .with_state(state);

        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("MCP transport bind failed: {}", e))?;
        axum::serve(listener, app.into_make_service())
            .await
            .map_err(|e| format!("MCP transport server failed: {}", e))?;
        Ok(())
    }
}

struct TransportState {
    consensus: Arc<StreamingConsensus>,
    registry_id: [u8; 32],
    agent_registry_id: [u8; 32],
    allowed_agents: Arc<RwLock<Vec<[u8; 32]>>>,
    last_agent_reload: RwLock<Instant>,
    // HTTP session store: session_token -> SessionAuth
    http_sessions: RwLock<HashMap<String, SessionAuth>>,
}

async fn health() -> impl IntoResponse {
    "ok"
}

/// SSE endpoint — GET /mcp
/// Streams real-time chain events to MCP clients.
/// Sends: new_block, chain_info updates
async fn sse_handler(
    State(state): State<Arc<TransportState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let consensus = state.consensus.clone();

    let stream = stream::unfold((consensus, 0u64), |(consensus, last_height)| async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        let height = consensus.get_current_height();
        if height > last_height {
            let event = Event::default().event("new_block").data(
                serde_json::json!({
                    "height": height,
                    "finalized_height": consensus.get_finalized_height(),
                })
                .to_string(),
            );
            Some((Ok(event), (consensus, height)))
        } else {
            // Send keepalive comment
            let event = Event::default().comment("keepalive");
            Some((Ok(event), (consensus, last_height)))
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn http_handler(
    State(state): State<Arc<TransportState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Parse body — tolerate empty body (some rmcp probes send no body)
    let body_val: serde_json::Value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                let err = serde_json::json!({"jsonrpc":"2.0","id":null,"result":null,
                    "error":{"code":-32700,"message":format!("Parse error: {}", e)}});
                return (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    axum::Json(err),
                )
                    .into_response();
            }
        }
    };

    // Streamable HTTP: session token in Mcp-Session-Id header
    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // New session — generate one
            let mut b = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut b);
            hex::encode(b)
        });

    let is_initialize = body_val
        .get("method")
        .and_then(|m| m.as_str())
        .map(|m| m == "initialize" || m == "mcp.initialize")
        .unwrap_or(false);

    let text = serde_json::to_string(&body_val).unwrap_or_default();

    let mut auth = {
        let sessions = state.http_sessions.read().unwrap();
        sessions
            .get(&session_id)
            .cloned()
            .unwrap_or_else(SessionAuth::new)
    };

    let response = handle_rpc_message(&state, &text, &mut auth).await;

    {
        let mut sessions = state.http_sessions.write().unwrap();
        sessions.insert(session_id.clone(), auth);
    }

    // MCP Streamable HTTP spec (2025-03-26): initialize response MUST include
    // Mcp-Session-Id so the client can attach it to all subsequent requests.
    let mut resp = axum::Json(response).into_response();
    if is_initialize {
        resp.headers_mut().insert(
            HeaderName::from_static("mcp-session-id"),
            HeaderValue::from_str(&session_id)
                .unwrap_or_else(|_| HeaderValue::from_static("session")),
        );
    }
    resp
}

async fn handle_rpc_message(
    state: &TransportState,
    text: &str,
    auth: &mut SessionAuth,
) -> McpResponse {
    let req: McpRequest = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            return error_response(None, -32700, &format!("Parse error: {}", e));
        }
    };

    let id = req.id.clone();
    let method = req.method.as_str();
    let params = req.params.clone().unwrap_or(Value::Null);

    match method {
        "initialize" | "mcp.initialize" => {
            let result = serde_json::json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": { "name": "truthlinked", "version": "0.1.0" },
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                }
            });
            ok_response(id, result)
        }
        "auth/challenge" | "mcp.auth.challenge" => {
            let mut nonce = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce);
            auth.pending_nonce = Some(nonce);
            ok_response(id, serde_json::json!({ "nonce": hex::encode(nonce) }))
        }
        "auth/respond" | "mcp.auth.respond" => {
            if let Err(e) = refresh_allowed_agents(state) {
                return error_response(id, -32002, &e);
            }
            let nonce = match auth.pending_nonce.take() {
                Some(n) => n,
                None => return error_response(id, -32002, "No challenge issued"),
            };
            let pk_hex = match params.get("public_key").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => return error_response(id, -32602, "Missing public_key"),
            };
            let sig_hex = match params.get("signature").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => return error_response(id, -32602, "Missing signature"),
            };
            let pk_bytes = match hex::decode(pk_hex) {
                Ok(b) => b,
                Err(_) => return error_response(id, -32602, "Invalid public_key hex"),
            };
            let sig_bytes = match hex::decode(sig_hex) {
                Ok(b) => b,
                Err(_) => return error_response(id, -32602, "Invalid signature hex"),
            };
            if pk_bytes.len() != 1952 || sig_bytes.len() != 3309 {
                return error_response(id, -32602, "Invalid key or signature length");
            }
            let pk_arr: [u8; 1952] = pk_bytes.as_slice().try_into().unwrap();
            let sig_arr: [u8; 3309] = sig_bytes.as_slice().try_into().unwrap();
            let pk = match PublicKey::try_from_bytes(pk_arr) {
                Ok(p) => p,
                Err(_) => return error_response(id, -32002, "Invalid public key"),
            };
            if !pk.verify(&nonce, &sig_arr, AUTH_SIGN_CONTEXT) {
                return error_response(id, -32002, "Signature verification failed");
            }
            let agent_id = truthlinked_state::pq_execution::account_id_from_pubkey(&pk_bytes);
            let allowed = state
                .allowed_agents
                .read()
                .map_err(|_| "Agent allowlist lock failed");
            let allowed = match allowed {
                Ok(v) => v,
                Err(e) => return error_response(id, -32002, &e),
            };
            if !allowed.iter().any(|id| *id == agent_id) {
                return error_response(id, -32002, "Agent key not authorized");
            }
            auth.authorized = true;
            auth.agent_id = Some(agent_id);
            auth.authorized_at = Some(Instant::now());
            auth.call_count = 0;
            ok_response(id, serde_json::json!({ "authorized": true }))
        }
        "tools/list" | "mcp.tools.list" => {
            // agent_id optional — if not provided, return all tools
            let agent_id = parse_account_param(&params, "agent_id").unwrap_or([0u8; 32]);
            let chain_state = state.consensus.get_state().load_full();
            let tools = truthlinked_mcp::enumerate_tools(
                chain_state.as_ref(),
                &state.registry_id,
                &state.agent_registry_id,
                &agent_id,
            );
            ok_response(id, serde_json::json!({ "tools": tools }))
        }
        "resources/list" | "mcp.resources.list" => {
            let chain_state = state.consensus.get_state().load_full();
            let resources =
                truthlinked_mcp::enumerate_resources(chain_state.as_ref(), &state.registry_id);
            ok_response(id, serde_json::json!({ "resources": resources }))
        }
        "prompts/list" | "mcp.prompts.list" => {
            let chain_state = state.consensus.get_state().load_full();
            let prompts =
                truthlinked_mcp::enumerate_prompts(chain_state.as_ref(), &state.registry_id);
            ok_response(id, serde_json::json!({ "prompts": prompts }))
        }
        "resources/read" | "mcp.resources.read" => {
            let uri = match params.get("uri").and_then(|v| v.as_str()) {
                Some(u) => u,
                None => return error_response(id, -32602, "Missing uri"),
            };
            let chain_state = state.consensus.get_state().load_full();
            let data =
                truthlinked_mcp::read_resource(chain_state.as_ref(), &state.registry_id, uri);
            ok_response(id, serde_json::json!({ "data": data }))
        }
        "prompts/get" | "mcp.prompts.get" => {
            let name = match params.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => return error_response(id, -32602, "Missing name"),
            };
            let chain_state = state.consensus.get_state().load_full();
            let prompt =
                truthlinked_mcp::get_prompt(chain_state.as_ref(), &state.registry_id, name);
            match prompt {
                Some(p) => ok_response(id, p),
                None => error_response(id, -32004, "Prompt not found"),
            }
        }
        "submit_transaction" | "mcp.submit_transaction" => {
            if let Err(e) = ensure_authorized(auth) {
                return error_response(id, -32002, &e);
            }
            let agent_id = match auth.agent_id {
                Some(id) => id,
                None => return error_response(id, -32001, "Authenticated agent missing"),
            };
            let tx_hex = match params.get("tx_hex").and_then(|v| v.as_str()) {
                Some(h) => h,
                None => return error_response(id, -32602, "Missing tx_hex"),
            };
            let tx_bytes = match hex::decode(tx_hex) {
                Ok(b) => b,
                Err(_) => return error_response(id, -32602, "Invalid tx_hex"),
            };
            let tx: truthlinked_core::pq_execution::Transaction = match bincode::deserialize(
                &tx_bytes,
            )
            .or_else(|_| postcard::from_bytes(&tx_bytes))
            {
                Ok(t) => t,
                Err(e) => return error_response(id, -32602, &format!("Tx decode failed: {}", e)),
            };
            match &tx.intent {
                truthlinked_core::pq_execution::TransactionIntent::McpToolCall { .. } => {}
                _ => {
                    return error_response(
                        id,
                        -32003,
                        "mcp.submit_transaction requires McpToolCall intent",
                    )
                }
            }
            if tx.sender != agent_id {
                return error_response(
                    id,
                    -32003,
                    &format!(
                        "Sender mismatch: tx.sender={} but authenticated agent={}",
                        hex::encode(tx.sender),
                        hex::encode(agent_id)
                    ),
                );
            }
            if let Err(e) = enforce_mcp_policy(
                &state.consensus,
                state.registry_id,
                state.agent_registry_id,
                &state.allowed_agents,
                &tx,
            ) {
                return error_response(id, -32003, &format!("Policy denied: {}", e));
            }
            match state.consensus.submit_transaction(tx).await {
                Ok(hash) => ok_response(id, serde_json::json!({ "tx_hash": hex::encode(hash) })),
                Err(e) => error_response(id, -32000, &e),
            }
        }
        "tools/call" | "mcp.tools.call" => {
            let tool_name = match params.get("name").and_then(|v| v.as_str()) {
                Some(n) => n.to_string(),
                None => return error_response(id, -32602, "Missing tool name"),
            };
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            let s = state.consensus.get_state().load_full();

            // Read-only tools — no auth required
            match tool_name.as_str() {
                "get_chain_info" => {
                    let h = state.consensus.get_current_height();
                    let fh = state.consensus.get_finalized_height();
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": serde_json::json!({
                                "height": h, "finalized_height": fh,
                                "genesis_hash": hex::encode(truthlinked_state::get_genesis_hash()),
                                "peer_count": state.consensus.get_session_count().await,
                            }).to_string() }]
                        }),
                    );
                }
                "get_balance" => {
                    let acct = args
                        .get("account_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let bal = hex::decode(acct)
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .map(|id: [u8; 32]| s.accounts.get(&id).map(|a| a.balance).unwrap_or(0))
                        .unwrap_or(0);
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": truthlinked_state::trth::format_amount(bal) }]
                        }),
                    );
                }
                "get_validators" => {
                    let vals: Vec<_> = s
                        .staking
                        .validators
                        .iter()
                        .map(|(pk, v)| {
                            serde_json::json!({
                                "pubkey": hex::encode(pk),
                                "active_stake": v.active_stake,
                                "jailed": v.jailed_until.is_some(),
                            })
                        })
                        .collect();
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": serde_json::to_string(&vals).unwrap_or_default() }]
                        }),
                    );
                }
                "get_token_info" => {
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": serde_json::json!({
                                "name": truthlinked_state::constants::TOKEN_NAME,
                                "symbol": truthlinked_state::constants::TOKEN_SYMBOL,
                                "decimals": truthlinked_state::constants::TOKEN_DECIMALS,
                                "total_supply": truthlinked_state::constants::TOTAL_SUPPLY.to_string(),
                            }).to_string() }]
                        }),
                    );
                }
                "get_cell_info" => {
                    let cell_id_hex = args.get("cell_id").and_then(|v| v.as_str()).unwrap_or("");
                    let info = hex::decode(cell_id_hex)
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .and_then(|id: [u8; 32]| {
                            s.cells.cells.get(&id).map(|c| {
                                serde_json::json!({
                                    "cell_id": cell_id_hex,
                                    "owner": hex::encode(c.owner),
                                    "is_token": c.is_token,
                                    "immutable": c.is_immutable,
                                })
                            })
                        })
                        .unwrap_or(serde_json::json!({"found": false}));
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": info.to_string() }]
                        }),
                    );
                }
                "get_transaction" => {
                    let tx_hash = args.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("");
                    let result = if let Some(storage) = state.consensus.get_storage() {
                        hex::decode(tx_hash)
                            .ok()
                            .and_then(|b| b.try_into().ok())
                            .and_then(|h: [u8; 32]| {
                                storage.get_transaction_by_hash(&h).ok().flatten()
                            })
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "not found".to_string())
                    } else {
                        "storage unavailable".to_string()
                    };
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": result }]
                        }),
                    );
                }
                "get_staking_info" => {
                    let active = s.staking.get_active_validators();
                    let total: u64 = active.values().sum();
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": serde_json::json!({
                                "active_validators": active.len(),
                                "total_validators": s.staking.validators.len(),
                                "total_staked": total.to_string(),
                            }).to_string() }]
                        }),
                    );
                }
                "get_oracle_result" => {
                    let req_id = args
                        .get("request_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let result = hex::decode(req_id)
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .and_then(|id: [u8; 32]| {
                            truthlinked_state::pq_execution::get_oracle_result(&id)
                        })
                        .map(|r| serde_json::to_string(&r).unwrap_or_default())
                        .unwrap_or_else(|| "not found".to_string());
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": result }]
                        }),
                    );
                }
                "get_account_history" => {
                    let acct = args
                        .get("account_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
                    let result = if let Some(storage) = state.consensus.get_storage() {
                        hex::decode(acct)
                            .ok()
                            .and_then(|b| b.try_into().ok())
                            .and_then(|id: [u8; 32]| {
                                storage
                                    .load_optimized_transaction_history(&id, limit, 0)
                                    .ok()
                            })
                            .map(|(txs, total)| {
                                serde_json::json!({"total": total, "transactions": txs}).to_string()
                            })
                            .unwrap_or_else(|| "not found".to_string())
                    } else {
                        "storage unavailable".to_string()
                    };
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": result }]
                        }),
                    );
                }
                // Write tools — require auth
                "submit_transaction" | "http_fetch" => {
                    if let Err(e) = ensure_authorized(auth) {
                        return error_response(id, -32002, &e);
                    }
                    // fall through to tx submission below
                }
                "faucet" => {
                    // Faucet requires a signed request. Axiom CLI handles key generation and signing.
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": "To claim devnet TLKD with Axiom CLI:\n\n1. Build the CLI: cargo build --release -p axiom-cli --bin axiom\n2. Generate keys: ./target/release/axiom account-create --output axiom_keys.json --encrypt\n3. Claim faucet: ./target/release/axiom faucet --from axiom_keys.json --amount 15000\n\nFaucet URL: https://faucet.truthlinked.org\nCooldown: 72 hours per account\nDefault amount: 15,000 TLKD per claim" }]
                        }),
                    );
                }
                "get_sdk" => {
                    return ok_response(
                        id,
                        serde_json::json!({
                            "content": [{
                                "type": "text",
                                "text": "Axiom CLI is the supported TruthLinked command-line interface.\n\nBuild from the repository:\n  cargo build --release -p axiom-cli --bin axiom\n\nCommon commands:\n  ./target/release/axiom account-create --output axiom_keys.json --encrypt\n  ./target/release/axiom chain-info\n  ./target/release/axiom faucet --from axiom_keys.json --amount 15000\n  ./target/release/axiom transfer --from axiom_keys.json --to-pubkey <recipient-pubkey> --amount 1\n"
                            }]
                        }),
                    );
                }
                _ => return error_response(id, -32601, &format!("Unknown tool: {}", tool_name)),
            }

            // Write path: submit_transaction — must be McpToolCall intent
            if tool_name == "submit_transaction" {
                let tx_hex = match args.get("tx_hex").and_then(|v| v.as_str()) {
                    Some(h) => h,
                    None => return error_response(id, -32602, "Missing tx_hex in arguments"),
                };
                let tx_bytes = match hex::decode(tx_hex) {
                    Ok(b) => b,
                    Err(_) => return error_response(id, -32602, "Invalid tx_hex"),
                };
                let tx: truthlinked_core::pq_execution::Transaction =
                    match bincode::deserialize(&tx_bytes)
                        .or_else(|_| postcard::from_bytes(&tx_bytes))
                    {
                        Ok(tx) => tx,
                        Err(e) => {
                            return error_response(
                                id.clone(),
                                -32602,
                                &format!("Tx decode failed: {}", e),
                            );
                        }
                    };

                // Enforce: tx must be McpToolCall intent
                match &tx.intent {
                    truthlinked_core::pq_execution::TransactionIntent::McpToolCall { .. } => {}
                    _ => {
                        return error_response(
                            id,
                            -32003,
                            "tools/call submit_transaction requires McpToolCall intent",
                        )
                    }
                }

                // Enforce: sender must match authenticated agent
                let agent_id = auth.agent_id.unwrap();
                if tx.sender != agent_id {
                    return error_response(
                        id,
                        -32003,
                        "tx.sender must match authenticated agent_id",
                    );
                }

                // Enforce policy check against live chain state
                if let Err(e) = enforce_mcp_policy(
                    &state.consensus,
                    state.registry_id,
                    state.agent_registry_id,
                    &state.allowed_agents,
                    &tx,
                ) {
                    return error_response(id, -32003, &format!("Policy denied: {}", e));
                }

                return match state.consensus.submit_transaction(tx).await {
                    Ok(hash) => ok_response(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": hex::encode(hash) }]
                        }),
                    ),
                    Err(e) => error_response(id, -32000, &e),
                };
            }

            // Write path: http_fetch — oracle requests are queued by cells during execution.
            // Return the deterministic request_id so the agent can poll get_oracle_result.
            if tool_name == "http_fetch" {
                let url = match args.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u,
                    None => return error_response(id, -32602, "Missing url"),
                };
                let cell_id_hex = match args.get("cell_id").and_then(|v| v.as_str()) {
                    Some(c) => c,
                    None => return error_response(id, -32602, "Missing cell_id"),
                };
                let request_id = truthlinked_oracle::http_oracle::request_id(
                    url,
                    "GET",
                    &[],
                    truthlinked_governance::UrlResponseFormat::Raw,
                    None,
                );
                return ok_response(
                    id,
                    serde_json::json!({
                        "content": [{ "type": "text", "text": serde_json::json!({
                            "request_id": hex::encode(request_id),
                            "status": "pending",
                            "note": "Oracle requests are queued when a cell calls http_get() during execution. Deploy a cell that calls http_get(url), then call it via tools/call submit_transaction. Poll get_oracle_result with the request_id once validators have committed.",
                            "url": url,
                            "consumer_cell_id": cell_id_hex,
                        }).to_string() }]
                    }),
                );
            }

            error_response(id, -32601, &format!("Unknown tool: {}", tool_name))
        }
        "mcp.suspend_agent" | "suspend_agent" => {
            // Owner suspends an agent — sets status=1 in the policy cell via SuspendAgent intent.
            // Requires the caller to be the agent's owner (enforced on-chain).
            let tx_hex = match params.get("tx_hex").and_then(|v| v.as_str()) {
                Some(h) => h,
                None => {
                    return error_response(
                        id,
                        -32602,
                        "Missing tx_hex (signed SuspendAgent transaction)",
                    )
                }
            };
            let tx_bytes = match hex::decode(tx_hex) {
                Ok(b) => b,
                Err(_) => return error_response(id, -32602, "Invalid tx_hex"),
            };
            let tx: truthlinked_core::pq_execution::Transaction = match bincode::deserialize(
                &tx_bytes,
            )
            .or_else(|_| postcard::from_bytes(&tx_bytes))
            {
                Ok(tx) => tx,
                Err(e) => {
                    return error_response(id.clone(), -32602, &format!("Tx decode failed: {}", e));
                }
            };
            match &tx.intent {
                truthlinked_core::pq_execution::TransactionIntent::SuspendAgent { .. } => {}
                _ => {
                    return error_response(id, -32003, "suspend_agent requires SuspendAgent intent")
                }
            }
            match state.consensus.submit_transaction(tx).await {
                Ok(hash) => ok_response(id, serde_json::json!({ "tx_hash": hex::encode(hash) })),
                Err(e) => error_response(id, -32000, &e),
            }
        }
        _ => error_response(id, -32601, "Method not found"),
    }
}

fn parse_account_param(params: &Value, name: &str) -> Result<[u8; 32], String> {
    let s = params
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing {}", name))?;
    let bytes = hex::decode(s).map_err(|_| format!("Invalid hex for {}", name))?;
    if bytes.len() != 32 {
        return Err(format!("{} must be 32-byte hex", name));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

const AUTH_SIGN_CONTEXT: &[u8] = b"truthlinked-mcp-auth-v1";

#[derive(Clone)]
struct SessionAuth {
    authorized: bool,
    agent_id: Option<[u8; 32]>,
    pending_nonce: Option<[u8; 32]>,
    authorized_at: Option<Instant>,
    call_count: u64,
}

impl SessionAuth {
    fn new() -> Self {
        Self {
            authorized: false,
            agent_id: None,
            pending_nonce: None,
            authorized_at: None,
            call_count: 0,
        }
    }
}

fn enforce_mcp_policy(
    consensus: &Arc<StreamingConsensus>,
    registry_id: [u8; 32],
    agent_registry_id: [u8; 32],
    allowed_agents: &Arc<RwLock<Vec<[u8; 32]>>>,
    tx: &truthlinked_core::pq_execution::Transaction,
) -> Result<(), String> {
    use truthlinked_core::pq_execution::TransactionIntent;
    use truthlinked_mcp::{agent_reg_keys, policy_keys, registry_keys, tool_keys};

    let (agent_id, tool_id, policy_cell_id, action_log_id) = match &tx.intent {
        TransactionIntent::McpToolCall {
            agent_id,
            tool_id,
            policy_cell_id,
            action_log_id,
            ..
        } => (*agent_id, *tool_id, *policy_cell_id, *action_log_id),
        _ => return Err("tools/call requires McpToolCall intent".to_string()),
    };

    if tx.sender != agent_id {
        return Err("McpToolCall sender must match agent_id".to_string());
    }
    if action_log_id.is_none() {
        return Err("McpToolCall requires action_log_id".to_string());
    }

    let allowed = allowed_agents
        .read()
        .map_err(|_| "Agent allowlist lock failed")?;
    if allowed.is_empty() {
        return Err("Agent key auth not configured".to_string());
    }
    if !allowed.iter().any(|id| *id == agent_id) {
        return Err("Agent key not authorized for MCP tools/call".to_string());
    }

    let state = consensus.get_state().load_full();

    let registry = state
        .cells
        .cells
        .get(&registry_id)
        .ok_or("McpRegistry not found")?;
    let agent_registry = state
        .cells
        .cells
        .get(&agent_registry_id)
        .ok_or("AgentRegistry not found")?;

    let stored_policy = agent_registry
        .storage
        .get(&agent_reg_keys::agent_policy(&agent_id))
        .copied()
        .ok_or("Agent not registered")?;
    if stored_policy != policy_cell_id {
        return Err("Policy cell mismatch for agent".to_string());
    }

    let policy = state
        .cells
        .cells
        .get(&policy_cell_id)
        .ok_or("Policy cell not found")?;

    let status = policy
        .storage
        .get(&policy_keys::STATUS)
        .map(|b| b[0])
        .unwrap_or(0);
    if status != 0 {
        return Err("Agent is suspended".to_string());
    }

    let tool = state
        .cells
        .cells
        .get(&tool_id)
        .ok_or("Tool cell not found")?;

    let enabled = tool
        .storage
        .get(&tool_keys::ENABLED)
        .map(|b| b[0] == 1)
        .unwrap_or(false);
    if !enabled {
        return Err("Tool is disabled".to_string());
    }

    // Ensure tool is registered in registry
    let mut registered = false;
    let tool_count = registry
        .storage
        .get(&registry_keys::TOOL_COUNT)
        .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0u8; 8])))
        .unwrap_or(0);
    for i in 0..tool_count {
        if registry.storage.get(&registry_keys::tool_entry(i)).copied() == Some(tool_id) {
            registered = true;
            break;
        }
    }
    if !registered {
        return Err("Tool not registered in MCP registry".to_string());
    }

    let perm = policy
        .storage
        .get(&policy_keys::tool_permission(&tool_id))
        .map(|b| b[0] == 1)
        .unwrap_or(false);
    let allow_reads = policy
        .storage
        .get(&policy_keys::ALLOW_READS)
        .map(|b| b[0] == 1)
        .unwrap_or(false);
    let category = tool
        .storage
        .get(&tool_keys::CATEGORY)
        .map(|b| b[0])
        .unwrap_or(0);

    if !perm && !(allow_reads && category == 0) {
        return Err("Policy denies tool call".to_string());
    }

    Ok(())
}

fn load_agents_from_chain(state: &TransportState) -> Vec<[u8; 32]> {
    use truthlinked_mcp::agent_reg_keys;
    let chain_state = state.consensus.get_state().load_full();
    let agent_registry_id = state.agent_registry_id;

    let mut registered = Vec::new();
    if let Some(registry) = chain_state.cells.cells.get(&agent_registry_id) {
        let count = registry
            .storage
            .get(&agent_reg_keys::AGENT_COUNT)
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0u8; 8])))
            .unwrap_or(0);
        for i in 0..count {
            if let Some(agent_id) = registry
                .storage
                .get(&agent_reg_keys::agent_entry(i))
                .copied()
            {
                if agent_id != [0u8; 32] && !registered.contains(&agent_id) {
                    registered.push(agent_id);
                }
            }
        }

        // Backward compatibility for registries created before agent_entry existed.
        for (account_id, _) in chain_state.accounts.iter() {
            let policy_key = agent_reg_keys::agent_policy(account_id);
            if let Some(val) = registry.storage.get(&policy_key).copied() {
                if val != [0u8; 32] && !registered.contains(account_id) {
                    registered.push(*account_id);
                }
            }
        }
    }
    // Also allow agents listed in the environment for local agent development.
    // TLKD_AGENT_KEYFILE is the current name; TRTH_AGENT_KEYFILE remains a
    // compatibility fallback for older deployments.
    if let Ok(raw) = std::env::var("TLKD_AGENT_KEYFILE")
        .or_else(|_| std::env::var("TRTH_AGENT_KEYFILE"))
    {
        for path in raw.split(',') {
            let path = path.trim();
            if path.is_empty() {
                continue;
            }
            if let Ok(id) = load_agent_keyfile(path) {
                if !registered.contains(&id) {
                    registered.push(id);
                }
            }
        }
    }
    registered
}

fn load_allowed_agent_keys() -> (Vec<[u8; 32]>, Vec<String>) {
    // Legacy: kept for startup initialization only.
    let Ok(raw) =
        std::env::var("TLKD_AGENT_KEYFILE").or_else(|_| std::env::var("TRTH_AGENT_KEYFILE"))
    else {
        return (Vec::new(), Vec::new());
    };
    let mut agents = Vec::new();
    let mut errors = Vec::new();
    for path in raw.split(',') {
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        match load_agent_keyfile(path) {
            Ok(id) => agents.push(id),
            Err(e) => errors.push(format!("{}: {}", path, e)),
        }
    }
    (agents, errors)
}

fn load_agent_keyfile(path: &str) -> Result<[u8; 32], String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let v: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("Invalid keyfile: {}", e))?;

    if v.get("encrypted")
        .and_then(|b| b.as_bool())
        .unwrap_or(false)
    {
        let pwd = std::env::var("TLKD_AGENT_KEY_PASSWORD")
            .or_else(|_| std::env::var("TRTH_AGENT_KEY_PASSWORD"))
            .map_err(|_| "Encrypted agent keyfile requires TLKD_AGENT_KEY_PASSWORD".to_string())?;
        let payload = v
            .get("data")
            .ok_or("Encrypted keyfile missing data payload")?;
        let decrypted = decrypt_keyfile(payload, &pwd)?;
        let v: serde_json::Value = serde_json::from_str(&decrypted)
            .map_err(|e| format!("Invalid decrypted keyfile: {}", e))?;
        return parse_agent_keyfile(&v);
    }

    parse_agent_keyfile(&v)
}

fn parse_agent_keyfile(v: &serde_json::Value) -> Result<[u8; 32], String> {
    let key_type = v
        .get("key_type")
        .and_then(|s| s.as_str())
        .ok_or("Missing key_type")?;
    if key_type != "agent" {
        return Err("Keyfile is not an agent key".to_string());
    }

    let pk_hex = v
        .get("dilithium_public")
        .and_then(|s| s.as_str())
        .ok_or("Missing dilithium_public")?;
    let pk_bytes = hex::decode(pk_hex).map_err(|_| "Invalid public key hex".to_string())?;
    Ok(truthlinked_state::pq_execution::account_id_from_pubkey(
        &pk_bytes,
    ))
}

fn decrypt_keyfile(payload: &serde_json::Value, password: &str) -> Result<String, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let salt_hex = payload
        .get("salt")
        .and_then(|s| s.as_str())
        .ok_or("Encrypted keyfile missing salt")?;
    let nonce_hex = payload
        .get("nonce")
        .and_then(|s| s.as_str())
        .ok_or("Encrypted keyfile missing nonce")?;
    let ciphertext_hex = payload
        .get("ciphertext")
        .and_then(|s| s.as_str())
        .ok_or("Encrypted keyfile missing ciphertext")?;

    let salt = hex::decode(salt_hex).map_err(|_| "Invalid salt hex".to_string())?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|_| "Invalid nonce hex".to_string())?;
    let ciphertext =
        hex::decode(ciphertext_hex).map_err(|_| "Invalid ciphertext hex".to_string())?;

    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce length".to_string());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Argon2 failed: {}", e))?;

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher init failed: {}", e))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decrypt failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|_| "Decrypted keyfile is not valid utf-8".to_string())
}

fn refresh_allowed_agents(state: &TransportState) -> Result<(), String> {
    const RELOAD_INTERVAL: Duration = Duration::from_secs(5);
    let now = Instant::now();
    {
        let last = state
            .last_agent_reload
            .read()
            .map_err(|_| "Agent allowlist lock failed".to_string())?;
        if now.duration_since(*last) < RELOAD_INTERVAL {
            return Ok(());
        }
    }
    // Read registered agents directly from the on-chain agent registry cell.
    // An agent is registered if agent_policy(agent_id) is non-zero in the registry cell storage.
    // This is the authoritative source — no static file needed.
    let agents = load_agents_from_chain(state);
    {
        let mut guard = state
            .allowed_agents
            .write()
            .map_err(|_| "Agent allowlist lock failed".to_string())?;
        *guard = agents;
    }
    let mut last = state
        .last_agent_reload
        .write()
        .map_err(|_| "Agent allowlist lock failed".to_string())?;
    *last = now;
    Ok(())
}

fn ensure_authorized(auth: &mut SessionAuth) -> Result<(), String> {
    const SESSION_TTL: Duration = Duration::from_secs(300);
    const MAX_CALLS: u64 = 500;
    if !auth.authorized {
        return Err("Authorization required".to_string());
    }
    let Some(since) = auth.authorized_at else {
        auth.authorized = false;
        return Err("Authorization expired".to_string());
    };
    if since.elapsed() > SESSION_TTL {
        auth.authorized = false;
        return Err("Authorization expired".to_string());
    }
    auth.call_count = auth.call_count.saturating_add(1);
    if auth.call_count > MAX_CALLS {
        auth.authorized = false;
        return Err("Authorization expired".to_string());
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct McpRequest {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct McpResponse {
    jsonrpc: String,
    id: Option<Value>,
    result: Option<Value>,
    error: Option<Value>,
}

fn ok_response(id: Option<Value>, result: Value) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(result),
        error: None,
    }
}

fn error_response(id: Option<Value>, code: i32, message: &str) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(serde_json::json!({ "code": code, "message": message })),
    }
}
