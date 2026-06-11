//! TruthLinked Chain Watcher
//!
//! - POST /register   { account_id, fcm_token }  — register device
//! - GET  /ws/{account_id}                        — WebSocket instant push
//! - Polls node every 2s, pushes via WebSocket + FCM

use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use hex;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::broadcast;
use truthlinked_core::pq_execution::usdc_system_cell_id;

#[derive(Clone)]
struct AppState {
    subs: Arc<DashMap<String, broadcast::Sender<String>>>,
    fcm_tokens: Arc<DashMap<String, String>>, // account_id -> fcm_token
    rpc: Arc<String>,
    project_id: Arc<String>,
    sa_path: Arc<String>,
}

#[derive(Deserialize)]
struct RegisterReq {
    account_id: String,
    #[serde(default)]
    fcm_token: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct TxEvent {
    tx_hash: String,
    title: String,
    body: String,
    intent_type: String,
    amount: Option<String>,
}

// ── Registration ──────────────────────────────────────────────────────────────

async fn register(
    State(s): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> Json<serde_json::Value> {
    s.subs
        .entry(req.account_id.clone())
        .or_insert_with(|| broadcast::channel(32).0);
    if !req.fcm_token.is_empty() {
        s.fcm_tokens
            .insert(req.account_id.clone(), req.fcm_token.clone());
    }
    // Persist to disk so registrations survive restarts
    persist_registrations(&s);
    tracing::info!(
        "Registered: {} (total: {})",
        &req.account_id[..8.min(req.account_id.len())],
        s.subs.len()
    );
    Json(serde_json::json!({"success": true}))
}

fn persist_registrations(s: &AppState) {
    let map: std::collections::HashMap<String, String> = s
        .fcm_tokens
        .iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    // Also persist accounts with no FCM token
    let all: std::collections::HashMap<String, String> = s
        .subs
        .iter()
        .map(|e| {
            (
                e.key().clone(),
                map.get(e.key()).cloned().unwrap_or_default(),
            )
        })
        .collect();
    if let Ok(json) = serde_json::to_string(&all) {
        let _ = std::fs::write("./watcher-registrations.json", json);
    }
}

fn load_registrations(s: &AppState) {
    let Ok(data) = std::fs::read_to_string("./watcher-registrations.json") else {
        return;
    };
    let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, String>>(&data) else {
        return;
    };
    for (account_id, fcm_token) in map {
        s.subs
            .entry(account_id.clone())
            .or_insert_with(|| broadcast::channel(32).0);
        if !fcm_token.is_empty() {
            s.fcm_tokens.insert(account_id, fcm_token);
        }
    }
    tracing::info!("Loaded {} registrations from disk", s.subs.len());
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

async fn ws_handler(
    Path(account_id): Path<String>,
    State(s): State<AppState>,
    ws: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    let rx = {
        let entry = s
            .subs
            .entry(account_id.clone())
            .or_insert_with(|| broadcast::channel(32).0);
        entry.subscribe()
    };
    ws.on_upgrade(move |socket| handle_ws(socket, rx, account_id))
}

async fn handle_ws(mut socket: WebSocket, mut rx: broadcast::Receiver<String>, account_id: String) {
    tracing::info!("WS connected: {}", &account_id[..8.min(account_id.len())]);
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(p) => { if socket.send(Message::Text(p.into())).await.is_err() { break; } }
                Err(_) => break,
            },
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                if socket.send(Message::Ping(vec![].into())).await.is_err() { break; }
            }
        }
    }
}

// ── FCM HTTP v1 push ──────────────────────────────────────────────────────────

async fn get_fcm_token(sa_path: &str) -> Option<String> {
    let output = tokio::process::Command::new("python3")
        .arg("-c")
        .arg(format!(r#"
import json, time, base64, urllib.request, urllib.parse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

with open('{}') as f:
    sa = json.load(f)

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

now = int(time.time())
header  = b64url(json.dumps({{'alg':'RS256','typ':'JWT'}}))
payload = b64url(json.dumps({{'iss':sa['client_email'],'scope':'https://www.googleapis.com/auth/firebase.messaging','aud':sa['token_uri'],'iat':now,'exp':now+3600}}))
key = serialization.load_pem_private_key(sa['private_key'].encode(), password=None)
sig = key.sign(f'{{header}}.{{payload}}'.encode(), padding.PKCS1v15(), hashes.SHA256())
jwt = f'{{header}}.{{payload}}.{{b64url(sig)}}'
data = urllib.parse.urlencode({{'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer','assertion':jwt}}).encode()
resp = json.loads(urllib.request.urlopen(urllib.request.Request(sa['token_uri'], data)).read())
print(resp['access_token'])
"#, sa_path))
        .output().await.ok()?;
    let token = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

async fn send_fcm(
    client: &reqwest::Client,
    sa_path: &str,
    project_id: &str,
    fcm_token: &str,
    title: &str,
    body: &str,
    tx_hash: &str,
) {
    let Some(access_token) = get_fcm_token(sa_path).await else {
        tracing::warn!("Failed to get FCM access token");
        return;
    };

    let payload = serde_json::json!({
        "message": {
            "token": fcm_token,
            "notification": { "title": title, "body": body },
            "android": { "priority": "high" },
            "data": { "type": "tx", "tx_hash": tx_hash }
        }
    });

    let url = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        project_id
    );
    match client
        .post(&url)
        .bearer_auth(&access_token)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => tracing::info!("FCM sent: {}", r.status()),
        Err(e) => tracing::warn!("FCM error: {}", e),
    }
}

// ── Tx types ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TxIntent {
    #[serde(rename = "type", default)]
    intent_type: String,
    amount: Option<String>,
    recipient: Option<String>,
    #[serde(default)]
    cell_id: Option<String>,
    data: Option<String>,
}

#[derive(Deserialize)]
struct TxRecord {
    tx_hash: String,
    status: String,
    intent: TxIntent,
}

#[derive(Deserialize)]
struct HistoryResp {
    transactions: Vec<TxRecord>,
    #[serde(default)]
    total_count: u64,
}

fn extract_amount(data: &str) -> Option<String> {
    let num: String = data
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let raw: u128 = num.parse().ok()?;
    if raw == 0 {
        return None;
    }
    let whole = raw / 1_000_000_000;
    let frac = raw % 1_000_000_000;
    if frac == 0 {
        Some(format!("{} TLKD", whole))
    } else {
        Some(format!(
            "{}.{} TLKD",
            whole,
            format!("{:09}", frac).trim_end_matches('0')
        ))
    }
}

fn make_event(tx: &TxRecord, my_id: &str) -> TxEvent {
    let intent_type = tx.intent.intent_type.to_lowercase();
    let usdc_cell_hex = hex::encode(usdc_system_cell_id());
    let (itype, amount) = if intent_type == "callcell" || intent_type == "call_cell" {
        let is_buy_cu = tx.intent.cell_id.as_deref() == Some(usdc_cell_hex.as_str());
        let t = if is_buy_cu { "buycu" } else { "callcell" };
        (t.to_string(), tx.intent.amount.clone())
    } else if intent_type == "complex" {
        let data = tx.intent.data.as_deref().unwrap_or("");
        let t = if data.contains("BuyCU") || data.contains("UsdcToCu") {
            "buycu"
        } else if data.contains("VeTrthLock") {
            "stakinglock"
        } else if data.contains("VeTrthUnlock") {
            "stakingunlock"
        } else if data.contains("Stake") {
            "stake"
        } else if data.contains("Unstake") {
            "unstake"
        } else if data.contains("MintNFT") {
            "mintnft"
        } else if data.contains("TransferNFT") {
            "transfernft"
        } else {
            "complex"
        };
        (t.to_string(), extract_amount(data))
    } else {
        (intent_type, tx.intent.amount.clone())
    };

    let is_in = tx.intent.recipient.as_deref() == Some(my_id)
        || itype.contains("airdrop")
        || itype.contains("mint");
    let amt = amount.as_deref().unwrap_or("TRTH");

    let (title, body) = match itype.as_str() {
        "transfer" => {
            if is_in {
                (format!("Received {}", amt), format!("You received {}", amt))
            } else {
                (
                    format!("Sent {}", amt),
                    format!("Transfer of {} confirmed", amt),
                )
            }
        }
        "buycu" => (
            format!("Bought CU"),
            format!("Swapped {} for compute units", amt),
        ),
        "stake" => (
            format!("Staked {}", amt),
            format!("{} staked to validator", amt),
        ),
        "unstake" => (format!("Unstaked {}", amt), format!("{} unstaking", amt)),
        "mintnft" => ("NFT Minted".into(), "New NFT minted to your wallet".into()),
        "transfernft" => {
            if is_in {
                (
                    "NFT Received".into(),
                    "An NFT was transferred to you".into(),
                )
            } else {
                ("NFT Sent".into(), "NFT transferred out".into())
            }
        }
        "stakinglock" => (
            format!("Locked {} staking", amt),
            format!("{} locked for governance", amt),
        ),
        "stakingunlock" => (
            format!("Unlocked {} staking", amt),
            format!("{} unlocked from staking", amt),
        ),
        _ => (
            "Transaction Confirmed".into(),
            "New transaction confirmed on-chain".into(),
        ),
    };

    TxEvent {
        tx_hash: tx.tx_hash.clone(),
        title,
        body,
        intent_type: itype,
        amount,
    }
}

// ── Poll loop ─────────────────────────────────────────────────────────────────

async fn poll_loop(state: AppState) {
    let client = reqwest::Client::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

    // Seed on startup
    {
        let ids: Vec<String> = state.subs.iter().map(|e| e.key().clone()).collect();
        for id in &ids {
            // Seed from the last 50 txs
            let count_res = client
                .post(format!("{}/transaction_history", state.rpc))
                .json(&serde_json::json!({"account_id": id, "limit": 1, "offset": 0}))
                .send()
                .await;
            let total = if let Ok(r) = count_res {
                r.json::<HistoryResp>()
                    .await
                    .map(|h| h.total_count)
                    .unwrap_or(0)
            } else {
                0
            };
            let offset = (total as usize).saturating_sub(50);
            if let Ok(res) = client
                .post(format!("{}/transaction_history", state.rpc))
                .json(&serde_json::json!({"account_id": id, "limit": 50, "offset": offset}))
                .send()
                .await
            {
                if let Ok(h) = res.json::<HistoryResp>().await {
                    for tx in h.transactions {
                        seen.insert(format!("{}:{}", id, tx.tx_hash));
                    }
                }
            }
        }
        tracing::info!("Seeded {} seen hashes", seen.len());
    }

    loop {
        interval.tick().await;
        let ids: Vec<String> = state.subs.iter().map(|e| e.key().clone()).collect();

        for id in ids {
            // Fetch newest txs: get total count first, then fetch last 10
            let count_res = client
                .post(format!("{}/transaction_history", state.rpc))
                .json(&serde_json::json!({"account_id": id, "limit": 1, "offset": 0}))
                .send()
                .await;
            let total = if let Ok(r) = count_res {
                r.json::<HistoryResp>()
                    .await
                    .map(|h| h.total_count)
                    .unwrap_or(0)
            } else {
                continue;
            };

            let offset = (total as usize).saturating_sub(10);
            let Ok(res) = client
                .post(format!("{}/transaction_history", state.rpc))
                .json(&serde_json::json!({"account_id": id, "limit": 10, "offset": offset}))
                .send()
                .await
            else {
                continue;
            };
            let Ok(history) = res.json::<HistoryResp>().await else {
                continue;
            };

            for tx in &history.transactions {
                // Build a per-account key so sender and receiver each get their own notification
                let account_tx_key = format!("{}:{}", id, tx.tx_hash);
                if seen.contains(&account_tx_key) {
                    continue;
                }
                if !matches!(
                    tx.status.to_lowercase().as_str(),
                    "success" | "confirmed" | "finalized"
                ) {
                    continue;
                }
                seen.insert(account_tx_key);

                let event = make_event(tx, &id);
                let payload = serde_json::to_string(&event).unwrap_or_default();

                // Push via WebSocket (instant when app is open)
                if let Some(sender) = state.subs.get(&id) {
                    let _ = sender.send(payload);
                }

                // Push via FCM (works when app is closed / phone locked)
                if let Some(token) = state.fcm_tokens.get(&id) {
                    send_fcm(
                        &client,
                        &state.sa_path,
                        &state.project_id,
                        &token,
                        &event.title,
                        &event.body,
                        &event.tx_hash,
                    )
                    .await;
                }

                tracing::info!("Pushed to {}: {}", &id[..8], event.title);
            }
        }
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let rpc = std::env::var("CHAIN_RPC").unwrap_or_else(|_| "http://localhost:19944".into());
    let port = std::env::var("WATCHER_PORT").unwrap_or_else(|_| "9977".into());
    let project_id = std::env::var("FCM_PROJECT_ID").unwrap_or_else(|_| "crom-c67df".into());
    let sa_path =
        std::env::var("FCM_SA_PATH").unwrap_or_else(|_| "./firebase-adminsdk.json".into());

    let state = AppState {
        subs: Arc::new(DashMap::new()),
        fcm_tokens: Arc::new(DashMap::new()),
        rpc: Arc::new(rpc),
        project_id: Arc::new(project_id),
        sa_path: Arc::new(sa_path),
    };

    tokio::spawn(poll_loop(state.clone()));

    // Load persisted registrations before starting
    load_registrations(&state);

    let app = Router::new()
        .route("/register", post(register))
        .route("/ws/{account_id}", get(ws_handler))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("Chain watcher listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(&addr).await?, app).await?;
    Ok(())
}
