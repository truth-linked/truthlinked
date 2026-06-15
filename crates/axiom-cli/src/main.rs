//! Axiom CLI is the command surface for TruthLinked accounts, cells,
//! governance, validators, MCP resources, and SDK workflows.
//!
//! The CLI signs transactions, submits postcard-encoded payloads to the
//! TruthLinked RPC, and prints inspection results in human-readable or JSON
//! format.
use bip39::Mnemonic;
use clap::{Parser, Subcommand, ValueEnum};
use fips204::traits::{SerDes, Signer};
use include_dir::{include_dir, Dir};
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;

use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use truthlinked_core::*;
use truthlinked_state::parse_amount as parse_tlkd_amount;

/// Returns the default signing key path.
fn default_keyfile_path() -> String {
    dirs::home_dir()
        .map(|p| p.join(".truthlinked").join("default.keys"))
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "default.keys".to_string())
}

#[derive(Deserialize, Default)]
struct CliConfig {
    rpc: Option<String>,
    rpc_by_network: Option<HashMap<String, String>>,
    default_keyfile: Option<String>,
}

fn load_cli_config() -> Option<CliConfig> {
    let path = dirs::home_dir().map(|p| p.join(".truthlinked").join("config.json"))?;
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn resolve_keyfile_path(config: Option<&CliConfig>) -> String {
    config
        .and_then(|c| c.default_keyfile.as_ref())
        .cloned()
        .unwrap_or_else(default_keyfile_path)
}

fn resolve_relative_to_config(path: &str, config_path: &std::path::Path) -> String {
    let key_path = std::path::Path::new(path);
    if key_path.is_absolute() {
        return path.to_string();
    }
    config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(key_path)
        .to_string_lossy()
        .to_string()
}

fn resolve_keyfile_from_config_file(
    path: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{} does not define a keyfile", path.display()).into());
    }

    if let Ok(config) = serde_json::from_str::<CliConfig>(trimmed) {
        if let Some(default_keyfile) = config.default_keyfile {
            return Ok(resolve_relative_to_config(&default_keyfile, path));
        }
        return Err(format!(
            "{} is a config file but has no default_keyfile",
            path.display()
        )
        .into());
    }

    Ok(resolve_relative_to_config(trimmed, path))
}

fn resolve_signing_keyfile_arg(
    from: Option<&str>,
    config: Option<&CliConfig>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(p) = from {
        if p.is_empty() {
            return Err("Keyfile path cannot be empty".into());
        }
        let path = std::path::Path::new(p);
        if !path.exists() || !path.is_file() {
            return Err(format!("Keyfile not found: {}", path.display()).into());
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("config") {
            return resolve_keyfile_from_config_file(path);
        }
        return Ok(p.to_string());
    }

    let local_config = std::path::Path::new("axiom/config");
    if local_config.exists() && local_config.is_file() {
        return resolve_keyfile_from_config_file(local_config);
    }

    Ok(resolve_keyfile_path(config))
}

fn resolve_rpc(cli: &Cli, config: Option<&CliConfig>) -> String {
    if let Ok(rpc) = std::env::var("TRUTHLINKED_RPC") {
        if !rpc.trim().is_empty() {
            return rpc;
        }
    }
    if let Some(rpc) = cli.rpc.as_ref() {
        return rpc.clone();
    }
    if let Some(network) = cli.network.as_ref() {
        if let Some(cfg) = config.and_then(|c| c.rpc_by_network.as_ref()) {
            if let Some(rpc) = cfg.get(&network.to_string()) {
                return rpc.clone();
            }
        }
        return network.default_rpc().to_string();
    }
    if let Some(rpc) = config.and_then(|c| c.rpc.as_ref()) {
        return rpc.clone();
    }
    "https://testnet.truthlinked.org".to_string()
}

fn resolve_output(cli: &Cli) -> OutputFormat {
    if cli.json {
        OutputFormat::Json
    } else {
        cli.output.unwrap_or(OutputFormat::Pretty)
    }
}

fn parse_amount_str(input: &str) -> Result<u128, String> {
    parse_tlkd_amount(input)
}

enum RecipientInput {
    AccountId([u8; 32]),
    Pubkey(Vec<u8>),
    Name(String),
}

fn parse_recipient_input(raw: &str) -> Result<RecipientInput, String> {
    if raw.is_empty() {
        return Err("Recipient cannot be empty".to_string());
    }
    if raw.ends_with(".tl") {
        return Ok(RecipientInput::Name(raw.to_string()));
    }
    if !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Recipient must be hex (pubkey/account ID) or a name ending in .tl".to_string());
    }
    if raw.len() % 2 != 0 {
        return Err(format!("Incomplete hex string: got {} chars, expected an even number", raw.len()));
    }
    if raw.len() == 64 {
        let bytes = hex::decode(raw).map_err(|_| "Invalid account ID hex".to_string())?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        return Ok(RecipientInput::AccountId(id));
    }
    if raw.len() == 3904 {
        let bytes = hex::decode(raw).map_err(|_| "Invalid pubkey hex".to_string())?;
        return Ok(RecipientInput::Pubkey(bytes));
    }
    Err(format!(
        "Recipient hex length not recognized: got {} hex chars ({} bytes); expected 64 hex chars for an account ID or 3904 hex chars for a Dilithium public key",
        raw.len(),
        raw.len() / 2
    ))
}

fn parse_hex_32(label: &str, raw: &str) -> Result<[u8; 32], String> {
    parse_hex_array::<32>(label, raw)
}

fn parse_hex_array<const N: usize>(label: &str, raw: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(raw).map_err(|_| format!("Invalid hex for {}", label))?;
    if bytes.len() != N {
        return Err(format!("{} must be {}-byte hex", label, N));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn private_balance_material(
    balance: u128,
    aes_seed_hex: &str,
    enc_nonce_hex: &str,
    commit_nonce_hex: &str,
) -> Result<(Vec<u8>, [u8; 32], [u8; 16]), Box<dyn std::error::Error>> {
    let seed = parse_hex_bytes("aes_seed_hex", aes_seed_hex)?;
    let enc_nonce = parse_hex_array::<12>("enc_nonce_hex", enc_nonce_hex)?;
    let commit_nonce = parse_hex_array::<16>("commit_nonce_hex", commit_nonce_hex)?;
    let aes_key = truthlinked_mcp::private_balance::derive_aes_key(&seed);
    let encrypted_balance =
        truthlinked_mcp::private_balance::encrypt_balance(balance, &aes_key, &enc_nonce)?;
    let commitment = truthlinked_mcp::private_balance::compute_commitment(
        balance,
        u128::from_le_bytes(commit_nonce),
        &encrypted_balance,
    );
    Ok((encrypted_balance, commitment, commit_nonce))
}

fn submit_signed_intent(
    client: &reqwest::blocking::Client,
    rpc: &str,
    retries: u32,
    sender_id: AccountId,
    sender_keys: &pq_identity::DualKeypair,
    intent: TransactionIntent,
) -> Result<Value, Box<dyn std::error::Error>> {
    let genesis_hash = fetch_genesis_hash(client, rpc, retries)?;
    let nonce = next_nonce(client, rpc, &sender_id, retries)?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let tx = Transaction {
        sender: sender_id,
        intent,
        signature: vec![],
        nonce,
        timestamp,
        genesis_fingerprint: genesis_hash,
        expiration_height: u64::MAX,
    };
    submit_transaction_with_nonce_retry(client, rpc, retries, sender_keys, tx)
}

fn attach_private_balance_output(
    res: &mut Value,
    cell_id: &AccountId,
    agent_id: &AccountId,
    balance: u128,
    encrypted_balance: &[u8],
    commitment: &[u8; 32],
    commit_nonce: &[u8; 16],
) {
    if let Some(map) = res.as_object_mut() {
        map.insert(
            "private_balance".to_string(),
            serde_json::json!({
                "cell_id": hex::encode(cell_id),
                "agent_id": hex::encode(agent_id),
                "balance_units": balance.to_string(),
                "encrypted_balance_hex": hex::encode(encrypted_balance),
                "commitment": hex::encode(commitment),
                "commit_nonce_hex": hex::encode(commit_nonce),
            }),
        );
    }
}

fn parse_hex_bytes(label: &str, raw: &str) -> Result<Vec<u8>, String> {
    hex::decode(raw).map_err(|_| format!("Invalid hex for {}", label))
}

fn parse_hex_bytes_exact(label: &str, raw: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let bytes = parse_hex_bytes(label, raw)?;
    if bytes.len() != expected_len {
        return Err(format!("{} must be {}-byte hex", label, expected_len));
    }
    Ok(bytes)
}

fn load_bytes(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(std::fs::read(path)?)
}

fn load_optional_bytes(path: Option<String>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(p) = path {
        Ok(std::fs::read(p)?)
    } else {
        Ok(Vec::new())
    }
}

fn prompt_line(label: &str) -> Result<String, Box<dyn std::error::Error>> {
    eprint!("{}: ", label);
    use std::io::Write;
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn confirm_or_abort(
    yes: bool,
    output: OutputFormat,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if yes || output == OutputFormat::Json {
        return Ok(());
    }
    eprint!("{} [y/N]: ", message);
    use std::io::Write;
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    let ok = matches!(buf.trim().to_lowercase().as_str(), "y" | "yes");
    if ok {
        Ok(())
    } else {
        Err("Aborted by user".into())
    }
}

fn get_json(
    client: &reqwest::blocking::Client,
    url: &str,
    retries: u32,
) -> Result<Value, Box<dyn std::error::Error>> {
    for attempt in 0..=retries {
        match client.get(url).send().and_then(|r| r.error_for_status()) {
            Ok(resp) => return Ok(resp.json()?),
            Err(_err) if attempt < retries => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err("unreachable".into())
}

fn post_json(
    client: &reqwest::blocking::Client,
    url: &str,
    body: Value,
    retries: u32,
) -> Result<Value, Box<dyn std::error::Error>> {
    for attempt in 0..=retries {
        match client
            .post(url)
            .json(&body)
            .send()
            .and_then(|r| r.error_for_status())
        {
            Ok(resp) => return Ok(resp.json()?),
            Err(_err) if attempt < retries => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err("unreachable".into())
}

fn post_bytes(
    client: &reqwest::blocking::Client,
    url: &str,
    body: Vec<u8>,
    retries: u32,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut last_err = String::new();
    for attempt in 0..=retries {
        match client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(body.clone())
            .send()
        {
            Ok(resp) => {
                let status = resp.status();
                let bytes = resp.bytes()?;
                if !status.is_success() {
                    last_err = format!(
                        "POST {} returned {}: {}",
                        url,
                        status,
                        String::from_utf8_lossy(&bytes)
                    );
                } else {
                    return Ok(serde_json::from_slice(&bytes)?);
                }
            }
            Err(err) => last_err = err.to_string(),
        }
        if attempt < retries {
            continue;
        }
    }
    Err(format!("post failed: {}", last_err).into())
}

fn expected_nonce_from_submit_response(res: &Value) -> Option<u64> {
    if res.get("success").and_then(|v| v.as_bool()) != Some(false) {
        return None;
    }
    let err = res.get("error")?.as_str()?;

    if let Some(start) = err.find("missing nonce ") {
        let rest = &err[start + "missing nonce ".len()..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if let Ok(nonce) = rest[..end].parse::<u64>() {
            return Some(nonce);
        }
    }

    let marker = "expected ";
    let start = err.find(marker)? + marker.len();
    let rest = &err[start..];
    let end = rest.find("..").or_else(|| rest.find(","))?;
    rest[..end].parse::<u64>().ok()
}

enum SubmittedTxOutcome {
    Confirmed,
    Rejected(String),
}

fn wait_for_submitted_tx_outcome(
    client: &reqwest::blocking::Client,
    rpc: &str,
    retries: u32,
    account_id: &[u8; 32],
    tx_hash: &str,
    nonce: u64,
) -> Result<SubmittedTxOutcome, String> {
    let wait_timeout = nonce_queue_wait_timeout();
    let wait_start = std::time::Instant::now();
    loop {
        let tx = get_json(client, &format!("{}/tx/{}", rpc, tx_hash), retries).ok();
        let status = tx
            .as_ref()
            .and_then(|v| v.get("status"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        match status.as_deref() {
            Some("rejected") => {
                let reason = tx
                    .as_ref()
                    .and_then(|v| v.get("reason").or_else(|| v.get("error")))
                    .and_then(|v| v.as_str())
                    .unwrap_or("transaction rejected")
                    .to_string();
                return Ok(SubmittedTxOutcome::Rejected(reason));
            }
            Some("confirmed") => {
                let chain_nonce = fetch_account_nonce(client, rpc, account_id, retries)?;
                if chain_nonce >= nonce {
                    return Ok(SubmittedTxOutcome::Confirmed);
                }
            }
            _ => {}
        }
        if wait_start.elapsed() >= wait_timeout {
            return Err(format!(
                "Submitted transaction {} did not confirm within {}s; retry later or increase AXIOM_NONCE_QUEUE_WAIT_SECS",
                tx_hash,
                wait_timeout.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn submit_transaction_with_nonce_retry(
    client: &reqwest::blocking::Client,
    rpc: &str,
    retries: u32,
    sender_keys: &pq_identity::DualKeypair,
    mut tx: Transaction,
) -> Result<Value, Box<dyn std::error::Error>> {
    let submit_url = format!("{}/submit_raw", rpc);
    for attempt in 0..=3 {
        tx.signature.clear();
        let signed = sender_keys.sign_transaction(&tx)?;
        let bytes = postcard::to_allocvec(&signed)?;
        let res = post_bytes(client, &submit_url, bytes, retries)?;
        if res.get("success").and_then(|v| v.as_bool()) == Some(true) {
            if let Some(hash) = res.get("tx_hash").and_then(|v| v.as_str()) {
                set_nonce_queue_last_tx(rpc, &tx.sender, hash, tx.nonce)?;
                match wait_for_submitted_tx_outcome(
                    client, rpc, retries, &tx.sender, hash, tx.nonce,
                )? {
                    SubmittedTxOutcome::Confirmed => return Ok(res),
                    SubmittedTxOutcome::Rejected(reason) => {
                        let next = fetch_account_nonce(client, rpc, &tx.sender, retries)?
                            .saturating_add(1);
                        set_nonce_queue_next(rpc, &tx.sender, next)?;
                        let mut rejected = res;
                        if let Some(map) = rejected.as_object_mut() {
                            map.insert("success".to_string(), serde_json::json!(false));
                            map.insert("error".to_string(), serde_json::json!(reason));
                        }
                        return Ok(rejected);
                    }
                }
            }
            return Ok(res);
        }
        if let Some(expected_nonce) = expected_nonce_from_submit_response(&res) {
            if expected_nonce != tx.nonce && attempt < 3 {
                set_nonce_queue_next(rpc, &tx.sender, expected_nonce.saturating_add(1))?;
                tx.nonce = expected_nonce;
                tx.timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                continue;
            }
        }
        return Ok(res);
    }
    unreachable!()
}

fn load_keypair_and_pubkey(
    path: &str,
) -> Result<(pq_identity::DualKeypair, Vec<u8>), Box<dyn std::error::Error>> {
    let keypair = pq_identity::DualKeypair::load(path)?;
    let pubkey = keypair.dilithium_pk.clone().into_bytes().to_vec();
    Ok((keypair, pubkey))
}

fn load_account_id_and_keypair(
    path: &str,
) -> Result<(AccountId, pq_identity::DualKeypair), Box<dyn std::error::Error>> {
    let keypair = pq_identity::DualKeypair::load(path)?;
    let pubkey = keypair.dilithium_pk.clone().into_bytes().to_vec();
    let account_id = pq_identity::account_id_from_pubkey(&pubkey);
    Ok((account_id, keypair))
}

fn load_keypair_arg(
    from: Option<&str>,
    config: Option<&CliConfig>,
) -> Result<pq_identity::DualKeypair, Box<dyn std::error::Error>> {
    let keyfile = resolve_signing_keyfile_arg(from, config)?;
    Ok(pq_identity::DualKeypair::load(&keyfile)?)
}

fn load_account_id_and_keypair_arg(
    from: Option<&str>,
    config: Option<&CliConfig>,
) -> Result<(AccountId, pq_identity::DualKeypair), Box<dyn std::error::Error>> {
    let keyfile = resolve_signing_keyfile_arg(from, config)?;
    load_account_id_and_keypair(&keyfile)
}

fn account_id_from_keyfile_arg(
    from: Option<&str>,
    config: Option<&CliConfig>,
) -> Result<AccountId, Box<dyn std::error::Error>> {
    let (account_id, _) = load_account_id_and_keypair_arg(from, config)?;
    Ok(account_id)
}

fn pubkey_from_keyfile_arg(
    from: Option<&str>,
    config: Option<&CliConfig>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let keypair = load_keypair_arg(from, config)?;
    Ok(keypair.dilithium_pk.into_bytes().to_vec())
}

fn get_expiration_height(
    client: &reqwest::blocking::Client,
    rpc: &str,
    retries: u32,
) -> Result<u64, Box<dyn std::error::Error>> {
    let info = get_json(client, &format!("{}/chain_info", rpc), retries)?;
    let height = info
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or("Missing height")?;
    Ok(height.saturating_add(100))
}

static SDK_TEMPLATE_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/template");

const LARGE_TRANSFER_TLKD: u64 = 1_000;

#[derive(Deserialize)]
#[allow(dead_code)]
struct RpcAccountInfo {
    account_id: String,
    found: bool,
    balance: String,
    balance_tlkd: String,
    is_cell: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RpcCellInfo {
    cell_id: String,
    found: bool,
    is_token: bool,
    immutable: bool,
}

/// Global CLI options.
#[derive(Parser)]
#[command(name = "axiom")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "TruthLinked command-line interface")]
struct Cli {
    /// TruthLinked RPC base URL.
    #[arg(long)]
    rpc: Option<String>,

    /// Network preset used when `--rpc` is omitted.
    #[arg(long, short = 'n', value_enum)]
    network: Option<Network>,

    /// Output format.
    #[arg(long, value_enum)]
    output: Option<OutputFormat>,

    /// Print machine-readable JSON.
    #[arg(long, short = 'j')]
    json: bool,

    /// Confirm command prompts automatically.
    #[arg(long, short = 'y')]
    yes: bool,

    /// RPC timeout in seconds.
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// RPC retry count.
    #[arg(long, default_value = "2")]
    retries: u32,

    #[command(subcommand)]
    command: Commands,
}

/// Command output mode.
#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Pretty,
    Json,
}

/// Built-in RPC networks.
#[derive(ValueEnum, Clone, Copy)]
enum Network {
    Local,
    Devnet,
    Testnet,
    Mainnet,
}

impl Network {
    fn default_rpc(self) -> &'static str {
        match self {
            Network::Local => "http://localhost:19944",
            Network::Devnet => "https://testnet.truthlinked.org",
            Network::Testnet => "https://testnet.truthlinked.org",
            Network::Mainnet => "https://mainnet.truthlinked.org",
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Network::Local => "local",
            Network::Devnet => "devnet",
            Network::Testnet => "testnet",
            Network::Mainnet => "mainnet",
        };
        write!(f, "{}", s)
    }
}

/// Actions under the `send` (or `s`, `pay`) command.
/// Everything that moves value or assets to others lives here or under `nft`.
#[derive(Subcommand, Clone)]
enum SendAction {
    /// Send native tokens (TLKD / the main value).
    ///
    /// This is the primary everyday command.
    /// Recipient can be a .tl name, account ID, or pubkey.
    /// Amount supports human numbers (e.g. 1.5, 1000, 2k).
    ///
    /// If you omit recipient or amount it will prompt you interactively.
    ///
    /// Examples:
    ///   axiom send alice.tl 100
    ///   axiom s 0xabc...def 42.5 --from ./my.keys
    ///   axiom pay grandma.tl 10
    #[command(visible_alias = "native", visible_alias = "value", visible_alias = "tlkd")]
    Native {
        /// Who to send to (.tl name, 64-char account id hex, or long pubkey hex).
        #[arg(value_name = "RECIPIENT", index = 1)]
        recipient: Option<String>,

        /// How much to send (human units, decimals OK).
        #[arg(value_name = "AMOUNT", index = 2)]
        amount: Option<String>,

        /// Keyfile / config to send from.
        /// Defaults to ~/.truthlinked/default.keys or ./axiom/config.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
    },

    /// Send an NFT as part of sending value.
    ///
    /// Use this or `axiom nft send ...` — both work.
    ///
    /// Recipient supports .tl names (recommended for humans).
    #[command(visible_alias = "nft")]
    Nft {
        /// The NFT's 32-byte ID as hex (64 characters).
        #[arg(value_name = "NFT_ID", index = 1)]
        nft_id: String,

        /// Recipient (.tl name is easiest, or hex account/pubkey).
        #[arg(value_name = "RECIPIENT", index = 2)]
        recipient: String,

        /// Optional sale/transfer price in native tokens.
        #[arg(long, short = 'p', value_name = "PRICE")]
        price: Option<String>,

        /// Keyfile to sign with.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
    },

    /// Send tokens from a token cell.
    ///
    /// This completes the "send value" family (native + NFT + tokens) under one
    /// easy command. Recipient supports .tl names, hex accounts, or pubkeys.
    ///
    /// Amount accepts human-friendly values (decimals, k/m suffixes, etc.).
    ///
    /// Examples:
    ///   axiom send token <token_id> alice.tl 100
    ///   axiom send token abcdef... grandma.tl 42.5
    ///   axiom s token <token> 0x... 1000 --from ./my.keys
    #[command(visible_alias = "token")]
    Token {
        /// Token cell ID (32-byte hex).
        #[arg(value_name = "TOKEN", index = 1)]
        token: String,

        /// Recipient (.tl name is easiest for humans).
        #[arg(value_name = "RECIPIENT", index = 2)]
        recipient: String,

        /// Amount in human units (supports decimals and suffixes).
        #[arg(value_name = "AMOUNT", index = 3)]
        amount: String,

        /// Keyfile / config to send from.
        /// Defaults to the one created with `axiom keygen`.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
    },
}

/// NFT-specific actions. Sending NFTs is also available via `axiom send nft`.
#[derive(Subcommand, Clone)]
enum NftAction {
    /// Mint a brand new NFT.
    ///
    /// You choose (or we can help generate) a unique 32-byte ID.
    /// Metadata URI is usually ipfs://... or https://...
    Mint {
        /// Unique 32-byte hex ID for this NFT (you must pick one that isn't used yet).
        #[arg(long, value_name = "NFT_ID")]
        nft_id: String,

        /// Human name for the NFT.
        #[arg(long, short = 'n', value_name = "NAME")]
        name: String,

        /// URI to the metadata / image / content.
        #[arg(long, short = 'm', value_name = "URI")]
        metadata_uri: String,

        /// Optional collection/group ID.
        #[arg(long)]
        collection: Option<String>,

        /// Royalty in basis points (e.g. 250 = 2.5%). Max 10000.
        #[arg(long, default_value = "0")]
        royalty_bps: u16,

        /// Who receives the royalty (defaults to you the minter).
        #[arg(long)]
        royalty_recipient: Option<String>,

        #[arg(long, short = 'f')]
        from: Option<String>,
    },

    /// Transfer / send an NFT to someone (same as `axiom send nft`).
    Send {
        #[arg(value_name = "NFT_ID", index = 1)]
        nft_id: String,

        #[arg(value_name = "RECIPIENT", index = 2)]
        recipient: String,

        #[arg(long, short = 'p')]
        price: Option<String>,

        #[arg(long, short = 'f')]
        from: Option<String>,
    },

    /// Permanently destroy an NFT you own.
    Burn {
        #[arg(value_name = "NFT_ID")]
        nft_id: String,

        #[arg(long, short = 'f')]
        from: Option<String>,
    },

    /// Approve another account to transfer your NFT on your behalf.
    Approve {
        #[arg(value_name = "NFT_ID")]
        nft_id: String,

        /// Who you are giving permission to (use "none" or omit to clear).
        #[arg(value_name = "APPROVED", index = 2)]
        approved: Option<String>,

        #[arg(long, short = 'f')]
        from: Option<String>,
    },

    /// Show details about one NFT.
    Info {
        #[arg(value_name = "NFT_ID")]
        nft_id: String,
    },

    /// List NFTs owned by an account (defaults to you).
    List {
        /// Account to list for (name, id, or keyfile). Defaults to your account.
        #[arg(value_name = "ACCOUNT")]
        account: Option<String>,
    },
}

/// TruthLinked command surface.
#[derive(Subcommand)]
enum Commands {
    /// Show chain height, finality, genesis, and mint authority.
    ///
    /// RPC: GET `/chain_info`.
    ChainInfo,
    /// Show native token metadata.
    ///
    /// RPC: GET `/token_info`.
    TokenInfo,
    /// Show peer and network health.
    ///
    /// RPC: GET `/network_info`.
    NetworkInfo,
    /// List validators.
    ///
    /// RPC: GET `/validators`.
    Validators,
    /// Show pending transaction pool status.
    ///
    /// RPC: GET `/mempool`.
    Mempool,

    /// Send value (native tokens, NFTs, or tokens from token cells).
    ///
    /// This is the primary, easy command for moving anything of value.
    /// Use `axiom send --help` (or `s`, `pay`) to see the options.
    /// Recipient always supports friendly .tl names.
    #[command(visible_alias = "s", visible_alias = "pay", visible_alias = "transfer")]
    Send {
        #[command(subcommand)]
        action: SendAction,
    },

    /// NFTs (mint, transfer/send, burn, approve, view).
    ///
    /// Sending NFTs is also available via `axiom send nft`.
    /// Use `axiom nft --help` (or `n`).
    #[command(visible_alias = "n", visible_alias = "nfts")]
    Nft {
        #[command(subcommand)]
        action: NftAction,
    },

    /// Show chain status and signer balance.
    /// Show chain status, peer metrics, and signer balance in a unified view.
    Status {
        /// Keyfile or config to sign with.
        /// Defaults to the key created with `axiom keygen` (stored as ~/.truthlinked/default.keys
        /// and recorded in ~/.truthlinked/config.json).
        /// Use --from only when you want to override for this command.
        #[arg(long, short = 'k', value_name = "KEYFILE")]
        from: Option<String>,
        /// Include compute escrow, staking, and token balances.
        #[arg(long)]
        full: bool,
    },
    ///
    /// RPC: GET `/resolve/{query}`.
    Resolve { query: String },
    /// List active cell governance proposals.
    ///
    /// RPC: GET `/cell_proposals`.
    ListCellProposals,
    /// Show transaction status by hash.
    ///
    /// RPC: GET `/tx/{hash}` with mempool status resolution.
    TxStatus { hash: String },
    /// Alias for tx-status: `tx <hash>`.
    Tx { hash: String },
    /// Show balance by account ID.
    ///
    /// RPC: POST `/balance`.
    Balance {
        /// Account ID. Defaults to the configured signing account when omitted.
        #[arg(value_name = "account_id")]
        account_id: Option<String>,
        /// Signing keyfile or config file used when account_id is omitted.
        #[arg(long, short = 'k', value_name = "KEYFILE")]
        from: Option<String>,
        /// Include compute escrow, staking, and token balances.
        #[arg(long, short = 'S')]
        full: bool,
    },
    /// Show balance by public key.
    ///
    /// RPC: POST `/balance_by_pubkey`.
    BalanceByPubkey {
        /// Public key hex. Defaults to the configured signing key when omitted.
        #[arg(value_name = "pubkey")]
        pubkey: Option<String>,
        /// Signing keyfile or config file used when pubkey is omitted.
        #[arg(long, short = 'k', value_name = "KEYFILE")]
        from: Option<String>,
        /// Include compute escrow, staking, and token balances.
        #[arg(long, short = 'S')]
        full: bool,
    },
    /// Derive an account ID from a keyfile or public key.
    ///
    /// Uses SHA256("tlkd-account-id-v1" || pubkey).
    AccountId {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen` (stored as ~/.truthlinked/default.keys
/// and recorded in ~/.truthlinked/config.json).
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Public key hex.
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Import a signing key from a mnemonic phrase.
    ///
    /// Writes a TruthLinked keyfile.
    ImportMnemonic {
        /// BIP39 mnemonic phrase.
        #[arg(long)]
        mnemonic: String,
        /// Output keyfile.
        #[arg(long, default_value_t = default_keyfile_path())]
        output: String,
        /// Mnemonic and key-file passphrase.
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Create a signing key and mnemonic phrase.
    ///
    /// Writes a TruthLinked keyfile and prints a backup mnemonic.
    #[command(visible_alias = "keygen")]
    AccountCreate {
        /// Output keyfile.
        #[arg(long, default_value_t = default_keyfile_path())]
        output: String,
        /// Encrypt the keyfile.
        #[arg(long)]
        encrypt: bool,
        /// Mnemonic and key-file passphrase.
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Claim testnet faucet funds.
    ///
    /// Submits a signed faucet request with a 15,000 TLKD testnet limit.
    Faucet {
        /// Signing keyfile or config file (defaults to ./axiom/config, config, or ~/.truthlinked/default.keys).
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Amount in TLKD units, or raw base units with the configured xiom suffix.
        #[arg(long, default_value = "15000")]
        amount: String,
    },
    /// Generate a genesis validator entry.
    ///
    /// Prints the validator account, public key, and allocation.
    GenesisValidator {
        /// Keyfile or config to sign with (validator).
/// Defaults to the key created with `axiom keygen` (see `axiom keygen --help`).
/// Use --from only to override.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Allocation in TLKD units, or raw base units with the configured xiom suffix.
        #[arg(long)]
        allocation: String,
    },
    /// Manage MCP agents, tools, and policy state.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Propose a treasury spend.
    ///
    /// Signs and submits a treasury proposal transaction.
    TreasuryProposeSpend {
        /// Proposer keyfile.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Recipient account ID.
        #[arg(long)]
        recipient: String,
        /// Amount in TLKD units, or raw base units with the configured xiom suffix.
        #[arg(long)]
        amount: String,
        /// Timelock in blocks
        #[arg(long)]
        timelock_blocks: u64,
        /// Proposal ID. Generates a proposal ID when omitted.
        #[arg(long)]
        proposal_id: Option<String>,
    },
    /// Vote on a treasury spend proposal.
    ///
    /// Signs and submits a treasury vote transaction.
    TreasuryVoteSpend {
        /// Voter keyfile.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Proposal ID.
        #[arg(long)]
        proposal_id: String,
        /// Approve the proposal.
        #[arg(long)]
        approve: bool,
    },
    /// Execute a treasury spend proposal.
    ///
    /// Signs and submits a treasury execution transaction.
    TreasuryExecuteSpend {
        /// Executor keyfile.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Proposal ID.
        #[arg(long)]
        proposal_id: String,
    },
    /// Show treasury proposal details.
    ///
    /// RPC: GET `/treasury/proposal/{id}`.
    TreasuryProposalInfo {
        /// Proposal ID.
        #[arg(long)]
        proposal_id: String,
    },
    /// Send value (native tokens or NFTs).
    ///
    /// The easiest and most important command for moving anything of value.
    /// Use `axiom send --help` to see all the ways to send.
    ///
    /// Native example:  axiom send alice.tl 100
    /// NFT example:     axiom send nft deadbeef... alice.tl
    ///
    /// Deposit the native token into compute escrow.
    ///
    /// Signs and submits a compute escrow deposit.
    DepositCompute {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Amount in TLKD units, or raw base units with the configured xiom suffix.
        #[arg(long)]
        amount: String,
    },
    /// Withdraw the native token from compute escrow.
    ///
    /// Signs and submits a compute escrow withdrawal.
    WithdrawCompute {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Amount in TLKD units, or raw base units with the configured xiom suffix.
        #[arg(long)]
        amount: String,
    },
    /// Batch transfer to multiple recipients (comma-separated pubkeys and amounts).
    ///
    /// Signs and submits a `BatchTransfer` transaction.
    BatchTransfer {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Comma-separated recipient pubkeys (hex)
        #[arg(long)]
        to_pubkeys: String,
        /// Comma-separated TLKD amounts
        #[arg(long)]
        amounts: String,
    },
    /// Setup validator (register + bond in one command).
    ///
    /// Signs and submits a `Stake` transaction.
    ValidatorSetup {
        /// Keyfile or config to sign with (validator).
/// Defaults to the key created with `axiom keygen` (see `axiom keygen --help`).
/// Use --from only to override.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Amount in TLKD units, or raw base units with the configured xiom suffix.
        #[arg(long)]
        amount: String,
    },
    /// Bond stake.
    ///
    /// Signs and submits a `Stake` transaction.
    /// Positional amount form: `bond <amount> [--from <keyfile>]`.
    Bond {
        /// Amount in TLKD units, or raw base units with the configured xiom suffix.
        #[arg(value_name = "amount")]
        amount: String,
        /// Keyfile or config to sign with (validator).
/// Defaults to the key created with `axiom keygen` (see `axiom keygen --help`).
/// Use --from only to override.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
    },
    /// Alias for bond: `stake <amount>`.
    Stake {
        /// Amount in TLKD units.
        #[arg(value_name = "amount")]
        amount: Option<String>,
        /// Keyfile or config to sign with (validator).
/// Defaults to the key created with `axiom keygen` (see `axiom keygen --help`).
/// Use --from only to override.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
    },
    /// Unbond stake (starts unbonding period).
    ///
    /// Signs and submits a `Unstake` transaction.
    Unbond {
        /// Keyfile or config to sign with (validator).
/// Defaults to the key created with `axiom keygen` (see `axiom keygen --help`).
/// Use --from only to override.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Amount to unstake, in TLKD units or raw base units.
        #[arg(long)]
        amount: String,
    },
    /// Withdraw unbonded stake.
    ///
    /// Signs and submits a `WithdrawStake` transaction.
    Withdraw {
        /// Keyfile or config to sign with (validator).
/// Defaults to the key created with `axiom keygen` (see `axiom keygen --help`).
/// Use --from only to override.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
    },
    /// Unjail validator.
    ///
    /// Signs and submits a `Unjail` transaction.
    Unjail {
        /// Keyfile or config to sign with (validator).
/// Defaults to the key created with `axiom keygen` (see `axiom keygen --help`).
/// Use --from only to override.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
    },
    /// Add a staking delegate (allows delegate to act on a validator).
    DelegateAdd {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Delegate public key
        #[arg(long)]
        delegate_pubkey: String,
    },
    /// Remove a staking delegate
    DelegateRemove {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Delegate public key
        #[arg(long)]
        delegate_pubkey: String,
    },
    /// Stake on behalf of a validator (delegate only)
    StakeFor {
        /// Delegate keyfile
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Validator owner public key
        #[arg(long)]
        owner_pubkey: String,
        /// Amount in TLKD units, or raw base units with the configured xiom suffix.
        #[arg(long)]
        amount: String,
    },
    /// Unstake on behalf of a validator (delegate only).
    ///
    /// Signs and submits a `Unstake` transaction.
    UnstakeFor {
        /// Delegate keyfile
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Validator owner public key
        #[arg(long)]
        owner_pubkey: String,
        /// Amount in TLKD units, or raw base units with the configured xiom suffix.
        #[arg(long)]
        amount: String,
    },
    /// Withdraw on behalf of a validator (delegate only).
    ///
    /// Signs and submits a `WithdrawStake` transaction.
    WithdrawFor {
        /// Delegate keyfile
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Validator owner public key
        #[arg(long)]
        owner_pubkey: String,
    },
    /// Unjail on behalf of a validator (delegate only).
    ///
    /// Signs and submits a `Unjail` transaction.
    UnjailFor {
        /// Delegate keyfile
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Validator owner public key
        #[arg(long)]
        owner_pubkey: String,
    },
    /// Lock the native token into staking.
    ///
    /// Signs and submits a staking system call.
    #[command(name = "staked-tlkd-lock")]
    StakedTlkdLock {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Amount to lock, in TLKD units or raw base units.
        #[arg(long)]
        amount: String,
        /// Lock duration in blocks
        #[arg(long)]
        lock_blocks: u64,
    },
    /// Extend an existing staking lock.
    ///
    /// Signs and submits a staking system call.
    #[command(name = "staked-tlkd-extend")]
    StakedTlkdExtend {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// New lock duration in blocks (from now)
        #[arg(long)]
        lock_blocks: u64,
    },
    /// Unlock matured staking position.
    ///
    /// Signs and submits a staking system call.
    #[command(name = "staked-tlkd-unlock")]
    StakedTlkdUnlock {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
    },
    /// Work with NFTs (mint, send/transfer, burn, approve, inspect).
    ///
    /// Sending NFTs is also available the intuitive way via `axiom send nft ...`.
    /// This group makes all NFT operations discoverable together.
    ///
    /// Deploy an Axiom cell.
    ///
    /// Signs and submits a `DeployCell` transaction.
    DeployCell {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        bytecode_file: Option<String>,
        #[arg(long, default_value = "0")]
        initial_balance: u64,
        #[arg(long)]
        manifest_file: Option<String>,
    },
    /// Alias for deploy-cell: `deploy <cell_id> <source>`.
    Deploy {
        #[arg(value_name = "cell_id")]
        cell_id: Option<String>,
        #[arg(value_name = "source")]
        source: Option<String>,
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
    },
    /// Deploy a token cell.
    ///
    /// Signs and submits a `DeployToken` transaction.
    DeployToken {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        symbol: String,
        #[arg(long)]
        decimals: u8,
        #[arg(long)]
        supply: u128,
    },
    /// Call a cell with calldata (optionally simulate only).
    ///
    /// `--simulate` runs the call through the RPC simulation endpoint.
    /// Without `--simulate`, signs and submits a cell call.
    CallCell {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        calldata: String,
        #[arg(long, default_value = "0")]
        value: u64,
        #[arg(long, default_value = "1000000")]
        gas_limit: u64,
        /// Run simulation
        #[arg(long, alias = "dry-run")]
        simulate: bool,
    },
    /// Upgrade cell (auto-builds from source if provided).
    ///
    /// Signs and submits an `UpgradeCell` transaction.
    UpgradeCell {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        bytecode_file: Option<String>,
        #[arg(long)]
        manifest_file: Option<String>,
    },
    /// Rotate account key.
    ///
    /// Signs and submits a `RotateKey` transaction.
    RotateKey {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        new_pubkey: String,
    },
    /// Accept cell ownership.
    ///
    /// Signs and submits an `AcceptOwnership` transaction.
    AcceptOwnership {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
    },
    /// Make cell immutable.
    ///
    /// Signs and submits a `MakeImmutable` transaction.
    MakeImmutable {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
    },
    /// Close cell and reclaim rent deposit.
    ///
    /// Signs and submits a `CloseCell` transaction.
    CloseCell {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
    },
    /// Propose upgrade for a system-owned cell (validators only).
    ///
    /// Signs and submits a proposal transaction.
    ProposeCellUpgrade {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        bytecode_file: Option<String>,
        #[arg(long)]
        manifest_file: Option<String>,
        #[arg(long, default_value = "7200")]
        timelock_blocks: u64,
    },
    /// Propose ownership transfer for a system-owned cell (validators only).
    ///
    /// Signs and submits a proposal transaction.
    ProposeCellOwnershipTransfer {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        new_owner: String,
        #[arg(long, default_value = "7200")]
        timelock_blocks: u64,
    },
    /// Propose making a system-owned cell immutable (validators only).
    ///
    /// Signs and submits a proposal transaction.
    ProposeCellMakeImmutable {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        #[arg(long, default_value = "7200")]
        timelock_blocks: u64,
    },
    /// Vote on an active cell proposal (validators only).
    ///
    /// Signs and submits a vote transaction.
    VoteCellProposal {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        approve: bool,
    },
    /// Execute a matured cell proposal (validators only).
    ///
    /// Signs and submits an execution transaction.
    ExecuteCellProposal {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
    },
    /// Token transfer (hidden for backward compat; use `axiom send token` instead).
    #[command(hide = true)]
    TokenTransfer {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        token: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },
    /// Token mint (hidden for backward compat).
    #[command(hide = true)]
    TokenMint {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        token: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },
    /// Token burn (hidden for backward compat).
    #[command(hide = true)]
    TokenBurn {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        token: String,
        #[arg(long)]
        amount: u128,
    },
    /// Propose token authority update (validators only).
    ///
    /// Signs and submits a proposal transaction.
    ProposeTokenAuthority {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        token: String,
        /// New mint authority account (hex)
        #[arg(long)]
        mint_authority: Option<String>,
        /// Clear mint authority (set to none)
        #[arg(long)]
        clear_mint_authority: bool,
        /// New freeze authority account (hex)
        #[arg(long)]
        freeze_authority: Option<String>,
        /// Clear freeze authority (set to none)
        #[arg(long)]
        clear_freeze_authority: bool,
        #[arg(long, default_value = "7200")]
        voting_period_blocks: u64,
    },
    /// Vote on token authority proposal (validators only).
    ///
    /// Signs and submits a vote transaction.
    VoteTokenAuthority {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        token: String,
        #[arg(long)]
        approve: bool,
    },
    /// Call cell chain (composability).
    ///
    /// `--simulate` runs the chain through the RPC simulation endpoint.
    /// Without `--simulate`, signs and submits a cell chain call.
    CallChain {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        calls: String,
        #[arg(long, default_value = "5000000")]
        gas_limit: u64,
        /// Run simulation
        #[arg(long, alias = "dry-run")]
        simulate: bool,
    },
    /// Propose cell name.
    ///
    /// Signs and submits a name registry transaction.
    ProposeName {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        owner: String,
    },
    /// Vote on name proposal.
    ///
    /// Signs and submits a name registry transaction.
    VoteName {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        approve: bool,
    },
    /// Renew name registration.
    ///
    /// Signs and submits a name registry transaction.
    RenewName {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        name: String,
    },
    /// Transfer name ownership.
    ///
    /// Signs and submits a name registry transaction.
    TransferName {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        new_owner: String,
    },
    /// Propose a bonded URL pattern for public HTTP oracle access.
    ///
    /// Submits a first-class URL governance transaction via `POST /submit_raw`.
    ProposeUrl {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long = "url-pattern")]
        url_pattern: String,
        /// Bond amount in TLKD units or raw base units.
        #[arg(long)]
        bond: String,
        #[arg(long, default_value = "7200")]
        voting_period_blocks: u64,
    },
    /// Validator vote on a URL proposal.
    ///
    /// Submits a first-class URL vote transaction via `POST /submit_raw`.
    VoteUrl {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long = "url-pattern")]
        url_pattern: String,
        #[arg(long)]
        approve: bool,
    },
    /// Report an approved URL as malicious (70% proposer bond slash).
    ///
    /// Submits a first-class URL report transaction via `POST /submit_raw`.
    ReportMaliciousUrl {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long = "url-pattern")]
        url_pattern: String,
        #[arg(long, default_value = "malicious behavior")]
        evidence: String,
    },
    /// Upgrade cell visibility tier (private/public).
    ///
    /// Signs and submits a cell visibility update.
    UpgradeVisibility {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        /// Visibility flag: true public, false private
        #[arg(long, default_value_t = true)]
        public: bool,
    },
    /// Build a cell and generate its manifest.
    ///
    /// Produces `.axiom` bytecode and a `.manifest.json` file.
    Build {
        #[arg(long)]
        source: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// Create a new Rust cell project from SDK template.
    ///
    /// Extracts embedded template files.
    SDKNew {
        #[arg(long)]
        path: String,
    },
    /// Build an SDK cell project.
    ///
    /// Produces `.axiom` bytecode and an auto-generated manifest.
    SDKBuild {
        #[arg(long)]
        path: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// Deploy an SDK cell project.
    ///
    /// Signs and submits a `DeployCell` transaction.
    SDKDeploy {
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        bytecode_file: Option<String>,
        #[arg(long, default_value = "0")]
        initial_balance: u64,
        #[arg(long)]
        manifest_file: Option<String>,
        #[arg(long, default_value_t = false)]
        skip_build: bool,
    },
    /// Initialize `manifest.json` for an Axiom bytecode file.
    ///
    /// Writes a scaffold manifest and embeds it in the bytecode.
    ManifestInit {
        #[arg(long)]
        bytecode_file: String,
    },
    /// Verify a manifest against bytecode before submission.
    ///
    /// Verifies declared slots match bytecode usage.
    ManifestVerify {
        #[arg(long)]
        bytecode_file: String,
        #[arg(long)]
        manifest_file: String,
    },
    /// Compute manifest hash.
    ///
    /// Produces a deterministic hash of the manifest.
    ManifestHash {
        #[arg(long)]
        bytecode_file: String,
        #[arg(long)]
        manifest_file: String,
    },

    // Advanced/validator commands are defined toward the end so they appear later in `axiom --help`.

    /// Generate validator keys + the genesis snippet the network needs.
    ///
    /// Run this once after (or instead of) normal `axiom keygen`.
    /// It produces a key file you can feed to the node binary and the JSON
    /// fragment for genesis_validator.json.
    ///
    /// This lets you do full validator setup from the same CLI (geth-style).
    ValidatorInit {
        /// Path for the validator key file (pass this to the node with --validator-keys).
        #[arg(long, default_value = "~/.truthlinked/validator.keys.json")]
        output: String,

        /// Allocation to suggest for the genesis entry.
        #[arg(long, default_value = "1000000")]
        allocation: String,
    },
}

#[derive(Subcommand)]
enum McpCommand {
    /// Register an MCP agent policy binding.
    RegisterAgent {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Agent keyfile (must be key_type=agent)
        #[arg(long)]
        agent_keyfile: String,
        /// Policy cell ID (32-byte hex)
        #[arg(long)]
        policy_cell_id: String,
        /// Agent registry cell ID (defaults to protocol address)
        #[arg(long)]
        agent_registry_id: Option<String>,
    },
    /// Register an MCP tool through protocol governance.
    RegisterTool {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Tool ID (32-byte hex)
        #[arg(long)]
        tool_id: String,
        /// Tool name
        #[arg(long)]
        name: String,
        /// Category (u8)
        #[arg(long, default_value = "0")]
        category: u8,
        /// Axiom bytecode file
        #[arg(long)]
        bytecode_file: String,
        /// Manifest file (`manifest.json` or `manifest.auto.json`)
        #[arg(long)]
        manifest_file: String,
        /// Input schema JSON file
        #[arg(long)]
        schema_file: String,
        /// MCP registry ID (defaults to protocol address)
        #[arg(long)]
        registry_id: Option<String>,
    },
    /// Register an MCP resource.
    RegisterResource {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Resource ID (32-byte hex)
        #[arg(long)]
        resource_id: String,
        /// Resource name
        #[arg(long)]
        name: String,
        /// URI scheme (e.g. https)
        #[arg(long)]
        uri_scheme: String,
        /// MIME type (e.g. application/json)
        #[arg(long)]
        mime_type: String,
        /// Axiom bytecode file for dynamic resources
        #[arg(long)]
        bytecode_file: Option<String>,
        /// Manifest file for dynamic resources
        #[arg(long)]
        manifest_file: Option<String>,
        /// Initial data JSON file (array of {key_hex,value_hex})
        #[arg(long)]
        initial_data_json: Option<String>,
        /// MCP registry ID (defaults to protocol address)
        #[arg(long)]
        registry_id: Option<String>,
    },
    /// Register an MCP prompt.
    RegisterPrompt {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Prompt ID (32-byte hex)
        #[arg(long)]
        prompt_id: String,
        /// Prompt name
        #[arg(long)]
        name: String,
        /// Template file (bytes)
        #[arg(long)]
        template_file: String,
        /// Prompt argument definition: name:description:required
        #[arg(long)]
        arg: Vec<String>,
        /// MCP registry ID (defaults to protocol address)
        #[arg(long)]
        registry_id: Option<String>,
    },
    /// Update policy limits.
    SetPolicy {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Policy cell ID (32-byte hex)
        #[arg(long)]
        policy_cell_id: String,
        /// Policy status: 0 active, 1 suspended
        #[arg(long, default_value = "0")]
        status: u8,
        /// Read permission: 0 disabled, 1 enabled
        #[arg(long, default_value = "1")]
        allow_reads: u8,
        /// Write permission: 0 disabled, 1 enabled
        #[arg(long, default_value = "1")]
        allow_writes: u8,
        /// Admin permission: 0 disabled, 1 enabled
        #[arg(long, default_value = "0")]
        allow_admin: u8,
        /// Rate limit per minute
        #[arg(long, default_value = "0")]
        rate_limit: u32,
        /// Spend per tx (u128)
        #[arg(long, default_value = "0")]
        spend_per_tx: u128,
        /// Spend per epoch (u128)
        #[arg(long, default_value = "0")]
        spend_epoch: u128,
        /// HITL threshold (u128)
        #[arg(long, default_value = "0")]
        hitl_threshold: u128,
    },
    /// Set per-tool permission in policy cell.
    SetToolPermission {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Policy cell ID (32-byte hex)
        #[arg(long)]
        policy_cell_id: String,
        /// Tool ID (32-byte hex)
        #[arg(long)]
        tool_id: String,
        /// Permission status: 0 disabled, 1 enabled
        #[arg(long)]
        enabled: u8,
    },
    /// Initialize an agent private-balance cell.
    PrivateBalanceInit {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Agent account ID (32-byte hex)
        #[arg(long)]
        agent_id: String,
        /// Private-balance cell ID (defaults to canonical cell for agent)
        #[arg(long)]
        cell_id: Option<String>,
        /// Initial private balance
        #[arg(long, default_value = "0")]
        balance: String,
        /// Secret seed used to derive the AES-256-GCM key
        #[arg(long)]
        aes_seed_hex: String,
        /// 12-byte AES-GCM nonce for this state
        #[arg(long)]
        enc_nonce_hex: String,
        /// 16-byte commitment nonce for this state
        #[arg(long)]
        commit_nonce_hex: String,
    },
    /// Deposit public native token into an agent private-balance cell.
    PrivateBalanceDeposit {
        /// Keyfile or config to sign with.
/// Defaults to the key created with `axiom keygen`.
/// Use --from only when you want to override for this command.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Private-balance cell ID (32-byte hex)
        #[arg(long)]
        cell_id: String,
        /// Agent account ID (32-byte hex)
        #[arg(long)]
        agent_id: String,
        /// Public amount to deposit
        #[arg(long)]
        amount: String,
        /// New hidden balance after deposit
        #[arg(long)]
        new_balance: String,
        /// Previous commitment from the cell/output
        #[arg(long)]
        old_commitment: String,
        /// Secret seed used to derive the AES-256-GCM key
        #[arg(long)]
        aes_seed_hex: String,
        /// 12-byte AES-GCM nonce for the new state
        #[arg(long)]
        enc_nonce_hex: String,
        /// 16-byte commitment nonce for the new state
        #[arg(long)]
        commit_nonce_hex: String,
    },
    /// Withdraw from an agent private-balance cell to a public account.
    PrivateBalanceWithdraw {
        /// Agent or owner keyfile/config. Defaults to the configured signing account.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Private-balance cell ID (32-byte hex)
        #[arg(long)]
        cell_id: String,
        /// Agent account ID (32-byte hex)
        #[arg(long)]
        agent_id: String,
        /// Public amount to withdraw
        #[arg(long)]
        amount: String,
        /// Public recipient account ID (32-byte hex)
        #[arg(long)]
        recipient: String,
        /// New hidden balance after withdrawal
        #[arg(long)]
        new_balance: String,
        /// Previous commitment from the cell/output
        #[arg(long)]
        old_commitment: String,
        /// Secret seed used to derive the AES-256-GCM key
        #[arg(long)]
        aes_seed_hex: String,
        /// 12-byte AES-GCM nonce for the new state
        #[arg(long)]
        enc_nonce_hex: String,
        /// 16-byte commitment nonce for the new state
        #[arg(long)]
        commit_nonce_hex: String,
    },
    /// Submit a confidential private-balance transfer proof.
    PrivateBalanceConfidentialTransfer {
        /// Owner or agent keyfile authorized for the sender private-balance cell
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Sender private-balance cell ID (32-byte hex)
        #[arg(long)]
        sender_cell_id: String,
        /// Sender agent account ID (32-byte hex)
        #[arg(long)]
        sender_agent_id: String,
        /// Recipient private-balance cell ID (32-byte hex)
        #[arg(long)]
        recipient_cell_id: String,
        /// Rescue amount commitment (32-byte hex)
        #[arg(long)]
        amount_commitment: String,
        /// STARK proof bytes as hex. Use this or --proof-file.
        #[arg(long)]
        proof_hex: Option<String>,
        /// STARK proof file. Use this or --proof-hex.
        #[arg(long)]
        proof_file: Option<String>,
        /// Sender encrypted balance after transfer (44-byte hex)
        #[arg(long)]
        sender_new_encrypted: String,
        /// Sender Rescue commitment (32-byte hex)
        #[arg(long)]
        sender_new_commitment: String,
        /// Sender new commitment nonce (16-byte hex)
        #[arg(long)]
        sender_new_commit_nonce: String,
        /// Sender previous commitment (32-byte hex)
        #[arg(long)]
        sender_old_commitment: String,
        /// Recipient encrypted balance after transfer (44-byte hex)
        #[arg(long)]
        recipient_new_encrypted: String,
        /// Recipient Rescue commitment (32-byte hex)
        #[arg(long)]
        recipient_new_commitment: String,
        /// Recipient new commitment nonce (16-byte hex)
        #[arg(long)]
        recipient_new_commit_nonce: String,
        /// Recipient previous commitment (32-byte hex)
        #[arg(long)]
        recipient_old_commitment: String,
    },
    /// Call an MCP tool.
    ToolCall {
        /// Agent keyfile or config file. Defaults to the configured signing account.
        #[arg(long, short = 'f', value_name = "KEYFILE")]
        from: Option<String>,
        /// Tool ID (32-byte hex)
        #[arg(long)]
        tool_id: String,
        /// Policy cell ID (32-byte hex)
        #[arg(long)]
        policy_cell_id: String,
        /// Action log cell ID (defaults to protocol address)
        #[arg(long)]
        action_log_id: Option<String>,
        /// Calldata hex
        #[arg(long)]
        calldata_hex: Option<String>,
        /// Calldata file
        #[arg(long)]
        calldata_file: Option<String>,
        /// Value (u128)
        #[arg(long, default_value = "0")]
        value: u128,
        /// Gas limit
        #[arg(long, default_value = "500000")]
        gas_limit: u64,
    },
}

fn resolve_cargo_binary() -> String {
    if let Ok(path) = std::env::var("CARGO") {
        return path;
    }
    let root_cargo = std::path::Path::new("/root/.cargo/bin/cargo");
    if root_cargo.exists() {
        return root_cargo.to_string_lossy().to_string();
    }
    "cargo".to_string()
}

/// Build an Axiom cell and generate a manifest.
///
/// `.cell` sources are compiled with the native Axiom compiler. Rust SDK
/// sources are built through their Cargo project so scaffolded SDK cells work
/// with project-local metadata.
fn build_cell(
    source: &str,
    output: Option<&str>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    use std::process::Command;

    let source_path = std::path::Path::new(source);
    let default_stem = source_path.with_extension("").to_string_lossy().to_string();
    let stem = output.unwrap_or(default_stem.as_str());
    let output_axiom = stem.to_string() + ".axiom";
    let output_manifest = stem.to_string() + ".manifest.json";
    if let Some(parent) = std::path::Path::new(&output_axiom).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    if let Some(parent) = std::path::Path::new(&output_manifest).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    println!("✦ [1/2] Compiling Axiom Cell State: {} → {}", source, output_axiom);
    if source_path.extension().and_then(|ext| ext.to_str()) == Some("cell") {
        let compiled = truthlinked_axiom_compiler::compile_file(source_path)?;
        std::fs::write(&output_axiom, &compiled.bytecode)?;
        std::fs::write(
            &output_manifest,
            serde_json::to_string_pretty(&compiled.manifest)?,
        )?;
    } else {
        let project_root = source_path
            .parent()
            .and_then(|p| {
                if p.ends_with("src") {
                    p.parent()
                } else {
                    Some(p)
                }
            })
            .ok_or("Cannot determine project root")?;
        let manifest_path = project_root.join("Cargo.toml").canonicalize()?;
        let result = Command::new(resolve_cargo_binary())
            .args([
                "run",
                "--release",
                "--quiet",
                "--manifest-path",
                manifest_path.to_string_lossy().as_ref(),
            ])
            .current_dir(project_root)
            .output()?;

        if !result.status.success() {
            eprintln!(
                " Build failed:\n{}",
                String::from_utf8_lossy(&result.stderr)
            );
            return Err("SDK build failed".into());
        }

        let produced = project_root.join("cell.axiom");
        if !produced.exists() {
            return Err(format!(
                "Build succeeded but {} was not produced",
                produced.display()
            )
            .into());
        }
        std::fs::copy(&produced, &output_axiom)?;
    }

    println!("✦ [2/2] Cell compilation completed successfully.");
    let bytecode = std::fs::read(&output_axiom)?;
    let analysis = truthlinked_core::cells::CellAccount::analyze_bytecode(&bytecode)
        .unwrap_or_else(|_| truthlinked_core::cells::ManifestAnalysis {
            static_read_slots: vec![],
            static_write_slots: vec![],
            has_storage_reads: false,
            has_storage_writes: false,
            fully_resolved: false,
        });

    let manifest = serde_json::json!({
        "declared_reads":      analysis.static_read_slots.iter().map(hex::encode).collect::<Vec<_>>(),
        "declared_writes":     analysis.static_write_slots.iter().map(hex::encode).collect::<Vec<_>>(),
        "commutative_keys":    [],
        "storage_key_specs":   [],
    });

    std::fs::write(&output_manifest, serde_json::to_string_pretty(&manifest)?)?;
    println!("⚙ Manifest Artifact Exported: {}", output_manifest);
    if !analysis.fully_resolved {
        println!("▲ Security Context: Dynamic storage keys identified. Cross-reference declared_reads/writes.");
    }

    Ok((output_axiom, output_manifest))
}
/// Fetch account information and require an account record.
///
/// RPC: GET `/account/{account_id}`
/// Returns account balance and cell status.
fn require_account_exists(
    client: &reqwest::blocking::Client,
    rpc: &str,
    account_id: &str,
) -> Result<RpcAccountInfo, Box<dyn std::error::Error>> {
    let info: RpcAccountInfo = client
        .get(format!("{}/account/{}", rpc, account_id))
        .send()?
        .json()?;
    if !info.found {
        return Err(format!("account {} not found", account_id).into());
    }
    Ok(info)
}

/// Fetch cell information and require a cell record.
///
/// RPC: GET `/cell/{cell_id}`
/// Returns token and immutability status.
fn require_cell_exists(
    client: &reqwest::blocking::Client,
    rpc: &str,
    cell_id: &str,
    retries: u32,
) -> Result<RpcCellInfo, Box<dyn std::error::Error>> {
    let info_val = get_json(client, &format!("{}/cell/{}", rpc, cell_id), retries)?;
    let info: RpcCellInfo = serde_json::from_value(info_val)?;
    if !info.found {
        return Err(format!("cell {} not found", cell_id).into());
    }
    Ok(info)
}

/// Fetch cell info and ensure it is a token cell.
/// Used by token mint/burn/transfer commands.
fn require_token_cell(
    client: &reqwest::blocking::Client,
    rpc: &str,
    token_id: &str,
    retries: u32,
) -> Result<RpcCellInfo, Box<dyn std::error::Error>> {
    let info = require_cell_exists(client, rpc, token_id, retries)?;
    if !info.is_token {
        return Err(format!("cell {} is not a token", token_id).into());
    }
    Ok(info)
}

/// Fetch the chain's genesis hash (used as `genesis_fingerprint` in tx signing).
///
/// RPC: GET `/chain_info`
/// Returns the active genesis hash.
fn fetch_genesis_hash(
    client: &reqwest::blocking::Client,
    rpc: &str,
    retries: u32,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let chain_info = get_json(client, &format!("{}/chain_info", rpc), retries)?;
    let genesis_hash_hex = chain_info["genesis_hash"]
        .as_str()
        .ok_or("No genesis hash")?;
    let mut genesis_hash = [0u8; 32];
    hex::decode_to_slice(genesis_hash_hex, &mut genesis_hash)?;
    Ok(genesis_hash)
}

fn fetch_account_nonce(
    client: &reqwest::blocking::Client,
    rpc: &str,
    account_id: &[u8; 32],
    retries: u32,
) -> Result<u64, String> {
    let res = get_json(
        client,
        &format!("{}/account/{}", rpc, hex::encode(account_id)),
        retries,
    )
    .map_err(|e| format!("Failed to fetch account nonce: {e}"))?;
    Ok(res.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0))
}

fn nonce_queue_dir() -> Result<std::path::PathBuf, String> {
    let base = dirs::home_dir()
        .ok_or_else(|| "Unable to locate home directory for nonce queue".to_string())?
        .join(".truthlinked")
        .join("nonce-queue");
    std::fs::create_dir_all(&base)
        .map_err(|e| format!("Failed to create nonce queue directory: {e}"))?;
    Ok(base)
}

fn nonce_queue_key(rpc: &str, account_id: &[u8; 32]) -> String {
    let mut input = Vec::with_capacity(rpc.len() + account_id.len() + 1);
    input.extend_from_slice(rpc.trim_end_matches('/').as_bytes());
    input.push(b':');
    input.extend_from_slice(account_id);
    blake3::hash(&input).to_hex()[..32].to_string()
}

struct NonceQueueLock {
    path: std::path::PathBuf,
}

impl Drop for NonceQueueLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn acquire_nonce_queue_lock(path: std::path::PathBuf) -> Result<NonceQueueLock, String> {
    let stale_after = Duration::from_secs(120);
    let start = std::time::Instant::now();
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                let _ = writeln!(file, "{}", std::process::id());
                return Ok(NonceQueueLock { path });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .map(|age| age > stale_after)
                    .unwrap_or(false);
                if stale {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if start.elapsed() > Duration::from_secs(20) {
                    return Err(format!(
                        "Timed out waiting for nonce queue lock {}",
                        path.display()
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(err) => return Err(format!("Failed to acquire nonce queue lock: {err}")),
        }
    }
}

fn read_queued_next_nonce(path: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

fn write_queued_next_nonce(path: &std::path::Path, next_nonce: u64) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(
        &tmp,
        format!(
            "{}
",
            next_nonce
        ),
    )
    .map_err(|e| format!("Failed to write nonce queue: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("Failed to commit nonce queue: {e}"))
}

fn set_nonce_queue_next(rpc: &str, account_id: &[u8; 32], next_nonce: u64) -> Result<(), String> {
    let dir = nonce_queue_dir()?;
    let key = nonce_queue_key(rpc, account_id);
    let path = dir.join(format!("{}.next", key));
    let _lock = acquire_nonce_queue_lock(dir.join(format!("{}.lock", key)))?;
    write_queued_next_nonce(&path, next_nonce)
}

fn nonce_queue_wait_timeout() -> Duration {
    std::env::var("AXIOM_NONCE_QUEUE_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(120))
}

fn set_nonce_queue_last_tx(
    rpc: &str,
    account_id: &[u8; 32],
    tx_hash: &str,
    nonce: u64,
) -> Result<(), String> {
    let dir = nonce_queue_dir()?;
    let key = nonce_queue_key(rpc, account_id);
    let path = dir.join(format!("{}.last", key));
    let _lock = acquire_nonce_queue_lock(dir.join(format!("{}.lock", key)))?;
    std::fs::write(
        &path,
        format!(
            "{}	{}
",
            tx_hash.trim(),
            nonce
        ),
    )
    .map_err(|e| format!("Failed to write nonce queue last tx: {e}"))
}

fn read_nonce_queue_last_tx(path: &std::path::Path) -> Option<(String, Option<u64>)> {
    let raw = std::fs::read_to_string(path).ok()?;
    let mut parts = raw.trim().split_whitespace();
    let hash = parts.next()?.to_string();
    if hash.is_empty() {
        return None;
    }
    let nonce = parts.next().and_then(|v| v.parse::<u64>().ok());
    Some((hash, nonce))
}

fn wait_for_previous_nonce_tx(
    client: &reqwest::blocking::Client,
    rpc: &str,
    account_id: &[u8; 32],
    retries: u32,
    last_path: &std::path::Path,
) -> Result<(), String> {
    let Some((hash, nonce)) = read_nonce_queue_last_tx(last_path) else {
        return Ok(());
    };
    let wait_timeout = nonce_queue_wait_timeout();
    let wait_start = std::time::Instant::now();
    loop {
        let status = get_json(client, &format!("{}/tx/{}", rpc, hash), retries)
            .ok()
            .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(str::to_string));
        match status.as_deref() {
            Some("rejected") => {
                let _ = std::fs::remove_file(last_path);
                return Ok(());
            }
            Some("confirmed") => {
                if let Some(nonce) = nonce {
                    let chain_nonce = fetch_account_nonce(client, rpc, account_id, retries)?;
                    if chain_nonce >= nonce {
                        let _ = std::fs::remove_file(last_path);
                        return Ok(());
                    }
                } else {
                    let _ = std::fs::remove_file(last_path);
                    return Ok(());
                }
            }
            _ => {}
        }
        if wait_start.elapsed() >= wait_timeout {
            return Err(format!(
                "Previous transaction {} did not finalize and advance nonce within {}s; retry later or increase AXIOM_NONCE_QUEUE_WAIT_SECS",
                hash,
                wait_timeout.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn next_nonce(
    client: &reqwest::blocking::Client,
    rpc: &str,
    account_id: &[u8; 32],
    retries: u32,
) -> Result<u64, String> {
    let dir = nonce_queue_dir()?;
    let key = nonce_queue_key(rpc, account_id);
    let path = dir.join(format!("{}.next", key));
    let last_path = dir.join(format!("{}.last", key));
    let _lock = acquire_nonce_queue_lock(dir.join(format!("{}.lock", key)))?;
    wait_for_previous_nonce_tx(client, rpc, account_id, retries, &last_path)?;
    let wait_timeout = nonce_queue_wait_timeout();
    let wait_start = std::time::Instant::now();
    let mut chain_next = fetch_account_nonce(client, rpc, account_id, retries)?.saturating_add(1);
    let mut queued_next = read_queued_next_nonce(&path).unwrap_or(chain_next);

    if queued_next > chain_next && !last_path.exists() {
        write_queued_next_nonce(&path, chain_next)?;
        queued_next = chain_next;
    }

    if queued_next > chain_next {
        while wait_start.elapsed() < wait_timeout {
            std::thread::sleep(Duration::from_millis(250));
            chain_next = fetch_account_nonce(client, rpc, account_id, retries)?.saturating_add(1);
            if chain_next >= queued_next {
                break;
            }
        }
    }

    if queued_next > chain_next && wait_start.elapsed() >= wait_timeout {
        return Err(format!(
            "Nonce queue is waiting for committed nonce {} but chain is still at next nonce {}; retry later or increase AXIOM_NONCE_QUEUE_WAIT_SECS",
            queued_next, chain_next
        ));
    }
    let nonce = chain_next.max(queued_next);
    write_queued_next_nonce(&path, nonce.saturating_add(1))?;
    Ok(nonce)
}

/// Serialize a JSON value according to the CLI output mode.
fn json_string(value: &Value, output: OutputFormat) -> Result<String, Box<dyn std::error::Error>> {
    match output {
        OutputFormat::Pretty => Ok(serde_json::to_string_pretty(value)?),
        OutputFormat::Json => Ok(serde_json::to_string(value)?),
    }
}

fn print_human(value: &Value, indent: usize, output: OutputFormat) {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                println!("{}  (empty_slot_descriptor)", pad);
                return;
            }
            for (key, val) in map {
                match val {
                    Value::Object(_) | Value::Array(_) => {
                        println!("{}  Key Definition ➔ {}", pad, key);
                        print_human(val, indent + 2, output);
                    }
                    _ => {
                        println!("{}  Slot Value      ➔ {} ({})", pad, key, format_scalar(val, output));
                    }
                }
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                println!("{}  (empty_slot_descriptor)", pad);
                return;
            }
            for (idx, item) in items.iter().enumerate() {
                match item {
                    Value::Object(_) | Value::Array(_) => {
                        println!("{}  Matrix Index    ➔ {}", pad, idx);
                        print_human(item, indent + 2, output);
                    }
                    _ => {
                        println!("{}  Array Element   ➔ {} ({})", pad, idx, format_scalar(item, output));
                    }
                }
            }
        }
        _ => {
            println!("{}  Scalar Register ➔ {}", pad, format_scalar(value, output));
        }
    }
}

fn format_scalar(value: &Value, output: OutputFormat) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(v) => v.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            if matches!(output, OutputFormat::Pretty) {
                format_address(s)
            } else {
                s.to_string()
            }
        }
        _ => value.to_string(),
    }
}

fn format_address(value: &str) -> String {
    if !is_probably_hex(value) {
        return value.to_string();
    }
    if value.len() < 64 {
        return value.to_string();
    }
    let prefix_len = 16.min(value.len());
    let suffix_len = 8.min(value.len().saturating_sub(prefix_len));
    let prefix = &value[..prefix_len];
    let suffix = &value[value.len() - suffix_len..];
    format!("{}...{}", prefix, suffix)
}

fn is_probably_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
}

fn print_output(value: &Value, output: OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    match output {
        OutputFormat::Json => {
            println!("{}", json_string(value, output)?);
        }
        OutputFormat::Pretty => {
            print_human(value, 0, output);
        }
    }
    Ok(())
}

fn print_balance_pretty(
    balance: &Value,
    tokens: Option<&Value>,
    full: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let balance_tlkd = balance
        .get("balance_tlkd")
        .and_then(|v| v.as_str())
        .unwrap_or("0 TLKD");
    if !full {
        println!("{} TLKD", balance_tlkd);
        return Ok(());
    }

    let account_id = balance
        .get("account_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let compute_escrow = balance
        .get("compute_escrow_tlkd_formatted")
        .and_then(|v| v.as_str())
        .or_else(|| balance.get("compute_escrow_tlkd").and_then(|v| v.as_str()))
        .unwrap_or("0");
    let staking_balance = balance
        .get("staking_balance_tlkd")
        .and_then(|v| v.as_str())
        .unwrap_or("0 TLKD");

    if !account_id.is_empty() {
        println!("Identity Address: 0x{}", format_address(account_id));
    }
    println!("Liquid Balance:   {} TLKD", balance_tlkd);
    println!("Compute Escrow:   {} TLKD", compute_escrow);
    println!("Staking Allocation: {} TLKD", staking_balance);

    match tokens
        .and_then(|v| v.get("balances"))
        .and_then(|v| v.as_array())
    {
        Some(list) if !list.is_empty() => {
            println!("── Registered Asset Balances:");
            for entry in list {
                let cell_id = entry.get("cell_id").and_then(|v| v.as_str()).unwrap_or("");
                let amount = entry.get("balance").and_then(|v| v.as_str()).unwrap_or("0");
                let formatted = entry.get("balance_formatted").and_then(|v| v.as_str());
                if let Some(token) = entry.get("token") {
                    let name = token
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown");
                    let symbol = token.get("symbol").and_then(|v| v.as_str()).unwrap_or("");
                    if let Some(pretty) = formatted {
                        println!(
                            "{}  {} ({})  {}",
                            format_address(cell_id),
                            name,
                            symbol,
                            pretty
                        );
                    } else {
                        println!(
                            "{}  {} ({})  {}",
                            format_address(cell_id),
                            name,
                            symbol,
                            amount
                        );
                    }
                } else if let Some(pretty) = formatted {
                    println!("{}  {}", format_address(cell_id), pretty);
                } else {
                    println!("{}  {}", format_address(cell_id), amount);
                }
            }
        }
        _ => {
            println!("── Registered Asset Balances: None discovered.");
        }
    }

    Ok(())
}

/// Recursively write an embedded template directory to disk.
fn write_embedded_dir(
    dir: &Dir,
    target: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    for subdir in dir.dirs() {
        write_embedded_dir(subdir, target)?;
    }
    for file in dir.files() {
        let mut relative_path = file.path().to_path_buf();
        if relative_path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml.tmpl") {
            relative_path.set_file_name("Cargo.toml");
        }
        let out_path = target.join(relative_path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&out_path, file.contents())?;
    }
    Ok(())
}

/// Parse a `CallChain` JSON payload into a typed list of cell calls.
/// Performs structural validation and size limits before submission.
fn parse_call_chain_json(
    calls: &str,
) -> Result<Vec<pq_execution::CellCall>, Box<dyn std::error::Error>> {
    let value: Value = serde_json::from_str(calls)?;
    let calls_arr = value.as_array().ok_or("call-chain JSON must be an array")?;
    if calls_arr.len() > constants::MAX_CALL_CHAIN_CALLS {
        return Err(format!(
            "call-chain has {} calls, max allowed is {}",
            calls_arr.len(),
            constants::MAX_CALL_CHAIN_CALLS
        )
        .into());
    }

    let mut cell_calls = Vec::with_capacity(calls_arr.len());
    let allowed_fields: HashSet<&str> = ["cell", "calldata", "value", "use_result_from"]
        .into_iter()
        .collect();
    let mut total_calldata = 0usize;

    for (idx, call) in calls_arr.iter().enumerate() {
        let obj = call.as_object().ok_or("each call must be a JSON object")?;
        for key in obj.keys() {
            if !allowed_fields.contains(key.as_str()) {
                return Err(format!("call {} has unknown field '{}'", idx, key).into());
            }
        }

        let cell_hex = obj
            .get("cell")
            .and_then(|v| v.as_str())
            .ok_or("Missing cell")?;
        let cell_bytes = hex::decode(cell_hex)?;
        if cell_bytes.len() != 32 {
            return Err(format!(
                "cell must be 32 bytes (64 hex chars), got {}",
                cell_hex.len()
            )
            .into());
        }
        let mut cell_arr = [0u8; 32];
        cell_arr.copy_from_slice(&cell_bytes);

        let calldata_hex = obj
            .get("calldata")
            .and_then(|v| v.as_str())
            .ok_or("Missing calldata")?;
        let calldata = hex::decode(calldata_hex)?;
        if calldata.len() > constants::MAX_CALLDATA_SIZE {
            return Err(format!(
                "calldata too large: {} bytes (max: {})",
                calldata.len(),
                constants::MAX_CALLDATA_SIZE
            )
            .into());
        }
        total_calldata = total_calldata.saturating_add(calldata.len());
        if total_calldata > constants::MAX_CALL_CHAIN_TOTAL_CALLDATA {
            return Err(format!(
                "call-chain total calldata too large: {} bytes (max: {})",
                total_calldata,
                constants::MAX_CALL_CHAIN_TOTAL_CALLDATA
            )
            .into());
        }

        let value = match obj.get("value") {
            Some(v) => v.as_u64().ok_or("value must be a non-negative integer")? as u128,
            None => 0,
        };

        let use_result_from = match obj.get("use_result_from") {
            Some(v) => {
                let idx_val = v
                    .as_u64()
                    .ok_or("use_result_from must be a non-negative integer")?
                    as usize;
                if idx_val >= idx {
                    return Err(format!(
                        "use_result_from must reference a prior call ({} >= {})",
                        idx_val, idx
                    )
                    .into());
                }
                Some(idx_val)
            }
            None => None,
        };

        cell_calls.push(pq_execution::CellCall {
            cell_id: cell_arr,
            calldata,
            value,
            use_result_from,
        });
    }

    Ok(cell_calls)
}

const SYSTEM_CONTROLLER_GAS_LIMIT: u64 = 200_000;
const VALIDATOR_PUBKEY_LEN: usize = 1952;

/// Compute a 4-byte method selector from a function name.
/// Used by system cell call encoding.
fn selector_of(name: &str) -> [u8; 4] {
    let mut hash: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash.to_le_bytes()
}

/// Encode name registry `propose` calldata.
fn encode_name_registry_propose(
    name: &str,
    target: [u8; 32],
    owner: [u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > u8::MAX as usize {
        return Err("name too long (max 255 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 1 + name_bytes.len() + 64);
    calldata.extend_from_slice(&selector_of("propose_name"));
    calldata.push(name_bytes.len() as u8);
    calldata.extend_from_slice(name_bytes);
    calldata.extend_from_slice(&target);
    calldata.extend_from_slice(&owner);
    Ok(calldata)
}

/// Encode name registry `vote` calldata.
fn encode_name_registry_vote(
    name: &str,
    approve: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > u8::MAX as usize {
        return Err("name too long (max 255 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 1 + name_bytes.len() + 1);
    calldata.extend_from_slice(&selector_of("vote_name"));
    calldata.push(name_bytes.len() as u8);
    calldata.extend_from_slice(name_bytes);
    calldata.push(if approve { 1 } else { 0 });
    Ok(calldata)
}

/// Encode name registry `renew` calldata.
fn encode_name_registry_renew(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > u8::MAX as usize {
        return Err("name too long (max 255 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 1 + name_bytes.len());
    calldata.extend_from_slice(&selector_of("renew_name"));
    calldata.push(name_bytes.len() as u8);
    calldata.extend_from_slice(name_bytes);
    Ok(calldata)
}

/// Encode name registry `transfer` calldata.
fn encode_name_registry_transfer(
    name: &str,
    new_owner: [u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > u8::MAX as usize {
        return Err("name too long (max 255 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 1 + name_bytes.len() + 32);
    calldata.extend_from_slice(&selector_of("transfer_name"));
    calldata.push(name_bytes.len() as u8);
    calldata.extend_from_slice(name_bytes);
    calldata.extend_from_slice(&new_owner);
    Ok(calldata)
}

/// Encode token authority `propose` calldata.
fn encode_token_authority_propose(
    token_cell: [u8; 32],
    set_mint: bool,
    mint_authority: [u8; 32],
    set_freeze: bool,
    freeze_authority: [u8; 32],
    voting_period_blocks: u64,
) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 1 + 32 + 1 + 32 + 8);
    calldata.extend_from_slice(&selector_of("propose_authority"));
    calldata.extend_from_slice(&token_cell);
    calldata.push(if set_mint { 1 } else { 0 });
    calldata.extend_from_slice(&mint_authority);
    calldata.push(if set_freeze { 1 } else { 0 });
    calldata.extend_from_slice(&freeze_authority);
    calldata.extend_from_slice(&voting_period_blocks.to_le_bytes());
    calldata
}

/// Encode token authority `vote` calldata.
fn encode_token_authority_vote(token_cell: [u8; 32], approve: bool) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 1);
    calldata.extend_from_slice(&selector_of("vote_authority"));
    calldata.extend_from_slice(&token_cell);
    calldata.push(if approve { 1 } else { 0 });
    calldata
}

/// Encode staking `stake` calldata for the staking controller cell.
fn encode_staking_stake(pubkey: &[u8], amount: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + VALIDATOR_PUBKEY_LEN + 8);
    calldata.extend_from_slice(&selector_of("stake"));
    calldata.extend_from_slice(pubkey);
    calldata.extend_from_slice(&amount.to_le_bytes());
    Ok(calldata)
}

/// Encode staking `unstake` calldata for the staking controller cell.
fn encode_staking_unstake(
    pubkey: &[u8],
    amount: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + VALIDATOR_PUBKEY_LEN + 8);
    calldata.extend_from_slice(&selector_of("unstake"));
    calldata.extend_from_slice(pubkey);
    calldata.extend_from_slice(&amount.to_le_bytes());
    Ok(calldata)
}

/// Encode staking `withdraw` calldata for the staking controller cell.
fn encode_staking_withdraw(pubkey: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + VALIDATOR_PUBKEY_LEN);
    calldata.extend_from_slice(&selector_of("withdraw"));
    calldata.extend_from_slice(pubkey);
    Ok(calldata)
}

/// Encode staking `unjail` calldata for the staking controller cell.
fn encode_staking_unjail(pubkey: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + VALIDATOR_PUBKEY_LEN);
    calldata.extend_from_slice(&selector_of("unjail"));
    calldata.extend_from_slice(pubkey);
    Ok(calldata)
}

/// Encode staking `lock` calldata.
fn encode_staking_lock(owner: [u8; 32], lock_blocks: u64) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 8);
    calldata.extend_from_slice(&selector_of("lock"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(&lock_blocks.to_le_bytes());
    calldata
}

/// Encode staking `extend` calldata.
fn encode_staking_extend(owner: [u8; 32], lock_blocks: u64) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 8);
    calldata.extend_from_slice(&selector_of("extend"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(&lock_blocks.to_le_bytes());
    calldata
}

/// Encode staking `unlock` calldata.
fn encode_staking_unlock(owner: [u8; 32]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector_of("unlock"));
    calldata.extend_from_slice(&owner);
    calldata
}

/// Encode treasury `propose` calldata.
fn encode_treasury_propose(
    proposal_id: [u8; 32],
    recipient: [u8; 32],
    amount: u128,
    timelock_blocks: u64,
) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 32 + 16 + 8);
    calldata.extend_from_slice(&selector_of("propose_spend"));
    calldata.extend_from_slice(&proposal_id);
    calldata.extend_from_slice(&recipient);
    calldata.extend_from_slice(&amount.to_le_bytes());
    calldata.extend_from_slice(&timelock_blocks.to_le_bytes());
    calldata
}

/// Encode treasury `vote` calldata.
fn encode_treasury_vote(proposal_id: [u8; 32], approve: bool) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 1);
    calldata.extend_from_slice(&selector_of("vote_spend"));
    calldata.extend_from_slice(&proposal_id);
    calldata.push(if approve { 1 } else { 0 });
    calldata
}

/// Encode treasury `execute` calldata.
fn encode_treasury_execute(proposal_id: [u8; 32]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector_of("execute_spend"));
    calldata.extend_from_slice(&proposal_id);
    calldata
}

/// Parse a 32-byte hex account ID string into `[u8; 32]`.
fn parse_account_id_hex(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err("account_id must be 32 bytes (64 hex chars)".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encode staking delegate `add` calldata.
fn encode_staking_delegate_add(delegate: [u8; 32]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector_of("delegate_add"));
    calldata.extend_from_slice(&delegate);
    calldata
}

/// Encode staking delegate `remove` calldata.
fn encode_staking_delegate_remove(delegate: [u8; 32]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector_of("delegate_remove"));
    calldata.extend_from_slice(&delegate);
    calldata
}

/// Encode staking `stake_for` calldata (delegate path).
fn encode_staking_stake_for(
    owner: [u8; 32],
    pubkey: &[u8],
    amount: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + 32 + VALIDATOR_PUBKEY_LEN + 8);
    calldata.extend_from_slice(&selector_of("stake_for"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(pubkey);
    calldata.extend_from_slice(&amount.to_le_bytes());
    Ok(calldata)
}

/// Encode staking `unstake_for` calldata (delegate path).
fn encode_staking_unstake_for(
    owner: [u8; 32],
    pubkey: &[u8],
    amount: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + 32 + VALIDATOR_PUBKEY_LEN + 8);
    calldata.extend_from_slice(&selector_of("unstake_for"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(pubkey);
    calldata.extend_from_slice(&amount.to_le_bytes());
    Ok(calldata)
}

/// Encode staking `withdraw_for` calldata (delegate path).
fn encode_staking_withdraw_for(
    owner: [u8; 32],
    pubkey: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + 32 + VALIDATOR_PUBKEY_LEN);
    calldata.extend_from_slice(&selector_of("withdraw_for"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(pubkey);
    Ok(calldata)
}

/// Encode staking `unjail_for` calldata (delegate path).
fn encode_staking_unjail_for(
    owner: [u8; 32],
    pubkey: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + 32 + VALIDATOR_PUBKEY_LEN);
    calldata.extend_from_slice(&selector_of("unjail_for"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(pubkey);
    Ok(calldata)
}

/// Parse a list of 32-byte hex strings into slot keys.
fn parse_manifest_slots(
    manifest: &serde_json::Value,
    field: &str,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    manifest[field]
        .as_array()
        .ok_or_else(|| format!("Missing {} in manifest", field))?
        .iter()
        .map(|v| {
            let hex = v
                .as_str()
                .ok_or_else(|| format!("Invalid {} entry", field))?;
            let bytes = hex::decode(hex)?;
            if bytes.len() != 32 {
                return Err(format!("{} entry must be 32 bytes", field).into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()
}

/// Load manifest fields (reads/writes/commutative/specs) from a JSON file.
fn load_manifest_sets(
    manifest_path: &str,
) -> Result<
    (
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
        Vec<truthlinked_core::cells::StorageKeySpec>,
        Vec<[u8; 32]>,
    ),
    Box<dyn std::error::Error>,
> {
    let manifest_json = std::fs::read_to_string(manifest_path)?;
    load_manifest_sets_from_json(&manifest_json)
}

/// Parse storage key specs from manifest JSON.
fn parse_manifest_specs(
    manifest: &serde_json::Value,
) -> Result<Vec<truthlinked_core::cells::StorageKeySpec>, Box<dyn std::error::Error>> {
    let specs = manifest
        .get("storage_key_specs")
        .and_then(|v| v.as_array())
        .ok_or("Missing storage_key_specs in manifest")?;
    let mut out = Vec::new();
    for item in specs {
        let offset = item
            .get("offset")
            .and_then(|v| v.as_u64())
            .ok_or("Invalid storage_key_specs.offset")?;
        let len = item
            .get("len")
            .and_then(|v| v.as_u64())
            .ok_or("Invalid storage_key_specs.len")?;
        out.push(truthlinked_core::cells::StorageKeySpec {
            offset: offset as usize,
            len: len as usize,
        });
    }
    Ok(out)
}

/// Parse oracle schema IDs from manifest JSON.
fn parse_manifest_schema_ids(
    manifest: &serde_json::Value,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    let empty = Vec::new();
    let arr = manifest
        .get("oracle_schema_ids")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut out = Vec::new();
    for item in arr {
        let hex = item
            .as_str()
            .ok_or_else(|| "Invalid oracle_schema_ids entry".to_string())?;
        let bytes = hex::decode(hex)?;
        if bytes.len() != 32 {
            return Err("oracle_schema_ids entry must be 32 bytes".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        out.push(arr);
    }
    Ok(out)
}

/// Load manifest fields directly from JSON bytes.
fn load_manifest_sets_from_json(
    manifest_json: &str,
) -> Result<
    (
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
        Vec<truthlinked_core::cells::StorageKeySpec>,
        Vec<[u8; 32]>,
    ),
    Box<dyn std::error::Error>,
> {
    let manifest: serde_json::Value = serde_json::from_str(manifest_json)?;
    let declared_reads = parse_manifest_slots(&manifest, "declared_reads")?;
    let declared_writes = parse_manifest_slots(&manifest, "declared_writes")?;
    let commutative_keys = parse_manifest_slots(&manifest, "commutative_keys")?;
    let storage_key_specs = parse_manifest_specs(&manifest)?;
    let oracle_schema_ids = parse_manifest_schema_ids(&manifest)?;
    Ok((
        declared_reads,
        declared_writes,
        commutative_keys,
        storage_key_specs,
        oracle_schema_ids,
    ))
}

/// Encode a u32 as ULEB128 (used for custom WASM sections).
#[allow(dead_code)]
fn encode_uleb_u32(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}

fn parse_package_name(cargo_toml: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(cargo_toml)?;
    let parsed: toml::Value = toml::from_str(&content)?;
    let name = parsed
        .get("package")
        .and_then(|pkg| pkg.get("name"))
        .and_then(|v| v.as_str())
        .ok_or("Could not parse package.name from Cargo.toml")?;
    Ok(name.to_string())
}

/// Build an SDK project and return generated artifact paths.
///
/// The scaffold ships with `src/main.rs`, while older projects may use
/// `src/lib.rs`. Accept both so `sdk-new` output builds without manual edits.
fn sdk_build_project(
    project_path: &str,
    output: Option<&str>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(project_path);
    let lib_source = root.join("src/lib.rs");
    let main_source = root.join("src/main.rs");
    let source = if lib_source.exists() {
        lib_source
    } else if main_source.exists() {
        main_source
    } else {
        return Err(format!(
            "SDK source not found: expected {} or {}",
            root.join("src/lib.rs").display(),
            root.join("src/main.rs").display()
        )
        .into());
    };

    let _ = sdk_generate_manifest(root);

    let output_base = if let Some(explicit) = output {
        explicit.to_string()
    } else {
        let build_dir = root.join("build");
        std::fs::create_dir_all(&build_dir)?;
        build_dir.join("cell").to_string_lossy().to_string()
    };

    build_cell(source.to_string_lossy().as_ref(), Some(&output_base))
}

/// Generate a manifest scaffold for an SDK project.
fn sdk_generate_manifest(root: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let manifest_bin = root.join("src/bin/manifest.rs");
    if !manifest_bin.exists() {
        return Ok(());
    }

    let out_path = root.join("manifest.auto.json");
    let status = Command::new(resolve_cargo_binary())
        .args(&["run", "--quiet", "--bin", "manifest", "--release"])
        .current_dir(root)
        .env(
            "TRUTHLINKED_MANIFEST_OUT",
            out_path.to_string_lossy().to_string(),
        )
        .status()?;

    if !status.success() {
        eprintln!(" Corporate System Exception: Manifest generation failed. Falling back to default baseline template.");
        return Ok(());
    }

    let _ = sdk_augment_manifest_from_source(root, &out_path);
    Ok(())
}

/// Augment the manifest by scanning Rust source for SDK storage patterns.
/// Use this output as a manifest review aid.
fn sdk_augment_manifest_from_source(
    root: &std::path::Path,
    manifest_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let src_root = root.join("src");
    if !src_root.exists() || !manifest_path.exists() {
        return Ok(());
    }

    let sources = read_project_sources(&src_root)?;
    if sources.is_empty() {
        return Ok(());
    }
    let joined = sources.join("\n");
    let consts = parse_const_offsets(&joined);
    let mut specs = Vec::new();
    let var_offsets = collect_var_key_bindings(&joined, &consts);
    for prefix in [
        "abi::read_account",
        "abi::read_account_id",
        "abi::read_bytes32",
        "truthlinked_sdk::abi::read_account",
        "crate::abi::read_account",
    ] {
        collect_key_specs(&joined, prefix, &consts, &mut specs);
    }
    collect_key_specs_from_storage_calls(&joined, &consts, &var_offsets, &mut specs);

    if specs.is_empty() {
        return Ok(());
    }

    let manifest_json = std::fs::read_to_string(manifest_path)?;
    let mut manifest: serde_json::Value = serde_json::from_str(&manifest_json)?;
    let array = manifest
        .get_mut("storage_key_specs")
        .and_then(|v| v.as_array_mut())
        .ok_or("manifest storage_key_specs missing or not array")?;

    let mut existing = std::collections::HashSet::new();
    for item in array.iter() {
        if let (Some(offset), Some(len)) = (item.get("offset"), item.get("len")) {
            if let (Some(offset), Some(len)) = (offset.as_u64(), len.as_u64()) {
                existing.insert((offset as usize, len as usize));
            }
        }
    }

    for (offset, len) in specs {
        if existing.insert((offset, len)) {
            array.push(serde_json::json!({ "offset": offset, "len": len }));
        }
    }
    array.sort_by(|a, b| {
        let ao = a.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
        let bo = b.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
        let al = a.get("len").and_then(|v| v.as_u64()).unwrap_or(0);
        let bl = b.get("len").and_then(|v| v.as_u64()).unwrap_or(0);
        ao.cmp(&bo).then(al.cmp(&bl))
    });

    std::fs::write(manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    Ok(())
}

/// Recursively read Rust source files for SDK analysis.
fn read_project_sources(root: &std::path::Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    fn visit(
        dir: &std::path::Path,
        out: &mut Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit(&path, out)?;
            } else if let Some(ext) = path.extension() {
                if ext == "rs" {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        out.push(text);
                    }
                }
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(root, &mut out)?;
    Ok(out)
}

#[derive(Debug)]
enum RecipientSpec {
    Name(String),
    AccountId([u8; 32]),
    Pubkey(Vec<u8>),
}

fn is_valid_name(name: &str) -> bool {
    if !name.is_ascii() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if lower != name {
        return false;
    }
    if !name.ends_with(".tl") {
        return false;
    }
    let root = &name[..name.len().saturating_sub(3)];
    if root.is_empty() || root.starts_with('.') || root.ends_with('.') {
        return false;
    }
    let mut letters = 0usize;
    let mut prev_dot = false;
    for ch in root.chars() {
        if ch == '.' {
            if prev_dot {
                return false;
            }
            prev_dot = true;
            continue;
        }
        if !(ch >= 'a' && ch <= 'z') {
            return false;
        }
        letters += 1;
        prev_dot = false;
    }
    letters > 0 && letters <= 12
}

fn parse_recipient_spec(input: &str) -> Result<RecipientSpec, Box<dyn std::error::Error>> {
    if input.ends_with(".tl") {
        if !is_valid_name(input) {
            return Err("Invalid name format (lowercase .tl, 12 letters max, dots allowed)".into());
        }
        return Ok(RecipientSpec::Name(input.to_string()));
    }

    let bytes = hex::decode(input)?;
    if bytes.len() == 32 {
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        return Ok(RecipientSpec::AccountId(id));
    }
    if bytes.len() == 1952 {
        return Ok(RecipientSpec::Pubkey(bytes));
    }

    Err("Recipient must be a .tl name, 64-hex account ID, or 3904-hex pubkey".into())
}

/// Parse `const` offsets from Rust source for manifest augmentation.
fn parse_const_offsets(source: &str) -> std::collections::HashMap<String, usize> {
    use regex::Regex;
    let mut map = std::collections::HashMap::new();
    let mut raw_map = std::collections::HashMap::new();
    let re = Regex::new(r"(?m)^\s*(?:pub\s+)?(?:const|static)\s+([A-Z0-9_]+)\s*:\s*(?:usize|u32|u64)\s*=\s*([^;]+);").ok();
    if let Some(re) = re {
        for caps in re.captures_iter(source) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let raw = caps
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            raw_map.insert(name, raw);
        }
    }
    for _ in 0..4 {
        let mut progressed = false;
        for (name, raw) in raw_map.iter() {
            if map.contains_key(name) {
                continue;
            }
            if let Some(value) = resolve_offset_expr(raw, &map) {
                map.insert(name.clone(), value);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    map
}

/// Parse a Rust usize literal (decimal or hex).
fn parse_usize_literal(raw: &str) -> Option<usize> {
    let s = raw.replace('_', "");
    if let Some(hex) = s.strip_prefix("0x") {
        usize::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<usize>().ok()
    }
}

/// Resolve an offset expression using the known const table.
fn resolve_offset_expr(
    expr: &str,
    consts: &std::collections::HashMap<String, usize>,
) -> Option<usize> {
    let mut cleaned = expr.replace(' ', "");
    while cleaned.starts_with('(') && cleaned.ends_with(')') && cleaned.len() > 2 {
        cleaned = cleaned[1..cleaned.len() - 1].to_string();
    }
    if let Some(v) = parse_usize_literal(&cleaned) {
        return Some(v);
    }
    if let Some(v) = consts.get(&cleaned) {
        return Some(*v);
    }
    if let Some((a, b)) = cleaned.split_once('+') {
        let left = resolve_offset_expr(a, consts)?;
        let right = resolve_offset_expr(b, consts)?;
        return left.checked_add(right);
    }
    None
}

/// Collect storage key specs from extracted patterns.
fn collect_key_specs(
    source: &str,
    fn_prefix: &str,
    consts: &std::collections::HashMap<String, usize>,
    out: &mut Vec<(usize, usize)>,
) {
    use regex::Regex;
    let pattern = format!(
        r"(?s){}\s*\(\s*[^,]+,\s*([A-Za-z0-9_+\s]+)\s*\)",
        regex::escape(fn_prefix)
    );
    let re = match Regex::new(&pattern) {
        Ok(v) => v,
        Err(_) => return,
    };
    for caps in re.captures_iter(source) {
        let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Some(offset) = resolve_offset_expr(expr, consts) {
            out.push((offset, 32));
        }
    }
}

/// Collect variable bindings used in derived storage slots.
fn collect_var_key_bindings(
    source: &str,
    consts: &std::collections::HashMap<String, usize>,
) -> std::collections::HashMap<String, usize> {
    use regex::Regex;
    let mut out = std::collections::HashMap::new();
    let prefixes = [
        "abi::read_account",
        "abi::read_account_id",
        "abi::read_bytes32",
        "truthlinked_sdk::abi::read_account",
        "crate::abi::read_account",
    ];
    for prefix in prefixes {
        let pattern = format!(
            r"(?s)let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{}\s*\(\s*[^,]+,\s*([A-Za-z0-9_+\s]+)\s*\)",
            regex::escape(prefix)
        );
        let re = match Regex::new(&pattern) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for caps in re.captures_iter(source) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let expr = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if let Some(offset) = resolve_offset_expr(expr, consts) {
                out.insert(name, offset);
            }
        }
    }
    out
}

/// Normalize a storage key expression for deterministic matching.
fn normalize_key_expr(expr: &str) -> String {
    let mut s = expr.trim().to_string();
    if let Some(stripped) = s.strip_prefix('&') {
        s = stripped.trim().to_string();
    }
    for suffix in [".as_bytes()", ".as_ref()", ".as_slice()"] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped.trim().to_string();
        }
    }
    if s.starts_with('(') && s.ends_with(')') && s.len() > 2 {
        s = s[1..s.len() - 1].trim().to_string();
    }
    s
}

/// Scan SDK storage calls to extract storage key specs.
fn collect_key_specs_from_storage_calls(
    source: &str,
    consts: &std::collections::HashMap<String, usize>,
    var_offsets: &std::collections::HashMap<String, usize>,
    out: &mut Vec<(usize, usize)>,
) {
    use regex::Regex;
    let patterns = [
        r"(?s)storage::slot_for\s*\(\s*[^,]+,\s*([^\)]+)\)",
        r"(?s)hashing::derive_slot\s*\(\s*[^,]+,\s*&?\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)hashing::derive_slot\s*\(\s*[^,]+,\s*&?\s*vec!\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)hashing::derive_slot\s*\(\s*[^,]+,\s*vec!\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)Slot::derived\s*\(\s*[^,]+,\s*&?\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)Slot::derived\s*\(\s*[^,]+,\s*&?\s*vec!\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)storage::Slot::derived\s*\(\s*[^,]+,\s*&?\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)storage::Slot::derived\s*\(\s*[^,]+,\s*&?\s*vec!\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)\.\s*(?:get|insert|remove|contains)_typed_key\s*\(\s*([^\),]+)",
        r"(?s)\.\s*(?:get|insert|remove|contains)_key\s*\(\s*([^\),]+)",
        r"(?s)\.\s*slots_for_key\s*\(\s*([^\)]+)\)",
    ];

    for pat in patterns {
        let re = match Regex::new(pat) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for caps in re.captures_iter(source) {
            let raw = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let mut expr = normalize_key_expr(raw);
            expr = extract_key_expr_from_list(&expr);
            for prefix in [
                "abi::read_account",
                "abi::read_account_id",
                "abi::read_bytes32",
                "truthlinked_sdk::abi::read_account",
                "crate::abi::read_account",
            ] {
                if expr.starts_with(prefix) {
                    if let Some(idx) = expr.find(',') {
                        let after = &expr[idx + 1..];
                        if let Some(end) = after.find(')') {
                            let offset_expr = after[..end].trim();
                            if let Some(offset) = resolve_offset_expr(offset_expr, consts) {
                                out.push((offset, 32));
                            }
                        }
                    }
                }
            }
            if let Some(offset) = var_offsets.get(&expr) {
                out.push((*offset, 32));
            }
        }
    }
}

/// Extract key expressions from list-style syntax.
fn extract_key_expr_from_list(expr: &str) -> String {
    // For derived slots, the final list element carries the runtime storage key.
    if expr.contains(',') {
        let mut parts = expr.split(',');
        let mut last = "";
        for part in parts.by_ref() {
            last = part;
        }
        return normalize_key_expr(last);
    }
    expr.to_string()
}

/// Locate an SDK build artifact.
fn sdk_locate_axiom(project_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let root = std::path::Path::new(project_path);

    let build_candidate = root.join("build/cell.axiom");
    if build_candidate.exists() {
        return Ok(build_candidate.to_string_lossy().to_string());
    }

    let cargo_toml = root.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(format!("Cargo.toml not found in {}", root.display()).into());
    }
    let crate_name = parse_package_name(&cargo_toml)?.replace('-', "_");
    let release_candidate = root
        .join("target/truthlinked-cells/release")
        .join(format!("{}.axiom", crate_name));
    if release_candidate.exists() {
        return Ok(release_candidate.to_string_lossy().to_string());
    }

    Err(format!(
        "No axiom artifact found for SDK project {}. Run `axiom sdk-build --path {}` first.",
        root.display(),
        project_path
    )
    .into())
}

/// Resolve manifest path, preferring explicit override if provided.
fn resolve_manifest_path(axiom_path: &str, manifest_override: Option<String>) -> Option<String> {
    if manifest_override.is_some() {
        return manifest_override;
    }
    let inferred = axiom_path.replace(".axiom", ".manifest.json");
    if std::path::Path::new(&inferred).exists() {
        Some(inferred)
    } else {
        None
    }
}

/// Submit a `DeployCell` transaction using the given bytecode and manifest.
fn submit_cell_deploy(
    client: &reqwest::blocking::Client,
    rpc: &str,
    from: &str,
    cell_id: &str,
    axiom_path: &str,
    manifest_path: Option<String>,
    initial_balance: u64,
    output: OutputFormat,
    retries: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let sender_keys = DualKeypair::load(from)?;
    let pubkey = sender_keys.dilithium_pk.clone().into_bytes();
    let sender_account_id = truthlinked_core::pq_identity::account_id_from_pubkey(&pubkey);

    let cell_id_bytes = hex::decode(cell_id)?;
    if cell_id_bytes.len() != 32 {
        return Err("cell_id must be 32 bytes hex".into());
    }
    let mut cell_id_arr = [0u8; 32];
    cell_id_arr.copy_from_slice(&cell_id_bytes);

    let bytecode = std::fs::read(axiom_path)?;
    let (declared_reads, declared_writes, commutative_keys, storage_key_specs, oracle_schema_ids) =
        if let Some(manifest_path) = manifest_path {
            let (reads, writes, commutative, specs, schema_ids) =
                load_manifest_sets(&manifest_path)?;
            truthlinked_core::cells::CellAccount::verify_manifest_against_bytecode(
                &bytecode, &reads, &writes, &specs,
            )?;
            eprintln!("✦ Validation Engine: Local contract manifest verified at {}", manifest_path);
            (reads, writes, commutative, specs, schema_ids)
        } else {
            let analysis = truthlinked_core::cells::CellAccount::analyze_bytecode(&bytecode)
                .map_err(|e| format!("Axiom static analysis failed: {}", e))?;
            if !analysis.fully_resolved {
                eprintln!("▲ Security Context: Unresolved dynamic storage tracks. Use --manifest-file to trigger collision checks.");
            }
            (
                analysis.static_read_slots,
                analysis.static_write_slots,
                vec![],
                vec![],
                vec![],
            )
        };

    let genesis_hash = fetch_genesis_hash(client, rpc, retries)?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let nonce = next_nonce(client, rpc, &sender_account_id, retries)?;
    let tx = Transaction {
        sender: sender_account_id,
        intent: TransactionIntent::DeployCell {
            cell_id: cell_id_arr,
            bytecode,
            initial_balance: initial_balance as u128,
            declared_reads,
            declared_writes,
            commutative_keys,
            storage_key_specs,
            oracle_schema_ids,
        },
        signature: vec![],
        nonce,
        timestamp,
        genesis_fingerprint: genesis_hash,
        expiration_height: u64::MAX,
    };

    let signed_tx = sender_keys.sign_transaction(&tx)?;
    let tx_bytes = postcard::to_allocvec(&signed_tx)?;

    eprintln!("✦ Network Engine: Broadcasting cell deployment payload to remote runtime environment...");
    let res: Value = post_bytes(client, &format!("{}/submit_raw", rpc), tx_bytes, retries)?;
    print_output(&res, output)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handle = std::thread::Builder::new()
        .name("axiom-cli".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| run_cli().map_err(|e| e.to_string()))?;

    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err("axiom cli thread panicked".into()),
    }
}

fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = load_cli_config();
    let output = resolve_output(&cli);
    let rpc = resolve_rpc(&cli, config.as_ref());
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(cli.timeout))
        .connection_verbose(false)
        .tcp_nodelay(true)
        .http1_only()
        .build()?;

    match cli.command {
        Commands::ChainInfo => {
            let res = get_json(&client, &format!("{}/chain_info", rpc), cli.retries)?;
            print_output(&res, output)?;
        }
        Commands::TokenInfo => {
            let res = get_json(&client, &format!("{}/token_info", rpc), cli.retries)?;
            print_output(&res, output)?;
        }
        Commands::NetworkInfo => {
            let res = get_json(&client, &format!("{}/network_info", rpc), cli.retries)?;
            print_output(&res, output)?;
        }
        Commands::Validators => {
            let res = get_json(&client, &format!("{}/validators", rpc), cli.retries)?;
            print_output(&res, output)?;
        }
        Commands::Mempool => {
            let res = get_json(&client, &format!("{}/mempool", rpc), cli.retries)?;
            print_output(&res, output)?;
        }
        Commands::Status { from, full } => {
            let account_id = account_id_from_keyfile_arg(from.as_deref(), config.as_ref())?;
            let chain = get_json(&client, &format!("{}/chain_info", rpc), cli.retries)?;
            let balance = post_json(
                &client,
                &format!("{}/balance", rpc),
                serde_json::json!({
                    "account_id": hex::encode(account_id),
                    "full": full
                }),
                cli.retries,
            )?;
            let res = serde_json::json!({
                "chain": chain,
                "balance": balance
            });
            print_output(&res, output)?;
        }
        Commands::Resolve { query } => {
            let q = urlencoding::encode(&query);
            let res = get_json(&client, &format!("{}/resolve/{}", rpc, q), cli.retries)?;
            print_output(&res, output)?;
        }

        Commands::ListCellProposals => {
            let res = get_json(&client, &format!("{}/cell_proposals", rpc), cli.retries)?;
            print_output(&res, output)?;
        }
        Commands::TxStatus { hash } | Commands::Tx { hash } => {
            let resp = client.get(format!("{}/tx/{}", rpc, hash)).send()?;
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                let pending = get_json(
                    &client,
                    &format!("{}/mempool/tx/{}", rpc, hash),
                    cli.retries,
                )?;
                let found = pending
                    .get("found")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let out = if found {
                    serde_json::json!({
                        "status": "pending",
                        "tx": pending.get("transaction").cloned().unwrap_or(serde_json::Value::Null)
                    })
                } else {
                    serde_json::json!({
                        "status": "not_found",
                        "tx": serde_json::Value::Null
                    })
                };
                print_output(&out, output)?;
                return Ok(());
            }
            if !resp.status().is_success() {
                return Err(format!("RPC error: status {}", resp.status()).into());
            }
            let confirmed: Value = resp.json()?;
            if let Some(err) = confirmed.get("error").filter(|v| !v.is_null()) {
                return Err(format!("RPC error: {}", err).into());
            }
            if !confirmed.is_null() {
                let out = serde_json::json!({
                    "status": "confirmed",
                    "tx": confirmed
                });
                print_output(&out, output)?;
            } else {
                let pending = get_json(
                    &client,
                    &format!("{}/mempool/tx/{}", rpc, hash),
                    cli.retries,
                )?;
                let found = pending
                    .get("found")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let out = if found {
                    serde_json::json!({
                        "status": "pending",
                        "tx": pending.get("transaction").cloned().unwrap_or(serde_json::Value::Null)
                    })
                } else {
                    serde_json::json!({
                        "status": "not_found",
                        "tx": serde_json::Value::Null
                    })
                };
                print_output(&out, output)?;
            }
        }
        Commands::Balance { account_id, from, full } => {
            let account_id = if let Some(account_id) = account_id {
                account_id
            } else {
                hex::encode(account_id_from_keyfile_arg(from.as_deref(), config.as_ref())?)
            };
            let res = post_json(
                &client,
                &format!("{}/balance", rpc),
                serde_json::json!({"account_id": account_id}),
                cli.retries,
            )?;
            if full {
                let tokens = post_json(
                    &client,
                    &format!("{}/token_balances", rpc),
                    serde_json::json!({"account_id": account_id, "include_metadata": true}),
                    cli.retries,
                )?;
                if matches!(output, OutputFormat::Json) {
                    let out = serde_json::json!({
                        "account_id": res.get("account_id").cloned().unwrap_or(Value::Null),
                        "balance": res.get("balance").cloned().unwrap_or(Value::Null),
                        "balance_tlkd": res.get("balance_tlkd").cloned().unwrap_or(Value::Null),
                        "compute_escrow_tlkd": res.get("compute_escrow_tlkd").cloned().unwrap_or(Value::Null),
                        "compute_escrow_tlkd_formatted": res.get("compute_escrow_tlkd_formatted").cloned().unwrap_or(Value::Null),
                        "staking_balance": res.get("staking_balance").cloned().unwrap_or(Value::Null),
                        "staking_balance_tlkd": res.get("staking_balance_tlkd").cloned().unwrap_or(Value::Null),
                        "token_balances": tokens.get("balances").cloned().unwrap_or(Value::Null),
                    });
                    print_output(&out, output)?;
                } else {
                    print_balance_pretty(&res, Some(&tokens), true)?;
                }
            } else if matches!(output, OutputFormat::Json) {
                print_output(&res, output)?;
            } else {
                print_balance_pretty(&res, None, false)?;
            }
        }
        Commands::BalanceByPubkey { pubkey, from, full } => {
            let pubkey = if let Some(pubkey) = pubkey {
                pubkey
            } else {
                hex::encode(pubkey_from_keyfile_arg(from.as_deref(), config.as_ref())?)
            };
            let res = post_json(
                &client,
                &format!("{}/balance_by_pubkey", rpc),
                serde_json::json!({"pubkey": pubkey}),
                cli.retries,
            )?;
            if full {
                let account_id = res.get("account_id").and_then(|v| v.as_str()).unwrap_or("");
                let tokens: Value = if account_id.is_empty() {
                    serde_json::json!({ "balances": [] })
                } else {
                    post_json(
                        &client,
                        &format!("{}/token_balances", rpc),
                        serde_json::json!({"account_id": account_id, "include_metadata": true}),
                        cli.retries,
                    )?
                };
                if matches!(output, OutputFormat::Json) {
                    let out = serde_json::json!({
                        "account_id": res.get("account_id").cloned().unwrap_or(Value::Null),
                        "balance": res.get("balance").cloned().unwrap_or(Value::Null),
                        "balance_tlkd": res.get("balance_tlkd").cloned().unwrap_or(Value::Null),
                        "compute_escrow_tlkd": res.get("compute_escrow_tlkd").cloned().unwrap_or(Value::Null),
                        "compute_escrow_tlkd_formatted": res.get("compute_escrow_tlkd_formatted").cloned().unwrap_or(Value::Null),
                        "staking_balance": res.get("staking_balance").cloned().unwrap_or(Value::Null),
                        "staking_balance_tlkd": res.get("staking_balance_tlkd").cloned().unwrap_or(Value::Null),
                        "token_balances": tokens.get("balances").cloned().unwrap_or(Value::Null),
                    });
                    print_output(&out, output)?;
                } else {
                    print_balance_pretty(&res, Some(&tokens), true)?;
                }
            } else if matches!(output, OutputFormat::Json) {
                print_output(&res, output)?;
            } else {
                print_balance_pretty(&res, None, false)?;
            }
        }

        Commands::AccountId { from, pubkey } => {
            let pk_bytes = if let Some(pk_hex) = pubkey {
                hex::decode(&pk_hex)?
            } else {
                pubkey_from_keyfile_arg(from.as_deref(), config.as_ref())?
            };

            if pk_bytes.len() != 1952 {
                return Err(format!(
                    "Invalid public key length: {} (expected 1952 bytes)",
                    pk_bytes.len()
                )
                .into());
            }

            let account_id = pq_identity::account_id_from_pubkey(&pk_bytes);
            if matches!(output, OutputFormat::Json) {
                let out = serde_json::json!({
                    "account_id": hex::encode(&account_id),
                    "public_key": hex::encode(&pk_bytes),
                });
                print_output(&out, output)?;
            } else {
                println!("Account Identity Hash: 0x{}", hex::encode(&account_id));
                println!("Public Identity Key:   0x{}", hex::encode(&pk_bytes));
            }
        }

        Commands::ImportMnemonic {
            mnemonic,
            output: output_path,
            passphrase,
        } => {
            let keyfile_password = passphrase.clone();
            let keypair = if let Some(pass) = passphrase {
                pq_identity::DualKeypair::from_mnemonic_with_passphrase(mnemonic, &pass)
            } else {
                pq_identity::DualKeypair::from_mnemonic(mnemonic)
            };

            let password = if let Some(password) = keyfile_password {
                if password.len() < 8 {
                    return Err("Password must be at least 8 characters".into());
                }
                password
            } else {
                rpassword::prompt_password("Enter password to encrypt keyfile: ")?
            };
            if output_path == default_keyfile_path() {
                if let Some(parent) = std::path::Path::new(&output_path).parent() {
                    std::fs::create_dir_all(parent)?;
                }
            }

            keypair.save_with_password(&output_path, Some(&password))?;

            let pubkey = keypair.dilithium_pk.clone().into_bytes();
            let account_id = pq_identity::account_id_from_pubkey(&pubkey);

            if matches!(output, OutputFormat::Json) {
                let out = serde_json::json!({
                    "status": "imported",
                    "keyfile": output_path,
                    "account_id": hex::encode(&account_id),
                    "public_key": hex::encode(&pubkey),
                });
                print_output(&out, output)?;
            } else {
                println!("┌── KEYPAIR LOGISTICS MANAGER");
                println!("│  Storage File:  {}", output_path);
                println!("│  Account Hash:  0x{}", hex::encode(&account_id));
                println!("│  Public Engine: 0x{}", hex::encode(&pubkey));
            }
        }
        Commands::AccountCreate {
            output: output_path,
            encrypt,
            passphrase,
        } => {
            let mut entropy = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut entropy);
            let mnemonic = Mnemonic::from_entropy(&entropy)?;
            let keypair = if let Some(pass) = &passphrase {
                pq_identity::DualKeypair::from_mnemonic_with_passphrase(mnemonic.to_string(), pass)
            } else {
                pq_identity::DualKeypair::from_mnemonic(mnemonic.to_string())
            };

            let password = if encrypt {
                let password = if let Some(password) = passphrase.clone() {
                    password
                } else {
                    let password =
                        rpassword::prompt_password("Enter password to encrypt keyfile: ")?;
                    let confirm = rpassword::prompt_password("Confirm password: ")?;
                    if password != confirm {
                        return Err("Passwords do not match".into());
                    }
                    password
                };
                if password.len() < 8 {
                    return Err("Password must be at least 8 characters".into());
                }
                Some(password)
            } else {
                eprintln!("▲ SECURITY WARNING: Local keyfile record will be committed to storage unencrypted.");
                None
            };

            if output_path == default_keyfile_path() {
                if let Some(parent) = std::path::Path::new(&output_path).parent() {
                    std::fs::create_dir_all(parent)?;
                }
            }

            // Guard: never silently overwrite an existing keyfile
            if std::path::Path::new(&output_path).exists() {
                eprint!("⚠ Key file already exists at {}. Overwrite? [y/N]: ", output_path);
                let mut ans = String::new();
                std::io::stdin().read_line(&mut ans)?;
                if ans.trim().to_lowercase() != "y" {
                    return Err(format!("Aborted — existing key file preserved: {}", output_path).into());
                }
            }
            keypair.save_with_password(&output_path, password.as_deref())?;

            let pubkey = keypair.dilithium_pk.clone().into_bytes();
            let account_id = pq_identity::account_id_from_pubkey(&pubkey);

            // Make the created key the default for all ops (unless --from is explicitly used)
            let is_default = output_path == default_keyfile_path();
            if is_default {
                if let Some(home) = dirs::home_dir() {
                    let cfg_dir = home.join(".truthlinked");
                    let _ = std::fs::create_dir_all(&cfg_dir);
                    let cfg_path = cfg_dir.join("config.json");
                    let mut cfg: serde_json::Value = if cfg_path.exists() {
                        serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap_or_default()).unwrap_or(serde_json::json!({}))
                    } else {
                        serde_json::json!({})
                    };
                    if let Some(obj) = cfg.as_object_mut() {
                        obj.insert("default_keyfile".to_string(), serde_json::json!(output_path));
                    }
                    let _ = std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg).unwrap_or_else(|_| cfg.to_string()));
                }
            }

            if matches!(output, OutputFormat::Json) {
                let out = serde_json::json!({
                    "status": "created",
                    "keyfile": output_path,
                    "account_id": hex::encode(&account_id),
                    "public_key": hex::encode(&pubkey),
                    "mnemonic": mnemonic.to_string(),
                    "passphrase_provided": passphrase.is_some(),
                    "is_now_default": is_default,
                });
                print_output(&out, output)?;
                eprintln!("▲ CRITICAL CLEAR-TEXT HAZARD: Private mnemonic seed printed to stdout context.");
            } else {
                println!("┌── KEYPAIR LOGISTICS MANAGER");
                println!("│  Storage File:  {}", output_path);
                println!("│  Account Hash:  0x{}", hex::encode(&account_id));
                println!("│  Public Engine: 0x{}", hex::encode(&pubkey));
                if is_default {
                    println!("│  Default Context:       Assigned as default routing key for local commands.");
                    println!("│  Parameter Optimization: Explicit execution flags via '--from' are no longer required.");
                }
                eprintln!("├─ ▲ EXTREME DATA CAUTION ───────────────────────────────────");
                eprintln!("│  Do not paste these seed strings into web browsers, logs, or public terminal runners.");
                eprintln!("│  Mnemonic Secret:  {}\n│  Passphrase Check: [User Custom Configuration Defined]", mnemonic);
                if passphrase.is_some() {
                    eprintln!("   Passphrase: (provided, must be remembered for recovery)");
                }
            }
        }

        Commands::Faucet { from, amount } => {
            let keyfile = resolve_signing_keyfile_arg(from.as_deref(), config.as_ref())?;
            let sender_keys = pq_identity::DualKeypair::load(&keyfile)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let amount_raw = parse_amount_str(&amount)?;
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }
            if amount_raw > constants::MAX_AIRDROP_AMOUNT {
                return Err("Faucet amount exceeds testnet maximum (15,000 TLKD)".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let genesis_hash_hex = hex::encode(genesis_hash);
            let is_local_rpc = rpc.contains("localhost") || rpc.contains("127.0.0.1");
            if genesis_hash[0..4] != [0, 0, 0, 0] && !is_local_rpc {
                return Err("Faucet is only available on testnet".into());
            }

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let nonce: u64 = rand::random();

            let mut msg = Vec::new();
            msg.extend_from_slice(&genesis_hash);
            msg.extend_from_slice(&sender_account_id);
            msg.extend_from_slice(&sender_pubkey);
            msg.extend_from_slice(&amount_raw.to_le_bytes());
            msg.extend_from_slice(&timestamp.to_le_bytes());
            msg.extend_from_slice(&nonce.to_le_bytes());

            let signature = sender_keys
                .dilithium_sk
                .try_sign(&msg, b"truthlinked-faucet-v1")?;

            let base = std::env::var("TLKD_FAUCET_URL")
                .unwrap_or_else(|_| "https://faucet.truthlinked.org".to_string());
            let req = serde_json::json!({
                "account_id": hex::encode(&sender_account_id),
                "pubkey": hex::encode(&sender_pubkey),
                "amount": amount_raw.to_string(),
                "chain_id": hex::encode(genesis_hash),
                "timestamp": timestamp,
                "nonce": nonce,
                "genesis_fingerprint": genesis_hash_hex,
                "signature": hex::encode(&signature),
            });

            let mut parsed = post_json(&client, &format!("{}/faucet", base), req, cli.retries)?;
            if let Some(map) = parsed.as_object_mut() {
                map.entry("recipient".to_string())
                    .or_insert_with(|| serde_json::json!(hex::encode(&sender_account_id)));
                map.entry("amount".to_string())
                    .or_insert_with(|| serde_json::json!(amount_raw.to_string()));
                let tlkd_display = { let w = amount_raw / truthlinked_core::constants::ONE_TLKD; let f = amount_raw % truthlinked_core::constants::ONE_TLKD; if f == 0 { format!("{} TLKD", w) } else { let s = format!("{:09}", f); format!("{}.{} TLKD", w, s.trim_end_matches("0")) } };
                map.entry("amount_tlkd".to_string())
                    .or_insert_with(|| serde_json::json!(tlkd_display));
            }
            print_output(&parsed, output)?;
        }

        Commands::GenesisValidator {
            from,
            allocation,
        } => {
            let allocation_raw = parse_amount_str(&allocation)?;
            if allocation_raw == 0 {
                return Err("Allocation must be > 0".into());
            }
            let keys_path = resolve_signing_keyfile_arg(from.as_deref(), config.as_ref())?;
            let keys = pq_identity::DualKeypair::load(&keys_path)?;
            let pubkey = keys.dilithium_pk.clone().into_bytes().to_vec();
            let account_id = pq_identity::account_id_from_pubkey(&pubkey);
            let entry = serde_json::json!({
                "from": keys_path,
                "allocation": allocation_raw,
                "allocation_tlkd": allocation,
                "account_id": hex::encode(account_id),
                "public_key": hex::encode(pubkey),
            });
            print_output(&entry, output)?;
        }

        Commands::ValidatorInit { output: val_key_out, allocation } => {
            let alloc_raw = parse_amount_str(&allocation)?;
            if alloc_raw == 0 {
                return Err("allocation must be > 0".into());
            }

            // Create (or reuse) a dedicated validator key (not the global default)
            let key_path = if val_key_out.starts_with('~') {
                let rest = val_key_out.trim_start_matches('~').trim_start_matches('/');
                dirs::home_dir()
                    .map(|h| h.join(rest))
                    .and_then(|p| p.to_str().map(String::from))
                    .unwrap_or(val_key_out.clone())
            } else {
                val_key_out.clone()
            };

            let keypair = if std::path::Path::new(&key_path).exists() {
                println!("⚙ Re-mapping terminal operations to existing validator signature file: {}", key_path);
                pq_identity::DualKeypair::load(&key_path)?
            } else {
                println!("⚙ Generating fresh cryptographic validator key records...");
                let mut entropy = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut entropy);
                let mnemonic = Mnemonic::from_entropy(&entropy)?;
                let kp = pq_identity::DualKeypair::from_mnemonic(mnemonic.to_string());
                if let Some(parent) = std::path::Path::new(&key_path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                kp.save_with_password(&key_path, None)?;
                println!("⚙ Validator signature files committed to: {}", key_path);
                println!("⚙ Account Backup Secret (Store Offline): {}", mnemonic);
                kp
            };

            let pubkey = keypair.dilithium_pk.clone().into_bytes().to_vec();
            let account_id = pq_identity::account_id_from_pubkey(&pubkey);

            let genesis_entry = serde_json::json!({
                "account": hex::encode(&account_id),
                "pubkey": hex::encode(&pubkey),
                "allocation": alloc_raw,
            });

            println!("\n┌── DATA EXPORT: GENESIS VALIDATOR COMPONENT (Append to genesis_validator.json)");
            println!("{}", serde_json::to_string_pretty(&genesis_entry).unwrap());

            println!("└────────────────────────────────────────────────────────────");
            println!("  ./target/release/node --validator-keys {} --genesis-file genesis_validator.json ...", key_path);
            println!("  (see start_network.sh for full examples)");

            if matches!(output, OutputFormat::Json) {
                let out = serde_json::json!({
                    "validator_keyfile": key_path,
                    "account_id": hex::encode(&account_id),
                    "public_key": hex::encode(&pubkey),
                    "genesis_entry": genesis_entry,
                });
                print_output(&out, output)?;
            }
        }

        Commands::Mcp { command } => match command {
            McpCommand::RegisterAgent {
                from,
                agent_keyfile,
                policy_cell_id,
                agent_registry_id,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let agent_keys = pq_identity::DualKeypair::load(&agent_keyfile)?;
                let agent_pubkey = agent_keys.dilithium_pk.clone().into_bytes().to_vec();
                let agent_id = pq_identity::account_id_from_pubkey(&agent_pubkey);

                let policy_cell = parse_hex_32("policy_cell_id", &policy_cell_id)?;
                let registry = if let Some(id) = agent_registry_id {
                    parse_hex_32("agent_registry_id", &id)?
                } else {
                    truthlinked_mcp::protocol_addresses::agent_registry()
                };

                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let nonce = next_nonce(&client, &rpc, &sender_id, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let tx = Transaction {
                    sender: sender_id,
                    intent: TransactionIntent::RegisterAgent {
                        agent_id,
                        policy_cell_id: policy_cell,
                        agent_registry_id: registry,
                    },
                    signature: vec![],
                    nonce,
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: u64::MAX,
                };
                let signed = sender_keys.sign_transaction(&tx)?;
                let bytes = postcard::to_allocvec(&signed)?;
                let res: Value =
                    post_bytes(&client, &format!("{}/submit_raw", rpc), bytes, cli.retries)?;
                print_output(&res, output)?;
            }
            McpCommand::RegisterTool {
                from,
                tool_id,
                name,
                category,
                bytecode_file,
                manifest_file,
                schema_file,
                registry_id,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let tool_id = parse_hex_32("tool_id", &tool_id)?;
                let registry = if let Some(id) = registry_id {
                    parse_hex_32("registry_id", &id)?
                } else {
                    truthlinked_mcp::protocol_addresses::mcp_registry()
                };
                let bytecode = load_bytes(&bytecode_file)?;
                let (reads, writes, commutative, specs, schema_ids) =
                    load_manifest_sets(&manifest_file)?;
                truthlinked_core::cells::CellAccount::verify_manifest_against_bytecode(
                    &bytecode, &reads, &writes, &specs,
                )?;
                let input_schema_json = load_bytes(&schema_file)?;

                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let nonce = next_nonce(&client, &rpc, &sender_id, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let tx = Transaction {
                    sender: sender_id,
                    intent: TransactionIntent::RegisterMcpTool {
                        tool_id,
                        bytecode,
                        name,
                        input_schema_json,
                        category,
                        declared_reads: reads,
                        declared_writes: writes,
                        commutative_keys: commutative,
                        oracle_schema_ids: schema_ids,
                        registry_id: registry,
                    },
                    signature: vec![],
                    nonce,
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: u64::MAX,
                };
                let signed = sender_keys.sign_transaction(&tx)?;
                let bytes = postcard::to_allocvec(&signed)?;
                let res: Value =
                    post_bytes(&client, &format!("{}/submit_raw", rpc), bytes, cli.retries)?;
                print_output(&res, output)?;
            }
            McpCommand::RegisterResource {
                from,
                resource_id,
                name,
                uri_scheme,
                mime_type,
                bytecode_file,
                manifest_file,
                initial_data_json,
                registry_id,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let resource_id = parse_hex_32("resource_id", &resource_id)?;
                let registry = if let Some(id) = registry_id {
                    parse_hex_32("registry_id", &id)?
                } else {
                    truthlinked_mcp::protocol_addresses::mcp_registry()
                };
                let bytecode = load_optional_bytes(bytecode_file)?;
                let (reads, writes, schema_ids) = if !bytecode.is_empty() {
                    let manifest = manifest_file
                        .ok_or("manifest_file required when bytecode_file is provided")?;
                    let (reads, writes, _commutative, specs, schema_ids) =
                        load_manifest_sets(&manifest)?;
                    truthlinked_core::cells::CellAccount::verify_manifest_against_bytecode(
                        &bytecode, &reads, &writes, &specs,
                    )?;
                    (reads, writes, schema_ids)
                } else {
                    (Vec::new(), Vec::new(), Vec::new())
                };

                let initial_data = if let Some(path) = initial_data_json {
                    let raw = std::fs::read_to_string(path)?;
                    let parsed: Vec<serde_json::Value> = serde_json::from_str(&raw)?;
                    let mut out = Vec::new();
                    for entry in parsed {
                        let k = entry
                            .get("key_hex")
                            .and_then(|v| v.as_str())
                            .ok_or("initial_data missing key_hex")?;
                        let v = entry
                            .get("value_hex")
                            .and_then(|v| v.as_str())
                            .ok_or("initial_data missing value_hex")?;
                        out.push((
                            parse_hex_bytes("key_hex", k)?,
                            parse_hex_bytes("value_hex", v)?,
                        ));
                    }
                    out
                } else {
                    Vec::new()
                };

                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let nonce = next_nonce(&client, &rpc, &sender_id, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let tx = Transaction {
                    sender: sender_id,
                    intent: TransactionIntent::RegisterMcpResource {
                        resource_id,
                        bytecode,
                        name,
                        uri_scheme,
                        mime_type,
                        initial_data,
                        declared_reads: reads,
                        declared_writes: writes,
                        oracle_schema_ids: schema_ids,
                        registry_id: registry,
                    },
                    signature: vec![],
                    nonce,
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: u64::MAX,
                };
                let signed = sender_keys.sign_transaction(&tx)?;
                let bytes = postcard::to_allocvec(&signed)?;
                let res: Value =
                    post_bytes(&client, &format!("{}/submit_raw", rpc), bytes, cli.retries)?;
                print_output(&res, output)?;
            }
            McpCommand::RegisterPrompt {
                from,
                prompt_id,
                name,
                template_file,
                arg,
                registry_id,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let prompt_id = parse_hex_32("prompt_id", &prompt_id)?;
                let registry = if let Some(id) = registry_id {
                    parse_hex_32("registry_id", &id)?
                } else {
                    truthlinked_mcp::protocol_addresses::mcp_registry()
                };
                let template_bytes = load_bytes(&template_file)?;
                let mut args = Vec::new();
                for raw in arg {
                    let parts: Vec<&str> = raw.splitn(3, ':').collect();
                    if parts.len() != 3 {
                        return Err("arg must be name:desc:required".into());
                    }
                    let required = matches!(parts[2], "1" | "true" | "yes" | "required");
                    args.push((parts[0].to_string(), parts[1].to_string(), required));
                }

                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let nonce = next_nonce(&client, &rpc, &sender_id, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let tx = Transaction {
                    sender: sender_id,
                    intent: TransactionIntent::RegisterMcpPrompt {
                        prompt_id,
                        name,
                        template_bytes,
                        arguments: args,
                        registry_id: registry,
                    },
                    signature: vec![],
                    nonce,
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: u64::MAX,
                };
                let signed = sender_keys.sign_transaction(&tx)?;
                let bytes = postcard::to_allocvec(&signed)?;
                let res: Value =
                    post_bytes(&client, &format!("{}/submit_raw", rpc), bytes, cli.retries)?;
                print_output(&res, output)?;
            }
            McpCommand::SetPolicy {
                from,
                policy_cell_id,
                status,
                allow_reads,
                allow_writes,
                allow_admin,
                rate_limit,
                spend_per_tx,
                spend_epoch,
                hitl_threshold,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let policy_cell = parse_hex_32("policy_cell_id", &policy_cell_id)?;
                let mut calldata = Vec::with_capacity(88);
                calldata.extend_from_slice(&sender_id);
                calldata.push(status);
                calldata.push(allow_reads);
                calldata.push(allow_writes);
                calldata.push(allow_admin);
                calldata.extend_from_slice(&rate_limit.to_le_bytes());
                calldata.extend_from_slice(&spend_per_tx.to_le_bytes());
                calldata.extend_from_slice(&spend_epoch.to_le_bytes());
                calldata.extend_from_slice(&hitl_threshold.to_le_bytes());

                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let nonce = next_nonce(&client, &rpc, &sender_id, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let tx = Transaction {
                    sender: sender_id,
                    intent: TransactionIntent::CallCell {
                        cell_id: policy_cell,
                        calldata,
                        value: 0,
                        gas_limit: 300_000,
                    },
                    signature: vec![],
                    nonce,
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: u64::MAX,
                };
                let signed = sender_keys.sign_transaction(&tx)?;
                let bytes = postcard::to_allocvec(&signed)?;
                let res: Value =
                    post_bytes(&client, &format!("{}/submit_raw", rpc), bytes, cli.retries)?;
                print_output(&res, output)?;
            }
            McpCommand::SetToolPermission {
                from,
                policy_cell_id,
                tool_id,
                enabled,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let policy_cell = parse_hex_32("policy_cell_id", &policy_cell_id)?;
                let tool_id = parse_hex_32("tool_id", &tool_id)?;
                let mut calldata = Vec::with_capacity(65);
                calldata.extend_from_slice(&sender_id);
                calldata.extend_from_slice(&tool_id);
                calldata.push(enabled);

                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let nonce = next_nonce(&client, &rpc, &sender_id, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let tx = Transaction {
                    sender: sender_id,
                    intent: TransactionIntent::CallCell {
                        cell_id: policy_cell,
                        calldata,
                        value: 0,
                        gas_limit: 200_000,
                    },
                    signature: vec![],
                    nonce,
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: u64::MAX,
                };
                let signed = sender_keys.sign_transaction(&tx)?;
                let bytes = postcard::to_allocvec(&signed)?;
                let res: Value =
                    post_bytes(&client, &format!("{}/submit_raw", rpc), bytes, cli.retries)?;
                print_output(&res, output)?;
            }
            McpCommand::PrivateBalanceInit {
                from,
                agent_id,
                cell_id,
                balance,
                aes_seed_hex,
                enc_nonce_hex,
                commit_nonce_hex,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let agent_id = parse_hex_32("agent_id", &agent_id)?;
                let cell_id = if let Some(raw) = cell_id {
                    parse_hex_32("cell_id", &raw)?
                } else {
                    truthlinked_mcp::private_balance::pb_keys::cell_for_agent(&agent_id)
                };
                let balance = parse_amount_str(&balance)?;
                let (encrypted_balance, commitment, commit_nonce) = private_balance_material(
                    balance,
                    &aes_seed_hex,
                    &enc_nonce_hex,
                    &commit_nonce_hex,
                )?;
                let mut res = submit_signed_intent(
                    &client,
                    &rpc,
                    cli.retries,
                    sender_id,
                    &sender_keys,
                    TransactionIntent::PrivateBalanceInit {
                        cell_id,
                        agent_id,
                        encrypted_balance: encrypted_balance.clone(),
                        commitment,
                        commit_nonce,
                    },
                )?;
                attach_private_balance_output(
                    &mut res,
                    &cell_id,
                    &agent_id,
                    balance,
                    &encrypted_balance,
                    &commitment,
                    &commit_nonce,
                );
                print_output(&res, output)?;
            }
            McpCommand::PrivateBalanceDeposit {
                from,
                cell_id,
                agent_id,
                amount,
                new_balance,
                old_commitment,
                aes_seed_hex,
                enc_nonce_hex,
                commit_nonce_hex,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let cell_id = parse_hex_32("cell_id", &cell_id)?;
                let agent_id = parse_hex_32("agent_id", &agent_id)?;
                let amount = parse_amount_str(&amount)?;
                let new_balance = parse_amount_str(&new_balance)?;
                let old_commitment = parse_hex_32("old_commitment", &old_commitment)?;
                let (new_encrypted_balance, new_commitment, new_commit_nonce) =
                    private_balance_material(
                        new_balance,
                        &aes_seed_hex,
                        &enc_nonce_hex,
                        &commit_nonce_hex,
                    )?;
                let mut res = submit_signed_intent(
                    &client,
                    &rpc,
                    cli.retries,
                    sender_id,
                    &sender_keys,
                    TransactionIntent::PrivateBalanceDeposit {
                        cell_id,
                        agent_id,
                        amount,
                        new_encrypted_balance: new_encrypted_balance.clone(),
                        new_commitment,
                        new_commit_nonce,
                        old_commitment,
                    },
                )?;
                attach_private_balance_output(
                    &mut res,
                    &cell_id,
                    &agent_id,
                    new_balance,
                    &new_encrypted_balance,
                    &new_commitment,
                    &new_commit_nonce,
                );
                print_output(&res, output)?;
            }
            McpCommand::PrivateBalanceWithdraw {
                from,
                cell_id,
                agent_id,
                amount,
                recipient,
                new_balance,
                old_commitment,
                aes_seed_hex,
                enc_nonce_hex,
                commit_nonce_hex,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let cell_id = parse_hex_32("cell_id", &cell_id)?;
                let agent_id = parse_hex_32("agent_id", &agent_id)?;
                let recipient = parse_hex_32("recipient", &recipient)?;
                let amount = parse_amount_str(&amount)?;
                let new_balance = parse_amount_str(&new_balance)?;
                let old_commitment = parse_hex_32("old_commitment", &old_commitment)?;
                let (new_encrypted_balance, new_commitment, new_commit_nonce) =
                    private_balance_material(
                        new_balance,
                        &aes_seed_hex,
                        &enc_nonce_hex,
                        &commit_nonce_hex,
                    )?;
                let mut res = submit_signed_intent(
                    &client,
                    &rpc,
                    cli.retries,
                    sender_id,
                    &sender_keys,
                    TransactionIntent::PrivateBalanceWithdraw {
                        cell_id,
                        agent_id,
                        amount,
                        recipient,
                        new_encrypted_balance: new_encrypted_balance.clone(),
                        new_commitment,
                        new_commit_nonce,
                        old_commitment,
                    },
                )?;
                attach_private_balance_output(
                    &mut res,
                    &cell_id,
                    &agent_id,
                    new_balance,
                    &new_encrypted_balance,
                    &new_commitment,
                    &new_commit_nonce,
                );
                print_output(&res, output)?;
            }
            McpCommand::PrivateBalanceConfidentialTransfer {
                from,
                sender_cell_id,
                sender_agent_id,
                recipient_cell_id,
                amount_commitment,
                proof_hex,
                proof_file,
                sender_new_encrypted,
                sender_new_commitment,
                sender_new_commit_nonce,
                sender_old_commitment,
                recipient_new_encrypted,
                recipient_new_commitment,
                recipient_new_commit_nonce,
                recipient_old_commitment,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let sender_cell_id = parse_hex_32("sender_cell_id", &sender_cell_id)?;
                let sender_agent_id = parse_hex_32("sender_agent_id", &sender_agent_id)?;
                let recipient_cell_id = parse_hex_32("recipient_cell_id", &recipient_cell_id)?;
                let amount_commitment = parse_hex_32("amount_commitment", &amount_commitment)?;
                let sender_new_encrypted = parse_hex_bytes_exact(
                    "sender_new_encrypted",
                    &sender_new_encrypted,
                    truthlinked_mcp::private_balance::CIPHERTEXT_LEN,
                )?;
                let sender_new_commitment =
                    parse_hex_32("sender_new_commitment", &sender_new_commitment)?;
                let sender_new_commit_nonce =
                    parse_hex_array::<16>("sender_new_commit_nonce", &sender_new_commit_nonce)?;
                let sender_old_commitment =
                    parse_hex_32("sender_old_commitment", &sender_old_commitment)?;
                let recipient_new_encrypted = parse_hex_bytes_exact(
                    "recipient_new_encrypted",
                    &recipient_new_encrypted,
                    truthlinked_mcp::private_balance::CIPHERTEXT_LEN,
                )?;
                let recipient_new_commitment =
                    parse_hex_32("recipient_new_commitment", &recipient_new_commitment)?;
                let recipient_new_commit_nonce = parse_hex_array::<16>(
                    "recipient_new_commit_nonce",
                    &recipient_new_commit_nonce,
                )?;
                let recipient_old_commitment =
                    parse_hex_32("recipient_old_commitment", &recipient_old_commitment)?;
                let stark_proof = match (proof_hex, proof_file) {
                    (Some(_), Some(_)) => {
                        return Err("Use either --proof-hex or --proof-file, not both".into());
                    }
                    (Some(raw), None) => parse_hex_bytes("proof_hex", &raw)?,
                    (None, Some(path)) => std::fs::read(path)?,
                    (None, None) => return Err("Provide --proof-hex or --proof-file".into()),
                };

                let proof_hash = hex::encode(blake3::hash(&stark_proof).as_bytes());
                let mut res = submit_signed_intent(
                    &client,
                    &rpc,
                    cli.retries,
                    sender_id,
                    &sender_keys,
                    TransactionIntent::PrivateBalanceConfidentialTransfer {
                        sender_cell_id,
                        sender_agent_id,
                        recipient_cell_id,
                        amount_commitment,
                        stark_proof: stark_proof.clone(),
                        sender_new_encrypted: sender_new_encrypted.clone(),
                        sender_new_commitment,
                        sender_new_commit_nonce,
                        sender_old_commitment,
                        recipient_new_encrypted: recipient_new_encrypted.clone(),
                        recipient_new_commitment,
                        recipient_new_commit_nonce,
                        recipient_old_commitment,
                    },
                )?;
                if let Some(map) = res.as_object_mut() {
                    map.insert(
                        "private_balance_confidential_transfer".to_string(),
                        serde_json::json!({
                            "sender_cell_id": hex::encode(sender_cell_id),
                            "sender_agent_id": hex::encode(sender_agent_id),
                            "recipient_cell_id": hex::encode(recipient_cell_id),
                            "amount_commitment": hex::encode(amount_commitment),
                            "sender_new_commitment": hex::encode(sender_new_commitment),
                            "recipient_new_commitment": hex::encode(recipient_new_commitment),
                            "proof_len": stark_proof.len(),
                            "proof_hash": proof_hash,
                            "fee_multiplier": 3
                        }),
                    );
                }
                print_output(&res, output)?;
            }
            McpCommand::ToolCall {
                from,
                tool_id,
                policy_cell_id,
                action_log_id,
                calldata_hex,
                calldata_file,
                value,
                gas_limit,
            } => {
                let (sender_id, sender_keys) = load_account_id_and_keypair_arg(from.as_deref(), config.as_ref())?;
                let tool_id = parse_hex_32("tool_id", &tool_id)?;
                let policy_cell = parse_hex_32("policy_cell_id", &policy_cell_id)?;
                let action_log = if let Some(id) = action_log_id {
                    parse_hex_32("action_log_id", &id)?
                } else {
                    truthlinked_mcp::protocol_addresses::action_log()
                };
                let calldata = if let Some(hex) = calldata_hex {
                    parse_hex_bytes("calldata_hex", &hex)?
                } else if let Some(path) = calldata_file {
                    load_bytes(&path)?
                } else {
                    Vec::new()
                };

                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let nonce = next_nonce(&client, &rpc, &sender_id, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let tx = Transaction {
                    sender: sender_id,
                    intent: TransactionIntent::McpToolCall {
                        agent_id: sender_id,
                        tool_id,
                        tool_calldata: calldata,
                        value,
                        gas_limit,
                        policy_cell_id: policy_cell,
                        action_log_id: Some(action_log),
                        timestamp,
                    },
                    signature: vec![],
                    nonce,
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: u64::MAX,
                };
                let signed = sender_keys.sign_transaction(&tx)?;
                let bytes = postcard::to_allocvec(&signed)?;
                let res: Value =
                    post_bytes(&client, &format!("{}/submit_raw", rpc), bytes, cli.retries)?;
                print_output(&res, output)?;
            }
        },

        Commands::Send { action } => match action {
            SendAction::Native { recipient: initial_recipient, amount: initial_amount, from } => {
                // Interactive native send (recipient/amount optional -> prompts)
                let mut current_recipient = initial_recipient;
                let recipient_spec = loop {
                    let r = match current_recipient.take() {
                        Some(val) => val,
                        None => prompt_line("Recipient (name ending in .tl, account ID, or pubkey)")?,
                    };
                    match parse_recipient_input(&r) {
                        Ok(spec) => break spec,
                        Err(e) => {
                            eprintln!("Corporate Exception Handling Engine: Command execution failed with exception: {}", e);
                        }
                    }
                };
                let mut current_amount = initial_amount;
                let amount_raw = loop {
                    let a = match current_amount.take() {
                        Some(val) => val,
                        None => prompt_line("Amount (e.g. 10 or 1.5k TLKD)")?,
                    };
                    match parse_amount_str(&a) {
                        Ok(val) => break val,
                        Err(e) => {
                            eprintln!("Corporate Exception Handling Engine: Command execution failed with exception: {}", e);
                        }
                    }
                };
                let from_path = resolve_signing_keyfile_arg(from.as_deref(), config.as_ref())?;

                if amount_raw == 0 {
                    return Err("Amount must be > 0".into());
                }
                if amount_raw >= (LARGE_TRANSFER_TLKD as u128) * truthlinked_core::ONE_TLKD {
                    confirm_or_abort(cli.yes, output, "Large transfer — are you sure?")?;
                }
                let (sender_keys, sender_pubkey) = load_keypair_and_pubkey(&from_path)?;
                let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let amount_units = amount_raw;

                let intent = match recipient_spec {
                    RecipientInput::Name(name) => pq_execution::TransactionIntent::TransferToName {
                        name,
                        amount: amount_units,
                    },
                    RecipientInput::AccountId(recipient_id) => {
                        pq_execution::TransactionIntent::Transfer {
                            recipient: recipient_id,
                            recipient_pubkey: None,
                            amount: amount_units,
                        }
                    }
                    RecipientInput::Pubkey(pubkey) => {
                        let recipient_id = pq_identity::account_id_from_pubkey(&pubkey);
                        pq_execution::TransactionIntent::Transfer {
                            recipient: recipient_id,
                            recipient_pubkey: Some(pubkey),
                            amount: amount_units,
                        }
                    }
                };

                let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
                let tx = pq_execution::Transaction {
                    sender: sender_account_id,
                    intent,
                    signature: vec![],
                    nonce,
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: get_expiration_height(&client, &rpc, cli.retries)?,
                };
                let signed = sender_keys.sign_transaction(&tx)?;
                let tx_bytes = postcard::to_allocvec(&signed)?;
                let res = post_bytes(
                    &client,
                    &format!("{}/submit_raw", rpc),
                    tx_bytes,
                    cli.retries,
                )?;
                print_output(&res, output)?;
            }

            SendAction::Nft { nft_id, recipient, price, from } => {
                // Send NFT (uses unified recipient parser supporting .tl names)
                let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
                let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
                let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

                let nft_id_bytes = hex::decode(&nft_id)?;
                if nft_id_bytes.len() != 32 {
                    return Err("nft_id must be 32 bytes (64 hex chars)".into());
                }
                let mut nft_id_arr = [0u8; 32];
                nft_id_arr.copy_from_slice(&nft_id_bytes);

                let sale_price = if let Some(p) = price {
                    let parsed = parse_amount_str(&p)?;
                    if parsed == 0 {
                        return Err("price must be > 0 if provided".into());
                    }
                    Some(parsed)
                } else {
                    None
                };

                // Use the unified recipient parser (supports .tl names)
                let recipient_spec = parse_recipient_input(&recipient)
                    .map_err(|e| format!("Bad recipient for NFT send: {}", e))?;

                let (recipient_account_id, recipient_pubkey_vec) = match recipient_spec {
                    RecipientInput::AccountId(id) => (id, None),
                    RecipientInput::Pubkey(pk) => {
                        if pk.len() != 1952 {
                            return Err("Recipient pubkey must be 1952 bytes (3904 hex)".into());
                        }
                        let acct = pq_identity::account_id_from_pubkey(&pk);
                        (acct, Some(pk))
                    }
                    RecipientInput::Name(name) => {
                        // Resolve .tl name via RPC for the TransferNFT intent
                        let q = urlencoding::encode(&name);
                        let res: Value = get_json(&client, &format!("{}/resolve/{}", rpc, q), cli.retries)?;
                        let acct_hex = res.get("account_id")
                            .and_then(|v| v.as_str())
                            .ok_or("Could not resolve .tl name to account for NFT send")?;
                        let acct_bytes = hex::decode(acct_hex)?;
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&acct_bytes);
                        (id, None)
                    }
                };

                // Ownership / approval check
                let nft_info: Value = get_json(&client, &format!("{}/nft/{}", rpc, nft_id), cli.retries)?;
                if !nft_info.get("found").and_then(|v| v.as_bool()).unwrap_or(false) {
                    return Err("NFT not found".into());
                }
                let owner = nft_info["nft"]["owner"].as_str().unwrap_or("");
                let approved = nft_info["nft"]["approved"].as_str().unwrap_or("");
                let sender_hex = hex::encode(&sender_account_id);
                if owner != sender_hex && approved != sender_hex {
                    return Err("Sender is not owner or approved operator".into());
                }

                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

                let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
                let tx = pq_execution::Transaction {
                    nonce,
                    sender: sender_account_id,
                    intent: pq_execution::TransactionIntent::TransferNFT {
                        nft_id: nft_id_arr,
                        recipient: recipient_account_id,
                        recipient_pubkey: recipient_pubkey_vec,
                        sale_price,
                    },
                    signature: vec![],
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: u64::MAX,
                };
                let signed_tx = sender_keys.sign_transaction(&tx)?;
                let tx_bytes = postcard::to_allocvec(&signed_tx)?;

                let res: Value = post_bytes(
                    &client,
                    &format!("{}/submit_raw", rpc),
                    tx_bytes,
                    cli.retries,
                )?;
                print_output(&res, output)?;
            }

            SendAction::Token { token, recipient, amount, from } => {
                let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
                let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
                let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

                let amount_raw = parse_amount_str(&amount)?;
                if amount_raw == 0 {
                    return Err("amount must be > 0".into());
                }

                let token_bytes = hex::decode(&token)?;
                if token_bytes.len() != 32 {
                    return Err("token must be 32 bytes (64 hex chars)".into());
                }
                let mut token_arr = [0u8; 32];
                token_arr.copy_from_slice(&token_bytes);

                // Recipient support (.tl names, accounts, pubkeys)
                let recipient_spec = parse_recipient_input(&recipient)
                    .map_err(|e| format!("Bad recipient: {}", e))?;

                let to_arr = match recipient_spec {
                    RecipientInput::AccountId(id) => id,
                    RecipientInput::Pubkey(pk) => {
                        if pk.len() != 1952 {
                            return Err("Recipient pubkey must be 1952 bytes (3904 hex)".into());
                        }
                        pq_identity::account_id_from_pubkey(&pk)
                    }
                    RecipientInput::Name(name) => {
                        let q = urlencoding::encode(&name);
                        let res: Value = get_json(&client, &format!("{}/resolve/{}", rpc, q), cli.retries)?;
                        let hex = res.get("account_id").and_then(|v| v.as_str()).ok_or("Could not resolve recipient name")?;
                        let bytes = hex::decode(hex)?;
                        if bytes.len() != 32 {
                            return Err("Resolved account ID is invalid".into());
                        }
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&bytes);
                        id
                    }
                };

                require_token_cell(&client, &rpc, &token, cli.retries)?;
                require_account_exists(&client, &rpc, &hex::encode(&to_arr))?;

                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

                let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
                let tx = pq_execution::Transaction {
                    nonce,
                    sender: sender_account_id,
                    intent: pq_execution::TransactionIntent::TokenTransfer {
                        token_cell: token_arr,
                        recipient: to_arr,
                        amount: amount_raw,
                    },
                    signature: vec![],
                    timestamp,
                    genesis_fingerprint: genesis_hash,
                    expiration_height: u64::MAX,
                };
                let signed_tx = sender_keys.sign_transaction(&tx)?;
                let tx_bytes = postcard::to_allocvec(&signed_tx)?;

                let res: Value = post_bytes(
                    &client,
                    &format!("{}/submit_raw", rpc),
                    tx_bytes,
                    cli.retries,
                )?;

                print_output(&res, output)?;
            }
        }


        Commands::DepositCompute { from, amount } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let amount_raw = parse_amount_str(&amount)?;
            if amount_raw == 0 {
                return Err("amount must be > 0".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::DepositCompute { amount: amount_raw },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }
        Commands::WithdrawCompute { from, amount } => {
            confirm_or_abort(cli.yes, output, "Withdraw compute escrow; confirm")?;
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let amount_raw = parse_amount_str(&amount)?;
            if amount_raw == 0 {
                return Err("amount must be > 0".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::WithdrawCompute { amount: amount_raw },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res: Value = client
                .post(format!("{}/submit_raw", rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?
                .json()?;

            print_output(&res, output)?;
        }
        Commands::BatchTransfer {
            from,
            to_pubkeys,
            amounts,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            let recipients: Vec<&str> = to_pubkeys.split(',').map(|s| s.trim()).collect();
            let amounts_vec: Vec<u128> = amounts
                .split(',')
                .map(|s| {
                    let s = s.trim();
                    let amt = parse_tlkd_amount(s)?;
                    Ok(amt)
                })
                .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

            if recipients.len() != amounts_vec.len() {
                return Err("Number of recipients must match number of amounts".into());
            }

            if recipients.is_empty() {
                return Err("No recipients provided".into());
            }
            if recipients.len() > constants::MAX_BATCH_TRANSFER_RECIPIENTS {
                return Err(format!(
                    "Too many recipients: {} (max: {})",
                    recipients.len(),
                    constants::MAX_BATCH_TRANSFER_RECIPIENTS
                )
                .into());
            }

            eprintln!("✦ Batch Scheduler: Compiling {} concurrent transactions into transaction block...", recipients.len());

            let balance_res = post_json(
                &client,
                &format!("{}/balance", rpc),
                serde_json::json!({"account_id": hex::encode(&sender_account_id)}),
                cli.retries,
            )?;

            let sender_balance: u128 = balance_res["balance"]
                .as_str()
                .and_then(|v| v.parse::<u128>().ok())
                .unwrap_or(0);

            let mut total_amount: u128 = 0;
            let mut parsed_recipients = Vec::with_capacity(recipients.len());
            for (i, (recipient_raw, amount)) in
                recipients.iter().zip(amounts_vec.iter()).enumerate()
            {
                if *amount == 0 {
                    return Err(format!("Amount at index {} must be > 0", i).into());
                }
                total_amount = total_amount.saturating_add(*amount);
                let spec = parse_recipient_spec(recipient_raw)?;
                parsed_recipients.push((spec, *amount));
            }

            if total_amount >= (LARGE_TRANSFER_TLKD as u128) * ONE_TLKD {
                confirm_or_abort(cli.yes, output, "Large batch transfer; confirm")?;
            }

            let est_gas =
                (recipients.len() as u128) * (truthlinked_core::constants::GAS_TRANSFER as u128);
            let est_total = total_amount.saturating_add(est_gas);
            if sender_balance < est_total {
                return Err(format!(
                    "Insufficient balance for batch transfer: need {}, have {}",
                    est_total, sender_balance
                )
                .into());
            }
            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let has_names = parsed_recipients
                .iter()
                .any(|(spec, _)| matches!(spec, RecipientSpec::Name(_)));
            let intent = if has_names {
                if parsed_recipients
                    .iter()
                    .any(|(spec, _)| !matches!(spec, RecipientSpec::Name(_)))
                {
                    return Err(
                        "BatchTransferToName requires all recipients to be .tl names".into(),
                    );
                }
                let transfers = parsed_recipients
                    .into_iter()
                    .map(|(spec, amount)| match spec {
                        RecipientSpec::Name(name) => {
                            pq_execution::NameTransferEntry { name, amount }
                        }
                        _ => unreachable!(),
                    })
                    .collect();
                pq_execution::TransactionIntent::BatchTransferToName { transfers }
            } else {
                let transfers = parsed_recipients
                    .into_iter()
                    .map(|(spec, amount)| match spec {
                        RecipientSpec::AccountId(recipient) => pq_execution::BatchTransferEntry {
                            recipient,
                            recipient_pubkey: None,
                            amount,
                        },
                        RecipientSpec::Pubkey(recipient_pubkey) => {
                            let recipient = pq_identity::account_id_from_pubkey(&recipient_pubkey);
                            pq_execution::BatchTransferEntry {
                                recipient,
                                recipient_pubkey: Some(recipient_pubkey),
                                amount,
                            }
                        }
                        RecipientSpec::Name(_) => unreachable!(),
                    })
                    .collect();
                pq_execution::TransactionIntent::BatchTransfer { transfers }
            };

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent,
                signature: vec![],
                nonce,
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("✦ Network Engine: Pushing transaction block array to consensus mempool...");
            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }
        Commands::ValidatorSetup { from, amount } => {
            let keyfile = resolve_signing_keyfile_arg(from.as_deref(), config.as_ref())?;
            let sender_keys = pq_identity::DualKeypair::load(&keyfile)?;

            if output == OutputFormat::Pretty {
                eprintln!("✦ Network Engine: Initiating staking bond sequence for {} TLKD...", amount);
            }
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let amount_raw = parse_amount_str(&amount)?;
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }

            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;
            let calldata = encode_staking_stake(&sender_pubkey, amount_u64)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();
            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            if res
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                let tx_hash = res
                    .get("tx_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                if output == OutputFormat::Pretty {
                    eprintln!("✦ Network Engine: Cryptographic deposit locked. Bonded {} TLKD.", amount);
                    eprintln!("  └─ Consensus TX Hash Reference: 0x{}", tx_hash);
                    eprintln!("\n✦ Operational Status: Validator Node Setup Finalized.");
                    eprintln!("   ├─ Core Node Status:  Active Consensus Participant");
                    eprintln!("   └─ Tokenized Stake:   {} TLKD", amount);
                }
            } else if output == OutputFormat::Pretty {
                eprintln!(" Bonding failed: {}", json_string(&res, output)?);
            }
            print_output(&res, output)?;
        }
        Commands::Bond { from, amount } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let amount_raw = parse_amount_str(&amount)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }

            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;
            let calldata = encode_staking_stake(&sender_pubkey, amount_u64)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();
            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }
        Commands::Stake { amount, from } => {
            let amount_raw = match amount {
                Some(a) => a,
                None => prompt_line("Amount (TLKD)")?,
            };
            let amount_raw = parse_amount_str(&amount_raw)?;
            let from_path = resolve_signing_keyfile_arg(from.as_deref(), config.as_ref())?;
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }
            let sender_keys = pq_identity::DualKeypair::load(&from_path)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;
            let calldata = encode_staking_stake(&sender_pubkey, amount_u64)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();
            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }
        Commands::Unbond { from, amount } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let amount_raw = parse_amount_str(&amount)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }
            confirm_or_abort(cli.yes, output, "Unbond stake; confirm")?;

            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;
            let calldata = encode_staking_unstake(&sender_pubkey, amount_u64)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();
            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }
        Commands::Withdraw { from } => {
            confirm_or_abort(cli.yes, output, "Withdraw stake; confirm")?;
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_withdraw(&sender_pubkey)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();
            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::Unjail { from } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_unjail(&sender_pubkey)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();
            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::DelegateAdd {
            from,
            delegate_pubkey,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let delegate_bytes = hex::decode(&delegate_pubkey)?;
            if delegate_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("delegate_pubkey must be 1952 bytes".into());
            }
            let delegate_account = pq_identity::account_id_from_pubkey(&delegate_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_delegate_add(delegate_account);
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }

        Commands::DelegateRemove {
            from,
            delegate_pubkey,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let delegate_bytes = hex::decode(&delegate_pubkey)?;
            if delegate_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("delegate_pubkey must be 1952 bytes".into());
            }
            let delegate_account = pq_identity::account_id_from_pubkey(&delegate_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_delegate_remove(delegate_account);
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }

        Commands::StakeFor {
            from,
            owner_pubkey,
            amount,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let owner_pubkey_bytes = hex::decode(&owner_pubkey)?;
            if owner_pubkey_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("owner_pubkey must be 1952 bytes".into());
            }
            let owner_account = pq_identity::account_id_from_pubkey(&owner_pubkey_bytes);

            let amount_raw = parse_amount_str(&amount)?;
            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata =
                encode_staking_stake_for(owner_account, &owner_pubkey_bytes, amount_u64)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }

        Commands::UnstakeFor {
            from,
            owner_pubkey,
            amount,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let owner_pubkey_bytes = hex::decode(&owner_pubkey)?;
            if owner_pubkey_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("owner_pubkey must be 1952 bytes".into());
            }
            let owner_account = pq_identity::account_id_from_pubkey(&owner_pubkey_bytes);

            let amount_raw = parse_amount_str(&amount)?;
            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata =
                encode_staking_unstake_for(owner_account, &owner_pubkey_bytes, amount_u64)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }

        Commands::WithdrawFor { from, owner_pubkey } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let owner_pubkey_bytes = hex::decode(&owner_pubkey)?;
            if owner_pubkey_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("owner_pubkey must be 1952 bytes".into());
            }
            let owner_account = pq_identity::account_id_from_pubkey(&owner_pubkey_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_withdraw_for(owner_account, &owner_pubkey_bytes)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }

        Commands::UnjailFor { from, owner_pubkey } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let owner_pubkey_bytes = hex::decode(&owner_pubkey)?;
            if owner_pubkey_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("owner_pubkey must be 1952 bytes".into());
            }
            let owner_account = pq_identity::account_id_from_pubkey(&owner_pubkey_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_unjail_for(owner_account, &owner_pubkey_bytes)?;
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }

        Commands::StakedTlkdLock {
            from,
            amount,
            lock_blocks,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            let owner = sender_account_id;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let amount_raw = parse_amount_str(&amount)?;
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }
            let calldata = encode_staking_lock(owner, lock_blocks);
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: amount_raw,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }

        Commands::StakedTlkdExtend { from, lock_blocks } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            let owner = sender_account_id;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_extend(owner, lock_blocks);
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }

        Commands::StakedTlkdUnlock { from } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            let owner = sender_account_id;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_unlock(owner);
            let cell_id = truthlinked_core::pq_execution::staking_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;
            print_output(&res, output)?;
        }

        Commands::TreasuryProposeSpend {
            from,
            recipient,
            amount,
            timelock_blocks,
            proposal_id,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let recipient_id = parse_account_id_hex(&recipient)?;
            let proposal_id = if let Some(hex_val) = proposal_id {
                parse_account_id_hex(&hex_val)?
            } else {
                let mut id = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut id);
                id
            };

            let amount_raw = parse_amount_str(&amount)?;
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }

            let calldata =
                encode_treasury_propose(proposal_id, recipient_id, amount_raw, timelock_blocks);
            let cell_id = truthlinked_core::pq_execution::treasury_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            if output == OutputFormat::Pretty {
                eprintln!(
                    "   Proposal ID: {}",
                    format_address(&hex::encode(proposal_id))
                );
            }
            print_output(&res, output)?;
        }

        Commands::TreasuryVoteSpend {
            from,
            proposal_id,
            approve,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let proposal_id = parse_account_id_hex(&proposal_id)?;
            let calldata = encode_treasury_vote(proposal_id, approve);
            let cell_id = truthlinked_core::pq_execution::treasury_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::TreasuryExecuteSpend { from, proposal_id } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let proposal_id = parse_account_id_hex(&proposal_id)?;
            let calldata = encode_treasury_execute(proposal_id);
            let cell_id = truthlinked_core::pq_execution::treasury_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::TreasuryProposalInfo { proposal_id } => {
            let _ = parse_account_id_hex(&proposal_id)?;
            let res: Value = client
                .get(format!("{}/treasury_proposal/{}", rpc, proposal_id))
                .send()?
                .json()?;
            print_output(&res, output)?;
        }



        Commands::Nft { action } => match action {
            NftAction::Mint { from, nft_id, name, metadata_uri, collection, royalty_bps, royalty_recipient } => {
                let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
                let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
                let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
                let nft_id_bytes = hex::decode(&nft_id)?; if nft_id_bytes.len() != 32 { return Err("nft_id 32 bytes".into()); }
                let mut nft_id_arr = [0u8; 32]; nft_id_arr.copy_from_slice(&nft_id_bytes);
                let collection_arr = collection.as_ref().and_then(|c| hex::decode(c).ok().filter(|b|b.len()==32).map(|b| {let mut a=[0u8;32];a.copy_from_slice(&b);a}));
                let royalty_recipient_id = royalty_recipient.as_ref().and_then(|r| hex::decode(r).ok().filter(|b|b.len()==32).map(|b| {let mut a=[0u8;32];a.copy_from_slice(&b);a}));
                if royalty_bps > 10_000 { return Err("royalty_bps 0-10000".into()); }
                let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
                let tx = pq_execution::Transaction {
                    nonce, sender: sender_account_id,
                    intent: pq_execution::TransactionIntent::MintNFT { nft_id: nft_id_arr, name, metadata_uri, collection: collection_arr, royalty_bps, royalty_recipient: royalty_recipient_id },
                    signature: vec![], timestamp, genesis_fingerprint: genesis_hash, expiration_height: u64::MAX,
                };
                let signed_tx = sender_keys.sign_transaction(&tx)?;
                let tx_bytes = postcard::to_allocvec(&signed_tx)?;
                let res: Value = post_bytes(&client, &format!("{}/submit_raw", rpc), tx_bytes, cli.retries)?;
                print_output(&res, output)?;
            }
            NftAction::Send { nft_id, recipient, price, from } => {
                // NFT transfer using recipient parser + ownership check
                let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
                let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
                let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
                let nft_id_bytes = hex::decode(&nft_id)?; if nft_id_bytes.len() != 32 { return Err("nft_id 32 bytes".into()); }
                let mut nft_id_arr = [0u8; 32]; nft_id_arr.copy_from_slice(&nft_id_bytes);
                let sale_price = price.as_ref().and_then(|p| parse_amount_str(p).ok());
                let recipient_spec = parse_recipient_input(&recipient).map_err(|e| format!("recipient: {}", e))?;
                let (rec_id, rec_pk) = match recipient_spec {
                    RecipientInput::AccountId(id) => (id, None),
                    RecipientInput::Pubkey(pk) => (pq_identity::account_id_from_pubkey(&pk), Some(pk)),
                    RecipientInput::Name(nm) => {
                        let q = urlencoding::encode(&nm);
                        let r: Value = get_json(&client, &format!("{}/resolve/{}", rpc, q), cli.retries)?;
                        let hx = r.get("account_id").and_then(|v| v.as_str()).ok_or("resolve")?;
                        let b = hex::decode(hx)?; let mut id=[0u8;32]; id.copy_from_slice(&b); (id, None)
                    }
                };
                // Ownership check
                let info: Value = get_json(&client, &format!("{}/nft/{}", rpc, nft_id), cli.retries)?;
                if !info.get("found").and_then(|v| v.as_bool()).unwrap_or(false) { return Err("NFT not found".into()); }
                let owner = info["nft"]["owner"].as_str().unwrap_or("");
                let appr = info["nft"]["approved"].as_str().unwrap_or("");
                let me = hex::encode(&sender_account_id);
                if owner != me && appr != me { return Err("not owner/approved".into()); }
                let genesis = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
                let tx = pq_execution::Transaction {
                    nonce, sender: sender_account_id,
                    intent: pq_execution::TransactionIntent::TransferNFT { nft_id: nft_id_arr, recipient: rec_id, recipient_pubkey: rec_pk, sale_price },
                    signature: vec![], timestamp: ts, genesis_fingerprint: genesis, expiration_height: u64::MAX,
                };
                let stx = sender_keys.sign_transaction(&tx)?; let b = postcard::to_allocvec(&stx)?;
                let res: Value = post_bytes(&client, &format!("{}/submit_raw", rpc), b, cli.retries)?;
                print_output(&res, output)?;
            }
            NftAction::Burn { from, nft_id } => {
                confirm_or_abort(cli.yes, output, "Burn NFT forever?")?;
                let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
                let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
                let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
                let b = hex::decode(&nft_id)?; if b.len() != 32 { return Err("32 byte nft_id".into()); }
                let mut arr = [0u8;32]; arr.copy_from_slice(&b);
                let genesis = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
                let tx = pq_execution::Transaction {
                    nonce, sender: sender_account_id,
                    intent: pq_execution::TransactionIntent::BurnNFT { nft_id: arr },
                    signature: vec![], timestamp: ts, genesis_fingerprint: genesis, expiration_height: u64::MAX,
                };
                let stx = sender_keys.sign_transaction(&tx)?; let bb = postcard::to_allocvec(&stx)?;
                let res: Value = post_bytes(&client, &format!("{}/submit_raw", rpc), bb, cli.retries)?;
                print_output(&res, output)?;
            }
            NftAction::Approve { from, nft_id, approved } => {
                let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
                let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
                let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
                let b = hex::decode(&nft_id)?; if b.len() != 32 { return Err("32 byte nft_id".into()); }
                let mut arr = [0u8;32]; arr.copy_from_slice(&b);
                let appr = approved.as_ref().and_then(|a| {
                    if a.to_lowercase()=="none"||a.is_empty(){return None;}
                    parse_recipient_input(a).ok().and_then(|spec| match spec {
                        RecipientInput::AccountId(id)=>Some(id),
                        RecipientInput::Pubkey(pk)=>Some(pq_identity::account_id_from_pubkey(&pk)),
                        _ => None,
                    })
                });
                let genesis = fetch_genesis_hash(&client, &rpc, cli.retries)?;
                let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
                let tx = pq_execution::Transaction {
                    nonce, sender: sender_account_id,
                    intent: pq_execution::TransactionIntent::ApproveNFT { nft_id: arr, approved: appr },
                    signature: vec![], timestamp: ts, genesis_fingerprint: genesis, expiration_height: u64::MAX,
                };
                let stx = sender_keys.sign_transaction(&tx)?; let bb = postcard::to_allocvec(&stx)?;
                let res: Value = post_bytes(&client, &format!("{}/submit_raw", rpc), bb, cli.retries)?;
                print_output(&res, output)?;
            }
            NftAction::Info { nft_id } => {
                let res: Value = get_json(&client, &format!("{}/nft/{}", rpc, nft_id), cli.retries)?;
                print_output(&res, output)?;
            }
            NftAction::List { account } => {
                let owner = if let Some(a) = account {
                    if a.ends_with(".tl") {
                        let q = urlencoding::encode(&a); let r: Value = get_json(&client, &format!("{}/resolve/{}", rpc, q), cli.retries)?; hex::decode(r.get("account_id").and_then(|v|v.as_str()).unwrap_or(""))?
                    } else if a.len()==64 { hex::decode(&a)? } else {
                        let p = resolve_signing_keyfile_arg(Some(&*a), config.as_ref())?; let pk = pq_identity::DualKeypair::load(&p)?; pq_identity::account_id_from_pubkey(&pk.dilithium_pk.clone().into_bytes()).to_vec()
                    }
                } else {
                    let p = resolve_signing_keyfile_arg(None, config.as_ref())?; let pk = pq_identity::DualKeypair::load(&p)?; pq_identity::account_id_from_pubkey(&pk.dilithium_pk.clone().into_bytes()).to_vec()
                };
                if owner.len()!=32 { return Err("owner".into()); }
                let mut arr=[0u8;32]; arr.copy_from_slice(&owner);
                let res: Value = get_json(&client, &format!("{}/nfts/{}", rpc, hex::encode(arr)), cli.retries)?;
                print_output(&res, output)?;
            }
        }

        Commands::DeployCell {
            from,
            cell_id,
            source,
            bytecode_file,
            initial_balance,
            manifest_file,
        } => {
            let (axiom_path, manifest_path) = if let Some(src) = source {
                eprintln!("✦ [1/2] Compiling target cell architecture directly from source context...");
                let (wasm, manifest) = build_cell(&src, None)?;
                (wasm, Some(manifest))
            } else if let Some(wasm) = bytecode_file {
                let manifest = manifest_file.or_else(|| {
                    let auto_manifest_path = wasm.replace(".axiom", ".manifest.json");
                    if std::path::Path::new(&auto_manifest_path).exists() {
                        eprintln!("✦ [2/2] Local structural manifest discovered at track reference: {}", auto_manifest_path);
                        Some(auto_manifest_path)
                    } else {
                        None
                    }
                });
                (wasm, manifest)
            } else {
                return Err("Must provide either --source or --bytecode-file".into());
            };

            let from = resolve_signing_keyfile_arg(from.as_deref(), config.as_ref())?;
            submit_cell_deploy(
                &client,
                &rpc,
                &from,
                &cell_id,
                &axiom_path,
                manifest_path,
                initial_balance,
                output,
                cli.retries,
            )?;
        }
        Commands::Deploy {
            cell_id,
            source,
            from,
        } => {
            let cell_id = match cell_id {
                Some(c) => c,
                None => prompt_line("Cell id (hex)")?,
            };
            let source = match source {
                Some(s) => s,
                None => prompt_line("Source (file path)")?,
            };
            let from = resolve_signing_keyfile_arg(from.as_deref(), config.as_ref())?;
            submit_cell_deploy(
                &client,
                &rpc,
                &from,
                &cell_id,
                &source,
                None,
                0,
                output,
                cli.retries,
            )?;
        }

        Commands::DeployToken {
            from,
            cell_id,
            name,
            symbol,
            decimals,
            supply,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let pubkey = sender_keys.dilithium_pk.clone().into_bytes();
            let sender_account_id = truthlinked_core::pq_identity::account_id_from_pubkey(&pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = Transaction {
                nonce,
                sender: sender_account_id,
                intent: TransactionIntent::DeployToken {
                    cell_id: cell_id_arr,
                    name,
                    symbol,
                    decimals,
                    total_supply: supply,
                    transfer_fee_bps: 0,
                    transfer_fee_recipient: None,
                    non_transferable: false,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("✦ Network Engine: Disbursing tokenized smart asset deployment across environment...");
            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::CallCell {
            from,
            cell_id,
            calldata,
            value,
            gas_limit,
            simulate,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let pubkey = sender_keys.dilithium_pk.clone().into_bytes();
            let sender_account_id = truthlinked_core::pq_identity::account_id_from_pubkey(&pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let calldata_bytes = hex::decode(&calldata)?;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = Transaction {
                nonce,
                sender: sender_account_id,
                intent: TransactionIntent::CallCell {
                    cell_id: cell_id_arr,
                    calldata: calldata_bytes,
                    value: value as u128,
                    gas_limit,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let endpoint = if simulate {
                "simulate_raw"
            } else {
                "submit_raw"
            };
            if simulate {
                eprintln!("✦ Simulation Engine: Running speculative local call transaction against block height...");
                eprintln!("  (Executing contract verification locally. Matrix states remain uncommitted to consensus.)");
            } else {
                eprintln!("✦ Network Engine: Transmitting execution call signature to network cell matrix...");
            }
            let res: Value = post_bytes(
                &client,
                &format!("{}/{}", rpc, endpoint),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::UpgradeCell {
            from,
            cell_id,
            source,
            bytecode_file,
            manifest_file,
        } => {
            let (axiom_path, manifest_path) = if let Some(src) = source {
                eprintln!("✦ [1/2] Compiling target cell architecture directly from source context...");
                let (wasm, manifest) = build_cell(&src, None)?;
                (wasm, Some(manifest))
            } else if let Some(wasm) = bytecode_file {
                let manifest = manifest_file.or_else(|| {
                    let auto_manifest = wasm.replace(".axiom", ".manifest.json");
                    if std::path::Path::new(&auto_manifest).exists() {
                        eprintln!("✦ [2/2] Network configuration mapping structural manifest matched at: {}", auto_manifest);
                        Some(auto_manifest)
                    } else {
                        None
                    }
                });
                (wasm, manifest)
            } else {
                return Err("Must provide either --source or --bytecode-file".into());
            };

            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let pubkey = sender_keys.dilithium_pk.clone().into_bytes();
            let sender_account_id = truthlinked_core::pq_identity::account_id_from_pubkey(&pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let new_bytecode = std::fs::read(&axiom_path)?;
            let (
                new_declared_reads,
                new_declared_writes,
                new_commutative_keys,
                new_storage_key_specs,
                new_oracle_schema_ids,
            ) = if let Some(manifest_path) = manifest_path {
                let (
                    new_declared_reads,
                    new_declared_writes,
                    new_commutative_keys,
                    new_storage_key_specs,
                    new_oracle_schema_ids,
                ) = load_manifest_sets(&manifest_path)?;
                truthlinked_core::cells::CellAccount::verify_manifest_against_bytecode(
                    &new_bytecode,
                    &new_declared_reads,
                    &new_declared_writes,
                    &new_storage_key_specs,
                )?;

                eprintln!("✦ Validation Engine: Contract integrity and manifest parameters verified locally.");
                (
                    new_declared_reads,
                    new_declared_writes,
                    new_commutative_keys,
                    new_storage_key_specs,
                    new_oracle_schema_ids,
                )
            } else {
                let analysis =
                    truthlinked_core::cells::CellAccount::analyze_bytecode(&new_bytecode)
                        .map_err(|e| format!("Axiom static analysis failed: {}", e))?;
                (
                    analysis.static_read_slots,
                    analysis.static_write_slots,
                    vec![],
                    vec![],
                    vec![],
                )
            };

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = Transaction {
                nonce,
                sender: sender_account_id,
                intent: TransactionIntent::UpgradeCell {
                    cell_id: cell_id_arr,
                    new_bytecode,
                    new_declared_reads,
                    new_declared_writes,
                    new_commutative_keys,
                    new_storage_key_specs,
                    new_oracle_schema_ids,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("✦ Network Engine: Packaging cell instruction upgrades for ledger state transition...");
            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::RotateKey { from, new_pubkey } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let new_pubkey_bytes = hex::decode(&new_pubkey)?;
            if new_pubkey_bytes.len() != 1952 {
                return Err("new_pubkey must be 1952 bytes (3904 hex chars)".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::RotateKey {
                    new_pubkey: new_pubkey_bytes,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::AcceptOwnership { from, cell_id } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::AcceptOwnership {
                    cell_id: cell_id_arr,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::MakeImmutable { from, cell_id } => {
            confirm_or_abort(cli.yes, output, "Make cell immutable; confirm")?;
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let cell_info = require_cell_exists(&client, &rpc, &cell_id, cli.retries)?;
            if cell_info.immutable {
                return Err("cell is already immutable".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::MakeImmutable {
                    cell_id: cell_id_arr,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::CloseCell { from, cell_id } => {
            confirm_or_abort(cli.yes, output, "Close cell; confirm")?;
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let cell_info = require_cell_exists(&client, &rpc, &cell_id, cli.retries)?;
            if cell_info.immutable {
                return Err("cell is immutable".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CloseCell {
                    cell_id: cell_id_arr,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::ProposeCellUpgrade {
            from,
            cell_id,
            source,
            bytecode_file,
            manifest_file,
            timelock_blocks,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let (axiom_path, manifest_path) = if let Some(src) = source {
                eprintln!("✦ [1/2] Compiling target cell architecture directly from source context...");
                let (wasm, manifest) = build_cell(&src, None)?;
                (wasm, Some(manifest))
            } else if let Some(wasm) = bytecode_file {
                let manifest = manifest_file.or_else(|| {
                    let auto_manifest = wasm.replace(".axiom", ".manifest.json");
                    if std::path::Path::new(&auto_manifest).exists() {
                        eprintln!("✦ [2/2] Network configuration mapping structural manifest matched at: {}", auto_manifest);
                        Some(auto_manifest)
                    } else {
                        None
                    }
                });
                (wasm, manifest)
            } else {
                return Err("Must provide either --source or --bytecode-file".into());
            };

            let new_bytecode = std::fs::read(&axiom_path)?;
            let (
                declared_reads,
                declared_writes,
                commutative_keys,
                storage_key_specs,
                new_oracle_schema_ids,
            ) = if let Some(manifest_path) = manifest_path {
                let (reads, writes, commutative, specs, schema_ids) =
                    load_manifest_sets(&manifest_path)?;
                truthlinked_core::cells::CellAccount::verify_manifest_against_bytecode(
                    &new_bytecode,
                    &reads,
                    &writes,
                    &specs,
                )?;
                (reads, writes, commutative, specs, schema_ids)
            } else {
                let analysis =
                    truthlinked_core::cells::CellAccount::analyze_bytecode(&new_bytecode)
                        .map_err(|e| format!("Axiom static analysis failed: {}", e))?;
                (
                    analysis.static_read_slots,
                    analysis.static_write_slots,
                    vec![],
                    vec![],
                    vec![],
                )
            };

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::ProposeCellUpgrade {
                    cell_id: cell_id_arr,
                    new_bytecode,
                    new_declared_reads: declared_reads,
                    new_declared_writes: declared_writes,
                    new_commutative_keys: commutative_keys,
                    new_storage_key_specs: storage_key_specs,
                    new_oracle_schema_ids,
                    timelock_blocks,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::ProposeCellOwnershipTransfer {
            from,
            cell_id,
            new_owner,
            timelock_blocks,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let new_owner_bytes = hex::decode(&new_owner)?;
            if new_owner_bytes.len() != 32 {
                return Err("new_owner must be 32 bytes (64 hex chars)".into());
            }
            let mut new_owner_arr = [0u8; 32];
            new_owner_arr.copy_from_slice(&new_owner_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::ProposeCellOwnershipTransfer {
                    cell_id: cell_id_arr,
                    new_owner: new_owner_arr,
                    timelock_blocks,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::ProposeCellMakeImmutable {
            from,
            cell_id,
            timelock_blocks,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::ProposeCellMakeImmutable {
                    cell_id: cell_id_arr,
                    timelock_blocks,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::VoteCellProposal {
            from,
            cell_id,
            approve,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::VoteCellProposal {
                    cell_id: cell_id_arr,
                    approve,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::ExecuteCellProposal { from, cell_id } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::ExecuteCellProposal {
                    cell_id: cell_id_arr,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::TokenTransfer {
            from,
            token,
            to,
            amount,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            if amount == 0 {
                return Err("amount must be > 0".into());
            }

            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);

            let to_bytes = hex::decode(&to)?;
            if to_bytes.len() != 32 {
                return Err("to must be 32 bytes (64 hex chars)".into());
            }
            let mut to_arr = [0u8; 32];
            to_arr.copy_from_slice(&to_bytes);

            require_token_cell(&client, &rpc, &token, cli.retries)?;
            require_account_exists(&client, &rpc, &to)?;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::TokenTransfer {
                    token_cell: token_arr,
                    recipient: to_arr,
                    amount,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::TokenMint {
            from,
            token,
            to,
            amount,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            if amount == 0 {
                return Err("amount must be > 0".into());
            }

            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);

            let to_bytes = hex::decode(&to)?;
            if to_bytes.len() != 32 {
                return Err("to must be 32 bytes (64 hex chars)".into());
            }
            let mut to_arr = [0u8; 32];
            to_arr.copy_from_slice(&to_bytes);

            require_token_cell(&client, &rpc, &token, cli.retries)?;
            require_account_exists(&client, &rpc, &to)?;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::TokenMint {
                    token_cell: token_arr,
                    recipient: to_arr,
                    amount,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::TokenBurn {
            from,
            token,
            amount,
        } => {
            confirm_or_abort(cli.yes, output, "Burn token supply; confirm")?;
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            if amount == 0 {
                return Err("amount must be > 0".into());
            }

            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);

            require_token_cell(&client, &rpc, &token, cli.retries)?;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::TokenBurn {
                    token_cell: token_arr,
                    amount,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::ProposeTokenAuthority {
            from,
            token,
            mint_authority,
            clear_mint_authority,
            freeze_authority,
            clear_freeze_authority,
            voting_period_blocks,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if mint_authority.is_some() && clear_mint_authority {
                return Err("Cannot set and clear mint authority at the same time".into());
            }
            if freeze_authority.is_some() && clear_freeze_authority {
                return Err("Cannot set and clear freeze authority at the same time".into());
            }
            let set_mint_authority = mint_authority.is_some() || clear_mint_authority;
            let set_freeze_authority = freeze_authority.is_some() || clear_freeze_authority;
            if !set_mint_authority && !set_freeze_authority {
                return Err("Must set at least one authority (mint or freeze)".into());
            }

            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);

            let new_mint_authority = if let Some(hex_val) = mint_authority {
                let bytes = hex::decode(&hex_val)?;
                if bytes.len() != 32 {
                    return Err("mint_authority must be 32 bytes (64 hex chars)".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else if clear_mint_authority {
                None
            } else {
                None
            };

            let new_freeze_authority = if let Some(hex_val) = freeze_authority {
                let bytes = hex::decode(&hex_val)?;
                if bytes.len() != 32 {
                    return Err("freeze_authority must be 32 bytes (64 hex chars)".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else if clear_freeze_authority {
                None
            } else {
                None
            };

            require_token_cell(&client, &rpc, &token, cli.retries)?;
            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let mint_arr = new_mint_authority.unwrap_or([0u8; 32]);
            let freeze_arr = new_freeze_authority.unwrap_or([0u8; 32]);
            let calldata = encode_token_authority_propose(
                token_arr,
                set_mint_authority,
                mint_arr,
                set_freeze_authority,
                freeze_arr,
                voting_period_blocks,
            );
            let cell_id = truthlinked_core::pq_execution::token_governance_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::VoteTokenAuthority {
            from,
            token,
            approve,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);

            require_token_cell(&client, &rpc, &token, cli.retries)?;
            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_token_authority_vote(token_arr, approve);
            let cell_id = truthlinked_core::pq_execution::token_governance_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::CallChain {
            from,
            calls,
            gas_limit,
            simulate,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_calls = parse_call_chain_json(&calls)?;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCellChain {
                    calls: cell_calls,
                    gas_limit,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let endpoint = if simulate {
                "simulate_raw"
            } else {
                "submit_raw"
            };
            if simulate {
                eprintln!("✦ Simulation Engine: Running multi-layer call chain transaction sequence...");
                eprintln!("  (Executing contract verification locally. Matrix states remain uncommitted to consensus.)");
            } else {
                eprintln!("Submitting call chain...");
            }
            let res: Value = post_bytes(
                &client,
                &format!("{}/{}", rpc, endpoint),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::ProposeName {
            from,
            name,
            target,
            owner,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if name.trim().is_empty() {
                return Err("name must not be empty".into());
            }

            let target_bytes = hex::decode(&target)?;
            if target_bytes.len() != 32 {
                return Err("target must be 32 bytes (64 hex chars)".into());
            }
            let mut target_arr = [0u8; 32];
            target_arr.copy_from_slice(&target_bytes);

            let owner_bytes = hex::decode(&owner)?;
            if owner_bytes.len() != 32 {
                return Err("owner must be 32 bytes (64 hex chars)".into());
            }
            let mut owner_arr = [0u8; 32];
            owner_arr.copy_from_slice(&owner_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let calldata = encode_name_registry_propose(&name, target_arr, owner_arr)?;
            let cell_id = truthlinked_core::pq_execution::name_registry_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::VoteName {
            from,
            name,
            approve,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if name.trim().is_empty() {
                return Err("name must not be empty".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let calldata = encode_name_registry_vote(&name, approve)?;
            let cell_id = truthlinked_core::pq_execution::name_registry_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::RenewName { from, name } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if name.trim().is_empty() {
                return Err("name must not be empty".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let calldata = encode_name_registry_renew(&name)?;
            let cell_id = truthlinked_core::pq_execution::name_registry_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::TransferName {
            from,
            name,
            new_owner,
        } => {
            confirm_or_abort(cli.yes, output, "Transfer name; confirm")?;
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if name.trim().is_empty() {
                return Err("name must not be empty".into());
            }

            let new_owner_bytes = hex::decode(&new_owner)?;
            if new_owner_bytes.len() != 32 {
                return Err("new_owner must be 32 bytes (64 hex chars)".into());
            }
            let mut new_owner_arr = [0u8; 32];
            new_owner_arr.copy_from_slice(&new_owner_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let calldata = encode_name_registry_transfer(&name, new_owner_arr)?;
            let cell_id = truthlinked_core::pq_execution::name_registry_system_cell_id();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = pq_execution::Transaction {
                nonce,
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::ProposeUrl {
            from,
            url_pattern,
            bond,
            voting_period_blocks,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if url_pattern.trim().is_empty() {
                return Err("URL_pattern must not be empty".into());
            }
            let bond_amount = parse_amount_str(&bond)?;
            if bond_amount == 0 {
                return Err("bond must be > 0".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = Transaction {
                nonce,
                sender: sender_account_id,
                intent: TransactionIntent::ProposeUrl {
                    url_pattern: url_pattern.clone(),
                    bond_amount,
                    voting_period_blocks,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("✦ Network Engine: Registering proposed URL network endpoint to distributed table structures...");
            let res: Value = post_bytes(
                &client,
                &format!("{}/submit_raw", rpc),
                tx_bytes,
                cli.retries,
            )?;

            print_output(&res, output)?;
        }

        Commands::VoteUrl {
            from,
            url_pattern,
            approve,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if url_pattern.trim().is_empty() {
                return Err("URL_pattern must not be empty".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = Transaction {
                nonce,
                sender: sender_account_id,
                intent: TransactionIntent::VoteUrl {
                    url_pattern: url_pattern.clone(),
                    approve,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("✦ Network Engine: Logging network validation vote for open endpoint routing target...");
            let res: Value = client
                .post(format!("{}/submit_raw", rpc))
                .body(tx_bytes)
                .send()?
                .json()?;

            print_output(&res, output)?;
        }

        Commands::ReportMaliciousUrl {
            from,
            url_pattern,
            evidence,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if url_pattern.trim().is_empty() {
                return Err("URL_pattern must not be empty".into());
            }
            if evidence.trim().is_empty() {
                return Err("evidence must not be empty".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = Transaction {
                nonce,
                sender: sender_account_id,
                intent: TransactionIntent::ReportMaliciousUrl {
                    url_pattern: url_pattern.clone(),
                    evidence: evidence.clone(),
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("✦ Network Engine: Broadcasted security report flag for malicious domain infrastructure...");
            let res: Value = client
                .post(format!("{}/submit_raw", rpc))
                .body(tx_bytes)
                .send()?
                .json()?;

            print_output(&res, output)?;
        }

        Commands::UpgradeVisibility {
            from,
            cell_id,
            public,
        } => {
            let sender_keys = load_keypair_arg(from.as_deref(), config.as_ref())?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32-byte hex".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            require_cell_exists(&client, &rpc, &cell_id, cli.retries)?;

            let genesis_hash = fetch_genesis_hash(&client, &rpc, cli.retries)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let visibility = if public { 1 } else { 0 };

            let nonce = next_nonce(&client, &rpc, &sender_account_id, cli.retries)?;
            let tx = Transaction {
                nonce,
                sender: sender_account_id,
                intent: TransactionIntent::SetCellVisibility {
                    cell_id: cell_id_arr,
                    visibility,
                },
                signature: vec![],
                timestamp,
                genesis_fingerprint: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("✦ Network Engine: Escalating execution visibility layer boundaries on active state space...");
            let res: Value = client
                .post(format!("{}/submit_raw", rpc))
                .body(tx_bytes)
                .send()?
                .json()?;

            print_output(&res, output)?;
        }
        Commands::Build { source, output } => {
            build_cell(&source, output.as_deref())?;
        }

        Commands::SDKNew { path } => {
            let target_dir = std::path::Path::new(&path);
            if target_dir.exists() {
                return Err(format!("Target path already exists: {}", path).into());
            }
            std::fs::create_dir_all(target_dir)?;
            write_embedded_dir(&SDK_TEMPLATE_DIR, target_dir)?;
            println!("✦ SDK Blueprint Engine: Fresh cell code architecture initialized at directory path: {}", path);
            println!("  Instruction Path:\n    Build Package ➔ axiom sdk-build --path {}", path);
        }

        Commands::SDKBuild { path, output } => {
            let (axiom_path, manifest_path) = sdk_build_project(&path, output.as_deref())?;
            println!("✦ SDK Blueprint Engine: Code compilation process completed successfully.");
            println!("   ├─ Bytecode Location:  {}", axiom_path);
            println!("   └─ Manifest Parameter:  {}", manifest_path);
        }

        Commands::SDKDeploy {
            from,
            cell_id,
            path,
            bytecode_file,
            initial_balance,
            manifest_file,
            skip_build,
        } => {
            let (axiom_path, built_manifest_path) = if let Some(wasm) = bytecode_file {
                (wasm, None)
            } else if skip_build {
                (sdk_locate_axiom(&path)?, None)
            } else {
                let (wasm, manifest) = sdk_build_project(&path, None)?;
                (wasm, Some(manifest))
            };

            let manifest_path =
                resolve_manifest_path(&axiom_path, manifest_file.or(built_manifest_path));

            let from = resolve_signing_keyfile_arg(from.as_deref(), config.as_ref())?;
            submit_cell_deploy(
                &client,
                &rpc,
                &from,
                &cell_id,
                &axiom_path,
                manifest_path,
                initial_balance,
                output,
                cli.retries,
            )?;
        }

        Commands::ManifestInit { bytecode_file } => {
            let bytecode = std::fs::read(&bytecode_file)?;
            let analysis = truthlinked_core::cells::CellAccount::analyze_bytecode(&bytecode)?;
            let reads_json: Vec<serde_json::Value> = analysis
                .static_read_slots
                .iter()
                .map(|s| serde_json::Value::String(hex::encode(s)))
                .collect();
            let writes_json: Vec<serde_json::Value> = analysis
                .static_write_slots
                .iter()
                .map(|s| serde_json::Value::String(hex::encode(s)))
                .collect();

            let resolution_note = if !analysis.has_storage_reads && !analysis.has_storage_writes {
                "No storage operations detected. Empty manifest is valid."
            } else if analysis.fully_resolved {
                "All storage slot addresses resolved from bytecode data section. Manifest is complete."
            } else {
                "PARTIAL: some storage calls use dynamic slot addresses that cannot be resolved statically. \
                 Review and complete declared_reads/declared_writes manually, \
                 or use the TruthLinked Rust SDK (storage_slot! macro) for full static resolution."
            };

            let manifest = serde_json::json!({
                "declared_reads":   reads_json,
                "declared_writes":  writes_json,
                "commutative_keys": [],
                "storage_key_specs": [],
                "oracle_schema_ids": [],
                "_resolution": resolution_note,
                "_static_analysis": {
                    "has_storage_reads":    analysis.has_storage_reads,
                    "has_storage_writes":   analysis.has_storage_writes,
                    "fully_resolved":       analysis.fully_resolved,
                    "resolved_read_count":  analysis.static_read_slots.len(),
                    "resolved_write_count": analysis.static_write_slots.len(),
                }
            });

            let manifest_path = bytecode_file.replace(".axiom", ".manifest.json");
            std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

            println!("⚙ Manifest structural document written to target path destination: {}", manifest_path);
            if analysis.fully_resolved {
                println!("┌── STATIC ANALYSIS COMPILER SUMMARY\n│  Memory Resolution: [COMPLETE] Full static mapping.");
                println!(
                    "  Read slots  resolved: {}",
                    analysis.static_read_slots.len()
                );
                println!(
                    "  Write slots resolved: {}",
                    analysis.static_write_slots.len()
                );
            } else if analysis.has_storage_reads || analysis.has_storage_writes {
                println!("┌── STATIC ANALYSIS COMPILER SUMMARY\n│  Memory Resolution: [PARTIAL ANALYSIS] Dynamic allocation loops bypass deep mapping.");
                println!("  Resolved reads:  {}", analysis.static_read_slots.len());
                println!("  Resolved writes: {}", analysis.static_write_slots.len());
                println!(
                    "  Action: fill remaining slots manually or use the SDK storage_slot! macro."
                );
            } else {
                println!("No storage operations. Manifest is complete.");
            }
        }

        Commands::ManifestVerify {
            bytecode_file,
            manifest_file,
        } => {
            let bytecode = std::fs::read(&bytecode_file)?;
            let (
                declared_reads,
                declared_writes,
                _commutative_keys,
                storage_key_specs,
                _oracle_schema_ids,
            ) = load_manifest_sets(&manifest_file)?;
            match truthlinked_core::cells::CellAccount::verify_manifest_against_bytecode(
                &bytecode,
                &declared_reads,
                &declared_writes,
                &storage_key_specs,
            ) {
                Ok(()) => {
                    let analysis =
                        truthlinked_core::cells::CellAccount::analyze_bytecode(&bytecode)?;
                    println!("┌── STATIC ANALYSIS COMPILER SUMMARY\n│  Memory Resolution: [COMPLETE] Full static mapping.");
                    println!("│  Target Bytecode:  {}", bytecode_file);
                    println!("│  Target Manifest:  {}", manifest_file);
                    println!("│  Explicit Reads:   {}", declared_reads.len());
                    println!("│  Explicit Writes:  {}", declared_writes.len());
                    println!("│  Key Index Specs:  {}", storage_key_specs.len());
                    if analysis.fully_resolved {
                        println!("│  Enforcement Mode: [FULL BOUNDARY SECURITY] ({} read / {} write slots locked in bytecode)",
                            analysis.static_read_slots.len(),
                            analysis.static_write_slots.len());
                    } else if analysis.has_storage_reads || analysis.has_storage_writes {
                        println!("│  Enforcement Mode: [PARTIAL ISOLATION] Dynamic storage references discovered.");
                        println!("│  Developer Directive: Wrap logic statements with the storage_slot! macro to fix compilation logs.");
                    } else {
                        println!("│  Enforcement Mode: No persistent state operations detected within target bytecode matrix.");
                    }
                }
                Err(e) => {
                    eprintln!("Corporate Security Exception: Structural manifest parameter verification failed.");
                    eprintln!("Corporate Security Trace Logic: Verification rejection exception reason: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::ManifestHash {
            bytecode_file,
            manifest_file,
        } => {
            let bytecode = std::fs::read(&bytecode_file)?;
            let (
                declared_reads,
                declared_writes,
                commutative_keys,
                _storage_key_specs,
                oracle_schema_ids,
            ) = load_manifest_sets(&manifest_file)?;

            let manifest_hash = truthlinked_core::cells::CellAccount::compute_manifest_hash(
                &bytecode,
                &declared_reads,
                &declared_writes,
                &commutative_keys,
                &oracle_schema_ids,
            );

            println!("│  Global Manifest Hash ID: 0x{}", hex::encode(&manifest_hash));
            println!("│  Bytecode Footprint ID:   {}", bytecode_file);
            println!("│  Consensus Target Key:    {}\n│  Status Note: This cryptographic root hash maps identity states upon network entry.", manifest_file);
            println!("│  Consensus Target Key:    {}\n│  Status Note: This cryptographic root hash maps identity states upon network entry.", manifest_file);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cmd(args: &[&str]) -> (OutputFormat, Commands) {
        let mut full = vec!["axiom"];
        full.extend_from_slice(args);
        let cli = Cli::parse_from(full);
        (resolve_output(&cli), cli.command)
    }

    #[test]
    fn parse_package_name_uses_toml() {
        let tmp = std::env::temp_dir().join(format!(
            "axiom_pkg_{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let content = r#"
[package]
name = "my_cell"
version = "0.1.0"

[package.metadata]
name = "not_this_one"
"#;
        std::fs::write(&tmp, content).unwrap();
        let name = parse_package_name(&tmp).unwrap();
        assert_eq!(name, "my_cell");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn json_string_respects_output_format() {
        let value = serde_json::json!({"ok": true, "n": 1});
        let compact = json_string(&value, OutputFormat::Json).unwrap();
        let pretty = json_string(&value, OutputFormat::Pretty).unwrap();
        assert!(compact.contains("\"ok\":true"));
        assert!(pretty.contains("\n"));
    }

    #[test]
    fn call_chain_total_calldata_limit_enforced() {
        let max = constants::MAX_CALL_CHAIN_TOTAL_CALLDATA;
        let call1 = serde_json::json!({
            "cell": "00".repeat(32),
            "calldata": hex::encode(vec![0u8; max]),
            "value": 0
        });
        let call2 = serde_json::json!({
            "cell": "11".repeat(32),
            "calldata": "00",
            "value": 0
        });
        let calls = serde_json::json!([call1, call2]).to_string();
        let err = parse_call_chain_json(&calls).expect_err("should exceed total calldata");
        assert!(err.to_string().contains("total calldata"));
    }

    #[test]
    fn parse_output_format_flag() {
        let (output, cmd) = parse_cmd(&["--output", "json", "chain-info"]);
        assert!(matches!(output, OutputFormat::Json));
        assert!(matches!(cmd, Commands::ChainInfo));
        let (output, cmd) = parse_cmd(&["-j", "chain-info"]);
        assert!(matches!(output, OutputFormat::Json));
        assert!(matches!(cmd, Commands::ChainInfo));
    }

    #[test]
    fn parse_basic_queries() {
        assert!(matches!(parse_cmd(&["chain-info"]).1, Commands::ChainInfo));
        assert!(matches!(parse_cmd(&["token-info"]).1, Commands::TokenInfo));
        assert!(matches!(
            parse_cmd(&["network-info"]).1,
            Commands::NetworkInfo
        ));
        assert!(matches!(parse_cmd(&["validators"]).1, Commands::Validators));
        assert!(matches!(parse_cmd(&["mempool"]).1, Commands::Mempool));
        assert!(matches!(parse_cmd(&["status"]).1, Commands::Status { .. }));
        assert!(matches!(
            parse_cmd(&["list-cell-proposals"]).1,
            Commands::ListCellProposals
        ));
        assert!(matches!(
            parse_cmd(&["tx-status", "aa"]).1,
            Commands::TxStatus { .. }
        ));
        assert!(matches!(parse_cmd(&["tx", "aa"]).1, Commands::Tx { .. }));
        assert!(matches!(
            parse_cmd(&["balance", "aa"]).1,
            Commands::Balance { .. }
        ));
        assert!(matches!(
            parse_cmd(&["balance-by-pubkey", "bb"]).1,
            Commands::BalanceByPubkey { .. }
        ));
    }

    #[test]
    fn parse_identity_commands() {
        let cmd = parse_cmd(&["account-id", "--pubkey", "aa"]).1;
        assert!(matches!(cmd, Commands::AccountId { .. }));
        let cmd = parse_cmd(&["import-mnemonic", "--mnemonic", "word1 word2 word3"]).1;
        assert!(matches!(cmd, Commands::ImportMnemonic { .. }));
        let cmd = parse_cmd(&["account-create", "--encrypt"]).1;
        assert!(matches!(cmd, Commands::AccountCreate { .. }));
    }

    #[test]
    fn parse_transfer_commands() {
        let cmd = parse_cmd(&["send", "alice.tl", "1"]).1;
        assert!(matches!(cmd, Commands::Send { .. }));
        let cmd = parse_cmd(&["transfer", "alice.tl", "1"]).1;  // alias
        assert!(matches!(cmd, Commands::Send { .. }));
        let cmd = parse_cmd(&["send", "nft", "aa", "bb"]).1;
        assert!(matches!(cmd, Commands::Send { .. }));
        let cmd = parse_cmd(&["deposit-compute", "--from", "k", "--amount", "1"]).1;
        assert!(matches!(cmd, Commands::DepositCompute { .. }));
        let cmd = parse_cmd(&["withdraw-compute", "--from", "k", "--amount", "1"]).1;
        assert!(matches!(cmd, Commands::WithdrawCompute { .. }));
        let cmd = parse_cmd(&[
            "batch-transfer",
            "--from",
            "k",
            "--to-pubkeys",
            "aa,bb",
            "--amounts",
            "1,2",
        ])
        .1;
        assert!(matches!(cmd, Commands::BatchTransfer { .. }));
        let cmd = parse_cmd(&["faucet", "--from", "k"]).1;
        assert!(matches!(cmd, Commands::Faucet { from: Some(_), .. }));
        let cmd = parse_cmd(&["faucet"]).1;
        assert!(matches!(cmd, Commands::Faucet { from: None, .. }));
    }

    #[test]
    fn parse_staking_commands() {
        assert!(matches!(
            parse_cmd(&["validator-setup", "--from", "k", "--amount", "10"]).1,
            Commands::ValidatorSetup { .. }
        ));
        assert!(matches!(
            parse_cmd(&["bond", "10", "--from", "k"]).1,
            Commands::Bond { .. }
        ));
        assert!(matches!(
            parse_cmd(&["stake", "10"]).1,
            Commands::Stake { .. }
        ));
        assert!(matches!(
            parse_cmd(&["unbond", "--from", "k", "--amount", "10"]).1,
            Commands::Unbond { .. }
        ));
        assert!(matches!(
            parse_cmd(&["withdraw", "--from", "k"]).1,
            Commands::Withdraw { .. }
        ));
        assert!(matches!(
            parse_cmd(&["unjail", "--from", "k"]).1,
            Commands::Unjail { .. }
        ));
    }

    #[test]
    fn parse_nft_commands() {
        assert!(matches!(
            parse_cmd(&[
                "nft", "mint",
                "--from", "k",
                "--nft-id", "aa",
                "--name", "n",
                "--metadata-uri", "ipfs://x"
            ])
            .1,
            Commands::Nft { .. }
        ));
        assert!(matches!(
            parse_cmd(&["nft", "send", "aa", "bb", "--from", "k"]).1,
            Commands::Nft { .. }
        ));
        assert!(matches!(
            parse_cmd(&["send", "nft", "aa", "bb"]).1,
            Commands::Send { .. }
        ));
        assert!(matches!(
            parse_cmd(&["nft", "burn", "aa", "--from", "k"]).1,
            Commands::Nft { .. }
        ));
        assert!(matches!(
            parse_cmd(&["nft", "approve", "aa", "bb", "--from", "k"]).1,
            Commands::Nft { .. }
        ));
        assert!(matches!(
            parse_cmd(&["nft", "info", "aa"]).1,
            Commands::Nft { .. }
        ));
        assert!(matches!(
            parse_cmd(&["nft", "list"]).1,
            Commands::Nft { .. }
        ));
    }

    #[test]
    fn parse_cell_commands() {
        assert!(matches!(
            parse_cmd(&[
                "deploy-cell",
                "--from",
                "k",
                "--cell-id",
                "aa",
                "--source",
                "src/lib.rs"
            ])
            .1,
            Commands::DeployCell { .. }
        ));
        assert!(matches!(
            parse_cmd(&["deploy", "aa", "src/lib.rs"]).1,
            Commands::Deploy { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "deploy-token",
                "--from",
                "k",
                "--cell-id",
                "aa",
                "--name",
                "T",
                "--symbol",
                "T",
                "--decimals",
                "9",
                "--supply",
                "100"
            ])
            .1,
            Commands::DeployToken { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "call-cell",
                "--from",
                "k",
                "--cell-id",
                "aa",
                "--calldata",
                "00",
                "--simulate"
            ])
            .1,
            Commands::CallCell { simulate: true, .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "upgrade-cell",
                "--from",
                "k",
                "--cell-id",
                "aa",
                "--bytecode-file",
                "c.axiom"
            ])
            .1,
            Commands::UpgradeCell { .. }
        ));
        assert!(matches!(
            parse_cmd(&["rotate-key", "--from", "k", "--new-pubkey", "aa"]).1,
            Commands::RotateKey { .. }
        ));
        assert!(matches!(
            parse_cmd(&["accept-ownership", "--from", "k", "--cell-id", "aa"]).1,
            Commands::AcceptOwnership { .. }
        ));
        assert!(matches!(
            parse_cmd(&["make-immutable", "--from", "k", "--cell-id", "aa"]).1,
            Commands::MakeImmutable { .. }
        ));
        assert!(matches!(
            parse_cmd(&["close-cell", "--from", "k", "--cell-id", "aa"]).1,
            Commands::CloseCell { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "propose-cell-upgrade",
                "--from",
                "k",
                "--cell-id",
                "aa",
                "--bytecode-file",
                "c.axiom"
            ])
            .1,
            Commands::ProposeCellUpgrade { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "propose-cell-ownership-transfer",
                "--from",
                "k",
                "--cell-id",
                "aa",
                "--new-owner",
                "bb"
            ])
            .1,
            Commands::ProposeCellOwnershipTransfer { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "propose-cell-make-immutable",
                "--from",
                "k",
                "--cell-id",
                "aa"
            ])
            .1,
            Commands::ProposeCellMakeImmutable { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "vote-cell-proposal",
                "--from",
                "k",
                "--cell-id",
                "aa",
                "--approve"
            ])
            .1,
            Commands::VoteCellProposal { .. }
        ));
        assert!(matches!(
            parse_cmd(&["execute-cell-proposal", "--from", "k", "--cell-id", "aa"]).1,
            Commands::ExecuteCellProposal { .. }
        ));
    }

    #[test]
    fn parse_token_commands() {
        // Fresh path
        assert!(matches!(
            parse_cmd(&["send", "token", "aa", "bb", "1"]).1,
            Commands::Send { .. }
        ));
        assert!(matches!(
            parse_cmd(&["send", "token", "aa", "bb", "1", "--from", "k"]).1,
            Commands::Send { .. }
        ));

        // Legacy flat form (hidden)
        assert!(matches!(
            parse_cmd(&[
                "token-transfer",
                "--from",
                "k",
                "--token",
                "aa",
                "--to",
                "bb",
                "--amount",
                "1"
            ])
            .1,
            Commands::TokenTransfer { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "token-mint",
                "--from",
                "k",
                "--token",
                "aa",
                "--to",
                "bb",
                "--amount",
                "1"
            ])
            .1,
            Commands::TokenMint { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "token-burn",
                "--from",
                "k",
                "--token",
                "aa",
                "--amount",
                "1"
            ])
            .1,
            Commands::TokenBurn { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "propose-token-authority",
                "--from",
                "k",
                "--token",
                "aa",
                "--mint-authority",
                "bb"
            ])
            .1,
            Commands::ProposeTokenAuthority { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "vote-token-authority",
                "--from",
                "k",
                "--token",
                "aa",
                "--approve"
            ])
            .1,
            Commands::VoteTokenAuthority { .. }
        ));
    }

    #[test]
    fn parse_call_chain_and_names() {
        assert!(matches!(
            parse_cmd(&["call-chain", "--from", "k", "--calls", "[]", "--simulate"]).1,
            Commands::CallChain { simulate: true, .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "propose-name",
                "--from",
                "k",
                "--name",
                "n",
                "--target",
                "aa",
                "--owner",
                "bb"
            ])
            .1,
            Commands::ProposeName { .. }
        ));
        assert!(matches!(
            parse_cmd(&["vote-name", "--from", "k", "--name", "n", "--approve"]).1,
            Commands::VoteName { .. }
        ));
        assert!(matches!(
            parse_cmd(&["renew-name", "--from", "k", "--name", "n"]).1,
            Commands::RenewName { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "transfer-name",
                "--from",
                "k",
                "--name",
                "n",
                "--new-owner",
                "aa"
            ])
            .1,
            Commands::TransferName { .. }
        ));
    }

    #[test]
    fn parse_url_governance_and_visibility() {
        assert!(matches!(
            parse_cmd(&[
                "propose-url",
                "--from",
                "k",
                "--url-pattern",
                "https://x/*",
                "--bond",
                "1"
            ])
            .1,
            Commands::ProposeUrl { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "vote-url",
                "--from",
                "k",
                "--url-pattern",
                "https://x/*",
                "--approve"
            ])
            .1,
            Commands::VoteUrl { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "report-malicious-url",
                "--from",
                "k",
                "--url-pattern",
                "https://x/*"
            ])
            .1,
            Commands::ReportMaliciousUrl { .. }
        ));
        assert!(matches!(
            parse_cmd(&["upgrade-visibility", "--from", "k", "--cell-id", "aa"]).1,
            Commands::UpgradeVisibility { .. }
        ));
    }

    #[test]
    fn parse_mcp_private_balance_commands() {
        let sender_cell = "11".repeat(32);
        let sender_agent = "22".repeat(32);
        let recipient_cell = "33".repeat(32);
        let amount_commitment = "44".repeat(32);
        let sender_enc = "55".repeat(44);
        let sender_new_commitment = "66".repeat(32);
        let sender_nonce = "77".repeat(16);
        let sender_old_commitment = "88".repeat(32);
        let recipient_enc = "99".repeat(44);
        let recipient_new_commitment = "aa".repeat(32);
        let recipient_nonce = "bb".repeat(16);
        let recipient_old_commitment = "cc".repeat(32);
        assert!(matches!(
            parse_cmd(&[
                "mcp",
                "private-balance-confidential-transfer",
                "--from",
                "k",
                "--sender-cell-id",
                &sender_cell,
                "--sender-agent-id",
                &sender_agent,
                "--recipient-cell-id",
                &recipient_cell,
                "--amount-commitment",
                &amount_commitment,
                "--proof-hex",
                "aa",
                "--sender-new-encrypted",
                &sender_enc,
                "--sender-new-commitment",
                &sender_new_commitment,
                "--sender-new-commit-nonce",
                &sender_nonce,
                "--sender-old-commitment",
                &sender_old_commitment,
                "--recipient-new-encrypted",
                &recipient_enc,
                "--recipient-new-commitment",
                &recipient_new_commitment,
                "--recipient-new-commit-nonce",
                &recipient_nonce,
                "--recipient-old-commitment",
                &recipient_old_commitment,
            ])
            .1,
            Commands::Mcp { .. }
        ));
    }

    #[test]
    fn parse_sdk_and_manifest_commands() {
        assert!(matches!(
            parse_cmd(&["build", "--source", "src/lib.rs"]).1,
            Commands::Build { .. }
        ));
        assert!(matches!(
            parse_cmd(&["sdk-new", "--path", "p"]).1,
            Commands::SDKNew { .. }
        ));
        assert!(matches!(
            parse_cmd(&["sdk-build", "--path", "p"]).1,
            Commands::SDKBuild { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "sdk-deploy",
                "--from",
                "k",
                "--cell-id",
                "aa",
                "--path",
                "p"
            ])
            .1,
            Commands::SDKDeploy { .. }
        ));
        assert!(matches!(
            parse_cmd(&["manifest-init", "--bytecode-file", "c.axiom"]).1,
            Commands::ManifestInit { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "manifest-verify",
                "--bytecode-file",
                "c.axiom",
                "--manifest-file",
                "m.json"
            ])
            .1,
            Commands::ManifestVerify { .. }
        ));
        assert!(matches!(
            parse_cmd(&[
                "manifest-hash",
                "--bytecode-file",
                "c.axiom",
                "--manifest-file",
                "m.json"
            ])
            .1,
            Commands::ManifestHash { .. }
        ));
    }
}
