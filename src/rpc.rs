//! HTTP RPC server for querying TruthLinked chain state and submitting transactions.

use axum::{
    extract::{Path, Query, State as AxumState},
    http::{header, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::cors::CorsLayer;
use truthlinked_consensus::streaming_consensus::StreamingConsensus;
use truthlinked_core::pq_execution::{Transaction, TransactionIntent};
use truthlinked_governance::params as gp;

fn track_rpc_request() {
    truthlinked_state::metrics::global().inc_rpc_requests();
}

fn track_rpc_error() {
    truthlinked_state::metrics::global().inc_rpc_errors();
}

pub struct RpcServer {
    pub consensus: Arc<StreamingConsensus>,
    pub port: u16,
}

#[derive(Clone)]
struct TokenStatsCache {
    last_updated: u64,
    circulating_supply: u128,
    holder_count: u64,
}

static TOKEN_STATS_CACHE: OnceLock<RwLock<TokenStatsCache>> = OnceLock::new();

fn token_stats_cache() -> &'static RwLock<TokenStatsCache> {
    TOKEN_STATS_CACHE.get_or_init(|| {
        RwLock::new(TokenStatsCache {
            last_updated: 0,
            circulating_supply: 0,
            holder_count: 0,
        })
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn compute_network_stats(consensus: &Arc<StreamingConsensus>) -> (f64, f64, f64) {
    let height = consensus.get_current_height();
    let storage = consensus.get_storage();
    let (tps_1min, tps_5min, avg_block_time) = if let Some(storage) = storage {
        let mut tx_count_1min = 0u64;
        let mut tx_count_5min = 0u64;
        let mut block_times = vec![];

        let now = now_secs();
        for h in height.saturating_sub(5000)..=height {
            if let Ok(Some(header)) = storage.load_batch_header_by_height(h) {
                let age = now.saturating_sub(header.timestamp);

                let vote_count = header.finality_certificate.signer_count() as u64;
                if let Ok(Some(batch)) = storage.load_batch(h) {
                    let tx_count = batch.len() as u64 + vote_count;
                    if age <= 60 {
                        tx_count_1min += tx_count;
                    }
                    if age <= 300 {
                        tx_count_5min += tx_count;
                    }
                }

                if h > 0 {
                    if let Ok(Some(prev_header)) = storage.load_batch_header_by_height(h - 1) {
                        block_times.push(header.timestamp.saturating_sub(prev_header.timestamp));
                    }
                }
            }
        }

        let tps_1min = tx_count_1min as f64 / 60.0;
        let tps_5min = tx_count_5min as f64 / 300.0;
        let avg_block_time = if !block_times.is_empty() {
            block_times.iter().sum::<u64>() as f64 / block_times.len() as f64
        } else {
            0.0
        };

        (tps_1min, tps_5min, avg_block_time)
    } else {
        (0.0, 0.0, 0.0)
    };

    (tps_1min, tps_5min, avg_block_time)
}

fn compute_storage_root(storage: &HashMap<[u8; 32], [u8; 32]>) -> [u8; 32] {
    let mut entries: Vec<([u8; 32], [u8; 32])> = storage.iter().map(|(k, v)| (*k, *v)).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    hasher.update(b"truthlinked.storage.root.v1");
    for (k, v) in entries {
        hasher.update(k);
        hasher.update(v);
    }
    let out = hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&out);
    root
}

impl RpcServer {
    pub fn new(consensus: Arc<StreamingConsensus>, port: u16) -> Self {
        Self { consensus, port }
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .route("/health", get(health))
            .route("/chain_info", get(chain_info))
            .route("/token_info", get(token_info))
            .route("/network_info", get(network_info))
            .route("/validators", get(validators))
            .route("/mempool", get(mempool))
            .route("/mempool/tx/{hash}", get(mempool_tx))
            .route("/nft/{id}", get(nft_info))
            .route("/nfts/{owner}", get(nfts_by_owner))
            .route("/account/{id}", get(account_info))
            .route("/account/{id}/balance", get(balance_get))
            .route(
                "/account/pubkey/{pubkey}/balance",
                get(balance_by_pubkey_get),
            )
            .route("/pubkey/{id}", get(pubkey_by_account))
            .route("/cell/{id}", get(cell_info))
            .route("/treasury_proposal/{id}", get(treasury_proposal))
            .route("/cell_proposals", get(cell_proposals))
            .route("/metrics", get(metrics))
            .route("/storage_metrics", get(storage_metrics))
            .route("/search", get(search))
            .route("/resolve/{q}", get(resolve))
            .route("/gas", get(gas_schedule))
            .route("/fee_distribution", get(fee_distribution))
            .route("/balance", post(balance))
            .route("/token_balance", post(token_balance))
            .route("/token_balances", post(token_balances))
            .route("/balance_by_pubkey", post(balance_by_pubkey))
            .route("/validator_info", post(validator_info))
            .route("/submit_raw", post(submit_raw))
            .route("/simulate_raw", post(simulate_raw))
            .route("/transaction_history", post(transaction_history))
            .route("/transactions/recent", get(recent_transactions))
            .route("/block/{height}", get(get_block_by_height))
            .route("/block/{height}/attestations", get(get_block_attestations))
            .route("/block/latest", get(get_latest_block))
            .route("/tx/{hash}", get(get_transaction_by_hash))
            .route("/name_registry", get(name_registry_dump))
            .layer(CorsLayer::permissive())
            .with_state(self.consensus);

        let addr = format!("0.0.0.0:{}", self.port);
        tracing::info!(" RPC server listening on {}", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    height: u64,
    finalized_height: u64,
    mempool_size: usize,
    reason: Option<String>,
}

async fn health(AxumState(consensus): AxumState<Arc<StreamingConsensus>>) -> Json<HealthResponse> {
    track_rpc_request();
    let is_synced = consensus.is_live_synced().await;
    let peer_count = consensus.get_session_count().await;
    let single_node = std::env::var("TRUTHLINKED_SINGLE_NODE").ok().as_deref() == Some("1");
    let (status, reason) = if !is_synced {
        ("degraded".to_string(), Some("syncing".to_string()))
    } else if peer_count == 0 && !single_node {
        ("degraded".to_string(), Some("no_peers".to_string()))
    } else {
        ("ok".to_string(), None)
    };
    Json(HealthResponse {
        status,
        version: env!("CARGO_PKG_VERSION").to_string(),
        height: consensus.get_current_height(),
        finalized_height: consensus.get_finalized_height(),
        mempool_size: consensus.batch_len().await,
        reason,
    })
}

#[derive(Serialize)]
struct ChainInfoResponse {
    genesis_fingerprint: String,
    network_version: String,
    height: u64,
    finalized_height: u64,
    genesis_hash: String,
    peer_count: usize,
    sync_status: String,
    foundation_mint_authority: Option<String>,
}

async fn chain_info(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
) -> Json<ChainInfoResponse> {
    track_rpc_request();
    let height = consensus.get_current_height();
    let finalized_height = consensus.get_finalized_height();
    let genesis_hash = truthlinked_state::get_genesis_hash();
    let state = consensus.get_state().load_full();
    let foundation_mint_authority = state.foundation_mint_authority.map(hex::encode);
    let peer_count = consensus.get_peer_count().await;
    let sync_status = if consensus.is_live_synced().await {
        "synced".to_string()
    } else {
        "syncing".to_string()
    };

    Json(ChainInfoResponse {
        genesis_fingerprint: hex::encode(genesis_hash),
        network_version: env!("CARGO_PKG_VERSION").to_string(),
        height,
        finalized_height,
        genesis_hash: hex::encode(genesis_hash),
        peer_count,
        sync_status,
        foundation_mint_authority,
    })
}

#[derive(Serialize)]
struct TokenInfoResponse {
    mint: String,
    name: String,
    symbol: String,
    total_supply: String,
    circulating_supply: String,
    holder_count: u64,
    decimals: u8,
    subunit: String,
    metadata_uri: Option<String>,
    last_updated: u64,
    is_cached: bool,
}

async fn token_info(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
) -> Json<TokenInfoResponse> {
    track_rpc_request();
    let mut cache = token_stats_cache().write().unwrap();
    let now = now_secs();
    let mut is_cached = true;
    if now.saturating_sub(cache.last_updated) > 30 {
        let state = consensus.get_state().load();
        let mut circulating = 0u128;
        let mut holders = 0u64;
        for (_id, account) in state.accounts.iter() {
            if account.balance > 0 {
                holders += 1;
            }
            circulating = circulating.saturating_add(account.balance);
        }
        cache.circulating_supply = circulating;
        cache.holder_count = holders;
        cache.last_updated = now;
        is_cached = false;
    }
    Json(TokenInfoResponse {
        mint: "native".to_string(),
        name: truthlinked_state::constants::TOKEN_NAME.to_string(),
        symbol: truthlinked_state::constants::TOKEN_SYMBOL.to_string(),
        total_supply: truthlinked_state::trth::format_amount(
            truthlinked_state::constants::TOTAL_SUPPLY,
        ),
        circulating_supply: truthlinked_state::trth::format_amount(cache.circulating_supply),
        holder_count: cache.holder_count,
        decimals: truthlinked_state::constants::TOKEN_DECIMALS,
        subunit: truthlinked_state::constants::TOKEN_SUBUNIT.to_string(),
        metadata_uri: None,
        last_updated: cache.last_updated,
        is_cached,
    })
}

#[derive(Serialize)]
struct GasScheduleResponse {
    base_fee: u64,
    priority_fee_low: u64,
    priority_fee_medium: u64,
    priority_fee_high: u64,
    gas_limit: u64,
    gas_price: u64,
    min_tx_fee: u64,
    tx_byte_fee: u64,
    max_gas_per_tx: u64,
    max_gas_per_batch: u64,
    mempool_max_bytes: u64,
    cu_per_tlkd: u64,
    cu_per_trth: u64,
    name_registration_fee: String,
    name_renewal_fee: String,
    storage_rent_lifetime_fee: String,
    fees: std::collections::BTreeMap<String, u64>,
}

async fn gas_schedule() -> Json<GasScheduleResponse> {
    track_rpc_request();
    let mut fees = std::collections::BTreeMap::new();
    fees.insert("Transfer".to_string(), gp::get_u64(gp::PARAM_GAS_TRANSFER));
    fees.insert("Claim".to_string(), gp::get_u64(gp::PARAM_GAS_CLAIM));
    fees.insert(
        "RotateKey".to_string(),
        gp::get_u64(gp::PARAM_GAS_ROTATE_KEY),
    );
    fees.insert(
        "RegisterValidator".to_string(),
        gp::get_u64(gp::PARAM_GAS_REGISTER_VALIDATOR),
    );
    fees.insert("Stake".to_string(), gp::get_u64(gp::PARAM_GAS_STAKE));
    fees.insert("Unstake".to_string(), gp::get_u64(gp::PARAM_GAS_UNSTAKE));
    fees.insert(
        "WithdrawStake".to_string(),
        gp::get_u64(gp::PARAM_GAS_WITHDRAW),
    );
    fees.insert("Unjail".to_string(), gp::get_u64(gp::PARAM_GAS_UNJAIL));
    fees.insert("MintNFT".to_string(), gp::get_u64(gp::PARAM_GAS_MINT_NFT));
    fees.insert(
        "TransferNFT".to_string(),
        gp::get_u64(gp::PARAM_GAS_TRANSFER_NFT),
    );
    fees.insert("BurnNFT".to_string(), gp::get_u64(gp::PARAM_GAS_BURN_NFT));
    fees.insert(
        "ApproveNFT".to_string(),
        gp::get_u64(gp::PARAM_GAS_APPROVE_NFT),
    );
    fees.insert(
        "DeployCell".to_string(),
        gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL),
    );
    fees.insert(
        "DeployToken".to_string(),
        gp::get_u64(gp::PARAM_GAS_DEPLOY_TOKEN),
    );
    fees.insert(
        "UpgradeCell".to_string(),
        gp::get_u64(gp::PARAM_GAS_UPGRADE_CELL),
    );
    fees.insert(
        "TokenTransfer".to_string(),
        gp::get_u64(gp::PARAM_GAS_TOKEN_TRANSFER),
    );
    fees.insert(
        "TokenMint".to_string(),
        gp::get_u64(gp::PARAM_GAS_TOKEN_MINT),
    );
    fees.insert(
        "TokenBurn".to_string(),
        gp::get_u64(gp::PARAM_GAS_TOKEN_BURN),
    );
    fees.insert(
        "DepositCompute".to_string(),
        gp::get_u64(gp::PARAM_GAS_TRANSFER),
    );
    fees.insert(
        "WithdrawCompute".to_string(),
        gp::get_u64(gp::PARAM_GAS_TRANSFER),
    );
    fees.insert(
        "AccordRead".to_string(),
        gp::get_u64(gp::PARAM_GAS_ORACLE_READ),
    );
    fees.insert(
        "OracleQueue".to_string(),
        gp::get_u64(gp::PARAM_GAS_ORACLE_QUEUE),
    );

    Json(GasScheduleResponse {
        base_fee: gp::get_u64(gp::PARAM_GAS_PRICE),
        priority_fee_low: gp::get_u64(gp::PARAM_MIN_TX_FEE),
        priority_fee_medium: gp::get_u64(gp::PARAM_MIN_TX_FEE),
        priority_fee_high: gp::get_u64(gp::PARAM_MIN_TX_FEE).saturating_mul(2),
        gas_limit: gp::get_u64(gp::PARAM_MAX_GAS_PER_TX),
        gas_price: gp::get_u64(gp::PARAM_GAS_PRICE),
        min_tx_fee: gp::get_u64(gp::PARAM_MIN_TX_FEE),
        tx_byte_fee: gp::get_u64(gp::PARAM_TX_BYTE_FEE),
        max_gas_per_tx: gp::get_u64(gp::PARAM_MAX_GAS_PER_TX),
        max_gas_per_batch: gp::get_u64(gp::PARAM_MAX_GAS_PER_BATCH),
        mempool_max_bytes: gp::get_u64(gp::PARAM_MEMPOOL_MAX_BYTES),
        cu_per_tlkd: gp::get_u64(gp::PARAM_CU_PER_TRTH),
        cu_per_trth: gp::get_u64(gp::PARAM_CU_PER_TRTH),
        name_registration_fee: gp::get_u128(gp::PARAM_NAME_REGISTRATION_FEE).to_string(),
        name_renewal_fee: gp::get_u128(gp::PARAM_NAME_RENEWAL_FEE).to_string(),
        storage_rent_lifetime_fee: gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE).to_string(),
        fees,
    })
}

#[derive(Serialize)]
struct FeeBucketResponse {
    units: String,
    tlkd: String,
    trth: String,
}

#[derive(Serialize)]
struct FeeDistributionSplitResponse {
    bps: u128,
    units: String,
    tlkd: String,
    trth: String,
}

#[derive(Serialize)]
struct FeeDistributionResponse {
    finalized_height: u64,
    distribution_interval_blocks: u64,
    next_distribution_height: u64,
    pending_protocol_revenue: FeeBucketResponse,
    pending_treasury_revenue: FeeBucketResponse,
    pending_total_revenue: FeeBucketResponse,
    accumulated_gas_fees: FeeBucketResponse,
    accumulated_name_fees: FeeBucketResponse,
    accumulated_compute_fees_trth: FeeBucketResponse,
    accumulated_treasury_fees: FeeBucketResponse,
    split: std::collections::BTreeMap<String, FeeDistributionSplitResponse>,
}

fn fee_bucket(amount: u128) -> FeeBucketResponse {
    let formatted = truthlinked_state::trth::format_amount(amount);
    FeeBucketResponse {
        units: amount.to_string(),
        tlkd: formatted.clone(),
        trth: formatted,
    }
}

fn fee_split(name_bps: u128, amount: u128) -> FeeDistributionSplitResponse {
    let formatted = truthlinked_state::trth::format_amount(amount);
    FeeDistributionSplitResponse {
        bps: name_bps,
        units: amount.to_string(),
        tlkd: formatted.clone(),
        trth: formatted,
    }
}

async fn fee_distribution(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
) -> Json<FeeDistributionResponse> {
    track_rpc_request();
    let finalized_height = consensus.get_finalized_height();
    let interval = gp::get_u64(gp::PARAM_GAS_DISTRIBUTION_INTERVAL).max(1);
    let next_distribution_height = if finalized_height == 0 {
        interval
    } else {
        finalized_height
            .saturating_div(interval)
            .saturating_add(1)
            .saturating_mul(interval)
    };

    let state = consensus.get_state().load_full();
    let protocol_revenue = state
        .accumulated_gas_fees
        .saturating_add(state.accumulated_name_fees)
        .saturating_add(state.accumulated_compute_fees_trth);
    let treasury_revenue = state.accumulated_treasury_fees;
    let total_revenue = protocol_revenue.saturating_add(treasury_revenue);

    let validator_bps = truthlinked_state::constants::FEE_SPLIT_VALIDATORS_BPS;
    let staking_bps = truthlinked_state::constants::FEE_SPLIT_STAKERS_BPS;
    let validator_share = total_revenue.saturating_mul(validator_bps) / 10_000;
    let staking_share = total_revenue.saturating_mul(staking_bps) / 10_000;
    let burn_share = total_revenue
        .saturating_sub(validator_share)
        .saturating_sub(staking_share);

    let mut split = std::collections::BTreeMap::new();
    split.insert(
        "validators".to_string(),
        fee_split(validator_bps, validator_share),
    );
    split.insert(
        "staked_tlkd_holders".to_string(),
        fee_split(staking_bps, staking_share),
    );
    split.insert(
        "staked_trth_holders".to_string(),
        fee_split(staking_bps, staking_share),
    );
    split.insert(
        "burn".to_string(),
        fee_split(truthlinked_state::constants::FEE_SPLIT_BURN_BPS, burn_share),
    );

    Json(FeeDistributionResponse {
        finalized_height,
        distribution_interval_blocks: interval,
        next_distribution_height,
        pending_protocol_revenue: fee_bucket(protocol_revenue),
        pending_treasury_revenue: fee_bucket(treasury_revenue),
        pending_total_revenue: fee_bucket(total_revenue),
        accumulated_gas_fees: fee_bucket(state.accumulated_gas_fees),
        accumulated_name_fees: fee_bucket(state.accumulated_name_fees),
        accumulated_compute_fees_trth: fee_bucket(state.accumulated_compute_fees_trth),
        accumulated_treasury_fees: fee_bucket(state.accumulated_treasury_fees),
        split,
    })
}

#[derive(Serialize)]
struct NetworkInfoResponse {
    node_count: usize,
    connected_peers: usize,
    version: String,
    avg_block_time_ms: u64,
    tps: f64,
    network_id: String,
}

async fn network_info(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
) -> Json<NetworkInfoResponse> {
    track_rpc_request();
    let _discovered = consensus.get_peer_count().await;
    let connected = consensus.get_session_count().await;
    let (tps_1min, _tps_5min, avg_block_time) = compute_network_stats(&consensus);
    let avg_block_time_ms = (avg_block_time * 1000.0) as u64;
    let genesis_hash = truthlinked_state::get_genesis_hash();

    Json(NetworkInfoResponse {
        node_count: connected,
        connected_peers: connected,
        version: env!("CARGO_PKG_VERSION").to_string(),
        avg_block_time_ms,
        tps: tps_1min,
        network_id: hex::encode(genesis_hash),
    })
}

#[derive(Serialize)]
struct ValidatorsResponse {
    validators: Vec<ValidatorInfo>,
    total_stake: String,
}

#[derive(Serialize)]
struct ValidatorInfo {
    identity: String,
    vote_account: String,
    activated_stake: String,
    commission_bps: u16,
    last_vote: Option<u64>,
    root_slot: Option<u64>,
    epoch_credits: u64,
    jailed: bool,
    active: bool,
}

async fn validators(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
) -> Json<ValidatorsResponse> {
    track_rpc_request();
    let state_arc = consensus.get_state();
    let state = state_arc.load();
    let active_validators = state.staking.get_active_validators();
    let total_stake: u64 = active_validators.values().sum();

    let validators: Vec<ValidatorInfo> = state
        .staking
        .validators
        .iter()
        .map(|(pubkey, stake)| ValidatorInfo {
            identity: hex::encode(pubkey),
            vote_account: hex::encode(pubkey),
            activated_stake: stake.active_stake.to_string(),
            commission_bps: 0,
            last_vote: None,
            root_slot: None,
            epoch_credits: 0,
            jailed: stake.jailed_until.is_some(),
            active: active_validators.contains_key(pubkey),
        })
        .collect();

    Json(ValidatorsResponse {
        validators,
        total_stake: total_stake.to_string(),
    })
}

#[derive(Serialize)]
struct MempoolResponse {
    pending_count: usize,
    pending_bytes: usize,
    max_bytes: usize,
    transactions: Vec<MempoolTxSummary>,
    next_cursor: Option<usize>,
    limit: usize,
    cursor: usize,
}

#[derive(Serialize)]
struct MempoolTxSummary {
    hash: String,
    sender: String,
    intent_type: String,
    byte_weight: usize,
    timestamp: u64,
    expiration_height: u64,
}

#[derive(Deserialize)]
struct MempoolQuery {
    limit: Option<usize>,
    cursor: Option<usize>,
    tx_type: Option<String>,
}

#[derive(Serialize)]
struct MempoolTxResponse {
    found: bool,
    transaction: Option<truthlinked_core::pq_execution::Transaction>,
}

async fn mempool(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Query(query): Query<MempoolQuery>,
) -> Json<MempoolResponse> {
    track_rpc_request();
    let limit = query.limit.unwrap_or(50).min(500);
    let cursor = query.cursor.unwrap_or(0);
    let filter = query.tx_type.as_ref().map(|s| s.to_lowercase());

    if consensus.can_accept_transactions().await.is_err() {
        return Json(MempoolResponse {
            pending_count: 0,
            pending_bytes: 0,
            max_bytes: gp::get_usize(gp::PARAM_MEMPOOL_MAX_BYTES),
            transactions: Vec::new(),
            next_cursor: None,
            limit,
            cursor,
        });
    }

    let pending_bytes = consensus.get_mempool_byte_weight().await;
    let max_bytes = gp::get_usize(gp::PARAM_MEMPOOL_MAX_BYTES);
    let txs = consensus.get_mempool_txs_with_hashes().await;
    let mut filtered = Vec::new();
    for (hash, tx) in txs {
        let intent_type = match &tx.intent {
            TransactionIntent::Transfer { .. } => "transfer",
            TransactionIntent::BatchTransfer { .. } => "batch_transfer",
            TransactionIntent::TransferToName { .. } => "transfer_to_name",
            TransactionIntent::BatchTransferToName { .. } => "batch_transfer_to_name",
            TransactionIntent::Claim { .. } => "claim",
            TransactionIntent::RotateKey { .. } => "rotate_key",
            TransactionIntent::DepositCompute { .. } => "deposit_compute",
            TransactionIntent::WithdrawCompute { .. } => "withdraw_compute",
            TransactionIntent::Stake { .. } => "stake",
            TransactionIntent::Unstake { .. } => "unstake",
            TransactionIntent::WithdrawStake => "withdraw_stake",
            TransactionIntent::Unjail => "unjail",
            TransactionIntent::MintNFT { .. } => "mint_nft",
            TransactionIntent::TransferNFT { .. } => "transfer_nft",
            TransactionIntent::BurnNFT { .. } => "burn_nft",
            TransactionIntent::ApproveNFT { .. } => "approve_nft",
            TransactionIntent::DeployCell { .. } => "deploy_cell",
            TransactionIntent::DeployToken { .. } => "deploy_token",
            TransactionIntent::CallCell { .. } => "call_cell",
            TransactionIntent::UpgradeCell { .. } => "upgrade_cell",
            TransactionIntent::TransferOwnership { .. } => "transfer_ownership",
            TransactionIntent::AcceptOwnership { .. } => "accept_ownership",
            TransactionIntent::MakeImmutable { .. } => "make_immutable",
            TransactionIntent::TokenTransfer { .. } => "token_transfer",
            TransactionIntent::TokenMint { .. } => "token_mint",
            TransactionIntent::TokenBurn { .. } => "token_burn",
            TransactionIntent::TokenFreeze { .. } => "token_freeze",
            TransactionIntent::TokenThaw { .. } => "token_thaw",
            TransactionIntent::ProposeTokenAuthority { .. } => "propose_token_authority",
            TransactionIntent::VoteTokenAuthority { .. } => "vote_token_authority",
            TransactionIntent::CallSystem { .. } => "call_system",
            TransactionIntent::CloseCell { .. } => "close_cell",
            TransactionIntent::ProposeCellUpgrade { .. } => "propose_cell_upgrade",
            TransactionIntent::ProposeCellOwnershipTransfer { .. } => "propose_cell_ownership",
            TransactionIntent::ProposeCellMakeImmutable { .. } => "propose_cell_make_immutable",
            TransactionIntent::VoteCellProposal { .. } => "vote_cell_proposal",
            TransactionIntent::ExecuteCellProposal { .. } => "execute_cell_proposal",
            TransactionIntent::CallCellChain { .. } => "call_chain",
            TransactionIntent::ProposeUrl { .. } => "propose_url",
            TransactionIntent::VoteUrl { .. } => "vote_url",
            TransactionIntent::ReportMaliciousUrl { .. } => "report_malicious_url",
            TransactionIntent::RegisterMcpTool { .. } => "mcp_register_tool",
            TransactionIntent::RegisterMcpResource { .. } => "mcp_register_resource",
            TransactionIntent::RegisterMcpPrompt { .. } => "mcp_register_prompt",
            TransactionIntent::RegisterAgent { .. } => "mcp_register_agent",
            TransactionIntent::SuspendAgent { .. } => "mcp_suspend_agent",
            TransactionIntent::ReinstateAgent { .. } => "mcp_reinstate_agent",
            TransactionIntent::McpToolCall { .. } => "mcp_tool_call",
            TransactionIntent::PrivateBalanceInit { .. } => "private_balance_init",
            TransactionIntent::PrivateBalanceDeposit { .. } => "private_balance_deposit",
            TransactionIntent::PrivateBalanceWithdraw { .. } => "private_balance_withdraw",
            TransactionIntent::PrivateBalanceConfidentialTransfer { .. } => {
                "private_balance_confidential_transfer"
            }
            TransactionIntent::SubmitOracleCommit { .. } => "oracle_commit",
            TransactionIntent::SubmitOracleReveal { .. } => "oracle_reveal",
            TransactionIntent::SetCellVisibility { .. } => "set_cell_visibility",
            TransactionIntent::WrapTRTH { .. } => "wrap_tlkd",
            TransactionIntent::UnwrapTRTH { .. } => "unwrap_tlkd",
        }
        .to_string();
        if let Some(filter) = &filter {
            if filter != &intent_type {
                continue;
            }
        }
        filtered.push((hash, tx, intent_type));
    }

    let pending_count = filtered.len();
    let end = (cursor + limit).min(pending_count);
    let next_cursor = if end < pending_count { Some(end) } else { None };

    let mut out = Vec::new();
    for (hash, tx, intent_type) in filtered.into_iter().skip(cursor).take(limit) {
        out.push(MempoolTxSummary {
            hash: hex::encode(hash),
            sender: hex::encode(tx.sender),
            intent_type,
            byte_weight: tx.byte_weight().unwrap_or(0),
            timestamp: tx.timestamp,
            expiration_height: tx.expiration_height,
        });
    }

    Json(MempoolResponse {
        pending_count,
        pending_bytes,
        max_bytes,
        transactions: out,
        next_cursor,
        limit,
        cursor,
    })
}

async fn mempool_tx(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(hash): Path<String>,
) -> Json<MempoolTxResponse> {
    track_rpc_request();
    let hash_bytes = match hex::decode(&hash) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            track_rpc_error();
            return Json(MempoolTxResponse {
                found: false,
                transaction: None,
            });
        }
    };
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash_bytes);

    if consensus.can_accept_transactions().await.is_err() {
        return Json(MempoolTxResponse {
            found: false,
            transaction: None,
        });
    }

    let txs = consensus.get_mempool_txs_with_hashes().await;
    for (tx_hash, tx) in txs {
        if tx_hash == hash_arr {
            return Json(MempoolTxResponse {
                found: true,
                transaction: Some(tx),
            });
        }
    }

    Json(MempoolTxResponse {
        found: false,
        transaction: None,
    })
}

#[derive(Serialize)]
struct BalanceResponse {
    account_id: String,
    balance: String,
    balance_tlkd: String,
    balance_trth: String,
    compute_escrow_trth: String,
    compute_escrow_tlkd_formatted: String,
    compute_escrow_trth_formatted: String,
    staking_balance: String,
    staking_balance_tlkd: String,
    staking_balance_trth: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    error_code: Option<i32>,
}

impl ErrorResponse {
    fn new(msg: &str) -> Self {
        Self {
            error: msg.to_string(),
            error_code: map_error_code(msg),
        }
    }
}

#[derive(Serialize)]
struct AccountInfoResponse {
    account_id: String,
    found: bool,
    balance: String,
    balance_tlkd: String,
    balance_trth: String,
    compute_escrow_trth: String,
    nonce: u64,
    replay_protection: String,
    code_hash: Option<String>,
    storage_root: Option<String>,
    is_cell: bool,
}

#[derive(Serialize)]
struct CellInfoResponse {
    cell_id: String,
    found: bool,
    is_token: bool,
    immutable: bool,
}

#[derive(Serialize)]
struct TreasuryProposalResponse {
    proposal_id: String,
    found: bool,
    recipient: String,
    amount: String,
    created_at_height: u64,
    timelock_blocks: u64,
    votes_for: u64,
    votes_against: u64,
    executed: bool,
}

fn decode_u64(raw: &[u8; 32]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&raw[..8]);
    u64::from_le_bytes(bytes)
}

fn decode_u128(raw: &[u8; 32]) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&raw[..16]);
    u128::from_le_bytes(bytes)
}

fn treasury_namespace(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    let out = h.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&out);
    slot
}

fn treasury_slot(namespace: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"trth:sdk:slot:v1");
    h.update([0u8]);
    h.update(namespace);
    for part in parts {
        h.update([0xFF]);
        h.update(part);
    }
    let out = h.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&out);
    slot
}

fn format_token_amount(amount: u128, decimals: u8, symbol: &str) -> String {
    if decimals == 0 {
        return format!("{} {}", amount, symbol);
    }
    let mut base = 1u128;
    for _ in 0..decimals {
        base = base.saturating_mul(10);
    }
    let whole = amount / base;
    let fractional = amount % base;
    if fractional == 0 {
        format!("{} {}", whole, symbol)
    } else {
        let frac_str = format!("{:0width$}", fractional, width = decimals as usize)
            .trim_end_matches('0')
            .to_string();
        format!("{}.{} {}", whole, frac_str, symbol)
    }
}

#[derive(Serialize)]
struct CellProposalInfo {
    cell_id: String,
    proposal_type: String,
    proposer: String,
    created_at_height: u64,
    timelock_blocks: u64,
    require_vote: bool,
    votes_for: u64,
    votes_against: u64,
    voters: usize,
    executed: bool,
    new_owner: Option<String>,
    new_bytecode_len: Option<usize>,
}

async fn cell_proposals(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
) -> Result<Json<Vec<CellProposalInfo>>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let state_arc = consensus.get_state();
    let state = state_arc.load();

    let mut proposals: Vec<CellProposalInfo> = Vec::new();
    for (cell_id, cell) in state.cells.cells.iter() {
        if let Some(p) = &cell.governance_proposal {
            let (proposal_type, new_owner, new_bytecode_len) = match &p.proposal_type {
                truthlinked_runtime::cells::ProposalType::OwnershipTransfer { new_owner } => (
                    "ownership_transfer".to_string(),
                    Some(hex::encode(new_owner)),
                    None,
                ),
                truthlinked_runtime::cells::ProposalType::Upgrade { new_bytecode, .. } => {
                    ("upgrade".to_string(), None, Some(new_bytecode.len()))
                }
                truthlinked_runtime::cells::ProposalType::MakeImmutable => {
                    ("make_immutable".to_string(), None, None)
                }
            };
            proposals.push(CellProposalInfo {
                cell_id: hex::encode(cell_id),
                proposal_type,
                proposer: hex::encode(p.proposer),
                created_at_height: p.created_at_height,
                timelock_blocks: p.timelock_blocks,
                require_vote: p.require_vote,
                votes_for: p.votes_for,
                votes_against: p.votes_against,
                voters: p.voters.len(),
                executed: p.executed,
                new_owner,
                new_bytecode_len,
            });
        }
    }

    Ok(Json(proposals))
}

#[derive(Deserialize)]
struct BalanceRequest {
    account_id: String,
}

fn build_balance_response(
    state: &truthlinked_state::pq_execution::State,
    account_id_arr: &[u8; 32],
    account_id_hex: String,
) -> BalanceResponse {
    let balance = state
        .accounts
        .get(account_id_arr)
        .map(|acc| acc.balance)
        .unwrap_or(0);
    let compute_escrow_trth = state
        .accounts
        .get(account_id_arr)
        .map(|acc| acc.compute_escrow_trth)
        .unwrap_or(0);
    let staking_balance = state.staking_balance_of(account_id_arr).unwrap_or(0);
    let balance_formatted = truthlinked_state::trth::format_amount(balance);
    let compute_escrow_formatted = truthlinked_state::trth::format_amount(compute_escrow_trth);
    let staking_balance_formatted =
        truthlinked_state::trth::format_amount(staking_balance as u128);
    BalanceResponse {
        account_id: account_id_hex,
        balance: balance.to_string(),
        balance_tlkd: balance_formatted.clone(),
        balance_trth: balance_formatted,
        compute_escrow_trth: compute_escrow_trth.to_string(),
        compute_escrow_tlkd_formatted: compute_escrow_formatted.clone(),
        compute_escrow_trth_formatted: compute_escrow_formatted,
        staking_balance: staking_balance.to_string(),
        staking_balance_tlkd: staking_balance_formatted.clone(),
        staking_balance_trth: staking_balance_formatted,
    }
}

async fn balance(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Json(req): Json<BalanceRequest>,
) -> Result<Json<BalanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let account_id_bytes = hex::decode(&req.account_id).map_err(|_| {
        track_rpc_error();
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("account_id must be hex")),
        )
    })?;
    if account_id_bytes.len() != 32 {
        track_rpc_error();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "account_id must be 32 bytes (64 hex chars)",
            )),
        ));
    }
    let mut account_id_arr = [0u8; 32];
    account_id_arr.copy_from_slice(&account_id_bytes);

    let state_arc = consensus.get_state();
    let state = state_arc.load();
    tracing::info!(
        "🔍 Balance query: account={}, total_accounts={}",
        req.account_id,
        state.accounts.len()
    );
    Ok(Json(build_balance_response(
        &state,
        &account_id_arr,
        req.account_id,
    )))
}

async fn balance_get(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(id): Path<String>,
) -> Result<Json<BalanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let account_id_bytes = hex::decode(&id).map_err(|_| {
        track_rpc_error();
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("account_id must be hex")),
        )
    })?;
    if account_id_bytes.len() != 32 {
        track_rpc_error();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "account_id must be 32 bytes (64 hex chars)",
            )),
        ));
    }
    let mut account_id_arr = [0u8; 32];
    account_id_arr.copy_from_slice(&account_id_bytes);
    let state_arc = consensus.get_state();
    let state = state_arc.load();
    Ok(Json(build_balance_response(&state, &account_id_arr, id)))
}

#[derive(Deserialize)]
struct TokenBalanceRequest {
    cell_id: String,
    account_id: String,
}

#[derive(Serialize)]
struct TokenBalanceResponse {
    cell_id: String,
    account_id: String,
    balance: String,
}

#[derive(Serialize)]
struct TokenMetadataResponse {
    name: String,
    symbol: String,
    decimals: u8,
    total_supply: String,
    transfer_fee_bps: u16,
    transfer_fee_recipient: Option<String>,
    mint_authority: Option<String>,
    freeze_authority: Option<String>,
    non_transferable: bool,
    transfer_hook: Option<String>,
    transfer_hook_gas: u64,
    metadata_uri: Option<String>,
    permanent_delegate: Option<String>,
}

#[derive(Serialize)]
struct TokenBalanceEntry {
    cell_id: String,
    balance: String,
    balance_formatted: Option<String>,
    token: Option<TokenMetadataResponse>,
}

#[derive(Serialize)]
struct TokenBalancesResponse {
    account_id: String,
    balances: Vec<TokenBalanceEntry>,
}

async fn token_balance(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Json(req): Json<TokenBalanceRequest>,
) -> Result<Json<TokenBalanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let cell_id_bytes = hex::decode(&req.cell_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("cell_id must be hex")),
        )
    })?;
    let account_id_bytes = hex::decode(&req.account_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("account_id must be hex")),
        )
    })?;
    if cell_id_bytes.len() != 32 || account_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "cell_id and account_id must be 32 bytes each",
            )),
        ));
    }
    let mut cell_id_arr = [0u8; 32];
    let mut account_id_arr = [0u8; 32];
    cell_id_arr.copy_from_slice(&cell_id_bytes);
    account_id_arr.copy_from_slice(&account_id_bytes);

    let state_arc = consensus.get_state();
    let state = state_arc.load();
    let balance = state
        .cells
        .token_balances
        .get(&(cell_id_arr, account_id_arr))
        .copied()
        .unwrap_or(0);

    Ok(Json(TokenBalanceResponse {
        cell_id: req.cell_id,
        account_id: req.account_id,
        balance: balance.to_string(),
    }))
}

#[derive(Deserialize)]
struct TokenBalancesRequest {
    account_id: String,
    include_metadata: Option<bool>,
}

async fn token_balances(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Json(req): Json<TokenBalancesRequest>,
) -> Result<Json<TokenBalancesResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let account_id_bytes = hex::decode(&req.account_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("account_id must be hex")),
        )
    })?;
    if account_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "account_id must be 32 bytes (64 hex chars)",
            )),
        ));
    }
    let mut account_id_arr = [0u8; 32];
    account_id_arr.copy_from_slice(&account_id_bytes);

    let state_arc = consensus.get_state();
    let state = state_arc.load();
    let mut balances: Vec<TokenBalanceEntry> = Vec::new();
    let include_metadata = req.include_metadata.unwrap_or(false);
    for ((cell_id, owner), amount) in state.cells.token_balances.iter() {
        if owner == &account_id_arr {
            let (token, balance_formatted) = if include_metadata {
                let token = state.lookup_cell(cell_id).and_then(|cell| {
                    if !cell.is_token {
                        return None;
                    }
                    cell.token_config.as_ref().map(|cfg| TokenMetadataResponse {
                        name: cfg.name.clone(),
                        symbol: cfg.symbol.clone(),
                        decimals: cfg.decimals,
                        total_supply: cfg.total_supply.to_string(),
                        transfer_fee_bps: cfg.transfer_fee_bps,
                        transfer_fee_recipient: cfg.transfer_fee_recipient.map(hex::encode),
                        mint_authority: cfg.mint_authority.map(hex::encode),
                        freeze_authority: cfg.freeze_authority.map(hex::encode),
                        non_transferable: cfg.non_transferable,
                        transfer_hook: cfg.transfer_hook.map(hex::encode),
                        transfer_hook_gas: cfg.transfer_hook_gas,
                        metadata_uri: cfg.metadata_uri.clone(),
                        permanent_delegate: cfg.permanent_delegate.map(hex::encode),
                    })
                });
                let balance_formatted = token
                    .as_ref()
                    .map(|cfg| format_token_amount(*amount, cfg.decimals, &cfg.symbol));
                (token, balance_formatted)
            } else {
                (None, None)
            };
            balances.push(TokenBalanceEntry {
                cell_id: hex::encode(cell_id),
                balance: amount.to_string(),
                balance_formatted,
                token,
            });
        }
    }
    balances.sort_by(|a, b| a.cell_id.cmp(&b.cell_id));

    Ok(Json(TokenBalancesResponse {
        account_id: req.account_id,
        balances,
    }))
}

#[derive(Deserialize)]
struct BalanceByPubkeyRequest {
    pubkey: String,
}

async fn balance_by_pubkey(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Json(req): Json<BalanceByPubkeyRequest>,
) -> Result<Json<BalanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let pubkey_bytes = hex::decode(&req.pubkey).map_err(|_| {
        track_rpc_error();
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("pubkey must be hex")),
        )
    })?;
    if pubkey_bytes.len() != 1952 {
        track_rpc_error();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "pubkey must be 1952 bytes (Dilithium, 3904 hex chars)",
            )),
        ));
    }
    let account_id = truthlinked_core::pq_identity::account_id_from_pubkey(&pubkey_bytes);

    let state_arc = consensus.get_state();
    let state = state_arc.load();
    let balance = state
        .accounts
        .get(&account_id)
        .map(|acc| acc.balance)
        .unwrap_or(0);
    let compute_escrow_trth = state
        .accounts
        .get(&account_id)
        .map(|acc| acc.compute_escrow_trth)
        .unwrap_or(0);

    let staking_balance = state.staking_balance_of(&account_id).unwrap_or(0);
    let balance_formatted = truthlinked_state::trth::format_amount(balance);
    let compute_escrow_formatted = truthlinked_state::trth::format_amount(compute_escrow_trth);
    let staking_balance_formatted =
        truthlinked_state::trth::format_amount(staking_balance as u128);
    Ok(Json(BalanceResponse {
        account_id: hex::encode(account_id),
        balance: balance.to_string(),
        balance_tlkd: balance_formatted.clone(),
        balance_trth: balance_formatted,
        compute_escrow_trth: compute_escrow_trth.to_string(),
        compute_escrow_tlkd_formatted: compute_escrow_formatted.clone(),
        compute_escrow_trth_formatted: compute_escrow_formatted,
        staking_balance: staking_balance.to_string(),
        staking_balance_tlkd: staking_balance_formatted.clone(),
        staking_balance_trth: staking_balance_formatted,
    }))
}

async fn balance_by_pubkey_get(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(pubkey): Path<String>,
) -> Result<Json<BalanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let pubkey_bytes = hex::decode(&pubkey).map_err(|_| {
        track_rpc_error();
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("pubkey must be hex")),
        )
    })?;
    if pubkey_bytes.len() != 1952 {
        track_rpc_error();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "pubkey must be 1952 bytes (Dilithium, 3904 hex chars)",
            )),
        ));
    }
    let account_id = truthlinked_core::pq_identity::account_id_from_pubkey(&pubkey_bytes);
    let state_arc = consensus.get_state();
    let state = state_arc.load();
    Ok(Json(build_balance_response(
        &state,
        &account_id,
        hex::encode(account_id),
    )))
}

async fn pubkey_by_account(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let bytes = hex::decode(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("account_id must be hex")),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("account_id must be 64 hex chars")),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let state = consensus.get_state().load_full();
    match state.accounts.get(&arr) {
        Some(acc) if !acc.pubkey_bytes.is_empty() => Ok(Json(serde_json::json!({
            "account_id": id,
            "pubkey": hex::encode(&acc.pubkey_bytes),
            "found": true
        }))),
        _ => Ok(Json(
            serde_json::json!({ "account_id": id, "pubkey": null, "found": false }),
        )),
    }
}

async fn account_info(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(id): Path<String>,
) -> Result<Json<AccountInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let account_id_bytes = hex::decode(&id).map_err(|_| {
        track_rpc_error();
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("account_id must be hex")),
        )
    })?;
    if account_id_bytes.len() != 32 {
        track_rpc_error();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "account_id must be 32 bytes (64 hex chars)",
            )),
        ));
    }
    let mut account_id_arr = [0u8; 32];
    account_id_arr.copy_from_slice(&account_id_bytes);

    let state_arc = consensus.get_state();
    let state = state_arc.load();
    let balance = state
        .accounts
        .get(&account_id_arr)
        .map(|acc| acc.balance)
        .unwrap_or(0);
    let compute_escrow_trth = state
        .accounts
        .get(&account_id_arr)
        .map(|acc| acc.compute_escrow_trth)
        .unwrap_or(0);
    let nonce = state
        .accounts
        .get(&account_id_arr)
        .map(|acc| acc.nonce)
        .unwrap_or(0);
    let found = state.accounts.contains_key(&account_id_arr);
    let cell = state.lookup_cell(&account_id_arr);
    let is_cell = cell.is_some();
    let (code_hash, storage_root) = if let Some(cell) = cell {
        let code_hash = blake3::hash(&cell.bytecode);
        let storage_root = compute_storage_root(&cell.storage);
        (
            Some(hex::encode(code_hash.as_bytes())),
            Some(hex::encode(storage_root)),
        )
    } else {
        (None, None)
    };

    let balance_formatted = truthlinked_state::trth::format_amount(balance);
    Ok(Json(AccountInfoResponse {
        account_id: id,
        found,
        balance: balance.to_string(),
        balance_tlkd: balance_formatted.clone(),
        balance_trth: balance_formatted,
        compute_escrow_trth: compute_escrow_trth.to_string(),
        nonce,
        replay_protection: "nonce+tx_hash".to_string(),
        code_hash,
        storage_root,
        is_cell,
    }))
}

async fn cell_info(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(id): Path<String>,
) -> Result<Json<CellInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let cell_id_bytes = hex::decode(&id).map_err(|_| {
        track_rpc_error();
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("cell_id must be hex")),
        )
    })?;
    if cell_id_bytes.len() != 32 {
        track_rpc_error();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "cell_id must be 32 bytes (64 hex chars)",
            )),
        ));
    }
    let mut cell_id_arr = [0u8; 32];
    cell_id_arr.copy_from_slice(&cell_id_bytes);

    let state_arc = consensus.get_state();
    let state = state_arc.load();
    let cell = state.lookup_cell(&cell_id_arr);

    let (found, is_token, immutable) = if let Some(c) = cell {
        (true, c.is_token, c.is_immutable)
    } else {
        (false, false, false)
    };

    Ok(Json(CellInfoResponse {
        cell_id: id,
        found,
        is_token,
        immutable,
    }))
}

async fn treasury_proposal(
    Path(id): Path<String>,
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
) -> Result<Json<TreasuryProposalResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();

    let id_bytes = hex::decode(&id).map_err(|_| {
        track_rpc_error();
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("proposal_id must be hex")),
        )
    })?;
    if id_bytes.len() != 32 {
        track_rpc_error();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "proposal_id must be 32 bytes (64 hex chars)",
            )),
        ));
    }
    let mut proposal_id = [0u8; 32];
    proposal_id.copy_from_slice(&id_bytes);

    let state = consensus.state_snapshot();
    let cell_id = truthlinked_core::pq_execution::treasury_system_cell_id();
    let cell = match state.lookup_cell(&cell_id) {
        Some(c) => c,
        None => {
            return Ok(Json(TreasuryProposalResponse {
                proposal_id: id,
                found: false,
                recipient: String::new(),
                amount: "0".to_string(),
                created_at_height: 0,
                timelock_blocks: 0,
                votes_for: 0,
                votes_against: 0,
                executed: false,
            }));
        }
    };

    let exists_ns = treasury_namespace("truthlinked.treasury.proposal.exists");
    let exists_slot = treasury_slot(&exists_ns, &[b"map:exists", &proposal_id]);
    let exists = cell.storage.get(&exists_slot).cloned().unwrap_or([0u8; 32]);
    if exists[0] != 1 {
        return Ok(Json(TreasuryProposalResponse {
            proposal_id: id,
            found: false,
            recipient: String::new(),
            amount: "0".to_string(),
            created_at_height: 0,
            timelock_blocks: 0,
            votes_for: 0,
            votes_against: 0,
            executed: false,
        }));
    }

    let recipient_ns = treasury_namespace("truthlinked.treasury.proposal.recipient");
    let amount_ns = treasury_namespace("truthlinked.treasury.proposal.amount");
    let created_ns = treasury_namespace("truthlinked.treasury.proposal.created");
    let timelock_ns = treasury_namespace("truthlinked.treasury.proposal.timelock");
    let votes_for_ns = treasury_namespace("truthlinked.treasury.proposal.votes_for");
    let votes_against_ns = treasury_namespace("truthlinked.treasury.proposal.votes_against");
    let executed_ns = treasury_namespace("truthlinked.treasury.proposal.executed");

    let recipient_slot = treasury_slot(&recipient_ns, &[b"map:value", &proposal_id]);
    let amount_slot = treasury_slot(&amount_ns, &[b"map:value", &proposal_id]);
    let created_slot = treasury_slot(&created_ns, &[b"map:value", &proposal_id]);
    let timelock_slot = treasury_slot(&timelock_ns, &[b"map:value", &proposal_id]);
    let votes_for_slot = treasury_slot(&votes_for_ns, &[b"map:value", &proposal_id]);
    let votes_against_slot = treasury_slot(&votes_against_ns, &[b"map:value", &proposal_id]);
    let executed_slot = treasury_slot(&executed_ns, &[b"map:value", &proposal_id]);

    let recipient_raw = cell
        .storage
        .get(&recipient_slot)
        .cloned()
        .unwrap_or([0u8; 32]);
    let amount_raw = cell.storage.get(&amount_slot).cloned().unwrap_or([0u8; 32]);
    let created_raw = cell
        .storage
        .get(&created_slot)
        .cloned()
        .unwrap_or([0u8; 32]);
    let timelock_raw = cell
        .storage
        .get(&timelock_slot)
        .cloned()
        .unwrap_or([0u8; 32]);
    let votes_for_raw = cell
        .storage
        .get(&votes_for_slot)
        .cloned()
        .unwrap_or([0u8; 32]);
    let votes_against_raw = cell
        .storage
        .get(&votes_against_slot)
        .cloned()
        .unwrap_or([0u8; 32]);
    let executed_raw = cell
        .storage
        .get(&executed_slot)
        .cloned()
        .unwrap_or([0u8; 32]);

    let amount = decode_u128(&amount_raw);
    let created_at_height = decode_u64(&created_raw);
    let timelock_blocks = decode_u64(&timelock_raw);
    let votes_for = decode_u64(&votes_for_raw);
    let votes_against = decode_u64(&votes_against_raw);
    let executed = executed_raw[0] == 1;

    Ok(Json(TreasuryProposalResponse {
        proposal_id: id,
        found: true,
        recipient: hex::encode(recipient_raw),
        amount: amount.to_string(),
        created_at_height,
        timelock_blocks,
        votes_for,
        votes_against,
        executed,
    }))
}

#[derive(Serialize)]
struct NftInfoResponse {
    found: bool,
    nft: Option<serde_json::Value>,
}

async fn nft_info(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(id): Path<String>,
) -> Result<Json<NftInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    track_rpc_request();
    let id_bytes = hex::decode(&id).map_err(|_| {
        track_rpc_error();
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("nft_id must be hex")),
        )
    })?;
    if id_bytes.len() != 32 {
        track_rpc_error();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("nft_id must be 32 bytes (64 hex chars)")),
        ));
    }
    let mut id_arr = [0u8; 32];
    id_arr.copy_from_slice(&id_bytes);

    let state = consensus.get_state().load();
    if let Some(nft) = state.nfts.get(&id_arr) {
        let mut response = serde_json::Map::new();
        response.insert("found".to_string(), serde_json::Value::Bool(true));
        response.insert(
            "nft_id".to_string(),
            serde_json::Value::String(hex::encode(nft.nft_id)),
        );
        response.insert(
            "owner".to_string(),
            serde_json::Value::String(hex::encode(nft.owner)),
        );
        response.insert(
            "name".to_string(),
            serde_json::Value::String(nft.name.clone()),
        );
        response.insert(
            "metadata_uri".to_string(),
            serde_json::Value::String(nft.metadata_uri.clone()),
        );
        response.insert(
            "minted_at".to_string(),
            serde_json::Value::Number(serde_json::Number::from(nft.minted_at)),
        );
        response.insert(
            "royalty_bps".to_string(),
            serde_json::Value::Number(serde_json::Number::from(nft.royalty_bps)),
        );

        if let Some(collection) = &nft.collection {
            response.insert(
                "collection".to_string(),
                serde_json::Value::String(hex::encode(*collection)),
            );
        }
        if let Some(recipient) = &nft.royalty_recipient {
            response.insert(
                "royalty_recipient".to_string(),
                serde_json::Value::String(hex::encode(*recipient)),
            );
        }
        if let Some(approved) = &nft.approved {
            response.insert(
                "approved".to_string(),
                serde_json::Value::String(hex::encode(*approved)),
            );
        }

        return Ok(Json(NftInfoResponse {
            found: true,
            nft: Some(serde_json::Value::Object(response)),
        }));
    }

    Ok(Json(NftInfoResponse {
        found: false,
        nft: None,
    }))
}

async fn nfts_by_owner(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(owner): Path<String>,
) -> Json<Value> {
    track_rpc_request();
    let owner_bytes = hex::decode(&owner).map_err(|_| {
        Json(json!({
            "success": false,
            "error": "owner must be hex",
            "error_code": map_error_code("owner must be hex"),
        }))
    });
    let owner_bytes = match owner_bytes {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if owner_bytes.len() != 32 {
        return Json(json!({
            "success": false,
            "error": "owner must be 32 bytes (64 hex chars)",
            "error_code": map_error_code("owner must be 32 bytes (64 hex chars)"),
        }));
    }
    let mut owner_arr = [0u8; 32];
    owner_arr.copy_from_slice(&owner_bytes);

    let state = consensus.get_state().load();

    // Collect all NFTs owned by this account
    let mut nfts: Vec<serde_json::Value> = Vec::new();
    for (_nft_id, nft) in state.nfts.iter() {
        if nft.owner == owner_arr {
            let mut nft_json = serde_json::Map::new();
            nft_json.insert(
                "nft_id".to_string(),
                serde_json::Value::String(hex::encode(nft.nft_id)),
            );
            nft_json.insert(
                "owner".to_string(),
                serde_json::Value::String(hex::encode(nft.owner)),
            );
            nft_json.insert(
                "name".to_string(),
                serde_json::Value::String(nft.name.clone()),
            );
            nft_json.insert(
                "metadata_uri".to_string(),
                serde_json::Value::String(nft.metadata_uri.clone()),
            );
            nft_json.insert(
                "minted_at".to_string(),
                serde_json::Value::Number(serde_json::Number::from(nft.minted_at)),
            );
            nft_json.insert(
                "royalty_bps".to_string(),
                serde_json::Value::Number(serde_json::Number::from(nft.royalty_bps)),
            );

            if let Some(collection) = &nft.collection {
                nft_json.insert(
                    "collection".to_string(),
                    serde_json::Value::String(hex::encode(*collection)),
                );
            }
            if let Some(recipient) = &nft.royalty_recipient {
                nft_json.insert(
                    "royalty_recipient".to_string(),
                    serde_json::Value::String(hex::encode(*recipient)),
                );
            }
            if let Some(approved) = &nft.approved {
                nft_json.insert(
                    "approved".to_string(),
                    serde_json::Value::String(hex::encode(*approved)),
                );
            }

            nfts.push(serde_json::Value::Object(nft_json));
        }
    }

    Json(json!({
        "success": true,
        "owner": owner,
        "count": nfts.len(),
        "nfts": nfts
    }))
}

#[derive(Serialize)]
struct ValidatorInfoResponse {
    pubkey: String,
    bonded: String,
    unbonding: Vec<UnbondingEntry>,
    jailed: bool,
    slash_count: u32,
}

#[derive(Serialize)]
struct UnbondingEntry {
    amount: String,
    completion_tick: u64,
}

#[derive(Deserialize)]
struct ValidatorInfoRequest {
    pubkey: String,
}

async fn validator_info(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Json(req): Json<ValidatorInfoRequest>,
) -> Json<Option<ValidatorInfoResponse>> {
    track_rpc_request();
    let pubkey_bytes = hex::decode(&req.pubkey).unwrap_or_default();

    let state_arc = consensus.get_state();
    let state = state_arc.load();
    let validator = state.staking.validators.get(&pubkey_bytes);

    Json(validator.map(|v| {
        ValidatorInfoResponse {
            pubkey: req.pubkey,
            bonded: v.active_stake.to_string(),
            unbonding: v
                .unbonding
                .iter()
                .map(|u| UnbondingEntry {
                    amount: u.amount.to_string(),
                    completion_tick: u.completion_tick,
                })
                .collect(),
            jailed: v.jailed_until.is_some(),
            slash_count: 0, // Not tracked in current ValidatorStake
        }
    }))
}

#[derive(Deserialize, Serialize)]
struct SubmitResponse {
    success: bool,
    tx_hash: Option<String>,
    error_code: Option<i32>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SimulateResponse {
    success: bool,
    gas_used: Option<String>,
    compute_units_consumed: Option<String>,
    gas_fee: Option<String>,
    name_fee: Option<String>,
    cu_fee: Option<String>,
    logs: Vec<String>,
    return_data: Option<String>,
    error_code: Option<i32>,
    error: Option<String>,
}

fn map_error_code(error: &str) -> Option<i32> {
    if let Some(idx) = error.find("Error code: ") {
        let tail = &error[idx + "Error code: ".len()..];
        let code_str = tail.split_whitespace().next().unwrap_or("");
        if let Ok(code) = code_str.parse::<i32>() {
            return Some(code);
        }
    }
    if error.starts_with("Failed to deserialize transaction:") {
        return Some(4003);
    }
    if error.starts_with("Failed to load transaction history:") {
        return Some(4004);
    }
    if error.contains("Node is syncing; try again later") {
        return Some(4002);
    }
    if error.contains("Direct calls to MCP tools are not permitted") {
        return Some(4101);
    }
    if error.contains("McpToolCall requires action_log_id") {
        return Some(4102);
    }
    match error {
        "account_id must be hex" => Some(1001),
        "account_id must be 32 bytes (64 hex chars)" => Some(1002),
        "account_id must be 64 hex chars" => Some(1003),
        "Invalid account_id format (must be 32-byte hex)" => Some(1004),
        "pubkey must be hex" => Some(1005),
        "pubkey must be 1952 bytes (Dilithium, 3904 hex chars)" => Some(1006),
        "cell_id must be hex" => Some(1007),
        "cell_id must be 32 bytes (64 hex chars)" => Some(1008),
        "cell_id and account_id must be 32 bytes each" => Some(1009),
        "proposal_id must be hex" => Some(1010),
        "proposal_id must be 32 bytes (64 hex chars)" => Some(1011),
        "nft_id must be hex" => Some(1012),
        "nft_id must be 32 bytes (64 hex chars)" => Some(1013),
        "owner must be hex" => Some(1014),
        "owner must be 32 bytes (64 hex chars)" => Some(1015),
        "resolve only supports .tl names; use /search for hashes or IDs" => Some(1201),
        "name expired" => Some(1202),
        "name not found" => Some(1203),
        "Storage not initialized" => Some(4001),
        _ => {
            let hash = blake3::hash(error.as_bytes());
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&hash.as_bytes()[..4]);
            let raw = u32::from_le_bytes(buf) % 1_000_000;
            Some(-((raw as i32) + 1))
        }
    }
}

async fn submit_raw(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    body: axum::body::Bytes,
) -> Json<SubmitResponse> {
    track_rpc_request();
    match postcard::from_bytes::<Transaction>(&body) {
        Ok(tx) => {
            // Reject only when materially behind; small live head lag can still accept tx ingress.
            if let Err(e) = consensus.can_accept_transactions().await {
                track_rpc_error();
                return Json(SubmitResponse {
                    success: false,
                    tx_hash: None,
                    error_code: map_error_code(&e),
                    error: Some(e),
                });
            }

            // Preflight validation so clients get a real error for the next executable
            // nonce, while still allowing pipelined future nonces into the mempool window.
            let state = consensus.get_state();
            let state_snapshot = state.load();
            let next_nonce = state_snapshot
                .accounts
                .get(&tx.sender)
                .map(|a| a.nonce.saturating_add(1))
                .unwrap_or(0);
            let preflight = if tx.nonce == next_nonce {
                state_snapshot.compute_transaction_diff(&tx).map(|_| ())
            } else {
                state_snapshot
                    .validate_transaction_for_mempool(&tx, gp::get_u64(gp::PARAM_NONCE_LOOKAHEAD))
            };
            if let Err(e) = preflight {
                track_rpc_error();
                return Json(SubmitResponse {
                    success: false,
                    tx_hash: None,
                    error_code: map_error_code(&e),
                    error: Some(e),
                });
            }

            // Submit to consensus (same as ingress WebSocket). This must report
            // admission failure instead of a transport-level false positive.
            match consensus.submit_transaction(tx).await {
                Ok(tx_hash) => Json(SubmitResponse {
                    success: true,
                    tx_hash: Some(hex::encode(tx_hash)),
                    error_code: None,
                    error: None,
                }),
                Err(e) => {
                    track_rpc_error();
                    Json(SubmitResponse {
                        success: false,
                        tx_hash: None,
                        error_code: map_error_code(&e),
                        error: Some(e),
                    })
                }
            }
        }
        Err(e) => {
            track_rpc_error();
            Json(SubmitResponse {
                success: false,
                tx_hash: None,
                error_code: None,
                error: Some(format!("Failed to deserialize transaction: {}", e)),
            })
        }
    }
}

async fn simulate_raw(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    body: axum::body::Bytes,
) -> Json<SimulateResponse> {
    track_rpc_request();
    match postcard::from_bytes::<Transaction>(&body) {
        Ok(tx) => {
            if let Err(e) = consensus.can_accept_transactions().await {
                track_rpc_error();
                return Json(SimulateResponse {
                    success: false,
                    gas_used: None,
                    compute_units_consumed: None,
                    gas_fee: None,
                    name_fee: None,
                    cu_fee: None,
                    logs: vec![],
                    return_data: None,
                    error_code: None,
                    error: Some(e),
                });
            }

            let state = consensus.get_state();
            match state.load().compute_transaction_diff(&tx) {
                Ok(diff) => Json(SimulateResponse {
                    success: true,
                    gas_used: Some(diff.gas_fee.to_string()),
                    compute_units_consumed: Some(diff.cu_fee.to_string()),
                    gas_fee: Some(diff.gas_fee.to_string()),
                    name_fee: Some(diff.name_fee.to_string()),
                    cu_fee: Some(diff.cu_fee.to_string()),
                    logs: vec![],
                    return_data: None,
                    error_code: None,
                    error: None,
                }),
                Err(e) => {
                    track_rpc_error();
                    Json(SimulateResponse {
                        success: false,
                        gas_used: None,
                        compute_units_consumed: None,
                        gas_fee: None,
                        name_fee: None,
                        cu_fee: None,
                        logs: vec![],
                        return_data: None,
                        error_code: map_error_code(&e),
                        error: Some(e),
                    })
                }
            }
        }
        Err(e) => {
            track_rpc_error();
            Json(SimulateResponse {
                success: false,
                gas_used: None,
                compute_units_consumed: None,
                gas_fee: None,
                name_fee: None,
                cu_fee: None,
                logs: vec![],
                return_data: None,
                error_code: None,
                error: Some(format!("Failed to deserialize transaction: {}", e)),
            })
        }
    }
}

#[derive(Deserialize)]
struct TransactionHistoryRequest {
    account_id: String, // Hex-encoded account ID
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize {
    50
}

#[derive(Serialize)]
struct TransactionHistoryResponse {
    success: bool,
    transactions: Vec<serde_json::Value>,
    total_count: u64,
    error_code: Option<i32>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct RecentTransactionsQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

async fn recent_transactions(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Query(req): Query<RecentTransactionsQuery>,
) -> Json<serde_json::Value> {
    track_rpc_request();
    let Some(storage) = consensus.get_storage() else {
        track_rpc_error();
        return Json(
            json!({ "success": false, "transactions": [], "total_count": 0, "error": "Storage not initialized" }),
        );
    };

    let limit = req.limit.clamp(1, 250);
    match storage.load_recent_transactions(limit, req.offset) {
        Ok((transactions, total_count)) => Json(json!({
            "success": true,
            "transactions": transactions,
            "total_count": total_count,
            "limit": limit,
            "offset": req.offset,
        })),
        Err(e) => {
            track_rpc_error();
            Json(
                json!({ "success": false, "transactions": [], "total_count": 0, "error": e.to_string() }),
            )
        }
    }
}

async fn transaction_history(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Json(req): Json<TransactionHistoryRequest>,
) -> Json<TransactionHistoryResponse> {
    track_rpc_request();
    // Decode account ID
    let account_id = match hex::decode(&req.account_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            track_rpc_error();
            return Json(TransactionHistoryResponse {
                success: false,
                transactions: vec![],
                total_count: 0,
                error_code: map_error_code("Invalid account_id format (must be 32-byte hex)"),
                error: Some("Invalid account_id format (must be 32-byte hex)".to_string()),
            });
        }
    };

    // Get storage
    let storage = match consensus.get_storage() {
        Some(s) => s,
        None => {
            track_rpc_error();
            return Json(TransactionHistoryResponse {
                success: false,
                transactions: vec![],
                total_count: 0,
                error_code: map_error_code("Storage not initialized"),
                error: Some("Storage not initialized".to_string()),
            });
        }
    };

    // Use optimized transaction history loading
    match storage.load_optimized_transaction_history(&account_id, req.limit, req.offset) {
        Ok((transactions, total_count)) => Json(TransactionHistoryResponse {
            success: true,
            transactions,
            total_count,
            error_code: None,
            error: None,
        }),
        Err(e) => {
            track_rpc_error();
            let msg = format!("Failed to load transaction history: {}", e);
            Json(TransactionHistoryResponse {
                success: false,
                transactions: vec![],
                total_count: 0,
                error_code: map_error_code(&msg),
                error: Some(msg),
            })
        }
    }
}

async fn metrics(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
) -> impl axum::response::IntoResponse {
    track_rpc_request();
    let metrics = truthlinked_state::metrics::global();
    metrics.set_height(consensus.get_current_height());
    metrics.set_finalized_height(consensus.get_finalized_height());
    metrics.set_mempool_size(consensus.batch_len().await as u64);
    metrics.set_peer_count(consensus.get_peer_count().await as u64);
    let (tps_1min, tps_5min, avg_block_time) = compute_network_stats(&consensus);
    metrics.set_avg_block_time_ms((avg_block_time * 1000.0) as u64);
    metrics.set_tps_1min(tps_1min.round() as u64);
    metrics.set_tps_5min(tps_5min.round() as u64);
    let body = metrics.render_prometheus();
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

async fn storage_metrics(AxumState(consensus): AxumState<Arc<StreamingConsensus>>) -> Json<Value> {
    track_rpc_request();
    if let Some(storage) = consensus.get_storage() {
        let m = storage.storage_metrics();
        Json(json!({
            "active_entries": m.active_entries,
            "flushing_entries": m.flushing_entries,
            "compacting_entries": m.compacting_entries,
            "index_entries": m.index_entries,
            "wal_bytes_since_compaction": m.wal_bytes_since_compaction,
            "wal_file_bytes": m.wal_file_bytes,
            "snapshot_file_bytes": m.snapshot_file_bytes,
            "compaction_active": m.compaction_active,
            "flush_active": m.flush_active,
            "sst_l0_files": m.sst_l0_files,
            "sst_l1_files": m.sst_l1_files,
            "sst_l2_files": m.sst_l2_files,
            "estimated_read_amplification": m.estimated_read_amplification,
        }))
    } else {
        Json(json!({"error": "storage not attached"}))
    }
}

// ========== NEW ENDPOINTS ==========

#[derive(Serialize)]
struct BlockResponse {
    height: u64,
    hash: String,
    parent_hash: String,
    state_root: String,
    timestamp: u64,
    validator: String,
    tx_count: usize,
    vote_tx_count: usize,
    transactions: Vec<serde_json::Value>,
    total_fees: String,
}

#[derive(Deserialize)]
struct BlockQuery {
    #[serde(default)]
    full: bool,
}

fn block_tx_record(tx: &Transaction, height: u64, batch_hash: [u8; 32]) -> serde_json::Value {
    let tx_hash: [u8; 32] =
        *blake3::hash(&postcard::to_allocvec(tx).unwrap_or_default()).as_bytes();
    serde_json::json!({
        "tx_hash": hex::encode(tx_hash),
        "batch_hash": hex::encode(batch_hash),
        "sender": hex::encode(tx.sender),
        "status": "confirmed",
        "timestamp": tx.timestamp,
        "intent": serde_json::to_value(&tx.intent).unwrap_or(serde_json::Value::Null),
        "height": height
    })
}

async fn get_block_by_height(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(height): Path<u64>,
    Query(query): Query<BlockQuery>,
) -> Json<Option<BlockResponse>> {
    let storage = match consensus.get_storage() {
        Some(s) => s,
        None => return Json(None),
    };

    let header = match storage.load_batch_header_by_height(height) {
        Ok(Some(h)) => h,
        _ => return Json(None),
    };

    let batch = storage.load_batch(height).ok().flatten();
    let transactions = if let Some(txs) = batch.as_ref().filter(|txs| !txs.is_empty()) {
        let mut out = Vec::with_capacity(txs.len());
        for tx in txs {
            if query.full {
                out.push(block_tx_record(tx, header.height, header.batch_hash));
            } else {
                let tx_hash: [u8; 32] =
                    *blake3::hash(&postcard::to_allocvec(tx).unwrap_or_default()).as_bytes();
                out.push(json!({
                    "tx_hash": hex::encode(tx_hash),
                }));
            }
        }
        out
    } else {
        storage
            .load_transactions_by_height(height)
            .unwrap_or_default()
            .into_iter()
            .map(|mut tx| {
                if !query.full {
                    let hash = tx
                        .get("tx_hash")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    tx = json!({ "tx_hash": hash });
                }
                tx
            })
            .collect()
    };

    Json(Some(BlockResponse {
        height: header.height,
        hash: hex::encode(header.batch_hash),
        parent_hash: hex::encode(header.parent_hash),
        state_root: hex::encode(header.state_root),
        timestamp: header.timestamp,
        validator: hex::encode(header.leader_pubkey),
        tx_count: transactions.len(),
        vote_tx_count: header.finality_certificate.signer_count(),
        transactions,
        total_fees: header.total_fees.to_string(),
    }))
}

async fn get_block_attestations(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(height): Path<u64>,
) -> Json<serde_json::Value> {
    let storage = match consensus.get_storage() {
        Some(s) => s,
        None => return Json(json!([])),
    };
    let header = match storage.load_batch_header_by_height(height) {
        Ok(Some(h)) => h,
        _ => return Json(json!([])),
    };
    let attestations: Vec<serde_json::Value> = header
        .finality_certificate
        .signatures
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let validator_hex = hex::encode(&a.validator_pubkey);
            let account_id = validator_hex.chars().take(64).collect::<String>();
            json!({
                "index":         i,
                "validator_index": a.validator_index,
                "height":        height,
                "block_hash":    hex::encode(header.batch_hash),
                "validator":     validator_hex,
                "account_id":    account_id,
                "sig_truncated": hex::encode(&a.signature[..8.min(a.signature.len())]),
            })
        })
        .collect();
    Json(json!({
        "height":     height,
        "block_hash": hex::encode(header.batch_hash),
        "count":      attestations.len(),
        "certificate_signed_stake": header.finality_certificate.signed_stake.to_string(),
        "certificate_signature_root": hex::encode(header.finality_certificate.signature_root),
        "attestations": attestations,
    }))
}

async fn get_latest_block(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Query(query): Query<BlockQuery>,
) -> Json<Option<BlockResponse>> {
    let height = consensus.get_current_height();
    if height == 0 {
        return Json(None);
    }

    let storage = match consensus.get_storage() {
        Some(s) => s,
        None => return Json(None),
    };

    let header = match storage.load_batch_header_by_height(height) {
        Ok(Some(h)) => h,
        _ => return Json(None),
    };

    let batch = storage.load_batch(height).ok().flatten();
    let transactions = if let Some(txs) = batch.as_ref().filter(|txs| !txs.is_empty()) {
        let mut out = Vec::with_capacity(txs.len());
        for tx in txs {
            if query.full {
                out.push(block_tx_record(tx, header.height, header.batch_hash));
            } else {
                let tx_hash: [u8; 32] =
                    *blake3::hash(&postcard::to_allocvec(tx).unwrap_or_default()).as_bytes();
                out.push(json!({
                    "tx_hash": hex::encode(tx_hash),
                }));
            }
        }
        out
    } else {
        storage
            .load_transactions_by_height(height)
            .unwrap_or_default()
            .into_iter()
            .map(|mut tx| {
                if !query.full {
                    let hash = tx
                        .get("tx_hash")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    tx = json!({ "tx_hash": hash });
                }
                tx
            })
            .collect()
    };

    Json(Some(BlockResponse {
        height: header.height,
        hash: hex::encode(header.batch_hash),
        parent_hash: hex::encode(header.parent_hash),
        state_root: hex::encode(header.state_root),
        timestamp: header.timestamp,
        validator: hex::encode(header.leader_pubkey),
        tx_count: transactions.len(),
        vote_tx_count: header.finality_certificate.signer_count(),
        transactions,
        total_fees: header.total_fees.to_string(),
    }))
}

#[derive(Serialize)]
struct TransactionResponse {
    hash: String,
    height: u64,
    timestamp: u64,
    from: String,
    intent: serde_json::Value,
    success: bool,
    status: String,
    error: Option<String>,
    gas_used: u64,
    gas_breakdown: Vec<(String, u64)>,
    gas_fee: Option<String>,
    cu_fee: Option<String>,
    compute_fee_trth: Option<String>,
    fee_paid_tlkd: Option<String>,
}

fn tx_string_field(tx_data: &serde_json::Value, key: &str) -> Option<String> {
    tx_data.get(key).and_then(|v| {
        if let Some(s) = v.as_str() {
            Some(s.to_string())
        } else if v.is_number() {
            Some(v.to_string())
        } else {
            None
        }
    })
}

#[derive(Deserialize)]
struct TxQuery {
    #[serde(default)]
    full: bool,
}

fn compute_gas_breakdown(intent: &serde_json::Value) -> (u64, Vec<(String, u64)>) {
    use truthlinked_governance::params as gp;
    let kind = intent
        .get("type")
        .or_else(|| intent.get("kind"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sig: u64 = 500;
    let (total, mut steps): (u64, Vec<(&str, u64)>) = match kind {
        "Transfer" | "TransferToName" => {
            let g = gp::get_u64(gp::PARAM_GAS_TRANSFER);
            (
                g,
                vec![("Balance debit", g / 2), ("Balance credit", g - g / 2)],
            )
        }
        "BatchTransfer" | "BatchTransferToName" => {
            let count = intent
                .get("transfers")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u64)
                .unwrap_or(1);
            let g = gp::get_u64(gp::PARAM_GAS_TRANSFER) * count;
            (
                g,
                vec![
                    ("Balance debit (x recipients)", g / 2),
                    ("Balance credit (x recipients)", g - g / 2),
                ],
            )
        }
        "Stake" => {
            let g = gp::get_u64(gp::PARAM_GAS_STAKE);
            (
                g,
                vec![("Balance debit", g / 5), ("Stake record write", g - g / 5)],
            )
        }
        "Unstake" => {
            let g = gp::get_u64(gp::PARAM_GAS_UNSTAKE);
            (
                g,
                vec![
                    ("Stake record read", g / 5),
                    ("Unbonding record write", g - g / 5),
                ],
            )
        }
        "WithdrawStake" => {
            let g = gp::get_u64(gp::PARAM_GAS_WITHDRAW);
            (
                g,
                vec![
                    ("Unbonding record read", g / 5),
                    ("Balance credit", g - g / 5),
                ],
            )
        }
        "Claim" => {
            let g = gp::get_u64(gp::PARAM_GAS_CLAIM);
            (
                g,
                vec![("Claim record read", g / 4), ("Balance credit", g - g / 4)],
            )
        }
        "RotateKey" => {
            let g = gp::get_u64(gp::PARAM_GAS_ROTATE_KEY);
            (g, vec![("Key record write", g)])
        }
        "DepositCompute" => {
            let g = gp::get_u64(gp::PARAM_GAS_TRANSFER);
            (
                g,
                vec![
                    ("Balance debit", g / 2),
                    ("Compute escrow credit", g - g / 2),
                ],
            )
        }
        "WithdrawCompute" => {
            let g = gp::get_u64(gp::PARAM_GAS_TRANSFER);
            (
                g,
                vec![
                    ("Compute escrow debit", g / 2),
                    ("Balance credit", g - g / 2),
                ],
            )
        }
        "WrapTRTH" => {
            let g = gp::get_u64(gp::PARAM_GAS_TRANSFER);
            (
                g,
                vec![("Balance debit", g / 2), ("wTLKD token mint", g - g / 2)],
            )
        }
        "UnwrapTRTH" => {
            let g = gp::get_u64(gp::PARAM_GAS_TRANSFER);
            (
                g,
                vec![("wTLKD token burn", g / 2), ("Balance credit", g - g / 2)],
            )
        }
        "TokenTransfer" => {
            let g = gp::get_u64(gp::PARAM_GAS_TOKEN_TRANSFER);
            (
                g,
                vec![
                    ("Token balance debit", g * 2 / 5),
                    ("Token balance credit", g - g * 2 / 5),
                ],
            )
        }
        "TokenMint" => {
            let g = gp::get_u64(gp::PARAM_GAS_TOKEN_MINT);
            (
                g,
                vec![
                    ("Authority check", g / 10),
                    ("Token supply update", g / 10),
                    ("Token balance credit", g - g / 10 - g / 10),
                ],
            )
        }
        "TokenBurn" => {
            let g = gp::get_u64(gp::PARAM_GAS_TOKEN_BURN);
            (
                g,
                vec![
                    ("Token balance debit", g * 9 / 10),
                    ("Token supply update", g - g * 9 / 10),
                ],
            )
        }
        "MintNFT" => {
            let g = gp::get_u64(gp::PARAM_GAS_MINT_NFT);
            (
                g,
                vec![
                    ("NFT metadata write", g * 9 / 10),
                    ("Ownership record write", g - g * 9 / 10),
                ],
            )
        }
        "TransferNFT" => {
            let g = gp::get_u64(gp::PARAM_GAS_TRANSFER_NFT);
            (
                g,
                vec![
                    ("Ownership check", g / 5),
                    ("Ownership record write", g - g / 5),
                ],
            )
        }
        "BurnNFT" => {
            let g = gp::get_u64(gp::PARAM_GAS_BURN_NFT);
            (
                g,
                vec![
                    ("Ownership check", g * 2 / 5),
                    ("NFT record delete", g - g * 2 / 5),
                ],
            )
        }
        "ApproveNFT" => {
            let g = gp::get_u64(gp::PARAM_GAS_APPROVE_NFT);
            (g, vec![("Approval record write", g)])
        }
        "DeployCell" => {
            let g = gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL);
            (
                g,
                vec![
                    ("Bytecode validation", g / 2),
                    ("Cell record write", g / 4),
                    ("Storage allocation", g - g / 2 - g / 4),
                ],
            )
        }
        "DeployToken" => {
            let g = gp::get_u64(gp::PARAM_GAS_DEPLOY_TOKEN);
            (
                g,
                vec![
                    ("Token schema validation", g / 2),
                    ("Token record write", g - g / 2),
                ],
            )
        }
        "UpgradeCell" => {
            let g = gp::get_u64(gp::PARAM_GAS_UPGRADE_CELL);
            (
                g,
                vec![
                    ("Authority check", g / 10),
                    ("Bytecode replace", g - g / 10),
                ],
            )
        }
        "CallCell" | "McpToolCall" | "CallCellChain" => {
            let gas_limit = intent
                .get("gas_limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL));
            let exec = gas_limit.saturating_sub(sig);
            (gas_limit, vec![("Cell execution (Axiom VM)", exec)])
        }
        "Unjail" => {
            let g = gp::get_u64(gp::PARAM_GAS_UNJAIL);
            (g, vec![("Validator record write", g)])
        }
        _ => (0, vec![]),
    };
    // Prepend sig verify to all steps
    let total_with_sig = total.saturating_add(sig);
    let mut out: Vec<(String, u64)> = vec![("Signature verify (ML-DSA-65)".to_string(), sig)];
    out.extend(steps.drain(..).map(|(l, c)| (l.to_string(), c)));
    (total_with_sig, out)
}

async fn get_transaction_by_hash(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(hash): Path<String>,
    Query(query): Query<TxQuery>,
) -> Json<Option<TransactionResponse>> {
    let storage = match consensus.get_storage() {
        Some(s) => s,
        None => return Json(None),
    };

    // Full hash lookup (64 hex chars)
    if let Ok(bytes) = hex::decode(&hash) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            if let Ok(Some(tx_data)) = storage.get_transaction_by_hash(&arr) {
                let intent = tx_data
                    .get("intent")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let (gas_used, gas_breakdown) = compute_gas_breakdown(&intent);
                let intent_out = if query.full {
                    intent
                } else {
                    serde_json::Value::Null
                };
                return Json(Some(TransactionResponse {
                    hash,
                    height: tx_data.get("height").and_then(|v| v.as_u64()).unwrap_or(0),
                    timestamp: tx_data
                        .get("timestamp")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    from: tx_data
                        .get("from")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    intent: intent_out,
                    success: true,
                    status: "confirmed".to_string(),
                    error: None,
                    gas_used,
                    gas_breakdown,
                    gas_fee: tx_string_field(&tx_data, "gas_fee"),
                    cu_fee: tx_string_field(&tx_data, "cu_fee"),
                    compute_fee_trth: tx_string_field(&tx_data, "compute_fee_trth"),
                    fee_paid_tlkd: tx_string_field(&tx_data, "fee_paid_tlkd"),
                }));
            }
            if let Some(status) = consensus.get_tx_lifecycle(&arr).await {
                if let truthlinked_consensus::streaming_consensus::TxLifecycleStatus::Pending {
                    since_height,
                } = status
                {
                    const STALE_PENDING_TX_BLOCKS: u64 = 64;
                    let finalized_height = consensus.get_finalized_height();
                    if finalized_height > since_height.saturating_add(STALE_PENDING_TX_BLOCKS) {
                        let still_in_mempool = consensus
                            .get_mempool_txs_with_hashes()
                            .await
                            .iter()
                            .any(|(tx_hash, _)| tx_hash == &arr);
                        if !still_in_mempool {
                            return Json(Some(transaction_lifecycle_response(
                                hash,
                                truthlinked_consensus::streaming_consensus::TxLifecycleStatus::Rejected {
                                    reason: format!(
                                        "not included within {} finalized blocks",
                                        STALE_PENDING_TX_BLOCKS
                                    ),
                                },
                            )));
                        }
                    }
                }
                return Json(Some(transaction_lifecycle_response(hash, status)));
            }
            return Json(None);
        }
    }

    // Prefix lookup for shorter hashes (dev convenience).
    let prefix = hash.trim().to_lowercase();
    if prefix.len() >= 8 && prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        match storage.get_transaction_by_hash_prefix(&prefix) {
            Ok(Some(tx_data)) => {
                let intent = tx_data
                    .get("intent")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let (gas_used, gas_breakdown) = compute_gas_breakdown(&intent);
                let intent_out = if query.full {
                    intent
                } else {
                    serde_json::Value::Null
                };
                return Json(Some(TransactionResponse {
                    hash: tx_data
                        .get("tx_hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&hash)
                        .to_string(),
                    height: tx_data.get("height").and_then(|v| v.as_u64()).unwrap_or(0),
                    timestamp: tx_data
                        .get("timestamp")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    from: tx_data
                        .get("from")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    intent: intent_out,
                    success: true,
                    status: "confirmed".to_string(),
                    error: None,
                    gas_used,
                    gas_breakdown,
                    gas_fee: tx_string_field(&tx_data, "gas_fee"),
                    cu_fee: tx_string_field(&tx_data, "cu_fee"),
                    compute_fee_trth: tx_string_field(&tx_data, "compute_fee_trth"),
                    fee_paid_tlkd: tx_string_field(&tx_data, "fee_paid_tlkd"),
                }));
            }
            Ok(None) => return Json(None),
            Err(_) => return Json(None),
        }
    }

    Json(None)
}

fn transaction_lifecycle_response(
    hash: String,
    status: truthlinked_consensus::streaming_consensus::TxLifecycleStatus,
) -> TransactionResponse {
    match status {
        truthlinked_consensus::streaming_consensus::TxLifecycleStatus::Pending { since_height } => {
            TransactionResponse {
                hash,
                height: since_height,
                timestamp: 0,
                from: String::new(),
                intent: serde_json::Value::Null,
                success: false,
                status: "pending".to_string(),
                error: None,
                gas_used: 0,
                gas_breakdown: Vec::new(),
                gas_fee: None,
                cu_fee: None,
                compute_fee_trth: None,
                fee_paid_tlkd: None,
            }
        }
        truthlinked_consensus::streaming_consensus::TxLifecycleStatus::Confirmed => {
            TransactionResponse {
                hash,
                height: 0,
                timestamp: 0,
                from: String::new(),
                intent: serde_json::Value::Null,
                success: true,
                status: "confirmed".to_string(),
                error: None,
                gas_used: 0,
                gas_breakdown: Vec::new(),
                gas_fee: None,
                cu_fee: None,
                compute_fee_trth: None,
                fee_paid_tlkd: None,
            }
        }
        truthlinked_consensus::streaming_consensus::TxLifecycleStatus::Rejected { reason } => {
            TransactionResponse {
                hash,
                height: 0,
                timestamp: 0,
                from: String::new(),
                intent: serde_json::Value::Null,
                success: false,
                status: "rejected".to_string(),
                error: Some(reason),
                gas_used: 0,
                gas_breakdown: Vec::new(),
                gas_fee: None,
                cu_fee: None,
                compute_fee_trth: None,
                fee_paid_tlkd: None,
            }
        }
    }
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

#[derive(Serialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

#[derive(Serialize)]
struct SearchResult {
    #[serde(rename = "type")]
    result_type: String,
    id: String,
    url: String,
    meta: serde_json::Value,
}

#[derive(Serialize)]
struct ResolveResponse {
    query: String,
    resolved_address: Option<String>,
    resolver: Option<String>,
    expiry: Option<u64>,
    error_code: Option<i32>,
    error: Option<String>,
}

async fn search(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    axum::extract::Query(query): axum::extract::Query<SearchQuery>,
) -> Json<SearchResponse> {
    let storage = match consensus.get_storage() {
        Some(s) => s,
        None => return Json(SearchResponse { results: vec![] }),
    };
    let mut results = vec![];

    // Try as height
    if let Ok(height) = query.q.parse::<u64>() {
        if let Ok(Some(header)) = storage.load_batch_header_by_height(height) {
            let hash = hex::encode(header.batch_hash);
            results.push(SearchResult {
                result_type: "block".to_string(),
                id: height.to_string(),
                url: format!("/block/{}", height),
                meta: json!({
                    "height": header.height,
                    "hash": hash,
                    "timestamp": header.timestamp,
                }),
            });
        }
    }

    // Try as tx hash
    if let Ok(hash_bytes) = hex::decode(&query.q) {
        if hash_bytes.len() == 32 {
            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(&hash_bytes);

            if let Ok(Some(tx_data)) = storage.get_transaction_by_hash(&tx_hash) {
                let height = tx_data.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                let from = tx_data
                    .get("from")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                results.push(SearchResult {
                    result_type: "tx".to_string(),
                    id: query.q.clone(),
                    url: format!("/tx/{}", query.q),
                    meta: json!({
                        "height": height,
                        "from": from,
                    }),
                });
            }

            // Try as account ID
            let state_arc = consensus.get_state();
            let state = state_arc.load();

            if let Some(account) = state.accounts.get(&tx_hash) {
                let is_cell = state.lookup_cell(&tx_hash).is_some();
                results.push(SearchResult {
                    result_type: "address".to_string(),
                    id: query.q.clone(),
                    url: format!("/account/{}", query.q),
                    meta: json!({
                        "balance": account.balance.to_string(),
                        "is_cell": is_cell,
                    }),
                });
            }
        }
    }

    if query.q.ends_with(".tl") {
        let state_arc = consensus.get_state();
        let state = state_arc.load();
        let current_height = state.staking.current_height;
        if let Some(reg) = state.name_registry.get(&query.q) {
            if current_height < reg.expires_at {
                let account_id = hex::encode(reg.target);
                results.push(SearchResult {
                    result_type: "name".to_string(),
                    id: query.q.clone(),
                    url: format!("/resolve/{}", query.q),
                    meta: json!({
                        "account_id": account_id,
                        "expires_at": reg.expires_at,
                        "is_cell": reg.is_cell,
                    }),
                });
            }
        }
    }

    Json(SearchResponse { results })
}

async fn resolve(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
    Path(q): Path<String>,
) -> Json<ResolveResponse> {
    track_rpc_request();
    if !q.ends_with(".tl") {
        return Json(ResolveResponse {
            query: q,
            resolved_address: None,
            resolver: None,
            expiry: None,
            error_code: map_error_code(
                "resolve only supports .tl names; use /search for hashes or IDs",
            ),
            error: Some(
                "resolve only supports .tl names; use /search for hashes or IDs".to_string(),
            ),
        });
    }

    let state_arc = consensus.get_state();
    let state = state_arc.load();
    let current_height = state.staking.current_height;
    if let Some(reg) = state.name_registry.get(&q) {
        if current_height < reg.expires_at {
            return Json(ResolveResponse {
                query: q,
                resolved_address: Some(hex::encode(reg.target)),
                resolver: Some("name_registry".to_string()),
                expiry: Some(reg.expires_at),
                error_code: None,
                error: None,
            });
        }
        return Json(ResolveResponse {
            query: q,
            resolved_address: None,
            resolver: Some("name_registry".to_string()),
            expiry: Some(reg.expires_at),
            error_code: map_error_code("name expired"),
            error: Some("name expired".to_string()),
        });
    }

    Json(ResolveResponse {
        query: q,
        resolved_address: None,
        resolver: Some("name_registry".to_string()),
        expiry: None,
        error_code: map_error_code("name not found"),
        error: Some("name not found".to_string()),
    })
}

async fn name_registry_dump(
    AxumState(consensus): AxumState<Arc<StreamingConsensus>>,
) -> Json<serde_json::Value> {
    track_rpc_request();
    let state = consensus.get_state().load();
    let current_height = state.staking.current_height;
    let names: serde_json::Map<String, serde_json::Value> = state
        .name_registry
        .iter()
        .filter(|(_, reg)| current_height < reg.expires_at)
        .map(|(name, reg)| {
            (
                name.clone(),
                json!({
                    "address": hex::encode(reg.target),
                    "expires_at": reg.expires_at,
                    "is_cell": reg.is_cell,
                }),
            )
        })
        .collect();
    Json(json!({ "names": names }))
}

