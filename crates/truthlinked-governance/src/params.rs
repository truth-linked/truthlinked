//! Governance-controlled protocol parameter definitions.
//!
//! Parameters are named, typed at the access boundary, and hashed with a stable
//! domain separator so proposals and runtime reads agree on the same key space.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use truthlinked_core::constants;

const PARAM_DOMAIN: &[u8] = b"truthlinked.param.v1";

pub const PARAM_GAS_TRANSFER: &str = "gas.transfer";
pub const PARAM_GAS_CLAIM: &str = "gas.claim";
pub const PARAM_GAS_ROTATE_KEY: &str = "gas.rotate_key";
pub const PARAM_GAS_REGISTER_VALIDATOR: &str = "gas.register_validator";
pub const PARAM_GAS_STAKE: &str = "gas.stake";
pub const PARAM_GAS_UNSTAKE: &str = "gas.unstake";
pub const PARAM_GAS_WITHDRAW: &str = "gas.withdraw";
pub const PARAM_GAS_UNJAIL: &str = "gas.unjail";
pub const PARAM_GAS_MINT_NFT: &str = "gas.mint_nft";
pub const PARAM_GAS_TRANSFER_NFT: &str = "gas.transfer_nft";
pub const PARAM_GAS_BURN_NFT: &str = "gas.burn_nft";
pub const PARAM_GAS_APPROVE_NFT: &str = "gas.approve_nft";
pub const PARAM_GAS_DEPLOY_CELL: &str = "gas.deploy_cell";
pub const PARAM_GAS_DEPLOY_TOKEN: &str = "gas.deploy_token";
pub const PARAM_GAS_UPGRADE_CELL: &str = "gas.upgrade_cell";
pub const PARAM_GAS_TOKEN_TRANSFER: &str = "gas.token_transfer";
pub const PARAM_GAS_TOKEN_MINT: &str = "gas.token_mint";
pub const PARAM_GAS_TOKEN_BURN: &str = "gas.token_burn";
pub const PARAM_GAS_ORACLE_READ: &str = "gas.oracle_read";
pub const PARAM_GAS_ORACLE_QUEUE: &str = "gas.oracle_queue";
pub const PARAM_GAS_PRICE: &str = "gas.price";
pub const PARAM_GAS_DISTRIBUTION_INTERVAL: &str = "gas.distribution_interval";

pub const PARAM_EMISSION_YEAR1_TLKD: &str = "emission.year1_tlkd";
pub const PARAM_EMISSION_DECAY_BPS_PER_YEAR: &str = "emission.decay_bps_per_year";
pub const PARAM_EMISSION_EPOCH_BLOCKS: &str = "emission.epoch_blocks";

pub const PARAM_BATCH_INTERVAL_MS: &str = "consensus.batch_interval_ms";
pub const PARAM_MAX_BATCH_SIZE: &str = "consensus.max_batch_size";
pub const PARAM_COMMITTEE_SIZE: &str = "consensus.committee_size";
pub const PARAM_EPOCH_DURATION_MS: &str = "consensus.epoch_duration_ms";
pub const PARAM_FINALIZATION_LAG: &str = "consensus.finalization_lag";
pub const PARAM_FINALIZATION_TIMEOUT_SECS: &str = "consensus.finalization_timeout_secs";
pub const PARAM_SYNC_THRESHOLD: &str = "sync.threshold";
pub const PARAM_MAX_BATCH_RANGE: &str = "sync.max_batch_range";
pub const PARAM_SYNC_PEER_TTL_SECS: &str = "sync.peer_ttl_secs";
pub const PARAM_SYNC_SNAPSHOT_THRESHOLD: &str = "sync.snapshot_threshold";

pub const PARAM_SLASH_PERCENTAGE: &str = "staking.slash_percentage";
pub const PARAM_ORACLE_LIE_SLASH_PERCENTAGE: &str = "staking.oracle_lie_slash_percentage";
pub const PARAM_ORACLE_SILENCE_SLASH_PERCENTAGE: &str = "staking.oracle_silence_slash_percentage";
pub const PARAM_DOWNTIME_SLASH_PERCENTAGE: &str = "staking.downtime_slash_percentage";
pub const PARAM_CENSORSHIP_SLASH_PERCENTAGE: &str = "staking.censorship_slash_percentage";

pub const PARAM_STREAMING_OPTIMAL_BATCH_SIZE: &str = "streaming.optimal_batch_size";
pub const PARAM_STREAMING_MAX_WAIT_MS: &str = "streaming.max_wait_ms";
pub const PARAM_STREAMING_MAX_SYNC_BUFFER_SIZE: &str = "streaming.max_sync_buffer_size";
pub const PARAM_STREAMING_MAX_BATCH_CACHE: &str = "streaming.max_batch_cache";
pub const PARAM_STREAMING_MAX_PENDING_HEADERS: &str = "streaming.max_pending_headers";
pub const PARAM_STREAMING_MAX_SEEN_TXS: &str = "streaming.max_seen_txs";
pub const PARAM_STREAMING_PENDING_BATCH_TIMEOUT_MS: &str = "streaming.pending_batch_timeout_ms";

pub const PARAM_MAX_GAS_PER_TX: &str = "limits.max_gas_per_tx";
pub const PARAM_MAX_GAS_PER_BATCH: &str = "limits.max_gas_per_batch";
pub const PARAM_MAX_CALLDATA_SIZE: &str = "limits.max_calldata_size";
pub const PARAM_MAX_CALL_CHAIN_CALLS: &str = "limits.max_call_chain_calls";
pub const PARAM_MAX_CALL_CHAIN_TOTAL_CALLDATA: &str = "limits.max_call_chain_total_calldata";
pub const PARAM_MAX_BATCH_TRANSFER_RECIPIENTS: &str = "limits.max_batch_transfer_recipients";
pub const PARAM_NONCE_LOOKAHEAD: &str = "limits.nonce_lookahead";
pub const PARAM_MAX_RETURN_DATA_SIZE: &str = "limits.max_return_data_size";
pub const PARAM_MAX_CALL_DEPTH: &str = "limits.max_call_depth";
pub const PARAM_MAX_LOG_DATA_SIZE: &str = "limits.max_log_data_size";
pub const PARAM_MAX_LOGS_PER_TX: &str = "limits.max_logs_per_tx";
pub const PARAM_MAX_LOG_TOPICS: &str = "limits.max_log_topics";
pub const PARAM_MAX_CELL_BYTECODE_SIZE: &str = "limits.max_cell_bytecode_size";
pub const PARAM_MAX_CELL_STORAGE_BYTES: &str = "limits.max_cell_storage_bytes";

pub const PARAM_STORAGE_RENT_LIFETIME_FEE: &str = "storage.rent_lifetime_fee";
pub const PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS: &str = "storage.rent_grace_period_blocks";
pub const PARAM_MIN_TX_FEE: &str = "fees.min_tx_fee";
pub const PARAM_TX_BYTE_FEE: &str = "fees.tx_byte";
pub const PARAM_MEMPOOL_MAX_BYTES: &str = "mempool.max_bytes";
pub const PARAM_AIRDROP_COOLDOWN_SECS: &str = "airdrop.cooldown_secs";
pub const PARAM_MAX_AIRDROP_AMOUNT: &str = "airdrop.max_amount";

pub const PARAM_NAME_REGISTRATION_FEE: &str = "name.registration_fee";
pub const PARAM_NAME_RENEWAL_FEE: &str = "name.renewal_fee";
pub const PARAM_NAME_EXPIRATION_BLOCKS: &str = "name.expiration_blocks";
pub const PARAM_NAME_VOTING_PERIOD: &str = "name.voting_period";
pub const PARAM_NAME_APPROVAL_THRESHOLD: &str = "name.approval_threshold";
pub const PARAM_TOKEN_AUTHORITY_APPROVAL_THRESHOLD: &str = "token.authority_approval_threshold";
pub const PARAM_CU_PER_TLKD: &str = "cu.per_tlkd";

pub const PARAM_ORACLE_COMMIT_QUORUM_PERCENT: &str = "oracle.commit_quorum_percent";
pub const PARAM_ORACLE_REVEAL_QUORUM_PERCENT: &str = "oracle.reveal_quorum_percent";
pub const PARAM_ORACLE_REQUEST_TIMEOUT_BLOCKS: &str = "oracle.request_timeout_blocks";
pub const PARAM_ORACLE_CACHE_EXPIRY_BLOCKS: &str = "oracle.cache_expiry_blocks";
pub const PARAM_MAX_RESPONSE_BYTES: &str = "oracle.max_response_bytes";
pub const PARAM_MAX_HTTP_BODY_BYTES: &str = "oracle.max_http_body_bytes";
pub const PARAM_MAX_HTTP_URL_BYTES: &str = "oracle.max_http_url_bytes";
pub const PARAM_MAX_HTTP_METHOD_BYTES: &str = "oracle.max_http_method_bytes";
pub const PARAM_HTTP_TIMEOUT_MS: &str = "oracle.http_timeout_ms";
pub const PARAM_MALICIOUS_SLASH_BPS: &str = "oracle.malicious_slash_bps";
pub const PARAM_MIN_URL_PROPOSAL_BOND: &str = "oracle.min_url_proposal_bond";
pub const PARAM_MIN_RAW_URL_PROPOSAL_BOND: &str = "oracle.min_raw_url_proposal_bond";
pub const PARAM_MAX_URL_VOTING_PERIOD_BLOCKS: &str = "oracle.max_url_voting_period_blocks";
pub const PARAM_MAX_SCHEMA_KEYS: &str = "oracle.max_schema_keys";
pub const PARAM_MAX_SCHEMA_KEY_BYTES: &str = "oracle.max_schema_key_bytes";
pub const PARAM_MAX_SCHEMA_VOTING_PERIOD_BLOCKS: &str = "oracle.max_schema_voting_period_blocks";
pub const PARAM_MAX_TOKEN_AUTHORITY_VOTING_PERIOD_BLOCKS: &str =
    "oracle.max_token_authority_voting_period_blocks";
pub const PARAM_PRIVATE_MAX_DEPTH: &str = "oracle.private_max_depth";
pub const PARAM_PUBLIC_MAX_DEPTH: &str = "oracle.public_max_depth";

pub const PARAM_INGRESS_MAX_CONNECTIONS: &str = "network.ingress.max_connections";
pub const PARAM_INGRESS_MAX_MESSAGE_BYTES: &str = "network.ingress.max_message_bytes";
pub const PARAM_INGRESS_MAX_MESSAGES_PER_SECOND: &str = "network.ingress.max_messages_per_second";

pub const PARAM_ACK_MAX_CONNECTIONS: &str = "network.ack.max_connections";
pub const PARAM_ACK_MAX_MESSAGE_BYTES: &str = "network.ack.max_message_bytes";
pub const PARAM_ACK_MAX_MESSAGES_PER_SECOND: &str = "network.ack.max_messages_per_second";
pub const PARAM_ACK_MAX_PENDING_BATCHES: &str = "network.ack.max_pending_batches";
pub const PARAM_ACK_MAX_BATCH_AGE_SECS: &str = "network.ack.max_batch_age_secs";

pub const PARAM_DISCOVERY_MAX_PEERS: &str = "network.discovery.max_peers";
pub const PARAM_DISCOVERY_PEER_TTL_SECS: &str = "network.discovery.peer_ttl_secs";
pub const PARAM_ATTESTATION_PIPELINE_MAX_PENDING: &str = "network.attestation.max_pending";

pub const PARAM_CHUNK_SIZE: &str = "network.transport.chunk_size";
pub const PARAM_HANDSHAKE_TIMEOUT_SECS: &str = "network.transport.handshake_timeout_secs";
pub const PARAM_MAX_PRIVATE_FEE: &str = "agent.private_balance.max_fee";
pub const PARAM_FEE_AUTHORITY: &str = "agent.private_balance.fee_authority";

lazy_static::lazy_static! {
    static ref PARAM_CACHE: RwLock<HashMap<[u8; 32], [u8; 32]>> = RwLock::new(HashMap::new());
}

pub trait ParamState {
    fn params(&self) -> &im::HashMap<[u8; 32], [u8; 32]>;
    fn params_mut(&mut self) -> &mut im::HashMap<[u8; 32], [u8; 32]>;
}

#[derive(Clone, Copy)]
enum ParamKind {
    U64,
    U128,
}

#[derive(Clone, Copy)]
struct ParamSpec {
    name: &'static str,
    kind: ParamKind,
    min_u64: u64,
    max_u64: u64,
    min_u128: u128,
    max_u128: u128,
}

const fn spec_u64(name: &'static str, min: u64, max: u64) -> ParamSpec {
    ParamSpec {
        name,
        kind: ParamKind::U64,
        min_u64: min,
        max_u64: max,
        min_u128: 0,
        max_u128: 0,
    }
}

const fn spec_u128(name: &'static str, min: u128, max: u128) -> ParamSpec {
    ParamSpec {
        name,
        kind: ParamKind::U128,
        min_u64: 0,
        max_u64: 0,
        min_u128: min,
        max_u128: max,
    }
}

const U64_MAX: u64 = u64::MAX;
const U128_MAX: u128 = u128::MAX;
const PERCENT_MAX: u64 = 100;
const BPS_MAX: u64 = 10_000;
const MIN_BATCH_INTERVAL_MS: u64 = 50;
const MAX_BATCH_INTERVAL_MS: u64 = 2_000;
const MIN_BATCH_SIZE: u64 = 1_000;
const MAX_BATCH_SIZE_CAP: u64 = 100_000;
const MIN_COMMITTEE_SIZE: u64 = 5;
const MAX_COMMITTEE_SIZE: u64 = 200;
const MIN_EPOCH_DURATION_MS: u64 = 10_000;
const MAX_EPOCH_DURATION_MS: u64 = 3_600_000;
const MIN_FINALIZATION_LAG: u64 = 1;
const MAX_FINALIZATION_LAG: u64 = 100;
const MIN_FINALIZATION_TIMEOUT_SECS: u64 = 1;
const MAX_FINALIZATION_TIMEOUT_SECS: u64 = 120;
const MIN_SYNC_THRESHOLD: u64 = 1;
const MAX_SYNC_THRESHOLD: u64 = 10_000;
const MIN_MAX_BATCH_RANGE: u64 = 10;
const MAX_MAX_BATCH_RANGE: u64 = 10_000;
const MIN_SYNC_PEER_TTL_SECS: u64 = 5;
const MAX_SYNC_PEER_TTL_SECS: u64 = 600;
const MIN_STREAM_BATCH_SIZE: u64 = 100;
const MAX_STREAM_BATCH_SIZE: u64 = 100_000;
const MIN_STREAM_WAIT_MS: u64 = 10;
const MAX_STREAM_WAIT_MS: u64 = 10_000;
const MIN_STREAM_BUFFER: u64 = 10;
const MAX_STREAM_BUFFER: u64 = 10_000;
const MIN_STREAM_SEEN_TXS: u64 = 1_000;
const MAX_STREAM_SEEN_TXS: u64 = 10_000_000;
const MIN_STREAM_PENDING_TIMEOUT_MS: u64 = 1_000;
const MAX_STREAM_PENDING_TIMEOUT_MS: u64 = 600_000;
const MIN_SYNC_SNAPSHOT_THRESHOLD: u64 = 100;
const MAX_SYNC_SNAPSHOT_THRESHOLD: u64 = 100_000;
const MIN_GAS_PER_TX: u64 = 10_000;
const MIN_GAS_PER_BATCH: u64 = 100_000;
const MIN_CALLDATA_SIZE: u64 = 1_024;
const MIN_CALL_CHAIN_CALLS: u64 = 1;
const MIN_BATCH_TRANSFER_RECIPIENTS: u64 = 1;
const MIN_RETURN_DATA_SIZE: u64 = 1_024;
const MIN_CALL_DEPTH: u64 = 1;
const MIN_LOG_DATA_SIZE: u64 = 1_024;
const MIN_LOGS_PER_TX: u64 = 1;
const MIN_LOG_TOPICS: u64 = 1;
const MIN_CELL_BYTECODE_SIZE: u64 = 1_024;
const MIN_CELL_STORAGE_BYTES: u64 = 1_024;
const MIN_SLASH_PERCENT: u64 = 5;
const MIN_ORACLE_LIE_SLASH_PERCENT: u64 = 30;
const MIN_ORACLE_SILENCE_SLASH_PERCENT: u64 = 2;
const MIN_DOWNTIME_SLASH_PERCENT: u64 = 1;
const MIN_CENSORSHIP_SLASH_PERCENT: u64 = 1;
const MAX_SLASH_PERCENT: u64 = 50;
const MIN_ORACLE_QUORUM: u64 = 33;
const MAX_ORACLE_QUORUM: u64 = 90;
const MIN_ORACLE_TIMEOUT_BLOCKS: u64 = 10;
const MAX_ORACLE_TIMEOUT_BLOCKS: u64 = 1_000_000;
const MIN_CACHE_EXPIRY_BLOCKS: u64 = 100;
const MAX_CACHE_EXPIRY_BLOCKS: u64 = 1_000_000;
const MIN_HTTP_BODY_BYTES: u64 = 256;
const MIN_HTTP_URL_BYTES: u64 = 32;
const MIN_HTTP_METHOD_BYTES: u64 = 4;
const MIN_HTTP_TIMEOUT_MS: u64 = 100;
const MAX_HTTP_TIMEOUT_MS: u64 = 60_000;
const MIN_AIRDROP_COOLDOWN_SECS: u64 = 3_600;
const MAX_AIRDROP_COOLDOWN_SECS: u64 = 7 * 24 * 3_600;
const MIN_AIRDROP_AMOUNT: u128 = constants::ONE_TLKD;
const MAX_AIRDROP_AMOUNT: u128 = 100_000 * constants::ONE_TLKD;
const MIN_NAME_FEE: u128 = constants::ONE_TLKD / 10;
const MAX_NAME_FEE: u128 = 1_000 * constants::ONE_TLKD;
const MIN_URL_PROPOSAL_BOND: u128 = constants::ONE_TLKD;
const MAX_URL_PROPOSAL_BOND: u128 = 1_000 * constants::ONE_TLKD;
const MIN_RAW_URL_PROPOSAL_BOND: u128 = 5 * constants::ONE_TLKD;
const MAX_RAW_URL_PROPOSAL_BOND: u128 = 10_000 * constants::ONE_TLKD;
const MAX_SCHEMA_KEYS: u64 = 64;
const MAX_SCHEMA_KEY_BYTES: u64 = 64;
const MAX_SCHEMA_VOTING_PERIOD_BLOCKS: u64 = 1_000_000;

const PINNED_PARAMS: &[&str] = &[
    PARAM_GAS_TRANSFER,
    PARAM_GAS_CLAIM,
    PARAM_GAS_ROTATE_KEY,
    PARAM_GAS_REGISTER_VALIDATOR,
    PARAM_GAS_STAKE,
    PARAM_GAS_UNSTAKE,
    PARAM_GAS_WITHDRAW,
    PARAM_GAS_UNJAIL,
    PARAM_GAS_MINT_NFT,
    PARAM_GAS_TRANSFER_NFT,
    PARAM_GAS_BURN_NFT,
    PARAM_GAS_APPROVE_NFT,
    PARAM_GAS_DEPLOY_CELL,
    PARAM_GAS_DEPLOY_TOKEN,
    PARAM_GAS_UPGRADE_CELL,
    PARAM_GAS_TOKEN_TRANSFER,
    PARAM_GAS_TOKEN_MINT,
    PARAM_GAS_TOKEN_BURN,
    PARAM_GAS_ORACLE_READ,
    PARAM_GAS_ORACLE_QUEUE,
    PARAM_GAS_PRICE,
    PARAM_GAS_DISTRIBUTION_INTERVAL,
    PARAM_EMISSION_YEAR1_TLKD,
    PARAM_EMISSION_DECAY_BPS_PER_YEAR,
    PARAM_EMISSION_EPOCH_BLOCKS,
    PARAM_BATCH_INTERVAL_MS,
    PARAM_MAX_BATCH_SIZE,
    PARAM_COMMITTEE_SIZE,
    PARAM_EPOCH_DURATION_MS,
    PARAM_FINALIZATION_LAG,
    PARAM_FINALIZATION_TIMEOUT_SECS,
    PARAM_SYNC_THRESHOLD,
    PARAM_MAX_BATCH_RANGE,
    PARAM_SYNC_PEER_TTL_SECS,
    PARAM_SYNC_SNAPSHOT_THRESHOLD,
    PARAM_SLASH_PERCENTAGE,
    PARAM_ORACLE_LIE_SLASH_PERCENTAGE,
    PARAM_ORACLE_SILENCE_SLASH_PERCENTAGE,
    PARAM_DOWNTIME_SLASH_PERCENTAGE,
    PARAM_CENSORSHIP_SLASH_PERCENTAGE,
    PARAM_STREAMING_OPTIMAL_BATCH_SIZE,
    PARAM_STREAMING_MAX_WAIT_MS,
    PARAM_STREAMING_MAX_SYNC_BUFFER_SIZE,
    PARAM_STREAMING_MAX_BATCH_CACHE,
    PARAM_STREAMING_MAX_PENDING_HEADERS,
    PARAM_STREAMING_MAX_SEEN_TXS,
    PARAM_STREAMING_PENDING_BATCH_TIMEOUT_MS,
    PARAM_MAX_GAS_PER_TX,
    PARAM_MAX_GAS_PER_BATCH,
    PARAM_MAX_CALLDATA_SIZE,
    PARAM_MAX_CALL_CHAIN_TOTAL_CALLDATA,
    PARAM_MAX_RETURN_DATA_SIZE,
    PARAM_MAX_CALL_DEPTH,
    PARAM_MAX_LOG_DATA_SIZE,
    PARAM_MAX_LOGS_PER_TX,
    PARAM_MAX_LOG_TOPICS,
    PARAM_MAX_CELL_BYTECODE_SIZE,
    PARAM_MAX_CELL_STORAGE_BYTES,
    PARAM_MAX_BATCH_TRANSFER_RECIPIENTS,
    PARAM_NONCE_LOOKAHEAD,
    PARAM_MAX_CALL_CHAIN_CALLS,
    PARAM_STORAGE_RENT_LIFETIME_FEE,
    PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS,
    PARAM_MIN_TX_FEE,
    PARAM_TX_BYTE_FEE,
    PARAM_MEMPOOL_MAX_BYTES,
    PARAM_AIRDROP_COOLDOWN_SECS,
    PARAM_MAX_AIRDROP_AMOUNT,
    PARAM_NAME_REGISTRATION_FEE,
    PARAM_NAME_RENEWAL_FEE,
    PARAM_NAME_EXPIRATION_BLOCKS,
    PARAM_NAME_VOTING_PERIOD,
    PARAM_NAME_APPROVAL_THRESHOLD,
    PARAM_TOKEN_AUTHORITY_APPROVAL_THRESHOLD,
    PARAM_CU_PER_TLKD,
    PARAM_ORACLE_COMMIT_QUORUM_PERCENT,
    PARAM_ORACLE_REVEAL_QUORUM_PERCENT,
    PARAM_ORACLE_REQUEST_TIMEOUT_BLOCKS,
    PARAM_ORACLE_CACHE_EXPIRY_BLOCKS,
    PARAM_MAX_RESPONSE_BYTES,
    PARAM_MAX_HTTP_BODY_BYTES,
    PARAM_MAX_HTTP_URL_BYTES,
    PARAM_MAX_HTTP_METHOD_BYTES,
    PARAM_HTTP_TIMEOUT_MS,
    PARAM_MALICIOUS_SLASH_BPS,
    PARAM_MIN_URL_PROPOSAL_BOND,
    PARAM_MIN_RAW_URL_PROPOSAL_BOND,
    PARAM_MAX_URL_VOTING_PERIOD_BLOCKS,
    PARAM_MAX_SCHEMA_KEYS,
    PARAM_MAX_SCHEMA_KEY_BYTES,
    PARAM_MAX_SCHEMA_VOTING_PERIOD_BLOCKS,
    PARAM_MAX_TOKEN_AUTHORITY_VOTING_PERIOD_BLOCKS,
    PARAM_PRIVATE_MAX_DEPTH,
    PARAM_PUBLIC_MAX_DEPTH,
];

const PARAM_SPECS: &[ParamSpec] = &[
    spec_u64(PARAM_GAS_TRANSFER, 1, U64_MAX),
    spec_u64(PARAM_GAS_CLAIM, 1, U64_MAX),
    spec_u64(PARAM_GAS_ROTATE_KEY, 1, U64_MAX),
    spec_u64(PARAM_GAS_REGISTER_VALIDATOR, 1, U64_MAX),
    spec_u64(PARAM_GAS_STAKE, 1, U64_MAX),
    spec_u64(PARAM_GAS_UNSTAKE, 1, U64_MAX),
    spec_u64(PARAM_GAS_WITHDRAW, 1, U64_MAX),
    spec_u64(PARAM_GAS_UNJAIL, 1, U64_MAX),
    spec_u64(PARAM_GAS_MINT_NFT, 1, U64_MAX),
    spec_u64(PARAM_GAS_TRANSFER_NFT, 1, U64_MAX),
    spec_u64(PARAM_GAS_BURN_NFT, 1, U64_MAX),
    spec_u64(PARAM_GAS_APPROVE_NFT, 1, U64_MAX),
    spec_u64(PARAM_GAS_DEPLOY_CELL, 1, U64_MAX),
    spec_u64(PARAM_GAS_DEPLOY_TOKEN, 1, U64_MAX),
    spec_u64(PARAM_GAS_UPGRADE_CELL, 1, U64_MAX),
    spec_u64(PARAM_GAS_TOKEN_TRANSFER, 1, U64_MAX),
    spec_u64(PARAM_GAS_TOKEN_MINT, 1, U64_MAX),
    spec_u64(PARAM_GAS_TOKEN_BURN, 1, U64_MAX),
    spec_u64(PARAM_GAS_ORACLE_READ, 1, U64_MAX),
    spec_u64(PARAM_GAS_ORACLE_QUEUE, 1, U64_MAX),
    spec_u64(PARAM_GAS_PRICE, 1, 1_000_000),
    spec_u64(
        PARAM_GAS_DISTRIBUTION_INTERVAL,
        constants::TREASURY_DISTRIBUTION_INTERVAL_BLOCKS,
        30 * constants::TREASURY_DISTRIBUTION_INTERVAL_BLOCKS,
    ),
    spec_u128(
        PARAM_EMISSION_YEAR1_TLKD,
        1_000_000 * constants::ONE_TLKD,
        100_000_000 * constants::ONE_TLKD,
    ),
    spec_u64(PARAM_EMISSION_DECAY_BPS_PER_YEAR, 500, 5_000),
    spec_u64(PARAM_EMISSION_EPOCH_BLOCKS, 43_200, 4_320_000),
    spec_u64(
        PARAM_BATCH_INTERVAL_MS,
        MIN_BATCH_INTERVAL_MS,
        MAX_BATCH_INTERVAL_MS,
    ),
    spec_u64(PARAM_MAX_BATCH_SIZE, MIN_BATCH_SIZE, MAX_BATCH_SIZE_CAP),
    spec_u64(PARAM_COMMITTEE_SIZE, MIN_COMMITTEE_SIZE, MAX_COMMITTEE_SIZE),
    spec_u64(
        PARAM_EPOCH_DURATION_MS,
        MIN_EPOCH_DURATION_MS,
        MAX_EPOCH_DURATION_MS,
    ),
    spec_u64(
        PARAM_FINALIZATION_LAG,
        MIN_FINALIZATION_LAG,
        MAX_FINALIZATION_LAG,
    ),
    spec_u64(
        PARAM_FINALIZATION_TIMEOUT_SECS,
        MIN_FINALIZATION_TIMEOUT_SECS,
        MAX_FINALIZATION_TIMEOUT_SECS,
    ),
    spec_u64(PARAM_SYNC_THRESHOLD, MIN_SYNC_THRESHOLD, MAX_SYNC_THRESHOLD),
    spec_u64(
        PARAM_MAX_BATCH_RANGE,
        MIN_MAX_BATCH_RANGE,
        MAX_MAX_BATCH_RANGE,
    ),
    spec_u64(
        PARAM_SYNC_PEER_TTL_SECS,
        MIN_SYNC_PEER_TTL_SECS,
        MAX_SYNC_PEER_TTL_SECS,
    ),
    spec_u64(
        PARAM_SYNC_SNAPSHOT_THRESHOLD,
        MIN_SYNC_SNAPSHOT_THRESHOLD,
        MAX_SYNC_SNAPSHOT_THRESHOLD,
    ),
    spec_u64(PARAM_SLASH_PERCENTAGE, MIN_SLASH_PERCENT, MAX_SLASH_PERCENT),
    spec_u64(
        PARAM_ORACLE_LIE_SLASH_PERCENTAGE,
        MIN_ORACLE_LIE_SLASH_PERCENT,
        MAX_SLASH_PERCENT,
    ),
    spec_u64(
        PARAM_ORACLE_SILENCE_SLASH_PERCENTAGE,
        MIN_ORACLE_SILENCE_SLASH_PERCENT,
        MAX_SLASH_PERCENT,
    ),
    spec_u64(
        PARAM_DOWNTIME_SLASH_PERCENTAGE,
        MIN_DOWNTIME_SLASH_PERCENT,
        MAX_SLASH_PERCENT,
    ),
    spec_u64(
        PARAM_CENSORSHIP_SLASH_PERCENTAGE,
        MIN_CENSORSHIP_SLASH_PERCENT,
        MAX_SLASH_PERCENT,
    ),
    spec_u64(
        PARAM_STREAMING_OPTIMAL_BATCH_SIZE,
        MIN_STREAM_BATCH_SIZE,
        MAX_STREAM_BATCH_SIZE,
    ),
    spec_u64(
        PARAM_STREAMING_MAX_WAIT_MS,
        MIN_STREAM_WAIT_MS,
        MAX_STREAM_WAIT_MS,
    ),
    spec_u64(
        PARAM_STREAMING_MAX_SYNC_BUFFER_SIZE,
        MIN_STREAM_BUFFER,
        MAX_STREAM_BUFFER,
    ),
    spec_u64(
        PARAM_STREAMING_MAX_BATCH_CACHE,
        MIN_STREAM_BUFFER,
        MAX_STREAM_BUFFER,
    ),
    spec_u64(
        PARAM_STREAMING_MAX_PENDING_HEADERS,
        MIN_STREAM_BUFFER,
        MAX_STREAM_BUFFER,
    ),
    spec_u64(
        PARAM_STREAMING_MAX_SEEN_TXS,
        MIN_STREAM_SEEN_TXS,
        MAX_STREAM_SEEN_TXS,
    ),
    spec_u64(
        PARAM_STREAMING_PENDING_BATCH_TIMEOUT_MS,
        MIN_STREAM_PENDING_TIMEOUT_MS,
        MAX_STREAM_PENDING_TIMEOUT_MS,
    ),
    spec_u64(
        PARAM_MAX_GAS_PER_TX,
        MIN_GAS_PER_TX,
        constants::MAX_GAS_PER_TX,
    ),
    spec_u64(
        PARAM_MAX_GAS_PER_BATCH,
        MIN_GAS_PER_BATCH,
        constants::MAX_GAS_PER_BATCH,
    ),
    spec_u64(
        PARAM_MAX_CALLDATA_SIZE,
        MIN_CALLDATA_SIZE,
        constants::MAX_CALLDATA_SIZE as u64,
    ),
    spec_u64(
        PARAM_MAX_CALL_CHAIN_CALLS,
        MIN_CALL_CHAIN_CALLS,
        constants::MAX_CALL_CHAIN_CALLS as u64,
    ),
    spec_u64(
        PARAM_MAX_CALL_CHAIN_TOTAL_CALLDATA,
        MIN_CALLDATA_SIZE,
        constants::MAX_CALL_CHAIN_TOTAL_CALLDATA as u64,
    ),
    spec_u64(
        PARAM_MAX_BATCH_TRANSFER_RECIPIENTS,
        MIN_BATCH_TRANSFER_RECIPIENTS,
        constants::MAX_BATCH_TRANSFER_RECIPIENTS as u64,
    ),
    spec_u64(PARAM_NONCE_LOOKAHEAD, 0, 1_000_000),
    spec_u64(
        PARAM_MAX_RETURN_DATA_SIZE,
        MIN_RETURN_DATA_SIZE,
        constants::MAX_RETURN_DATA_SIZE as u64,
    ),
    spec_u64(
        PARAM_MAX_CALL_DEPTH,
        MIN_CALL_DEPTH,
        constants::MAX_CALL_DEPTH as u64,
    ),
    spec_u64(
        PARAM_MAX_LOG_DATA_SIZE,
        MIN_LOG_DATA_SIZE,
        constants::MAX_LOG_DATA_SIZE as u64,
    ),
    spec_u64(
        PARAM_MAX_LOGS_PER_TX,
        MIN_LOGS_PER_TX,
        constants::MAX_LOGS_PER_TX as u64,
    ),
    spec_u64(
        PARAM_MAX_LOG_TOPICS,
        MIN_LOG_TOPICS,
        constants::MAX_LOG_TOPICS as u64,
    ),
    spec_u64(
        PARAM_MAX_CELL_BYTECODE_SIZE,
        MIN_CELL_BYTECODE_SIZE,
        constants::MAX_CELL_BYTECODE_SIZE as u64,
    ),
    spec_u64(
        PARAM_MAX_CELL_STORAGE_BYTES,
        MIN_CELL_STORAGE_BYTES,
        constants::MAX_CELL_STORAGE_BYTES,
    ),
    spec_u128(
        PARAM_STORAGE_RENT_LIFETIME_FEE,
        constants::ONE_TLKD,
        U128_MAX,
    ),
    spec_u64(PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS, 1, U64_MAX),
    spec_u64(PARAM_MIN_TX_FEE, 1, U64_MAX),
    spec_u64(PARAM_TX_BYTE_FEE, 0, 1_000_000),
    spec_u64(PARAM_MEMPOOL_MAX_BYTES, 1_048_576, 1024 * 1024 * 1024),
    spec_u64(
        PARAM_AIRDROP_COOLDOWN_SECS,
        MIN_AIRDROP_COOLDOWN_SECS,
        MAX_AIRDROP_COOLDOWN_SECS,
    ),
    spec_u128(
        PARAM_MAX_AIRDROP_AMOUNT,
        MIN_AIRDROP_AMOUNT,
        MAX_AIRDROP_AMOUNT,
    ),
    spec_u128(PARAM_NAME_REGISTRATION_FEE, MIN_NAME_FEE, MAX_NAME_FEE),
    spec_u128(PARAM_NAME_RENEWAL_FEE, MIN_NAME_FEE, MAX_NAME_FEE),
    spec_u64(PARAM_NAME_EXPIRATION_BLOCKS, 10_000, 200_000_000),
    spec_u64(PARAM_NAME_VOTING_PERIOD, 10_000, 10_000_000),
    spec_u64(PARAM_NAME_APPROVAL_THRESHOLD, 51, PERCENT_MAX),
    spec_u64(PARAM_TOKEN_AUTHORITY_APPROVAL_THRESHOLD, 51, PERCENT_MAX),
    spec_u64(PARAM_CU_PER_TLKD, 1_000, constants::MAX_CU_PER_TLKD),
    spec_u64(
        PARAM_ORACLE_COMMIT_QUORUM_PERCENT,
        MIN_ORACLE_QUORUM,
        MAX_ORACLE_QUORUM,
    ),
    spec_u64(
        PARAM_ORACLE_REVEAL_QUORUM_PERCENT,
        MIN_ORACLE_QUORUM,
        MAX_ORACLE_QUORUM,
    ),
    spec_u64(
        PARAM_ORACLE_REQUEST_TIMEOUT_BLOCKS,
        MIN_ORACLE_TIMEOUT_BLOCKS,
        MAX_ORACLE_TIMEOUT_BLOCKS,
    ),
    spec_u64(
        PARAM_ORACLE_CACHE_EXPIRY_BLOCKS,
        MIN_CACHE_EXPIRY_BLOCKS,
        MAX_CACHE_EXPIRY_BLOCKS,
    ),
    spec_u64(
        PARAM_MAX_RESPONSE_BYTES,
        1_024,
        constants::MAX_RESPONSE_BYTES as u64,
    ),
    spec_u64(
        PARAM_MAX_HTTP_BODY_BYTES,
        MIN_HTTP_BODY_BYTES,
        constants::MAX_HTTP_BODY_BYTES as u64,
    ),
    spec_u64(
        PARAM_MAX_HTTP_URL_BYTES,
        MIN_HTTP_URL_BYTES,
        constants::MAX_HTTP_URL_BYTES as u64,
    ),
    spec_u64(
        PARAM_MAX_HTTP_METHOD_BYTES,
        MIN_HTTP_METHOD_BYTES,
        constants::MAX_HTTP_METHOD_BYTES as u64,
    ),
    spec_u64(
        PARAM_HTTP_TIMEOUT_MS,
        MIN_HTTP_TIMEOUT_MS,
        MAX_HTTP_TIMEOUT_MS,
    ),
    spec_u64(PARAM_MALICIOUS_SLASH_BPS, 100, BPS_MAX),
    spec_u128(
        PARAM_MIN_URL_PROPOSAL_BOND,
        MIN_URL_PROPOSAL_BOND,
        MAX_URL_PROPOSAL_BOND,
    ),
    spec_u128(
        PARAM_MIN_RAW_URL_PROPOSAL_BOND,
        MIN_RAW_URL_PROPOSAL_BOND,
        MAX_RAW_URL_PROPOSAL_BOND,
    ),
    spec_u64(PARAM_MAX_URL_VOTING_PERIOD_BLOCKS, 10_000, 10_000_000),
    spec_u64(PARAM_MAX_SCHEMA_KEYS, 1, MAX_SCHEMA_KEYS),
    spec_u64(PARAM_MAX_SCHEMA_KEY_BYTES, 8, MAX_SCHEMA_KEY_BYTES),
    spec_u64(
        PARAM_MAX_SCHEMA_VOTING_PERIOD_BLOCKS,
        10_000,
        MAX_SCHEMA_VOTING_PERIOD_BLOCKS,
    ),
    spec_u64(
        PARAM_MAX_TOKEN_AUTHORITY_VOTING_PERIOD_BLOCKS,
        10_000,
        10_000_000,
    ),
    spec_u64(PARAM_PRIVATE_MAX_DEPTH, 1, 10),
    spec_u64(PARAM_PUBLIC_MAX_DEPTH, 1, 64),
    spec_u64(PARAM_INGRESS_MAX_CONNECTIONS, 1, 100_000),
    spec_u64(PARAM_INGRESS_MAX_MESSAGE_BYTES, 1_024, 16 * 1024 * 1024),
    spec_u64(PARAM_INGRESS_MAX_MESSAGES_PER_SECOND, 1, 100_000),
    spec_u64(PARAM_ACK_MAX_CONNECTIONS, 1, 100_000),
    spec_u64(PARAM_ACK_MAX_MESSAGE_BYTES, 1_024, 16 * 1024 * 1024),
    spec_u64(PARAM_ACK_MAX_MESSAGES_PER_SECOND, 1, 100_000),
    spec_u64(PARAM_ACK_MAX_PENDING_BATCHES, 1, 100_000),
    spec_u64(PARAM_ACK_MAX_BATCH_AGE_SECS, 1, 3_600),
    spec_u64(PARAM_DISCOVERY_MAX_PEERS, 1, 100_000),
    spec_u64(PARAM_DISCOVERY_PEER_TTL_SECS, 10, 86_400),
    spec_u64(PARAM_ATTESTATION_PIPELINE_MAX_PENDING, 1, 100_000),
    spec_u64(PARAM_CHUNK_SIZE, 1_024, 1_048_576),
    spec_u64(PARAM_HANDSHAKE_TIMEOUT_SECS, 1, 120),
];

pub fn param_key(name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PARAM_DOMAIN);
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encode_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&value.to_le_bytes());
    out
}

fn encode_u128(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&value.to_le_bytes());
    out
}

fn decode_u64(value: [u8; 32]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&value[..8]);
    u64::from_le_bytes(buf)
}

fn decode_u128(value: [u8; 32]) -> u128 {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&value[..16]);
    u128::from_le_bytes(buf)
}

fn insert_u64<S: ParamState>(state: &mut S, name: &str, value: u64) {
    state
        .params_mut()
        .insert(param_key(name), encode_u64(value));
}

fn insert_u128<S: ParamState>(state: &mut S, name: &str, value: u128) {
    state
        .params_mut()
        .insert(param_key(name), encode_u128(value));
}

pub fn insert_genesis_params<S: ParamState>(state: &mut S) {
    insert_u64(state, PARAM_GAS_TRANSFER, constants::GAS_TRANSFER);
    insert_u64(state, PARAM_GAS_CLAIM, constants::GAS_CLAIM);
    insert_u64(state, PARAM_GAS_ROTATE_KEY, constants::GAS_ROTATE_KEY);
    insert_u64(
        state,
        PARAM_GAS_REGISTER_VALIDATOR,
        constants::GAS_REGISTER_VALIDATOR,
    );
    insert_u64(state, PARAM_GAS_STAKE, constants::GAS_STAKE);
    insert_u64(state, PARAM_GAS_UNSTAKE, constants::GAS_UNSTAKE);
    insert_u64(state, PARAM_GAS_WITHDRAW, constants::GAS_WITHDRAW);
    insert_u64(state, PARAM_GAS_UNJAIL, constants::GAS_UNJAIL);
    insert_u64(state, PARAM_GAS_MINT_NFT, constants::GAS_MINT_NFT);
    insert_u64(state, PARAM_GAS_TRANSFER_NFT, constants::GAS_TRANSFER_NFT);
    insert_u64(state, PARAM_GAS_BURN_NFT, constants::GAS_BURN_NFT);
    insert_u64(state, PARAM_GAS_APPROVE_NFT, constants::GAS_APPROVE_NFT);
    insert_u64(state, PARAM_GAS_DEPLOY_CELL, constants::GAS_DEPLOY_CELL);
    insert_u64(state, PARAM_GAS_DEPLOY_TOKEN, constants::GAS_DEPLOY_TOKEN);
    insert_u64(state, PARAM_GAS_UPGRADE_CELL, constants::GAS_UPGRADE_CELL);
    insert_u64(
        state,
        PARAM_GAS_TOKEN_TRANSFER,
        constants::GAS_TOKEN_TRANSFER,
    );
    insert_u64(state, PARAM_GAS_TOKEN_MINT, constants::GAS_TOKEN_MINT);
    insert_u64(state, PARAM_GAS_TOKEN_BURN, constants::GAS_TOKEN_BURN);
    insert_u64(state, PARAM_GAS_ORACLE_READ, constants::GAS_ORACLE_READ);
    insert_u64(state, PARAM_GAS_ORACLE_QUEUE, constants::GAS_ORACLE_QUEUE);
    insert_u64(state, PARAM_GAS_PRICE, constants::GAS_PRICE);
    insert_u64(
        state,
        PARAM_GAS_DISTRIBUTION_INTERVAL,
        constants::GAS_DISTRIBUTION_INTERVAL,
    );
    insert_u128(
        state,
        PARAM_EMISSION_YEAR1_TLKD,
        25_000_000 * constants::ONE_TLKD,
    );
    insert_u64(state, PARAM_EMISSION_DECAY_BPS_PER_YEAR, 2_000);
    insert_u64(state, PARAM_EMISSION_EPOCH_BLOCKS, 432_000);

    insert_u64(state, PARAM_BATCH_INTERVAL_MS, constants::BATCH_INTERVAL_MS);
    insert_u64(
        state,
        PARAM_MAX_BATCH_SIZE,
        constants::MAX_BATCH_SIZE as u64,
    );
    insert_u64(
        state,
        PARAM_COMMITTEE_SIZE,
        constants::COMMITTEE_SIZE as u64,
    );
    insert_u64(state, PARAM_EPOCH_DURATION_MS, constants::EPOCH_DURATION_MS);
    insert_u64(state, PARAM_FINALIZATION_LAG, constants::FINALIZATION_LAG);
    insert_u64(
        state,
        PARAM_FINALIZATION_TIMEOUT_SECS,
        constants::FINALIZATION_TIMEOUT_SECS,
    );
    insert_u64(state, PARAM_SYNC_THRESHOLD, constants::SYNC_THRESHOLD);
    insert_u64(state, PARAM_MAX_BATCH_RANGE, constants::MAX_BATCH_RANGE);
    insert_u64(
        state,
        PARAM_SYNC_PEER_TTL_SECS,
        constants::SYNC_PEER_TTL_SECS,
    );
    insert_u64(
        state,
        PARAM_SYNC_SNAPSHOT_THRESHOLD,
        constants::SYNC_SNAPSHOT_THRESHOLD,
    );
    insert_u64(state, PARAM_SLASH_PERCENTAGE, constants::SLASH_PERCENTAGE);
    insert_u64(
        state,
        PARAM_ORACLE_LIE_SLASH_PERCENTAGE,
        constants::ORACLE_LIE_SLASH_PERCENTAGE,
    );
    insert_u64(
        state,
        PARAM_ORACLE_SILENCE_SLASH_PERCENTAGE,
        constants::ORACLE_SILENCE_SLASH_PERCENTAGE,
    );
    insert_u64(
        state,
        PARAM_DOWNTIME_SLASH_PERCENTAGE,
        constants::DOWNTIME_SLASH_PERCENTAGE,
    );
    insert_u64(
        state,
        PARAM_CENSORSHIP_SLASH_PERCENTAGE,
        constants::CENSORSHIP_SLASH_PERCENTAGE,
    );

    insert_u64(
        state,
        PARAM_STREAMING_OPTIMAL_BATCH_SIZE,
        constants::STREAMING_OPTIMAL_BATCH_SIZE as u64,
    );
    insert_u64(
        state,
        PARAM_STREAMING_MAX_WAIT_MS,
        constants::STREAMING_MAX_WAIT_MS,
    );
    insert_u64(
        state,
        PARAM_STREAMING_MAX_SYNC_BUFFER_SIZE,
        constants::STREAMING_MAX_SYNC_BUFFER_SIZE as u64,
    );
    insert_u64(
        state,
        PARAM_STREAMING_MAX_BATCH_CACHE,
        constants::STREAMING_MAX_BATCH_CACHE as u64,
    );
    insert_u64(
        state,
        PARAM_STREAMING_MAX_PENDING_HEADERS,
        constants::STREAMING_MAX_PENDING_HEADERS as u64,
    );
    insert_u64(
        state,
        PARAM_STREAMING_MAX_SEEN_TXS,
        constants::STREAMING_MAX_SEEN_TXS as u64,
    );
    insert_u64(
        state,
        PARAM_STREAMING_PENDING_BATCH_TIMEOUT_MS,
        constants::STREAMING_PENDING_BATCH_TIMEOUT_MS,
    );

    insert_u64(
        state,
        PARAM_INGRESS_MAX_CONNECTIONS,
        constants::INGRESS_MAX_CONNECTIONS as u64,
    );
    insert_u64(
        state,
        PARAM_INGRESS_MAX_MESSAGE_BYTES,
        constants::INGRESS_MAX_MESSAGE_BYTES as u64,
    );
    insert_u64(
        state,
        PARAM_INGRESS_MAX_MESSAGES_PER_SECOND,
        constants::INGRESS_MAX_MESSAGES_PER_SECOND as u64,
    );

    insert_u64(
        state,
        PARAM_ACK_MAX_CONNECTIONS,
        constants::ACK_MAX_CONNECTIONS as u64,
    );
    insert_u64(
        state,
        PARAM_ACK_MAX_MESSAGE_BYTES,
        constants::ACK_MAX_MESSAGE_BYTES as u64,
    );
    insert_u64(
        state,
        PARAM_ACK_MAX_MESSAGES_PER_SECOND,
        constants::ACK_MAX_MESSAGES_PER_SECOND as u64,
    );
    insert_u64(
        state,
        PARAM_ACK_MAX_PENDING_BATCHES,
        constants::ACK_MAX_PENDING_BATCHES as u64,
    );
    insert_u64(
        state,
        PARAM_ACK_MAX_BATCH_AGE_SECS,
        constants::ACK_MAX_BATCH_AGE_SECS,
    );

    insert_u64(
        state,
        PARAM_DISCOVERY_MAX_PEERS,
        constants::DISCOVERY_MAX_PEERS as u64,
    );
    insert_u64(
        state,
        PARAM_DISCOVERY_PEER_TTL_SECS,
        constants::DISCOVERY_PEER_TTL_SECS,
    );
    insert_u64(
        state,
        PARAM_ATTESTATION_PIPELINE_MAX_PENDING,
        constants::ATTESTATION_PIPELINE_MAX_PENDING as u64,
    );

    insert_u64(state, PARAM_CHUNK_SIZE, constants::CHUNK_SIZE as u64);
    insert_u64(
        state,
        PARAM_HANDSHAKE_TIMEOUT_SECS,
        constants::HANDSHAKE_TIMEOUT_SECS,
    );

    insert_u64(state, PARAM_MAX_GAS_PER_TX, constants::MAX_GAS_PER_TX);
    insert_u64(state, PARAM_MAX_GAS_PER_BATCH, constants::MAX_GAS_PER_BATCH);
    insert_u64(
        state,
        PARAM_MAX_CALLDATA_SIZE,
        constants::MAX_CALLDATA_SIZE as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_CALL_CHAIN_CALLS,
        constants::MAX_CALL_CHAIN_CALLS as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_CALL_CHAIN_TOTAL_CALLDATA,
        constants::MAX_CALL_CHAIN_TOTAL_CALLDATA as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_BATCH_TRANSFER_RECIPIENTS,
        constants::MAX_BATCH_TRANSFER_RECIPIENTS as u64,
    );
    insert_u64(state, PARAM_NONCE_LOOKAHEAD, constants::NONCE_LOOKAHEAD);
    insert_u64(
        state,
        PARAM_MAX_RETURN_DATA_SIZE,
        constants::MAX_RETURN_DATA_SIZE as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_CALL_DEPTH,
        constants::MAX_CALL_DEPTH as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_LOG_DATA_SIZE,
        constants::MAX_LOG_DATA_SIZE as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_LOGS_PER_TX,
        constants::MAX_LOGS_PER_TX as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_LOG_TOPICS,
        constants::MAX_LOG_TOPICS as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_CELL_BYTECODE_SIZE,
        constants::MAX_CELL_BYTECODE_SIZE as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_CELL_STORAGE_BYTES,
        constants::MAX_CELL_STORAGE_BYTES,
    );

    insert_u128(
        state,
        PARAM_STORAGE_RENT_LIFETIME_FEE,
        constants::STORAGE_RENT_LIFETIME_FEE,
    );
    insert_u64(
        state,
        PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS,
        constants::STORAGE_RENT_GRACE_PERIOD_BLOCKS,
    );
    insert_u64(state, PARAM_MIN_TX_FEE, constants::MIN_TX_FEE);
    insert_u64(state, PARAM_TX_BYTE_FEE, constants::TX_BYTE_FEE);
    insert_u64(
        state,
        PARAM_MEMPOOL_MAX_BYTES,
        constants::MEMPOOL_MAX_BYTES as u64,
    );
    insert_u64(
        state,
        PARAM_AIRDROP_COOLDOWN_SECS,
        constants::AIRDROP_COOLDOWN_SECS,
    );
    insert_u128(
        state,
        PARAM_MAX_AIRDROP_AMOUNT,
        constants::MAX_AIRDROP_AMOUNT,
    );

    insert_u128(
        state,
        PARAM_NAME_REGISTRATION_FEE,
        constants::NAME_REGISTRATION_FEE,
    );
    insert_u128(state, PARAM_NAME_RENEWAL_FEE, constants::NAME_RENEWAL_FEE);
    insert_u64(
        state,
        PARAM_NAME_EXPIRATION_BLOCKS,
        constants::NAME_EXPIRATION_BLOCKS,
    );
    insert_u64(
        state,
        PARAM_NAME_VOTING_PERIOD,
        constants::NAME_VOTING_PERIOD,
    );
    insert_u64(
        state,
        PARAM_NAME_APPROVAL_THRESHOLD,
        constants::NAME_APPROVAL_THRESHOLD,
    );
    insert_u64(
        state,
        PARAM_TOKEN_AUTHORITY_APPROVAL_THRESHOLD,
        constants::TOKEN_AUTHORITY_APPROVAL_THRESHOLD,
    );
    insert_u64(state, PARAM_CU_PER_TLKD, constants::CU_PER_TLKD);

    insert_u64(
        state,
        PARAM_ORACLE_COMMIT_QUORUM_PERCENT,
        constants::ORACLE_COMMIT_QUORUM_PERCENT,
    );
    insert_u64(
        state,
        PARAM_ORACLE_REVEAL_QUORUM_PERCENT,
        constants::ORACLE_REVEAL_QUORUM_PERCENT,
    );
    insert_u64(
        state,
        PARAM_ORACLE_REQUEST_TIMEOUT_BLOCKS,
        constants::ORACLE_REQUEST_TIMEOUT_BLOCKS,
    );
    insert_u64(
        state,
        PARAM_ORACLE_CACHE_EXPIRY_BLOCKS,
        constants::CACHE_EXPIRY_BLOCKS,
    );
    insert_u64(
        state,
        PARAM_MAX_RESPONSE_BYTES,
        constants::MAX_RESPONSE_BYTES as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_HTTP_BODY_BYTES,
        constants::MAX_HTTP_BODY_BYTES as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_HTTP_URL_BYTES,
        constants::MAX_HTTP_URL_BYTES as u64,
    );
    insert_u64(
        state,
        PARAM_MAX_HTTP_METHOD_BYTES,
        constants::MAX_HTTP_METHOD_BYTES as u64,
    );
    insert_u64(state, PARAM_HTTP_TIMEOUT_MS, constants::HTTP_TIMEOUT_MS);
    insert_u64(
        state,
        PARAM_MALICIOUS_SLASH_BPS,
        constants::MALICIOUS_SLASH_BPS,
    );
    insert_u128(
        state,
        PARAM_MIN_URL_PROPOSAL_BOND,
        constants::MIN_URL_PROPOSAL_BOND,
    );
    insert_u128(
        state,
        PARAM_MIN_RAW_URL_PROPOSAL_BOND,
        constants::MIN_RAW_URL_PROPOSAL_BOND,
    );
    insert_u64(
        state,
        PARAM_MAX_URL_VOTING_PERIOD_BLOCKS,
        constants::MAX_URL_VOTING_PERIOD_BLOCKS,
    );
    insert_u64(state, PARAM_MAX_SCHEMA_KEYS, constants::MAX_SCHEMA_KEYS);
    insert_u64(
        state,
        PARAM_MAX_SCHEMA_KEY_BYTES,
        constants::MAX_SCHEMA_KEY_BYTES,
    );
    insert_u64(
        state,
        PARAM_MAX_SCHEMA_VOTING_PERIOD_BLOCKS,
        constants::MAX_SCHEMA_VOTING_PERIOD_BLOCKS,
    );
    insert_u64(
        state,
        PARAM_MAX_TOKEN_AUTHORITY_VOTING_PERIOD_BLOCKS,
        constants::MAX_TOKEN_AUTHORITY_VOTING_PERIOD_BLOCKS,
    );
    insert_u64(
        state,
        PARAM_PRIVATE_MAX_DEPTH,
        constants::PRIVATE_MAX_DEPTH as u64,
    );
    insert_u64(
        state,
        PARAM_PUBLIC_MAX_DEPTH,
        constants::PUBLIC_MAX_DEPTH as u64,
    );
    // Private balance params
    insert_u128(state, PARAM_MAX_PRIVATE_FEE, 1_000_000_000_000u128);
    insert_bytes32(
        state,
        PARAM_FEE_AUTHORITY,
        truthlinked_core::pq_execution::system_authority_id(),
    );
}

pub fn rehydrate_from_state<S: ParamState>(state: &S) {
    if state.params().is_empty() {
        return;
    }
    let mut next = HashMap::with_capacity(state.params().len());
    for (key, value) in state.params().iter() {
        next.insert(*key, *value);
    }
    let mut guard = PARAM_CACHE.write().expect("param cache lock");
    *guard = next;
}

pub fn update_param(key: [u8; 32], value: [u8; 32]) {
    PARAM_CACHE
        .write()
        .expect("param cache lock")
        .insert(key, value);
}

fn require_param(name: &str) -> [u8; 32] {
    let key = param_key(name);
    let guard = PARAM_CACHE.read().expect("param cache lock");
    if let Some(value) = guard.get(&key) {
        return *value;
    }
    drop(guard);
    #[cfg(test)]
    {
        if PARAM_CACHE.read().expect("param cache lock").is_empty() {
            struct TestState {
                params: im::HashMap<[u8; 32], [u8; 32]>,
            }
            impl ParamState for TestState {
                fn params(&self) -> &im::HashMap<[u8; 32], [u8; 32]> {
                    &self.params
                }
                fn params_mut(&mut self) -> &mut im::HashMap<[u8; 32], [u8; 32]> {
                    &mut self.params
                }
            }
            let mut state = TestState {
                params: im::HashMap::new(),
            };
            insert_genesis_params(&mut state);
            let mut guard = PARAM_CACHE.write().expect("param cache lock");
            if guard.is_empty() {
                for (k, v) in state.params.iter() {
                    guard.insert(*k, *v);
                }
            }
        }
        let guard = PARAM_CACHE.read().expect("param cache lock");
        if let Some(value) = guard.get(&key) {
            return *value;
        }
    }
    match name {
        PARAM_TX_BYTE_FEE => return encode_u64(constants::TX_BYTE_FEE),
        PARAM_MEMPOOL_MAX_BYTES => return encode_u64(constants::MEMPOOL_MAX_BYTES as u64),
        _ => {}
    }
    panic!("missing on-chain parameter: {}", name)
}

pub fn is_known_param_key(key: &[u8; 32]) -> bool {
    PARAM_SPECS.iter().any(|spec| &param_key(spec.name) == key)
}

pub fn validate_param_value(key: &[u8; 32], value: [u8; 32]) -> Result<(), String> {
    if PINNED_PARAMS.iter().any(|name| &param_key(name) == key) {
        return Err("Governance parameter is pinned and cannot be changed".to_string());
    }
    let spec = PARAM_SPECS
        .iter()
        .find(|spec| &param_key(spec.name) == key)
        .ok_or_else(|| "Unknown governance parameter key".to_string())?;
    match spec.kind {
        ParamKind::U64 => {
            let v = decode_u64(value);
            if v < spec.min_u64 || v > spec.max_u64 {
                return Err("Governance parameter value out of range".to_string());
            }
        }
        ParamKind::U128 => {
            let v = decode_u128(value);
            if v < spec.min_u128 || v > spec.max_u128 {
                return Err("Governance parameter value out of range".to_string());
            }
        }
    }
    // Hard safety caps: governance cannot exceed compiled limits.
    let v64 = decode_u64(value);
    let k_max_gas = param_key(PARAM_MAX_GAS_PER_TX);
    let k_max_calldata = param_key(PARAM_MAX_CALLDATA_SIZE);
    let k_max_chain_calldata = param_key(PARAM_MAX_CALL_CHAIN_TOTAL_CALLDATA);
    let k_cu_per_tlkd = param_key(PARAM_CU_PER_TLKD);
    if key == &k_max_gas && v64 > constants::MAX_GAS_PER_TX {
        return Err("max_gas_per_tx exceeds hard cap".to_string());
    }
    if key == &k_max_calldata && v64 > constants::MAX_CALLDATA_SIZE as u64 {
        return Err("max_calldata_size exceeds hard cap".to_string());
    }
    if key == &k_max_chain_calldata && v64 > constants::MAX_CALL_CHAIN_TOTAL_CALLDATA as u64 {
        return Err("max_call_chain_total_calldata exceeds hard cap".to_string());
    }
    if key == &k_cu_per_tlkd && v64 > constants::MAX_CU_PER_TLKD {
        return Err("cu_per_tlkd exceeds hard cap".to_string());
    }
    Ok(())
}

pub fn get_param_by_key(key: &[u8; 32]) -> Option<[u8; 32]> {
    let guard = PARAM_CACHE.read().expect("param cache lock");
    guard.get(key).copied()
}

pub fn get_u64(name: &str) -> u64 {
    decode_u64(require_param(name))
}

pub fn get_u128(name: &str) -> u128 {
    decode_u128(require_param(name))
}

pub fn get_usize(name: &str) -> usize {
    decode_u64(require_param(name)) as usize
}

pub fn get_u32(name: &str) -> u32 {
    decode_u64(require_param(name)) as u32
}

pub fn get_u16(name: &str) -> u16 {
    decode_u64(require_param(name)) as u16
}

pub fn get_u8(name: &str) -> u8 {
    decode_u64(require_param(name)) as u8
}

/// Read a raw 32-byte param value (used for AccountId-typed params like fee_authority).
pub fn get_bytes32(name: &str) -> [u8; 32] {
    require_param(name)
}

fn insert_bytes32<S: ParamState>(state: &mut S, name: &str, value: [u8; 32]) {
    state.params_mut().insert(param_key(name), value);
}
