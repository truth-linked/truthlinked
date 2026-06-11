//! Protocol constants shared across TruthLinked components.
//!
//! Values in this module affect transaction pricing, execution limits, staking,
//! networking, and governance behavior. Changes should be treated as protocol
//! changes and coordinated with every crate or service that validates chain data.

pub const ONE_TRTH: u128 = 1_000_000_000;

/// One whole TLKD expressed in xiom base units.
pub const ONE_TLKD: u128 = ONE_TRTH;

pub const TX_SIGN_CONTEXT: &[u8] = b"truthlinked-transaction-v1";
pub const GENERIC_SIGN_CONTEXT: &[u8] = b"truthlinked-generic-v1";

pub const GAS_TRANSFER: u64 = 1_000;

pub const STORAGE_RENT_LIFETIME_FEE: u128 = ONE_TRTH;
pub const TX_BYTE_FEE: u64 = 1;
pub const MEMPOOL_MAX_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_CALLDATA_SIZE: usize = 262_144;
pub const MAX_RETURN_DATA_SIZE: usize = MAX_CALLDATA_SIZE;
pub const MAX_CALL_CHAIN_CALLS: usize = 64;
pub const MAX_CALL_CHAIN_TOTAL_CALLDATA: usize = MAX_CALLDATA_SIZE;
pub const MAX_BATCH_TRANSFER_RECIPIENTS: usize = 64;
pub const NONCE_LOOKAHEAD: u64 = 64;

pub const MIN_URL_PROPOSAL_BOND: u128 = ONE_TRTH;
pub const MIN_RAW_URL_PROPOSAL_BOND: u128 = 5 * ONE_TRTH;
pub const MAX_SCHEMA_KEYS: u64 = 64;
pub const MAX_SCHEMA_KEY_BYTES: u64 = 64;
pub const MAX_SCHEMA_VOTING_PERIOD_BLOCKS: u64 = 1_000_000;

pub const MAX_AIRDROP_AMOUNT: u128 = 15_000 * ONE_TRTH;

// Consensus defaults
pub const BATCH_INTERVAL_MS: u64 = 200;
pub const MAX_BATCH_SIZE: usize = 30000;
pub const COMMITTEE_SIZE: usize = 20;
pub const EPOCH_DURATION_MS: u64 = 60000;
pub const FINALIZATION_LAG: u64 = 2;
pub const FINALIZATION_TIMEOUT_SECS: u64 = 10;
pub const SYNC_THRESHOLD: u64 = 8;
pub const MAX_BATCH_RANGE: u64 = 1000;
pub const SYNC_PEER_TTL_SECS: u64 = 30;
pub const SYNC_SNAPSHOT_THRESHOLD: u64 = 1_000;

// Staking slash defaults
pub const MIN_VALIDATOR_STAKE: u64 = 10_000_000_000;
pub const MAX_VALIDATOR_STAKE: u64 = 1_000_000_000_000_000_000;
pub const UNBONDING_TICKS: u64 = 181_440_000;
pub const JAIL_DURATION_BLOCKS: u64 = 100;
pub const MAX_UNBONDING_ENTRIES: usize = 100;
pub const SLASH_PERCENTAGE: u64 = 5;
pub const ORACLE_LIE_SLASH_PERCENTAGE: u64 = 30;
pub const ORACLE_SILENCE_SLASH_PERCENTAGE: u64 = 2;
pub const DOWNTIME_SLASH_PERCENTAGE: u64 = 1;
pub const CENSORSHIP_SLASH_PERCENTAGE: u64 = 1;

// Streaming consensus defaults
pub const STREAMING_OPTIMAL_BATCH_SIZE: usize = 10_000;
pub const STREAMING_MAX_WAIT_MS: u64 = 300;
pub const STREAMING_MAX_SYNC_BUFFER_SIZE: usize = 100;
pub const STREAMING_MAX_BATCH_CACHE: usize = 256;
pub const STREAMING_MAX_PENDING_HEADERS: usize = 256;
pub const STREAMING_MAX_SEEN_TXS: usize = 1_000_000;
pub const STREAMING_PENDING_BATCH_TIMEOUT_MS: u64 = 5_000;

// Network limits
pub const INGRESS_MAX_CONNECTIONS: usize = 1024;
pub const INGRESS_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const INGRESS_MAX_MESSAGES_PER_SECOND: u32 = 200;
pub const ACK_MAX_CONNECTIONS: usize = 512;
pub const ACK_MAX_MESSAGE_BYTES: usize = 256 * 1024;
pub const ACK_MAX_MESSAGES_PER_SECOND: u32 = 200;
pub const ACK_MAX_PENDING_BATCHES: usize = 4096;
pub const ACK_MAX_BATCH_AGE_SECS: u64 = 300;
pub const DISCOVERY_MAX_PEERS: usize = 2048;
pub const DISCOVERY_PEER_TTL_SECS: u64 = 600;
pub const ATTESTATION_PIPELINE_MAX_PENDING: usize = 4096;
pub const CHUNK_SIZE: usize = 4096;
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

// VM limits
pub const DEFAULT_GAS_LIMIT: u64 = 1_000_000;
pub const MAX_GAS_PER_TX: u64 = 10_000_000;
pub const MAX_GAS_PER_BATCH: u64 = 100_000_000;
pub const MAX_CALL_DEPTH: u32 = 30;
pub const MAX_LOG_DATA_SIZE: usize = 65_536;
pub const MAX_LOGS_PER_TX: usize = 100;
pub const MAX_LOG_TOPICS: usize = 8;
pub const MAX_CELL_BYTECODE_SIZE: usize = 1_000_000;
pub const MAX_CELL_STORAGE_BYTES: u64 = 10_000_000;

// Fees and CU pricing
pub const GAS_PRICE: u64 = 1;
pub const GAS_CLAIM: u64 = 2_000;
pub const GAS_ROTATE_KEY: u64 = 1_000;
pub const GAS_REGISTER_VALIDATOR: u64 = 10_000;
pub const GAS_STAKE: u64 = 5_000;
pub const GAS_UNSTAKE: u64 = 5_000;
pub const GAS_WITHDRAW: u64 = 5_000;
pub const GAS_UNJAIL: u64 = 10_000;
pub const GAS_MINT_NFT: u64 = 50_000;
pub const GAS_TRANSFER_NFT: u64 = 10_000;
pub const GAS_BURN_NFT: u64 = 5_000;
pub const GAS_APPROVE_NFT: u64 = 5_000;
pub const GAS_DEPLOY_CELL: u64 = 1_000_000;
pub const GAS_DEPLOY_TOKEN: u64 = 500_000;
pub const GAS_UPGRADE_CELL: u64 = 500_000;
pub const GAS_TOKEN_TRANSFER: u64 = 5_000;
pub const GAS_TOKEN_MINT: u64 = 10_000;
pub const GAS_TOKEN_BURN: u64 = 5_000;
pub const GAS_ORACLE_READ: u64 = 1_000;
pub const GAS_ORACLE_QUEUE: u64 = 5_000;
pub const TREASURY_DISTRIBUTION_INTERVAL_BLOCKS: u64 = 1_296_000;
pub const GAS_DISTRIBUTION_INTERVAL: u64 = TREASURY_DISTRIBUTION_INTERVAL_BLOCKS;

pub const STORAGE_RENT_GRACE_PERIOD_BLOCKS: u64 = 2_592_000;
pub const MIN_TX_FEE: u64 = 100;
pub const AIRDROP_COOLDOWN_SECS: u64 = 259_200;

pub const NAME_REGISTRATION_FEE: u128 = 10_000_000_000;
pub const NAME_RENEWAL_FEE: u128 = 1_000_000_000;
pub const NAME_EXPIRATION_BLOCKS: u64 = 12_960_000;
pub const NAME_VOTING_PERIOD: u64 = 432_000;
pub const NAME_APPROVAL_THRESHOLD: u64 = 67;
pub const TOKEN_AUTHORITY_APPROVAL_THRESHOLD: u64 = 67;

pub const CU_PER_TRTH: u64 = 1_000_000;
pub const MAX_CU_PER_TRTH: u64 = 1_000_000_000;

// MCP storage key namespace
pub const fn mcp_key(prefix: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < prefix.len() && i < 32 {
        out[i] = prefix[i];
        i += 1;
    }
    out
}

pub const MCP_REGISTRY_TOOL_COUNT_KEY: [u8; 32] = mcp_key(b"mcp:tool_count");
pub const MCP_REGISTRY_RESOURCE_COUNT_KEY: [u8; 32] = mcp_key(b"mcp:resource_count");
pub const MCP_REGISTRY_PROMPT_COUNT_KEY: [u8; 32] = mcp_key(b"mcp:prompt_count");
pub const MCP_REGISTRY_VERSION_KEY: [u8; 32] = mcp_key(b"mcp:registry_ver");

pub const MCP_TOOL_NAME_KEY: [u8; 32] = mcp_key(b"tool:name");
pub const MCP_TOOL_DESC_HASH_KEY: [u8; 32] = mcp_key(b"tool:desc_hash");
pub const MCP_TOOL_SCHEMA_HASH_KEY: [u8; 32] = mcp_key(b"tool:schema");
pub const MCP_TOOL_CATEGORY_KEY: [u8; 32] = mcp_key(b"tool:category");
pub const MCP_TOOL_CALL_COUNT_KEY: [u8; 32] = mcp_key(b"tool:calls");
pub const MCP_TOOL_OWNER_KEY: [u8; 32] = mcp_key(b"tool:owner");
pub const MCP_TOOL_ENABLED_KEY: [u8; 32] = mcp_key(b"tool:enabled");

pub const MCP_RESOURCE_NAME_KEY: [u8; 32] = mcp_key(b"res:name");
pub const MCP_RESOURCE_URI_SCHEME_KEY: [u8; 32] = mcp_key(b"res:uri_scheme");
pub const MCP_RESOURCE_MIME_TYPE_KEY: [u8; 32] = mcp_key(b"res:mime");
pub const MCP_RESOURCE_CONTENT_HASH_KEY: [u8; 32] = mcp_key(b"res:content");
pub const MCP_RESOURCE_UPDATED_AT_KEY: [u8; 32] = mcp_key(b"res:updated");
pub const MCP_RESOURCE_READ_COUNT_KEY: [u8; 32] = mcp_key(b"res:reads");

pub const MCP_PROMPT_NAME_KEY: [u8; 32] = mcp_key(b"prompt:name");
pub const MCP_PROMPT_TEMPLATE_HASH_KEY: [u8; 32] = mcp_key(b"prompt:template");
pub const MCP_PROMPT_ARG_COUNT_KEY: [u8; 32] = mcp_key(b"prompt:argc");
pub const MCP_PROMPT_USE_COUNT_KEY: [u8; 32] = mcp_key(b"prompt:uses");
pub const MCP_PROMPT_APPROVED_AT_KEY: [u8; 32] = mcp_key(b"prompt:approved");

pub const MCP_POLICY_OWNER_KEY: [u8; 32] = mcp_key(b"pol:owner");
pub const MCP_POLICY_STATUS_KEY: [u8; 32] = mcp_key(b"pol:status");
pub const MCP_POLICY_ALLOW_READS_KEY: [u8; 32] = mcp_key(b"pol:reads");
pub const MCP_POLICY_ALLOW_WRITES_KEY: [u8; 32] = mcp_key(b"pol:writes");
pub const MCP_POLICY_ALLOW_ADMIN_KEY: [u8; 32] = mcp_key(b"pol:admin");
pub const MCP_POLICY_RATE_LIMIT_KEY: [u8; 32] = mcp_key(b"pol:rate");
pub const MCP_POLICY_SPEND_PER_TX_KEY: [u8; 32] = mcp_key(b"pol:spend_tx");
pub const MCP_POLICY_SPEND_EPOCH_KEY: [u8; 32] = mcp_key(b"pol:spend_ep");
pub const MCP_POLICY_EPOCH_USED_KEY: [u8; 32] = mcp_key(b"pol:ep_used");
pub const MCP_POLICY_EPOCH_RESET_TS_KEY: [u8; 32] = mcp_key(b"pol:ep_reset");
pub const MCP_POLICY_ACTIONS_MIN_KEY: [u8; 32] = mcp_key(b"pol:acts_min");
pub const MCP_POLICY_MIN_WINDOW_TS_KEY: [u8; 32] = mcp_key(b"pol:min_ts");
pub const MCP_POLICY_TOTAL_ACTIONS_KEY: [u8; 32] = mcp_key(b"pol:total");
pub const MCP_POLICY_HITL_THRESHOLD_KEY: [u8; 32] = mcp_key(b"pol:hitl");
pub const MCP_POLICY_SUSPEND_REASON_KEY: [u8; 32] = mcp_key(b"pol:sus_reason");

pub const MCP_AGENT_REGISTRY_COUNT_KEY: [u8; 32] = mcp_key(b"areg:count");

pub const ORACLE_COMMIT_QUORUM_PERCENT: u64 = 51;
pub const ORACLE_REVEAL_QUORUM_PERCENT: u64 = 67;
pub const ORACLE_REQUEST_TIMEOUT_BLOCKS: u64 = 120;
pub const CACHE_EXPIRY_BLOCKS: u64 = 7_200;
pub const MAX_RESPONSE_BYTES: usize = 1_000_000;
pub const MAX_HTTP_BODY_BYTES: usize = 128 * 1024;
pub const MAX_HTTP_URL_BYTES: usize = 2_048;
pub const MAX_HTTP_METHOD_BYTES: usize = 16;
pub const HTTP_TIMEOUT_MS: u64 = 5_000;
pub const MALICIOUS_SLASH_BPS: u64 = 7_000;
pub const MAX_URL_VOTING_PERIOD_BLOCKS: u64 = 100_000;
pub const MAX_TOKEN_AUTHORITY_VOTING_PERIOD_BLOCKS: u64 = 100_000;
pub const PRIVATE_MAX_DEPTH: u32 = 2;
pub const PUBLIC_MAX_DEPTH: u32 = 30;

pub const HTTP_ORACLE_RC_OK: i32 = 0;
pub const HTTP_ORACLE_RC_MEM_ERR: i32 = -1;
pub const HTTP_ORACLE_RC_ENCODING_ERR: i32 = -2;
pub const HTTP_ORACLE_RC_URL_NOT_APPROVED: i32 = -3;
pub const HTTP_ORACLE_RC_PENDING: i32 = -5;
pub const HTTP_ORACLE_RC_EXPIRED: i32 = -6;
pub const HTTP_ORACLE_RC_RESPONSE_TOO_LARGE: i32 = -7;
pub const HTTP_ORACLE_RC_DEPTH_LIMIT_EXCEEDED: i32 = -8;
pub const HTTP_ORACLE_RC_INVALID_METHOD: i32 = -9;
