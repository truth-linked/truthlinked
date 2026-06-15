//! TruthLinked Constants - All system-wide configuration values

use truthlinked_core::constants::MAX_GAS_PER_TX;

// ========== NETWORK PARAMETERS ==========

/// Ingress server port (client transaction submission)
pub const INGRESS_PORT: u16 = 18080;

/// ACK server port (validator attestations)
pub const ACK_SERVER_PORT: u16 = 18081;

/// RPC server port (HTTP API)
pub const RPC_PORT: u16 = 19944;

// ========== STAKING PARAMETERS ==========

/// Number of blocks after which a committed-but-unrevealed oracle request expires (slash window)
/// At 200ms/block: 7200 blocks = ~24 min. Validators have that long to reveal after commit quorum.
pub const ORACLE_REVEAL_DEADLINE_BLOCKS: u64 = 7200;

// ========== TIME VALIDATION PARAMETERS ==========

/// Max future timestamp drift for batch headers (5 minutes)
pub const BATCH_MAX_FUTURE_DRIFT: u64 = 300;

/// Max past age for batch headers (1 hour)
pub const BATCH_MAX_PAST_AGE: u64 = 3600;

/// Max future timestamp drift for snapshots (1 minute)
pub const SNAPSHOT_MAX_FUTURE_DRIFT: u64 = 60;

/// Max past age for snapshots (30 minutes)
pub const SNAPSHOT_MAX_PAST_AGE: u64 = 1800;

// ========== ACK SERVER PARAMETERS ==========

// ========== TOKEN PARAMETERS ==========

/// Token name
pub const TOKEN_NAME: &str = "TruthLinked";

/// Token symbol
pub const TOKEN_SYMBOL: &str = "TLKD";

/// Smallest unit name
pub const TOKEN_SUBUNIT: &str = "xiom";

/// Token decimals
pub const TOKEN_DECIMALS: u8 = 9;

/// Total supply (1 billion TLKD)
pub const TOTAL_SUPPLY: u128 = 1_000_000_000_000_000_000;

/// Maximum total devnet faucet mint allowance (100 million TLKD).
pub const MAX_TESTNET_MINT: u128 = 100_000_000 * truthlinked_core::constants::ONE_TLKD;

// ========== STORAGE PARAMETERS ==========

/// Maximum blockchain headers kept in memory (~10KB each with Dilithium sigs)
pub const MAX_HEADER_HISTORY: u64 = 2_000;

/// Maximum snapshots kept on disk
pub const MAX_SNAPSHOTS_KEPT: usize = 10;

/// executed_tx_hashes cap and keep-after-prune
pub const MAX_EXECUTED_TX_HASHES: usize = 100_000;
pub const KEEP_EXECUTED_TX_HASHES: usize = 80_000;

/// pending_batches hard cap in streaming consensus
pub const MAX_PENDING_BATCHES: usize = 64;

/// State collection caps (pruned end-of-block)
pub const MAX_AIRDROP_CLAIMS: usize = 50_000;
pub const MAX_PENDING_NAMES: usize = 1_000;
pub const MAX_TOKEN_AUTHORITY_PROPOSALS: usize = 256;
pub const MAX_URL_PROPOSALS: usize = 256;
pub const MAX_SCHEMA_PROPOSALS: usize = 256;
pub const MAX_ORACLE_RESULTS: usize = 1_000;
pub const MAX_NAME_REGISTRY: usize = 100_000;
pub const MAX_SCHEMA_REGISTRY: usize = 10_000;

/// AttestationPipeline early buffer cap
pub const MAX_EARLY_ATTESTATION_BUFFER: usize = 64;

/// SyncManager peer_heights hard cap
pub const MAX_SYNC_PEER_HEIGHTS: usize = 256;

// ========== CRYPTOGRAPHIC CONTEXTS ==========

/// Signing context for batch headers
pub const BATCH_SIGN_CONTEXT: &[u8] = b"truthlinked-batch-v1";

/// Signing context for attestations
pub const ATTESTATION_CONTEXT: &[u8] = b"truthlinked-attestation-v1";
pub const STREAM_TX_CONTEXT: &[u8] = b"truthlinked-streamed-tx-v1";

/// Signing context for snapshots
pub const SNAPSHOT_SIGN_CONTEXT: &[u8] = b"truthlinked-snapshot-v1";

// ========== VM PARAMETERS ==========

/// Maximum recursion depth in cell VM
pub const MAX_RECURSION_DEPTH: u32 = 256;

/// Maximum compute units per cell execution (same as max gas per tx)
pub const MAX_COMPUTE_UNITS: u64 = MAX_GAS_PER_TX;

/// Maximum loop iterations per loop
pub const MAX_LOOP_ITERATIONS: u64 = 10_000;

/// Maximum loop nesting depth
pub const MAX_LOOP_DEPTH: u32 = 10;

// ========== COMPUTE UNIT COSTS ==========

/// Base cost per opcode
pub const CU_BASE: u64 = 100;

/// State write operation
pub const CU_SET_FIELD: u64 = 1_000;

/// State read operation
pub const CU_GET_FIELD: u64 = 500;

/// State delete operation
pub const CU_DELETE_FIELD: u64 = 1_000;

/// Addition operation
pub const CU_ADD: u64 = 200;

/// Subtraction operation
pub const CU_SUB: u64 = 200;

/// Multiplication operation
pub const CU_MUL: u64 = 300;

/// Division operation
pub const CU_DIV: u64 = 400;

/// Comparison operations
pub const CU_COMPARE: u64 = 150;

/// If statement
pub const CU_IF: u64 = 200;

/// Loop initialization
pub const CU_LOOP: u64 = 500;

/// Stack operations
pub const CU_STACK: u64 = 50;

/// Emit log/event
pub const CU_EMIT_LOG: u64 = 1_000;

/// System context access
pub const CU_SYSTEM_CONTEXT: u64 = 50;

/// Hashing operations
pub const CU_BLAKE3: u64 = 500;
pub const CU_SHA256: u64 = 500;

// ========== DETERMINISTIC GAS METERING ==========

/// This ensures all validators compute the same gas cost regardless of Wasmer version

/// Bitwise operations
pub const CU_BITWISE: u64 = 100;

/// Bytes operations
pub const CU_BYTES: u64 = 100;

/// Storage iteration
pub const CU_STORAGE_ITER: u64 = 1_000;

/// Cell calls
pub const CU_CALL: u64 = 10_000;
pub const CU_STATIC_CALL: u64 = 5_000;

/// Dilithium signature verification (FREE - subsidized by chain)
pub const CU_DILITHIUM_VERIFY: u64 = 0;

/// Owner check
pub const CU_REQUIRE_OWNER: u64 = 100;

// staking lock parameters (blocks)
// 1 month to 4 years, based on 200ms block time.
pub const STAKED_TRTH_MIN_LOCK_BLOCKS: u64 = 30 * 432_000;
pub const STAKED_TRTH_MAX_LOCK_BLOCKS: u64 = 4 * 365 * 432_000;

// ========== EMISSION PARAMETERS ==========

/// Blocks per year at 300ms block time (365.25 days × 24h × 3600s / 0.3s)
pub const BLOCKS_PER_YEAR: u64 = 105_120_000;

/// Year-1 treasury emission in whole TLKD (multiply by ONE_TLKD for xiom)
pub const EMISSION_YEAR1_TLKD: u128 = 25_000_000;

/// Annual emission decay in basis points (2000 = 20%)
pub const EMISSION_DECAY_BPS_PER_YEAR: u64 = 2_000;

/// Emission epoch length in blocks (~1 day at 300ms/block)
pub const EMISSION_EPOCH_BLOCKS: u64 = 432_000;

// ========== FEE SPLIT PARAMETERS (basis points) ==========

/// Validators share of protocol fee revenue (60%)
pub const FEE_SPLIT_VALIDATORS_BPS: u128 = 6_000;

/// Stakers share of protocol fee revenue (20%)
pub const FEE_SPLIT_STAKERS_BPS: u128 = 2_000;

/// Burn share of protocol fee revenue (20%)
pub const FEE_SPLIT_BURN_BPS: u128 = 2_000;

// ========== SECURITY PARAMETERS ==========

/// Storage cost per byte (compute units)
pub const CU_STORAGE_PER_BYTE: u64 = 10;

/// Canonical storage key width for cell storage host ABI.
pub const STORAGE_KEY_BYTES: usize = 32;

/// Canonical storage value width for cell storage host ABI.
pub const STORAGE_VALUE_BYTES: usize = 32;

// ========== SNAPSHOT VALIDATION LIMITS ==========

/// Max signatures accepted in a snapshot payload.
pub const SNAPSHOT_MAX_SIGNATURES: usize = 1_000;

// ========== ANSI COLOR CODES ==========

pub const ANSI_RESET: &str = "\x1b[0m";
pub const ANSI_GREEN: &str = "\x1b[32m";
pub const ANSI_RED: &str = "\x1b[31m";
pub const ANSI_YELLOW: &str = "\x1b[33m";
pub const ANSI_CYAN: &str = "\x1b[36m";
pub const ANSI_BOLD: &str = "\x1b[1m";
pub const ANSI_DIM: &str = "\x1b[2m";
