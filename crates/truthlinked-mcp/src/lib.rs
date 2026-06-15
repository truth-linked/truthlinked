//! TruthLinked on-chain MCP primitives for agent-native blockchain execution.
//!
//! This is not a server wrapping the chain.
//! MCP tools, resources, and prompts are smart cells deployed on TruthLinked.
//!
//! Architecture:
//!
//!   McpRegistry cell   - the chain's MCP namespace. Stores all registered
//!                            tool resource prompt cell ids. The agent's
//!                            tools list is a read of this cell's storage.
//!
//!   McpTool cell       - each tool is a deployed Axiom cell with
//!                            storage["schema"]     = json schema bytes
//!                            storage["name"]       = tool name bytes
//!                            storage["version"]    = semver bytes
//!                            calling the tool is a CallCell on that cell.
//!                            the tool's Axiom bytecode is the tool's logic.
//!
//!   McpResource cell   - a cell whose storage is the resource data.
//!                            reading a resource reads cell storage slots.
//!                            the resource is versioned by manifest_version.
//!
//!   McpPrompt cell     - a cell storing prompt templates in storage.
//!                            validators approve prompts via the name registry.
//!                            prompt provenance is provable: who deployed it,
//!                            which block, what manifest hash.
//!
//!   AgentPolicy cell   - a Axiom cell that enforces what calls an agent
//!                            is permitted to make. Called before every tool call
//!                            via CallCellChain. Reverts the chain if policy
//!                            is violated, the chain enforces it, not middleware.
//!
//!   AgentRegistry cell - maps agent_id to policy_cell_id.
//!                            owner sets this. Agent cannot change it.
//!                            stored on chain. Immutable once the owner locks it.
//!
//! New TransactionIntents:
//!
//!   RegisterMcpTool       - deploys a tool cell and registers in McpRegistry
//!   RegisterMcpResource   - deploys a resource cell and registers in McpRegistry
//!   RegisterMcpPrompt     - deploys a prompt cell and validator approves name
//!   RegisterAgent         - binds agent_id to policy_cell_id in AgentRegistry
//!   UpdateAgentPolicy     - owner calls policy cell to change permissions
//!   SuspendAgent          - owner sets agent status to Suspended in AgentRegistry
//!   McpToolCall           - agent calls a tool with policy check and execution,
//!                           all atomic in one CallCellChain transaction
//!
//! The MCP protocol transport (websocket json-rpc) is a thin adapter that
//! translates MCP wire messages into TruthLinked transactions and reads.
//! Every tool call produces a transaction. Every resource read reads cell
//! storage. The chain is the MCP server. The transport is just protocol glue.

use im::HashMap as ImHashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use truthlinked_core::pq_execution::{AccountId, CellCall, TransactionIntent};
use truthlinked_governance::params as gp;
use truthlinked_runtime::cells::{CellAccount, CellState};
use truthlinked_runtime::compiler_aware::StorageKey;
use truthlinked_runtime::types::{AccountRecord, CellUpdate, StateDiff};
pub mod private_balance;
pub mod zk_transfer;

pub trait McpStateView {
    fn cells(&self) -> &CellState;
    fn accounts(&self) -> &ImHashMap<AccountId, AccountRecord>;
}

//
// Storage key namespaces.
// All MCP on-chain state lives in cell storage using these key prefixes.
// Every key is 32 bytes. Multi-byte fields are packed with blake3 hashing.
//

/// Canonical storage keys for the McpRegistry cell
pub mod registry_keys {
    /// storage[TOOL_COUNT]          = u64 little-endian: total registered tools
    pub const TOOL_COUNT: [u8; 32] = truthlinked_core::constants::MCP_REGISTRY_TOOL_COUNT_KEY;
    /// storage[RESOURCE_COUNT]      = u64: total registered resources
    pub const RESOURCE_COUNT: [u8; 32] =
        truthlinked_core::constants::MCP_REGISTRY_RESOURCE_COUNT_KEY;
    /// storage[PROMPT_COUNT]        = u64: total registered prompts
    pub const PROMPT_COUNT: [u8; 32] = truthlinked_core::constants::MCP_REGISTRY_PROMPT_COUNT_KEY;
    /// storage[REGISTRY_VERSION]    = u64: incremented on every registration
    pub const REGISTRY_VER: [u8; 32] = truthlinked_core::constants::MCP_REGISTRY_VERSION_KEY;

    /// storage[tool_entry(i)]       = [u8; 32]: cell_id of tool i
    pub fn tool_entry(index: u64) -> [u8; 32] {
        let mut k = truthlinked_core::constants::mcp_key(b"mcp:tool:");
        k[16..24].copy_from_slice(&index.to_le_bytes());
        k
    }
    /// storage[resource_entry(i)]   = [u8; 32]: cell_id of resource i
    pub fn resource_entry(index: u64) -> [u8; 32] {
        let mut k = truthlinked_core::constants::mcp_key(b"mcp:res:");
        k[16..24].copy_from_slice(&index.to_le_bytes());
        k
    }
    /// storage[prompt_entry(i)]     = [u8; 32]: cell_id of prompt i
    pub fn prompt_entry(index: u64) -> [u8; 32] {
        let mut k = truthlinked_core::constants::mcp_key(b"mcp:prompt:");
        k[16..24].copy_from_slice(&index.to_le_bytes());
        k
    }
    /// storage[name_to_tool(name)]  = [u8; 32]: cell_id for a named tool
    pub fn name_to_tool(name: &str) -> [u8; 32] {
        blake3_key(b"mcp:ntool:", name.as_bytes())
    }
    /// storage[name_to_resource(name)] = [u8; 32]: cell_id
    pub fn name_to_resource(name: &str) -> [u8; 32] {
        blake3_key(b"mcp:nres:", name.as_bytes())
    }
    /// storage[name_to_prompt(name)] = [u8; 32]
    pub fn name_to_prompt(name: &str) -> [u8; 32] {
        blake3_key(b"mcp:nprompt:", name.as_bytes())
    }

    pub fn key(prefix: &[u8]) -> [u8; 32] {
        truthlinked_core::constants::mcp_key(prefix)
    }
    pub fn blake3_key(prefix: &[u8], data: &[u8]) -> [u8; 32] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(data);
        *blake3::hash(&input).as_bytes()
    }
}

/// Canonical storage keys for a McpTool cell
pub mod tool_keys {
    /// storage[NAME]      = UTF-8 bytes of tool name (max 32 bytes, padded)
    pub const NAME: [u8; 32] = truthlinked_core::constants::MCP_TOOL_NAME_KEY;
    /// storage[DESCRIPTION]= first 32 bytes of description hash (full desc in metadata)
    pub const DESC_HASH: [u8; 32] = truthlinked_core::constants::MCP_TOOL_DESC_HASH_KEY;
    /// storage[SCHEMA_HASH]= blake3(input_schema_json)
    pub const SCHEMA_HASH: [u8; 32] = truthlinked_core::constants::MCP_TOOL_SCHEMA_HASH_KEY;
    /// storage[CATEGORY]  = u8 category tag (0=read, 1=write, 2=admin)
    pub const CATEGORY: [u8; 32] = truthlinked_core::constants::MCP_TOOL_CATEGORY_KEY;
    /// storage[CALL_COUNT] = u64: total successful invocations (commutative Add)
    pub const CALL_COUNT: [u8; 32] = truthlinked_core::constants::MCP_TOOL_CALL_COUNT_KEY;
    /// storage[OWNER]      = [u8; 32]: who governs this tool's Axiom bytecode
    pub const OWNER: [u8; 32] = truthlinked_core::constants::MCP_TOOL_OWNER_KEY;
    /// storage[ENABLED]    = u8: 1=enabled, 0=disabled
    pub const ENABLED: [u8; 32] = truthlinked_core::constants::MCP_TOOL_ENABLED_KEY;
}

/// Canonical storage keys for a McpResource cell
pub mod resource_keys {
    pub const NAME: [u8; 32] = truthlinked_core::constants::MCP_RESOURCE_NAME_KEY;
    pub const URI_SCHEME: [u8; 32] = truthlinked_core::constants::MCP_RESOURCE_URI_SCHEME_KEY;
    pub const MIME_TYPE: [u8; 32] = truthlinked_core::constants::MCP_RESOURCE_MIME_TYPE_KEY;
    pub const CONTENT_HASH: [u8; 32] = truthlinked_core::constants::MCP_RESOURCE_CONTENT_HASH_KEY;
    pub const UPDATED_AT: [u8; 32] = truthlinked_core::constants::MCP_RESOURCE_UPDATED_AT_KEY;
    pub const READ_COUNT: [u8; 32] = truthlinked_core::constants::MCP_RESOURCE_READ_COUNT_KEY;

    /// Dynamic content slot: resource data is stored at blake3("res:data:" || slot_key)
    pub fn data_slot(slot_key: &[u8]) -> [u8; 32] {
        super::registry_keys::blake3_key(b"res:data:", slot_key)
    }
}

/// Canonical storage keys for a McpPrompt cell
pub mod prompt_keys {
    pub const NAME: [u8; 32] = truthlinked_core::constants::MCP_PROMPT_NAME_KEY;
    pub const TEMPLATE_HASH: [u8; 32] = truthlinked_core::constants::MCP_PROMPT_TEMPLATE_HASH_KEY;
    pub const ARG_COUNT: [u8; 32] = truthlinked_core::constants::MCP_PROMPT_ARG_COUNT_KEY;
    pub const USE_COUNT: [u8; 32] = truthlinked_core::constants::MCP_PROMPT_USE_COUNT_KEY;
    pub const APPROVED_AT: [u8; 32] = truthlinked_core::constants::MCP_PROMPT_APPROVED_AT_KEY;

    /// Argument schema at index i
    pub fn arg_schema(i: u8) -> [u8; 32] {
        let mut k = truthlinked_core::constants::mcp_key(b"prompt:arg:");
        k[16] = i;
        k
    }
}

/// Canonical storage keys for an AgentPolicy cell
pub mod policy_keys {
    pub const OWNER: [u8; 32] = truthlinked_core::constants::MCP_POLICY_OWNER_KEY;
    pub const STATUS: [u8; 32] = truthlinked_core::constants::MCP_POLICY_STATUS_KEY;
    /// 0=active 1=suspended 2=revoked (stored as u8)
    pub const ALLOW_READS: [u8; 32] = truthlinked_core::constants::MCP_POLICY_ALLOW_READS_KEY;
    pub const ALLOW_WRITES: [u8; 32] = truthlinked_core::constants::MCP_POLICY_ALLOW_WRITES_KEY;
    pub const ALLOW_ADMIN: [u8; 32] = truthlinked_core::constants::MCP_POLICY_ALLOW_ADMIN_KEY;
    pub const RATE_LIMIT: [u8; 32] = truthlinked_core::constants::MCP_POLICY_RATE_LIMIT_KEY;
    /// Max calls per minute: u32
    pub const SPEND_PER_TX: [u8; 32] = truthlinked_core::constants::MCP_POLICY_SPEND_PER_TX_KEY;
    /// Max TLKD per tx: u128 LE
    pub const SPEND_EPOCH: [u8; 32] = truthlinked_core::constants::MCP_POLICY_SPEND_EPOCH_KEY;
    pub const EPOCH_USED: [u8; 32] = truthlinked_core::constants::MCP_POLICY_EPOCH_USED_KEY;
    pub const EPOCH_RESET_TS: [u8; 32] = truthlinked_core::constants::MCP_POLICY_EPOCH_RESET_TS_KEY;
    pub const ACTIONS_MIN: [u8; 32] = truthlinked_core::constants::MCP_POLICY_ACTIONS_MIN_KEY;
    pub const MIN_WINDOW_TS: [u8; 32] = truthlinked_core::constants::MCP_POLICY_MIN_WINDOW_TS_KEY;
    pub const TOTAL_ACTIONS: [u8; 32] = truthlinked_core::constants::MCP_POLICY_TOTAL_ACTIONS_KEY;
    pub const HITL_THRESHOLD: [u8; 32] = truthlinked_core::constants::MCP_POLICY_HITL_THRESHOLD_KEY;
    pub const SUSPEND_REASON: [u8; 32] = truthlinked_core::constants::MCP_POLICY_SUSPEND_REASON_KEY;

    /// Per-tool permission: blake3("pol:tool:" || tool_cell_id)
    pub fn tool_permission(tool_id: &[u8; 32]) -> [u8; 32] {
        super::registry_keys::blake3_key(b"pol:tool:", tool_id)
    }
}

/// Canonical storage keys for the AgentRegistry cell
pub mod agent_reg_keys {
    pub const AGENT_COUNT: [u8; 32] = truthlinked_core::constants::MCP_AGENT_REGISTRY_COUNT_KEY;

    /// agent_id -> policy_cell_id
    pub fn agent_policy(agent_id: &[u8; 32]) -> [u8; 32] {
        super::registry_keys::blake3_key(b"areg:pol:", agent_id)
    }
    /// agent_id -> owner_id
    pub fn agent_owner(agent_id: &[u8; 32]) -> [u8; 32] {
        super::registry_keys::blake3_key(b"areg:own:", agent_id)
    }
    /// index -> agent_id for enumerable registry scans.
    pub fn agent_entry(index: u64) -> [u8; 32] {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&index.to_le_bytes());
        super::registry_keys::blake3_key(b"areg:idx:", &bytes)
    }

    /// agent_id -> registered_at (u64)
    pub fn agent_registered_at(agent_id: &[u8; 32]) -> [u8; 32] {
        super::registry_keys::blake3_key(b"areg:reg:", agent_id)
    }
}

//
// NEW TRANSACTION INTENTS
// These extend TransactionIntent in pq_execution.rs.
// Listed here as the canonical definition - will be merged into the enum.
//

/// All new MCP-related intent variants to be added to TransactionIntent.
/// Design rule: every intent maps to deterministic state transitions.
/// The parallel executor's conflict domain extracts their storage keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum McpIntent {
    /// Deploy a tool cell and register it in the McpRegistry.
    /// The tool's Axiom bytecode is its implementation. Schema lives in storage.
    /// Anyone can deploy a tool. The registry is permissionless.
    RegisterMcpTool {
        /// Desired tool cell address
        tool_id: AccountId,
        /// Axiom bytecode implementing the tool's logic
        bytecode: Vec<u8>,
        /// Tool name (max 32 bytes)
        name: String,
        /// Full JSON schema (stored as blake3 hash on-chain, full bytes in calldata)
        input_schema_json: Vec<u8>,
        /// 0=read-only, 1=writes state, 2=admin
        category: u8,
        /// Storage slots the Axiom bytecode reads/writes (for parallel conflict detection)
        declared_reads: Vec<[u8; 32]>,
        declared_writes: Vec<[u8; 32]>,
        commutative_keys: Vec<[u8; 32]>,
        oracle_schema_ids: Vec<[u8; 32]>,
        /// Address of the McpRegistry to register into
        registry_id: AccountId,
    },

    /// Deploy a resource cell. Its storage IS the resource data.
    /// Agents read resources by calling get_cell_storage on specific slots.
    RegisterMcpResource {
        resource_id: AccountId,
        bytecode: Vec<u8>, // Axiom bytecode for dynamic resources (optional)
        name: String,
        uri_scheme: String, // e.g. "trth://chain/validators"
        mime_type: String,  // "application/json", "text/plain", etc.
        /// Initial content: map of slot_key -> content_bytes (hashed to storage key)
        initial_data: Vec<(Vec<u8>, Vec<u8>)>,
        declared_reads: Vec<[u8; 32]>,
        declared_writes: Vec<[u8; 32]>,
        oracle_schema_ids: Vec<[u8; 32]>,
        registry_id: AccountId,
    },

    /// Deploy a prompt template cell.
    /// Prompt templates go through the validator name registry for approval.
    /// An approved prompt has a validator-certified name on-chain.
    RegisterMcpPrompt {
        prompt_id: AccountId,
        name: String,
        /// Full template bytes (stored as hash on-chain, full bytes in calldata)
        template_bytes: Vec<u8>,
        /// Argument definitions: (arg_name, arg_description, required)
        arguments: Vec<(String, String, bool)>,
        registry_id: AccountId,
    },

    /// Bind an agent's public key to a policy cell.
    /// Only the owner_id account can call this.
    /// The agent cannot register itself.
    RegisterAgent {
        agent_id: AccountId, // H(dilithium_pubkey)
        policy_cell_id: AccountId,
        agent_registry_id: AccountId,
    },

    /// Owner updates agent's policy by calling the policy cell directly.
    /// This IS a CallCell transaction on the policy cell.
    /// Listed here for clarity - the diff handler routes it as CallCell.
    UpdateAgentPolicy {
        policy_cell_id: AccountId,
        updates: PolicyUpdate,
    },

    /// Owner suspends an agent immediately. Stored in AgentRegistry.
    SuspendAgent {
        agent_id: AccountId,
        agent_registry_id: AccountId,
        reason: String,
    },

    /// Owner reinstates a suspended agent.
    ReinstateAgent {
        agent_id: AccountId,
        agent_registry_id: AccountId,
    },

    /// The core MCP tool call intent.
    ///
    /// This compiles into a CallCellChain:
    ///   1. Call policy_cell with (agent_id, tool_id, calldata_hash) - reverts if blocked
    ///   2. Call tool_cell with agent_calldata - executes the tool
    ///   3. (Optional) Call action_log_cell with (tool_id, result_hash) - appends log entry
    ///
    /// The ENTIRE chain is atomic. If policy rejects, nothing is written.
    /// If the tool fails, the policy gate's side effects are also rolled back.
    /// The action log entry only lands if the tool succeeded.
    McpToolCall {
        agent_id: AccountId,
        tool_id: AccountId,
        tool_calldata: Vec<u8>,
        value: u128,
        gas_limit: u64,
        policy_cell_id: AccountId,
        action_log_id: Option<AccountId>,
        timestamp: u64,
    },
}

/// Policy fields an owner may update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUpdate {
    pub status: Option<u8>, // 0=active 1=suspended 2=revoked
    pub allow_reads: Option<bool>,
    pub allow_writes: Option<bool>,
    pub allow_admin: Option<bool>,
    pub rate_limit: Option<u32>,
    pub spend_per_tx: Option<u128>,
    pub spend_epoch: Option<u128>,
    pub hitl_threshold: Option<u128>,
    /// Per-tool grants: (tool_cell_id, allowed)
    pub tool_permissions: Vec<(AccountId, bool)>,
}

//
// CONFLICT DOMAIN EXTRACTION
// The parallel executor needs to know which storage slots each MCP intent touches.
// This is called from compiler_aware.rs::ConcreteConflictDomain::from_transaction.
//

/// Extract conflict domain for MCP intents.
/// This is the extension point for compiler_aware.rs.
pub fn mcp_conflict_domain(intent: &McpIntent) -> (Vec<StorageKey>, Vec<StorageKey>) {
    match intent {
        McpIntent::RegisterMcpTool {
            tool_id,
            registry_id,
            ..
        } => {
            // Writes: tool cell storage + registry TOOL_COUNT + registry tool_entry
            // Read:   registry TOOL_COUNT (to get current index)
            (
                vec![StorageKey::CellStorage(
                    *registry_id,
                    registry_keys::TOOL_COUNT,
                )],
                vec![
                    StorageKey::CellStorage(*registry_id, registry_keys::TOOL_COUNT),
                    StorageKey::CellStorage(*registry_id, registry_keys::REGISTRY_VER),
                    StorageKey::CellStorage(*tool_id, tool_keys::NAME),
                ],
            )
        }

        McpIntent::RegisterMcpResource {
            resource_id,
            registry_id,
            ..
        } => (
            vec![StorageKey::CellStorage(
                *registry_id,
                registry_keys::RESOURCE_COUNT,
            )],
            vec![
                StorageKey::CellStorage(*registry_id, registry_keys::RESOURCE_COUNT),
                StorageKey::CellStorage(*registry_id, registry_keys::REGISTRY_VER),
                StorageKey::CellStorage(*resource_id, resource_keys::NAME),
            ],
        ),

        McpIntent::RegisterMcpPrompt {
            prompt_id,
            registry_id,
            ..
        } => (
            vec![StorageKey::CellStorage(
                *registry_id,
                registry_keys::PROMPT_COUNT,
            )],
            vec![
                StorageKey::CellStorage(*registry_id, registry_keys::PROMPT_COUNT),
                StorageKey::CellStorage(*registry_id, registry_keys::REGISTRY_VER),
                StorageKey::CellStorage(*prompt_id, prompt_keys::NAME),
            ],
        ),

        McpIntent::RegisterAgent {
            agent_id,
            agent_registry_id,
            ..
        } => (
            vec![StorageKey::CellStorage(
                *agent_registry_id,
                agent_reg_keys::AGENT_COUNT,
            )],
            vec![
                StorageKey::CellStorage(*agent_registry_id, agent_reg_keys::agent_policy(agent_id)),
                StorageKey::CellStorage(*agent_registry_id, agent_reg_keys::agent_owner(agent_id)),
                StorageKey::CellStorage(*agent_registry_id, agent_reg_keys::agent_entry(0)),
                StorageKey::CellStorage(*agent_registry_id, agent_reg_keys::AGENT_COUNT),
            ],
        ),

        McpIntent::SuspendAgent {
            agent_id,
            agent_registry_id,
            ..
        }
        | McpIntent::ReinstateAgent {
            agent_id,
            agent_registry_id,
        } => (
            vec![],
            vec![StorageKey::CellStorage(
                *agent_registry_id,
                agent_reg_keys::agent_policy(agent_id),
            )],
        ),

        McpIntent::UpdateAgentPolicy {
            policy_cell_id,
            updates,
        } => {
            let mut writes = vec![
                StorageKey::CellStorage(*policy_cell_id, policy_keys::STATUS),
                StorageKey::CellStorage(*policy_cell_id, policy_keys::ALLOW_READS),
                StorageKey::CellStorage(*policy_cell_id, policy_keys::ALLOW_WRITES),
            ];
            for (tool_id, _) in &updates.tool_permissions {
                writes.push(StorageKey::CellStorage(
                    *policy_cell_id,
                    policy_keys::tool_permission(tool_id),
                ));
            }
            (vec![], writes)
        }

        McpIntent::McpToolCall {
            agent_id,
            tool_id,
            policy_cell_id,
            action_log_id,
            ..
        } => {
            // Reads: policy cell state (to verify before execution)
            // Writes: policy TOTAL_ACTIONS (commutative Add - no conflict across agents),
            //         policy ACTIONS_MIN (commutative Add),
            //         policy EPOCH_USED (commutative Add),
            //         tool CALL_COUNT (commutative Add),
            //         action log (commutative Append)
            // The tool's own declared_writes will be added by the cell execution layer.
            let reads = vec![
                StorageKey::CellStorage(*policy_cell_id, policy_keys::STATUS),
                StorageKey::CellStorage(*policy_cell_id, policy_keys::ALLOW_WRITES),
                StorageKey::CellStorage(*policy_cell_id, policy_keys::SPEND_EPOCH),
            ];
            let mut writes = vec![
                // These are commutative - multiple agents can log concurrently
                StorageKey::CellStorage(*policy_cell_id, policy_keys::TOTAL_ACTIONS),
                StorageKey::CellStorage(*policy_cell_id, policy_keys::ACTIONS_MIN),
                StorageKey::CellStorage(*tool_id, tool_keys::CALL_COUNT),
            ];
            if let Some(log_id) = action_log_id {
                // Append to action log - commutative, zero conflict
                writes.push(StorageKey::CellStorage(
                    *log_id,
                    registry_keys::blake3_key(b"log:", agent_id),
                ));
            }
            (reads, writes)
        }
    }
}

//
// DIFF COMPUTATION
// These are the state transition functions for each MCP intent.
// They integrate with State::compute_transaction_diff_internal in pq_execution.rs.
//

/// Compute the StateDiff for RegisterMcpTool.
///
/// Creates the tool cell account with:
///   - Axiom bytecode as the implementation
///   - Schema hash, name, category stored in cell storage
///   - Commutative CALL_COUNT key registered so parallel invocations compose
/// Updates McpRegistry storage to include the new tool.
pub fn diff_register_tool(
    state: &impl McpStateView,
    sender: AccountId,
    intent: &McpIntent,
    timestamp: u64,
) -> Result<StateDiff, String> {
    let (
        tool_id,
        bytecode,
        name,
        input_schema_json,
        category,
        declared_reads,
        declared_writes,
        commutative_keys,
        oracle_schema_ids,
        registry_id,
    ) = match intent {
        McpIntent::RegisterMcpTool {
            tool_id,
            bytecode,
            name,
            input_schema_json,
            category,
            declared_reads,
            declared_writes,
            commutative_keys,
            oracle_schema_ids,
            registry_id,
        } => (
            tool_id,
            bytecode,
            name,
            input_schema_json,
            category,
            declared_reads,
            declared_writes,
            commutative_keys,
            oracle_schema_ids,
            registry_id,
        ),
        _ => return Err("Wrong intent".into()),
    };

    if name.len() > 64 {
        return Err("Tool name too long (max 64 bytes)".into());
    }
    if bytecode.is_empty() {
        return Err("Tool bytecode is empty".into());
    }
    if bytecode.len() > gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE) {
        return Err("Tool bytecode exceeds max size".into());
    }
    if bytecode.len() < 4 || &bytecode[0..4] != b"AXIO" {
        return Err("Invalid Axiom bytecode: missing magic bytes".into());
    }
    truthlinked_runtime::cells::CellAccount::verify_manifest_against_bytecode(
        bytecode,
        declared_reads,
        declared_writes,
        &[],
    )?;
    truthlinked_runtime::cells::CellAccount::require_inferable(bytecode, &[])?;

    // Tool cell must not already exist
    if state.cells().cells.contains_key(tool_id) {
        return Err(format!(
            "Tool cell {} already deployed",
            hex::encode(tool_id)
        ));
    }

    // Registry cell must exist
    let registry = state
        .cells()
        .cells
        .get(registry_id)
        .ok_or("McpRegistry cell not found")?;

    // Rent-exempt deposit (refundable on close)
    let rent_deposit = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
    let sender_account = state
        .accounts()
        .get(&sender)
        .ok_or("Sender account not found")?;
    if sender_account.balance < rent_deposit {
        return Err("Insufficient balance for rent deposit".into());
    }

    // Build the tool's initial storage
    let mut tool_storage: HashMap<[u8; 32], [u8; 32]> = HashMap::new();

    // Name: first 32 bytes, padded
    let mut name_bytes = [0u8; 32];
    let n = name.len().min(32);
    name_bytes[..n].copy_from_slice(&name.as_bytes()[..n]);
    tool_storage.insert(tool_keys::NAME, name_bytes);

    // Schema hash
    let schema_hash = *blake3::hash(input_schema_json).as_bytes();
    tool_storage.insert(tool_keys::SCHEMA_HASH, schema_hash);

    // Description hash (schema IS the description for now)
    tool_storage.insert(tool_keys::DESC_HASH, schema_hash);

    // Category
    let mut cat_bytes = [0u8; 32];
    cat_bytes[0] = *category;
    tool_storage.insert(tool_keys::CATEGORY, cat_bytes);

    // Enabled = 1
    let mut enabled = [0u8; 32];
    enabled[0] = 1;
    tool_storage.insert(tool_keys::ENABLED, enabled);

    // Owner = sender
    tool_storage.insert(tool_keys::OWNER, sender);

    // CALL_COUNT = 0 (commutative Add key - registered for zero-conflict parallel logging)
    tool_storage.insert(tool_keys::CALL_COUNT, [0u8; 32]);

    // Compute manifest hash binding bytecode + declared sets
    let manifest_hash = truthlinked_runtime::cells::CellAccount::compute_manifest_hash(
        bytecode,
        declared_reads,
        declared_writes,
        commutative_keys,
        oracle_schema_ids,
    );

    // Build the CellAccount
    let tool_cell = truthlinked_runtime::cells::CellAccount {
        cell_id: *tool_id,
        owner: truthlinked_core::pq_execution::system_authority_id(),
        bytecode: bytecode.clone(),
        storage: tool_storage,
        balance: 0,
        rent_deposit,
        is_token: false,
        token_config: None,
        created_at: timestamp,
        upgraded_at: None,
        last_rent_paid_height: 0,
        rent_grace_blocks: gp::get_u64(gp::PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS),
        pending_owner: None,
        is_immutable: false,
        declared_reads: declared_reads.clone(),
        declared_writes: declared_writes.clone(),
        commutative_keys: commutative_keys.clone(),
        storage_key_specs: vec![],
        oracle_schema_ids: oracle_schema_ids.clone(),
        governance_proposal: None,
        manifest_version: 1,
        manifest_hash,
    };

    // Update the registry: increment TOOL_COUNT and add tool_entry
    let current_count = read_u64_from_storage(registry, &registry_keys::TOOL_COUNT);
    let new_count = current_count.checked_add(1).ok_or("Tool count overflow")?;

    let mut diff = StateDiff::default();

    let mut sender_updated = sender_account.clone();
    sender_updated.balance = sender_updated.balance.saturating_sub(rent_deposit);
    diff.account_updates.insert(sender, sender_updated);

    // Deploy the tool cell
    diff.cell_updates.push(CellUpdate::Deploy {
        cell_id: *tool_id,
        cell: tool_cell,
    });

    // Update registry: TOOL_COUNT
    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *registry_id,
        storage_diff: {
            let mut m = HashMap::new();
            // TOOL_COUNT
            let mut count_bytes = [0u8; 32];
            count_bytes[..8].copy_from_slice(&new_count.to_le_bytes());
            m.insert(registry_keys::TOOL_COUNT, Some(count_bytes));
            // tool_entry(current_count) = tool_id
            m.insert(registry_keys::tool_entry(current_count), Some(*tool_id));
            // name_to_tool(name) = tool_id
            m.insert(registry_keys::name_to_tool(name), Some(*tool_id));
            // increment registry version
            let ver = read_u64_from_storage(registry, &registry_keys::REGISTRY_VER);
            let mut ver_bytes = [0u8; 32];
            ver_bytes[..8].copy_from_slice(&(ver + 1).to_le_bytes());
            m.insert(registry_keys::REGISTRY_VER, Some(ver_bytes));
            m
        },
    });

    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL) as u128;

    Ok(diff)
}

/// Compute the StateDiff for RegisterAgent.
/// Binds agent_id -> (policy_cell_id, owner_id) in the AgentRegistry.
pub fn diff_register_agent(
    state: &impl McpStateView,
    sender: AccountId,
    intent: &McpIntent,
    timestamp: u64,
) -> Result<StateDiff, String> {
    let (agent_id, policy_cell_id, agent_registry_id) = match intent {
        McpIntent::RegisterAgent {
            agent_id,
            policy_cell_id,
            agent_registry_id,
        } => (agent_id, policy_cell_id, agent_registry_id),
        _ => return Err("Wrong intent".into()),
    };

    // Registry must exist
    let registry = state
        .cells()
        .cells
        .get(agent_registry_id)
        .ok_or("AgentRegistry cell not found")?;

    // Policy cell must exist
    if !state.cells().cells.contains_key(policy_cell_id) {
        return Err("Policy cell not found".into());
    }

    // Owner and agent must be different accounts - agent cannot self-register.
    // This ensures the owner can suspend/reinstate even if the agent key is compromised.
    if &sender == agent_id {
        return Err(
            "Agent cannot register itself: owner and agent_id must be different accounts".into(),
        );
    }

    // Agent must not already be registered
    let existing_policy_slot = agent_reg_keys::agent_policy(agent_id);
    if registry.storage.get(&existing_policy_slot) != Some(&[0u8; 32])
        && registry.storage.contains_key(&existing_policy_slot)
    {
        return Err("Agent already registered".into());
    }

    let current_count = read_u64_from_storage(registry, &agent_reg_keys::AGENT_COUNT);
    let new_count = current_count.checked_add(1).ok_or("Agent count overflow")?;

    let mut diff = StateDiff::default();
    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *agent_registry_id,
        storage_diff: {
            let mut m = HashMap::new();
            m.insert(
                agent_reg_keys::agent_policy(agent_id),
                Some(*policy_cell_id),
            );
            m.insert(agent_reg_keys::agent_owner(agent_id), Some(sender));
            m.insert(agent_reg_keys::agent_entry(current_count), Some(*agent_id));
            let mut ts_bytes = [0u8; 32];
            ts_bytes[..8].copy_from_slice(&timestamp.to_le_bytes());
            m.insert(
                agent_reg_keys::agent_registered_at(agent_id),
                Some(ts_bytes),
            );
            let mut count_bytes = [0u8; 32];
            count_bytes[..8].copy_from_slice(&new_count.to_le_bytes());
            m.insert(agent_reg_keys::AGENT_COUNT, Some(count_bytes));
            m
        },
    });

    // Initialize policy cell storage with safe defaults.
    // Without this the policy cell is blank - enforce_mcp_policy reads zeros
    // and the agent has no defined permissions.
    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *policy_cell_id,
        storage_diff: {
            let mut m = HashMap::new();
            // STATUS = 0 (active)
            m.insert(policy_keys::STATUS, Some([0u8; 32]));
            // OWNER = sender
            m.insert(policy_keys::OWNER, Some(sender));
            // ALLOW_READS = 1
            let mut allow_reads = [0u8; 32];
            allow_reads[0] = 1;
            m.insert(policy_keys::ALLOW_READS, Some(allow_reads));
            // ALLOW_WRITES = 1
            let mut allow_writes = [0u8; 32];
            allow_writes[0] = 1;
            m.insert(policy_keys::ALLOW_WRITES, Some(allow_writes));
            // ALLOW_ADMIN = 0
            m.insert(policy_keys::ALLOW_ADMIN, Some([0u8; 32]));
            // RATE_LIMIT = 0 (unlimited)
            m.insert(policy_keys::RATE_LIMIT, Some([0u8; 32]));
            // SPEND_PER_TX = 0 (unlimited)
            m.insert(policy_keys::SPEND_PER_TX, Some([0u8; 32]));
            // SPEND_EPOCH = 0 (unlimited)
            m.insert(policy_keys::SPEND_EPOCH, Some([0u8; 32]));
            // TOTAL_ACTIONS = 0
            m.insert(policy_keys::TOTAL_ACTIONS, Some([0u8; 32]));
            m
        },
    });

    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
    Ok(diff)
}

/// Compute the StateDiff for SuspendAgent / ReinstateAgent.
pub fn diff_set_agent_status(
    state: &impl McpStateView,
    sender: AccountId,
    intent: &McpIntent,
) -> Result<StateDiff, String> {
    let (agent_id, registry_id, new_status, reason) = match intent {
        McpIntent::SuspendAgent {
            agent_id,
            agent_registry_id,
            reason,
        } => (agent_id, agent_registry_id, 1u8, reason.as_str()),
        McpIntent::ReinstateAgent {
            agent_id,
            agent_registry_id,
        } => (agent_id, agent_registry_id, 0u8, ""),
        _ => return Err("Wrong intent".into()),
    };

    let registry = state
        .cells()
        .cells
        .get(registry_id)
        .ok_or("AgentRegistry not found")?;

    // Only the registered owner can suspend/reinstate
    let owner_slot = agent_reg_keys::agent_owner(agent_id);
    let stored_owner = registry
        .storage
        .get(&owner_slot)
        .copied()
        .unwrap_or([0u8; 32]);
    if stored_owner != sender {
        return Err("Only the agent's registered owner can change agent status".into());
    }

    // Get the policy cell for this agent and update its STATUS key
    let policy_id_bytes = registry
        .storage
        .get(&agent_reg_keys::agent_policy(agent_id))
        .copied()
        .ok_or("Agent not registered")?;

    let mut diff = StateDiff::default();

    // Update STATUS in the policy cell
    let mut status_bytes = [0u8; 32];
    status_bytes[0] = new_status;
    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: policy_id_bytes,
        storage_diff: {
            let mut m = HashMap::new();
            m.insert(policy_keys::STATUS, Some(status_bytes));
            if !reason.is_empty() {
                // Store first 32 bytes of reason hash
                let reason_hash = *blake3::hash(reason.as_bytes()).as_bytes();
                m.insert(policy_keys::SUSPEND_REASON, Some(reason_hash));
            }
            m
        },
    });

    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128;
    Ok(diff)
}

/// Compile McpToolCall into a CallCellChain intent.
///
/// This is the key transformation. The McpToolCall intent is NOT a new execution
/// path - it compiles into the existing CallCellChain, which the parallel
/// executor already knows how to handle. The atomicity, rollback, and gas
/// metering are inherited for free.
///
/// Call chain:
///   [0] policy_cell(agent_id, tool_id, calldata_hash, value, timestamp)
///       - Axiom policy logic: check status, rate limit, spend, tool permission
///       - returns 1 byte: 0x01=permit, 0x00=deny
///       - if deny: entire chain reverts
///
///   [1] tool_cell(agent_calldata)
///       - Axiom tool logic: actual computation
///       - return data = tool result
///       - may read/write its declared storage slots
///
///   [2] (optional) action_log_cell(agent_id, tool_id, result_hash)
///       - Axiom log appender: appends to the agent's on-chain action log
///       - uses commutative Append storage key: zero conflict with other agents
///       - uses result from [1] to hash the tool's output
pub fn compile_tool_call_to_chain(intent: &McpIntent) -> Result<TransactionIntent, String> {
    let (
        agent_id,
        tool_id,
        tool_calldata,
        value,
        gas_limit,
        policy_cell_id,
        action_log_id,
        timestamp,
    ) = match intent {
        McpIntent::McpToolCall {
            agent_id,
            tool_id,
            tool_calldata,
            value,
            gas_limit,
            policy_cell_id,
            action_log_id,
            timestamp,
        } => (
            agent_id,
            tool_id,
            tool_calldata,
            value,
            gas_limit,
            policy_cell_id,
            action_log_id,
            timestamp,
        ),
        _ => return Err("Wrong intent type".into()),
    };
    let log_id = action_log_id
        .as_ref()
        .ok_or("McpToolCall requires action_log_id")?;

    let calldata_hash = *blake3::hash(tool_calldata).as_bytes();
    let mut policy_calldata = Vec::with_capacity(120);
    policy_calldata.extend_from_slice(agent_id);
    policy_calldata.extend_from_slice(tool_id);
    policy_calldata.extend_from_slice(&calldata_hash);
    policy_calldata.extend_from_slice(&value.to_le_bytes());
    policy_calldata.extend_from_slice(&timestamp.to_le_bytes());

    let mut calls = vec![
        CellCall {
            cell_id: *policy_cell_id,
            calldata: policy_calldata,
            value: 0,
            use_result_from: None,
        },
        // Step 1: Tool execution
        CellCall {
            cell_id: *tool_id,
            calldata: tool_calldata.clone(),
            value: *value,
            use_result_from: None, // Tool gets direct calldata, not policy result
        },
    ];

    let mut log_calldata = Vec::with_capacity(96);
    log_calldata.extend_from_slice(agent_id);
    log_calldata.extend_from_slice(tool_id);
    log_calldata.extend_from_slice(&timestamp.to_le_bytes());

    calls.push(CellCall {
        cell_id: *log_id,
        calldata: log_calldata,
        value: 0,
        use_result_from: Some(1),
    });

    Ok(TransactionIntent::CallCellChain {
        calls,
        gas_limit: *gas_limit,
    })
}

/// Compute the StateDiff for RegisterMcpResource.
/// Deploys a resource cell and registers it in the McpRegistry.
pub fn diff_register_resource(
    state: &impl McpStateView,
    sender: AccountId,
    intent: &McpIntent,
    timestamp: u64,
) -> Result<StateDiff, String> {
    let (
        resource_id,
        bytecode,
        name,
        uri_scheme,
        mime_type,
        initial_data,
        declared_reads,
        declared_writes,
        oracle_schema_ids,
        registry_id,
    ) = match intent {
        McpIntent::RegisterMcpResource {
            resource_id,
            bytecode,
            name,
            uri_scheme,
            mime_type,
            initial_data,
            declared_reads,
            declared_writes,
            oracle_schema_ids,
            registry_id,
        } => (
            resource_id,
            bytecode,
            name,
            uri_scheme,
            mime_type,
            initial_data,
            declared_reads,
            declared_writes,
            oracle_schema_ids,
            registry_id,
        ),
        _ => return Err("Wrong intent".into()),
    };

    if name.len() > 64 {
        return Err("Resource name too long".into());
    }
    if uri_scheme.len() > 64 {
        return Err("URI scheme too long".into());
    }
    if !bytecode.is_empty() {
        if bytecode.len() > gp::get_usize(gp::PARAM_MAX_CELL_BYTECODE_SIZE) {
            return Err("Resource bytecode exceeds max size".into());
        }
        if bytecode.len() < 4 || &bytecode[0..4] != b"AXIO" {
            return Err("Invalid Axiom bytecode: missing magic bytes".into());
        }
        truthlinked_runtime::cells::CellAccount::verify_manifest_against_bytecode(
            bytecode,
            declared_reads,
            declared_writes,
            &[],
        )?;
        truthlinked_runtime::cells::CellAccount::require_inferable(bytecode, &[])?;
    }

    if state.cells().cells.contains_key(resource_id) {
        return Err(format!(
            "Resource cell {} already deployed",
            hex::encode(resource_id)
        ));
    }

    let registry = state
        .cells()
        .cells
        .get(registry_id)
        .ok_or("McpRegistry cell not found")?;

    // Rent-exempt deposit (refundable on close)
    let rent_deposit = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
    let sender_account = state
        .accounts()
        .get(&sender)
        .ok_or("Sender account not found")?;
    if sender_account.balance < rent_deposit {
        return Err("Insufficient balance for rent deposit".into());
    }

    // Build resource cell storage
    let mut resource_storage: HashMap<[u8; 32], [u8; 32]> = HashMap::new();

    let mut name_bytes = [0u8; 32];
    let n = name.len().min(32);
    name_bytes[..n].copy_from_slice(&name.as_bytes()[..n]);
    resource_storage.insert(resource_keys::NAME, name_bytes);

    let mut uri_bytes = [0u8; 32];
    let u = uri_scheme.len().min(32);
    uri_bytes[..u].copy_from_slice(&uri_scheme.as_bytes()[..u]);
    resource_storage.insert(resource_keys::URI_SCHEME, uri_bytes);

    let mut mime_bytes = [0u8; 32];
    let m = mime_type.len().min(32);
    mime_bytes[..m].copy_from_slice(&mime_type.as_bytes()[..m]);
    resource_storage.insert(resource_keys::MIME_TYPE, mime_bytes);

    // Timestamp
    let mut ts_bytes = [0u8; 32];
    ts_bytes[..8].copy_from_slice(&timestamp.to_le_bytes());
    resource_storage.insert(resource_keys::UPDATED_AT, ts_bytes);

    // Initial data slots
    for (slot_key, content) in initial_data {
        if content.len() > 32 {
            return Err("Resource initial data values must be <= 32 bytes".into());
        }
        let storage_key = resource_keys::data_slot(slot_key);
        let mut value = [0u8; 32];
        let len = content.len().min(32);
        value[..len].copy_from_slice(&content[..len]);
        resource_storage.insert(storage_key, value);
    }

    // Content hash of all initial data combined
    let all_data: Vec<u8> = initial_data
        .iter()
        .flat_map(|(k, v)| {
            let mut combined = k.clone();
            combined.extend_from_slice(v);
            combined
        })
        .collect();
    resource_storage.insert(
        resource_keys::CONTENT_HASH,
        *blake3::hash(&all_data).as_bytes(),
    );

    let manifest_hash = truthlinked_runtime::cells::CellAccount::compute_manifest_hash(
        bytecode,
        declared_reads,
        declared_writes,
        &[],
        oracle_schema_ids,
    );

    let resource_cell = truthlinked_runtime::cells::CellAccount {
        cell_id: *resource_id,
        owner: truthlinked_core::pq_execution::system_authority_id(),
        bytecode: bytecode.clone(),
        storage: resource_storage,
        balance: 0,
        rent_deposit,
        is_token: false,
        token_config: None,
        created_at: timestamp,
        upgraded_at: None,
        last_rent_paid_height: 0,
        rent_grace_blocks: gp::get_u64(gp::PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS),
        pending_owner: None,
        is_immutable: false,
        declared_reads: declared_reads.clone(),
        declared_writes: declared_writes.clone(),
        commutative_keys: vec![],
        storage_key_specs: vec![],
        oracle_schema_ids: oracle_schema_ids.clone(),
        governance_proposal: None,
        manifest_version: 1,
        manifest_hash,
    };

    let current_count = read_u64_from_storage(registry, &registry_keys::RESOURCE_COUNT);
    let new_count = current_count
        .checked_add(1)
        .ok_or("Resource count overflow")?;

    let mut diff = StateDiff::default();

    let mut sender_updated = sender_account.clone();
    sender_updated.balance = sender_updated.balance.saturating_sub(rent_deposit);
    diff.account_updates.insert(sender, sender_updated);

    diff.cell_updates.push(CellUpdate::Deploy {
        cell_id: *resource_id,
        cell: resource_cell,
    });

    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *registry_id,
        storage_diff: {
            let mut m = HashMap::new();
            let mut count_bytes = [0u8; 32];
            count_bytes[..8].copy_from_slice(&new_count.to_le_bytes());
            m.insert(registry_keys::RESOURCE_COUNT, Some(count_bytes));
            m.insert(
                registry_keys::resource_entry(current_count),
                Some(*resource_id),
            );
            m.insert(registry_keys::name_to_resource(name), Some(*resource_id));
            let ver = read_u64_from_storage(registry, &registry_keys::REGISTRY_VER);
            let mut ver_bytes = [0u8; 32];
            ver_bytes[..8].copy_from_slice(&(ver + 1).to_le_bytes());
            m.insert(registry_keys::REGISTRY_VER, Some(ver_bytes));
            m
        },
    });

    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL) as u128;
    Ok(diff)
}

/// Compute the StateDiff for RegisterMcpPrompt.
/// Deploys a prompt cell and registers it in the McpRegistry.
/// Prompts go through the validator name registry for on-chain approval.
pub fn diff_register_prompt(
    state: &impl McpStateView,
    sender: AccountId,
    intent: &McpIntent,
    timestamp: u64,
) -> Result<StateDiff, String> {
    let (prompt_id, name, template_bytes, arguments, registry_id) = match intent {
        McpIntent::RegisterMcpPrompt {
            prompt_id,
            name,
            template_bytes,
            arguments,
            registry_id,
        } => (prompt_id, name, template_bytes, arguments, registry_id),
        _ => return Err("Wrong intent".into()),
    };

    if name.len() > 64 {
        return Err("Prompt name too long".into());
    }
    if arguments.len() > 255 {
        return Err("Too many arguments (max 255)".into());
    }

    if state.cells().cells.contains_key(prompt_id) {
        return Err(format!(
            "Prompt cell {} already deployed",
            hex::encode(prompt_id)
        ));
    }

    let registry = state
        .cells()
        .cells
        .get(registry_id)
        .ok_or("McpRegistry cell not found")?;

    // Rent-exempt deposit (refundable on close)
    let rent_deposit = gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE);
    let sender_account = state
        .accounts()
        .get(&sender)
        .ok_or("Sender account not found")?;
    if sender_account.balance < rent_deposit {
        return Err("Insufficient balance for rent deposit".into());
    }

    let mut prompt_storage: HashMap<[u8; 32], [u8; 32]> = HashMap::new();

    let mut name_bytes = [0u8; 32];
    let n = name.len().min(32);
    name_bytes[..n].copy_from_slice(&name.as_bytes()[..n]);
    prompt_storage.insert(prompt_keys::NAME, name_bytes);

    // Template hash - full template stored off-chain, hash lives on-chain
    let template_hash = *blake3::hash(template_bytes).as_bytes();
    prompt_storage.insert(prompt_keys::TEMPLATE_HASH, template_hash);

    // Argument count
    let mut argc_bytes = [0u8; 32];
    argc_bytes[0] = arguments.len() as u8;
    prompt_storage.insert(prompt_keys::ARG_COUNT, argc_bytes);

    // Each argument name (first 32 bytes)
    for (i, (arg_name, _desc, _required)) in arguments.iter().enumerate() {
        let mut arg_bytes = [0u8; 32];
        let n = arg_name.len().min(32);
        arg_bytes[..n].copy_from_slice(&arg_name.as_bytes()[..n]);
        prompt_storage.insert(prompt_keys::arg_schema(i as u8), arg_bytes);
    }

    // approved_at = 0 (not yet validator-approved - requires name-registry system cell approval)
    prompt_storage.insert(prompt_keys::APPROVED_AT, [0u8; 32]);
    prompt_storage.insert(prompt_keys::USE_COUNT, [0u8; 32]);

    let manifest_hash =
        truthlinked_runtime::cells::CellAccount::compute_manifest_hash(&[], &[], &[], &[], &[]);

    let prompt_cell = truthlinked_runtime::cells::CellAccount {
        cell_id: *prompt_id,
        owner: truthlinked_core::pq_execution::system_authority_id(),
        bytecode: vec![], // Prompts have no executable bytecode - pure storage
        storage: prompt_storage,
        balance: 0,
        rent_deposit,
        is_token: false,
        token_config: None,
        created_at: timestamp,
        upgraded_at: None,
        last_rent_paid_height: 0,
        rent_grace_blocks: gp::get_u64(gp::PARAM_STORAGE_RENT_GRACE_PERIOD_BLOCKS),
        pending_owner: None,
        is_immutable: false,
        declared_reads: vec![],
        declared_writes: vec![],
        commutative_keys: vec![prompt_keys::USE_COUNT], // commutative: agents increment USE_COUNT concurrently
        storage_key_specs: vec![],
        oracle_schema_ids: vec![],
        governance_proposal: None,
        manifest_version: 1,
        manifest_hash,
    };

    let current_count = read_u64_from_storage(registry, &registry_keys::PROMPT_COUNT);
    let new_count = current_count
        .checked_add(1)
        .ok_or("Prompt count overflow")?;

    let mut diff = StateDiff::default();

    let mut sender_updated = sender_account.clone();
    sender_updated.balance = sender_updated.balance.saturating_sub(rent_deposit);
    diff.account_updates.insert(sender, sender_updated);

    diff.cell_updates.push(CellUpdate::Deploy {
        cell_id: *prompt_id,
        cell: prompt_cell,
    });

    diff.cell_updates.push(CellUpdate::StorageChange {
        cell_id: *registry_id,
        storage_diff: {
            let mut m = HashMap::new();
            let mut count_bytes = [0u8; 32];
            count_bytes[..8].copy_from_slice(&new_count.to_le_bytes());
            m.insert(registry_keys::PROMPT_COUNT, Some(count_bytes));
            m.insert(registry_keys::prompt_entry(current_count), Some(*prompt_id));
            m.insert(registry_keys::name_to_prompt(name), Some(*prompt_id));
            let ver = read_u64_from_storage(registry, &registry_keys::REGISTRY_VER);
            let mut ver_bytes = [0u8; 32];
            ver_bytes[..8].copy_from_slice(&(ver + 1).to_le_bytes());
            m.insert(registry_keys::REGISTRY_VER, Some(ver_bytes));
            m
        },
    });

    // NOTE: Prompt is DEPLOYED but NOT YET APPROVED.
    // The deployer must then call the name-registry system cell and wait for validator votes.
    // Only approved prompts appear in prompts/list (filtered by APPROVED_AT != 0).
    diff.cu_fee = gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL) as u128;
    Ok(diff)
}

//
// MCP PROTOCOL TRANSPORT
// This is the ONLY part that is not on-chain. It is the thinnest possible
// wire adapter: JSON-RPC 2.0 over WebSocket. It translates MCP method calls
// into TruthLinked transactions and on-chain storage reads.
// There is NO policy enforcement here. The chain does that.
//

// CHAIN STATE READERS
// These read from cell storage - the chain IS the data source.
//

/// Read all registered tools from McpRegistry storage.
/// Filters to only tools the agent is permitted to call per their policy.
fn is_native_mcp_tool(name: &str) -> bool {
    matches!(
        name,
        "get_chain_info"
            | "get_balance"
            | "get_validators"
            | "get_token_info"
            | "get_cell_info"
            | "get_transaction"
            | "get_staking_info"
            | "get_oracle_result"
            | "get_account_history"
            | "submit_transaction"
            | "http_fetch"
            | "get_sdk"
            | "faucet"
    )
}

pub fn enumerate_tools(
    state: &impl McpStateView,
    registry_id: &AccountId,
    agent_reg_id: &AccountId,
    agent_id: &AccountId,
) -> Vec<serde_json::Value> {
    let registry = match state.cells().cells.get(registry_id) {
        Some(r) => r,
        None => return vec![],
    };

    let tool_count = read_u64_from_storage(registry, &registry_keys::TOOL_COUNT);

    // Get agent's policy cell to filter permitted tools
    let policy_cell = state.cells().cells.get(agent_reg_id).and_then(|ar| {
        let pol_id = ar
            .storage
            .get(&agent_reg_keys::agent_policy(agent_id))
            .copied()?;
        state.cells().cells.get(&pol_id)
    });

    (0..tool_count).filter_map(|i| {
        let tool_id = registry.storage.get(&registry_keys::tool_entry(i)).copied()?;
        let tool = state.cells().cells.get(&tool_id)?;

        // Check if enabled
        let enabled = tool.storage.get(&tool_keys::ENABLED)
            .map(|b| b[0] == 1).unwrap_or(false);
        if !enabled { return None; }

        // Check policy permission for this tool
        if let Some(policy) = policy_cell {
            let perm = policy.storage.get(&policy_keys::tool_permission(&tool_id))
                .map(|b| b[0] == 1)
                .unwrap_or(false);
            // If allow_reads is true and tool is category 0, permit regardless
            let allow_reads = policy.storage.get(&policy_keys::ALLOW_READS)
                .map(|b| b[0] == 1).unwrap_or(false);
            let category = tool.storage.get(&tool_keys::CATEGORY)
                .map(|b| b[0]).unwrap_or(0);
            if !perm && !(allow_reads && category == 0) {
                return None;
            }
        }

        let name_bytes = tool.storage.get(&tool_keys::NAME).copied().unwrap_or([0u8; 32]);
        let name = String::from_utf8_lossy(name_bytes.split(|&b| b == 0).next().unwrap_or(&[]))
            .to_string();

        if !is_native_mcp_tool(&name) {
            return None;
        }

        let builtin_schemas: std::collections::HashMap<&str, serde_json::Value> = [
            ("get_chain_info",      serde_json::json!({"type":"object","properties":{},"required":[]})),
            ("get_balance",         serde_json::json!({"type":"object","properties":{"account_id":{"type":"string","description":"32-byte account ID as hex"}},"required":["account_id"]})),
            ("get_validators",      serde_json::json!({"type":"object","properties":{},"required":[]})),
            ("get_token_info",      serde_json::json!({"type":"object","properties":{},"required":[]})),
            ("get_cell_info",       serde_json::json!({"type":"object","properties":{"cell_id":{"type":"string","description":"32-byte cell ID as hex"}},"required":["cell_id"]})),
            ("get_transaction",     serde_json::json!({"type":"object","properties":{"tx_hash":{"type":"string","description":"32-byte tx hash as hex"}},"required":["tx_hash"]})),
            ("get_staking_info",    serde_json::json!({"type":"object","properties":{},"required":[]})),
            ("get_oracle_result",   serde_json::json!({"type":"object","properties":{"request_id":{"type":"string","description":"32-byte oracle request ID as hex"}},"required":["request_id"]})),
            ("get_account_history", serde_json::json!({"type":"object","properties":{"account_id":{"type":"string"},"limit":{"type":"integer","default":20}},"required":["account_id"]})),
            ("submit_transaction",  serde_json::json!({"type":"object","properties":{"tx_hex":{"type":"string","description":"Hex-encoded bincode-serialized signed Transaction"}},"required":["tx_hex"]})),
            ("http_fetch",          serde_json::json!({"type":"object","properties":{"url":{"type":"string"},"cell_id":{"type":"string","description":"Cell that will consume the result (64-char hex)"}},"required":["url","cell_id"]})),
            ("get_sdk",             serde_json::json!({"type":"object","properties":{},"required":[]})),
            ("faucet",              serde_json::json!({"type":"object","properties":{"account_id":{"type":"string","description":"Your 64-char hex account ID"},"pubkey":{"type":"string","description":"Your ML-DSA public key hex"}},"required":["account_id","pubkey"]})),
        ].into_iter().collect();

        let builtin_descs: std::collections::HashMap<&str, &str> = [
            ("get_chain_info",      "Get current chain height, genesis hash, finalized height, and network info."),
            ("get_balance",         "Get TLKD balance for an account. Input: account_id as 64-char hex."),
            ("get_validators",      "List all active validators with stake and status."),
            ("get_token_info",      "Get TLKD token metadata: name, symbol, decimals, total supply."),
            ("get_cell_info",       "Get cell account info by cell_id as 64-char hex."),
            ("get_transaction",     "Get transaction details by tx_hash as 64-char hex."),
            ("get_staking_info",    "Get staking state: total staked, validator count, epoch info."),
            ("get_oracle_result",   "Poll the result of an oracle HTTP fetch by request_id."),
            ("get_account_history", "Get recent transaction history for an account."),
            ("submit_transaction",  "Submit a pre-signed transaction (hex-encoded bincode). Returns tx_hash."),
            ("http_fetch",          "Queue an oracle HTTP GET. Validators fetch and commit-reveal the response. Returns request_id."),
            ("get_sdk",              "Get Axiom CLI build and usage instructions. Axiom CLI generates ML-DSA-65 keypairs, signs transactions, and submits them to TruthLinked."),
            ("faucet",               "Claim testnet TLKD tokens with Axiom CLI. Run axiom account-create first, then axiom faucet --from mykeys.json. 12-hour cooldown per account."),
        ].into_iter().collect();

        let input_schema = builtin_schemas.get(name.as_str())
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type":"object"}));
        let description = builtin_descs.get(name.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("On-chain tool cell {}.", &hex::encode(tool_id)[..8]));

        Some(serde_json::json!({
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "_meta": {
                "cell_id": hex::encode(tool_id),
                "category": tool.storage.get(&tool_keys::CATEGORY).map(|b| b[0]).unwrap_or(0),
                "manifest_version": tool.manifest_version,
                "manifest_hash": hex::encode(tool.manifest_hash),
                "call_count": read_u64_from_storage(tool, &tool_keys::CALL_COUNT)
            }
        }))
    }).collect()
}

pub fn enumerate_resources(
    state: &impl McpStateView,
    registry_id: &AccountId,
) -> Vec<serde_json::Value> {
    let registry = match state.cells().cells.get(registry_id) {
        Some(r) => r,
        None => return vec![],
    };

    let count = read_u64_from_storage(registry, &registry_keys::RESOURCE_COUNT);

    (0..count).filter_map(|i| {
        let res_id = registry.storage.get(&registry_keys::resource_entry(i)).copied()?;
        let res = state.cells().cells.get(&res_id)?;

        let name_bytes = res.storage.get(&resource_keys::NAME).copied().unwrap_or([0u8; 32]);
        let name = utf8_from_padded(&name_bytes);

        let uri_bytes = res.storage.get(&resource_keys::URI_SCHEME).copied().unwrap_or([0u8; 32]);
        let uri_scheme = utf8_from_padded(&uri_bytes);

        let mime_bytes = res.storage.get(&resource_keys::MIME_TYPE).copied().unwrap_or([0u8; 32]);
        let mime = utf8_from_padded(&mime_bytes);

        Some(serde_json::json!({
            "uri": format!("trth://{}", hex::encode(res_id)),
            "name": name,
            "description": format!("On-chain resource cell. URI scheme: {}. Manifest v{}.", uri_scheme, res.manifest_version),
            "mimeType": mime
        }))
    }).collect()
}

pub fn enumerate_prompts(
    state: &impl McpStateView,
    registry_id: &AccountId,
) -> Vec<serde_json::Value> {
    let registry = match state.cells().cells.get(registry_id) {
        Some(r) => r,
        None => return vec![],
    };

    let count = read_u64_from_storage(registry, &registry_keys::PROMPT_COUNT);

    (0..count).filter_map(|i| {
        let prompt_id = registry.storage.get(&registry_keys::prompt_entry(i)).copied()?;
        let prompt = state.cells().cells.get(&prompt_id)?;

        let approved_at = read_u64_from_storage(prompt, &prompt_keys::APPROVED_AT);
        if approved_at == 0 {
            return None;
        }

        let name_bytes = prompt.storage.get(&prompt_keys::NAME).copied().unwrap_or([0u8; 32]);
        let name = utf8_from_padded(&name_bytes);

        let arg_count = prompt.storage.get(&prompt_keys::ARG_COUNT)
            .map(|b| b[0] as u8).unwrap_or(0);

        let arguments: Vec<serde_json::Value> = (0..arg_count).map(|j| {
            let arg_bytes = prompt.storage.get(&prompt_keys::arg_schema(j))
                .copied().unwrap_or([0u8; 32]);
            serde_json::json!({
                "name": utf8_from_padded(&arg_bytes),
                "required": true
            })
        }).collect();

        Some(serde_json::json!({
            "name": name,
            "description": format!("On-chain prompt cell {}. Validator-approved. Manifest v{}.", &hex::encode(prompt_id)[..8], prompt.manifest_version),
            "arguments": arguments,
            "_meta": {
                "cell_id": hex::encode(prompt_id),
                "manifest_hash": hex::encode(prompt.manifest_hash),
                "use_count": read_u64_from_storage(prompt, &prompt_keys::USE_COUNT)
            }
        }))
    }).collect()
}

pub fn read_resource(state: &impl McpStateView, registry_id: &AccountId, uri: &str) -> String {
    // URI format: trth://<64-hex-cell-id>
    //             trth://<64-hex-cell-id>/<slot-key-hex>
    //             trth://name/<resource-name>/<slot-key-hex>
    let path = uri.trim_start_matches("trth://");
    let parts: Vec<&str> = path.splitn(3, '/').collect();

    let (cell_id_hex, slot_key_opt) = match parts.as_slice() {
        [cid] => (*cid, None),
        [cid, slot] => (*cid, Some(*slot)),
        ["name", name, slot] => {
            // Look up by name via registry
            if let Some(registry) = state.cells().cells.get(registry_id) {
                let res_id_bytes = registry.storage.get(&registry_keys::name_to_resource(name));
                if let Some(id_bytes) = res_id_bytes {
                    return read_resource(
                        state,
                        registry_id,
                        &format!("trth://{}/{}", hex::encode(id_bytes), slot),
                    );
                }
            }
            return serde_json::json!({ "error": "Resource name not found" }).to_string();
        }
        _ => return serde_json::json!({ "error": "Invalid URI format" }).to_string(),
    };

    let cell_id_bytes = match hex::decode(cell_id_hex) {
        Ok(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        }
        _ => return serde_json::json!({ "error": "Invalid cell ID in URI" }).to_string(),
    };

    let cell = match state.cells().cells.get(&cell_id_bytes) {
        Some(c) => c,
        None => return serde_json::json!({ "error": "Resource cell not found" }).to_string(),
    };

    if let Some(slot_hex) = slot_key_opt {
        let slot_bytes = match hex::decode(slot_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            Ok(b) => resource_keys::data_slot(&b),
            _ => return serde_json::json!({ "error": "Invalid slot key" }).to_string(),
        };

        let value = cell
            .storage
            .get(&slot_bytes)
            .map(|v| hex::encode(v))
            .unwrap_or_else(|| {
                "0000000000000000000000000000000000000000000000000000000000000000".into()
            });

        serde_json::json!({
            "cell_id": hex::encode(cell_id_bytes),
            "slot_key": hex::encode(slot_bytes),
            "value": value,
            "manifest_version": cell.manifest_version
        })
        .to_string()
    } else {
        // Read all storage (up to 256 slots - do not dump unbounded state)
        let slots: HashMap<String, String> = cell
            .storage
            .iter()
            .take(256)
            .map(|(k, v)| (hex::encode(k), hex::encode(v)))
            .collect();

        serde_json::json!({
            "cell_id":     hex::encode(cell_id_bytes),
            "manifest_version": cell.manifest_version,
            "manifest_hash":   hex::encode(cell.manifest_hash),
            "storage_slots":   slots.len(),
            "storage":         slots
        })
        .to_string()
    }
}

pub fn get_prompt(
    state: &impl McpStateView,
    registry_id: &AccountId,
    name: &str,
) -> Option<serde_json::Value> {
    let registry = state.cells().cells.get(registry_id)?;
    let prompt_id = registry
        .storage
        .get(&registry_keys::name_to_prompt(name))
        .copied()?;
    let prompt = state.cells().cells.get(&prompt_id)?;

    let template_hash = prompt
        .storage
        .get(&prompt_keys::TEMPLATE_HASH)
        .map(hex::encode)
        .unwrap_or_default();

    let template_preview = if template_hash.len() >= 8 {
        &template_hash[..8]
    } else {
        &template_hash
    };

    Some(serde_json::json!({
        "messages": [{
            "role": "user",
            "content": {
                "type": "text",
                "text": format!(
                    "On-chain prompt '{}'. Template hash: {}. Fetch full template via: resources/read trth://{}/template",
                    name, template_preview, hex::encode(prompt_id)
                )
            }
        }],
        "_meta": {
            "cell_id":  hex::encode(prompt_id),
            "template_hash": template_hash,
            "manifest_version": prompt.manifest_version,
            "manifest_hash": hex::encode(prompt.manifest_hash)
        }
    }))
}

//
// CHAIN GENESIS HELPERS
// Called during chain genesis to deploy the protocol cells.
//

/// Canonical MCP protocol cell addresses (well-known, deterministic)
pub mod protocol_addresses {
    /// blake3("truthlinked:mcp:registry:v1")[..32]
    pub fn mcp_registry() -> [u8; 32] {
        *blake3::hash(b"truthlinked:mcp:registry:v1").as_bytes()
    }
    /// blake3("truthlinked:mcp:agent_registry:v1")[..32]
    pub fn agent_registry() -> [u8; 32] {
        *blake3::hash(b"truthlinked:mcp:agent_registry:v1").as_bytes()
    }
    /// blake3("truthlinked:mcp:action_log:v1")[..32]
    pub fn action_log() -> [u8; 32] {
        *blake3::hash(b"truthlinked:mcp:action_log:v1").as_bytes()
    }
}

/// Deploy all MCP protocol cells at genesis.
/// This is called from genesis.rs during chain initialization.
pub fn deploy_mcp_genesis_cells(
    cell_state: &mut CellState,
    genesis_authority: AccountId,
    timestamp: u64,
) -> Result<(), String> {
    // McpRegistry: no bytecode - pure storage cell, governed by chain rules
    cell_state.deploy_cell(
        protocol_addresses::mcp_registry(),
        genesis_authority,
        vec![], // No bytecode needed - storage is read directly by the transport
        {
            let mut m = HashMap::new();
            let zero = [0u8; 32];
            m.insert(registry_keys::TOOL_COUNT, zero);
            m.insert(registry_keys::RESOURCE_COUNT, zero);
            m.insert(registry_keys::PROMPT_COUNT, zero);
            m.insert(registry_keys::REGISTRY_VER, zero);
            m
        },
        0,
        timestamp,
        vec![
            registry_keys::TOOL_COUNT,
            registry_keys::RESOURCE_COUNT,
            registry_keys::PROMPT_COUNT,
        ],
        vec![
            registry_keys::TOOL_COUNT,
            registry_keys::RESOURCE_COUNT,
            registry_keys::PROMPT_COUNT,
            registry_keys::REGISTRY_VER,
        ],
        vec![], // No commutative keys - registry writes are serialized
        Vec::new(),
        Vec::new(),
    )?;

    // AgentRegistry
    cell_state.deploy_cell(
        protocol_addresses::agent_registry(),
        genesis_authority,
        vec![],
        {
            let mut m = HashMap::new();
            m.insert(agent_reg_keys::AGENT_COUNT, [0u8; 32]);
            m
        },
        0,
        timestamp,
        vec![],
        vec![agent_reg_keys::AGENT_COUNT],
        vec![],
        Vec::new(),
        Vec::new(),
    )?;

    // ActionLog: commutative Append per agent - zero conflict across agents
    cell_state.deploy_cell(
        protocol_addresses::action_log(),
        genesis_authority,
        vec![],
        HashMap::new(),
        0,
        timestamp,
        vec![],
        vec![],
        // Every agent's log slot is commutative
        vec![], // Populated dynamically as agents register
        Vec::new(),
        Vec::new(),
    )?;

    // Register built-in read-only tools (no bytecode - transport handles natively)
    let builtin_tools: &[(&str, &str, u8, &str)] = &[
        ("get_chain_info",        "Get current chain height, genesis hash, finalized height, and network info.", 0,
         r#"{"type":"object","properties":{},"required":[]}"#),
        ("get_balance",           "Get TLKD balance for an account. Input: account_id as 64-char hex.", 0,
         r#"{"type":"object","properties":{"account_id":{"type":"string","description":"32-byte account ID as hex"}},"required":["account_id"]}"#),
        ("get_validators",        "List all active validators with stake and status.", 0,
         r#"{"type":"object","properties":{},"required":[]}"#),
        ("get_token_info",        "Get TLKD token metadata: name, symbol, decimals, total supply.", 0,
         r#"{"type":"object","properties":{},"required":[]}"#),
        ("get_cell_info",         "Get cell account info by cell_id as 64-char hex.", 0,
         r#"{"type":"object","properties":{"cell_id":{"type":"string","description":"32-byte cell ID as hex"}},"required":["cell_id"]}"#),
        ("get_transaction",       "Get transaction details by tx_hash as 64-char hex.", 0,
         r#"{"type":"object","properties":{"tx_hash":{"type":"string","description":"32-byte tx hash as hex"}},"required":["tx_hash"]}"#),
        ("get_staking_info",      "Get staking state: total staked, validator count, epoch info.", 0,
         r#"{"type":"object","properties":{},"required":[]}"#),
        ("get_oracle_result",     "Poll the result of an oracle HTTP fetch by request_id.", 0,
         r#"{"type":"object","properties":{"request_id":{"type":"string","description":"32-byte oracle request ID as hex"}},"required":["request_id"]}"#),
        ("get_account_history",   "Get recent transaction history for an account.", 0,
         r#"{"type":"object","properties":{"account_id":{"type":"string"},"limit":{"type":"integer","default":20}},"required":["account_id"]}"#),
        ("submit_transaction",    "Submit a pre-signed transaction (hex-encoded bincode). Returns tx_hash.", 1,
         r#"{"type":"object","properties":{"tx_hex":{"type":"string","description":"Hex-encoded bincode-serialized signed Transaction"}},"required":["tx_hex"]}"#),
        ("http_fetch",            "Queue an oracle HTTP GET request. Validators fetch and commit-reveal the response. Returns request_id to poll with get_oracle_result.", 1,
         r#"{"type":"object","properties":{"url":{"type":"string","description":"URL to fetch"},"cell_id":{"type":"string","description":"Cell that will consume the result (64-char hex)"}},"required":["url","cell_id"]}"#),
        ("get_sdk",               "Get Axiom CLI build and usage instructions. Axiom CLI generates ML-DSA-65 keypairs and signs transactions.", 0,
         r#"{"type":"object","properties":{},"required":[]}"#),
        ("faucet",                "Claim testnet TLKD tokens. Requires account_id and pubkey from axiom account-create. 12-hour cooldown per account.", 0,
         r#"{"type":"object","properties":{"account_id":{"type":"string","description":"Your 64-char hex account ID"},"pubkey":{"type":"string","description":"Your Dilithium public key hex"}},"required":["account_id","pubkey"]}"#),
    ];

    let registry_id = protocol_addresses::mcp_registry();

    for (i, (name, _desc, category, schema_json)) in builtin_tools.iter().enumerate() {
        let tool_id =
            *blake3::hash(format!("truthlinked:mcp:builtin:{}", name).as_bytes()).as_bytes();

        let schema_hash = *blake3::hash(schema_json.as_bytes()).as_bytes();
        let mut name_bytes = [0u8; 32];
        let n = name.len().min(32);
        name_bytes[..n].copy_from_slice(&name.as_bytes()[..n]);

        let mut cat_bytes = [0u8; 32];
        cat_bytes[0] = *category;
        let mut enabled = [0u8; 32];
        enabled[0] = 1;
        let mut count_bytes = [0u8; 32];
        count_bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());

        let mut tool_storage = HashMap::new();
        tool_storage.insert(tool_keys::NAME, name_bytes);
        tool_storage.insert(tool_keys::SCHEMA_HASH, schema_hash);
        tool_storage.insert(tool_keys::DESC_HASH, schema_hash);
        tool_storage.insert(tool_keys::CATEGORY, cat_bytes);
        tool_storage.insert(tool_keys::ENABLED, enabled);
        tool_storage.insert(tool_keys::OWNER, genesis_authority);
        tool_storage.insert(tool_keys::CALL_COUNT, [0u8; 32]);

        cell_state.deploy_cell(
            tool_id,
            genesis_authority,
            vec![], // no bytecode - transport handles natively
            tool_storage,
            0,
            timestamp,
            vec![],
            vec![tool_keys::CALL_COUNT],
            vec![tool_keys::CALL_COUNT], // commutative - parallel calls do not conflict
            Vec::new(),
            Vec::new(),
        )?;

        // Register in McpRegistry storage
        let idx = i as u64;
        let mut new_count = [0u8; 32];
        new_count[..8].copy_from_slice(&(idx + 1).to_le_bytes());
        let mut ver_bytes = [0u8; 32];
        ver_bytes[..8].copy_from_slice(&(idx + 1).to_le_bytes());

        let registry = cell_state
            .cells
            .get_mut(&registry_id)
            .ok_or("McpRegistry cell missing")?;
        registry
            .storage
            .insert(registry_keys::tool_entry(idx), tool_id);
        registry
            .storage
            .insert(registry_keys::name_to_tool(name), tool_id);
        registry
            .storage
            .insert(registry_keys::TOOL_COUNT, new_count);
        registry
            .storage
            .insert(registry_keys::REGISTRY_VER, ver_bytes);
    }

    tracing::info!(
        " MCP protocol cells deployed: registry={} agent_reg={} action_log={} builtin_tools={}",
        hex::encode(protocol_addresses::mcp_registry()),
        hex::encode(protocol_addresses::agent_registry()),
        hex::encode(protocol_addresses::action_log()),
        builtin_tools.len(),
    );

    Ok(())
}

//
// UTILITIES
//

fn read_u64_from_storage(cell: &CellAccount, key: &[u8; 32]) -> u64 {
    cell.storage
        .get(key)
        .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0u8; 8])))
        .unwrap_or(0)
}

fn utf8_from_padded(bytes: &[u8; 32]) -> String {
    String::from_utf8_lossy(bytes.split(|&b| b == 0).next().unwrap_or(&[])).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestState {
        cells: CellState,
        accounts: ImHashMap<AccountId, AccountRecord>,
        params: ImHashMap<[u8; 32], [u8; 32]>,
    }

    impl McpStateView for TestState {
        fn cells(&self) -> &CellState {
            &self.cells
        }

        fn accounts(&self) -> &ImHashMap<AccountId, AccountRecord> {
            &self.accounts
        }
    }

    impl truthlinked_governance::params::ParamState for TestState {
        fn params(&self) -> &ImHashMap<[u8; 32], [u8; 32]> {
            &self.params
        }

        fn params_mut(&mut self) -> &mut ImHashMap<[u8; 32], [u8; 32]> {
            &mut self.params
        }
    }

    fn setup_state_with_registry() -> TestState {
        let mut state = TestState {
            cells: CellState::new(),
            accounts: ImHashMap::new(),
            params: ImHashMap::new(),
        };
        truthlinked_governance::params::insert_genesis_params(&mut state);
        truthlinked_governance::params::rehydrate_from_state(&state);

        let genesis_authority = [1u8; 32];
        deploy_mcp_genesis_cells(&mut state.cells, genesis_authority, 0).unwrap();
        assert!(
            truthlinked_governance::params::get_param_by_key(
                &truthlinked_governance::params::param_key(
                    truthlinked_governance::params::PARAM_MAX_CELL_BYTECODE_SIZE,
                )
            )
            .is_some(),
            "MCP tests require max cell bytecode genesis param"
        );
        state
    }

    #[test]
    fn register_tool_rejects_invalid_bytecode() {
        let mut state = setup_state_with_registry();
        state.accounts.insert(
            [9u8; 32],
            AccountRecord {
                pubkey_bytes: vec![],
                balance: gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE) * 2,
                compute_escrow_tlkd: 0,
                nonce: 0,
                nfts: vec![],
            },
        );
        let intent = McpIntent::RegisterMcpTool {
            tool_id: [2u8; 32],
            bytecode: vec![1, 2, 3], // invalid Axiom bytecode
            name: "tool".into(),
            input_schema_json: b"{}".to_vec(),
            category: 0,
            declared_reads: vec![],
            declared_writes: vec![],
            commutative_keys: vec![],
            oracle_schema_ids: vec![],
            registry_id: protocol_addresses::mcp_registry(),
        };
        let err = diff_register_tool(&state, [9u8; 32], &intent, 0).unwrap_err();
        assert!(
            err.contains("Invalid Axiom bytecode") || err.contains("Invalid bytecode"),
            "got: {err}"
        );
    }

    #[test]
    fn enumerate_tools_hides_custom_registered_tools() {
        let mut state = setup_state_with_registry();
        let registry_id = protocol_addresses::mcp_registry();
        let custom_tool_id = [7u8; 32];

        let mut name_bytes = [0u8; 32];
        name_bytes[.."custom-tool".len()].copy_from_slice(b"custom-tool");
        let mut category = [0u8; 32];
        category[0] = 1;
        let mut enabled = [0u8; 32];
        enabled[0] = 1;
        let mut storage = HashMap::new();
        storage.insert(tool_keys::NAME, name_bytes);
        storage.insert(tool_keys::CATEGORY, category);
        storage.insert(tool_keys::ENABLED, enabled);
        storage.insert(tool_keys::SCHEMA_HASH, [0u8; 32]);
        storage.insert(tool_keys::DESC_HASH, [0u8; 32]);
        storage.insert(tool_keys::OWNER, [1u8; 32]);
        storage.insert(tool_keys::CALL_COUNT, [0u8; 32]);

        state
            .cells
            .deploy_cell(
                custom_tool_id,
                [1u8; 32],
                vec![],
                storage,
                0,
                0,
                vec![],
                vec![tool_keys::CALL_COUNT],
                vec![tool_keys::CALL_COUNT],
                Vec::new(),
                Vec::new(),
            )
            .unwrap();

        let registry = state.cells.cells.get_mut(&registry_id).unwrap();
        let count = read_u64_from_storage(registry, &registry_keys::TOOL_COUNT);
        registry
            .storage
            .insert(registry_keys::tool_entry(count), custom_tool_id);
        let mut new_count = [0u8; 32];
        new_count[..8].copy_from_slice(&(count + 1).to_le_bytes());
        registry
            .storage
            .insert(registry_keys::TOOL_COUNT, new_count);

        let tools = enumerate_tools(
            &state,
            &registry_id,
            &protocol_addresses::agent_registry(),
            &[0u8; 32],
        );
        assert!(tools
            .iter()
            .any(|tool| tool.get("name").and_then(|v| v.as_str()) == Some("get_chain_info")));
        assert!(!tools
            .iter()
            .any(|tool| tool.get("name").and_then(|v| v.as_str()) == Some("custom-tool")));
    }

    #[test]
    fn register_resource_rejects_large_initial_data() {
        let mut state = setup_state_with_registry();
        state.accounts.insert(
            [9u8; 32],
            AccountRecord {
                pubkey_bytes: vec![],
                balance: gp::get_u128(gp::PARAM_STORAGE_RENT_LIFETIME_FEE) * 2,
                compute_escrow_tlkd: 0,
                nonce: 0,
                nfts: vec![],
            },
        );
        let intent = McpIntent::RegisterMcpResource {
            resource_id: [3u8; 32],
            bytecode: vec![],
            name: "res".into(),
            uri_scheme: "trth".into(),
            mime_type: "application/json".into(),
            initial_data: vec![(b"slot".to_vec(), vec![0u8; 33])],
            declared_reads: vec![],
            declared_writes: vec![],
            oracle_schema_ids: vec![],
            registry_id: protocol_addresses::mcp_registry(),
        };
        let err = diff_register_resource(&state, [9u8; 32], &intent, 0).unwrap_err();
        assert!(err.contains("<= 32 bytes"));
    }
}
