//! Truthlinked Consensus Src Genesis
//!
//! Owns genesis state construction and boot-time validation.
//! Consensus changes are protocol-critical; preserve deterministic replay, recovery safety, and wire compatibility.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use truthlinked_core::cells::StorageKeySpec;
use truthlinked_core::constants::ONE_TLKD;
use truthlinked_core::constants::STORAGE_RENT_GRACE_PERIOD_BLOCKS;
use truthlinked_core::pq_execution::{system_authority_id, treasury_system_cell_id};
use truthlinked_core::pq_identity::{account_id_from_pubkey, DualKeypair};
use truthlinked_runtime::cells::CellAccount;
use truthlinked_runtime::types::AccountRecord;
use truthlinked_state::constants::TOTAL_SUPPLY;
use truthlinked_state::State;

const FOUNDATION_MINT_PUBKEY_HEX: &str = "cc3e65bd89c24875f2bcf3ef14d34ecea14404ca79565ce237ebf45005a22bcda4a75dd99c2fdedcf5cb108105c790aa27e9174afe8e49e122a826d6b2ab457ae9f4f784b41f4d3afadb88dfb26ead96e1caf8b6c5442f7d94ac9d2c96894a7033ac447ce635ed9cfef4765ead4df7513dfd976341a37c9e3de2d18d581abac831adbec7e5277a5f45efeb5e9761a3288d08af1f571722f0f928bd8c495f59f69774297b89d7ddce10fd4bdc5495d2c3e297e7c170b36bf206a6de1e6e0787b86695b7f3683eb9bd808244256a1e8e41aebd341f10b5d83e21aaa11e28fdd7cd7073d1aa8f3c454acfc82152d1f651923b27c222ea9cedaadb0e19d424d1f83e216265fc90613d5981ccd3adc2d50e2825dc2a42c3f713c8018294910282a8b508c2381fb456acb7a3262528e63dff1a7c741fd6e1d515a89226705a2b2b25a00cd9d24cb5b362523c439e48b3516d09fe3465129d5e181a9958babd167aad0af3ee971967979804102b9969f1124ed288003c2ceeec18bfe0c2e97c2b5288d28a86b2c72d8bb79bfca95d4147333637c5e52aacc2ee0342a02b6bd2f8ed6b3970ed977010265e8adbd750da34ef6efb255d98174e42cfbbd37cf167fbcffcf3a94e60311f5b8cb4038ffa5634fb180fd18752c24f8b5388a2cfbae1751e28f0274d02fe7120cd9e74e7760761dde46bd7d3f66d23246cb01127e8499b1d9652ffb6e1becabaa7a773900162699d8315bca40e2bdabe157fa38938bb7350bfdc9f314d501437b87e1a81eb6e99201f9bcb5a67e39210940b9fc86a60ca6ee9a67dd771b2eb62f4ab2e4b48ab46946fe2c205a35ceb6159ac5c3f089d28f34bb5c4a835da7e36a18059034fecc341d04a6bb5e1d64d001eceba0b5a98f5c04a47e7a4e8a489429677141d1276156b853ac8bbdb7b35fd01592101f507c28569f052541d5421bc5fdedfcd978d4be7fc3faa3e6fcf9e5b458d53fb5fd4d8ed229085725e551c7bbfafe0068cc23d68a119854952b2883a1d4c8110a11f3f9f2c77e5f6a8b6f7f83ddfb745d5cb6ca84def1caf77d8cf5f78583850010a1bc1cc3044e82effe42caa9d6ca3395872e0254fef1947c8e2a74454ede3e93a3f12741d4a14514745b8f40f51d05c43e85e8542b41e5977f947bc4d4ff57e1ee687a674cfd5a1a1154d11e0c406857d802d096ef46bd8fb535cde8a97e8a6fa71658be9a9489e936bd3c8e9f5a21548aa0f71659a2e2a577d7b9351ee55642c2dcad5eed9c1f2d5051f17d9daa5adabd287de2a0a29d8c8343921a6a3d94c5e190c773f410fc51091c496eb4c7905ffbaaf942195cb9c60183a5602413ef4abeeb36258d0f1a3caa1b3516c8bdef2c5c6e3b7ab7b87f45c7994136c832e3c7e7590edb227bb9100d96ee05410a27eca7e398a92e601a435fc82450e9bb7b215b21db37a1fad8adf9614c6dfe474ae5118b0e69faf22fc78e63a362308644ae03b648a62e7991e9f56177c508f67c4a70cd0a783886afbec6869fcd734bce51c66134e831df369c70f6b8514b9a01d930010fcb946cc9217534ae86b038d53d7b67bf524835cb868aaf44f2e97f1394c462295863be3795ddf46b4e3b1b9971ecb8eabe58095b50614704bb804203e15dc981ef67cd6f14858d2d97ea175f3ff5cf7d910a045825c8e9eb4d7924bfb91b5bf770a18fd3cfb01d6e01e84c7960964b546e692b5d1568b57f5a1a7085c60cdab8575ae4ce23b12749e9c3e9a6bc3068735121ae1048306f10319cb676c3fa7e8e19dd66defd2878dd2f02b4823628e761169079b4a1b0e9b28f9874d1747a7a3bead82310475278994882fc638287a943939d2632e07f68bb528fdd437c33254c6fbc8f0702cc602eace460bee121561f57e7c775f434728a72c9a4958f4cea69d2dfc4ab2a7b0632eba06532b09590883732588bd055372822d711c81da7aca714991d1994225f6ee75bd400956c4f66ab26665127dc30c205693fc2ded471447bbc0260258783a433d50a014adbe3b78d6b4afc9204f4e4dbca85fe06801ed7f9f8a31a465fdc3fa0060e80b2c9179da5463285368ed5374a79e39b3add06c4c8af310a9b80358189895b20e4f7a4c7e701ba32a6f580e0b60aaf70771716fffb84a176a268135e8ddee2f477a23a47dabeba9067dbb20b59adc59ec0e0e648e31238a66f737e0d87d0a2acf6f92587e22f703de242ed9399b347659d80cf1b6fae4d0f54004ef4832b7d127b7d055785fe5652980f6f2e28b104668213b65063bc341ba92824a40a0c64826b0f58257a900b78f4c2959abacd5969f5353648ed7835012c13bed9d7b9c9f9c6008f44c7c1eeef14f0654f6f0cf76dec9b85a0d6534f8d86b1e89718cb851174857e71da21d2b5c849f7888a16c60df8c6e339325302ef16c6008b405a1f88dfcba72fe239010485e95cce74c9d50a07fe0983dab626935a3ca3921da0036acf21a08f6226e59feecc0089bf1bad7d53e984a4c7d26df645a3ccb0b33a1e61e5408ba1e7e4e86386db261bef8ec58d07499bce4e465310ef2d3701699c68c4142156ecfaabef3f13bcb39ae7627ac1f44f526136411ecffa9d05f639cbaa4e1e366eea8d3032612c7b2fb75e33af5b4828d682347d0a912ca1ca0d66abde1ca06f247ba182f85d6a2eddf1fca4d7f21a2399a2831dc085fd0ed3140b6a10eb13affb4eeac31b01640c3b4c1976f99bcabc15d36afe4cf25fa5506ba31da9d8dad73fd7358";
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub keys_file: String,
    pub allocation: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub validators: Vec<GenesisValidator>,
    pub foundation_mint_pubkey: Option<String>,
    pub genesis_timestamp: u64,
    pub network: String, // "mainnet", "testnet", or "devnet"
}

impl GenesisConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read genesis config: {}", e))?;
        serde_json::from_str(&json).map_err(|e| format!("Failed to parse genesis config: {}", e))
    }

    pub fn mainnet() -> Self {
        Self {
            validators: vec![],
            foundation_mint_pubkey: None,
            genesis_timestamp: 1800000000, // Jun 14, 2027 00:00:00 UTC (future mainnet launch)
            network: "mainnet".to_string(),
        }
    }

    pub fn testnet() -> Self {
        Self {
            validators: vec![
                GenesisValidator {
                    keys_file: "validator1_keys.json".to_string(),
                    allocation: 100_000 * ONE_TLKD,
                },
                GenesisValidator {
                    keys_file: "validator2_keys.json".to_string(),
                    allocation: 100_000 * ONE_TLKD,
                },
                GenesisValidator {
                    keys_file: "validator3_keys.json".to_string(),
                    allocation: 100_000 * ONE_TLKD,
                },
            ],
            foundation_mint_pubkey: None,
            genesis_timestamp: 1735689600, // Jan 1, 2025 00:00:00 UTC
            network: "testnet".to_string(),
        }
    }

    pub fn devnet() -> Self {
        Self {
            validators: vec![
                GenesisValidator {
                    keys_file: "validator1_keys.json".to_string(),
                    allocation: 50_000 * ONE_TLKD,
                },
                GenesisValidator {
                    keys_file: "validator2_keys.json".to_string(),
                    allocation: 70_000 * ONE_TLKD,
                },
                GenesisValidator {
                    keys_file: "validator3_keys.json".to_string(),
                    allocation: 80_000 * ONE_TLKD,
                },
            ],
            foundation_mint_pubkey: None,
            genesis_timestamp: 1704067200, // Jan 1, 2024 00:00:00 UTC
            network: "devnet".to_string(),
        }
    }

    pub fn default_devnet() -> Self {
        Self::devnet()
    }
}

pub fn initialize_genesis(state: &mut State, config: &GenesisConfig) {
    use fips204::traits::SerDes;

    tracing::info!("═══════════════════════════════════════════════════════");
    tracing::info!(" Initializing {} genesis", config.network.to_uppercase());
    tracing::info!(
        " Genesis timestamp: {} ({})",
        config.genesis_timestamp,
        chrono::DateTime::from_timestamp(config.genesis_timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "invalid".to_string())
    );
    tracing::info!("═══════════════════════════════════════════════════════");

    let total_supply = TOTAL_SUPPLY;
    let validators_allocated: u128 = config.validators.iter().map(|v| v.allocation).sum();
    if validators_allocated > total_supply {
        panic!("Validator allocations exceed total supply");
    }

    let mut total_allocation = 0u128;
    for (idx, validator) in config.validators.iter().enumerate() {
        let keypair = DualKeypair::load(&validator.keys_file)
            .unwrap_or_else(|e| panic!("Failed to load {}: {}", validator.keys_file, e));

        let dilithium_pubkey = keypair.dilithium_pk.into_bytes().to_vec();
        let account_id = account_id_from_pubkey(&dilithium_pubkey);

        let stake_amount = (validator.allocation * 80) / 100;
        let liquid_amount = validator.allocation.saturating_sub(stake_amount);

        state.accounts.insert(
            account_id,
            AccountRecord {
                pubkey_bytes: dilithium_pubkey.clone(),
                balance: liquid_amount,
                compute_escrow_tlkd: 0,
                nonce: 0,
                nfts: vec![],
            },
        );

        state.staking.validators.insert(
            dilithium_pubkey.clone(),
            truthlinked_staking::ValidatorStake::new(stake_amount as u64),
        );

        total_allocation = total_allocation.saturating_add(validator.allocation);

        tracing::info!(
            "   Validator {}: {} TLKD ({}% staked, {}% liquid) ({})",
            idx + 1,
            validator.allocation / ONE_TLKD,
            80,
            20,
            hex::encode(&account_id[..8])
        );
    }

    let pk = hex::decode(FOUNDATION_MINT_PUBKEY_HEX)
        .unwrap_or_else(|e| panic!("Failed to decode foundation_mint_pubkey: {}", e));
    if pk.len() != 1952 {
        panic!("foundation_mint_pubkey must be 1952 bytes (Dilithium pubkey)");
    }
    let account_id = account_id_from_pubkey(&pk);
    state.accounts.insert(
        account_id,
        AccountRecord {
            pubkey_bytes: pk.clone(),
            balance: 0,
            compute_escrow_tlkd: 0,
            nonce: 0,
            nfts: vec![],
        },
    );
    state.foundation_mint_authority = Some(account_id);
    tracing::info!(
        "   Foundation mint authority set: {}",
        hex::encode(&account_id[..8])
    );

    // Deploy System Authority cell (validator-governed upgrade authority)
    let system_id = system_authority_id();
    if !state.cells.cells.contains_key(&system_id) {
        let manifest_hash = CellAccount::compute_manifest_hash(&[], &[], &[], &[], &[]);
        state.cells.cells.insert(
            system_id,
            CellAccount {
                cell_id: system_id,
                owner: system_id,
                bytecode: vec![],
                storage: HashMap::new(),
                balance: 0,
                rent_deposit: 0,
                is_token: false,
                token_config: None,
                created_at: config.genesis_timestamp,
                upgraded_at: None,
                last_rent_paid_height: 0,
                rent_grace_blocks: STORAGE_RENT_GRACE_PERIOD_BLOCKS,
                pending_owner: None,
                is_immutable: true,
                declared_reads: Vec::new(),
                declared_writes: Vec::new(),
                commutative_keys: Vec::new(),
                storage_key_specs: Vec::new(),
                oracle_schema_ids: Vec::new(),
                governance_proposal: None,
                manifest_version: 1,
                manifest_hash,
            },
        );
        tracing::info!(
            "   System authority cell deployed: {}",
            hex::encode(&system_id[..8])
        );
    }

    let genesis_timestamp = config.genesis_timestamp;

    match truthlinked_mcp::deploy_mcp_genesis_cells(&mut state.cells, system_id, genesis_timestamp)
    {
        Ok(()) => tracing::info!(" MCP protocol cells deployed at genesis"),
        Err(e) => tracing::warn!("  MCP genesis deploy failed (non-fatal): {}", e),
    }

    {
        use truthlinked_core::pq_execution::{
            governance_system_cell_id, name_registry_system_cell_id,
            oracle_governance_system_cell_id, staking_system_cell_id,
            token_governance_system_cell_id, treasury_system_cell_id,
        };
        use truthlinked_runtime::cells::CellAccount;
        let make = |cell_id: [u8; 32]| CellAccount {
            cell_id,
            owner: system_id,
            bytecode: vec![],
            storage: std::collections::HashMap::new(),
            balance: 0,
            rent_deposit: 0,
            is_token: false,
            token_config: None,
            created_at: genesis_timestamp,
            upgraded_at: None,
            last_rent_paid_height: 0,
            rent_grace_blocks: 0,
            pending_owner: None,
            is_immutable: true,
            declared_reads: vec![],
            declared_writes: vec![],
            commutative_keys: vec![],
            storage_key_specs: vec![],
            oracle_schema_ids: vec![],
            governance_proposal: None,
            manifest_version: 1,
            manifest_hash: [0u8; 32],
        };
        use truthlinked_core::pq_execution::wtrth_system_cell_id;
        for id in [
            staking_system_cell_id(),
            governance_system_cell_id(),
            treasury_system_cell_id(),
            name_registry_system_cell_id(),
            token_governance_system_cell_id(),
            oracle_governance_system_cell_id(),
            wtrth_system_cell_id(),
        ] {
            state.cells.cells.insert(id, make(id));
        }
        tracing::info!("  System cells registered at genesis (native Rust handlers)");
    }

    let treasury_reserve = total_supply.saturating_sub(total_allocation);
    if let Some(cell) = state.cells.cells.get_mut(&treasury_system_cell_id()) {
        cell.balance = cell.balance.saturating_add(treasury_reserve);
    } else {
        panic!("treasury system cell not deployed");
    }
    total_allocation = total_allocation.saturating_add(treasury_reserve);

    if total_allocation != total_supply {
        panic!(
            "Genesis allocation mismatch: allocated {} vs supply {}",
            total_allocation / ONE_TLKD,
            total_supply / ONE_TLKD
        );
    }

    tracing::info!(
        " Genesis initialized: {} validators + treasury reserve = {} TLKD total supply",
        config.validators.len(),
        total_allocation / ONE_TLKD
    );
}

#[allow(dead_code)]
fn parse_manifest_slots(manifest: &Value, field: &str) -> Result<Vec<[u8; 32]>, String> {
    let arr = manifest[field]
        .as_array()
        .ok_or_else(|| format!("Missing {} in manifest", field))?;
    let mut out = Vec::new();
    for v in arr {
        let s = v.as_str().ok_or("manifest slot must be string")?;
        let bytes = hex::decode(s).map_err(|_| "invalid hex in manifest slot")?;
        if bytes.len() != 32 {
            return Err("manifest slot must be 32 bytes".to_string());
        }
        let mut arr32 = [0u8; 32];
        arr32.copy_from_slice(&bytes);
        out.push(arr32);
    }
    Ok(out)
}

#[allow(dead_code)]
fn parse_manifest_specs(manifest: &Value) -> Result<Vec<StorageKeySpec>, String> {
    let specs = manifest["storage_key_specs"]
        .as_array()
        .ok_or("Missing storage_key_specs in manifest")?;
    let mut out = Vec::new();
    for s in specs {
        let offset = s["offset"]
            .as_u64()
            .ok_or("storage_key_specs.offset missing")?;
        let len = s["len"].as_u64().ok_or("storage_key_specs.len missing")?;
        out.push(StorageKeySpec {
            offset: offset as usize,
            len: len as usize,
        });
    }
    Ok(out)
}

#[allow(dead_code)]
fn parse_manifest_schema_ids(manifest: &Value) -> Result<Vec<[u8; 32]>, String> {
    let empty = Vec::new();
    let arr = manifest
        .get("oracle_schema_ids")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut out = Vec::new();
    for v in arr {
        let s = v.as_str().ok_or("oracle_schema_ids entry must be string")?;
        let bytes = hex::decode(s).map_err(|_| "invalid hex in oracle_schema_ids")?;
        if bytes.len() != 32 {
            return Err("oracle_schema_ids entry must be 32 bytes".to_string());
        }
        let mut arr32 = [0u8; 32];
        arr32.copy_from_slice(&bytes);
        out.push(arr32);
    }
    Ok(out)
}
