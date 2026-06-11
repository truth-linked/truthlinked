//! Truthlinked Consensus Src Genesis
//!
//! Owns genesis state construction and boot-time validation.
//! Consensus changes are protocol-critical; preserve deterministic replay, recovery safety, and wire compatibility.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use truthlinked_core::cells::StorageKeySpec;
use truthlinked_core::constants::ONE_TRTH;
use truthlinked_core::constants::STORAGE_RENT_GRACE_PERIOD_BLOCKS;
use truthlinked_core::pq_execution::{system_authority_id, treasury_system_cell_id};
use truthlinked_core::pq_identity::{account_id_from_pubkey, DualKeypair};
use truthlinked_runtime::cells::CellAccount;
use truthlinked_runtime::types::AccountRecord;
use truthlinked_state::constants::TOTAL_SUPPLY;
use truthlinked_state::State;

const FOUNDATION_MINT_PUBKEY_HEX: &str = "decbc4bd14caba575328a0ddcfb633009e2ca6058085a9b404753dac5b8d98f11b3650d866f01d14914087498d87970cdd4ebcc5afa76989d15ab816a74cbe7ab44cbca9cd7484a62f4507e23cbc425e1a937b3f00588af9a4d55e278a678075e6e99401612508b1b35856a89a4b1241c50cc32b5863483913d72ac70a6b0764774fad57a0135c2a7c0756ecf8fd7ca6c56bf20ea86c3c5049fb988c6c3240b32d2e08cefccd1f4cd1b8286cbce04ac53b2c2d637a8ed4d2aa7f464fd8ecbad9001b531b7a2e499769059ad701fcdbe905829bace71b9c612ab5d787f526f4c94c7f385eff033433a9747598155e705afecc5136878a260aedda8afddb9564edbc103fca3b302f114048072b549bfc2eccd466243aa8b9edb6ec31cf2fba2e78d69ee77c848322883aec63f33e63363c6f44f8eccdce936e482b89f036e45ac154a1449547f6ba247ab1a953f5ecfb462ec690f5487fea88996bf9bd8de8a6478bc52360355dabc050f1d00a956ea15bd55a50621405ad5e1d5e32d95566994905ffa15dea19920830f9b3d96959182fe04102a67c90dc5cc499af5c59bc011f1b68b8119168ad0bacb22f088ce15c5de2b36fafb328266dccca6f0806c84cc07311bc86d5008bdc95d35c7f54bcb03da196301f7d03cbf7083f9fef89d49c4f26b4b3ab2cc3eeb19938fcb937f30a11b0ae0b2a57748c8a0cfb70be082b1a32d80a9593c51e289e45280b7ae7e0bce690e64dba637648480ddfd4348df1e6a2eface8c6dc6c56f8f65b4dd9eb7db507d1949ada2ad69a73130ae66ada35b78c725bad4b2b9576e0a3b612d75076b7db61481d93e7208db731a03fbe79d2f4fac5960588ffb077e2b45cc0ed8d36e36aac2fa91409b966368f5b00b1ce7ae88b8ed0613e1ae15435b9da407192da122888c196586ad3b9734198ff3f6c27c4c2fc0806886fdb635fc8d7a87a163643d377dd6a104fbed2fae4248d8c5c6cdf49a663193c18bacca954531c42d68e2ae0a1117647bb772f921d6d52a2277d40a3339f8193799858907d80e8a997278b5c0b99b3424badd9bf569cafbd24e1e60dc1878d4609c09d046d000da5d4719571c5b2c3643ffba85c085233d1d1cbc58dfd31bfb23de9ef38ffab3aa56e4818394692e558c7720dc09feac8d66e51102df60d38dbeade04870e0341f482eb51faaf34b3a93118e69d5fa8449aeef127b6bd137e532045bb0042a4b1ff53aa066648c9da516269b0d4486a2b13338ba72274b67dcfee807b8cbc1d822a5110c69a91b9b8c6b450b759d56e17eaccb3bae71993a8a787262a3eef25aa8586f1c59f708493375a5eeb988628472c93cb8fe8d5f45bf19649532a05b28122885ea4b54e2fc7c42a3278c6b0311918a1c2567a6ac77edfcc981294c3d6dde9973fa5b670080830a96a192fd27764662ea0c853895c9255fc244395a4704aec9a957f2d0a2acf8b11b19bca6d107c2cec5d5b547d02915b35757a29a0470a380b2f2728fc917dfedbefa4aab2792a14cf69fe606307d7cdb93b885a958a9705858efdc0831ca591771174f0b03a55f8cce968f6622a95a293a5199175b61167b327a9a8bc17a62b1d4b7aea7ea766c847167a53da2a6e5c6e96d275ed3c0d7e45504a20fb4e2895ec4dba76251b9c200b8f4e163bd97e18b7fd5162ffb26f1fddb277422268722da3505b6d3638551895d17e0f14697a1543246f1b975e52cc2fe355569ceacfaf6dc32a971441100f7750cfc43288cb0ddee4db770e3dbc70997f7c653ec8cf553bb5c2b48dafdf586a1734cb06e63b20b75e3d7c2101235bbbcc7bc49b1f7623dc5b18481fd47a4df78a10056011d57b271075051eaccf4aef4d9f521d9792d4c445800b52894d2d0c84796fa2097feb824283672df0e679c66107ecf32d01861ab204c80565fb819b132b8a7f681fd89561beb32d3505afdbd98b05234f911f0c08500ad0e814d9cd585d3e3a2f3dfb20504ce26ec248db78acfd1af5d490c53f483ab13b67774f763314127f51778aac984d00e69c31d115da5b11a114a256eb7215ccf59e57cd46c78ad33234c38a1e464088ba0298e18079956d4a36c809b1a09e9a6d00395740423056efeab6fab69d211a68da95f70a715b93ef2ce9199af43d6d24960eefec6e2fe4dc0ce0bfd216f1e4fc9852755c0034e1f302cb9229d3a1fe68e3d77561cb5a92b4174761ca8a8dcfedd47133d79bef6d6417a2cab6e888a6959ae52a07b0615f00221b9bad0c505fbdd4e17443eebad8283e71ab90069f3ca6088121f4656dc9866d430d39c71815510cad710310ffdaf46db747b633c26c7b6933355df47def6492374c88c149882db13ba1ff2ce10f29b71b1abf5c4b5dd057ed6c3dde70b9ab94e754efb0a160c5429f16303d55d7f7570c21a790d5a63cc6acc79d584f32ddeaa772da5780a4f73c6d08ae7d9dd22855898fec3b9caae003d83b3fb329a2f3c540d02adcca9b39568cd3855029da05ac20fd92d3deafd04103ade91d5dfc045522c4122747a81381e740035a6c7f3a874c3a8da6af99e1177002460836110a5115376e2f11f6a9a947b68ad944d4e0a04214264fc760974132220af99a72e0d7f100419cc1bcdf2897c7a42c388b47f2b2019920d23a0c629775b5b642d1554d956359805f474aad99ebbc5f74e0dc7af94f87896fca0e433ea62400ee5b8f2b2d678cc4ae7eb3e1b6456dd07ddff6b3bca52a220f594133bf36bc8a4dbf";
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
                    allocation: 100_000 * ONE_TRTH,
                },
                GenesisValidator {
                    keys_file: "validator2_keys.json".to_string(),
                    allocation: 100_000 * ONE_TRTH,
                },
                GenesisValidator {
                    keys_file: "validator3_keys.json".to_string(),
                    allocation: 100_000 * ONE_TRTH,
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
                    allocation: 50_000 * ONE_TRTH,
                },
                GenesisValidator {
                    keys_file: "validator2_keys.json".to_string(),
                    allocation: 70_000 * ONE_TRTH,
                },
                GenesisValidator {
                    keys_file: "validator3_keys.json".to_string(),
                    allocation: 80_000 * ONE_TRTH,
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
                compute_escrow_trth: 0,
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
            validator.allocation / ONE_TRTH,
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
            compute_escrow_trth: 0,
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
            total_allocation / ONE_TRTH,
            total_supply / ONE_TRTH
        );
    }

    tracing::info!(
        " Genesis initialized: {} validators + treasury reserve = {} TLKD total supply",
        config.validators.len(),
        total_allocation / ONE_TRTH
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
