//! TruthLinked validator node entry point.
use clap::Parser;
use std::sync::Arc;
use truthlinked_consensus::streaming_consensus::StreamingConsensus;
use truthlinked_core::constants::ONE_TRTH;
use truthlinked_core::DualKeypair;
use truthlinked_net::ingress::IngressServer;

#[derive(Parser, Debug)]
#[command(name = "truthlinked-node")]
#[command(about = "TruthLinked Post-Quantum Blockchain Node (Streaming Consensus)", long_about = None)]
struct Args {
    /// Path to validator keys JSON file
    #[arg(long, value_name = "FILE")]
    validator_keys: String,

    /// Data directory for blockchain storage
    #[arg(long, value_name = "PATH", default_value = "./data")]
    data_dir: String,

    /// Ingress port (single entry point for all transactions)
    #[arg(long, value_name = "PORT", default_value = "18080")]
    ingress_port: u16,

    /// P2P port (validator-to-validator PQ-encrypted mesh)
    #[arg(long, value_name = "PORT", default_value = "19080")]
    p2p_port: u16,

    /// RPC port
    #[arg(long, value_name = "PORT", default_value = "19944")]
    rpc_port: u16,

    /// Bootstrap node addresses (comma-separated)
    #[arg(long, value_name = "ADDR", value_delimiter = ',')]
    bootnodes: Vec<String>,

    /// Genesis file path
    #[arg(long, value_name = "FILE")]
    genesis_file: Option<String>,

    /// Archive/full node: keep all block data forever (no pruning).
    /// Default: prune raw batch data older than 2 snapshot intervals.
    #[arg(long, default_value = "false")]
    full: bool,

    /// Run a one-validator local chain for single-machine testing.
    /// The genesis validator set is reduced to this node's validator key.
    #[arg(long, default_value = "false")]
    single_node: bool,

    /// Limit the local genesis validator set to the first N validators from genesis.
    /// Useful for running one to five validators on one machine without editing genesis JSON.
    #[arg(long, value_name = "N")]
    local_validator_count: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    if let Ok(interval) = std::env::var("TRUTHLINKED_SNAPSHOT_INTERVAL") {
        if let Ok(val) = interval.parse::<u64>() {
            truthlinked_consensus::snapshot::set_snapshot_interval(val);
            tracing::info!(" Snapshot interval set to {} blocks", val);
        }
    }

    tracing::info!(" Starting TruthLinked Node (Streaming Consensus)");
    tracing::info!(" Data directory: {}", args.data_dir);
    tracing::info!(" Validator keys: {}", args.validator_keys);

    let keypair = DualKeypair::load(&args.validator_keys)?;
    let dilithium_pubkey = keypair.dilithium_pk.clone().into_bytes().to_vec();

    tracing::info!(
        " Validator Dilithium pubkey: {}",
        hex::encode(&dilithium_pubkey[..8])
    );

    let mut genesis_config = if let Some(ref path) = args.genesis_file {
        truthlinked_consensus::genesis::GenesisConfig::load(path)?
    } else {
        truthlinked_consensus::genesis::GenesisConfig::default_devnet()
    };

    if args.single_node {
        let allocation = genesis_config
            .validators
            .iter()
            .find(|v| v.keys_file == args.validator_keys)
            .map(|v| v.allocation)
            .or_else(|| genesis_config.validators.first().map(|v| v.allocation))
            .unwrap_or(100_000 * ONE_TRTH);
        genesis_config.validators = vec![truthlinked_consensus::genesis::GenesisValidator {
            keys_file: args.validator_keys.clone(),
            allocation,
        }];
        tracing::warn!(
            " Single-node local chain enabled: genesis validator set reduced to {}",
            args.validator_keys
        );
    } else if let Some(count) = args.local_validator_count {
        if count == 0 || count > genesis_config.validators.len() {
            return Err(format!(
                "--local-validator-count must be between 1 and {}",
                genesis_config.validators.len()
            )
            .into());
        }
        genesis_config.validators.truncate(count);
        tracing::warn!(
            " Local validator count enabled: genesis validator set truncated to {}",
            count
        );
    }

    let mut state = truthlinked_state::State::genesis();
    truthlinked_consensus::genesis::initialize_genesis(&mut state, &genesis_config);

    let mut genesis_hash = compute_genesis_hash(&state);
    if std::env::var("TRUTHLINKED_FORCE_TESTNET").ok().as_deref() == Some("1") {
        genesis_hash = [0u8; 32];
        tracing::warn!(" TRUTHLINKED_FORCE_TESTNET=1 set: forcing testnet genesis fingerprint");
    }
    truthlinked_state::set_genesis_hash(genesis_hash);
    tracing::info!(
        " Genesis hash (genesis fingerprint): {}",
        hex::encode(genesis_hash)
    );

    let mut validators = Vec::new();

    for validator_config in &genesis_config.validators {
        let val_keypair = DualKeypair::load(&validator_config.keys_file)?;
        let val_dilithium_pk = val_keypair.dilithium_pk.into_bytes().to_vec();

        validators.push(val_dilithium_pk);
    }

    tracing::info!(" Total validators: {}", validators.len());

    std::fs::create_dir_all(&args.data_dir)?;
    let mut storage_inner = truthlinked_consensus::persistence::Storage::new(&args.data_dir)?;
    storage_inner.set_full_node(args.full);
    let storage = Arc::new(storage_inner);
    tracing::info!(
        " Storage initialized at {} ({})",
        args.data_dir,
        if args.full { "archive" } else { "pruned" }
    );

    let (mut consensus, _rx) = StreamingConsensus::new(keypair, validators.clone(), state);
    consensus.set_storage(storage.clone());

    let consensus = Arc::new(consensus);

    tracing::info!(" Streaming consensus initialized (gossip-based attestations)");

    // Startup restore strategy:
    // 1. Load latest snapshot (O(1)) to get state at snapshot height.
    // 2. Always replay the delta from snapshot_height+1 → stored tip.
    //    This recovers any blocks finalized after the last snapshot.
    // 3. If no snapshot exists, replay everything from genesis.
    match consensus.fast_sync_from_snapshot().await {
        Ok(()) => {
            let snap_h = consensus.get_current_height();
            tracing::info!(" Snapshot restored at height {}", snap_h);
        }
        Err(e) => {
            tracing::info!("No snapshot: {} — will replay from genesis", e);
        }
    }
    // Always replay the delta (snapshot_height+1 → stored tip).
    // replay_from_storage detects the snapshot and skips already-applied blocks.
    match consensus.replay_from_storage().await {
        Ok(height) => tracing::info!(" Replay complete at height {}", height),
        Err(e) => tracing::info!("No stored blocks: {} — starting from genesis", e),
    }
    if args.single_node {
        std::env::set_var("TRUTHLINKED_SINGLE_NODE", "1");
        consensus.set_synced().await;
        tracing::warn!(" Single-node local chain marked synced without peer confirmation");
    } else {
        // Sync state is set by sync_detection_task once peers confirm our height.
        // Do not call set_synced() here; let peer confirmation gate it.
    }

    // Refresh the active attester set immediately so attestations work from block 1.
    // Use clock-based epoch (same formula as attesters_for_header) so all nodes
    // independently arrive at the same active attester set regardless of start time.
    {
        let epoch_ms = truthlinked_governance::params::get_u64(
            truthlinked_governance::params::PARAM_EPOCH_DURATION_MS,
        );
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let epoch = if epoch_ms == 0 { 0 } else { now_ms / epoch_ms };
        consensus.refresh_active_attesters(epoch).await;
    }
    tracing::info!(" Initial active attester set refreshed");

    // Spawn background catch-up task: fetches missing blocks from peers,
    // gates attestation until fully caught up
    let catchup_consensus = consensus.clone();
    tokio::spawn(async move {
        catchup_consensus.peer_catchup_task().await;
    });
    tracing::info!(" Peer catch-up task spawned — node will attest once caught up");

    // Spawn autonomous block repairer: detects and fixes corrupt/missing blocks
    consensus.spawn_block_repairer();
    tracing::info!(" Block repairer spawned");

    // Parses each bootnode entry as "ip:port:pk_hex", then maintains persistent
    // connections with exponential backoff + jitter. Skips already-connected
    // peers. Re-checks every 30 s so transient failures self-heal.
    if !args.bootnodes.is_empty() {
        #[derive(Clone)]
        struct BootPeer {
            addr: String,
            pk: Vec<u8>,
        }

        let mut boot_peers: Vec<BootPeer> = Vec::new();
        for entry in &args.bootnodes {
            // Format: "ip:port:pk_hex" — split on the LAST colon to isolate pk.
            match entry.rfind(':') {
                None => {
                    tracing::warn!(" Bootnode entry missing pk_hex, skipping: {}", entry);
                }
                Some(colon) => {
                    let addr = entry[..colon].to_string();
                    let pk_hex = &entry[colon + 1..];
                    match hex::decode(pk_hex) {
                        Ok(pk) if pk.len() == 1952 => {
                            tracing::info!(
                                " Bootnode registered: {} (pk {}...)",
                                addr,
                                &pk_hex[..8]
                            );
                            boot_peers.push(BootPeer { addr, pk });
                        }
                        Ok(pk) => {
                            tracing::warn!(
                                " Bootnode pk wrong length ({} bytes, need 1952), skipping: {}",
                                pk.len(),
                                addr
                            );
                        }
                        Err(e) => {
                            tracing::warn!(" Bootnode pk_hex decode failed for {}: {}", addr, e);
                        }
                    }
                }
            }
        }

        if !boot_peers.is_empty() {
            let n_peers = boot_peers.len();
            let dial_consensus = consensus.clone();
            let boot_peers_arc = boot_peers.clone();
            tokio::spawn(async move {
                let boot_peers = boot_peers_arc;
                use rand::Rng;
                use tokio::time::{sleep, Duration};

                // Per-peer backoff state: (attempt_count, next_retry_at)
                let mut backoff: std::collections::HashMap<String, (u32, std::time::Instant)> =
                    std::collections::HashMap::new();

                // Small initial delay so our own listener is fully up before dialing.
                sleep(Duration::from_secs(2)).await;

                loop {
                    for peer in &boot_peers {
                        // Skip if already connected.
                        if dial_consensus.is_peer_connected(&peer.pk).await {
                            backoff.remove(&peer.addr);
                            continue;
                        }

                        // Honour per-peer backoff window.
                        let now = std::time::Instant::now();
                        if let Some((_, next_retry)) = backoff.get(&peer.addr) {
                            if now < *next_retry {
                                continue;
                            }
                        }

                        tracing::info!(
                            " Dialing bootnode {} (pk {}...)",
                            peer.addr,
                            hex::encode(&peer.pk[..4])
                        );

                        match dial_consensus
                            .connect_to_peer(&peer.addr, peer.pk.clone())
                            .await
                        {
                            Ok(()) => {
                                tracing::info!(
                                    " Connected to bootnode {} (pk {}...)",
                                    peer.addr,
                                    hex::encode(&peer.pk[..4])
                                );
                                backoff.remove(&peer.addr);
                            }
                            Err(e) => {
                                let entry = backoff.entry(peer.addr.clone()).or_insert((0, now));
                                entry.0 += 1;
                                let attempts = entry.0;
                                // Exponential backoff: 5s * 2^(n-1), capped at 300s,
                                // plus up to 5s random jitter to avoid thundering herd.
                                let base_secs = (5u64 * (1u64 << (attempts - 1).min(6))).min(300);
                                let jitter_ms = rand::thread_rng().gen_range(0..5_000u64);
                                let delay = Duration::from_millis(base_secs * 1_000 + jitter_ms);
                                entry.1 = now + delay;
                                tracing::warn!(
                                    " Bootnode {} unreachable (attempt {}): {} — retry in {:.1}s",
                                    peer.addr,
                                    attempts,
                                    e,
                                    delay.as_secs_f64()
                                );
                            }
                        }
                    }

                    // Poll every 30 s; per-peer backoff handles the actual retry timing.
                    sleep(Duration::from_secs(30)).await;
                }
            });

            tracing::info!(" Bootnode dialer spawned ({} peers)", n_peers);
        }
    }
    // ── End bootnode dialer ───────────────────────────────────────────────────────────────────────────

    let mcp_consensus = consensus.clone();
    let mcp_port = args.rpc_port + 1;
    let mcp_handle = tokio::spawn(async move {
        let transport = truthlinked::mcp_transport::OnChainMcpTransport::new(
            mcp_consensus,
            mcp_port,
            truthlinked_mcp::protocol_addresses::mcp_registry(),
            truthlinked_mcp::protocol_addresses::agent_registry(),
        );
        if let Err(e) = transport.start().await {
            tracing::error!("MCP transport error: {}", e);
        }
    });

    let rpc_consensus = consensus.clone();
    let rpc_port = args.rpc_port;
    let rpc_handle = tokio::spawn(async move {
        let rpc_server = truthlinked::rpc::RpcServer::new(rpc_consensus, rpc_port);
        if let Err(e) = rpc_server.start().await {
            tracing::error!("RPC server error: {}", e);
        }
    });

    let finalization_consensus = consensus.clone();
    let finalization_handle = tokio::spawn(async move {
        finalization_consensus.finalization_task().await;
    });

    let snapshot_consensus = consensus.clone();
    let snapshot_handle = tokio::spawn(async move {
        use tokio::time::{interval, Duration};
        let mut timer = interval(Duration::from_secs(60));

        loop {
            timer.tick().await;
            let height = snapshot_consensus.get_finalized_height();

            if height > 0 && height % 1000 == 0 {
                if let Err(e) = snapshot_consensus.create_snapshot(height).await {
                    tracing::error!("Failed to create snapshot at height {}: {}", height, e);
                }
            }
        }
    });

    let epoch_consensus = consensus.clone();
    let epoch_handle = tokio::spawn(async move {
        epoch_consensus.epoch_rotation_task().await;
    });

    let gossip_consensus = consensus.clone();
    let _gossip_handle = tokio::spawn(async move {
        gossip_consensus.profile_gossip_task().await;
    });

    let attestation_consensus = consensus.clone();
    let attestation_handle = tokio::spawn(async move {
        attestation_consensus.attestation_cleanup_task().await;
    });

    let height_consensus = consensus.clone();
    let height_handle = tokio::spawn(async move {
        height_consensus.height_announcement_task().await;
    });

    let p2p_consensus = consensus.clone();
    let p2p_port = args.p2p_port;
    let p2p_handle = tokio::spawn(async move {
        if let Err(e) = truthlinked_consensus::streaming_consensus::start_ingress_server(
            p2p_port,
            p2p_consensus,
        )
        .await
        {
            tracing::error!("P2P listener error: {}", e);
        }
    });
    tracing::info!(" P2P listener port: {}", args.p2p_port);

    let ingress_consensus = consensus.clone();
    let ingress_handle = tokio::spawn(async move {
        let server = IngressServer::new(args.ingress_port, ingress_consensus);
        if let Err(e) = server.start().await {
            tracing::error!("Ingress server error: {}", e);
        }
    });

    // Delay startup to allow peer connections and block sync before producing.
    let batch_consensus = consensus.clone();
    let batch_handle = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
        batch_consensus.batch_timer_task().await;
    });

    //  Oracle fetch loop
    // After each block, this validator:
    //   1. Reads all pending oracle requests from state.
    //   2. Fetches each URL independently.
    //   3. Submits SubmitOracleCommit transactions to chain.
    //   4. Waits one block for commit quorum, then submits SubmitOracleReveal.
    //
    // The loop polls every 200ms (one batch interval). Commits and reveals are
    // held in a local HashMap keyed by request_id so they survive across ticks.
    //
    let oracle_consensus = consensus.clone();
    let oracle_handle = tokio::spawn(async move {
        use std::collections::HashMap;
        use tokio::time::{interval, Duration};
        use truthlinked_core::pq_execution::{Transaction, TransactionIntent};
        use truthlinked_core::pq_identity::account_id_from_pubkey;
        use truthlinked_oracle::http_oracle::validator_fetch_and_commit;

        // pending_reveals: request_id -> (response_body, status)
        let mut pending_reveals: HashMap<[u8; 32], (Vec<u8>, u16)> = HashMap::new();
        // committed_at: request_id -> chain height at commit time
        let mut committed_at: HashMap<[u8; 32], u64> = HashMap::new();
        // already_committed: request_ids we sent a commit tx for this round
        let mut already_committed: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        // Requests for which this validator has already submitted a reveal.
        // Keep this separate from `pending_reveals`: transaction submission only
        // means the reveal entered the network, not that state has reflected it
        // yet. Without this guard the oracle loop can resubmit commits/reveals
        // for the same request while the previous tx is still being finalized.
        let mut already_revealed: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();

        let validator_pk = oracle_consensus.get_validator_pubkey();
        let keypair = oracle_consensus.get_keypair();
        let sender_id = account_id_from_pubkey(&validator_pk);
        let genesis_fingerprint = truthlinked_state::get_genesis_hash();
        // Local nonce counter — incremented after each submitted tx so we never
        // submit two txs with the same nonce even if state hasn't updated yet.
        let mut local_nonce: Option<u64> = None;

        let mut ticker = interval(Duration::from_millis(250));

        loop {
            ticker.tick().await;

            let current_height = oracle_consensus.get_current_height();
            let state_arc = oracle_consensus.get_state();
            let state = state_arc.load();

            // Sync local nonce with chain — if chain advanced past our counter, reset.
            let chain_nonce = state
                .accounts
                .get(&sender_id)
                .map(|a| a.nonce + 1)
                .unwrap_or(1);
            if local_nonce.map_or(true, |n| chain_nonce > n) {
                local_nonce = Some(chain_nonce);
            }

            // Skip if we are not a registered validator in this state.
            if !state.staking.validators.contains_key(&validator_pk) {
                continue;
            }

            //  PHASE 2: commit pending requests we haven't committed yet
            let pending_requests: Vec<_> = state
                .pending_oracle_requests
                .values()
                .filter(|r| {
                    if already_committed.contains(&r.request_id) {
                        return false;
                    }
                    if let Some(tally) = state.oracle_pending.get(&r.request_id) {
                        if tally.commits.contains_key(&validator_pk) {
                            return false;
                        }
                    }
                    true
                })
                .cloned()
                .collect();

            if !pending_requests.is_empty() {
                tracing::info!(
                    " Oracle: {} pending requests, fetching...",
                    pending_requests.len()
                );
                let payloads = validator_fetch_and_commit(
                    &pending_requests,
                    &validator_pk,
                    current_height,
                    &state.schema_registry,
                )
                .await;
                tracing::info!(" Oracle: got {} commit payloads", payloads.len());

                for payload in payloads {
                    let req_id = payload.request_id;

                    // Build and sign the SubmitOracleCommit transaction.
                    let expiration_height = current_height + 100;
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    let chain_nonce = state
                        .accounts
                        .get(&sender_id)
                        .map(|a| a.nonce + 1)
                        .unwrap_or(1);
                    let oracle_nonce = local_nonce
                        .map(|n| n.max(chain_nonce))
                        .unwrap_or(chain_nonce);
                    local_nonce = Some(oracle_nonce + 1);
                    let unsigned = Transaction {
                        nonce: oracle_nonce,
                        sender: sender_id,
                        intent: TransactionIntent::SubmitOracleCommit {
                            request_id: req_id,
                            commit_hash: payload.commit_hash,
                        },
                        signature: vec![],
                        timestamp: ts,
                        genesis_fingerprint,
                        expiration_height,
                    };

                    match keypair.sign_transaction(&unsigned) {
                        Ok(signed) => {
                            if let Err(e) = oracle_consensus.submit_transaction(signed).await {
                                tracing::warn!(
                                    "  Oracle commit submit failed for {}: {}",
                                    hex::encode(&req_id[..4]),
                                    e
                                );
                            } else {
                                tracing::debug!(
                                    " Oracle commit submitted for request {}",
                                    hex::encode(&req_id[..4])
                                );
                                already_committed.insert(req_id);
                                committed_at.insert(req_id, current_height);
                                // Store the body for the reveal phase.
                                pending_reveals.insert(
                                    req_id,
                                    (payload.response_body, payload.response_status),
                                );
                            }
                        }
                        Err(e) => tracing::warn!("  Oracle commit sign failed: {}", e),
                    }
                }
            }

            //  PHASE 3: reveal once commit tally has had one block to settle
            // We reveal if: the tally exists, commit quorum is reached, we have
            // not yet revealed (reveals tally won't contain our pk), and at least
            // one block has passed since our commit.
            let reveal_candidates: Vec<[u8; 32]> = pending_reveals
                .keys()
                .filter(|req_id| {
                    // Must have committed at least 1 block ago.
                    let commit_height = committed_at.get(*req_id).copied().unwrap_or(0);
                    if already_revealed.contains(*req_id) {
                        return false;
                    }
                    if current_height <= commit_height {
                        return false;
                    }
                    // Tally must exist and have reached commit quorum.
                    if let Some(tally) = state.oracle_pending.get(*req_id) {
                        if !tally.commit_quorum_reached() {
                            return false;
                        }
                        // We must not have already revealed.
                        if tally.reveals.contains_key(&validator_pk) {
                            return false;
                        }
                        // Our commit must be in the tally.
                        tally.commits.contains_key(&validator_pk)
                    } else {
                        // Tally gone — request already finalized or expired. Clean up.
                        false
                    }
                })
                .copied()
                .collect();

            for req_id in reveal_candidates {
                if let Some((body, status)) = pending_reveals.get(&req_id) {
                    let expiration_height = current_height + 100;
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    let chain_nonce = state
                        .accounts
                        .get(&sender_id)
                        .map(|a| a.nonce + 1)
                        .unwrap_or(1);
                    let oracle_nonce = local_nonce
                        .map(|n| n.max(chain_nonce))
                        .unwrap_or(chain_nonce);
                    local_nonce = Some(oracle_nonce + 1);
                    let unsigned = Transaction {
                        nonce: oracle_nonce,
                        sender: sender_id,
                        intent: TransactionIntent::SubmitOracleReveal {
                            request_id: req_id,
                            response_body: body.clone(),
                            response_status: *status,
                        },
                        signature: vec![],
                        timestamp: ts,
                        genesis_fingerprint,
                        expiration_height,
                    };

                    match keypair.sign_transaction(&unsigned) {
                        Ok(signed) => {
                            if let Err(e) = oracle_consensus.submit_transaction(signed).await {
                                tracing::warn!(
                                    "  Oracle reveal submit failed for {}: {}",
                                    hex::encode(&req_id[..4]),
                                    e
                                );
                            } else {
                                tracing::debug!(
                                    " Oracle reveal submitted for request {}",
                                    hex::encode(&req_id[..4])
                                );
                                // Reveal has entered the network. Do not remove
                                // `already_committed` here; state may not have
                                // applied the reveal yet, and removing it causes
                                // duplicate commit spam for the same request. GC
                                // below clears all local markers once the request
                                // leaves pending/tally state.
                                pending_reveals.remove(&req_id);
                                already_revealed.insert(req_id);
                            }
                        }
                        Err(e) => tracing::warn!("  Oracle reveal sign failed: {}", e),
                    }
                }
            }

            //  GC: remove entries for requests no longer in pending state
            pending_reveals.retain(|req_id, _| {
                state.pending_oracle_requests.contains_key(req_id)
                    || state.oracle_pending.contains_key(req_id)
            });
            already_committed.retain(|req_id| {
                state.pending_oracle_requests.contains_key(req_id)
                    || state.oracle_pending.contains_key(req_id)
            });
            committed_at.retain(|req_id, _| {
                state.pending_oracle_requests.contains_key(req_id)
                    || state.oracle_pending.contains_key(req_id)
            });
            already_revealed.retain(|req_id| {
                state.pending_oracle_requests.contains_key(req_id)
                    || state.oracle_pending.contains_key(req_id)
            });

            // Oracle finalization stops at OracleResult. Calling a cell-specific
            // settle method is an ABI concern for the caller/CLI; the node must
            // not guess a method name and inject failing CallCell transactions.
        }
    });

    tracing::info!(" Node started successfully!");
    tracing::info!(" MCP on-chain transport port: {}", mcp_port);
    tracing::info!(" Ingress port: {}", args.ingress_port);
    tracing::info!(" RPC port: {}", args.rpc_port);
    tracing::info!(" Attestations: P2P gossip (no separate ACK server)");
    tracing::info!("⏱  Batch interval: 200ms");
    tracing::info!(" Epoch interval: 1 minute");
    tracing::info!(" Active attester set: active validators");
    tracing::info!(" All validators stream transactions (automatic forwarding)");
    tracing::info!("  Only active validators attest");

    // Wait for all tasks — only exit on ctrl_c or truly fatal errors.
    // Non-fatal task exits are logged and ignored so the node stays up.
    tokio::select! {
        _ = rpc_handle => tracing::error!("RPC server stopped unexpectedly — node continuing"),
        _ = finalization_handle => tracing::error!("Finalization task stopped unexpectedly — node continuing"),
        _ = snapshot_handle => tracing::error!("Snapshot task stopped unexpectedly — node continuing"),
        _ = epoch_handle => tracing::error!("Epoch rotation stopped unexpectedly — node continuing"),
        _ = height_handle => tracing::error!("Height announcement stopped unexpectedly — node continuing"),
        _ = attestation_handle => tracing::error!("Attestation cleanup stopped unexpectedly — node continuing"),
        _ = p2p_handle => tracing::warn!("P2P listener stopped (peer disconnect?) — node continuing"),
        _ = ingress_handle => tracing::error!("Ingress server stopped unexpectedly — node continuing"),
        _ = mcp_handle => tracing::warn!("MCP transport stopped — node continuing"),
        _ = batch_handle => tracing::error!("Batch timer stopped unexpectedly — node continuing"),
        _ = oracle_handle => tracing::warn!("Oracle fetch loop stopped — node continuing"),
        _ = shutdown_signal() => {
            tracing::info!(" Shutting down...");
            return Ok(());
        }
    }

    // A non-fatal task exited — keep the node alive.
    tracing::warn!("A background task exited — node remains running. Send SIGTERM to shut down.");
    shutdown_signal().await;
    tracing::info!(" Shutting down...");
    Ok(())
}

/// Waits for SIGTERM always; also waits for SIGINT only when running interactively (tty).
/// This prevents ctrl_c in any terminal from killing a daemonized node.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let interactive = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
    if interactive {
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    } else {
        sigterm.recv().await;
    }
}

fn compute_genesis_hash(state: &truthlinked_state::State) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();

    // Hash all genesis accounts
    let mut accounts: Vec<_> = state.accounts.iter().collect();
    accounts.sort_by_key(|(id, _)| *id);

    for (account_id, account) in accounts {
        hasher.update(account_id);
        hasher.update(&account.balance.to_le_bytes());
    }

    hasher.finalize().into()
}
use fips204::traits::SerDes;
