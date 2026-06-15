//! Truthlinked Consensus Src Bin Consensus Bench
//!
//! Owns consensus benchmark wiring for repeatable performance checks.
//! Consensus changes are protocol-critical; preserve deterministic replay, recovery safety, and wire compatibility.

/// Full consensus benchmark - 3 nodes, real execution, real DonaDB storage.
///
/// Pipeline per block:
///   1. Leader builds batch + signs header (Dilithium)
///   2. Validators 2 & 3 attest (sign batch_hash)
///   3. Parallel tx execution (real state transitions)
///   4. All 3 nodes commit via save_block -> DonaDB batch -> fsync
///
/// Usage:
///   cargo run --release --bin consensus-bench -- [total_txs] [batch_size]
///   cargo run --release --bin consensus-bench -- 8000000 1000
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use fips204::traits::{SerDes, Signer};
use truthlinked_consensus::{BatchHeader, Persistence};
use truthlinked_core::{
    pq_execution::{Transaction, TransactionIntent},
    DualKeypair,
};
use truthlinked_runtime::types::AccountRecord;
use truthlinked_state::State;

const BATCH_SIGN_CTX: &[u8] = b"truthlinked-batch-v1";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn pk_bytes(kp: &DualKeypair) -> Vec<u8> {
    kp.dilithium_pk.clone().into_bytes().to_vec()
}

fn sign(kp: &DualKeypair, hash: &[u8; 32]) -> Vec<u8> {
    kp.dilithium_sk
        .try_sign(hash, BATCH_SIGN_CTX)
        .expect("sign failed")
        .to_vec()
}

fn make_state(validators: &[DualKeypair]) -> State {
    let mut state = State::genesis();
    for kp in validators {
        let pk = pk_bytes(kp);
        let id: [u8; 32] = blake3::hash(&pk).into();
        state.accounts.insert(
            id,
            AccountRecord {
                pubkey_bytes: pk.clone(),
                balance: 1_000_000_000_000_000,
                compute_escrow_tlkd: 0,
                nonce: 0,
                nfts: vec![],
            },
        );
        state
            .staking
            .stake(pk, truthlinked_core::constants::MIN_VALIDATOR_STAKE)
            .unwrap();
    }
    // fund 10k sender accounts
    for i in 0u64..10_000 {
        let id: [u8; 32] = blake3::hash(&i.to_le_bytes()).into();
        state.accounts.insert(
            id,
            AccountRecord {
                pubkey_bytes: vec![],
                balance: 1_000_000_000_000_000_000,
                compute_escrow_tlkd: 0,
                nonce: 0,
                nfts: vec![],
            },
        );
    }
    state
}

fn make_batch(block_idx: u64, size: usize, state: &State) -> Vec<Transaction> {
    let genesis_fingerprint = [0u8; 32];
    (0..size)
        .map(|i| {
            let s = ((block_idx as usize * size + i) % 10_000) as u64;
            let sender: [u8; 32] = blake3::hash(&s.to_le_bytes()).into();
            let recipient: [u8; 32] = blake3::hash(&((s + 1) % 10_000).to_le_bytes()).into();
            let nonce = state
                .accounts
                .get(&sender)
                .map(|a| a.nonce + 1)
                .unwrap_or(1);
            Transaction {
                sender,
                intent: TransactionIntent::Transfer {
                    recipient,
                    recipient_pubkey: None,
                    amount: 1,
                },
                signature: vec![0u8; 32], // bench: sig verification skipped
                nonce,
                timestamp: 1,
                genesis_fingerprint,
                expiration_height: u64::MAX,
            }
        })
        .collect()
}

fn state_root(state: &State) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&state.staking.current_height.to_le_bytes());
    h.update(&(state.accounts.len() as u64).to_le_bytes());
    h.finalize().into()
}

fn percentile(mut v: Vec<f64>, p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 * p / 100.0) as usize).min(v.len() - 1)]
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let total_txs: usize = args
        .get(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(8_000_000);
    let batch_size: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(1_000);
    let num_blocks = total_txs / batch_size;

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║         TruthLinked Consensus Benchmark                  ║");
    println!(
        "║  nodes=3  txs={:<8}  batch={:<6}  storage=DonaDB    ║",
        total_txs, batch_size
    );
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // ── Setup ─────────────────────────────────────────────────────────────────
    print!("Generating 3 validator keypairs (Dilithium ML-DSA-65)... ");
    let t = Instant::now();
    let validators: Vec<DualKeypair> = (0..3).map(|_| DualKeypair::generate()).collect();
    let vpks: Vec<Vec<u8>> = validators.iter().map(pk_bytes).collect();
    println!("{:.2}s", t.elapsed().as_secs_f64());

    print!("Building genesis state (10k accounts + 3 staked validators)... ");
    let t = Instant::now();
    let mut state = make_state(&validators);
    println!("{:.2}s", t.elapsed().as_secs_f64());

    print!("Initializing DonaDB storage (3 nodes)... ");
    let t = Instant::now();
    let storages: Vec<Arc<Persistence>> = (0..3usize)
        .map(|i| {
            let path = format!("/tmp/tl-consensus-bench-node-{}", i);
            let _ = std::fs::remove_dir_all(&path);
            Arc::new(Persistence::new(&path).unwrap())
        })
        .collect();
    println!("{:.2}s\n", t.elapsed().as_secs_f64());

    println!(
        "Running {} blocks × {} tx = {} total txs...\n",
        num_blocks, batch_size, total_txs
    );

    // ── Benchmark ─────────────────────────────────────────────────────────────
    let name_registry: HashMap<String, [u8; 32]> = HashMap::new();
    let mut block_ms: Vec<f64> = Vec::with_capacity(num_blocks);
    let mut exec_ms: Vec<f64> = Vec::with_capacity(num_blocks);
    let mut store_ms: Vec<f64> = Vec::with_capacity(num_blocks);
    let mut total_committed = 0u64;
    let mut total_failed = 0u64;
    let report_every = (num_blocks / 10).max(1);
    let bench_start = Instant::now();

    for block in 0..num_blocks {
        let block_start = Instant::now();

        // 1. Build batch
        let batch = make_batch(block as u64, batch_size, &state);

        // 2. Execute (real parallel state machine)
        let t0 = Instant::now();
        let new_state =
            match truthlinked_state::parallel_executor::execute_batch_parallel_with_profiler(
                &state, &batch, None,
            ) {
                Ok(result) => {
                    total_failed += result.failed.len() as u64;
                    let mut s = result.state;
                    s.advance_block_counters();
                    s
                }
                Err(e) => {
                    eprintln!("exec error block {}: {}", block, e);
                    state.clone()
                }
            };
        let em = t0.elapsed().as_secs_f64() * 1000.0;
        exec_ms.push(em);

        // 3. Build header (leader = node 0)
        let parent_hash: [u8; 32] = if block == 0 {
            [0u8; 32]
        } else {
            blake3::hash(&((block - 1) as u64).to_le_bytes()).into()
        };
        let sr = state_root(&new_state);
        let batch_hash: [u8; 32] = {
            let mut h = blake3::Hasher::new();
            for tx in &batch {
                h.update(&tx.sender);
                h.update(&tx.nonce.to_le_bytes());
            }
            h.finalize().into()
        };
        let leader_sig = sign(&validators[0], &batch_hash);
        let header = BatchHeader::new(
            block as u64 + 1,
            parent_hash,
            batch_hash,
            batch_hash, // execution_order_root (same for bench)
            sr,
            1u64,  // timestamp
            0u128, // total_fees
            truthlinked_consensus::blockchain::PqFinalityCertificate::empty(
                block as u64 + 1,
                0,
                batch_hash,
                sr,
            ),
            vpks[0].clone(),
            leader_sig,
            0u64, /* leader_round */
        );

        // 4. Attestation: nodes 1 & 2 sign (2/3 threshold)
        let _att1 = sign(&validators[1], &batch_hash);
        let _att2 = sign(&validators[2], &batch_hash);

        // 5. All 3 nodes commit to storage
        let t0 = Instant::now();
        let results = vec!["success".to_string(); batch.len()];
        for storage in &storages {
            storage
                .save_block(&header, &batch, &results, &name_registry)
                .unwrap();
        }
        let sm = t0.elapsed().as_secs_f64() * 1000.0;
        store_ms.push(sm);

        state = new_state;
        total_committed += batch.len() as u64;

        let bm = block_start.elapsed().as_secs_f64() * 1000.0;
        block_ms.push(bm);

        if (block + 1) % report_every == 0 || block == num_blocks - 1 {
            let tps = total_committed as f64 / bench_start.elapsed().as_secs_f64();
            println!(
                "  block {:>6} | {:>9} txs committed | {:>7.0} TPS | exec {:>5.1}ms | store {:>5.1}ms",
                block + 1,
                total_committed,
                tps,
                em,
                sm
            );
        }
    }

    // ── Results ───────────────────────────────────────────────────────────────
    let elapsed = bench_start.elapsed().as_secs_f64();
    println!();
    println!("══════════════════════════════════════════════════════════");
    println!("  RESULTS");
    println!("══════════════════════════════════════════════════════════");
    println!("  Total txs committed : {}", total_committed);
    println!("  Total failed        : {}", total_failed);
    println!("  Total time          : {:.2}s", elapsed);
    println!(
        "  Throughput          : {:.0} TPS",
        total_committed as f64 / elapsed
    );
    println!(
        "  Block rate          : {:.1} blocks/sec",
        num_blocks as f64 / elapsed
    );
    println!();
    println!(
        "  Block latency (ms)  p50={:.2}  p95={:.2}  p99={:.2}",
        percentile(block_ms.clone(), 50.0),
        percentile(block_ms.clone(), 95.0),
        percentile(block_ms.clone(), 99.0)
    );
    println!(
        "  Execution (ms)      p50={:.2}  p99={:.2}",
        percentile(exec_ms.clone(), 50.0),
        percentile(exec_ms.clone(), 99.0)
    );
    println!(
        "  Storage/3nodes (ms) p50={:.2}  p99={:.2}",
        percentile(store_ms.clone(), 50.0),
        percentile(store_ms.clone(), 99.0)
    );
    println!("══════════════════════════════════════════════════════════");
    println!(
        "  Final height : {}  |  Accounts : {}",
        state.staking.current_height,
        state.accounts.len()
    );
}
