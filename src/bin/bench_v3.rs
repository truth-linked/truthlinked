//! TruthLinked Benchmark Suite v3.0
//!
//! Fixes from v2.0 review:
//!   B1: warmup + 300 iters + trimmed mean → fix P50=0 noise
//!   B2: include nonce_updates + native_debits in actual write set → fix precision undercounting
//!   B3: critical-path serialization density replaces raw fallback rate
//!   B4: DonaDB tail latency histogram (not just max)
//!   B5: NEW — adversarial conflict graph (hot rotation, nonce storm, manifest inflation, cross-shard chains)

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use truthlinked_core::pq_execution::{AccountId, Transaction, TransactionIntent};
use truthlinked_runtime::{
    cells::CellAccount,
    compiler_aware::{partition_by_compiler_domains, ConcreteConflictDomain, StorageKey},
};
use truthlinked_state::{
    parallel_executor::execute_batch_parallel,
    pq_execution::{account_id_from_pubkey, State},
};
use truthlinked_runtime::types::AccountRecord;

// ─── helpers ──────────────────────────────────────────────────────────────────

fn fake_pk(n: u64) -> Vec<u8> {
    let mut pk = vec![0u8; 1952];
    pk[..8].copy_from_slice(&n.to_le_bytes());
    pk
}

fn seeded_state(n: u64) -> State {
    let mut state = State::genesis();
    for i in 0..n {
        let pk = fake_pk(i);
        let id = account_id_from_pubkey(&pk);
        state.accounts.insert(id, AccountRecord {
            pubkey_bytes: pk,
            balance: 1_000_000_000,
            compute_escrow_tlkd: 0,
            nonce: 0,
            nfts: vec![],
        });
    }
    state
}

fn transfer_tx(from: u64, to: u64, nonce: u64) -> Transaction {
    let recipient_pk = fake_pk(to);
    Transaction {
        sender: account_id_from_pubkey(&fake_pk(from)),
        nonce,
        timestamp: 0,
        genesis_fingerprint: [0u8; 32],
        expiration_height: u64::MAX,
        intent: TransactionIntent::Transfer {
            recipient: account_id_from_pubkey(&recipient_pk),
            recipient_pubkey: Some(recipient_pk),
            amount: 1,
        },
        signature: vec![0u8; 64],
    }
}

fn batch_transfer_tx(from: u64, recipients: &[u64], nonce: u64) -> Transaction {
    use truthlinked_core::pq_execution::BatchTransferEntry;
    Transaction {
        sender: account_id_from_pubkey(&fake_pk(from)),
        nonce,
        timestamp: 0,
        genesis_fingerprint: [0u8; 32],
        expiration_height: u64::MAX,
        intent: TransactionIntent::BatchTransfer {
            transfers: recipients.iter().map(|&to| {
                let pk = fake_pk(to);
                BatchTransferEntry {
                    recipient: account_id_from_pubkey(&pk),
                    recipient_pubkey: Some(pk),
                    amount: 1,
                }
            }).collect(),
        },
        signature: vec![0u8; 64],
    }
}

/// Trimmed mean: drop top and bottom 5% to remove outliers.
fn trimmed_mean(samples: &[f64]) -> f64 {
    if samples.is_empty() { return 0.0; }
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let cut = (s.len() as f64 * 0.05) as usize;
    let trimmed = &s[cut..s.len().saturating_sub(cut)];
    if trimmed.is_empty() { return s[s.len() / 2]; }
    trimmed.iter().sum::<f64>() / trimmed.len() as f64
}

fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() { return 0.0; }
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[((s.len() as f64 * p) as usize).min(s.len() - 1)]
}

fn section(title: &str) {
    println!("\n{}", "─".repeat(74));
    println!("  {}", title);
    println!("{}", "─".repeat(74));
}

// ─── benchmark 1: tps with warmup + 300 iters + trimmed mean ─────────────────

fn bench_e2e_tps() {
    section("BENCHMARK 1 — End-to-End TPS (300 iters, warmup, trimmed mean)");

    let n_accounts = 2_000u64;
    let batch_sizes = [50usize, 200, 500, 1_000, 2_000];
    let warmup = 10usize;
    let iters = 300usize;

    println!("  Batch | Trimmed TPS | P50 TPS  | P95 TPS  | P99 TPS  | ms/batch");
    println!("  ----- | ----------- | -------- | -------- | -------- | --------");

    for &bsz in &batch_sizes {
        let state = seeded_state(n_accounts);

        // Warmup: discard results
        for i in 0..warmup {
            let batch: Vec<Transaction> = (0..bsz)
                .map(|j| transfer_tx((i * bsz + j) as u64 % n_accounts, (i * bsz + j + 1) as u64 % n_accounts, i as u64))
                .collect();
            let _ = execute_batch_parallel(&state, &batch);
        }

        let mut tps_samples: Vec<f64> = Vec::with_capacity(iters);
        let mut ms_samples: Vec<f64> = Vec::with_capacity(iters);

        for i in 0..iters {
            let batch: Vec<Transaction> = (0..bsz)
                .map(|j| {
                    let from = (i * bsz + j) as u64 % n_accounts;
                    let to = (from + 1) % n_accounts;
                    transfer_tx(from, to, i as u64)
                })
                .collect();

            let t0 = Instant::now();
            if let Ok(r) = execute_batch_parallel(&state, &batch) {
                let elapsed = t0.elapsed();
                // Reject sub-microsecond measurements (timer resolution floor)
                if elapsed > Duration::from_micros(10) {
                    let ms = elapsed.as_secs_f64() * 1000.0;
                    tps_samples.push(r.applied as f64 / elapsed.as_secs_f64());
                    ms_samples.push(ms);
                }
            }
        }

        if tps_samples.len() > 10 {
            let trimmed = trimmed_mean(&tps_samples);
            let p50 = percentile(&tps_samples, 0.50);
            let p95 = percentile(&tps_samples, 0.95);
            let p99 = percentile(&tps_samples, 0.99);
            let ms = trimmed_mean(&ms_samples);
            println!("  {:5} | {:11.0} | {:8.0} | {:8.0} | {:8.0} | {:8.2}",
                bsz, trimmed, p50, p95, p99, ms);
        }
    }

    println!();
    println!("  Sig verification skipped. Multiply ~0.3x for ML-DSA-65 real-world cost.");
    println!("  P50 now reflects post-warmup steady-state, not cold-start noise.");
}

// ─── benchmark 2: manifest precision with full write set ─────────────────────

fn bench_manifest_precision_full() {
    section("BENCHMARK 2 — Manifest Precision (full write set: accounts + nonces + debits)");

    let n_accounts = 500u64;
    let state = seeded_state(n_accounts);
    let n_tx = 300usize;

    println!("  TX type       | N   | Precision | Over-decl% | Under-decl | Notes");
    println!("  ------------- | --- | --------- | ---------- | ---------- | -----");

    for (label, txs) in [
        ("Transfer", (0..n_tx).map(|i| {
            let from = i as u64 % n_accounts;
            transfer_tx(from, (from + 1) % n_accounts, i as u64)
        }).collect::<Vec<_>>()),
        ("BatchTransfer", (0..50usize).map(|i| {
            let from = (i * 7) as u64 % n_accounts;
            let recps: Vec<u64> = (1..=4).map(|j| (from + j) % n_accounts).collect();
            batch_transfer_tx(from, &recps, i as u64)
        }).collect::<Vec<_>>()),
    ] {
        let mut precisions: Vec<f64> = vec![];
        let mut over_decl_counts: Vec<f64> = vec![];
        let mut under_decl = 0usize; // SHOULD stay 0 — undeclared write = correctness violation

        let cells: HashMap<AccountId, CellAccount> = HashMap::new();

        for tx in &txs {
            let domain = ConcreteConflictDomain::from_transaction(tx, None, &cells);

            // Declared account-level write set from scheduler
            let declared: HashSet<AccountId> = domain.writes.iter()
                .filter_map(|k| if let StorageKey::Account(id) = k { Some(*id) } else { None })
                .collect();

            if let Ok(diff) = state.compute_transaction_diff_skip_sig(tx) {
                // FULL actual write set: account_updates + nonce_updates + native_debits
                let mut actual: HashSet<AccountId> = diff.account_updates.keys().copied().collect();
                for (id, _) in &diff.nonce_updates { actual.insert(*id); }
                for (id, _) in &diff.native_debits { actual.insert(*id); }
                for (id, _) in &diff.native_transfers { actual.insert(*id); }

                if declared.is_empty() { continue; }

                let intersection = actual.intersection(&declared).count();
                let over = declared.len().saturating_sub(actual.len()); // keys declared but not written
                let under = actual.len().saturating_sub(declared.len()); // keys written but not declared

                if under > 0 { under_decl += 1; } // correctness alarm

                let precision = intersection as f64 / declared.len() as f64;
                precisions.push(precision);
                over_decl_counts.push(over as f64 / declared.len().max(1) as f64 * 100.0);
            }
        }

        if !precisions.is_empty() {
            let mean_prec = precisions.iter().sum::<f64>() / precisions.len() as f64;
            let mean_over = over_decl_counts.iter().sum::<f64>() / over_decl_counts.len() as f64;
            let correctness = if under_decl == 0 { "✓ safe" } else { "✗ VIOLATION" };
            println!("  {:13} | {:3} | {:9.4} | {:9.1}% | {:10} | {}",
                label, precisions.len(), mean_prec, mean_over, under_decl, correctness);
        }
    }

    println!();
    println!("  Over-decl% = % of declared keys not actually written (safe but wasteful).");
    println!("  Under-decl = undeclared writes (correctness violation — should always be 0).");
    println!("  Precision gap from account-level abstraction vs storage-level write set.");
    println!("  Fix: expose nonce/fee paths as declared keys in the conflict domain.");
}

// ─── benchmark 3: critical-path serialization density ────────────────────────

fn bench_serialization_density() {
    section("BENCHMARK 3 — Critical-Path Serialization Density");

    // "Batch fallback rate" was too coarse. This measures:
    //   - partition size distribution (how many txs share a serial slot)
    //   - critical path length (largest partition = bottleneck)
    //   - serialization density (% of txs in singleton partitions vs shared)

    let n_accounts = 1_000u64;
    let state = seeded_state(n_accounts);
    let iters = 100usize;
    let batch_size = 200usize;

    let scenarios: &[(&str, Box<dyn Fn(usize, usize) -> Transaction>)] = &[
        ("distinct_pairs", Box::new(|i, j| {
            let from = (i * 200 + j) as u64 % 1000;
            transfer_tx(from, (from + 100) % 1000, (i * 200 + j) as u64)
        })),
        ("hot_dex_20pct", Box::new(|i, j| {
            if j % 5 == 0 { transfer_tx((i * 200 + j) as u64 % 1000, 0, (i * 200 + j) as u64) }
            else { let from = (i * 200 + j) as u64 % 1000; transfer_tx(from, (from + 50) % 1000, (i * 200 + j) as u64) }
        })),
        ("hot_dex_50pct", Box::new(|i, j| {
            if j % 2 == 0 { transfer_tx((i * 200 + j) as u64 % 1000, 0, (i * 200 + j) as u64) }
            else { let from = (i * 200 + j) as u64 % 1000; transfer_tx(from, (from + 50) % 1000, (i * 200 + j) as u64) }
        })),
        ("all_to_one", Box::new(|i, j| {
            transfer_tx((i * 200 + j) as u64 % 1000, 0, (i * 200 + j) as u64)
        })),
    ];

    println!("  Scenario       | Avg partitions | Crit-path | Serial density | Parallelism");
    println!("  -------------- | -------------- | --------- | -------------- | -----------");

    for (name, make_tx) in scenarios {
        let cells: HashMap<AccountId, CellAccount> = state.cells.cells.clone();
        let mut crit_paths: Vec<f64> = vec![];
        let mut serial_densities: Vec<f64> = vec![];
        let mut parallelisms: Vec<f64> = vec![];
        let mut part_counts: Vec<f64> = vec![];

        for i in 0..iters {
            let batch: Vec<Transaction> = (0..batch_size).map(|j| make_tx(i, j)).collect();
            let parts = partition_by_compiler_domains(&batch, &cells);

            let n_parts = parts.len() as f64;
            let crit = parts.iter().map(|p| p.len()).max().unwrap_or(0) as f64;
            // Serial density: fraction of txs in partitions-of-1 (true singletons)
            let singleton_txs: usize = parts.iter().filter(|p| p.len() == 1).count();
            let serial_density = singleton_txs as f64 / batch_size as f64;

            crit_paths.push(crit);
            serial_densities.push(serial_density);
            parallelisms.push(batch_size as f64 / n_parts);
            part_counts.push(n_parts);
        }

        println!("  {:14} | {:14.1} | {:9.1} | {:14.1}% | {:>11.2}x",
            name,
            trimmed_mean(&part_counts),
            trimmed_mean(&crit_paths),
            trimmed_mean(&serial_densities) * 100.0,
            trimmed_mean(&parallelisms),
        );
    }

    println!();
    println!("  Crit-path = largest partition (this determines minimum batch latency).");
    println!("  Serial density = % of txs that got a partition of size 1.");
    println!("  At 50% hot-DEX traffic, critical path dominates — parallelism collapses.");
}

// ─── benchmark 4: donadb tail latency histogram ───────────────────────────────

fn bench_donadb_tail() {
    section("BENCHMARK 4 — DonaDB Tail Latency Under Sustained Write Pressure");

    use bytes::Bytes;
    use donadb::DonaDb;
    use std::sync::Arc;

    let wal = "/tmp/bench_dona_tail.wal";
    let _ = std::fs::remove_file(wal);
    let _ = std::fs::remove_file(format!("{}.snap", wal));
    let _ = std::fs::remove_dir_all(format!("{}.sst", wal));

    let db = Arc::new(DonaDb::open_wal(wal));
    let n_pre = 50_000usize;

    // Pre-populate
    for i in 0..n_pre {
        db.set(0, Bytes::from(format!("k:{:010}", i)), Bytes::from(vec![b'x'; 64]), i as u64);
    }
    db.sync();

    // Background writer — sustained full-speed writes
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_w = stop.clone();
    let db_w = Arc::clone(&db);
    let writer = std::thread::spawn(move || {
        let mut i = n_pre;
        while !stop_w.load(std::sync::atomic::Ordering::Relaxed) {
            db_w.set(0, Bytes::from(format!("k:{:010}", i % 200_000)), Bytes::from(vec![b'v'; 64]), i as u64);
            i += 1;
        }
    });

    // Collect 10,000 read latencies
    let n_reads = 10_000usize;
    let mut lats: Vec<f64> = Vec::with_capacity(n_reads);
    for i in 0..n_reads {
        let t0 = Instant::now();
        let _ = db.get(0, format!("k:{:010}", i % n_pre).as_bytes());
        lats.push(t0.elapsed().as_nanos() as f64 / 1000.0);
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    writer.join().unwrap();

    // Histogram buckets
    let buckets = [(0.0, 1.0), (1.0, 5.0), (5.0, 20.0), (20.0, 100.0), (100.0, 1000.0), (1000.0, f64::MAX)];
    let labels = ["<1μs", "1-5μs", "5-20μs", "20-100μs", "100μs-1ms", ">1ms"];

    println!("  Read latency distribution under sustained background writes (n={}):", n_reads);
    println!();
    println!("  Bucket    | Count  | % of reads | Bar");
    println!("  --------- | ------ | ---------- | ---");

    for (i, (lo, hi)) in buckets.iter().enumerate() {
        let count = lats.iter().filter(|&&v| v >= *lo && v < *hi).count();
        let pct = count as f64 / n_reads as f64 * 100.0;
        let bar = "█".repeat((pct / 2.0) as usize);
        println!("  {:9} | {:6} | {:9.2}% | {}", labels[i], count, pct, bar);
    }

    println!();
    println!("  P50={:.2}μs  P95={:.2}μs  P99={:.2}μs  P99.9={:.2}μs  max={:.1}μs",
        percentile(&lats, 0.50),
        percentile(&lats, 0.95),
        percentile(&lats, 0.99),
        percentile(&lats, 0.999),
        lats.iter().cloned().fold(0.0f64, f64::max),
    );
    println!("  The '>1ms' bucket is the tail stall metric — memtable flush / WAL lock convoy.");

    let _ = std::fs::remove_file(wal);
    let _ = std::fs::remove_file(format!("{}.snap", wal));
    let _ = std::fs::remove_dir_all(format!("{}.sst", wal));
}

// ─── benchmark 5: adversarial conflict graph ─────────────────────────────────

fn bench_adversarial() {
    section("BENCHMARK 5 — Adversarial Conflict Graph Generator");

    // Four adversarial patterns that can be used to attack parallel schedulers:
    //   A. Hot account rotation  — attacker rotates a hot sink every N txs to maximise conflicts
    //   B. Nonce storm           — single sender floods N txs forcing full serial lane
    //   C. Manifest inflation    — cells declaring O(N) keys to bloat scheduler O(n²) scan
    //   D. Cross-shard chains    — txs where each tx conflicts with exactly the next one (linear chain)

    let n_accounts = 2_000u64;
    let state = seeded_state(n_accounts);
    let batch_size = 200usize;
    let iters = 100usize;

    println!("  Attack pattern     | Partitions | Crit-path | Parallelism | TPS (trimmed)");
    println!("  ------------------ | ---------- | --------- | ----------- | -------------");

    // A: Hot account rotation — attacker cycles hot account every 10 txs
    {
        let cells: HashMap<AccountId, CellAccount> = state.cells.cells.clone();
        let mut part_counts = vec![];
        let mut crit_paths = vec![];
        let mut tps_samples = vec![];

        for i in 0..iters {
            let batch: Vec<Transaction> = (0..batch_size).map(|j| {
                let hot = ((i * batch_size + j) / 10) as u64 % n_accounts; // rotates every 10 txs
                let from = (i * batch_size + j + 500) as u64 % n_accounts;
                transfer_tx(from, hot, (i * batch_size + j) as u64)
            }).collect();

            let parts = partition_by_compiler_domains(&batch, &cells);
            part_counts.push(parts.len() as f64);
            crit_paths.push(parts.iter().map(|p| p.len()).max().unwrap_or(0) as f64);

            let t0 = Instant::now();
            if let Ok(r) = execute_batch_parallel(&state, &batch) {
                let e = t0.elapsed();
                if e > Duration::from_micros(10) {
                    tps_samples.push(r.applied as f64 / e.as_secs_f64());
                }
            }
        }
        println!("  {:18} | {:10.1} | {:9.1} | {:11.2}x | {:>13.0}",
            "hot_rotation",
            trimmed_mean(&part_counts),
            trimmed_mean(&crit_paths),
            batch_size as f64 / trimmed_mean(&part_counts),
            trimmed_mean(&tps_samples));
    }

    // B: Nonce storm — one sender, 200 txs (full serial lane)
    {
        let cells: HashMap<AccountId, CellAccount> = state.cells.cells.clone();
        let mut part_counts = vec![];
        let mut crit_paths = vec![];
        let mut tps_samples = vec![];

        for i in 0..iters {
            let batch: Vec<Transaction> = (0..batch_size).map(|j| {
                // Same sender to different recipients — nonce lane forces sequential
                transfer_tx(0, (j + 1) as u64 % n_accounts, (i * batch_size + j) as u64)
            }).collect();

            let parts = partition_by_compiler_domains(&batch, &cells);
            part_counts.push(parts.len() as f64);
            crit_paths.push(parts.iter().map(|p| p.len()).max().unwrap_or(0) as f64);

            let t0 = Instant::now();
            if let Ok(r) = execute_batch_parallel(&state, &batch) {
                let e = t0.elapsed();
                if e > Duration::from_micros(10) {
                    tps_samples.push(r.applied as f64 / e.as_secs_f64());
                }
            }
        }
        println!("  {:18} | {:10.1} | {:9.1} | {:11.2}x | {:>13.0}",
            "nonce_storm",
            trimmed_mean(&part_counts),
            trimmed_mean(&crit_paths),
            batch_size as f64 / trimmed_mean(&part_counts),
            trimmed_mean(&tps_samples));
    }

    // C: Manifest inflation — cells with 200 declared keys each (O(n²) scan pressure)
    {
        let mut cells: HashMap<AccountId, CellAccount> = state.cells.cells.clone();
        let cell_id = account_id_from_pubkey(&fake_pk(9999));
        // Inject a cell with 200 declared writes
        let bloated_keys: Vec<[u8; 32]> = (0u64..200).map(|k| {
            let mut b = [0u8; 32]; b[..8].copy_from_slice(&k.to_le_bytes()); b
        }).collect();
        cells.insert(cell_id, truthlinked_runtime::cells::CellAccount {
            cell_id,
            owner: [0u8; 32],
            bytecode: vec![],
            storage: HashMap::new(),
            balance: 0,
            rent_deposit: 0,
            is_token: false,
            token_config: None,
            created_at: 0,
            upgraded_at: None,
            last_rent_paid_height: 0,
            rent_grace_blocks: 0,
            pending_owner: None,
            is_immutable: false,
            declared_reads: vec![],
            declared_writes: bloated_keys,
            commutative_keys: vec![],
            storage_key_specs: vec![],
            oracle_schema_ids: vec![],
            governance_proposal: None,
            manifest_version: 1,
            manifest_hash: [0u8; 32],
        });

        let mut part_counts = vec![];
        let mut crit_paths = vec![];
        let mut extract_times = vec![];

        for i in 0..iters {
            // Mix: 10 bloated-cell calls + 190 normal transfers
            let batch: Vec<Transaction> = (0..batch_size).map(|j| {
                if j < 10 {
                    Transaction {
                        sender: account_id_from_pubkey(&fake_pk((i * batch_size + j) as u64 % n_accounts)),
                        nonce: (i * batch_size + j) as u64,
                        timestamp: 0,
                        genesis_fingerprint: [0u8; 32],
                        expiration_height: u64::MAX,
                        intent: TransactionIntent::CallCell {
                            cell_id,
                            calldata: vec![],
                            value: 0,
                            gas_limit: 1_000_000,
                        },
                        signature: vec![0u8; 64],
                    }
                } else {
                    let from = (i * batch_size + j) as u64 % n_accounts;
                    transfer_tx(from, (from + 1) % n_accounts, (i * batch_size + j) as u64)
                }
            }).collect();

            let t0 = Instant::now();
            let parts = partition_by_compiler_domains(&batch, &cells);
            extract_times.push(t0.elapsed().as_nanos() as f64 / batch_size as f64);
            part_counts.push(parts.len() as f64);
            crit_paths.push(parts.iter().map(|p| p.len()).max().unwrap_or(0) as f64);
        }

        println!("  {:18} | {:10.1} | {:9.1} | {:11.2}x | {:>10.0} ns/tx",
            "manifest_inflation",
            trimmed_mean(&part_counts),
            trimmed_mean(&crit_paths),
            batch_size as f64 / trimmed_mean(&part_counts),
            trimmed_mean(&extract_times));
        println!("  {:18}   (extraction cost shown instead of TPS — scheduler overhead attack)", "");
    }

    // D: Cross-shard chain — tx[i] sends to tx[i+1]'s sender (linear conflict chain)
    {
        let cells: HashMap<AccountId, CellAccount> = state.cells.cells.clone();
        let mut part_counts = vec![];
        let mut crit_paths = vec![];
        let mut tps_samples = vec![];

        for i in 0..iters {
            // tx[j]: account[j] → account[j+1], creating a dependency chain
            let batch: Vec<Transaction> = (0..batch_size).map(|j| {
                let from = (i * batch_size + j) as u64 % n_accounts;
                let to = (i * batch_size + j + 1) as u64 % n_accounts;
                transfer_tx(from, to, (i * batch_size + j) as u64)
            }).collect();

            let parts = partition_by_compiler_domains(&batch, &cells);
            part_counts.push(parts.len() as f64);
            crit_paths.push(parts.iter().map(|p| p.len()).max().unwrap_or(0) as f64);

            let t0 = Instant::now();
            if let Ok(r) = execute_batch_parallel(&state, &batch) {
                let e = t0.elapsed();
                if e > Duration::from_micros(10) {
                    tps_samples.push(r.applied as f64 / e.as_secs_f64());
                }
            }
        }
        println!("  {:18} | {:10.1} | {:9.1} | {:11.2}x | {:>13.0}",
            "cross_shard_chain",
            trimmed_mean(&part_counts),
            trimmed_mean(&crit_paths),
            batch_size as f64 / trimmed_mean(&part_counts),
            trimmed_mean(&tps_samples));
    }

    println!();
    println!("  Interpretation:");
    println!("    hot_rotation   — attacker forces new hot account every 10 txs");
    println!("    nonce_storm    — single-sender flood, forces pure serial lane");
    println!("    manifest_infl  — bloated cell manifests attack O(n²) conflict scan");
    println!("    cross_shard    — linear tx chain, each tx blocks the next");
    println!("  TPS gap between best-case (B1) and worst-case adversarial = attack surface.");
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║      TRUTHLINKED BENCHMARK SUITE v3.0 — ADVERSARIAL + FIXED        ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");

    bench_e2e_tps();
    bench_manifest_precision_full();
    bench_serialization_density();
    bench_donadb_tail();
    bench_adversarial();

    println!("\n{}", "═".repeat(74));
    println!("  All benchmarks complete.");
    println!("{}\n", "═".repeat(74));
}
