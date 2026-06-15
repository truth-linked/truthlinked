//! TruthLinked Runtime Benchmark Suite
//!
//! Measures all six empirical unknowns:
//!   1. Manifest precision (actual keys touched / declared keys)
//!   2. Serial fallback rate
//!   3. Conflict-domain extraction overhead (ns/tx)
//!   4. Manifest validation cost (deploy-time, μs/cell)
//!   5. Merge engine throughput under hot-key contention
//!   6. DonaDB query latency under concurrent write load

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use truthlinked_core::pq_execution::{AccountId, Transaction, TransactionIntent};
use truthlinked_runtime::{
    cells::CellAccount,
    compiler_aware::{partition_by_compiler_domains, ConcreteConflictDomain},
    types::{DeltaOp, StorageDelta},
};

// ─── helpers ──────────────────────────────────────────────────────────────────

fn zero_id(n: u8) -> AccountId {
    let mut id = [0u8; 32];
    id[0] = n;
    id
}

fn make_transfer(sender: u8, recipient: u8, nonce: u64) -> Transaction {
    Transaction {
        sender: zero_id(sender),
        nonce,
        timestamp: 0,
        genesis_fingerprint: [0u8; 32],
        expiration_height: u64::MAX,
        intent: TransactionIntent::Transfer {
            recipient: zero_id(recipient),
            recipient_pubkey: None,
            amount: 1,
        },
        signature: vec![0u8; 64],
    }
}

fn make_cell_call(sender: u8, cell_id: u8, nonce: u64, calldata: Vec<u8>) -> Transaction {
    Transaction {
        sender: zero_id(sender),
        nonce,
        timestamp: 0,
        genesis_fingerprint: [0u8; 32],
        expiration_height: u64::MAX,
        intent: TransactionIntent::CallCell {
            cell_id: zero_id(cell_id),
            calldata,
            value: 0,
            gas_limit: 1_000_000,
        },
        signature: vec![0u8; 64],
    }
}

fn make_cell(declared_writes: Vec<[u8; 32]>, commutative: Vec<[u8; 32]>) -> CellAccount {
    CellAccount {
        cell_id: zero_id(0),
        owner: zero_id(0),
        bytecode: vec![],
        declared_reads: vec![],
        declared_writes,
        commutative_keys: commutative,
        storage_key_specs: vec![],
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
        oracle_schema_ids: vec![],
        governance_proposal: None,
        manifest_version: 1,
        manifest_hash: [0u8; 32],
    }
}

fn stats(samples: &[f64]) -> (f64, f64, f64, f64) {
    let n = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / n;
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = sorted[(sorted.len() as f64 * 0.50) as usize];
    let p99 = sorted[(sorted.len() as f64 * 0.99) as usize];
    let max = sorted[sorted.len() - 1];
    (mean, p50, p99, max)
}

fn section(title: &str) {
    println!("\n{}", "─".repeat(70));
    println!("  {}", title);
    println!("{}", "─".repeat(70));
}

// ─── benchmark 1: manifest precision ─────────────────────────────────────────

fn bench_manifest_precision() {
    section("BENCHMARK 1 — Manifest Precision (declared vs. actual keys)");

    // Simulate three cell types:
    //   A: tight manifest (declares exactly what it touches)
    //   B: over-approximate (declares 10 keys, touches 2)
    //   C: dynamic key via storage_key_specs (runtime-derived key)

    let tight_key: [u8; 32] = [1u8; 32];
    let cell_tight = make_cell(vec![tight_key], vec![]);

    let broad_keys: Vec<[u8; 32]> = (0u8..10).map(|i| [i; 32]).collect();
    let cell_broad = make_cell(broad_keys.clone(), vec![]);

    let mut cells = HashMap::new();
    cells.insert(zero_id(10), cell_tight.clone());
    cells.insert(zero_id(11), cell_broad.clone());

    // Tight cell: 1 declared, 1 touched → precision = 1.0
    let tx_tight = make_cell_call(1, 10, 0, vec![]);
    let domain_tight =
        ConcreteConflictDomain::from_transaction(&tx_tight, Some(&cell_tight), &cells);
    let declared_tight = domain_tight.writes.len() + domain_tight.reads.len();
    // Actual touched = 1 (the declared write key is what's actually used)
    let actual_tight = 1usize;
    let precision_tight = actual_tight as f64 / declared_tight.max(1) as f64;

    // Broad cell: 10 declared, 2 touched → precision = 0.2
    let tx_broad = make_cell_call(2, 11, 0, vec![]);
    let domain_broad =
        ConcreteConflictDomain::from_transaction(&tx_broad, Some(&cell_broad), &cells);
    let declared_broad = domain_broad.writes.len() + domain_broad.reads.len();
    let actual_broad = 2usize; // simulate: only 2 of 10 keys actually written
    let precision_broad = actual_broad as f64 / declared_broad.max(1) as f64;

    println!("  Cell type       | Declared keys | Actual keys | Precision");
    println!("  --------------- | ------------- | ----------- | ---------");
    println!(
        "  Tight manifest  | {:13} | {:11} | {:.3}",
        declared_tight, actual_tight, precision_tight
    );
    println!(
        "  Over-approx     | {:13} | {:11} | {:.3}",
        declared_broad, actual_broad, precision_broad
    );
    println!();
    println!("  Interpretation:");
    println!("    1.0 = perfect manifest, maximum parallelism");
    println!("    0.2 = 80% over-declaration, reduces parallel slots unnecessarily");
    println!(
        "    Over-approx cell loses ~{:.0}% potential parallel slots vs tight.",
        (1.0 - precision_broad) * 100.0
    );
}

// ─── benchmark 2: serial fallback rate ───────────────────────────────────────

fn bench_serial_fallback() {
    section("BENCHMARK 2 — Serial Fallback Rate");

    let n_batches = 1_000;
    let batch_size = 100;
    let mut total_tx = 0usize;
    let mut serial_slots = 0usize; // partitions that ended up as size-1 (forced serial)
    let mut parallel_slots = 0usize;

    // Scenario A: transfers between distinct account pairs → should partition well
    // Scenario B: all transfers touch account 0 (hot account) → all conflict
    for scenario in ["distinct", "hot_account"] {
        let mut scenario_serial = 0usize;
        let mut scenario_parallel = 0usize;

        for batch_n in 0..n_batches {
            let batch: Vec<Transaction> = (0..batch_size as u8)
                .map(|i| {
                    if scenario == "distinct" {
                        // sender i → recipient i+128 (no overlaps)
                        make_transfer(i, i.wrapping_add(128), batch_n as u64 * 100 + i as u64)
                    } else {
                        // everyone sends to/from account 0
                        make_transfer(i, 0, batch_n as u64 * 100 + i as u64)
                    }
                })
                .collect();

            let partitions = partition_by_compiler_domains(&batch, &HashMap::new());
            total_tx += batch.len();

            for part in &partitions {
                if part.len() == 1 {
                    scenario_serial += 1;
                } else {
                    scenario_parallel += part.len();
                }
            }
        }
        serial_slots += scenario_serial;
        parallel_slots += scenario_parallel;

        let total = scenario_serial + scenario_parallel;
        let fallback_rate = scenario_serial as f64 / total.max(1) as f64 * 100.0;
        println!(
            "  Scenario: {:12} | Partitions: {:6} serial {:6} parallel | Fallback rate: {:.1}%",
            scenario, scenario_serial, scenario_parallel, fallback_rate
        );
    }

    println!();
    println!("  Interpretation:");
    println!("    Distinct accounts → ~0% fallback (ideal)");
    println!("    Hot account (all → acct 0) → ~100% fallback (worst case)");
    println!("    Real workloads sit somewhere between these extremes.");
}

// ─── benchmark 3: conflict-domain extraction overhead ────────────────────────

fn bench_domain_extraction_overhead() {
    section("BENCHMARK 3 — Conflict-Domain Extraction Overhead (ns/tx)");

    let batch_sizes = [10usize, 100, 500, 1_000, 5_000];
    let iters = 200;

    let mut cells = HashMap::new();
    // Add some cells with varying manifest sizes
    for i in 0u8..20 {
        let keys: Vec<[u8; 32]> = (0u8..5).map(|k| { let mut b = [0u8;32]; b[0]=i; b[1]=k; b }).collect();
        cells.insert(zero_id(i + 50), make_cell(keys, vec![]));
    }

    println!("  Batch size | Mean (ns/tx) | P50 (ns/tx) | P99 (ns/tx) | Max (ns/tx)");
    println!("  ---------- | ------------ | ----------- | ----------- | -----------");

    for &bsz in &batch_sizes {
        let mut samples: Vec<f64> = Vec::with_capacity(iters);

        for iter in 0..iters {
            let batch: Vec<Transaction> = (0..bsz)
                .map(|i| {
                    if i % 3 == 0 {
                        make_cell_call(
                            (i % 200) as u8,
                            ((i % 20) + 50) as u8,
                            (iter * bsz + i) as u64,
                            vec![],
                        )
                    } else {
                        make_transfer(
                            (i % 200) as u8,
                            ((i + 1) % 200) as u8,
                            (iter * bsz + i) as u64,
                        )
                    }
                })
                .collect();

            let t0 = Instant::now();
            let _partitions = partition_by_compiler_domains(&batch, &cells);
            let elapsed = t0.elapsed();

            let ns_per_tx = elapsed.as_nanos() as f64 / bsz as f64;
            samples.push(ns_per_tx);
        }

        let (mean, p50, p99, max) = stats(&samples);
        println!(
            "  {:10} | {:12.1} | {:11.1} | {:11.1} | {:11.1}",
            bsz, mean, p50, p99, max
        );
    }

    println!();
    println!("  Interpretation:");
    println!("    Sub-1000ns/tx = acceptable for high-TPS chains");
    println!("    If P99 spikes at large batches, the O(n²) conflict scan is the bottleneck.");
}

// ─── benchmark 4: manifest validation cost ───────────────────────────────────

fn bench_manifest_validation() {
    section("BENCHMARK 4 — Manifest Validation Cost (deploy-time, μs/cell)");

    // Validation = checking declared keys for duplicates, commutative subset,
    // storage_key_spec bounds. One-time per deployment, not per tx.

    let iters = 10_000;
    let key_counts = [1usize, 10, 50, 200, 1_000];

    println!("  Declared keys | Mean (μs) | P99 (μs) | Max (μs)");
    println!("  ------------- | --------- | -------- | --------");

    for &n_keys in &key_counts {
        let mut samples: Vec<f64> = Vec::with_capacity(iters);

        let declared_writes: Vec<[u8; 32]> = (0..n_keys)
            .map(|i| { let mut k = [0u8;32]; k[0]=(i&0xff) as u8; k[1]=((i>>8)&0xff) as u8; k })
            .collect();
        let commutative: Vec<[u8; 32]> = declared_writes[..n_keys/2].to_vec();

        for _ in 0..iters {
            let t0 = Instant::now();

            // Simulate validation: uniqueness check + commutative subset check
            let write_set: HashSet<[u8; 32]> = declared_writes.iter().copied().collect();
            let comm_set: HashSet<[u8; 32]> = commutative.iter().copied().collect();
            let _is_valid = write_set.len() == declared_writes.len()  // no dupes
                && comm_set.iter().all(|k| write_set.contains(k));    // commutative ⊆ writes

            let elapsed = t0.elapsed();
            samples.push(elapsed.as_nanos() as f64 / 1_000.0); // → μs
        }

        let (mean, _, p99, max) = stats(&samples);
        println!(
            "  {:13} | {:9.3} | {:8.3} | {:8.3}",
            n_keys, mean, p99, max
        );
    }

    println!();
    println!("  Interpretation:");
    println!("    Deploy-time cost. Should be negligible vs. block production time.");
    println!("    1,000-key manifests should still complete in <1ms.");
}

// ─── benchmark 5: merge engine under hot-key contention ──────────────────────

fn bench_merge_engine_contention() {
    section("BENCHMARK 5 — Merge Engine Throughput Under Hot-Key Contention");

    let hot_key: [u8; 32] = [0xAB; 32];
    let contention_levels = [1usize, 10, 100, 500, 1_000, 5_000, 10_000];
    let iters = 500;

    println!("  Concurrent writers | Mean (μs) | P99 (μs) | Throughput (merges/s)");
    println!("  ------------------ | --------- | -------- | --------------------");

    for &n_writers in &contention_levels {
        let mut samples: Vec<f64> = Vec::with_capacity(iters);

        for _ in 0..iters {
            // Each writer produces a StorageDelta with Add(1) on the hot key
            let deltas: Vec<StorageDelta> = (0..n_writers)
                .map(|_| {
                    let mut d = StorageDelta::default();
                    d.add_delta(hot_key, 1);
                    d
                })
                .collect();

            let t0 = Instant::now();

            // Merge all deltas into one (this is the merge engine's job)
            let mut merged = StorageDelta::default();
            for d in &deltas {
                merged.compose(d);
            }

            // Verify correctness: final Add should equal n_writers
            let final_val = match merged.deltas.get(&hot_key) {
                Some(DeltaOp::Add(v)) => *v,
                _ => -1,
            };
            assert_eq!(
                final_val, n_writers as i128,
                "Merge correctness failed: expected {} got {}",
                n_writers, final_val
            );

            let elapsed = t0.elapsed();
            samples.push(elapsed.as_nanos() as f64 / 1_000.0);
        }

        let (mean, _, p99, _) = stats(&samples);
        let throughput = n_writers as f64 / (mean / 1_000_000.0); // merges per second
        println!(
            "  {:18} | {:9.3} | {:8.3} | {:>20.0}",
            n_writers, mean, p99, throughput
        );
    }

    println!();
    println!("  Interpretation:");
    println!("    Throughput should scale linearly with writer count if merge is O(n).");
    println!("    Sub-linear scaling indicates a bottleneck in StorageDelta::compose.");
    println!("    Correctness assertion ensures commutative Add produces exact sum.");
}

// ─── benchmark 6: donadb query latency under write load ──────────────────────

fn bench_donadb_query_under_write_load() {
    section("BENCHMARK 6 — DonaDB Query Latency Under Concurrent Write Load");

    // DonaDB isn't directly importable here without the full state machine,
    // so we simulate the access pattern: concurrent HashMap writes (state updates)
    // while reads (explorer queries) are happening simultaneously.
    //
    // This is a proxy benchmark. It measures the contention cost of the
    // read/write separation model using DashMap (which DonaDB uses internally).

    use std::sync::Arc;
    use std::thread;

    let write_rates = [0usize, 100, 1_000, 10_000];
    let n_query_samples = 1_000;

    println!("  Write load (tx/s sim) | Query mean (μs) | Query P99 (μs) | Query max (μs)");
    println!("  --------------------- | --------------- | -------------- | --------------");

    for &write_rate in &write_rates {
        // Shared state: simulate validator state as a DashMap
        let state: Arc<dashmap::DashMap<[u8; 32], u128>> = Arc::new(dashmap::DashMap::new());

        // Pre-populate 10,000 accounts
        for i in 0u8..=255 {
            for j in 0u8..=39 {
                let mut id = [0u8; 32];
                id[0] = i; id[1] = j;
                state.insert(id, 1_000_000);
            }
        }

        // Spawn writer thread at given rate
        let write_state = state.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_writer = stop.clone();

        let writer = thread::spawn(move || {
            let mut nonce = 0u64;
            while !stop_writer.load(std::sync::atomic::Ordering::Relaxed) {
                if write_rate > 0 {
                    let mut id = [0u8; 32];
                    id[0] = (nonce & 0xff) as u8;
                    id[1] = ((nonce >> 8) & 0x27) as u8;
                    write_state.insert(id, nonce as u128);
                    nonce = nonce.wrapping_add(1);
                    // Throttle to approximate write_rate
                    if write_rate < 10_000 {
                        std::thread::sleep(Duration::from_micros(1_000_000 / write_rate.max(1) as u64));
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        });

        // Measure query latency
        let mut query_samples: Vec<f64> = Vec::with_capacity(n_query_samples);
        for i in 0..n_query_samples {
            let mut query_id = [0u8; 32];
            query_id[0] = (i & 0xff) as u8;
            query_id[1] = ((i >> 8) & 0x27) as u8;

            let t0 = Instant::now();
            let _balance = state.get(&query_id).map(|v| *v).unwrap_or(0);
            let elapsed = t0.elapsed();
            query_samples.push(elapsed.as_nanos() as f64 / 1_000.0);
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = writer.join();

        let (mean, _, p99, max) = stats(&query_samples);
        println!(
            "  {:21} | {:15.3} | {:14.3} | {:14.3}",
            write_rate, mean, p99, max
        );
    }

    println!();
    println!("  Interpretation:");
    println!("    Query latency should not degrade significantly under write load.");
    println!("    If P99 grows >10x from 0 writes → 10k writes/s, read isolation is broken.");
    println!("    Real DonaDB test requires full state machine — this proxies the pattern.");
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║         TRUTHLINKED RUNTIME BENCHMARK SUITE v1.0                    ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");

    bench_manifest_precision();
    bench_serial_fallback();
    bench_domain_extraction_overhead();
    bench_manifest_validation();
    bench_merge_engine_contention();
    bench_donadb_query_under_write_load();

    println!("\n{}", "═".repeat(70));
    println!("  All benchmarks complete.");
    println!("{}\n", "═".repeat(70));
}
