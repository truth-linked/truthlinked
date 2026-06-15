//! TruthLinked Benchmark Suite v4.0 — Three-Layer Isolation
//!
//! Fixes v3 issues:
//!   - Split into 3 independent measurement layers (no coupling)
//!   - TPS computed from ms/batch directly (no timer-floor filtering)
//!   - Each layer is independently interpretable
//!
//! Layer 1: Pure Scheduler  — no state, no WAL, measures ns/tx partition cost only
//! Layer 2: State Engine    — in-memory state application, no WAL, measures executor throughput
//! Layer 3: Storage Engine  — DonaDB isolated, no executor, measures WAL+SST latency

use std::collections::HashMap;
use std::time::Instant;

use truthlinked_core::pq_execution::{AccountId, Transaction, TransactionIntent};
use truthlinked_runtime::{
    cells::CellAccount,
    compiler_aware::partition_by_compiler_domains,
    types::AccountRecord,
};
use truthlinked_state::{
    parallel_executor::execute_batch_parallel,
    pq_execution::{account_id_from_pubkey, State},
};

// ─── helpers ──────────────────────────────────────────────────────────────────

fn fake_pk(n: u64) -> Vec<u8> {
    let mut pk = vec![0u8; 1952];
    pk[..8].copy_from_slice(&n.to_le_bytes());
    pk
}

fn seeded_state(n: u64) -> State {
    let mut s = State::genesis();
    for i in 0..n {
        let pk = fake_pk(i);
        let id = account_id_from_pubkey(&pk);
        s.accounts.insert(id, AccountRecord {
            pubkey_bytes: pk, balance: 1_000_000_000,
            compute_escrow_tlkd: 0, nonce: 0, nfts: vec![],
        });
    }
    s
}

fn transfer_tx(from: u64, to: u64, nonce: u64) -> Transaction {
    let rpk = fake_pk(to);
    Transaction {
        sender: account_id_from_pubkey(&fake_pk(from)),
        nonce, timestamp: 0, genesis_fingerprint: [0u8; 32], expiration_height: u64::MAX,
        intent: TransactionIntent::Transfer {
            recipient: account_id_from_pubkey(&rpk),
            recipient_pubkey: Some(rpk),
            amount: 1,
        },
        signature: vec![0u8; 64],
    }
}

fn pct(mut s: Vec<f64>, p: f64) -> f64 {
    if s.is_empty() { return 0.0; }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[((s.len() as f64 * p) as usize).min(s.len() - 1)]
}

fn tmean(samples: &[f64]) -> f64 {
    if samples.is_empty() { return 0.0; }
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let cut = (s.len() as f64 * 0.05) as usize;
    let t = &s[cut..s.len().saturating_sub(cut)];
    if t.is_empty() { return s[s.len()/2]; }
    t.iter().sum::<f64>() / t.len() as f64
}

fn section(t: &str) {
    println!("\n{}", "─".repeat(74));
    println!("  {}", t);
    println!("{}", "─".repeat(74));
}

// ─── layer 1: pure scheduler ─────────────────────────────────────────────────

fn layer1_scheduler() {
    section("LAYER 1 — Pure Scheduler (no state, no WAL)");
    println!("  Measures: partition_by_compiler_domains() only");
    println!("  Isolates: O(n²) conflict scan cost, parallelism quality");
    println!();

    let iters = 100usize;
    let batch_sizes = [50usize, 200, 500, 1_000];
    let cells: HashMap<AccountId, CellAccount> = HashMap::new();

    let patterns: &[(&str, Box<dyn Fn(usize, usize) -> Transaction>)] = &[
        ("distinct",     Box::new(|i,j| transfer_tx((i*5000+j) as u64%10000, (i*5000+j+5000) as u64%10000, (i*5000+j) as u64))),
        ("hot_20pct",    Box::new(|i,j| if j%5==0 { transfer_tx((i*5000+j) as u64%10000, 0, (i*5000+j) as u64) } else { transfer_tx((i*5000+j) as u64%10000, (i*5000+j+1) as u64%10000, (i*5000+j) as u64) })),
        ("nonce_storm",  Box::new(|i,j| transfer_tx(0, (j+1) as u64%10000, (i*5000+j) as u64))),
        ("hot_rotation", Box::new(|i,j| { let hot=((i*5000+j)/10) as u64%10000; transfer_tx((i*5000+j+500) as u64%10000, hot, (i*5000+j) as u64) })),
    ];

    println!("  Pattern      | Batch | ns/tx (mean) | ns/tx (p99) | Parallelism");
    println!("  ------------ | ----- | ------------ | ----------- | -----------");

    for (name, make_tx) in patterns {
        for &bsz in &batch_sizes {
            let mut ns: Vec<f64> = Vec::with_capacity(iters);
            let mut para: Vec<f64> = Vec::with_capacity(iters);
            // warmup
            for i in 0..10 { let b: Vec<_>=(0..bsz).map(|j|make_tx(i,j)).collect(); let _=partition_by_compiler_domains(&b,&cells); }
            for i in 0..iters {
                let b: Vec<Transaction>=(0..bsz).map(|j|make_tx(i,j)).collect();
                let t0=Instant::now();
                let p=partition_by_compiler_domains(&b,&cells);
                ns.push(t0.elapsed().as_nanos() as f64/bsz as f64);
                para.push(bsz as f64/p.len() as f64);
            }
            println!("  {:12} | {:5} | {:12.1} | {:11.1} | {:11.2}x",
                name, bsz, tmean(&ns), pct(ns,0.99), tmean(&para));
        }
        println!();
    }
}

// ─── layer 2: state engine (in-memory, no wal) ────────────────────────────────

fn layer2_state_engine() {
    section("LAYER 2 — State Engine (in-memory executor, no WAL)");
    println!("  Measures: execute_batch_parallel() on pre-seeded in-memory State");
    println!("  Isolates: executor + merge throughput, zero storage I/O");
    println!();

    let n_accounts = 5_000u64;
    let iters = 200usize;
    let batch_sizes = [50usize, 200, 500, 1_000, 2_000];
    let state = seeded_state(n_accounts);

    println!("  Batch | TPS       | ms/batch | P50 ms | P95 ms | P99 ms | Applied%");
    println!("  ----- | --------- | -------- | ------ | ------ | ------ | --------");

    for &bsz in &batch_sizes {
        // warmup
        for i in 0..20 {
            let b: Vec<_>=(0..bsz).map(|j| transfer_tx((i*bsz+j) as u64%n_accounts,(i*bsz+j+1) as u64%n_accounts,i as u64)).collect();
            let _=execute_batch_parallel(&state,&b);
        }
        let mut ms: Vec<f64>=Vec::with_capacity(iters);
        let mut apct: Vec<f64>=Vec::with_capacity(iters);
        for i in 0..iters {
            let batch: Vec<_>=(0..bsz).map(|j|{ let f=(i*bsz+j) as u64%n_accounts; transfer_tx(f,(f+1)%n_accounts,i as u64) }).collect();
            let t0=Instant::now();
            if let Ok(r)=execute_batch_parallel(&state,&batch) {
                ms.push(t0.elapsed().as_secs_f64()*1000.0);
                apct.push(r.applied as f64/bsz as f64*100.0);
            }
        }
        if ms.len()>10 {
            let mean_ms=tmean(&ms);
            let tps=(bsz as f64/(mean_ms/1000.0)) as u64;
            println!("  {:5} | {:9} | {:8.2} | {:6.2} | {:6.2} | {:6.2} | {:7.1}%",
                bsz, tps, mean_ms, pct(ms.clone(),0.50), pct(ms.clone(),0.95), pct(ms.clone(),0.99), tmean(&apct));
        }
    }

    // hot account comparison
    println!();
    println!("  Workload comparison at batch=500:");
    for (label, hot_pct) in [("distinct_100%",0usize),("hot_20%",20),("hot_50%",50),("all_to_one",100)] {
        let mut ms: Vec<f64>=Vec::with_capacity(iters);
        for i in 0..iters {
            let batch: Vec<_>=(0..500usize).map(|j|{
                let flip = (j*100)/500;
                if flip < hot_pct { transfer_tx((i*500+j) as u64%n_accounts, 0, (i*500+j) as u64) }
                else { let f=(i*500+j) as u64%n_accounts; transfer_tx(f,(f+1)%n_accounts,(i*500+j) as u64) }
            }).collect();
            let t0=Instant::now();
            if let Ok(_)=execute_batch_parallel(&state,&batch) { ms.push(t0.elapsed().as_secs_f64()*1000.0); }
        }
        if ms.len()>10 {
            let mean_ms=tmean(&ms);
            println!("  {:15}: {:6.0} TPS  ({:.2}ms mean, p99={:.2}ms)",
                label, 500.0/(mean_ms/1000.0), mean_ms, pct(ms,0.99));
        }
    }

    println!();
    println!("  TPS = batch_size / mean_ms * 1000. No timer filtering. Applied% = tx success rate.");
}

// ─── layer 3: storage engine (donadb isolated) ────────────────────────────────

fn layer3_storage() {
    section("LAYER 3 — Storage Engine (DonaDB isolated, no executor)");
    println!("  Measures: WAL write TPS, read latency, versioned reads");
    println!("  Isolates: pure storage I/O, no scheduler or executor");
    println!();

    use bytes::Bytes;
    use donadb::DonaDb;
    use std::sync::Arc;

    let wal = "/tmp/bench_v4_l3.wal";
    let clean = || {
        let _ = std::fs::remove_file(wal);
        let _ = std::fs::remove_file(format!("{}.snap", wal));
        let _ = std::fs::remove_dir_all(format!("{}.sst", wal));
    };
    clean();

    // 3a: write throughput by value size
    println!("  3a. WAL write TPS by value size (100k ops, sequential vs 8-thread):");
    println!("  Val bytes | Sequential  | 4-thread    | 8-thread");
    println!("  --------- | ----------- | ----------- | --------");

    for vsz in [32usize, 256, 1024, 4096] {
        let n = 100_000usize;
        let val = Bytes::from(vec![b'x'; vsz]);
        clean();

        let db = DonaDb::open_wal(wal);
        let t = Instant::now();
        for i in 0..n { db.set(0, Bytes::from(format!("k:{:010}",i)), val.clone(), i as u64); }
        db.sync();
        let seq = n as f64 / t.elapsed().as_secs_f64();
        clean();

        let tps_n = |nthreads: usize| {
            let db = Arc::new(DonaDb::open_wal(wal));
            let t = Instant::now();
            let hs: Vec<_> = (0..nthreads).map(|tid| {
                let db = Arc::clone(&db); let val = val.clone();
                std::thread::spawn(move || {
                    let per = n / nthreads;
                    let mut wb = donadb::WriteBatch::new();
                    let mut wbn = 0usize;
                    for i in 0..per {
                        wb.set(Bytes::from(format!("t{}:{:010}", tid, i)), val.clone());
                        wbn += 1;
                        if wbn >= 500 { db.write_batch(wb); wb = donadb::WriteBatch::new(); wbn = 0; }
                    }
                    if wbn > 0 { db.write_batch(wb); }
                })
            }).collect();
            for h in hs { h.join().unwrap(); }
            db.sync();
            let tps = n as f64 / t.elapsed().as_secs_f64();
            clean();
            tps
        };

        println!("  {:9} | {:11.0} | {:11.0} | {:8.0}", vsz, seq, tps_n(4), tps_n(8));
    }

    // 3b: read latency histogram under write pressure
    println!();
    println!("  3b. Read latency under write pressure (5k reads, 20k pre-populated keys):");
    println!("  Pressure | P50 (μs) | P95 (μs) | P99 (μs) | P99.9 (μs) | >1ms");
    println!("  -------- | -------- | -------- | -------- | ---------- | ----");

    for pressure in ["none", "moderate", "full"] {
        clean();
        let db = Arc::new(DonaDb::open_wal(wal));
        let n_pre = 20_000usize;
        for i in 0..n_pre { db.set(0, Bytes::from(format!("r:{:08}",i)), Bytes::from_static(b"val"), i as u64); }
        db.sync();

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sw = stop.clone(); let dw = Arc::clone(&db);
        let writer = std::thread::spawn(move || {
            let mut i = n_pre;
            while !sw.load(std::sync::atomic::Ordering::Relaxed) {
                match pressure {
                    "none"     => { std::thread::sleep(std::time::Duration::from_secs(9999)); }
                    "moderate" => { dw.set(0,Bytes::from(format!("r:{:08}",i%100_000)),Bytes::from_static(b"v"),i as u64); i+=1; std::thread::sleep(std::time::Duration::from_micros(100)); }
                    _          => { dw.set(0,Bytes::from(format!("r:{:08}",i%100_000)),Bytes::from_static(b"v"),i as u64); i+=1; }
                }
            }
        });

        let mut lats: Vec<f64> = Vec::with_capacity(5_000);
        for i in 0..5_000usize {
            let t0=Instant::now();
            let _=db.get(0,format!("r:{:08}",i%n_pre).as_bytes());
            lats.push(t0.elapsed().as_nanos() as f64/1000.0);
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().unwrap();

        let over = lats.iter().filter(|&&v| v>=1000.0).count();
        println!("  {:8} | {:8.2} | {:8.2} | {:8.2} | {:10.2} | {:4}",
            pressure,
            pct(lats.clone(),0.50), pct(lats.clone(),0.95),
            pct(lats.clone(),0.99), pct(lats.clone(),0.999), over);
        clean();
    }

    // 3c: versioned read latency
    println!();
    println!("  3c. Versioned read latency (100 heights × 100 keys = 10k versions):");
    clean();
    let db = DonaDb::open_wal(wal);
    for h in 0u64..100 {
        for k in 0..100usize { db.set(0, Bytes::from(format!("b:{:04}",k)), Bytes::copy_from_slice(&(h*1000+k as u64).to_le_bytes()), h); }
        if h%25==24 { db.sync(); }
    }
    db.sync();
    let mut vlats: Vec<f64>=vec![];
    for h in [0u64,24,49,74,99] {
        for k in 0..100usize {
            let t0=Instant::now();
            let _=db.get_at(0,format!("b:{:04}",k).as_bytes(),h);
            vlats.push(t0.elapsed().as_nanos() as f64/1000.0);
        }
    }
    println!("  P50={:.2}μs  P95={:.2}μs  P99={:.2}μs  max={:.1}μs  n={}",
        pct(vlats.clone(),0.50), pct(vlats.clone(),0.95),
        pct(vlats.clone(),0.99), vlats.iter().cloned().fold(0.0f64,f64::max), vlats.len());
    clean();
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║   TRUTHLINKED BENCHMARK SUITE v4.0 — THREE-LAYER ISOLATION         ║");
    println!("╠══════════════════════════════════════════════════════════════════════╣");
    println!("║   L1: Pure Scheduler  — no state, no WAL                           ║");
    println!("║   L2: State Engine    — in-memory only, no WAL                     ║");
    println!("║   L3: Storage Engine  — DonaDB only, no executor                   ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");

    layer1_scheduler();
    layer2_state_engine();
    layer3_storage();

    println!("\n{}", "═".repeat(74));
    println!("  Done. Each layer independently interpretable.");
    println!("{}\n", "═".repeat(74));
}
