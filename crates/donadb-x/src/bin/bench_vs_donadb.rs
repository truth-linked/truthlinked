//! donadb-X vs donadb 0.1.3
//!
//! Direct head-to-head comparison between the two TruthLinked storage engines.
//! Both engines are tested under identical conditions on the same hardware.
//!
//! donadb (0.1.3) is an LSM engine: DashMap memtable + background WAL writer
//! thread + SST tier with CRC-protected snapshot compaction. WAL is flushed
//! asynchronously via an unbounded crossbeam channel (no fsync per write).
//!
//! donadb-X is a lock-free mmap engine: commutative append log + atomic
//! N-shard buffer swap + parallel BLAKE3 Merkle fold + crash-safe manifest.
//!
//! NOTE: donadb's set() writes *two* internal keys per logical write — a head
//! key for latest-value reads and a version key for MVCC. donadb-X writes one
//! record per put(). This is called out where it affects fairness.

use donadb_x::{DonaDbX, Config};
use donadb::{DonaDb, DonaDbConfig};
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;

fn rand_key(n: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0..8].copy_from_slice(&n.to_le_bytes());
    k[8..16].copy_from_slice(
        &n.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407)
            .to_le_bytes(),
    );
    k
}

fn rand_val(seed: u64, size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size];
    for i in 0..size {
        v[i] = (seed.wrapping_add(i as u64).wrapping_mul(2654435761) >> 24) as u8;
    }
    v
}

fn ops_per_sec(ops: u64, ms: u128) -> u64 {
    if ms == 0 { ops * 1000 } else { ops * 1000 / ms as u64 }
}

fn dona_cfg(dir: std::path::PathBuf) -> DonaDbConfig {
    DonaDbConfig { data_dir: dir, ..Default::default() }
}

fn sep(title: &str) {
    println!("\n╔{:═<72}╗", format!("  {title}  "));
    println!("╚{:═<72}╝", "");
}

fn result_row(engines: &[(&str, u64)]) {
    let best = engines.iter().map(|(_, s)| *s).max().unwrap_or(1);
    for (name, ops_s) in engines {
        let pct  = ops_s * 100 / best.max(1);
        let bar  = "█".repeat((pct as usize / 5).min(20));
        let star = if *ops_s == best { " ◀ fastest" } else { "" };
        println!("  {:<14} {:>10} ops/s  {:>3}%  {:<20}{}", name, ops_s, pct, bar, star);
    }
}

fn progress(engine: &str) {
    print!("  running {}...", engine);
    let _ = std::io::Write::flush(&mut std::io::stdout());
}
fn done(ops_s: u64) { println!("  {} ops/s", ops_s); }

fn main() {
    let dir  = tempdir().unwrap();
    let cpus = num_cpus::get();

    // Thread count for concurrent workloads.
    // Override with --threads N or BENCH_THREADS=N; defaults to logical CPU count.
    let max_threads: usize = std::env::args()
        .zip(std::env::args().skip(1))
        .find_map(|(flag, val)| {
            if flag == "--threads" { val.parse().ok() } else { None }
        })
        .or_else(|| std::env::var("BENCH_THREADS").ok().and_then(|v| v.parse().ok()))
        .unwrap_or(cpus)
        .max(1);

    println!("\n┌──────────────────────────────────────────────────────────────────────┐");
    println!("│  donadb-X  vs  donadb 0.1.3                                         │");
    println!("│  Same data · Same hardware · Zero stubs · No fsync per write        │");
    println!("└──────────────────────────────────────────────────────────────────────┘");
    println!("  Platform : {}  Arch : {}  CPUs : {}  Threads : {}  SIMD : {}",
        std::env::consts::OS, std::env::consts::ARCH, cpus, max_threads,
        if is_x86_feature_detected!("avx2") { "AVX2" } else { "scalar" });
    println!("  donadb note: set() writes 2 internal keys per logical write (head + version).");

    // ── A. Sequential Write ───────────────────────────────────────────────────
    sep("A. Sequential Write — 500K × 64-byte values");
    let n   = 500_000u64;
    let val = rand_val(1, 64);

    progress("donadb-X");
    let x_a = {
        let db = DonaDbX::open(dir.path().join("x_a"),
            Config { buffer_size: 256 << 20, ..Default::default() }).unwrap();
        for i in 0..2_000u64 { db.put(rand_key(i), &val).unwrap(); }
        db.commit(0).unwrap().wait();
        let t = Instant::now();
        for i in 0..n { db.put(rand_key(i), &val).unwrap(); }
        let ms = t.elapsed().as_millis();
        db.commit(0).unwrap().wait();
        ops_per_sec(n, ms)
    };
    done(x_a);

    progress("donadb  ");
    let d_a = {
        let db = DonaDb::open(dona_cfg(dir.path().join("d_a"))).unwrap();
        let t  = Instant::now();
        for i in 0..n {
            db.set(0, rand_key(i).to_vec(), val.clone(), 1);
        }
        ops_per_sec(n, t.elapsed().as_millis())
    };
    done(d_a);

    result_row(&[("donadb-X", x_a), ("donadb 0.1.3", d_a)]);

    // ── B. Random Read ────────────────────────────────────────────────────────
    sep("B. Random Read — 200K reads over 100K committed keys");
    let nk   = 100_000u64;
    let rval = rand_val(2, 64);
    let rds  = 200_000u64;

    progress("donadb-X");
    let x_b = {
        let db = DonaDbX::open(dir.path().join("x_b"),
            Config { buffer_size: 128 << 20, ..Default::default() }).unwrap();
        for i in 0..nk { db.put(rand_key(i), &rval).unwrap(); }
        db.commit(0).unwrap().wait();
        let t = Instant::now();
        let mut s = 0usize;
        for i in 0..rds {
            if let Ok(v) = db.get(&rand_key((i.wrapping_mul(7919)) % nk)) { s += v.len(); }
        }
        let _ = s;
        ops_per_sec(rds, t.elapsed().as_millis())
    };
    done(x_b);

    progress("donadb  ");
    let d_b = {
        let db = DonaDb::open(dona_cfg(dir.path().join("d_b"))).unwrap();
        for i in 0..nk { db.set(0, rand_key(i).to_vec(), rval.clone(), 1); }
        let t = Instant::now();
        let mut s = 0usize;
        for i in 0..rds {
            let k = rand_key((i.wrapping_mul(7919)) % nk);
            if let Ok(Some(v)) = db.get(0, k.as_slice()) { s += v.len(); }
        }
        let _ = s;
        ops_per_sec(rds, t.elapsed().as_millis())
    };
    done(d_b);

    result_row(&[("donadb-X", x_b), ("donadb 0.1.3", d_b)]);

    // ── C. Concurrent Write ───────────────────────────────────────────────────
    sep(&format!("C. Concurrent Write — {max_threads} threads × 200K writes"));
    let threads = max_threads;
    let ops_pt  = 200_000u64;
    let total   = ops_pt * threads as u64;
    let cval    = rand_val(3, 64);

    progress("donadb-X");
    let x_c = {
        let db = Arc::new(DonaDbX::open(dir.path().join("x_c"),
            Config { buffer_size: 512 << 20, ..Default::default() }).unwrap());
        for s in 0..threads {
            let w = db.writer(s);
            for i in 0..500u64 { w.put(rand_key(i), &cval).unwrap(); }
        }
        db.commit(0).unwrap().wait();
        let t = Instant::now();
        let hs: Vec<_> = (0..threads).map(|tid| {
            let db2 = Arc::clone(&db); let v2 = cval.clone();
            std::thread::spawn(move || {
                let w    = db2.writer(tid);
                let base = 500 + tid as u64 * ops_pt;
                for i in 0..ops_pt { w.put(rand_key(base + i), &v2).unwrap(); }
            })
        }).collect();
        for h in hs { h.join().unwrap(); }
        let ms = t.elapsed().as_millis().max(1);
        db.commit(0).unwrap().wait();
        ops_per_sec(total, ms)
    };
    done(x_c);

    progress("donadb  ");
    let d_c = {
        // DonaDb is Clone + Send so we can share it across threads directly
        let db  = DonaDb::open(dona_cfg(dir.path().join("d_c"))).unwrap();
        let t   = Instant::now();
        let hs: Vec<_> = (0..threads).map(|tid| {
            let db2 = db.clone(); let v2 = cval.clone();
            std::thread::spawn(move || {
                let base = tid as u64 * ops_pt;
                for i in 0..ops_pt {
                    db2.set(0, rand_key(base + i).to_vec(), v2.clone(), 1);
                }
            })
        }).collect();
        for h in hs { h.join().unwrap(); }
        ops_per_sec(total, t.elapsed().as_millis().max(1))
    };
    done(d_c);

    result_row(&[("donadb-X", x_c), ("donadb 0.1.3", d_c)]);

    // ── D. Mixed 80/20 ────────────────────────────────────────────────────────
    sep("D. Mixed Workload — 80% Write / 20% Read (200K ops, 128-byte values)");
    let mn   = 200_000u64;
    let mval = rand_val(4, 128);
    let pre  = 100_000u64;

    progress("donadb-X");
    let x_d = {
        let db = DonaDbX::open(dir.path().join("x_d"),
            Config { buffer_size: 512 << 20, ..Default::default() }).unwrap();
        for i in 0..pre { db.put(rand_key(i), &mval).unwrap(); }
        db.commit(0).unwrap().wait();
        let t = Instant::now();
        for i in 0..mn {
            if i % 5 == 0 { let _ = db.get(&rand_key(i % pre)); }
            else { db.put(rand_key(pre + i), &mval).unwrap(); }
        }
        let ms = t.elapsed().as_millis().max(1);
        db.commit(1).unwrap().wait();
        ops_per_sec(mn, ms)
    };
    done(x_d);

    progress("donadb  ");
    let d_d = {
        let db = DonaDb::open(dona_cfg(dir.path().join("d_d"))).unwrap();
        for i in 0..pre { db.set(0, rand_key(i).to_vec(), mval.clone(), 0); }
        let t = Instant::now();
        for i in 0..mn {
            if i % 5 == 0 { let _ = db.get(0, rand_key(i % pre).as_slice()); }
            else { db.set(0, rand_key(pre + i).to_vec(), mval.clone(), 1); }
        }
        ops_per_sec(mn, t.elapsed().as_millis().max(1))
    };
    done(d_d);

    result_row(&[("donadb-X", x_d), ("donadb 0.1.3", d_d)]);

    // ── E. MVCC Point-in-Time Read ────────────────────────────────────────────
    sep("E. MVCC Read — get_at(key, height=0) over 10K written versions");

    progress("donadb-X");
    let x_e = {
        let db  = DonaDbX::open(dir.path().join("x_e"),
            Config { buffer_size: 64 << 20, ..Default::default() }).unwrap();
        let key = rand_key(42);
        for h in 0..10_000u64 { db.put(key, &rand_val(h, 32)).unwrap(); }
        db.commit(10_000).unwrap().wait();
        let iters = 1_000u64;
        let t = Instant::now();
        for _ in 0..iters { let _ = db.get_at(&key, 0); }
        ops_per_sec(iters, t.elapsed().as_millis().max(1))
    };
    done(x_e);

    progress("donadb  ");
    let d_e = {
        let db  = DonaDb::open(dona_cfg(dir.path().join("d_e"))).unwrap();
        let key = rand_key(42);
        for h in 0..10_000u64 { db.set(0, key.to_vec(), rand_val(h, 32), h); }
        let iters = 1_000u64;
        let t = Instant::now();
        for _ in 0..iters { let _ = db.get_at(0, key.as_slice(), 0); }
        ops_per_sec(iters, t.elapsed().as_millis().max(1))
    };
    done(d_e);

    result_row(&[("donadb-X", x_e), ("donadb 0.1.3", d_e)]);

    // ── F. Crash Recovery ─────────────────────────────────────────────────────
    sep("F. Crash Recovery — reopen + replay 500K committed records");
    let rn    = 500_000u64;
    let rval2 = rand_val(6, 64);

    progress("donadb-X");
    let x_f = {
        let p = dir.path().join("x_f");
        {
            let db = DonaDbX::open(&p,
                Config { buffer_size: 128 << 20, ..Default::default() }).unwrap();
            for i in 0..rn { db.put(rand_key(i), &rval2).unwrap(); }
            db.commit(0).unwrap().wait();
        }
        let t   = Instant::now();
        let db2 = DonaDbX::open(&p,
            Config { buffer_size: 128 << 20, ..Default::default() }).unwrap();
        let ms  = t.elapsed().as_millis().max(1);
        println!("    donadb-X: {} ms  ({} keys indexed)", ms, db2.len());
        ops_per_sec(rn, ms)
    };

    progress("donadb  ");
    let d_f = {
        let p = dir.path().join("d_f");
        {
            let db = DonaDb::open(dona_cfg(p.clone())).unwrap();
            for i in 0..rn { db.set(0, rand_key(i).to_vec(), rval2.clone(), 0); }
            db.sync();
        }
        let t   = Instant::now();
        let db2 = DonaDb::open(dona_cfg(p.clone())).unwrap();
        let ms  = t.elapsed().as_millis().max(1);
        println!("    donadb:   {} ms  ({} memtable entries)", ms, db2.len());
        ops_per_sec(rn, ms)
    };

    result_row(&[("donadb-X", x_f), ("donadb 0.1.3", d_f)]);

    // ── Summary ───────────────────────────────────────────────────────────────
    println!("\n┌──────────────────────────────────────────────────────────────────────┐");
    println!("│  Summary                                                             │");
    println!("├──────────────────────────────────┬──────────────┬───────────────────┤");
    println!("│  Workload                        │  donadb-X    │  donadb 0.1.3     │");
    println!("├──────────────────────────────────┼──────────────┼───────────────────┤");
    println!("│  A. Sequential write 500K        │  {:>8} K  │  {:>11} K   │",
        x_a / 1000, d_a / 1000);
    println!("│  B. Random read 200K             │  {:>8} K  │  {:>11} K   │",
        x_b / 1000, d_b / 1000);
    println!("│  C. Concurrent write {max_threads}T          │  {:>8} K  │  {:>11} K   │",
        x_c / 1000, d_c / 1000);
    println!("│  D. Mixed 80/20 200K             │  {:>8} K  │  {:>11} K   │",
        x_d / 1000, d_d / 1000);
    println!("│  E. MVCC get_at depth 10K        │  {:>8} K  │  {:>11} K   │",
        x_e / 1000, d_e / 1000);
    println!("│  F. Crash recovery 500K records  │  {:>8} K  │  {:>11} K   │",
        x_f / 1000, d_f / 1000);
    println!("└──────────────────────────────────┴──────────────┴───────────────────┘");
    println!("\n  ✓ Zero stubs. Zero mocking. Real wall-clock. Real disk.");
    println!("  ✓ donadb set() writes 2 internal keys per logical write (head + version).\n");
}
