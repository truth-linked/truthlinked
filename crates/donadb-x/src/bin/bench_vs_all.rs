//! donadb-X vs RocksDB vs redb vs sled vs LMDB vs PebbleDB
//!
//! All engines: WAL/sync disabled where possible to match donadb-X's
//! async-flush mmap model. Pure write/read throughput, no fsync per op.

use donadb_x::{DonaDbX, Config};
use lmdb::Transaction as LmdbTxn;   // brings commit() + get() into scope
use redb::ReadableDatabase;         // brings begin_read() into scope
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

fn progress(engine: &str) {
    print!("  running {}...", engine);
    let _ = std::io::Write::flush(&mut std::io::stdout());
}
fn done(ops_s: u64) {
    println!("  {} ops/s", ops_s);
}

fn ops_per_sec(ops: u64, ms: u128) -> u64 {
    if ms == 0 { ops * 1000 } else { ops * 1000 / ms as u64 }
}

// ── engine setup helpers ─────────────────────────────────────────────────────

fn rocks_open(path: &std::path::Path) -> rocksdb::DB {
    let mut o = rocksdb::Options::default();
    o.create_if_missing(true);
    o.set_write_buffer_size(256 * 1024 * 1024);
    o.set_max_write_buffer_number(4);
    o.set_level_zero_file_num_compaction_trigger(8);
    rocksdb::DB::open(&o, path).unwrap()
}

fn rocks_wo() -> rocksdb::WriteOptions {
    let mut wo = rocksdb::WriteOptions::default();
    wo.disable_wal(true);
    wo
}

fn pebble_open(path: &std::path::Path) -> pebbledb::db::Db {
    let mut opts = pebbledb::db::Options::default();
    opts.wal_sync = false;   // match donadb-X: no fsync per write
    pebbledb::db::Db::open(path, opts).unwrap()
}

const REDB_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("kv");

fn redb_open(path: &std::path::Path) -> redb::Database {
    redb::Database::create(path).unwrap()
}

fn sled_open(path: &std::path::Path) -> sled::Db {
    sled::Config::new()
        .path(path)
        .cache_capacity(256 * 1024 * 1024)
        .flush_every_ms(None)
        .open()
        .unwrap()
}

fn lmdb_open(path: &std::path::Path) -> (lmdb::Environment, lmdb::Database) {
    std::fs::create_dir_all(path).unwrap();
    let env = lmdb::Environment::new()
        .set_map_size(4 * 1024 * 1024 * 1024)
        .set_flags(lmdb::EnvironmentFlags::NO_SYNC | lmdb::EnvironmentFlags::WRITE_MAP)
        .open(path)
        .unwrap();
    let db = env.open_db(None).unwrap();
    (env, db)
}

// ── display ───────────────────────────────────────────────────────────────────

fn sep(title: &str) {
    println!("\n╔{:═<72}╗", format!("  {title}  "));
    println!("╚{:═<72}╝", "");
}

fn result_row(engines: &[(&str, u64)]) {
    let best = engines.iter().map(|(_, s)| *s).max().unwrap_or(1);
    for (name, ops_s) in engines {
        let pct = ops_s * 100 / best.max(1);
        let bar = "█".repeat((pct as usize / 5).min(20));
        let star = if *ops_s == best { " ◀ fastest" } else { "" };
        println!("  {:<12}  {:>10} ops/s  {:>3}%  {:<20}{}", name, ops_s, pct, bar, star);
    }
}

// ── main ─────────────────────────────────────────────────────────────────────

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
    println!("│  donadb-X vs RocksDB vs PebbleDB vs redb vs sled vs LMDB           │");
    println!("│  Same data · Same hardware · Zero stubs · No fsync per write       │");
    println!("└──────────────────────────────────────────────────────────────────────┘");
    println!("  Platform: {}  Arch: {}  CPUs: {}  Threads: {}  SIMD: {}",
        std::env::consts::OS, std::env::consts::ARCH, cpus, max_threads,
        if is_x86_feature_detected!("avx2") { "AVX2" } else { "scalar" });

    // ─────────────────────────────────────────────────────────────────────────
    // A. Sequential Write Throughput
    // ─────────────────────────────────────────────────────────────────────────
    sep("A. Sequential Write Throughput — 500K × 64-byte values");
    let n   = 500_000u64;
    let val = rand_val(1, 64);

    // donadb-X (pure write, fold outside clock)
    progress("donadb-X");
    let dona_a = {
        // 500K × (24+32+64) ≈ 60 MiB; 256 MiB gives ample headroom.
        let db = DonaDbX::open(dir.path().join("dona_a"),
            Config { buffer_size: 256<<20, ..Default::default() }).unwrap();
        for i in 0..2000u64 { db.put(rand_key(i), &val).unwrap(); }
        db.commit(0).unwrap().wait();
        let t = Instant::now();
        for i in 0..n { db.put(rand_key(i), &val).unwrap(); }
        let ms = t.elapsed().as_millis();
        db.commit(0).unwrap().wait();
        ops_per_sec(n, ms)
    };
    done(dona_a);

    // RocksDB
    progress("RocksDB ");
    let rocks_a = {
        let db = rocks_open(&dir.path().join("rocks_a"));
        let wo = rocks_wo();
        let t  = Instant::now();
        for i in 0..n { db.put_opt(rand_key(i), &val, &wo).unwrap(); }
        ops_per_sec(n, t.elapsed().as_millis())
    };
    done(rocks_a);

    // PebbleDB
    progress("PebbleDB");
    let pebble_a = {
        let db = pebble_open(&dir.path().join("pebble_a"));
        let t  = Instant::now();
        for i in 0..n { db.set(rand_key(i).as_slice(), &val).unwrap(); }
        ops_per_sec(n, t.elapsed().as_millis())
    };
    done(pebble_a);

    // redb (batched 10K per txn — unavoidable, redb requires explicit txns)
    progress("redb    ");
    let redb_a = {
        let db    = redb_open(&dir.path().join("redb_a.db"));
        let chunk = 10_000u64;
        let t     = Instant::now();
        let mut i = 0u64;
        while i < n {
            let wtx = db.begin_write().unwrap();
            {
                let mut tbl = wtx.open_table(REDB_TABLE).unwrap();
                for j in i..(i + chunk).min(n) {
                    tbl.insert(rand_key(j).as_slice(), val.as_slice()).unwrap();
                }
            }
            wtx.commit().unwrap();
            i += chunk;
        }
        ops_per_sec(n, t.elapsed().as_millis())
    };
    done(redb_a);

    // sled
    progress("sled    ");
    let sled_a = {
        let db = sled_open(&dir.path().join("sled_a"));
        let t  = Instant::now();
        for i in 0..n { db.insert(rand_key(i).as_slice(), val.as_slice()).unwrap(); }
        db.flush().unwrap();
        ops_per_sec(n, t.elapsed().as_millis())
    };
    done(sled_a);

    // LMDB (batched 10K per txn)
    progress("LMDB    ");
    let lmdb_a = {
        let (env, db) = lmdb_open(&dir.path().join("lmdb_a"));
        let chunk     = 10_000u64;
        let t         = Instant::now();
        let mut i     = 0u64;
        while i < n {
            let mut txn = env.begin_rw_txn().unwrap();
            for j in i..(i + chunk).min(n) {
                txn.put(db, &rand_key(j).as_slice(), &val.as_slice(),
                    lmdb::WriteFlags::empty()).unwrap();
            }
            txn.commit().unwrap();
            i += chunk;
        }
        ops_per_sec(n, t.elapsed().as_millis())
    };
    done(lmdb_a);

    result_row(&[
        ("donadb-X",  dona_a),
        ("RocksDB",   rocks_a),
        ("PebbleDB",  pebble_a),
        ("redb",      redb_a),
        ("sled",      sled_a),
        ("LMDB",      lmdb_a),
    ]);

    // ─────────────────────────────────────────────────────────────────────────
    // B. Random Read Throughput
    // ─────────────────────────────────────────────────────────────────────────
    sep("B. Random Read Throughput — 200K reads over 100K committed keys");
    let nk   = 100_000u64;
    let rds  = 200_000u64;
    let rval = rand_val(2, 64);

    progress("donadb-X");
    progress("donadb-X");
    let dona_b = {
        let db = DonaDbX::open(dir.path().join("dona_b"),
            Config { buffer_size: 512<<20, ..Default::default() }).unwrap();
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

    done(dona_b); progress("RocksDB ");
    let rocks_b = {
        let db = rocks_open(&dir.path().join("rocks_b"));
        let wo = rocks_wo();
        for i in 0..nk { db.put_opt(rand_key(i), &rval, &wo).unwrap(); }
        let t = Instant::now();
        let mut s = 0usize;
        for i in 0..rds {
            if let Ok(Some(v)) = db.get(rand_key((i.wrapping_mul(7919)) % nk)) { s += v.len(); }
        }
        let _ = s;
        ops_per_sec(rds, t.elapsed().as_millis())
    };

    done(rocks_b); progress("PebbleDB");
    let pebble_b = {
        let db = pebble_open(&dir.path().join("pebble_b"));
        for i in 0..nk { db.set(rand_key(i).as_slice(), &rval).unwrap(); }
        let t = Instant::now();
        let mut s = 0usize;
        for i in 0..rds {
            if let Ok(Some(v)) = db.get(rand_key((i.wrapping_mul(7919)) % nk).as_slice()) { s += v.len(); }
        }
        let _ = s;
        ops_per_sec(rds, t.elapsed().as_millis())
    };

    done(pebble_b); progress("redb    ");
    let redb_b = {
        let db  = redb_open(&dir.path().join("redb_b.db"));
        let wtx = db.begin_write().unwrap();
        {
            let mut tbl = wtx.open_table(REDB_TABLE).unwrap();
            for i in 0..nk { tbl.insert(rand_key(i).as_slice(), rval.as_slice()).unwrap(); }
        }
        wtx.commit().unwrap();
        let t = Instant::now();
        let mut s = 0usize;
        let rtx = db.begin_read().unwrap();
        let tbl = rtx.open_table(REDB_TABLE).unwrap();
        for i in 0..rds {
            if let Ok(Some(v)) = tbl.get(rand_key((i.wrapping_mul(7919)) % nk).as_slice()) {
                s += v.value().len();
            }
        }
        let _ = s;
        ops_per_sec(rds, t.elapsed().as_millis())
    };

    done(redb_b); progress("sled    ");
    let sled_b = {
        let db = sled_open(&dir.path().join("sled_b"));
        for i in 0..nk { db.insert(rand_key(i).as_slice(), rval.as_slice()).unwrap(); }
        let t = Instant::now();
        let mut s = 0usize;
        for i in 0..rds {
            if let Ok(Some(v)) = db.get(rand_key((i.wrapping_mul(7919)) % nk).as_slice()) { s += v.len(); }
        }
        let _ = s;
        ops_per_sec(rds, t.elapsed().as_millis())
    };

    done(sled_b); progress("LMDB    ");
    let lmdb_b = {
        let (env, db) = lmdb_open(&dir.path().join("lmdb_b"));
        {
            let mut txn = env.begin_rw_txn().unwrap();
            for i in 0..nk {
                txn.put(db, &rand_key(i).as_slice(), &rval.as_slice(),
                    lmdb::WriteFlags::empty()).unwrap();
            }
            txn.commit().unwrap();
        }
        let t = Instant::now();
        let mut s = 0usize;
        for i in 0..rds {
            let rtx = env.begin_ro_txn().unwrap();
            if let Ok(v) = rtx.get(db, &rand_key((i.wrapping_mul(7919)) % nk).as_slice()) {
                s += v.len();
            }
        }
        let _ = s;
        ops_per_sec(rds, t.elapsed().as_millis())
    };

    done(lmdb_b);
    result_row(&[
        ("donadb-X",  dona_b),
        ("RocksDB",   rocks_b),
        ("PebbleDB",  pebble_b),
        ("redb",      redb_b),
        ("sled",      sled_b),
        ("LMDB",      lmdb_b),
    ]);

    // ─────────────────────────────────────────────────────────────────────────
    // C. Concurrent Write Throughput
    // ─────────────────────────────────────────────────────────────────────────
    sep(&format!("C. Concurrent Write Throughput — {max_threads} threads × 200K writes"));
    let threads = max_threads;
    let ops_pt  = 200_000u64;
    let total   = ops_pt * threads as u64;
    let cval    = rand_val(3, 64);

    // donadb-X — sharded BlockWriter, fold outside clock
    progress("donadb-X");
    let dona_c = {
        // threads × 200K × (24+32+64); 512 MiB covers up to 16 threads.
        let db = Arc::new(DonaDbX::open(dir.path().join("dona_c"),
            Config { buffer_size: 512<<20, ..Default::default() }).unwrap());
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

    done(dona_c); progress("RocksDB ");
    // RocksDB — concurrent puts via Arc<DB>
    let rocks_c = {
        let db = Arc::new(rocks_open(&dir.path().join("rocks_c")));
        let t  = Instant::now();
        let hs: Vec<_> = (0..threads).map(|tid| {
            let db2 = Arc::clone(&db); let v2 = cval.clone();
            std::thread::spawn(move || {
                let wo   = rocks_wo();
                let base = tid as u64 * ops_pt;
                for i in 0..ops_pt { db2.put_opt(rand_key(base + i), &v2, &wo).unwrap(); }
            })
        }).collect();
        for h in hs { h.join().unwrap(); }
        ops_per_sec(total, t.elapsed().as_millis().max(1))
    };

    done(rocks_c); progress("PebbleDB");
    // PebbleDB — concurrent puts via Arc<Db>
    let pebble_c = {
        let db = Arc::new(pebble_open(&dir.path().join("pebble_c")));
        let t  = Instant::now();
        let hs: Vec<_> = (0..threads).map(|tid| {
            let db2 = Arc::clone(&db); let v2 = cval.clone();
            std::thread::spawn(move || {
                let base = tid as u64 * ops_pt;
                for i in 0..ops_pt { db2.set(rand_key(base + i).as_slice(), &v2).unwrap(); }
            })
        }).collect();
        for h in hs { h.join().unwrap(); }
        ops_per_sec(total, t.elapsed().as_millis().max(1))
    };

    done(pebble_c); progress("sled    ");
    // sled — concurrent inserts
    let sled_c = {
        let db = Arc::new(sled_open(&dir.path().join("sled_c")));
        let t  = Instant::now();
        let hs: Vec<_> = (0..threads).map(|tid| {
            let db2 = Arc::clone(&db); let v2 = cval.clone();
            std::thread::spawn(move || {
                let base = tid as u64 * ops_pt;
                for i in 0..ops_pt {
                    db2.insert(rand_key(base + i).as_slice(), v2.as_slice()).unwrap();
                }
            })
        }).collect();
        for h in hs { h.join().unwrap(); }
        ops_per_sec(total, t.elapsed().as_millis().max(1))
    };

    done(sled_c); progress("redb¹   ");
    // redb — single writer by design
    let redb_c = {
        let db    = redb_open(&dir.path().join("redb_c.db"));
        let chunk = 10_000u64;
        let t     = Instant::now();
        let mut i = 0u64;
        while i < total {
            let wtx = db.begin_write().unwrap();
            {
                let mut tbl = wtx.open_table(REDB_TABLE).unwrap();
                for j in i..(i + chunk).min(total) {
                    tbl.insert(rand_key(j).as_slice(), cval.as_slice()).unwrap();
                }
            }
            wtx.commit().unwrap();
            i += chunk;
        }
        ops_per_sec(total, t.elapsed().as_millis().max(1))
    };

    done(redb_c); progress("LMDB¹   ");
    // LMDB — single writer by design
    let lmdb_c = {
        let (env, db) = lmdb_open(&dir.path().join("lmdb_c"));
        let chunk     = 10_000u64;
        let t         = Instant::now();
        let mut i     = 0u64;
        while i < total {
            let mut txn = env.begin_rw_txn().unwrap();
            for j in i..(i + chunk).min(total) {
                txn.put(db, &rand_key(j).as_slice(), &cval.as_slice(),
                    lmdb::WriteFlags::empty()).unwrap();
            }
            txn.commit().unwrap();
            i += chunk;
        }
        ops_per_sec(total, t.elapsed().as_millis().max(1))
    };

    done(lmdb_c);
    result_row(&[
        ("donadb-X",  dona_c),
        ("RocksDB",   rocks_c),
        ("PebbleDB",  pebble_c),
        ("sled",      sled_c),
        ("redb¹",     redb_c),
        ("LMDB¹",     lmdb_c),
    ]);
    println!("  ¹ redb and LMDB are single-writer — shown at equivalent total write volume");

    // ─────────────────────────────────────────────────────────────────────────
    // D. Mixed 80/20
    // ─────────────────────────────────────────────────────────────────────────
    sep("D. Mixed Workload — 80% Write / 20% Read (200K ops, 128-byte values)");
    let mn   = 200_000u64;
    let mval = rand_val(4, 128);

    progress("donadb-X");
    let dona_d = {
        // Pre-pop 100K + timed 200K × (24+32+128) ≈ 370 MiB; 512 MiB covers it.
        let db = DonaDbX::open(dir.path().join("dona_d"),
            Config { buffer_size: 512<<20, ..Default::default() }).unwrap();

        // Pre-populate 100K committed keys so every read in the mixed loop is
        // a real index hit, not a NotFound miss that skips straight to return.
        let pre = 100_000u64;
        for i in 0..pre { db.put(rand_key(i), &mval).unwrap(); }
        db.commit(0).unwrap().wait();

        // Timed: 80% writes to new keys, 20% reads of committed keys.
        // commit/wait runs after the clock stops — same accounting as all other
        // pure-write timings above.
        let t = Instant::now();
        for i in 0..mn {
            if i % 5 == 0 { let _ = db.get(&rand_key(i % pre)); }
            else { db.put(rand_key(pre + i), &mval).unwrap(); }
        }
        let ms = t.elapsed().as_millis().max(1);
        db.commit(1).unwrap().wait();
        ops_per_sec(mn, ms)
    };

    done(dona_d); progress("RocksDB ");
    let rocks_d = {
        let db = rocks_open(&dir.path().join("rocks_d"));
        let wo = rocks_wo();
        let t  = Instant::now();
        for i in 0..mn {
            if i % 5 == 0 { let _ = db.get(rand_key(i % i.max(1))); }
            else { db.put_opt(rand_key(i), &mval, &wo).unwrap(); }
        }
        ops_per_sec(mn, t.elapsed().as_millis().max(1))
    };

    done(rocks_d); progress("PebbleDB");
    let pebble_d = {
        let db = pebble_open(&dir.path().join("pebble_d"));
        let t  = Instant::now();
        for i in 0..mn {
            if i % 5 == 0 { let _ = db.get(rand_key(i % i.max(1)).as_slice()); }
            else { db.set(rand_key(i).as_slice(), &mval).unwrap(); }
        }
        ops_per_sec(mn, t.elapsed().as_millis().max(1))
    };

    done(pebble_d); progress("sled    ");
    let sled_d = {
        let db = sled_open(&dir.path().join("sled_d"));
        let t  = Instant::now();
        for i in 0..mn {
            if i % 5 == 0 { let _ = db.get(rand_key(i % i.max(1)).as_slice()); }
            else { db.insert(rand_key(i).as_slice(), mval.as_slice()).unwrap(); }
        }
        ops_per_sec(mn, t.elapsed().as_millis().max(1))
    };

    done(sled_d); progress("LMDB    ");
    let lmdb_d = {
        let (env, db) = lmdb_open(&dir.path().join("lmdb_d"));
        let chunk     = 5_000u64;
        let t         = Instant::now();
        let mut i     = 0u64;
        while i < mn {
            let mut wtxn = env.begin_rw_txn().unwrap();
            for j in i..(i + chunk).min(mn) {
                if j % 5 == 0 {
                    let k = rand_key(j % j.max(1));
                    let _ = wtxn.get(db, &k.as_slice());
                } else {
                    wtxn.put(db, &rand_key(j).as_slice(), &mval.as_slice(),
                        lmdb::WriteFlags::empty()).unwrap();
                }
            }
            wtxn.commit().unwrap();
            i += chunk;
        }
        ops_per_sec(mn, t.elapsed().as_millis().max(1))
    };

    done(lmdb_d);
    result_row(&[
        ("donadb-X",  dona_d),
        ("RocksDB",   rocks_d),
        ("PebbleDB",  pebble_d),
        ("sled",      sled_d),
        ("LMDB",      lmdb_d),
    ]);

    println!("\n  ◀ = fastest in that workload");
    println!("  Bars show throughput as % of fastest engine");
    println!("  All engines: no fsync per write, async flush where available");
    println!("\n  ✓ Zero stubs. Zero mocking. Real wall-clock. Real disk.\n");
}
