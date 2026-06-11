//! Manual DonaDB diagnostics.
//!
//! This binary is intentionally separate from the library test suite. It runs
//! larger local exercises for snapshot recovery, SST movement, read throughput,
//! and write throughput when an operator wants an interactive storage probe.

use bytes::Bytes;
use donadb::DonaDB;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(|s| s.trim()) == Some("sst-e2e") {
        unsafe {
            std::env::set_var("DONADB_L0_MAX", "2");
            std::env::set_var("DONADB_L1_MAX", "2");
            std::env::set_var("DONADB_L2_MAX", "2");
        }

        let dir = "/tmp/donadb-sst-e2e";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();

        let sst = Arc::new(donadb::sst::SstLevel::open(Path::new(dir)).unwrap());

        println!("=== SST E2E: L0 → L1 → L2 compaction ===");

        for i in 0..8usize {
            let entries: Vec<(Bytes, Bytes)> = (0..200)
                .map(|k| {
                    (
                        Bytes::from(format!("k{:02}:{:04}", i, k)),
                        Bytes::from_static(b"v"),
                    )
                })
                .collect();
            sst.flush(entries).unwrap();
            let (l0, l1, l2) = sst.stats();
            println!("  after flush {}: l0={} l1={} l2={}", i + 1, l0, l1, l2);
            std::thread::sleep(Duration::from_millis(50));
        }

        std::thread::sleep(Duration::from_millis(200));
        let (l0, l1, l2) = sst.stats();
        println!("  final: l0={} l1={} l2={}", l0, l1, l2);

        let total = 8 * 200;
        let found = (0..8usize)
            .flat_map(|i| (0..200usize).map(move |k| (i, k)))
            .filter(|(i, k)| sst.get(format!("k{:02}:{:04}", i, k).as_bytes()).is_some())
            .count();
        println!(
            "  keys readable: {}/{} {}",
            found,
            total,
            if found == total { "✓" } else { "✗" }
        );

        println!(
            "  compaction fired: {} {}",
            if l1 > 0 || l2 > 0 { "yes" } else { "no" },
            if l1 > 0 || l2 > 0 { "✓" } else { "✗" }
        );
        return;
    }

    if args.get(1).map(|s| s.trim()) == Some("sst-load") {
        let wal = "/tmp/donadb-load-test.wal";
        let _ = std::fs::remove_file(wal);
        let _ = std::fs::remove_file(format!("{}.snap", wal));
        let _ = std::fs::remove_dir_all(format!("{}.sst", wal));

        unsafe {
            std::env::set_var("DONADB_MEMTABLE_FLUSH", "50000");
            std::env::set_var("DONADB_L0_MAX", "2");
            std::env::set_var("DONADB_L1_MAX", "2");
            std::env::set_var("DONADB_L2_MAX", "2");
        }

        let db = DonaDB::open_wal(wal);
        let total = 1_000_000usize;
        let batch = 1000usize;
        let start = Instant::now();

        for i in 0..total {
            db.set(
                0,
                Bytes::from(format!("k:{:09}", i)),
                Bytes::from_static(b"v"),
                0,
            );
            if i % 10_000 == 9_999 {
                db.sync();
                std::thread::sleep(Duration::from_millis(20));
                let (l0, l1, l2) = db.sst_stats();
                println!("  wrote {} | l0={} l1={} l2={}", i + 1, l0, l1, l2);
            }
            let _ = batch;
        }

        std::thread::sleep(Duration::from_millis(500));
        let (l0, l1, l2) = db.sst_stats();
        let tps = total as f64 / start.elapsed().as_secs_f64();
        println!("\nDONE: {:.0} TPS | l0={} l1={} l2={}", tps, l0, l1, l2);

        let check_keys = [0usize, 50_000, 150_000, 300_000, 399_999];
        for k in check_keys {
            let v = db.get(0, format!("k:{:09}", k).as_bytes()).ok().flatten();
            println!(
                "  k:{:09} = {} {}",
                k,
                if v.is_some() { "found" } else { "MISSING" },
                if v.is_some() { "✓" } else { "✗" }
            );
        }
        return;
    }

    if args.get(1).map(|s| s.trim()) == Some("tps-read") {
        let wal = "/tmp/donadb-read-test.wal";
        let _ = std::fs::remove_file(wal);
        let _ = std::fs::remove_file(format!("{}.snap", wal));
        let _ = std::fs::remove_dir_all(format!("{}.sst", wal));

        unsafe {
            std::env::set_var("DONADB_MEMTABLE_FLUSH", "50000");
        }

        let keys: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(500_000);
        let reads: usize = args
            .get(3)
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000);
        let threads: usize = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(8);
        let payload = Bytes::from(vec![7u8; 64]);

        {
            let db = DonaDB::open_wal(wal);
            for i in 0..keys {
                db.set(
                    0,
                    Bytes::from(format!("r:{:09}", i)),
                    payload.clone(),
                    i as u64,
                );
                if i % 10_000 == 9_999 {
                    db.sync();
                }
            }
            db.sync();
            std::thread::sleep(Duration::from_millis(500));
            let (l0, l1, l2) = db.sst_stats();
            println!("LOAD: keys={} | l0={} l1={} l2={}", keys, l0, l1, l2);
        }

        let db = Arc::new(DonaDB::open_wal(wal));
        let per = reads / threads;
        let misses = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let start = Instant::now();
        let mut handles = Vec::with_capacity(threads);
        for t in 0..threads {
            let db = Arc::clone(&db);
            let misses = Arc::clone(&misses);
            handles.push(std::thread::spawn(move || {
                let mut x = (t as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                for _ in 0..per {
                    x = x
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    let idx = (x as usize) % keys;
                    if db
                        .get(0, format!("r:{:09}", idx).as_bytes())
                        .ok()
                        .flatten()
                        .is_none()
                    {
                        misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let secs = start.elapsed().as_secs_f64().max(0.0001);
        let actual_reads = per * threads;
        let misses = misses.load(std::sync::atomic::Ordering::Relaxed);
        println!(
            "READ TPS: {:.0} ops/sec (reads={}, keys={}, threads={}, misses={})",
            actual_reads as f64 / secs,
            actual_reads,
            keys,
            threads,
            misses
        );
        return;
    }

    if args.get(1).map(|s| s.trim()) == Some("tps-write") {
        let wal = "/tmp/donadb-tps-test.wal";
        let _ = std::fs::remove_file(wal);
        let _ = std::fs::remove_file(format!("{}.snap", wal));
        let _ = std::fs::remove_dir_all(format!("{}.sst", wal));

        let total_ops: usize = args
            .get(2)
            .and_then(|v| v.parse().ok())
            .unwrap_or(2_000_000);
        let batch_size: usize = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(1_000);
        let threads: usize = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(8);

        let value = Bytes::from_static(b"v");
        let db = Arc::new(DonaDB::open_wal(wal));
        let barrier = Arc::new(std::sync::Barrier::new(threads));
        let per = total_ops / threads;
        let blocks_each = (per + batch_size - 1) / batch_size;

        let start = Instant::now();
        let mut handles = Vec::with_capacity(threads);
        for t in 0..threads {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            let value = value.clone();
            handles.push(std::thread::spawn(move || {
                let base = t * per;
                for b in 0..blocks_each {
                    let mut batch = donadb::WriteBatch::new();
                    let lo = base + b * batch_size;
                    let hi = (lo + batch_size).min(base + per);
                    for i in lo..hi {
                        batch.set(Bytes::from(format!("k:{:09}", i)), value.clone());
                    }
                    db.write_batch(batch);

                    let w = barrier.wait();
                    if w.is_leader() {
                        db.sync();
                    }
                    barrier.wait();
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        db.sync();

        let secs = start.elapsed().as_secs_f64().max(0.0001);
        println!(
            "WRITE TPS: {:.0} ops/sec (ops={}, batch={}, threads={}, group-commit)",
            total_ops as f64 / secs,
            total_ops,
            batch_size,
            threads
        );
        return;
    }

    let wal = "/tmp/donadb-snap-test.wal";
    let snap = format!("{}.snap", wal);
    println!("=== 1. Snapshot write + load ===");
    let _ = std::fs::remove_file(wal);
    let _ = std::fs::remove_file(&snap);
    let _ = std::fs::remove_dir_all(format!("{}.sst", wal));
    {
        let db = DonaDB::open_wal(wal);
        for i in 0..1000usize {
            db.set(
                0,
                Bytes::from(format!("k:{:06}", i)),
                Bytes::from(format!("v:{}", i)),
                0,
            );
        }
        db.sync();
        std::thread::sleep(Duration::from_millis(300));
    }
    let sz = std::fs::metadata(&snap).map(|m| m.len()).unwrap_or(0);
    println!(
        "  snapshot: {} bytes {}",
        sz,
        if sz > 0 { "✓" } else { "✗" }
    );
    println!("=== 2. Corrupt snap → WAL preserved ===");
    let _ = std::fs::remove_file(wal);
    let _ = std::fs::remove_file(&snap);
    {
        let db = DonaDB::open_wal(wal);
        for i in 0..500usize {
            db.set(
                0,
                Bytes::from(format!("bf:{:06}", i)),
                Bytes::from_static(b"v"),
                0,
            );
        }
        db.sync();
    }
    std::fs::write(&snap, b"corrupt").unwrap();
    {
        let db = DonaDB::open_wal(wal);
        let f = (0..500usize)
            .filter(|i| {
                db.get(0, format!("bf:{:06}", i).as_bytes())
                    .ok()
                    .flatten()
                    .is_some()
            })
            .count();
        println!(
            "  WAL intact: {}/500 {}",
            f,
            if f == 500 { "✓" } else { "✗" }
        );
    }
    println!("=== 3. Truncated snap → WAL fallback ===");
    let _ = std::fs::remove_file(wal);
    let _ = std::fs::remove_file(&snap);
    {
        let db = DonaDB::open_wal(wal);
        for i in 0..300usize {
            db.set(
                0,
                Bytes::from(format!("tr:{:06}", i)),
                Bytes::from_static(b"v"),
                0,
            );
        }
        db.sync();
    }
    std::fs::write(&snap, b"truncated").unwrap();
    {
        let db = DonaDB::open_wal(wal);
        let f = (0..300usize)
            .filter(|i| {
                db.get(0, format!("tr:{:06}", i).as_bytes())
                    .ok()
                    .flatten()
                    .is_some()
            })
            .count();
        println!("  fallback: {}/300 {}", f, if f == 300 { "✓" } else { "✗" });
    }
    println!("=== 4. Valid snap CRC ===");
    let _ = std::fs::remove_file(wal);
    let _ = std::fs::remove_file(&snap);
    {
        let db = DonaDB::open_wal(wal);
        for i in 0..200usize {
            db.set(
                0,
                Bytes::from(format!("ok:{:06}", i)),
                Bytes::from_static(b"v"),
                0,
            );
        }
        db.sync();
        std::thread::sleep(Duration::from_millis(300));
    }
    {
        let db = DonaDB::open_wal(wal);
        let f = (0..200usize)
            .filter(|i| {
                db.get(0, format!("ok:{:06}", i).as_bytes())
                    .ok()
                    .flatten()
                    .is_some()
            })
            .count();
        println!("  reload: {}/200 {}", f, if f == 200 { "✓" } else { "✗" });
    }
}
