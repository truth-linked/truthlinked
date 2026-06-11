//! DonaDB throughput and correctness probe.
//!
//! This binary combines basic correctness checks with heavier WAL, SST,
//! compaction, and versioned-read workloads. It is useful for local capacity
//! checks; the integration tests remain the authoritative regression suite.

use bytes::Bytes;
use donadb::{DonaDB, WriteBatch};
use std::sync::{Arc, Barrier};
use std::time::Instant;

fn cleanup(wal: &str) {
    let _ = std::fs::remove_file(wal);
    let _ = std::fs::remove_file(format!("{}.snap", wal));
    let _ = std::fs::remove_dir_all(format!("{}.sst", wal));
}

fn test_versioned_rw() {
    println!("\n=== 1. Versioned Read/Write Correctness ===");
    let wal = "/tmp/donadb-tps-versioned.wal";
    cleanup(wal);

    let db = DonaDB::open_wal(wal);
    let domain = 1u32;
    let key = b"balance:alice";

    for h in 0u64..10 {
        db.set(
            domain,
            Bytes::copy_from_slice(key),
            Bytes::copy_from_slice(&(h * 100).to_le_bytes()),
            h,
        );
    }
    db.sync();

    let head = db.get(domain, key).unwrap().unwrap();
    let head_val = u64::from_le_bytes(head.as_ref().try_into().unwrap());
    println!(
        "  head (latest) = {} (expected 900) {}",
        head_val,
        if head_val == 900 { "✓" } else { "✗" }
    );

    let mut ok = true;
    for h in 0u64..10 {
        let v = db.get_at(domain, key, h).unwrap();
        let val = v
            .as_ref()
            .and_then(|b| b.as_ref().try_into().ok().map(u64::from_le_bytes));
        let expected = h * 100;
        if val != Some(expected) {
            println!("  height {} = {:?} (expected {}) ✗", h, val, expected);
            ok = false;
        }
    }
    if ok {
        println!("  versioned reads at heights 0-9 ✓");
    }

    db.set(
        domain,
        Bytes::copy_from_slice(key),
        Bytes::copy_from_slice(&9999u64.to_le_bytes()),
        10,
    );
    db.sync();
    let head2 = db.get(domain, key).unwrap().unwrap();
    let head2_val = u64::from_le_bytes(head2.as_ref().try_into().unwrap());
    println!(
        "  after overwrite at h=10: head = {} (expected 9999) {}",
        head2_val,
        if head2_val == 9999 { "✓" } else { "✗" }
    );

    let old = db.get_at(domain, key, 5).unwrap();
    let old_val = old
        .as_ref()
        .and_then(|b| b.as_ref().try_into().ok().map(u64::from_le_bytes));
    println!(
        "  history at h=5 = {:?} (expected 500) {}",
        old_val,
        if old_val == Some(500) { "✓" } else { "✗" }
    );
}

fn test_wal_tps_sequential(ops: usize) {
    println!("\n=== 2. WAL TPS — Sequential ({} ops) ===", ops);
    let wal = "/tmp/donadb-tps-seq.wal";
    cleanup(wal);

    let db = DonaDB::open_wal(wal);
    let val = Bytes::from_static(b"value_payload_32bytes_xxxxxxxxxxx");

    let t = Instant::now();
    for i in 0..ops {
        db.set(
            0,
            Bytes::from(format!("k:{:010}", i)),
            val.clone(),
            i as u64,
        );
    }
    db.sync();
    let elapsed = t.elapsed().as_secs_f64();
    println!(
        "  {:.0} ops/sec  ({:.2}ms total)",
        ops as f64 / elapsed,
        elapsed * 1000.0
    );
}

fn test_wal_tps_parallel(total_ops: usize, threads: usize, batch_size: usize) {
    println!(
        "\n=== 3. WAL TPS — Parallel ({} ops, {} threads, batch={}) ===",
        total_ops, threads, batch_size
    );
    let wal = "/tmp/donadb-tps-par.wal";
    cleanup(wal);

    let db = Arc::new(DonaDB::open_wal(wal));
    let barrier = Arc::new(Barrier::new(threads));
    let per = total_ops / threads;
    let blocks_each = (per + batch_size - 1) / batch_size;
    let val = Bytes::from_static(b"v");

    let t = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|t_id| {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            let val = val.clone();
            std::thread::spawn(move || {
                let base = t_id * per;
                for b in 0..blocks_each {
                    let mut batch = WriteBatch::new();
                    let lo = base + b * batch_size;
                    let hi = (lo + batch_size).min(base + per);
                    for i in lo..hi {
                        batch.set(Bytes::from(format!("k:{:010}", i)), val.clone());
                    }
                    db.write_batch(batch);
                    let w = barrier.wait();
                    if w.is_leader() {
                        db.sync();
                    }
                    barrier.wait();
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
    db.sync();

    let elapsed = t.elapsed().as_secs_f64();
    println!(
        "  {:.0} ops/sec  ({:.2}ms total)",
        total_ops as f64 / elapsed,
        elapsed * 1000.0
    );

    let spot = [0, total_ops / 4, total_ops / 2, total_ops - 1];
    let mut all_ok = true;
    for k in spot {
        if db
            .get(0, format!("k:{:010}", k).as_bytes())
            .ok()
            .flatten()
            .is_none()
        {
            println!("  MISSING key k:{:010} ✗", k);
            all_ok = false;
        }
    }
    if all_ok {
        println!("  spot-check reads ✓");
    }
}

fn test_compaction() {
    println!("\n=== 4. Compaction Under Load ===");
    let wal = "/tmp/donadb-tps-compact.wal";
    cleanup(wal);

    unsafe {
        std::env::set_var("DONADB_COMPACT_KB", "512");
    }

    let db = Arc::new(DonaDB::open_wal(wal));
    let val = Bytes::from(vec![b'x'; 64]);
    let ops = 200_000usize;

    let t = Instant::now();
    for i in 0..ops {
        db.set(
            0,
            Bytes::from(format!("c:{:010}", i)),
            val.clone(),
            i as u64,
        );
        if i % 20_000 == 19_999 {
            db.sync();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    db.sync();
    std::thread::sleep(std::time::Duration::from_millis(300));

    let elapsed = t.elapsed().as_secs_f64();
    println!(
        "  {:.0} ops/sec under compaction pressure",
        ops as f64 / elapsed
    );

    let spot = [0usize, 50_000, 100_000, 199_999];
    let mut all_ok = true;
    for k in spot {
        if db
            .get(0, format!("c:{:010}", k).as_bytes())
            .ok()
            .flatten()
            .is_none()
        {
            println!("  MISSING after compaction: c:{:010} ✗", k);
            all_ok = false;
        }
    }
    if all_ok {
        println!("  data intact after compaction ✓");
    }

    unsafe {
        std::env::remove_var("DONADB_COMPACT_KB");
    }
}

fn test_sst_flush() {
    println!("\n=== 5. SST Flush + Read-back ===");
    let wal = "/tmp/donadb-tps-sst.wal";
    cleanup(wal);

    unsafe {
        std::env::set_var("DONADB_MEMTABLE_FLUSH", "50000");
        std::env::set_var("DONADB_L0_MAX", "2");
        std::env::set_var("DONADB_L1_MAX", "2");
    }

    let db = DonaDB::open_wal(wal);
    let total = 300_000usize;
    let val = Bytes::from_static(b"sst_val");

    let t = Instant::now();
    for i in 0..total {
        db.set(
            0,
            Bytes::from(format!("s:{:010}", i)),
            val.clone(),
            i as u64,
        );
        if i % 50_000 == 49_999 {
            db.sync();
            let (l0, l1, l2) = db.sst_stats();
            println!("  wrote {} | l0={} l1={} l2={}", i + 1, l0, l1, l2);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    db.sync();
    std::thread::sleep(std::time::Duration::from_millis(300));

    let elapsed = t.elapsed().as_secs_f64();
    let (l0, l1, l2) = db.sst_stats();
    println!(
        "  {:.0} ops/sec | final l0={} l1={} l2={}",
        total as f64 / elapsed,
        l0,
        l1,
        l2
    );

    let spot = [0usize, 49_999, 100_000, 200_000, 299_999];
    let mut found = 0;
    for k in spot {
        if db
            .get(0, format!("s:{:010}", k).as_bytes())
            .ok()
            .flatten()
            .is_some()
        {
            found += 1;
        }
    }
    println!(
        "  reads across levels: {}/{} {}",
        found,
        spot.len(),
        if found == spot.len() { "✓" } else { "✗" }
    );

    unsafe {
        std::env::remove_var("DONADB_MEMTABLE_FLUSH");
        std::env::remove_var("DONADB_L0_MAX");
        std::env::remove_var("DONADB_L1_MAX");
    }
}

fn test_versioned_after_flush() {
    println!("\n=== 6. Versioned Reads After SST Flush ===");
    let wal = "/tmp/donadb-tps-ver-sst.wal";
    cleanup(wal);

    unsafe {
        std::env::set_var("DONADB_MEMTABLE_FLUSH", "10000");
    }

    let db = DonaDB::open_wal(wal);
    let domain = 2u32;

    let keys = 200usize;
    let versions = 50u64;
    for h in 0..versions {
        for k in 0..keys {
            db.set(
                domain,
                Bytes::from(format!("acct:{:04}", k)),
                Bytes::copy_from_slice(&((h * 1000 + k as u64) as u64).to_le_bytes()),
                h,
            );
        }
        if h % 10 == 9 {
            db.sync();
        }
    }
    db.sync();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let check_heights = [0u64, 25, 49];
    let mut all_ok = true;
    for h in check_heights {
        for k in [0usize, 99, 199] {
            let v = db
                .get_at(domain, format!("acct:{:04}", k).as_bytes(), h)
                .unwrap();
            let val = v
                .as_ref()
                .and_then(|b| b.as_ref().try_into().ok().map(u64::from_le_bytes));
            let expected = h * 1000 + k as u64;
            if val != Some(expected) {
                println!("  h={} k={} = {:?} (expected {}) ✗", h, k, val, expected);
                all_ok = false;
            }
        }
    }
    if all_ok {
        println!("  versioned reads across SST flush ✓");
    }

    unsafe {
        std::env::remove_var("DONADB_MEMTABLE_FLUSH");
    }
}

fn test_deletes() {
    println!("\n=== 7. Delete + Tombstone ===");
    let wal = "/tmp/donadb-tps-del.wal";
    cleanup(wal);

    let db = DonaDB::open_wal(wal);
    let domain = 0u32;

    for i in 0..1000usize {
        db.set(
            domain,
            Bytes::from(format!("d:{:04}", i)),
            Bytes::from_static(b"alive"),
            i as u64,
        );
    }
    db.sync();

    for i in (0..1000usize).step_by(2) {
        db.del(domain, format!("d:{:04}", i).as_bytes(), 1001);
    }
    db.sync();

    let mut missing_evens = 0;
    let mut present_odds = 0;
    for i in 0..1000usize {
        let v = db
            .get(domain, format!("d:{:04}", i).as_bytes())
            .ok()
            .flatten();
        if i % 2 == 0 && v.is_none() {
            missing_evens += 1;
        }
        if i % 2 == 1 && v.is_some() {
            present_odds += 1;
        }
    }
    println!(
        "  deleted evens gone: {}/500 {}",
        missing_evens,
        if missing_evens == 500 { "✓" } else { "✗" }
    );
    println!(
        "  odds still present: {}/500 {}",
        present_odds,
        if present_odds == 500 { "✓" } else { "✗" }
    );
}

fn main() {
    println!("DonaDB Full TPS + Correctness Test");
    println!("====================================");

    test_versioned_rw();
    test_wal_tps_sequential(500_000);
    test_wal_tps_parallel(1_000_000, 8, 1_000);
    test_compaction();
    test_sst_flush();
    test_versioned_after_flush();
    test_deletes();

    println!("\n=== Done ===");
}
