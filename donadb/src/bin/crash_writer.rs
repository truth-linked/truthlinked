//! Crash-test workload generator for DonaDB.
//!
//! The integration tests spawn this binary, let it write under a specific
//! pressure mode, and kill the process without shutdown. The parent test then
//! reopens the database and verifies that committed prefixes remain readable.

use bytes::Bytes;
use donadb::{DonaDb, DonaDbConfig};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn configure_pressure() {
    unsafe {
        std::env::set_var("DONADB_MEMTABLE_FLUSH", "32");
        std::env::set_var("DONADB_COMPACT_KB", "64");
        std::env::set_var("DONADB_L0_MAX", "2");
        std::env::set_var("DONADB_L1_MAX", "2");
        std::env::set_var("DONADB_L2_MAX", "2");
    }
}

fn open_db(dir: &Path) -> DonaDb {
    DonaDb::open(DonaDbConfig {
        data_dir: dir.to_path_buf(),
        shard_count: 32,
        compaction_threads: 2,
        block_cache_bytes: 4 * 1024 * 1024,
        write_buffer_bytes: 4 * 1024 * 1024,
    })
    .expect("open db")
}

fn write_record(db: &DonaDb, prefix: &str, i: usize, value_len: usize) {
    db.set(
        0,
        Bytes::from(format!("{prefix}:{i:08}")),
        Bytes::from(vec![(i % 251) as u8; value_len]),
        i as u64,
    );
}

fn log_metrics(db: &DonaDb, mode: &str, i: usize) {
    let m = db.metrics();
    eprintln!(
        "mode={mode} i={i} flush={} compact={} l0={} l1={} l2={} wal_bytes={} wal_file={} snap={}",
        m.flush_active,
        m.compaction_active,
        m.sst_l0_files,
        m.sst_l1_files,
        m.sst_l2_files,
        m.wal_bytes_since_compaction,
        m.wal_file_bytes,
        m.snapshot_file_bytes
    );
}

fn wal_loop(dir: &Path) {
    let db = open_db(dir);
    for i in 0..500_000usize {
        write_record(&db, "wal", i, 256);
        if i % 8 == 7 {
            db.sync();
        }
        if i % 256 == 255 {
            log_metrics(&db, "wal", i);
        }
    }
    db.sync();
}

fn flush_loop(dir: &Path) {
    let db = open_db(dir);
    for i in 0..500_000usize {
        write_record(&db, "flush", i, 1024);
        if i % 16 == 15 {
            db.sync();
        }
        if i % 256 == 255 {
            log_metrics(&db, "flush", i);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    db.sync();
}

fn compaction_loop(dir: &Path) {
    let db = open_db(dir);
    for i in 0..500_000usize {
        write_record(&db, "compact", i, 2048);
        if i % 32 == 31 {
            db.sync();
        }
        if i % 128 == 127 {
            log_metrics(&db, "compact", i);
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    db.sync();
}

fn checkpoint_loop(dir: &Path, checkpoint_dir: &Path) {
    let db = open_db(dir);
    for i in 0..500_000usize {
        write_record(&db, "checkpoint", i, 1536);
        if i % 24 == 23 {
            db.sync();
        }
        if i % 128 == 127 {
            let _ = db.checkpoint(checkpoint_dir);
            log_metrics(&db, "checkpoint", i);
        }
    }
    db.sync();
    let _ = db.checkpoint(checkpoint_dir);
}

fn restart_loop(dir: &Path) {
    for round in 0..100_000usize {
        let db = open_db(dir);
        for j in 0..64usize {
            let i = round * 64 + j;
            write_record(&db, "restart", i, 512);
        }
        db.sync();
        log_metrics(&db, "restart", round * 64);
        drop(db);
    }
}

fn main() {
    configure_pressure();
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("data dir"));
    let mode = args
        .next()
        .unwrap_or_else(|| "flush-compaction".to_string());
    let checkpoint_dir = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.with_extension("checkpoint"));

    match mode.as_str() {
        "wal" => wal_loop(&dir),
        "flush" => flush_loop(&dir),
        "compaction" | "flush-compaction" => compaction_loop(&dir),
        "checkpoint" => checkpoint_loop(&dir, &checkpoint_dir),
        "restart-loop" => restart_loop(&dir),
        other => panic!("unknown crash writer mode: {other}"),
    }
}
