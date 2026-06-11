use bytes::Bytes;
use donadb::{DonaDb, DonaDbConfig, WriteBatch};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tempfile::TempDir;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn open_temp_db() -> (TempDir, DonaDb) {
    let dir = TempDir::new().unwrap();
    let db = DonaDb::open(DonaDbConfig {
        data_dir: dir.path().to_path_buf(),
        shard_count: 16,
        compaction_threads: 2,
        block_cache_bytes: 4 * 1024 * 1024,
        write_buffer_bytes: 4 * 1024 * 1024,
    })
    .unwrap();
    (dir, db)
}

fn batch_marker(tag: u8) -> Vec<u8> {
    let mut b = vec![tag];
    b.extend_from_slice(&crc32fast::hash(&[tag]).to_le_bytes());
    b
}

fn head_key(domain: u32, user_key: &[u8]) -> Bytes {
    let mut b = Vec::with_capacity(1 + 4 + user_key.len());
    b.push(0x01);
    b.extend_from_slice(&domain.to_be_bytes());
    b.extend_from_slice(user_key);
    Bytes::from(b)
}

fn encode_set(key: &Bytes, val: &Bytes) -> Vec<u8> {
    let mut b = Vec::with_capacity(13 + key.len() + val.len());
    b.push(0u8);
    b.extend_from_slice(&(key.len() as u32).to_le_bytes());
    b.extend_from_slice(key);
    b.extend_from_slice(&(val.len() as u32).to_le_bytes());
    b.extend_from_slice(val);
    let crc = crc32fast::hash(&b);
    b.extend_from_slice(&crc.to_le_bytes());
    b
}

#[test]
fn wal_replay_persists_synced_batch_after_reopen() {
    let dir = TempDir::new().unwrap();
    {
        let db = DonaDb::open(DonaDbConfig {
            data_dir: dir.path().to_path_buf(),
            ..DonaDbConfig::default()
        })
        .unwrap();
        let mut batch = WriteBatch::new();
        batch.put(
            7,
            Bytes::from_static(b"account:a"),
            Bytes::from_static(b"100"),
        );
        batch.put(
            7,
            Bytes::from_static(b"account:b"),
            Bytes::from_static(b"200"),
        );
        db.write_batch(batch);
        db.finalize_block(42).unwrap();
    }

    let reopened = DonaDb::open(DonaDbConfig {
        data_dir: dir.path().to_path_buf(),
        ..DonaDbConfig::default()
    })
    .unwrap();
    assert_eq!(reopened.get(7, b"account:a").unwrap().unwrap(), b"100"[..]);
    assert_eq!(reopened.get(7, b"account:b").unwrap().unwrap(), b"200"[..]);
}

#[test]
fn wal_replay_ignores_incomplete_batch_tail() {
    let dir = TempDir::new().unwrap();
    {
        let db = DonaDb::open(DonaDbConfig {
            data_dir: dir.path().to_path_buf(),
            ..DonaDbConfig::default()
        })
        .unwrap();
        db.set(
            0,
            Bytes::from_static(b"committed"),
            Bytes::from_static(b"yes"),
            1,
        );
        db.sync();
    }

    let wal_path = dir.path().join("donadb.wal");
    let mut wal = OpenOptions::new().append(true).open(&wal_path).unwrap();
    wal.write_all(&batch_marker(2)).unwrap();
    wal.write_all(&encode_set(
        &head_key(0, b"half-written"),
        &Bytes::from_static(b"must-not-appear"),
    ))
    .unwrap();
    wal.sync_all().unwrap();

    let reopened = DonaDb::open(DonaDbConfig {
        data_dir: dir.path().to_path_buf(),
        ..DonaDbConfig::default()
    })
    .unwrap();
    assert_eq!(reopened.get(0, b"committed").unwrap().unwrap(), b"yes"[..]);
    assert!(reopened.get(0, b"half-written").unwrap().is_none());
}

#[test]
fn versioned_reads_keep_historical_values_and_head() {
    let (_dir, db) = open_temp_db();
    for h in 1..=10u64 {
        db.set(
            3,
            Bytes::from_static(b"balance"),
            Bytes::from(h.to_le_bytes().to_vec()),
            h,
        );
    }
    db.sync();

    assert_eq!(
        u64::from_le_bytes(
            db.get(3, b"balance")
                .unwrap()
                .unwrap()
                .as_ref()
                .try_into()
                .unwrap()
        ),
        10
    );
    assert_eq!(
        u64::from_le_bytes(
            db.get_at(3, b"balance", 4)
                .unwrap()
                .unwrap()
                .as_ref()
                .try_into()
                .unwrap()
        ),
        4
    );
    assert!(db.get_at(3, b"balance", 0).unwrap().is_none());
}

#[test]
fn delete_tombstone_survives_reopen() {
    let dir = TempDir::new().unwrap();
    {
        let db = DonaDb::open(DonaDbConfig {
            data_dir: dir.path().to_path_buf(),
            ..DonaDbConfig::default()
        })
        .unwrap();
        db.set(
            0,
            Bytes::from_static(b"doomed"),
            Bytes::from_static(b"value"),
            1,
        );
        db.del(0, b"doomed", 2);
        db.finalize_block(2).unwrap();
        assert!(db.get(0, b"doomed").unwrap().is_none());
    }
    let reopened = DonaDb::open(DonaDbConfig {
        data_dir: dir.path().to_path_buf(),
        ..DonaDbConfig::default()
    })
    .unwrap();
    assert!(reopened.get(0, b"doomed").unwrap().is_none());
    assert_eq!(
        reopened.get_at(0, b"doomed", 1).unwrap().unwrap(),
        b"value"[..]
    );
}

#[test]
fn prefix_and_range_scans_return_sorted_live_heads_only() {
    let (_dir, db) = open_temp_db();
    for key in ["acct:001", "acct:002", "acct:003", "cfg:001"] {
        db.set(
            0,
            Bytes::from(key.as_bytes().to_vec()),
            Bytes::from_static(b"v"),
            1,
        );
    }
    db.del(0, b"acct:002", 2);
    db.sync();

    let prefix: Vec<_> = db
        .scan_prefix_domain(0, b"acct:")
        .unwrap()
        .into_iter()
        .map(|(k, _)| String::from_utf8(k.to_vec()).unwrap())
        .collect();
    assert_eq!(prefix, vec!["acct:001", "acct:003"]);

    let range: Vec<_> = db
        .scan(0, b"acct:001", b"acct:999")
        .unwrap()
        .into_iter()
        .map(|(k, _)| String::from_utf8(k.to_vec()).unwrap())
        .collect();
    assert_eq!(range, vec!["acct:001", "acct:003"]);
}

#[test]
fn memtable_flush_to_sst_preserves_reads_after_reopen() {
    let _guard = env_lock().lock().unwrap();
    unsafe {
        std::env::set_var("DONADB_MEMTABLE_FLUSH", "16");
    }
    let dir = TempDir::new().unwrap();
    {
        let db = DonaDb::open(DonaDbConfig {
            data_dir: dir.path().to_path_buf(),
            ..DonaDbConfig::default()
        })
        .unwrap();
        for i in 0..256usize {
            db.set(
                0,
                Bytes::from(format!("flush:{i:04}")),
                Bytes::from(format!("v{i}")),
                i as u64,
            );
        }
        db.sync();
        std::thread::sleep(Duration::from_millis(300));
        let (l0, l1, l2) = db.sst_stats();
        assert!(
            l0 + l1 + l2 > 0,
            "expected SST files after flush, got {l0}/{l1}/{l2}"
        );
    }

    let reopened = DonaDb::open(DonaDbConfig {
        data_dir: dir.path().to_path_buf(),
        ..DonaDbConfig::default()
    })
    .unwrap();
    for i in [0usize, 31, 127, 255] {
        assert_eq!(
            reopened
                .get(0, format!("flush:{i:04}").as_bytes())
                .unwrap()
                .unwrap(),
            format!("v{i}").as_bytes()[..]
        );
    }
    unsafe {
        std::env::remove_var("DONADB_MEMTABLE_FLUSH");
    }
}

#[test]
fn compaction_pressure_keeps_all_spot_reads() {
    let _guard = env_lock().lock().unwrap();
    unsafe {
        std::env::set_var("DONADB_MEMTABLE_FLUSH", "32");
        std::env::set_var("DONADB_L0_MAX", "2");
        std::env::set_var("DONADB_L1_MAX", "2");
        std::env::set_var("DONADB_L2_MAX", "2");
    }
    let (_dir, db) = open_temp_db();
    for i in 0..2_000usize {
        db.set(
            0,
            Bytes::from(format!("compact:{i:05}")),
            Bytes::from(vec![(i % 251) as u8; 128]),
            i as u64,
        );
        if i % 100 == 99 {
            db.sync();
        }
    }
    db.sync();
    std::thread::sleep(Duration::from_millis(800));
    let (l0, l1, l2) = db.sst_stats();
    assert!(l0 + l1 + l2 > 0);

    for i in [0usize, 17, 255, 777, 1_999] {
        let value = db
            .get(0, format!("compact:{i:05}").as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(value.len(), 128);
        assert_eq!(value[0], (i % 251) as u8);
    }
    unsafe {
        std::env::remove_var("DONADB_MEMTABLE_FLUSH");
        std::env::remove_var("DONADB_L0_MAX");
        std::env::remove_var("DONADB_L1_MAX");
        std::env::remove_var("DONADB_L2_MAX");
    }
}

#[test]
fn checkpoint_restores_wal_snapshot_and_sst_data() {
    let _guard = env_lock().lock().unwrap();
    unsafe {
        std::env::set_var("DONADB_MEMTABLE_FLUSH", "16");
    }
    let dir = TempDir::new().unwrap();
    let checkpoint = TempDir::new().unwrap();
    let checkpoint_path = checkpoint.path().join("cp");
    {
        let db = DonaDb::open(DonaDbConfig {
            data_dir: dir.path().to_path_buf(),
            ..DonaDbConfig::default()
        })
        .unwrap();
        for i in 0..256usize {
            db.set(
                0,
                Bytes::from(format!("cp:{i:04}")),
                Bytes::from(format!("v{i}")),
                i as u64,
            );
        }
        db.sync();
        std::thread::sleep(Duration::from_millis(250));
        db.checkpoint(&checkpoint_path).unwrap();
    }
    let restored = DonaDb::open(DonaDbConfig {
        data_dir: checkpoint_path,
        ..DonaDbConfig::default()
    })
    .unwrap();
    for i in [0usize, 63, 128, 255] {
        assert_eq!(
            restored
                .get(0, format!("cp:{i:04}").as_bytes())
                .unwrap()
                .unwrap(),
            format!("v{i}").as_bytes()[..]
        );
    }
    unsafe {
        std::env::remove_var("DONADB_MEMTABLE_FLUSH");
    }
}

#[test]
fn metrics_report_flush_compaction_sst_and_read_amplification() {
    let _guard = env_lock().lock().unwrap();
    unsafe {
        std::env::set_var("DONADB_MEMTABLE_FLUSH", "32");
        std::env::set_var("DONADB_COMPACT_KB", "64");
        std::env::set_var("DONADB_L0_MAX", "2");
        std::env::set_var("DONADB_L1_MAX", "2");
        std::env::set_var("DONADB_L2_MAX", "2");
    }
    let (_dir, db) = open_temp_db();
    for i in 0..512usize {
        db.set(
            0,
            Bytes::from(format!("metric:{i:04}")),
            Bytes::from(vec![i as u8; 512]),
            i as u64,
        );
        if i % 64 == 63 {
            db.sync();
        }
    }
    db.sync();
    std::thread::sleep(Duration::from_millis(500));
    let m = db.metrics();
    assert!(m.index_entries > 0);
    assert!(m.wal_file_bytes > 0 || m.snapshot_file_bytes > 0);
    assert!(m.sst_l0_files + m.sst_l1_files + m.sst_l2_files > 0);
    assert!(m.estimated_read_amplification >= 1);
    unsafe {
        std::env::remove_var("DONADB_MEMTABLE_FLUSH");
        std::env::remove_var("DONADB_COMPACT_KB");
        std::env::remove_var("DONADB_L0_MAX");
        std::env::remove_var("DONADB_L1_MAX");
        std::env::remove_var("DONADB_L2_MAX");
    }
}

#[test]
fn wal_corruption_stops_replay_without_panicking_and_keeps_prior_batch() {
    let dir = TempDir::new().unwrap();
    {
        let db = DonaDb::open(DonaDbConfig {
            data_dir: dir.path().to_path_buf(),
            ..DonaDbConfig::default()
        })
        .unwrap();
        db.set(
            0,
            Bytes::from_static(b"safe"),
            Bytes::from_static(b"before"),
            1,
        );
        db.sync();
        db.set(
            0,
            Bytes::from_static(b"after"),
            Bytes::from_static(b"maybe"),
            2,
        );
        db.sync();
    }
    let wal_path = dir.path().join("donadb.wal");
    let mut bytes = std::fs::read(&wal_path).unwrap();
    assert!(bytes.len() > 20);
    let pos = bytes.len() / 2;
    bytes[pos] ^= 0x55;
    std::fs::write(&wal_path, bytes).unwrap();

    let reopened = DonaDb::open(DonaDbConfig {
        data_dir: dir.path().to_path_buf(),
        ..DonaDbConfig::default()
    })
    .unwrap();
    assert_eq!(reopened.get(0, b"safe").unwrap().unwrap(), b"before"[..]);
    let _ = reopened.get(0, b"after").unwrap();
}

fn crash_writer_exe() -> String {
    std::env::var("CARGO_BIN_EXE_donadb-crash-writer")
        .unwrap_or_else(|_| "target/debug/donadb-crash-writer".to_string())
}

fn kill_writer_after(
    dir: &TempDir,
    mode: &str,
    checkpoint: Option<&std::path::Path>,
    after: Duration,
) {
    let mut cmd = std::process::Command::new(crash_writer_exe());
    cmd.arg(dir.path())
        .arg(mode)
        .stderr(std::process::Stdio::piped());
    if let Some(path) = checkpoint {
        cmd.arg(path);
    }
    let mut child = cmd.spawn().expect("spawn crash writer");
    std::thread::sleep(after);
    let _ = child.kill();
    let _ = child.wait();
}

fn assert_committed_prefix(dir: &TempDir, prefix: &str, min_found: usize) -> DonaDb {
    let db = DonaDb::open(DonaDbConfig {
        data_dir: dir.path().to_path_buf(),
        ..DonaDbConfig::default()
    })
    .unwrap();
    let mut contiguous = 0usize;
    for i in 0..50_000usize {
        if db
            .get(0, format!("{prefix}:{i:08}").as_bytes())
            .unwrap()
            .is_some()
        {
            contiguous += 1;
        } else {
            break;
        }
    }
    let sampled_found = (0..50_000usize)
        .step_by(97)
        .filter(|i| {
            db.get(0, format!("{prefix}:{i:08}").as_bytes())
                .unwrap()
                .is_some()
        })
        .count();
    assert!(
        contiguous >= min_found,
        "expected committed {prefix} prefix >= {min_found}, contiguous={contiguous}, sampled_found={sampled_found}"
    );
    db
}

#[test]
fn process_kill_during_wal_write_recovers_committed_prefix() {
    let dir = TempDir::new().unwrap();
    kill_writer_after(&dir, "wal", None, Duration::from_millis(350));
    let db = assert_committed_prefix(&dir, "wal", 8);
    let m = db.metrics();
    assert!(m.wal_file_bytes > 0 || m.snapshot_file_bytes > 0);
}

#[test]
fn process_kill_during_flush_recovers_committed_prefix() {
    let dir = TempDir::new().unwrap();
    kill_writer_after(&dir, "flush", None, Duration::from_millis(650));
    let db = assert_committed_prefix(&dir, "flush", 16);
    let m = db.metrics();
    assert!(m.sst_l0_files + m.sst_l1_files + m.sst_l2_files > 0 || m.wal_file_bytes > 0);
}

#[test]
fn process_kill_during_compaction_recovers_committed_prefix() {
    let dir = TempDir::new().unwrap();
    kill_writer_after(&dir, "compaction", None, Duration::from_millis(900));
    let db = assert_committed_prefix(&dir, "compact", 32);
    let m = db.metrics();
    assert!(m.wal_file_bytes > 0 || m.snapshot_file_bytes > 0);
}

#[test]
fn process_kill_during_checkpoint_keeps_primary_db_and_visible_checkpoint_openable() {
    let dir = TempDir::new().unwrap();
    let checkpoint_root = TempDir::new().unwrap();
    let checkpoint = checkpoint_root.path().join("checkpoint");
    kill_writer_after(
        &dir,
        "checkpoint",
        Some(&checkpoint),
        Duration::from_millis(900),
    );
    let _primary = assert_committed_prefix(&dir, "checkpoint", 24);

    if checkpoint.exists() {
        let cp = DonaDb::open(DonaDbConfig {
            data_dir: checkpoint.clone(),
            ..DonaDbConfig::default()
        })
        .unwrap();
        let found = (0..50_000usize)
            .filter(|i| {
                cp.get(0, format!("checkpoint:{i:08}").as_bytes())
                    .unwrap()
                    .is_some()
            })
            .count();
        assert!(
            found >= 24,
            "visible checkpoint opened but had only {found} keys"
        );
    }
}

#[test]
fn process_kill_during_restart_loop_recovers_committed_prefix() {
    let dir = TempDir::new().unwrap();
    kill_writer_after(&dir, "restart-loop", None, Duration::from_millis(800));
    let db = assert_committed_prefix(&dir, "restart", 64);
    let m = db.metrics();
    assert!(
        m.wal_file_bytes > 0
            || m.snapshot_file_bytes > 0
            || m.sst_l0_files + m.sst_l1_files + m.sst_l2_files > 0
    );
}

#[test]
fn process_kill_matrix_survives_repeated_reopen_cycles() {
    let cases = [
        ("wal", "wal", 250, 8),
        ("flush", "flush", 450, 16),
        ("compaction", "compact", 650, 32),
        ("restart-loop", "restart", 450, 64),
    ];
    for (mode, prefix, delay_ms, min_found) in cases {
        let dir = TempDir::new().unwrap();
        for _ in 0..3 {
            kill_writer_after(&dir, mode, None, Duration::from_millis(delay_ms));
            let _ = assert_committed_prefix(&dir, prefix, min_found);
        }
    }
}
