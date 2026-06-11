#![allow(dead_code)]

use bytes::Bytes;
use donadb::{DonaDb, DonaDbConfig};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub enum SeedKind {
    Wal,
    Sst,
    Snapshot,
}

pub fn seed_dir(kind: SeedKind) -> PathBuf {
    match kind {
        SeedKind::Wal => WAL_SEED.get_or_init(|| build_seed("wal", SeedKind::Wal)).clone(),
        SeedKind::Sst => SST_SEED.get_or_init(|| build_seed("sst", SeedKind::Sst)).clone(),
        SeedKind::Snapshot => SNAP_SEED
            .get_or_init(|| build_seed("snapshot", SeedKind::Snapshot))
            .clone(),
    }
}

static WAL_SEED: OnceLock<PathBuf> = OnceLock::new();
static SST_SEED: OnceLock<PathBuf> = OnceLock::new();
static SNAP_SEED: OnceLock<PathBuf> = OnceLock::new();

fn build_seed(name: &str, kind: SeedKind) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("donadb-fuzz-seed-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create fuzz seed dir");

    match kind {
        SeedKind::Wal => {
            let db = open_db(&dir);
            fill_db(&db, "wal", 80, 97);
            db.sync();
        }
        SeedKind::Sst => {
            configure_small_lsm();
            let db = open_db(&dir);
            fill_db(&db, "sst", 96, 257);
            db.sync();
            wait_for(Duration::from_millis(600), || list_sst_files(&dir).len() > 0);
        }
        SeedKind::Snapshot => {
            configure_small_lsm();
            std::env::set_var("DONADB_COMPACT_KB", "4");
            let db = open_db(&dir);
            fill_db(&db, "snap", 128, 1536);
            db.sync();
            wait_for(Duration::from_millis(1500), || dir.join("donadb.wal.snap").exists());
        }
    }

    dir
}

fn configure_small_lsm() {
    std::env::set_var("DONADB_MEMTABLE_FLUSH", "8");
    std::env::set_var("DONADB_L0_MAX", "2");
    std::env::set_var("DONADB_L1_MAX", "2");
    std::env::set_var("DONADB_L2_MAX", "2");
}

fn open_db(dir: &Path) -> DonaDb {
    DonaDb::open(DonaDbConfig {
        data_dir: dir.to_path_buf(),
        shard_count: 16,
        compaction_threads: 1,
        block_cache_bytes: 1024 * 1024,
        write_buffer_bytes: 1024 * 1024,
    })
    .expect("open fuzz seed db")
}

fn fill_db(db: &DonaDb, prefix: &str, count: usize, value_len: usize) {
    for i in 0..count {
        let mut value = vec![0u8; value_len];
        for (j, byte) in value.iter_mut().enumerate() {
            *byte = ((i.wrapping_mul(31) + j.wrapping_mul(17)) & 0xff) as u8;
        }
        db.set(
            0,
            Bytes::from(format!("{prefix}:{i:04}")),
            Bytes::from(value),
            i as u64 + 1,
        );
    }
}

pub fn copy_seed_to_temp(seed: &Path) -> Option<tempfile::TempDir> {
    let tmp = tempfile::tempdir().ok()?;
    copy_dir_all(seed, tmp.path()).ok()?;
    Some(tmp)
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else if ty.is_file() {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

pub fn list_sst_files(dir: &Path) -> Vec<PathBuf> {
    let sst_dir = dir.join("donadb.wal.sst");
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(sst_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "sst") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

pub fn mutate_file(path: &Path, data: &[u8]) {
    let Ok(mut bytes) = fs::read(path) else {
        return;
    };
    if data.is_empty() || bytes.is_empty() {
        return;
    }

    let mut cursor = 0usize;
    let operations = 1 + (data[cursor] as usize % 16);
    cursor = cursor.wrapping_add(1);

    for _ in 0..operations {
        if cursor >= data.len() || bytes.is_empty() {
            break;
        }
        let op = data[cursor] % 6;
        cursor += 1;
        let pos = pick_usize(data, &mut cursor, bytes.len());
        match op {
            0 => bytes[pos] ^= 1u8 << (data.get(cursor).copied().unwrap_or(0) % 8),
            1 => bytes[pos] = data.get(cursor).copied().unwrap_or(0xff),
            2 => {
                let new_len = pick_usize(data, &mut cursor, bytes.len());
                bytes.truncate(new_len);
            }
            3 => {
                let insert_len = 1 + pick_usize(data, &mut cursor, 32);
                let mut insert = Vec::with_capacity(insert_len);
                for _ in 0..insert_len {
                    insert.push(data.get(cursor).copied().unwrap_or(0xa5));
                    cursor = cursor.wrapping_add(1);
                }
                let at = pos.min(bytes.len());
                bytes.splice(at..at, insert);
            }
            4 => {
                let len = pick_usize(data, &mut cursor, 64).min(bytes.len() - pos);
                bytes.drain(pos..pos + len);
            }
            _ => {
                let width = if data.get(cursor).copied().unwrap_or(0) & 1 == 0 { 4 } else { 8 };
                cursor = cursor.wrapping_add(1);
                for i in 0..width {
                    if pos + i < bytes.len() {
                        bytes[pos + i] = 0xff;
                    }
                }
            }
        }
        cursor = cursor.wrapping_add(1);
    }

    let _ = fs::write(path, bytes);
}

fn pick_usize(data: &[u8], cursor: &mut usize, modulo: usize) -> usize {
    if modulo == 0 {
        return 0;
    }
    let mut value = 0usize;
    for shift in 0..8 {
        let b = data.get(*cursor).copied().unwrap_or(0) as usize;
        value ^= b << ((shift % std::mem::size_of::<usize>()) * 8);
        *cursor = (*cursor).wrapping_add(1);
    }
    value % modulo
}

pub fn recover_and_exercise(dir: &Path, prefix: &[u8]) {
    let Ok(db) = DonaDb::open(DonaDbConfig {
        data_dir: dir.to_path_buf(),
        shard_count: 16,
        compaction_threads: 1,
        block_cache_bytes: 1024 * 1024,
        write_buffer_bytes: 1024 * 1024,
    }) else {
        return;
    };

    for i in [0usize, 1, 7, 31, 79, 127] {
        let key = format!("{}:{i:04}", String::from_utf8_lossy(prefix));
        let _ = db.get(0, key.as_bytes());
        let _ = db.get_at(0, key.as_bytes(), i as u64 + 1);
    }
    let _ = db.scan_prefix_domain(0, prefix);
    let _ = db.scan(0, prefix, b"zzzz");
    let _ = db.metrics();

    let checkpoint = dir.join("checkpoint-copy");
    if db.checkpoint(&checkpoint).is_ok() {
        let _ = DonaDb::open(DonaDbConfig {
            data_dir: checkpoint,
            shard_count: 16,
            compaction_threads: 1,
            block_cache_bytes: 1024 * 1024,
            write_buffer_bytes: 1024 * 1024,
        });
    }
}

fn wait_for(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
