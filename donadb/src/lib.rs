//! DonaDB is TruthLinked Labs embedded storage engine for validator state.
//!
//! The engine is built around a write-ahead log, in-memory memtables, immutable
//! SST files, and CRC-protected snapshots. Writes update the active memtable
//! immediately and are appended to the WAL by a dedicated writer thread. Reads
//! consult the active memtable, any frozen memtable being flushed or compacted,
//! and finally the SST tier.
//!
//! Recovery always starts from the latest readable snapshot, then replays the
//! WAL until the first incomplete or corrupt record. This makes torn WAL tails
//! safe after process death while preserving all fully synced batches. Snapshot
//! rotation is deliberately conservative: DonaDB verifies a freshly written
//! snapshot before it asks the WAL writer to truncate and reopen the log.
//!
//! Keys are separated by domain and by record kind. Head keys store the latest
//! value for normal reads; version keys retain historical values by block
//! height for deterministic blockchain state queries.

use arc_swap::{ArcSwap, ArcSwapOption};
use bytes::Bytes;
use crc32fast::Hasher as Crc32;
use crossbeam_channel::{Sender, unbounded};
use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::thread;

pub mod error;
pub mod types;
pub use error::{DbError, DbResult};
pub use types::{BlockHeight, DomainId};

pub mod sst;
use sst::SstLevel;

const LOCAL_BATCH: usize = 64;
const RAM_BUF_SIZE: usize = 4 * 1024 * 1024;
const COMPACT_THRESHOLD: u64 = 256 * 1024 * 1024;
const MEMTABLE_FLUSH_ENTRIES: usize = 10_000;
const MAX_WAL_KEY_LEN: usize = 16 * 1024 * 1024;
const MAX_WAL_VALUE_LEN: usize = 128 * 1024 * 1024;
const MAX_SNAPSHOT_KEY_LEN: usize = MAX_WAL_KEY_LEN;
const MAX_SNAPSHOT_VALUE_LEN: usize = MAX_WAL_VALUE_LEN;
const HEAD_TAG: u8 = 0x01;
const VER_TAG: u8 = 0x02;
const DOMAIN_LEN: usize = 4;

#[derive(Clone)]
/// Runtime configuration for a DonaDB instance.
///
/// `data_dir` is the durable database directory. `shard_count` controls the
/// DashMap shard count used for the active memtable. The remaining fields are
/// retained as tuning hooks for callers and future cache/write-buffer policy.
pub struct DonaDbConfig {
    pub data_dir: PathBuf,
    pub shard_count: usize,
    pub compaction_threads: usize,
    pub block_cache_bytes: usize,
    pub write_buffer_bytes: usize,
}

impl Default for DonaDbConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./donadb"),
            shard_count: 256,
            compaction_threads: 2,
            block_cache_bytes: 64 * 1024 * 1024,
            write_buffer_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Point-in-time storage metrics used by validators, indexers, and tests.
pub struct DonaDbMetrics {
    pub active_entries: usize,
    pub flushing_entries: usize,
    pub compacting_entries: usize,
    pub index_entries: usize,
    pub wal_bytes_since_compaction: u64,
    pub wal_file_bytes: u64,
    pub snapshot_file_bytes: u64,
    pub compaction_active: bool,
    pub flush_active: bool,
    pub sst_l0_files: usize,
    pub sst_l1_files: usize,
    pub sst_l2_files: usize,
    pub estimated_read_amplification: usize,
}

#[inline]
fn memtable_flush_threshold() -> usize {
    std::env::var("DONADB_MEMTABLE_FLUSH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MEMTABLE_FLUSH_ENTRIES)
}

#[inline]
fn head_key(domain: DomainId, user_key: &[u8]) -> Bytes {
    let mut b = Vec::with_capacity(1 + DOMAIN_LEN + user_key.len());
    b.push(HEAD_TAG);
    b.extend_from_slice(&domain.to_be_bytes());
    b.extend_from_slice(user_key);
    Bytes::from(b)
}

#[inline]
fn head_prefix(domain: DomainId) -> Vec<u8> {
    let mut b = Vec::with_capacity(1 + DOMAIN_LEN);
    b.push(HEAD_TAG);
    b.extend_from_slice(&domain.to_be_bytes());
    b
}

#[inline]
fn head_range(domain: DomainId, start: &[u8], end: &[u8]) -> (Bytes, Bytes) {
    let mut s = head_prefix(domain);
    s.extend_from_slice(start);
    let mut e = head_prefix(domain);
    e.extend_from_slice(end);
    (Bytes::from(s), Bytes::from(e))
}

#[inline]
fn strip_head_prefix(k: &[u8]) -> Bytes {
    if k.len() <= 1 + DOMAIN_LEN {
        return Bytes::new();
    }
    Bytes::copy_from_slice(&k[1 + DOMAIN_LEN..])
}

#[inline]
fn version_key(domain: DomainId, user_key: &[u8], height: BlockHeight) -> Bytes {
    let mut b = Vec::with_capacity(1 + DOMAIN_LEN + user_key.len() + 8);
    b.push(VER_TAG);
    b.extend_from_slice(&domain.to_be_bytes());
    b.extend_from_slice(user_key);
    b.extend_from_slice(&height.to_be_bytes());
    Bytes::from(b)
}

#[inline]
fn version_range(domain: DomainId, user_key: &[u8], height: BlockHeight) -> (Bytes, Bytes) {
    let mut s = Vec::with_capacity(1 + DOMAIN_LEN + user_key.len() + 8);
    s.push(VER_TAG);
    s.extend_from_slice(&domain.to_be_bytes());
    s.extend_from_slice(user_key);
    s.extend_from_slice(&0u64.to_be_bytes());
    let mut e = Vec::with_capacity(1 + DOMAIN_LEN + user_key.len() + 8);
    e.push(VER_TAG);
    e.extend_from_slice(&domain.to_be_bytes());
    e.extend_from_slice(user_key);
    let end_h = height.saturating_add(1);
    e.extend_from_slice(&end_h.to_be_bytes());
    (Bytes::from(s), Bytes::from(e))
}

#[inline]
fn height_from_version_key(k: &[u8]) -> Option<u64> {
    if k.len() < 1 + DOMAIN_LEN + 8 {
        return None;
    }
    let h = &k[k.len() - 8..];
    Some(u64::from_be_bytes(h.try_into().ok()?))
}

fn encode_set(key: &Bytes, val: &Bytes) -> Vec<u8> {
    let mut b = Vec::with_capacity(13 + key.len() + val.len());
    b.push(0u8);
    b.extend_from_slice(&(key.len() as u32).to_le_bytes());
    b.extend_from_slice(key);
    b.extend_from_slice(&(val.len() as u32).to_le_bytes());
    b.extend_from_slice(val);
    let crc = crc32(&b);
    b.extend_from_slice(&crc.to_le_bytes());
    b
}

fn encode_del(key: &Bytes) -> Vec<u8> {
    let mut b = Vec::with_capacity(9 + key.len());
    b.push(1u8);
    b.extend_from_slice(&(key.len() as u32).to_le_bytes());
    b.extend_from_slice(key);
    let crc = crc32(&b);
    b.extend_from_slice(&crc.to_le_bytes());
    b
}

fn encode_batch_marker(tag: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(5);
    b.push(tag);
    let crc = crc32(&[tag]);
    b.extend_from_slice(&crc.to_le_bytes());
    b
}

fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

fn write_snapshot(path: &str, memtable: &DashMap<Bytes, Bytes>) -> io::Result<()> {
    let tmp = format!("{}.tmp", path);
    let mut f = std::fs::File::create(&tmp)?;
    let mut hasher = crc32fast::Hasher::new();

    let count_bytes = (memtable.len() as u64).to_le_bytes();
    f.write_all(&count_bytes)?;
    hasher.update(&count_bytes);

    for e in memtable.iter() {
        let kl = (e.key().len() as u32).to_le_bytes();
        let vl = (e.value().len() as u32).to_le_bytes();
        f.write_all(&kl)?;
        hasher.update(&kl);
        f.write_all(e.key())?;
        hasher.update(e.key());
        f.write_all(&vl)?;
        hasher.update(&vl);
        f.write_all(e.value())?;
        hasher.update(e.value());
    }

    // The footer covers the full body so a partial or corrupted snapshot is rejected.
    let crc = hasher.finalize();
    f.write_all(&crc.to_le_bytes())?;

    f.flush()?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    let dir = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let dir_f = std::fs::File::open(dir)?;
    dir_f.sync_all()?;
    Ok(())
}

fn load_snapshot(
    path: &str,
    memtable: &DashMap<Bytes, Bytes>,
    index: &SkipMap<Bytes, ()>,
) -> io::Result<usize> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    // Minimum layout: entry_count(u64) followed by crc32(u32).
    if data.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot too small",
        ));
    }

    let (body, crc_bytes) = data.split_at(data.len() - 4);
    let stored_crc = u32::from_le_bytes(crc_bytes.try_into().unwrap());
    let computed_crc = crc32fast::hash(body);
    if stored_crc != computed_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "snapshot CRC mismatch: stored={:#010x} computed={:#010x}",
                stored_crc, computed_crc
            ),
        ));
    }

    let count = u64::from_le_bytes(body[0..8].try_into().unwrap()) as usize;
    let mut pos = 8;
    for _ in 0..count {
        if pos + 4 > body.len() {
            break;
        }
        let klen = u32::from_le_bytes(body[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if klen > MAX_SNAPSHOT_KEY_LEN || pos + klen + 4 > body.len() {
            break;
        }
        let key = Bytes::copy_from_slice(&body[pos..pos + klen]);
        pos += klen;
        let vlen = u32::from_le_bytes(body[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if vlen > MAX_SNAPSHOT_VALUE_LEN || pos + vlen > body.len() {
            break;
        }
        let val = Bytes::copy_from_slice(&body[pos..pos + vlen]);
        pos += vlen;
        index.insert(key.clone(), ());
        memtable.insert(key, val);
    }
    Ok(count)
}

/// Replay a WAL into the supplied memtable and index.
///
/// Replay stops at the first malformed, incomplete, or CRC-invalid record. This
/// is intentional: a partially flushed tail must not make recovery fail, and no
/// operation from an unfinished batch is made visible.
pub fn replay_wal(
    path: &str,
    memtable: &DashMap<Bytes, Bytes>,
    index: &SkipMap<Bytes, ()>,
) -> io::Result<usize> {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let mut pos = 0;
    let mut count = 0;
    let mut in_batch = false;
    let mut batch_ops: Vec<BatchOp> = Vec::new();
    while pos < data.len() {
        if pos + 1 > data.len() {
            break;
        }
        let tag = data[pos];
        pos += 1;
        match tag {
            2 | 3 => {
                if pos + 4 > data.len() {
                    break;
                }
                let crc = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                pos += 4;
                if crc32(&[tag]) != crc {
                    break;
                }
                if tag == 2 {
                    in_batch = true;
                    batch_ops.clear();
                } else if tag == 3 {
                    if in_batch {
                        for op in batch_ops.drain(..) {
                            match op {
                                BatchOp::Set(key, val) => {
                                    index.insert(key.clone(), ());
                                    memtable.insert(key, val);
                                }
                                BatchOp::Del(key) => {
                                    index.remove(&key);
                                    memtable.remove(&key);
                                }
                            }
                        }
                        count += 1;
                    }
                    in_batch = false;
                }
                continue;
            }
            _ => {}
        }
        if pos + 4 > data.len() {
            break;
        }
        let klen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if klen > MAX_WAL_KEY_LEN || pos + klen > data.len() {
            break;
        }
        let key = Bytes::copy_from_slice(&data[pos..pos + klen]);
        pos += klen;
        match tag {
            0 => {
                if pos + 4 > data.len() {
                    break;
                }
                let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4;
                if vlen > MAX_WAL_VALUE_LEN || pos + vlen > data.len() {
                    break;
                }
                let val = Bytes::copy_from_slice(&data[pos..pos + vlen]);
                pos += vlen;
                if pos + 4 > data.len() {
                    break;
                }
                let crc = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                pos += 4;
                let mut h = Crc32::new();
                h.update(&[tag]);
                h.update(&(klen as u32).to_le_bytes());
                h.update(&key);
                h.update(&(vlen as u32).to_le_bytes());
                h.update(&val);
                if h.finalize() != crc {
                    break;
                }
                if in_batch {
                    batch_ops.push(BatchOp::Set(key, val));
                } else {
                    index.insert(key.clone(), ());
                    memtable.insert(key, val);
                    count += 1;
                }
            }
            1 => {
                if pos + 4 > data.len() {
                    break;
                }
                let crc = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                pos += 4;
                let mut h = Crc32::new();
                h.update(&[tag]);
                h.update(&(klen as u32).to_le_bytes());
                h.update(&key);
                if h.finalize() != crc {
                    break;
                }
                if in_batch {
                    batch_ops.push(BatchOp::Del(key));
                } else {
                    index.remove(&key);
                    memtable.remove(&key);
                    count += 1;
                }
            }
            _ => break,
        }
    }
    Ok(count)
}

/// A group of state mutations that should be appended to the WAL as one batch.
pub struct WriteBatch {
    pub(crate) ops: Vec<UserOp>,
    pub(crate) height: BlockHeight,
    pub(crate) db: Option<Arc<DonaDb>>,
}

#[derive(Clone)]
/// A single user-level state mutation before it is expanded into head/version keys.
pub enum UserOp {
    Put {
        domain: DomainId,
        key: Bytes,
        value: Bytes,
    },
    Del {
        domain: DomainId,
        key: Bytes,
    },
}

pub(crate) enum BatchOp {
    Set(Bytes, Bytes),
    Del(Bytes),
}

impl WriteBatch {
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            height: 0,
            db: None,
        }
    }
    pub fn put(&mut self, domain: DomainId, key: impl Into<Bytes>, value: impl Into<Bytes>) {
        self.ops.push(UserOp::Put {
            domain,
            key: key.into(),
            value: value.into(),
        });
    }
    pub fn del(&mut self, domain: DomainId, key: impl Into<Bytes>) {
        self.ops.push(UserOp::Del {
            domain,
            key: key.into(),
        });
    }
    /// Add a domain-zero put operation for older call sites.
    pub fn set(&mut self, key: impl Into<Bytes>, value: impl Into<Bytes>) {
        self.put(0, key, value);
    }
    /// Add a domain-zero delete operation for older call sites.
    pub fn remove(&mut self, key: impl Into<Bytes>) {
        self.del(0, key);
    }
    pub fn commit(mut self) -> DbResult<()> {
        if let Some(db) = self.db.take() {
            db.apply_batch(self.height, self.ops);
            Ok(())
        } else {
            Err(DbError::Invalid("WriteBatch not bound to a DB".into()))
        }
    }
}

pub(crate) enum WalOp {
    Batch(Vec<BatchOp>),
    Sync(std::sync::mpsc::SyncSender<()>),
    Rotate {
        path: String,
        ack: std::sync::mpsc::SyncSender<()>,
    },
}

type MemTable = Arc<DashMap<Bytes, Bytes>>;

#[derive(Clone)]
/// Embedded LSM database handle.
///
/// Cloning the handle is cheap: all mutable storage state is shared behind
/// atomics, concurrent maps, and the WAL channel.
pub struct DonaDb {
    active: Arc<ArcSwap<DashMap<Bytes, Bytes>>>,
    flushing_mem: Arc<ArcSwapOption<DashMap<Bytes, Bytes>>>,
    compacting_mem: Arc<ArcSwapOption<DashMap<Bytes, Bytes>>>,
    index: Arc<SkipMap<Bytes, ()>>,
    wal_tx: Sender<Vec<WalOp>>,
    wal_bytes: Arc<AtomicU64>,
    compacting: Arc<AtomicU64>,
    wal_path: Arc<String>,
    snap_path: Arc<String>,
    /// Immutable SST tier used after memtable flushes and compaction.
    sst: Arc<SstLevel>,
    flushing: Arc<AtomicU64>,
}

pub type DonaDB = DonaDb;

thread_local! {
    static LOCAL_BUF: RefCell<Vec<WalOp>> = RefCell::new(Vec::with_capacity(LOCAL_BATCH));
}

impl DonaDb {
    /// Open or create a database rooted at `config.data_dir`.
    pub fn open(config: DonaDbConfig) -> DbResult<Self> {
        let DonaDbConfig {
            data_dir,
            shard_count,
            ..
        } = config.clone();
        std::fs::create_dir_all(&data_dir)?;
        let wal_path = data_dir.join("donadb.wal");
        Ok(Self::open_wal_with_shards(
            wal_path
                .to_str()
                .ok_or_else(|| DbError::Invalid("invalid wal path".into()))?,
            shard_count,
        ))
    }

    /// Open a database using an explicit WAL file path and default sharding.
    pub fn open_wal(wal_path: &str) -> Self {
        Self::open_wal_with_shards(wal_path, 256)
    }

    /// Open a database using an explicit WAL file path and memtable shard count.
    pub fn open_wal_with_shards(wal_path: &str, shard_count: usize) -> Self {
        let snap_path = format!("{}.snap", wal_path);
        let memtable: MemTable = Arc::new(DashMap::with_shard_amount(shard_count));
        let index = Arc::new(SkipMap::new());

        let snap_n = load_snapshot(&snap_path, &memtable, &index).unwrap_or(0);
        let wal_n = replay_wal(wal_path, &memtable, &index).unwrap_or(0);
        if snap_n + wal_n > 0 {
            eprintln!("donadb: loaded {} snap + {} wal entries", snap_n, wal_n);
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(wal_path)
            .expect("donadb: failed to open WAL");

        let (wal_tx, wal_rx) = unbounded::<Vec<WalOp>>();

        thread::spawn(move || {
            let mut ram: Vec<u8> = Vec::with_capacity(RAM_BUF_SIZE);
            let mut file = file;
            macro_rules! enc {
                ($op:expr) => {
                    match $op {
                        WalOp::Batch(ops) => {
                            ram.extend(encode_batch_marker(2));
                            for op in ops {
                                match op {
                                    BatchOp::Set(k, v) => {
                                        ram.extend(encode_set(&k, &v));
                                    }
                                    BatchOp::Del(k) => {
                                        ram.extend(encode_del(&k));
                                    }
                                }
                            }
                            ram.extend(encode_batch_marker(3));
                        }
                        WalOp::Sync(_) | WalOp::Rotate { .. } => {}
                    }
                };
            }
            for batch in &wal_rx {
                let mut sync_ack: Option<std::sync::mpsc::SyncSender<()>> = None;
                let mut rotate: Option<(String, std::sync::mpsc::SyncSender<()>)> = None;
                for op in batch {
                    match op {
                        WalOp::Sync(a) => sync_ack = Some(a),
                        WalOp::Rotate { path, ack } => rotate = Some((path, ack)),
                        op => enc!(op),
                    }
                }
                while let Ok(b) = wal_rx.try_recv() {
                    for op in b {
                        match op {
                            WalOp::Sync(a) => sync_ack = Some(a),
                            WalOp::Rotate { path, ack } => rotate = Some((path, ack)),
                            op => enc!(op),
                        }
                    }
                }
                if ram.len() >= RAM_BUF_SIZE {
                    let _ = file.write_all(&ram);
                    let _ = file.sync_all();
                    ram.clear();
                }
                if let Some(a) = sync_ack {
                    if !ram.is_empty() {
                        let _ = file.write_all(&ram);
                        let _ = file.sync_all();
                        ram.clear();
                    }
                    let _ = a.send(());
                }
                if let Some((path, ack)) = rotate {
                    if !ram.is_empty() {
                        let _ = file.write_all(&ram);
                        let _ = file.sync_all();
                        ram.clear();
                    }
                    // Rotation is acknowledged only after the old file is durable and the new file is open.
                    match OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&path)
                    {
                        Ok(new_file) => {
                            file = new_file;
                        }
                        Err(e) => {
                            eprintln!("donadb: WAL rotate failed: {}", e);
                        }
                    }
                    let _ = ack.send(());
                }
            }
        });

        let _ = wal_tx.send(vec![]);

        let sst_dir = format!("{}.sst", wal_path);
        let sst = Arc::new(
            SstLevel::open(std::path::Path::new(&sst_dir))
                .expect("donadb: failed to open SST level"),
        );

        // SST files are loaded as readers and queried lazily; recent keys are rebuilt from snapshot and WAL.

        Self {
            active: Arc::new(ArcSwap::from(memtable)),
            flushing_mem: Arc::new(ArcSwapOption::from(None)),
            compacting_mem: Arc::new(ArcSwapOption::from(None)),
            index,
            wal_tx,
            wal_bytes: Arc::new(AtomicU64::new(0)),
            compacting: Arc::new(AtomicU64::new(0)),
            wal_path: Arc::new(wal_path.to_string()),
            snap_path: Arc::new(snap_path),
            sst,
            flushing: Arc::new(AtomicU64::new(0)),
        }
    }

    #[inline]
    fn memtable(&self) -> MemTable {
        self.active.load_full()
    }

    #[inline]
    fn get_memtable_value(&self, key: &[u8]) -> Option<Bytes> {
        if let Some(v) = self.active.load().get(key).map(|v| v.clone()) {
            return Some(v);
        }
        if let Some(mt) = self.flushing_mem.load_full() {
            if let Some(v) = mt.get(key).map(|v| v.clone()) {
                return Some(v);
            }
        }
        if let Some(mt) = self.compacting_mem.load_full() {
            if let Some(v) = mt.get(key).map(|v| v.clone()) {
                return Some(v);
            }
        }
        None
    }

    #[inline]
    fn memtable_contains(&self, key: &[u8]) -> bool {
        if self.active.load().contains_key(key) {
            return true;
        }
        self.flushing_mem
            .load_full()
            .map(|mt| mt.contains_key(key))
            .unwrap_or(false)
            || self
                .compacting_mem
                .load_full()
                .map(|mt| mt.contains_key(key))
                .unwrap_or(false)
    }

    fn maybe_compact(&self, written: u64) {
        let prev = self.wal_bytes.fetch_add(written, Ordering::Relaxed);
        let threshold = std::env::var("DONADB_COMPACT_KB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|kb| kb * 1024)
            .unwrap_or(COMPACT_THRESHOLD);
        if prev + written < threshold {
            return;
        }
        self.trigger_compact();
    }

    fn trigger_compact(&self) {
        if self
            .compacting
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.wal_bytes.store(0, Ordering::Relaxed);

        let snap = (*self.snap_path).clone();
        let wal = (*self.wal_path).clone();
        let compacting = Arc::clone(&self.compacting);
        let active = Arc::clone(&self.active);
        let wal_tx = self.wal_tx.clone();
        let flushing = Arc::clone(&self.flushing);
        let compacting_mem = Arc::clone(&self.compacting_mem);
        let sst = Arc::clone(&self.sst);

        thread::spawn(move || {
            // Snapshot compaction owns the memtable swap; wait for ordinary flushes to finish first.
            while flushing.load(Ordering::Acquire) != 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let old_mt = active.swap(Arc::new(DashMap::with_shard_amount(256)));
            compacting_mem.store(Some(old_mt.clone()));

            // Sync the WAL before snapshotting so every entry in old_mt has durable backing.
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let _ = wal_tx.send(vec![WalOp::Sync(tx)]);
            let _ = rx.recv();

            if write_snapshot(&snap, &old_mt).is_err() {
                compacting.store(0, Ordering::Release);
                return;
            }

            // Keep the old WAL unless the new snapshot can be parsed and its CRC validates.
            {
                let verify_mt: DashMap<Bytes, Bytes> = DashMap::new();
                let verify_idx = SkipMap::new();
                if load_snapshot(&snap, &verify_mt, &verify_idx).is_err() {
                    eprintln!(
                        "donadb: snapshot CRC verification failed — keeping WAL, aborting compaction"
                    );
                    compacting.store(0, Ordering::Release);
                    return;
                }
            }

            let (rot_tx, rot_rx) = std::sync::mpsc::sync_channel(1);
            let _ = wal_tx.send(vec![WalOp::Rotate {
                path: wal.clone(),
                ack: rot_tx,
            }]);
            let _ = rot_rx.recv();

            // Keep compacting_mem visible until its SST flush succeeds.
            loop {
                if flushing
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let entries: Vec<(Bytes, Bytes)> = old_mt
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect();
            if let Err(e) = sst.flush(entries) {
                eprintln!("donadb: SST flush failed after snapshot: {}", e);
            } else {
                sst.maybe_compact_async();
                compacting_mem.store(None);
            }
            flushing.store(0, Ordering::Release);

            eprintln!(
                "donadb: compaction complete ({} snap, {} active)",
                old_mt.len(),
                active.load().len()
            );
            compacting.store(0, Ordering::Release);
        });
    }

    /// Start a block-scoped batch at `block_height`.
    pub fn begin_batch(self: &Arc<Self>, block_height: BlockHeight, _entropy: &[u8]) -> WriteBatch {
        WriteBatch {
            ops: Vec::new(),
            height: block_height,
            db: Some(Arc::clone(self)),
        }
    }

    #[inline]
    /// Store `value` as the latest and historical value for `domain/key`.
    pub fn set(
        &self,
        domain: DomainId,
        key: impl Into<Bytes>,
        value: impl Into<Bytes>,
        height: BlockHeight,
    ) {
        self.apply_batch(
            height,
            vec![UserOp::Put {
                domain,
                key: key.into(),
                value: value.into(),
            }],
        );
    }

    #[inline]
    /// Return the latest live value for `domain/key`.
    pub fn get(&self, domain: DomainId, key: &[u8]) -> DbResult<Option<Bytes>> {
        let hk = head_key(domain, key);
        if let Some(v) = self.get_memtable_value(&hk) {
            if sst::is_tombstone(&v) {
                return Ok(None);
            }
            return Ok(Some(v));
        }
        Ok(self.sst.get(&hk))
    }

    /// Return the newest historical value at or before `height`.
    pub fn get_at(
        &self,
        domain: DomainId,
        key: &[u8],
        height: BlockHeight,
    ) -> DbResult<Option<Bytes>> {
        let (start, end) = version_range(domain, key, height);
        let mut best: Option<(u64, Bytes)> = None;

        for entry in self.index.range(start.clone()..end.clone()) {
            if let Some(v) = self.get_memtable_value(entry.key().as_ref()) {
                if let Some(h) = height_from_version_key(entry.key().as_ref()) {
                    if h <= height {
                        if best.as_ref().map(|(bh, _)| h > *bh).unwrap_or(true) {
                            best = Some((h, v));
                        }
                    }
                }
            }
        }

        for (k, v) in self.sst.scan_range_raw(start.as_ref(), end.as_ref()) {
            if let Some(h) = height_from_version_key(k.as_ref()) {
                if h <= height {
                    if best.as_ref().map(|(bh, _)| h > *bh).unwrap_or(true) {
                        best = Some((h, v));
                    }
                }
            }
        }

        Ok(best.map(|(_, v)| v).filter(|v| !sst::is_tombstone(v)))
    }

    /// Move an oversized active memtable into the SST tier without blocking writers.
    fn maybe_flush_to_sst(&self) {
        if self.compacting.load(Ordering::Acquire) != 0 {
            return;
        }
        let count = self.active.load().len();
        if count < memtable_flush_threshold() {
            return;
        }
        if self
            .flushing
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let active = Arc::clone(&self.active);
        let sst = Arc::clone(&self.sst);
        let flushing = Arc::clone(&self.flushing);
        let flushing_mem = Arc::clone(&self.flushing_mem);

        thread::spawn(move || {
            let old_mt = active.swap(Arc::new(DashMap::with_shard_amount(256)));
            flushing_mem.store(Some(old_mt.clone()));
            let entries: Vec<(Bytes, Bytes)> = old_mt
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect();
            if let Err(e) = sst.flush(entries) {
                eprintln!("donadb: SST flush failed: {}", e);
            }
            sst.maybe_compact_async();
            flushing_mem.store(None);
            flushing.store(0, Ordering::Release);
        });
    }

    #[inline]
    /// Delete the latest value while preserving historical lookup semantics.
    pub fn del(&self, domain: DomainId, key: &[u8], height: BlockHeight) {
        self.apply_batch(
            height,
            vec![UserOp::Del {
                domain,
                key: Bytes::copy_from_slice(key),
            }],
        );
    }

    /// Apply a prepared batch immediately and enqueue it for WAL persistence.
    pub fn write_batch(&self, batch: WriteBatch) {
        self.apply_batch(batch.height, batch.ops);
    }

    fn apply_batch(&self, height: BlockHeight, ops: Vec<UserOp>) {
        let mt = self.active.load();
        let mut sz = 10u64;
        let mut wal_ops: Vec<BatchOp> = Vec::with_capacity(ops.len() * 2);

        for op in ops {
            match op {
                UserOp::Put { domain, key, value } => {
                    let hk = head_key(domain, &key);
                    let vk = version_key(domain, &key, height);
                    sz += (13 + hk.len() + value.len()) as u64;
                    sz += (13 + vk.len() + value.len()) as u64;
                    mt.insert(hk.clone(), value.clone());
                    mt.insert(vk.clone(), value.clone());
                    self.index.insert(hk.clone(), ());
                    self.index.insert(vk.clone(), ());
                    wal_ops.push(BatchOp::Set(hk, value.clone()));
                    wal_ops.push(BatchOp::Set(vk, value));
                }
                UserOp::Del { domain, key } => {
                    let hk = head_key(domain, &key);
                    let vk = version_key(domain, &key, height);
                    let tv = sst::tombstone(0);
                    sz += (9 + hk.len()) as u64;
                    sz += (9 + vk.len()) as u64;
                    mt.insert(hk.clone(), tv.clone());
                    mt.insert(vk.clone(), tv.clone());
                    self.index.insert(hk.clone(), ());
                    self.index.insert(vk.clone(), ());
                    wal_ops.push(BatchOp::Set(hk, tv.clone()));
                    wal_ops.push(BatchOp::Set(vk, tv));
                }
            }
        }

        if !wal_ops.is_empty() {
            let _ = self.wal_tx.send(vec![WalOp::Batch(wal_ops)]);
        }
        self.maybe_compact(sz);
        self.maybe_flush_to_sst();
    }

    /// Flush queued WAL operations and wait until the WAL is synced to disk.
    pub fn sync(&self) {
        self.flush();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let _ = self.wal_tx.send(vec![WalOp::Sync(tx)]);
        let _ = rx.recv();
    }

    /// Durably finalize all writes submitted for a block.
    pub fn finalize_block(&self, _height: BlockHeight) -> DbResult<()> {
        self.sync();
        Ok(())
    }

    /// Send this thread's buffered WAL operations to the writer thread.
    pub fn flush(&self) {
        let tx = self.wal_tx.clone();
        LOCAL_BUF.with(|buf| {
            let mut b = buf.borrow_mut();
            if !b.is_empty() {
                let ops = std::mem::replace(&mut *b, Vec::with_capacity(LOCAL_BATCH));
                let _ = tx.send(ops);
            }
        });
    }

    /// Scan live head keys in `[start, end)` for one domain.
    pub fn scan(
        &self,
        domain: DomainId,
        start: &[u8],
        end: &[u8],
    ) -> DbResult<Vec<(Bytes, Bytes)>> {
        let (s, e) = head_range(domain, start, end);
        let mut results: Vec<(Bytes, Bytes)> = self
            .index
            .range(s.clone()..e.clone())
            .filter_map(|entry| {
                self.get_memtable_value(entry.key().as_ref()).and_then(|v| {
                    if sst::is_tombstone(&v) {
                        None
                    } else {
                        Some((strip_head_prefix(entry.key().as_ref()), v.clone()))
                    }
                })
            })
            .collect();
        for (k, v) in self.sst.scan_range(s.as_ref(), e.as_ref()) {
            if !self.memtable_contains(&k) && !sst::is_tombstone(&v) {
                results.push((strip_head_prefix(k.as_ref()), v));
            }
        }
        results.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        Ok(results)
    }

    /// Return all live head keys for one domain.
    pub fn scan_all(&self, domain: DomainId) -> DbResult<Vec<(Bytes, Bytes)>> {
        self.scan_prefix_domain(domain, &[])
    }

    /// Return all live head keys with `prefix` in one domain.
    pub fn scan_prefix_domain(
        &self,
        domain: DomainId,
        prefix: &[u8],
    ) -> DbResult<Vec<(Bytes, Bytes)>> {
        let mut p = head_prefix(domain);
        p.extend_from_slice(prefix);
        let start = Bytes::from(p.clone());
        let mut results: Vec<(Bytes, Bytes)> = self
            .index
            .range(start..)
            .take_while(|e| e.key().starts_with(&p))
            .filter_map(|e| {
                self.get_memtable_value(e.key().as_ref()).and_then(|v| {
                    if sst::is_tombstone(&v) {
                        None
                    } else {
                        Some((strip_head_prefix(e.key().as_ref()), v.clone()))
                    }
                })
            })
            .collect();

        for (k, v) in self.sst.scan_prefix(&p) {
            if !self.memtable_contains(&k) && !sst::is_tombstone(&v) {
                results.push((strip_head_prefix(k.as_ref()), v));
            }
        }
        results.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        Ok(results)
    }

    /// Domain-zero prefix scan retained for callers that do not use domains.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Vec<(Bytes, Bytes)> {
        self.scan_prefix_domain(0, prefix).unwrap_or_default()
    }

    /// Domain-zero range scan retained for callers that do not use domains.
    pub fn scan_range(&self, start: &[u8], end: &[u8]) -> Vec<(Bytes, Bytes)> {
        self.scan(0, start, end).unwrap_or_default()
    }

    /// Return the active memtable entry count.
    pub fn len(&self) -> usize {
        self.memtable().len()
    }
    /// Return true when the active memtable contains no entries.
    pub fn is_empty(&self) -> bool {
        self.memtable().is_empty()
    }

    /// Collect storage health and amplification counters.
    pub fn metrics(&self) -> DonaDbMetrics {
        let active = self.active.load();
        let flushing_mem = self.flushing_mem.load_full();
        let compacting_mem = self.compacting_mem.load_full();
        let (sst_l0, sst_l1, sst_l2) = self.sst.stats();
        let wal_file_bytes = std::fs::metadata(self.wal_path.as_ref())
            .map(|m| m.len())
            .unwrap_or(0);
        let snapshot_file_bytes = std::fs::metadata(self.snap_path.as_ref())
            .map(|m| m.len())
            .unwrap_or(0);
        let mem_layers =
            1 + usize::from(flushing_mem.is_some()) + usize::from(compacting_mem.is_some());
        DonaDbMetrics {
            active_entries: active.len(),
            flushing_entries: flushing_mem.as_ref().map(|m| m.len()).unwrap_or(0),
            compacting_entries: compacting_mem.as_ref().map(|m| m.len()).unwrap_or(0),
            index_entries: self.index.len(),
            wal_bytes_since_compaction: self.wal_bytes.load(Ordering::Relaxed),
            wal_file_bytes,
            snapshot_file_bytes,
            compaction_active: self.compacting.load(Ordering::Acquire) != 0,
            flush_active: self.flushing.load(Ordering::Acquire) != 0,
            sst_l0_files: sst_l0,
            sst_l1_files: sst_l1,
            sst_l2_files: sst_l2,
            estimated_read_amplification: mem_layers + sst_l0 + sst_l1 + sst_l2,
        }
    }

    /// Create a filesystem checkpoint that can be opened as an independent database.
    pub fn checkpoint(&self, destination: impl AsRef<Path>) -> DbResult<()> {
        self.sync();
        let destination = destination.as_ref();
        let tmp = destination.with_extension("tmp");
        if tmp.exists() {
            std::fs::remove_dir_all(&tmp)?;
        }
        std::fs::create_dir_all(&tmp)?;

        let wal_src = Path::new(self.wal_path.as_ref());
        if wal_src.exists() {
            std::fs::copy(wal_src, tmp.join("donadb.wal"))?;
        }
        let snap_src = Path::new(self.snap_path.as_ref());
        if snap_src.exists() {
            std::fs::copy(snap_src, tmp.join("donadb.wal.snap"))?;
        }
        let sst_src = PathBuf::from(format!("{}.sst", self.wal_path.as_ref()));
        if sst_src.exists() {
            copy_dir_all(&sst_src, &tmp.join("donadb.wal.sst"))?;
        }
        sync_dir(&tmp)?;
        if destination.exists() {
            std::fs::remove_dir_all(destination)?;
        }
        std::fs::rename(&tmp, destination)?;
        if let Some(parent) = destination.parent() {
            sync_dir(parent)?;
        }
        Ok(())
    }

    /// Return the number of SST files in L0, L1, and L2.
    pub fn sst_stats(&self) -> (usize, usize, usize) {
        self.sst.stats()
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst_path)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), dst_path)?;
        }
    }
    sync_dir(dst)?;
    Ok(())
}

fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = std::fs::File::open(path)?;
    dir.sync_all()
}
