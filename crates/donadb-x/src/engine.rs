//! Engine layer — the public-facing orchestrator of all five subsystems.
//!
//! This module owns the [`DonaDbX`] struct and wires together:
//!
//! - **Subsystem 2** ([`crate::commutative::CommutativeLog`]): lock-free mmap append log.
//! - **Subsystem 3** ([`crate::dual_buffer::DualBufferEngine`]): parallel fold coordinator.
//! - **Subsystem 4** (Rayon fold pool inside `DualBufferEngine`): parallel BLAKE3 + XOR
//!   state-root computation, running asynchronously after each `commit()`.
//! - **Subsystem 5** ([`crate::segment`]): segment rotation, JSON manifest, crash recovery.
//! - **Subsystem 1** ([`ExecutionFrame`]): isolated write arena with rollback support.

#![allow(unsafe_code)]

use crate::commutative::{CommutativeLog, CMAG, CTOMB, CHDR};
use crate::dual_buffer::DualBufferEngine;
use crate::index::ShardIndex;
use crate::segment::{Manifest, SegmentMeta, SealedSegment};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Re-export so callers can use [`BlockWriter`] without importing `dual_buffer`.
pub use crate::dual_buffer::BlockWriter;

// ── Config ────────────────────────────────────────────────────────────────────

/// Runtime configuration for a [`DonaDbX`] instance.
///
/// All fields have sensible defaults via [`Config::default()`]; most deployments
/// only need to override `buffer_size` to match available RAM.
///
/// # Example
/// ```
/// use donadb_x::Config;
///
/// let cfg = Config {
///     buffer_size:      512 << 20, // 512 MiB segments
///     rotate_threshold: 0.75,
///     fold_threads:     Some(4),
/// };
/// ```
#[derive(Clone, Debug)]
pub struct Config {
    /// Maximum size of a single log segment in bytes.
    ///
    /// The active log is memory-mapped at this size on creation. When the fill
    /// ratio reaches [`rotate_threshold`][Config::rotate_threshold], the segment
    /// is sealed and a fresh one is opened.
    ///
    /// Default: `2 GiB` (`2 << 30`).
    pub buffer_size: u64,

    /// Fraction of [`buffer_size`][Config::buffer_size] at which segment rotation
    /// is triggered, expressed as a value in `(0.0, 1.0]`.
    ///
    /// Rotation is checked after every `commit()`. Once
    /// `write_offset / buffer_size >= rotate_threshold`, the current segment is
    /// sealed atomically and a new active log is created.
    ///
    /// Default: `0.80` (rotate at 80 % full).
    pub rotate_threshold: f64,

    /// Number of threads used by the Rayon fold pool for post-commit hashing.
    ///
    /// `None` lets the engine choose automatically (currently half of the
    /// logical CPU count). Set an explicit value to bound CPU usage on
    /// shared hosts.
    ///
    /// Default: `None` (auto-detect).
    pub fold_threads: Option<usize>,
}

impl Default for Config {
    /// Returns a configuration suitable for most validator deployments:
    /// 2 GiB segments, 80 % rotation threshold, auto-detected fold threads.
    fn default() -> Self {
        Self {
            buffer_size:      2 << 30,
            rotate_threshold: 0.80,
            fold_threads:     None,
        }
    }
}

// ── DonaDbX ───────────────────────────────────────────────────────────────────

/// The top-level storage engine handle.
///
/// `DonaDbX` is a single struct that encapsulates all five subsystems of the
/// DonaDbX storage engine. It is `Send + Sync` and is typically shared across
/// threads via an `Arc<DonaDbX>`.
///
/// Writes are lock-free on the hot path: [`put()`][DonaDbX::put] performs a
/// single `fetch_add` to reserve space in the active log, then copies the
/// payload in. [`commit()`][DonaDbX::commit] snapshots all shards and launches
/// a parallel fold; the returned [`CommitAck`] lets callers wait for or poll
/// the resulting state root.
pub struct DonaDbX {
    dbe: DualBufferEngine,
    gen: AtomicU64,
    sealed: parking_lot::RwLock<Vec<SealedSegment>>,
    manifest: parking_lot::Mutex<Manifest>,
    manifest_path: PathBuf,
    dir: PathBuf,
    cfg: Config,
    current_height: AtomicU64,
    /// Direct Arc to the current segment's CommutativeLog.
    /// Updated only on segment rotation. Zero atomic overhead on the read
    /// hot path — no ArcSwap load, no refcount bump per get().
    segment_log: arc_swap::ArcSwap<CommutativeLog>,
}

// ── CommitAck ─────────────────────────────────────────────────────────────────

/// Handle returned by [`DonaDbX::commit()`].
///
/// After a `commit()` call, the active log is atomically swapped and the Rayon
/// fold pool begins computing the new state root in the background. `CommitAck`
/// lets callers synchronise with that computation.
///
/// - Call [`wait()`][CommitAck::wait] to **block** until the fold completes and
///   obtain the 32-byte state root. Use this at the end of a block when you need
///   the root before producing a block header.
/// - Call [`try_poll()`][CommitAck::try_poll] to **check without blocking**
///   whether the fold has finished. Useful in async runtimes or polling loops
///   where blocking is undesirable.
///
/// The `#[must_use]` attribute ensures that accidentally discarding an ack
/// (and therefore never waiting for the fold) produces a compiler warning.
#[must_use = "call .wait() to obtain the state root once the fold completes"]
pub struct CommitAck {
    rx: std::sync::mpsc::Receiver<[u8; 32]>,
}

impl CommitAck {
    /// Block until the async fold completes and return the 32-byte state root.
    ///
    /// If the fold thread panicked or the channel was dropped, returns an
    /// all-zero sentinel value rather than propagating the error.
    pub fn wait(self) -> [u8; 32] {
        self.rx.recv().unwrap_or([0u8; 32])
    }

    /// Non-blocking poll. Returns `Some(root)` if the fold has finished,
    /// `None` if it is still running.
    pub fn try_poll(&self) -> Option<[u8; 32]> {
        self.rx.try_recv().ok()
    }
}

// ── DonaDbX impl ──────────────────────────────────────────────────────────────

impl DonaDbX {
    // ── Subsystem 5: open + crash recovery ────────────────────────────────────

    /// Open or create a DonaDbX database at `dir`.
    ///
    /// # First call (new database)
    /// The directory is created if it does not exist. A fresh `seg_active.log`
    /// is memory-mapped at `cfg.buffer_size` bytes, and a `manifest.json` is
    /// written listing it as the sole active segment.
    ///
    /// # Reopen (existing database)
    /// The manifest is read to discover all sealed segments, which are
    /// memory-mapped read-only. The active log is then replayed: every record
    /// whose offset falls below the persisted committed-offset is re-inserted
    /// into the in-memory index and XOR Merkle accumulator. This restores full
    /// query capability without a separate write-ahead log.
    ///
    /// # Crash recovery
    /// If the process crashed mid-write, the active log may contain a partial
    /// record beyond the committed-offset. The replay scan stops at the first
    /// corrupt or incomplete record, leaving only fully written data visible.
    /// No manual repair step is required.
    ///
    /// # Errors
    /// Returns [`crate::DbError::Io`] if the directory cannot be created, any
    /// segment file cannot be opened, or the manifest cannot be read or written.
    /// Returns [`crate::DbError::Corrupt`] if a mandatory segment file is
    /// structurally invalid.
    pub fn open(dir: impl AsRef<Path>, cfg: Config) -> crate::DbResult<Self> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;

        let manifest_path = dir.join("manifest.json");
        let mut manifest  = Manifest::load(&manifest_path)?;

        // Memory-map every sealed segment listed in the manifest.
        let mut sealed_vec: Vec<SealedSegment> = Vec::new();
        for meta in manifest.segments.iter().filter(|m| m.sealed) {
            sealed_vec.push(SealedSegment::open(meta.clone())?);
        }

        // Open the durable active log file (seg_active.log).
        let active_path = dir.join("seg_active.log");
        let active_log  = Arc::new(CommutativeLog::open(&active_path, cfg.buffer_size)?);

        // Construct the DualBufferEngine, passing the active log as its initial buffer.
        let dbe = DualBufferEngine::open(dir, cfg.buffer_size, Arc::clone(&active_log))?;

        // Replay committed records from the active log to rebuild the index and
        // Merkle accumulator after a restart or crash.
        {
            Self::replay_into(&active_log, 0, &dbe.index, &dbe.merkle)?;
        }
        // The local active_log Arc is dropped here; DualBufferEngine holds the
        // sole remaining reference via its internal ArcSwap.

        // Ensure the manifest always has an entry for the active segment.
        if !manifest.segments.iter().any(|m| !m.sealed) {
            manifest.segments.push(SegmentMeta {
                id:         manifest.next_id,
                path:       dir.join("seg_active.log").to_string_lossy().into(),
                sealed:     false,
                used:       0,
                min_height: 0,
                max_height: u64::MAX,
            });
            manifest.next_id += 1;
            manifest.save(&manifest_path)?;
        }

        Ok(Self {
            dbe,
            gen:           AtomicU64::new(0),
            sealed:        parking_lot::RwLock::new(sealed_vec),
            manifest:      parking_lot::Mutex::new(manifest),
            manifest_path,
            dir:           dir.to_owned(),
            cfg,
            current_height: AtomicU64::new(0),
            segment_log:   arc_swap::ArcSwap::from(Arc::clone(&active_log)),
        })
    }

    // ── Subsystem 2: lock-free write ──────────────────────────────────────────

    /// Append a key-value pair to the active log.
    ///
    /// This method is **truly lock-free**: it performs a single atomic
    /// `fetch_add` to reserve a slot in the memory-mapped log, then copies
    /// the key and value into that slot with `memcpy`. No mutex or spin-lock
    /// is acquired on this path.
    ///
    /// The `prev_offset` field in the record header is written as `0` here.
    /// The fold pass, which runs after [`commit()`][Self::commit], patches it
    /// to the previous offset for the same key using the index it already holds.
    /// This keeps the write path free of any index reads or shard locks.
    ///
    /// # Parameters
    /// - `key`: the 32-byte key to write.
    /// - `value`: arbitrary byte slice to associate with the key.
    ///
    /// # Returns
    /// The byte offset in the log at which this record was written. Offsets are
    /// stable for the lifetime of the segment and can be used with
    /// [`get_at()`][Self::get_at] for direct MVCC access.
    ///
    /// # Errors
    /// Returns [`crate::DbError::LogFull`] if the active segment has no room
    /// for the record.
    #[inline(always)]
    pub fn put(&self, key: [u8; 32], value: &[u8]) -> crate::DbResult<u64> {
        let height = self.current_height.load(Ordering::Acquire);
        self.dbe.active.load().put_versioned(key, value, 0, height)
    }

    // ── Subsystem 3 + 4: commit — snapshot + async parallel fold ─────────────

    /// Commit all pending writes for block `height` and launch the async fold.
    ///
    /// Snapshots the write frontier across all shards and dispatches a parallel
    /// fold operation:
    ///
    /// 1. **Snapshot frontiers** — capture `write_offset` for each shard
    /// 2. **Parallel fold** — the Rayon thread pool processes all shards
    ///    simultaneously, computing `BLAKE3(value)` for every record, updating
    ///    the index with correct `prev_offset` MVCC chain pointers, and
    ///    XOR-folding results into the commutative state root
    ///
    /// The fold runs on a dedicated thread pool without blocking the caller.
    ///
    /// # Returns
    /// A [`CommitAck`] whose [`wait()`][CommitAck::wait] method blocks until
    /// the fold finishes and returns the new 32-byte state root.
    ///
    /// # Errors
    /// Returns [`crate::DbError::Io`] if segment rotation fails.
    pub fn commit(&self, height: u64) -> crate::DbResult<CommitAck> {
        self.current_height.store(height, Ordering::Release);
        let cur_gen     = self.gen.load(Ordering::Acquire);
        let sealed_used = self.dbe.active.load().write_offset();

        // Snapshot all shards and dispatch parallel fold
        let fold_ack = self.dbe.swap(cur_gen)?;

        // After the swap, check whether the sealed buffer has crossed the
        // rotation threshold and rotate if so.
        if sealed_used as f64 / self.cfg.buffer_size as f64 >= self.cfg.rotate_threshold {
            self.rotate(height, sealed_used)?;
        }

        Ok(CommitAck { rx: fold_ack.into_rx() })
    }

    // ── Reads ─────────────────────────────────────────────────────────────────

    /// Look up the latest committed value for `key`.
    ///
    /// Search order (optimized for minimal latency):
    /// 0. **Value cache** — O(1) lock-free CLOCK cache, zero mmap access
    /// 1. **Index** — O(1) lock-free DashMap lookup per shard
    /// 2. **Active log unflushed region** — linear scan for writes since last fold
    /// 3. **Sealed segments** — historical data from rotated segments
    ///
    /// The index entry's `log_id` is compared against the current generation
    /// counter before dereferencing the offset. If they differ, the entry
    /// belongs to a segment that has since been rotated.
    ///
    /// # Errors
    /// Returns [`crate::DbError::NotFound`] if the key has never been written.
    /// Returns [`crate::DbError::Corrupt`] if the record at the stored offset
    /// fails its magic-number check.
    pub fn get(&self, key: &[u8; 32]) -> crate::DbResult<Vec<u8>> {
        // Step 0: value cache — O(1), zero mmap access, zero page faults.
        // Populated by the fold thread on each commit(). A cache hit returns
        // immediately without consulting the index or touching the mmap.
        if let Some(entry) = self.dbe.index.get_entry(key) {
            if entry.deleted { return Err(crate::DbError::NotFound); }
            if let Some(cached) = self.dbe.vcache.get(key) {
                return Ok(cached.to_vec());
            }
        }

        // Step 1: index — O(1), covers all folded writes.
        if let Some(entry) = self.dbe.index.get_entry(key) {
            if entry.deleted { return Err(crate::DbError::NotFound); }
            if entry.log_id == self.gen.load(Ordering::Acquire) {
                let log = self.segment_log.load();
                if let Ok(v) = self.read_from_log(&log, entry.offset as usize) {
                    return Ok(v);
                }
            }
        }

        // Step 2: unflushed active-log scan — writes since last fold.
        {
            let active = self.dbe.active.load();
            if let Some(v) = active.scan_unflushed(key) {
                return Ok(v);
            }
        }

        // Step 3: sealed segments — rotated history.
        for seg in self.sealed.read().iter().rev() {
            if let Some(v) = seg.get_at(key, seg.meta.max_height) {
                return Ok(v);
            }
        }
        Err(crate::DbError::NotFound)
    }

    /// Zero-copy read — return a `MmapRef` pointing directly into the mmap.
    ///
    /// Same lookup order as [`get`][Self::get] but avoids heap allocation
    /// on the happy path by returning a reference into the mmap.
    ///
    /// Falls back to a `Vec`-backed allocation (wrapped in `MmapRef`) only
    /// for values that live in sealed segments (sealed segment reads already
    /// return `Vec<u8>`).
    ///
    /// # Errors
    /// Returns [`crate::DbError::NotFound`] if the key has never been written
    /// or was deleted.
    pub fn get_slice(&self, key: &[u8; 32]) -> crate::DbResult<crate::commutative::MmapRef> {
        if let Some(entry) = self.dbe.index.get_entry(key) {
            if entry.deleted { return Err(crate::DbError::NotFound); }
            if entry.log_id == self.gen.load(Ordering::Acquire) {
                let committed = self.segment_log.load();
                if let Some(r) = committed.value_ref(entry.offset as usize) {
                    return Ok(r);
                }
            }
        }
        // Unflushed active-log scan
        {
            let active = self.dbe.active.load();
            if let Some(v) = active.scan_unflushed(key) {
                return Ok(crate::commutative::MmapRef::from_vec(v));
            }
        }
        // Sealed segments
        for seg in self.sealed.read().iter().rev() {
            if let Some(v) = seg.get_at(key, seg.meta.max_height) {
                return Ok(crate::commutative::MmapRef::from_vec(v));
            }
        }
        Err(crate::DbError::NotFound)
    }

    /// Look up the value of `key` as it was at block `height`.
    ///
    /// Performs an **MVCC chain walk**: each log record stores a `prev_offset`
    /// pointer to the preceding version of the same key. This method follows
    /// the chain from the most recent entry backwards until it finds a record
    /// whose block height is ≤ `height`.
    ///
    /// `height` semantics: a record written during `commit(h)` has height `h`.
    /// Requesting `get_at(key, h)` returns the value that was current at the
    /// end of block `h` — i.e., the most recent write with `record.height <= h`.
    ///
    /// The search tries the active log first (if its `min_height <= height`),
    /// then walks sealed segments in reverse chronological order.
    ///
    /// # Errors
    /// Returns [`crate::DbError::NotFound`] if no version of the key exists at
    /// or before `height`.
    pub fn get_at(&self, key: &[u8; 32], height: u64) -> crate::DbResult<Vec<u8>> {
        let active_min = self.manifest.lock().segments.iter()
            .find(|m| !m.sealed)
            .map(|m| m.min_height)
            .unwrap_or(0);

        if active_min <= height {
            if let Some(entry) = self.dbe.index.get_entry(key) {
                if entry.log_id == self.gen.load(Ordering::Acquire) {
                    let log = self.segment_log.load();
                    if let Ok(v) = self.chain_walk(&log, entry.offset as usize, height) {
                        return Ok(v);
                    }
                }
            }
        }

        for seg in self.sealed.read().iter().rev() {
            if seg.meta.min_height > height {
                continue;
            }
            if let Some(v) = seg.get_at(key, height) {
                return Ok(v);
            }
        }
        Err(crate::DbError::NotFound)
    }

    /// Mark `key` as deleted in the active log.
    ///
    /// Appends a tombstone record (`CTOMB` magic, `vlen = 0`) to the active log.
    /// After `commit()` + `ack.wait()`:
    /// - [`get(key)`][Self::get] returns `NotFound`.
    /// - The key's `key XOR BLAKE3(value)` contribution is XORed out of the
    ///   state root accumulator, keeping the root consistent.
    /// - The key is excluded from [`scan_prefix`][Self::scan_prefix] results.
    ///
    /// Deletion is reversible: a subsequent `put(key, new_value)` in a later
    /// block resurrects the key normally.
    ///
    /// # Errors
    /// Returns [`crate::DbError::LogFull`] if the active segment has no room.
    #[inline(always)]
    pub fn delete(&self, key: [u8; 32]) -> crate::DbResult<u64> {
        let height = self.current_height.load(Ordering::Acquire);
        // Remove from the value cache immediately so concurrent get() calls
        // see NotFound without waiting for the next fold.
        self.dbe.vcache.remove(&key);
        self.dbe.active.load().del_versioned(key, 0, height)
    }

    /// Return all committed key-value pairs whose key starts with `prefix`.
    ///
    /// Results are collected from the in-memory index (folded writes) and the
    /// active-log unflushed region (writes since the last `commit()`), then
    /// sorted by key in ascending order.
    ///
    /// Keys that were deleted (tombstoned) are excluded. The prefix is matched
    /// byte-for-byte against the full 32-byte key.
    ///
    /// # Performance
    /// O(n) over the number of live index entries — the index is unordered
    /// (shard hash maps), so a full scan is required. For workloads that call
    /// `scan_prefix` frequently consider keeping a sorted secondary structure;
    /// for consensus storage (one scan per block boundary) this is fine.
    pub fn scan_prefix(&self, prefix: &[u8]) -> crate::DbResult<Vec<([u8; 32], Vec<u8>)>> {
        let mut results: Vec<([u8; 32], Vec<u8>)> = Vec::new();

        // Step 1: collect all non-deleted index entries whose key matches prefix.
        // Use get() for value retrieval — it handles committed log, active-log
        // unflushed region, and sealed segments correctly across any number of
        // prior commits.
        for entry in self.dbe.index.all_entries() {
            if entry.deleted { continue; }
            if !entry.key.starts_with(prefix) { continue; }
            if let Ok(v) = self.get(&entry.key) {
                results.push((entry.key, v));
            }
        }

        // Step 2: overlay unflushed active-log writes — covers keys written in
        // the current uncommitted batch that are not yet in the index.
        let active = self.dbe.active.load();
        for (key, val) in active.scan_all_unflushed() {
            if !key.starts_with(prefix) { continue; }
            results.retain(|(k, _)| k != &key);
            if !val.is_empty() {
                results.push((key, val));
            }
        }

        results.sort_unstable_by_key(|(k, _)| *k);
        Ok(results)
    }

    pub fn scan_from_reverse(&self, start: &[u8; 32]) -> crate::DbResult<Vec<([u8; 32], Vec<u8>)>> {
        let mut results: Vec<([u8; 32], Vec<u8>)> = Vec::new();

        for entry in self.dbe.index.all_entries() {
            if entry.deleted { continue; }
            if entry.key.as_ref() > start.as_ref() { continue; }
            if let Ok(v) = self.get(&entry.key) {
                results.push((entry.key, v));
            }
        }

        results.sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
        Ok(results)
    }

    /// Return the current 32-byte state root.
    ///
    /// The state root is a commutative XOR accumulator over `key XOR BLAKE3(value)`
    /// for every key currently in the index. It is updated incrementally by the
    /// fold pass after each [`commit()`][Self::commit], so this call is **O(1)** —
    /// it simply reads the accumulator value from memory.
    ///
    /// The root covers exactly the set of keys visible to [`get()`][Self::get]:
    /// all committed writes across the active log and all sealed segments.
    pub fn state_root(&self) -> [u8; 32] {
        self.dbe.state_root()
    }

    /// Return the number of distinct keys in the index.
    ///
    /// This counts unique keys across all shards of the in-memory [`ShardIndex`].
    /// It reflects the state after the last completed fold, not pending writes
    /// in the active buffer.
    pub fn len(&self) -> usize {
        self.dbe.index.len()
    }

    /// Returns `true` if the index contains no keys.
    ///
    /// This checks whether the in-memory index is empty after the last
    /// completed fold, not including pending writes in the active buffer.
    pub fn is_empty(&self) -> bool {
        self.dbe.index.is_empty()
    }

    /// Return the number of index shards (informational).
    pub fn num_shards(&self) -> usize {
        self.dbe.num_shards()
    }

    /// Acquire a per-thread write handle for shard `shard_id`.
    ///
    /// `BlockWriter` holds a direct `Arc<CommutativeLog>`, bypassing the
    /// `ArcSwap` load on every write. This makes it suitable for tight loops
    /// where the overhead of an atomic pointer load per `put()` would be
    /// measurable.
    ///
    /// **Shard semantics**: `shard_id` is purely advisory — it is used by the
    /// `DualBufferEngine` to partition keys across index shards for reduced
    /// lock contention. A thread should pick a consistent shard for the
    /// duration of a block. The number of valid shard IDs is
    /// [`num_shards()`][Self::num_shards]; values outside that range are
    /// wrapped modulo the shard count.
    ///
    /// **One per thread per block**: do not share a `BlockWriter` between
    /// threads. Obtain a new writer at the start of each block, as the
    /// underlying `Arc<CommutativeLog>` is replaced on every
    /// [`commit()`][Self::commit].
    pub fn writer(&self, shard_id: usize) -> BlockWriter {
        let height = self.current_height.load(Ordering::Acquire);
        self.dbe.writer(shard_id, height)
    }

    // ── Subsystem 1: ExecutionFrame factory ───────────────────────────────────

    /// Begin an isolated write frame.
    ///
    /// An `ExecutionFrame` provides **read isolation**: writes made through the
    /// frame are appended to the active log (and are therefore durable once
    /// [`commit()`][ExecutionFrame::commit] is called), but they are not
    /// inserted into the index until the fold pass runs after the commit.
    /// Concurrent [`get()`][Self::get] calls on the parent `DonaDbX` will not
    /// observe the frame's writes until after the commit and fold complete.
    ///
    /// If the frame is no longer needed, call [`abort()`][ExecutionFrame::abort]
    /// to zero out the reserved log region and roll back the write offset as if
    /// the writes never happened.
    pub fn begin_frame(&self) -> ExecutionFrame<'_> {
        ExecutionFrame {
            db:     self,
            start:  self.dbe.active.load().write_offset(),
            log_id: self.gen.load(Ordering::Acquire),
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Read the value from the committed log at byte offset `off`.
    ///
    /// Validates the record magic number and length fields before copying the
    /// value bytes into a new `Vec`. Returns `Corrupt` on any structural error.
    #[cfg(test)]
    fn read_committed(&self, off: usize) -> crate::DbResult<Vec<u8>> {
        self.read_from_log(&self.segment_log.load(), off)
    }

    /// Read the value at byte offset `off` from an arbitrary `CommutativeLog`.
    fn read_from_log(&self, log: &CommutativeLog, off: usize) -> crate::DbResult<Vec<u8>> {
        let cap = log.capacity as usize;
        if off + CHDR + 32 > cap {
            return Err(crate::DbError::Corrupt);
        }
        let ptr = log.mmap_ptr();
        let magic = u32::from_le_bytes(unsafe {
            std::slice::from_raw_parts(ptr.add(off), 4)
        }.try_into().unwrap());
        if magic != CMAG {
            return Err(crate::DbError::Corrupt);
        }
        let vlen = u32::from_le_bytes(unsafe {
            std::slice::from_raw_parts(ptr.add(off + 4), 4)
        }.try_into().unwrap()) as usize;
        let vs = off + CHDR + 32;
        if vs + vlen > cap {
            return Err(crate::DbError::Corrupt);
        }
        Ok(unsafe { std::slice::from_raw_parts(ptr.add(vs), vlen).to_vec() })
    }

    /// Walk the MVCC `prev_offset` chain to find the value at or before `target` height.
    ///
    /// Each record in the log stores a `prev_offset` pointer (8 bytes at header
    /// offset 8) to the previous write for the same key, and a block height (8
    /// bytes at header offset 16). This method follows the chain until it finds
    /// a record whose height ≤ `target` and returns its value, or returns
    /// `NotFound` if no such record exists.
    fn chain_walk(
        &self,
        log: &CommutativeLog,
        start: usize,
        target: u64,
    ) -> crate::DbResult<Vec<u8>> {
        let cap = log.capacity as usize;
        let ptr = log.mmap_ptr();
        let mut off = start;
        loop {
            if off + CHDR + 32 > cap {
                return Err(crate::DbError::Corrupt);
            }
            let magic = u32::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(off), 4)
            }.try_into().unwrap());
            if magic != CMAG {
                return Err(crate::DbError::Corrupt);
            }
            let vlen = u32::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(off + 4), 4)
            }.try_into().unwrap()) as usize;
            let prev = u64::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(off + 8), 8)
            }.try_into().unwrap());
            let rec_h = u64::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(off + 16), 8)
            }.try_into().unwrap());
            if rec_h <= target {
                let vs = off + CHDR + 32;
                if vs + vlen > cap {
                    return Err(crate::DbError::Corrupt);
                }
                return Ok(unsafe {
                    std::slice::from_raw_parts(ptr.add(vs), vlen).to_vec()
                });
            }
            if prev == 0 {
                return Err(crate::DbError::NotFound);
            }
            off = prev as usize;
        }
    }

    /// Subsystem 5: seal the active log, open a fresh active log, and update
    /// the manifest and in-memory sealed segment list.
    ///
    /// The rename from `seg_active.log` to the new sealed path is a POSIX
    /// atomic operation; the existing mmap mapping in the `DualBufferEngine`
    /// remains valid through the rename. The manifest is written twice: once
    /// with the sealed entry and once with the new active entry, so a crash
    /// between the two writes leaves a recoverable state.
    fn rotate(&self, height: u64, actual: u64) -> crate::DbResult<()> {
        let next_id   = { self.manifest.lock().next_id };
        let seal_path = self.dir.join(format!("seg_{:04}.log", next_id));
        let seal_min  = self.manifest.lock().segments.iter()
            .find(|m| !m.sealed)
            .map(|m| m.min_height)
            .unwrap_or(0);

        // Atomically rename the active file; the existing mmap stays valid.
        std::fs::rename(self.dir.join("seg_active.log"), &seal_path)
            .map_err(crate::DbError::Io)?;

        // Write the manifest with the sealed entry first, then with the new
        // active entry. Crashing between the two saves leaves a recoverable
        // manifest (the new active segment simply won't exist yet and will be
        // created as empty on the next open).
        {
            let mut m = self.manifest.lock();
            m.segments.retain(|s| s.sealed);
            m.segments.push(SegmentMeta {
                id:         next_id,
                path:       seal_path.to_string_lossy().into(),
                sealed:     true,
                used:       actual,
                min_height: seal_min,
                max_height: height,
            });
            m.next_id += 1;
            m.save(&self.manifest_path)?;
            let new_id = m.next_id;
            m.segments.push(SegmentMeta {
                id:         new_id,
                path:       self.dir.join("seg_active.log").to_string_lossy().into(),
                sealed:     false,
                used:       0,
                min_height: height + 1,
                max_height: u64::MAX,
            });
            m.next_id += 1;
            m.save(&self.manifest_path)?;
        }

        // Bump the generation counter so that any index entries written to the
        // old log are recognised as belonging to a sealed segment on the next
        // get() call.
        self.gen.fetch_add(1, Ordering::AcqRel);
        let new_log = Arc::new(CommutativeLog::open(
            &self.dir.join("seg_active.log"),
            self.cfg.buffer_size,
        )?);
        // Install the new log into shard 0 (updates active/committed aliases)
        // and into segment_log so get() reads from the new segment immediately.
        self.dbe.replace_shard_log(0, Arc::clone(&new_log));
        self.segment_log.store(new_log);
        self.dbe.vcache.clear();

        // Memory-map the newly sealed segment and append it to the sealed list.
        let new_meta = self.manifest.lock().segments.iter()
            .find(|s| s.id == next_id)
            .ok_or_else(|| crate::DbError::Io(
                std::io::Error::new(std::io::ErrorKind::NotFound, "sealed meta missing"),
            ))?
            .clone();
        self.sealed.write().push(SealedSegment::open(new_meta)?);
        Ok(())
    }

    /// Replay committed records from `log` into `index` and `merkle`.
    ///
    /// Called during [`open()`][Self::open] to restore in-memory state from the
    /// durable active log after a restart or crash. The scan starts at byte
    /// offset 8 (after the log header) and stops at the first corrupt or
    /// incomplete record. Only records below the persisted `committed_offset`
    /// are processed.
    ///
    /// For each record, the accumulator is updated by XORing out the old
    /// `key XOR BLAKE3(old_value)` contribution (if the key was already seen
    /// earlier in the replay) and XORing in the new `key XOR BLAKE3(value)`.
    fn replay_into(
        log:    &Arc<CommutativeLog>,
        log_id: u64,
        index:  &Arc<ShardIndex>,
        merkle: &Arc<parking_lot::Mutex<[u8; 32]>>,
    ) -> crate::DbResult<()> {
        let committed = log.committed_offset() as usize;
        if committed <= 8 {
            return Ok(());
        }
        let ptr = log.mmap_ptr();
        let mut cur = 8usize;
        let mut acc = [0u8; 32];

        while cur + CHDR + 32 <= committed {
            let magic = u32::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(cur), 4)
            }.try_into().unwrap());

            if magic == CTOMB {
                let key: [u8; 32] = unsafe {
                    std::slice::from_raw_parts(ptr.add(cur + CHDR), 32)
                }.try_into().unwrap();
                // XOR out using cached value_hash — no mmap re-read needed.
                if let Some(entry) = index.get_entry(&key) {
                    if !entry.deleted {
                        for i in 0..32 { acc[i] ^= key[i] ^ entry.value_hash[i]; }
                    }
                }
                let wc = index.count(&key) + 1;
                index.upsert_with_deleted(key, cur as u64, wc, log_id, true);
                cur += CHDR + 32;
                continue;
            }

            if magic != CMAG {
                break;
            }
            let vlen = u32::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(cur + 4), 4)
            }.try_into().unwrap()) as usize;
            let total = CHDR + 32 + vlen;
            if cur + total > committed || vlen > committed {
                break;
            }
            let key: [u8; 32] = unsafe {
                std::slice::from_raw_parts(ptr.add(cur + CHDR), 32)
            }.try_into().unwrap();
            let val_end = cur + CHDR + 32 + vlen;
            if val_end > committed {
                break;
            }
            let val = unsafe { std::slice::from_raw_parts(ptr.add(cur + CHDR + 32), vlen) };
            let vh  = *blake3::hash(val).as_bytes();

            // Remove the previous contribution of this key from the accumulator.
            if let Some(entry) = index.get_entry(&key) {
                if !entry.deleted {
                    // Use cached value_hash — never re-read from mmap.
                    for i in 0..32 { acc[i] ^= key[i] ^ entry.value_hash[i]; }
                }
            }
            for i in 0..32 {
                acc[i] ^= key[i] ^ vh[i];
            }
            let wc = index.count(&key) + 1;
            index.upsert_full(key, cur as u64, wc, log_id, false, vh);
            cur += total;
        }
        log.set_committed(cur as u64);
        *merkle.lock() = acc;
        Ok(())
    }
}

// ── Subsystem 1: ExecutionFrame ───────────────────────────────────────────────

/// An isolated write arena scoped to a single block.
///
/// Writes appended through an `ExecutionFrame` go into the active log immediately
/// (making them durable on fsync) but are not visible to [`DonaDbX::get()`]
/// until the frame is committed and the subsequent fold pass updates the index.
///
/// Use [`abort()`][ExecutionFrame::abort] to roll back all writes made since the
/// frame was created, as if they never happened. Use
/// [`commit()`][ExecutionFrame::commit] to promote them into the committed log.
pub struct ExecutionFrame<'a> {
    db:     &'a DonaDbX,
    /// Write offset in the active log at the time the frame was opened.
    /// Used as the rollback point on abort.
    start:  u64,
    /// Log generation at frame creation. If this differs from the current
    /// generation at abort time, a rotation has already sealed the frame;
    /// no rollback is needed.
    log_id: u64,
}

impl<'a> ExecutionFrame<'a> {
    /// Append a key-value pair within this frame.
    ///
    /// Identical semantics to [`DonaDbX::put()`]: lock-free, one `fetch_add`,
    /// one `memcpy`. The write is not reflected in [`DonaDbX::get()`] until
    /// this frame is committed and the fold completes.
    #[inline(always)]
    pub fn put(&self, key: [u8; 32], value: &[u8]) -> crate::DbResult<u64> {
        self.db.put(key, value)
    }

    /// Commit all writes in this frame for block `height`.
    ///
    /// Equivalent to calling [`DonaDbX::commit()`] directly. The frame is
    /// consumed and its writes become visible to readers after the fold
    /// completes.
    pub fn commit(self, height: u64) -> crate::DbResult<CommitAck> {
        self.db.commit(height)
    }

    /// Abort this frame, rolling back all writes made since it was created.
    ///
    /// Zero-fills the log region from `start` to the current write offset,
    /// then resets the write offset to `start`. This makes the region
    /// available for reuse and leaves no trace in the log.
    ///
    /// If a segment rotation occurred after this frame was opened (detected
    /// by comparing the stored `log_id` with the current generation), the
    /// frame has already been sealed into a segment. In that case the abort
    /// is a no-op: the rotation's committed-offset boundary already excludes
    /// any partial writes from this frame.
    ///
    /// The method waits for all in-flight lock-free writes (those that reserved
    /// space but have not yet finished copying) to complete before zeroing, to
    /// avoid a data race with concurrent writers in the same shard.
    pub fn abort(self) {
        let log_arc = self.db.dbe.active.load_full();
        let cur_gen = self.db.gen.load(Ordering::Acquire);
        // If the log was rotated after this frame was created, the frame's
        // writes are already sealed and there is nothing to roll back.
        if cur_gen != self.log_id {
            return;
        }
        let _guard = log_arc.commit_lock.lock();
        // Wait for any concurrent lock-free writers that have reserved space
        // but have not yet finished their memcpy.
        while log_arc.inflight.load(Ordering::Acquire) > 0 {
            std::hint::spin_loop();
        }
        let current = log_arc.write_offset() as usize;
        let start   = self.start as usize;
        if current > start {
            unsafe {
                std::ptr::write_bytes(
                    log_arc.mmap_ptr().add(start) as *mut u8,
                    0,
                    current - start,
                );
            }
        }
        log_arc.write_offset.store(self.start, Ordering::Release);
    }
}

#[cfg(test)]
mod engine_tests {
    use super::*;
    use tempfile::tempdir;

    fn cfg() -> Config { Config { buffer_size: 256 << 20, ..Default::default() } }

    #[test]
    fn scan_prefix_debug() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), cfg()).unwrap();
        let mut k1 = [0u8; 32]; k1[0] = 0x01; k1[1] = 0x00;
        let mut k2 = [0u8; 32]; k2[0] = 0x01; k2[1] = 0x01;
        let mut k3 = [0u8; 32]; k3[0] = 0x02;
        db.put(k1, b"a").unwrap();
        db.put(k2, b"b").unwrap();
        db.put(k3, b"c").unwrap();
        db.commit(1).unwrap().wait();

        let cur_gen = db.gen.load(Ordering::Acquire);
        eprintln!("cur_gen = {cur_gen}");
        for e in db.dbe.index.all_entries() {
            let rc = db.read_committed(e.offset as usize);
            let sw = e.key.starts_with(&[0x01u8]);
            eprintln!("  key[0]={:#04x} log_id={} offset={} deleted={} read_committed={:?} starts_with_01={}",
                e.key[0], e.log_id, e.offset, e.deleted, rc.as_ref().map(|v| v.len()), sw);
        }
        let result = db.scan_prefix(&[0x01u8]).unwrap();
        eprintln!("scan_prefix results: {}", result.len());
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn cache_populated_and_hit() {
        let d  = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), cfg()).unwrap();
        let mut k = [0u8; 32]; k[0] = 0x42;
        db.put(k, b"cached_value").unwrap();
        db.commit(1).unwrap().wait();

        let cache_len = db.dbe.vcache.len();
        eprintln!("vcache entries after commit: {}", cache_len);
        assert!(cache_len > 0, "fold thread must populate cache");

        // Direct cache hit
        let hit = db.dbe.vcache.get(&k);
        assert!(hit.is_some(), "key must be in cache after fold");
        assert_eq!(hit.unwrap().as_ref(), b"cached_value");

        // get() must return the cached value
        assert_eq!(db.get(&k).unwrap(), b"cached_value");
    }

    #[test]
    fn optimization_benchmark() {
        use std::time::Instant;
        use std::sync::Arc;
        
        let d = tempdir().unwrap();
        let db = Arc::new(DonaDbX::open(d.path(), cfg()).unwrap());
        
        eprintln!("\n╔════════════════════════════════════════════════════════════╗");
        eprintln!("║  DonaDbX Optimization Benchmark                            ║");
        eprintln!("╚════════════════════════════════════════════════════════════╝");
        
        // Test 1: Write throughput
        let n = 50_000u64;
        let val = vec![42u8; 128];
        
        eprintln!("\n[1] Write {} keys (128 bytes each)", n);
        let write_start = Instant::now();
        for i in 0..n {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&i.to_le_bytes());
            db.put(key, &val).unwrap();
        }
        let write_time = write_start.elapsed();
        eprintln!("    Write time: {:?} ({:.0} ops/s)", 
            write_time, n as f64 / write_time.as_secs_f64());
        
        // Test 2: Commit + parallel fold
        eprintln!("\n[2] Commit + parallel fold");
        let commit_start = Instant::now();
        let root = db.commit(1).unwrap().wait();
        let commit_time = commit_start.elapsed();
        eprintln!("    Commit time: {:?}", commit_time);
        eprintln!("    State root: {}", hex::encode(&root[..8]));
        
        // Test 3: Cache effectiveness (CLOCK eviction)
        eprintln!("\n[3] Read performance (cache effectiveness)");
        let cache_len = db.dbe.vcache.len();
        eprintln!("    Cache entries: {}", cache_len);
        
        let read_start = Instant::now();
        let mut hits = 0;
        for i in 0..10_000u64 {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(i * 5).to_le_bytes());
            if db.get(&key).is_ok() {
                hits += 1;
            }
        }
        let read_time = read_start.elapsed();
        eprintln!("    10K reads: {:?} ({:.0} reads/s)", 
            read_time, 10_000.0 / read_time.as_secs_f64());
        eprintln!("    Hit rate: {:.1}%", hits as f64 / 100.0);
        
        // Test 4: Multi-shard concurrent writes
        eprintln!("\n[4] Concurrent writes (multi-shard)");
        let threads = 4;
        let per_thread = 10_000u64;
        let val_arc = Arc::new(val);
        
        let concurrent_start = Instant::now();
        let handles: Vec<_> = (0..threads).map(|shard_id| {
            let db = Arc::clone(&db);
            let val = Arc::clone(&val_arc);
            std::thread::spawn(move || {
                let writer = db.writer(shard_id);
                for i in 0..per_thread {
                    let mut key = [0u8; 32];
                    key[0] = shard_id as u8;
                    key[8..16].copy_from_slice(&i.to_le_bytes());
                    writer.put(key, &val).unwrap();
                }
            })
        }).collect();
        
        for h in handles { h.join().unwrap(); }
        let concurrent_time = concurrent_start.elapsed();
        let total_ops = threads as u64 * per_thread;
        eprintln!("    {} threads × {} ops: {:?} ({:.0} ops/s)", 
            threads, per_thread, concurrent_time, 
            total_ops as f64 / concurrent_time.as_secs_f64());
        
        let root2 = db.commit(2).unwrap().wait();
        eprintln!("    Final index size: {} keys", db.len());
        eprintln!("    State root: {}", hex::encode(&root2[..8]));
        
        eprintln!("\n✓ All optimization benchmarks passed");
    }
}
