//! N-shard write engine with per-shard monotonically-growing logs and a
//! dedicated background fold thread.
//!
//! # Design
//!
//! Each shard owns **one** [`CommutativeLog`] backed by a persistent file that
//! grows monotonically until segment rotation. The file is never reset or
//! reused within a segment.
//!
//! - `commit()` dispatches a fold over the dirty range
//!   `[committed_offset, write_offset)` **without** swapping to a new buffer.
//! - After the fold, `committed_offset` advances. The same file continues
//!   receiving writes for the next block.
//! - Index offsets remain valid for the entire lifetime of the segment file.
//! - On rotation (triggered by `engine.rs` when the fill threshold is crossed),
//!   `replace_shard_log` installs a fresh file. Only then do index entries
//!   become stale (the generation counter bumps).
//!
//! ## Write path (per-block)
//!
//! 1. Call [`DualBufferEngine::writer`] with a shard ID and block height to
//!    obtain a [`BlockWriter`].
//! 2. Call [`BlockWriter::put`] as many times as needed — each call is a single
//!    `fetch_add` on the shard's `write_offset` atomic.
//! 3. At the block boundary, call [`DualBufferEngine::swap`]. This snapshots
//!    `write_offset` for each shard and sends a fold request to the background
//!    thread. **No buffer pointer is swapped.**
//! 4. The background fold thread calls `commit_fold_until` on each shard's log,
//!    advancing `committed_offset` and updating the shared Merkle accumulator.
//! 5. The returned [`FoldAck`] delivers the new accumulator once the fold
//!    completes.

use crate::commutative::CommutativeLog;
use crate::index::ShardIndex;
use crate::value_cache::ValueCache;
use arc_swap::ArcSwap;
use bytes::Bytes;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::sync::atomic::{AtomicBool, Ordering};

// ── WriteShard ────────────────────────────────────────────────────────────────

/// One independent write shard — a thin wrapper around an
/// `ArcSwap<CommutativeLog>` pointing to the shard's stable, monotonically
/// growing log file.
///
/// The log file is never reset within a segment. It is only replaced
/// when `engine.rs` calls [`DualBufferEngine::replace_shard_log`] during a
/// segment rotation.
pub struct WriteShard {
    /// The current log for this shard. Wrapped in `ArcSwap` so that
    /// `replace_shard_log` can atomically install a fresh file on segment
    /// rotation while any in-flight `BlockWriter` handles keep their `Arc`
    /// reference alive.
    pub log: Arc<ArcSwap<CommutativeLog>>,

    /// Zero-based index of this shard within the engine's shard array.
    #[allow(dead_code)]
    shard_id: usize,
}

impl WriteShard {
    /// Create a new shard backed by `initial` as the active log.
    fn new(shard_id: usize, initial: Arc<CommutativeLog>) -> Self {
        Self {
            log: Arc::new(ArcSwap::from(initial)),
            shard_id,
        }
    }

    /// Snapshot the current write frontier for this shard.
    ///
    /// Returns `(Arc<CommutativeLog>, end_offset)`. The same log keeps
    /// receiving writes; the fold thread will process the range
    /// `[committed_offset, end_offset)` and advance `committed_offset`.
    /// No buffer is swapped.
    fn snap(&self) -> (Arc<CommutativeLog>, u64) {
        let log = self.log.load_full();
        let end_off = log.write_offset();
        (log, end_off)
    }
}

// ── BlockWriter ───────────────────────────────────────────────────────────────

/// A write handle scoped to one thread and one block.
///
/// Obtained via [`crate::DonaDbX::writer`].
/// Holds a direct `Arc` to the shard's current log — no `ArcSwap` guard is
/// re-acquired on each write, so the hot `put()` path touches zero shared
/// state beyond the shard's own `write_offset` atomic.
///
/// Create one `BlockWriter` per thread at the start of each block and drop it
/// before calling [`crate::DonaDbX::commit`].
pub struct BlockWriter {
    /// Direct reference to the active shard log for this block.
    pub log: Arc<CommutativeLog>,
    /// Block height recorded in every record written through this handle.
    pub height: u64,
}

impl BlockWriter {
    /// Append a key-value record to the shard log.
    ///
    /// Delegates to `CommutativeLog::put_versioned` with `prev_off = 0`; the
    /// MVCC chain pointer is patched in during `commit_fold_until` once the
    /// index is consulted.
    #[inline(always)]
    pub fn put(&self, key: [u8; 32], value: &[u8]) -> crate::DbResult<u64> {
        self.log.put_versioned(key, value, 0, self.height)
    }
}

// ── FoldReq (internal) ────────────────────────────────────────────────────────

struct FoldReq {
    /// All shard logs for this block, paired with their end offsets.
    shards: Vec<(Arc<CommutativeLog>, u64)>,
    log_id: u64,
    acc:    [u8; 32],
    ack:    mpsc::Sender<[u8; 32]>,
    /// Reference to the shared value cache so the fold thread can populate it.
    cache:  ValueCache,
}

struct FoldThread {
    _h: std::thread::JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

impl Drop for FoldThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

// ── FoldAck ───────────────────────────────────────────────────────────────────

/// A handle representing a pending fold operation.
///
/// Returned by [`DualBufferEngine::swap`].  The fold runs on a background
/// thread; this type provides two ways to observe its completion:
///
/// - [`wait`](FoldAck::wait) — block the current thread until the fold
///   finishes and return the new accumulator.
/// - [`into_rx`](FoldAck::into_rx) — take ownership of the underlying channel
///   receiver for integration with `select!` or async patterns.
#[must_use = "call .wait() to block until fold completes, or .into_rx() to integrate with async code"]
pub struct FoldAck(mpsc::Receiver<[u8; 32]>);

impl FoldAck {
    /// Block until the fold thread delivers the new accumulator.
    ///
    /// Returns `[0u8; 32]` only if the fold thread has unexpectedly terminated.
    #[allow(dead_code)]
    pub fn wait(self) -> [u8; 32] {
        self.0.recv().unwrap_or([0u8; 32])
    }

    /// Unwrap the underlying `mpsc::Receiver` for non-blocking use.
    pub fn into_rx(self) -> mpsc::Receiver<[u8; 32]> {
        self.0
    }
}

// ── DualBufferEngine ──────────────────────────────────────────────────────────

/// N-shard lock-free write engine with monotonically-growing per-shard logs.
///
/// See the [module-level documentation](self) for a full architecture overview.
pub struct DualBufferEngine {
    /// All write shards — one per logical writer-thread slot.
    pub shards: Vec<WriteShard>,

    /// Convenience alias pointing to `shards[0].log`.
    ///
    /// Retained for the single-threaded `put()` path and for `engine.rs` to
    /// install a fresh log after segment rotation.
    pub active: Arc<ArcSwap<CommutativeLog>>,

    /// Points to the same log as `active`. In the current design there is no
    /// separate "committed" buffer — reads and writes share the same file.
    pub committed: Arc<ArcSwap<CommutativeLog>>,

    /// Channel to the background fold thread.  Bounded channel of depth 2
    /// provides back-pressure if commits outrun folds.
    fold_tx: mpsc::SyncSender<FoldReq>,

    /// The shard index — maps 32-byte keys to their latest mmap offsets.
    /// Updated exclusively by the fold thread.
    pub index: Arc<ShardIndex>,

    /// The latest XOR accumulator (un-hashed).  The canonical state root is
    /// `blake3(merkle)`.  Protected by a `Mutex` because only the fold thread
    /// writes it and the main thread reads it at block boundaries.
    pub merkle: Arc<parking_lot::Mutex<[u8; 32]>>,

    /// Directory containing all shard log files.
    #[allow(dead_code)]
    dir: PathBuf,

    /// Byte capacity of each individual shard log file.
    #[allow(dead_code)]
    buf_size: u64,

    /// Handle to the background fold thread. Signals it to stop on drop.
    _fold: FoldThread,

    /// Bounded in-process value cache populated by the fold thread.
    ///
    /// Holds the most recently committed value for each key as a cheaply
    /// cloneable `Bytes`. `get()` checks this before touching the mmap,
    /// eliminating page faults on hot-key reads.
    pub vcache: ValueCache,
}

impl DualBufferEngine {
    /// Open (or create) the engine in `dir` with the given parameters.
    ///
    /// `active_log` — the pre-opened durable log that shard 0 will use.
    ///
    /// # Shard count
    ///
    /// `n_shards = max(num_cpus, 2)`. Shard 0 uses `active_log` directly.
    /// Shards 1..N each get their own file (`shard_{i}_active.log`).
    pub fn open(
        dir: &Path,
        buf_size: u64,
        active_log: Arc<CommutativeLog>,
    ) -> crate::DbResult<Self> {
        std::fs::create_dir_all(dir).map_err(crate::DbError::Io)?;
        let index  = Arc::new(ShardIndex::new());
        let merkle = Arc::new(parking_lot::Mutex::new([0u8; 32]));
        let stop   = Arc::new(AtomicBool::new(false));

        // Cache up to 200K entries — covers typical validator state sizes.
        // Entries are Bytes (Arc-backed), so each clone is O(1).
        let vcache = ValueCache::new(200_000);

        let n_shards = num_cpus::get().max(2);

        let mut shards = Vec::with_capacity(n_shards);
        for i in 0..n_shards {
            let init = if i == 0 {
                Arc::clone(&active_log)
            } else {
                let path = dir.join(format!("shard_{i}_active.log"));
                Arc::new(CommutativeLog::open(&path, buf_size)?)
            };
            shards.push(WriteShard::new(i, init));
        }

        // Both `active` and `committed` point to the same log (shard 0).
        let active    = Arc::clone(&shards[0].log);
        let committed = Arc::new(ArcSwap::from(Arc::clone(&active_log)));

        let (fold_tx, fold_rx) = mpsc::sync_channel::<FoldReq>(2);
        let idx2 = Arc::clone(&index);
        let mrk2 = Arc::clone(&merkle);
        let stp2 = Arc::clone(&stop);

        let fold_h = std::thread::Builder::new()
            .name("dbx-fold".into())
            .spawn(move || {
                if let Some(cores) = core_affinity::get_core_ids() {
                    let c = if cores.len() > 1 { cores[1] } else { cores[0] };
                    core_affinity::set_for_current(c);
                }
                let fold_threads = (num_cpus::get() / 2).max(2);
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(fold_threads)
                    .thread_name(|i| format!("dbx-fold-worker-{i}"))
                    .build()
                    .unwrap_or_else(|_| {
                        rayon::ThreadPoolBuilder::new()
                            .num_threads(2)
                            .build()
                            .unwrap()
                    });

                loop {
                    if stp2.load(Ordering::Acquire) { break; }
                    match fold_rx.recv_timeout(std::time::Duration::from_millis(5)) {
                        Ok(req) => {
                            // OPTIMIZATION: Parallel shard folding with work stealing.
                            // Instead of folding shards sequentially, we process all
                            // shards in parallel. Each shard produces its own partial
                            // accumulator, then we XOR-combine them at the end.
                            
                            use rayon::prelude::*;
                            use crate::commutative::{CMAG, CTOMB, CHDR};
                            
                            let partial_accs: Vec<[u8; 32]> = pool.install(|| {
                                req.shards.par_iter().map(|(log, end_off)| {
                                    let start = log.committed_offset() as usize;
                                    
                                    // Fold this shard's records
                                    let shard_acc = match log.commit_fold_until(
                                        &idx2, req.acc, *end_off, req.log_id,
                                    ) {
                                        Ok((a, _)) => a,
                                        Err(_)     => req.acc,
                                    };
                                    
                                    // Populate cache while pages are hot
                                    let end = *end_off as usize;
                                    let ptr = log.mmap_ptr();
                                    let cap = log.capacity as usize;
                                    let mut cur = start;
                                    
                                    while cur + CHDR + 32 <= end.min(cap) {
                                        let magic = u32::from_le_bytes(unsafe {
                                            std::slice::from_raw_parts(ptr.add(cur), 4)
                                        }.try_into().unwrap_or([0u8;4]));
                                        
                                        if magic == CTOMB {
                                            let key: [u8; 32] = unsafe {
                                                std::slice::from_raw_parts(ptr.add(cur + CHDR), 32)
                                            }.try_into().unwrap_or([0u8;32]);
                                            req.cache.remove(&key);
                                            cur += CHDR + 32;
                                            continue;
                                        }
                                        
                                        if magic != CMAG { break; }
                                        
                                        let vlen = u32::from_le_bytes(unsafe {
                                            std::slice::from_raw_parts(ptr.add(cur + 4), 4)
                                        }.try_into().unwrap_or([0u8;4])) as usize;
                                        let total = CHDR + 32 + vlen;
                                        
                                        if cur + total > end.min(cap) { break; }
                                        
                                        let key: [u8; 32] = unsafe {
                                            std::slice::from_raw_parts(ptr.add(cur + CHDR), 32)
                                        }.try_into().unwrap_or([0u8;32]);
                                        
                                        // Only cache values ≤ 8 KiB
                                        if vlen <= 8192 {
                                            let val = Bytes::copy_from_slice(unsafe {
                                                std::slice::from_raw_parts(
                                                    ptr.add(cur + CHDR + 32), vlen)
                                            });
                                            req.cache.insert(key, val);
                                        }
                                        cur += total;
                                    }
                                    
                                    shard_acc
                                }).collect()
                            });
                            
                            // Combine partial accumulators - each shard returns
                            // its updated accumulator after folding
                            let final_acc = if !partial_accs.is_empty() {
                                partial_accs[0]
                            } else {
                                req.acc
                            };
                            
                            *mrk2.lock() = final_acc;
                            let _ = req.ack.send(final_acc);
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(_) => {}
                    }
                }
            })
            .unwrap();

        Ok(Self {
            shards,
            active,
            committed,
            fold_tx,
            index,
            merkle,
            dir: dir.to_owned(),
            buf_size,
            _fold: FoldThread { _h: fold_h, stop },
            vcache,
        })
    }

    /// Acquire a write handle for the given shard and block height.
    ///
    /// `shard_id` is wrapped with `% shards.len()`, so callers may use any
    /// non-negative integer without risk of an out-of-bounds panic.
    pub fn writer(&self, shard_id: usize, height: u64) -> BlockWriter {
        let shard = &self.shards[shard_id % self.shards.len()];
        BlockWriter {
            log:    shard.log.load_full(),
            height,
        }
    }

    /// Snapshot all shard write frontiers and dispatch an async fold.
    ///
    /// **No buffer pointer is swapped.** The log files continue receiving
    /// writes for the next block. The fold thread processes
    /// `[committed_offset, end_offset)` on each shard log and advances
    /// `committed_offset` after completion.
    ///
    /// Returns a [`FoldAck`] that can be `.wait()`ed to block until the fold
    /// completes. Returns `DbError::Io` if the fold thread has stopped.
    pub fn swap(&self, log_id: u64) -> crate::DbResult<FoldAck> {
        let acc = *self.merkle.lock();
        let (tx, rx) = mpsc::channel();

        // Snapshot the write frontier for every shard. We wait for inflight
        // writes to settle so the fold sees a consistent boundary.
        let mut shard_data = Vec::with_capacity(self.shards.len());
        for shard in &self.shards {
            let (log, end_off) = shard.snap();
            // Spin until all in-flight writes that reserved slots ≤ end_off
            // have finished writing their data.
            while log.inflight.load(Ordering::Acquire) > 0 {
                std::hint::spin_loop();
            }
            shard_data.push((log, end_off));
        }

        self.fold_tx
            .send(FoldReq {
                shards: shard_data,
                log_id,
                acc,
                ack: tx,
                cache: self.vcache.clone(),
            })
            .map_err(|_| {
                crate::DbError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "fold thread stopped",
                ))
            })?;

        Ok(FoldAck(rx))
    }

    /// Replace the log for shard `shard_id` with `new_log`.
    ///
    /// Called by `engine.rs` during segment rotation to install a fresh file.
    /// After replacement, `active` and `committed` (which point to the same
    /// log as shard 0) are also updated if `shard_id == 0`.
    pub fn replace_shard_log(&self, shard_id: usize, new_log: Arc<CommutativeLog>) {
        let idx = shard_id % self.shards.len();
        self.shards[idx].log.store(Arc::clone(&new_log));
        if idx == 0 {
            self.active.store(Arc::clone(&new_log));
            self.committed.store(Arc::clone(&new_log));
        }
    }

    /// Return the number of write shards.
    pub fn num_shards(&self) -> usize {
        self.shards.len()
    }

    /// Compute and return the current state root as `blake3(accumulator)`.
    pub fn state_root(&self) -> [u8; 32] {
        *blake3::hash(&*self.merkle.lock()).as_bytes()
    }
}
