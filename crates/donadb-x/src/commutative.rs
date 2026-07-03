//! CommutativeLog — lock-free mmap append log with parallel rayon fold at commit.
//!
//! # Design rationale
//!
//! TruthLinked (and BFT blockchains in general) execute state in strict, numbered
//! batches called blocks.  Two properties hold that make this architecture safe:
//!
//! 1. **Read isolation** — every read targets the *previous* committed block.
//!    No thread ever reads uncommitted state from the currently-active buffer.
//!
//! 2. **Write commutativity** — within a single block, the order in which
//!    independent transactions write is irrelevant; the final state is identical
//!    regardless of interleaving.
//!
//! Together these mean the index does not need to be updated on every `put()`.
//! Instead, all writes land in a flat mmap log (one atomic `fetch_add` each),
//! and at the block boundary a single parallel fold scans the dirty slice,
//! upserts the index, and derives the new state root via XOR-accumulation of
//! `key XOR blake3(value)` contributions.
//!
//! # Write path
//! `put_versioned()`: one `fetch_add` to reserve space, one `copy_nonoverlapping`
//! to write the packed header, key, and value.  No locks.  No hashing.
//!
//! # Commit path
//! `commit_fold_until()`:
//!   1. Parse the dirty `[committed_offset..end_offset]` slice into record descriptors.
//!   2. `rayon::par_iter` hashes every value with blake3 in parallel.
//!   3. Sequential dedup keeps the last write per key within this block.
//!   4. For each surviving key, undo the old accumulator contribution and XOR in
//!      the new one; batch-upsert into the shard index by parallel shard.
//!   5. Advance `committed_offset` and persist it to the 8-byte header at offset 0.

#![allow(unsafe_code)]

use crate::{DbError, DbResult};
use crate::index::ShardIndex;
use memmap2::{MmapMut, MmapOptions};
use rayon::prelude::*;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Record layout
// ─────────────────────────────────────────────────────────────────────────────
//
// Each record written by `put_versioned()` has the following layout:
//
//   Offset   Size  Field
//   ──────────────────────────────────────────────────────────
//        0      4  magic       — always CMAG (0xC047_C047)
//        4      4  vlen        — length of the value payload in bytes
//        8      8  prev_offset — mmap offset of previous write for this key
//                               (MVCC chain pointer; 0 means first write)
//       16      8  height      — block height at write time
//   ──────────────────────────────────────────────────────────  (24 bytes header)
//       24     32  key         — the 32-byte key
//       56      N  value       — raw value bytes (N == vlen)
//
// The first 8 bytes of the file (offset 0..8) are NOT a record header; they
// hold the persisted committed_offset used by `open()` for crash recovery.

/// Magic number that marks the start of every valid record header.
///
/// The distinctive bit pattern (two copies of `0xC047`) makes it easy to
/// detect a torn write or a seek past valid data during log parsing.
pub(crate) const CMAG: u32 = 0xC047_C047;

/// Tombstone magic — written by `del_versioned` to mark a key as deleted.
///
/// Shares the `C047` suffix with `CMAG` so scanners that walk the log by
/// record size can step over tombstones correctly. The fold recognises this
/// magic and XORs out the key's accumulator contribution rather than adding
/// a new one, then marks the index entry as `deleted = true`.
pub(crate) const CTOMB: u32 = 0xDEAD_C047;

/// Size of the packed record header in bytes (magic + vlen + prev_offset + height).
///
/// Equals 4 + 4 + 8 + 8 = 24.  The key (32 bytes) and value (N bytes) follow
/// immediately after this header.
pub(crate) const CHDR: usize = 24;

// ─────────────────────────────────────────────────────────────────────────────
// CommutativeLog
// ─────────────────────────────────────────────────────────────────────────────

pub struct CommutativeLog {
    /// Memory-mapped file backing the log.  All record writes go here directly.
    mmap: MmapMut,

    /// Byte offset one past the last reserved (but possibly not yet written) record.
    ///
    /// Advanced atomically by `put_versioned()` via `fetch_add`.  May be ahead
    /// of `committed_offset` while in-flight writes are still in progress.
    pub write_offset: AtomicU64,

    /// Byte offset one past the last record fully committed to the index.
    ///
    /// Represents the stable read frontier: everything below this offset is
    /// guaranteed to be visible in the index.  Advanced by `commit_fold_until()`.
    committed_offset: AtomicU64,

    /// Total capacity of the mmap file in bytes.  Writes that would exceed this
    /// return `DbError::LogFull`.
    pub capacity: u64,

    /// Ensures only one `commit_fold` runs at a time.
    ///
    /// Concurrent commits would produce incorrect accumulator values because
    /// each commit reads the current index state before updating it; two
    /// overlapping commits would both see the same "old" values and double-undo
    /// contributions.
    pub(crate) commit_lock: parking_lot::Mutex<()>,

    /// Count of `put_versioned()` calls that have reserved an offset but have
    /// not yet finished writing their data into the mmap.
    ///
    /// `commit_fold_until()` and `reset()` spin on this reaching zero before
    /// they touch the region those writes are landing in.  Uses `AcqRel` on
    /// increment and `Release` on decrement so the mmap writes are visible
    /// before the counter drops back to zero.
    pub(crate) inflight: std::sync::atomic::AtomicI64,
}

impl CommutativeLog {
    /// Open (or create) a log file at `path` with a maximum size of `size` bytes.
    ///
    /// `path` — the file is created if it does not exist.  On restart the same
    /// path must be passed to recover the previous committed state.
    ///
    /// `size` — the mmap (and underlying file) is pre-allocated to exactly this
    /// many bytes.  Choose a value large enough to hold one full block's worth
    /// of writes.
    ///
    /// # Crash recovery
    ///
    /// The first 8 bytes of the file always hold the last persisted
    /// `committed_offset` as a little-endian `u64`.  On open, if that value is
    /// within `(8, size]` both `write_offset` and `committed_offset` are
    /// initialised to it, so the next `commit_fold` resumes from where the
    /// previous run left off.  Any unreachable bytes between the persisted offset
    /// and the physical end of the file are simply ignored.
    pub fn open(path: &Path, size: u64) -> DbResult<Self> {
        use std::os::unix::io::AsRawFd;

        let f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;

        // set_len / ftruncate only extends the file metadata; on sparse-file
        // filesystems (ext4, xfs, btrfs) it does NOT allocate physical disk
        // blocks.  A later memcpy into an unallocated page triggers a page
        // fault that the kernel must satisfy by allocating a block.  If the
        // disk is full at that moment, the kernel cannot complete the fault and
        // delivers SIGBUS — killing the process with no opportunity to handle
        // the error.
        //
        // posix_fallocate(2) forces the kernel to allocate real disk blocks for
        // the entire segment up front.  If physical space is unavailable it
        // returns ENOSPC here, at segment-creation time, where we can convert
        // it into a normal DbError and surface it gracefully to the caller —
        // long before any write or validator loop is running.
        //
        // We call set_len first so the file descriptor has the right size
        // before fallocate inspects it (required on some older kernels).
        f.set_len(size)?;
        // SAFETY: f is a valid, open file descriptor for the duration of this call.
        let rc = unsafe { libc::posix_fallocate(f.as_raw_fd(), 0, size as libc::off_t) };
        if rc != 0 {
            return Err(DbError::Io(std::io::Error::from_raw_os_error(rc)));
        }

        let mmap = unsafe { MmapOptions::new().map_mut(&f)? };
        let persisted = u64::from_le_bytes(mmap[0..8].try_into().unwrap_or([0u8; 8]));
        let start = if persisted > 8 && persisted <= size { persisted } else { 8 };
        Ok(Self {
            mmap,
            write_offset:     AtomicU64::new(start),
            committed_offset: AtomicU64::new(start),
            capacity:         size,
            commit_lock:      parking_lot::Mutex::new(()),
            inflight:         std::sync::atomic::AtomicI64::new(0),
        })
    }

    /// Append a key-value record with an MVCC chain pointer and block height.
    ///
    /// This is the main hot-path write operation.
    ///
    /// # Atomicity guarantee
    ///
    /// A single `fetch_add(total, AcqRel)` on `write_offset` reserves the byte
    /// range `[off, off + total)` atomically.  Because `fetch_add` is
    /// unconditional (no CAS loop), there is zero contention between concurrent
    /// writers — each thread gets its own disjoint slice of the log.  On
    /// capacity overflow the reservation is reversed with a compensating
    /// `fetch_sub` and `DbError::LogFull` is returned.
    ///
    /// # In-flight tracking
    ///
    /// Between reserving the slot and finishing the write, `inflight` is
    /// incremented.  `commit_fold_until()` and `reset()` spin-wait on
    /// `inflight == 0` before reading or rewinding the log, ensuring they never
    /// observe a partially-written record.
    ///
    /// # Record layout (packed `Hdr` struct)
    ///
    /// The 24-byte header is written as a single `repr(C, packed)` struct in one
    /// `write_unaligned` call — one cache-line store instead of four separate
    /// writes.  The key (32 bytes) and value (N bytes) follow immediately.
    ///
    /// - `prev_off` — mmap offset of the most recently committed record for this
    ///   key, or `0` for the first write.  Patched after commit if a prior
    ///   record is discovered during `commit_fold_until`.
    /// - `height`   — the block height at write time, used for point-in-time queries.
    #[inline(always)]
    pub fn put_versioned(&self, key: [u8; 32], value: &[u8], prev_off: u64, height: u64) -> DbResult<u64> {
        let total = (CHDR + 32 + value.len()) as u64;

        // Reserve the byte range with one atomic add — no CAS spin, no lock.
        // We claim the slot first, then check bounds.  On overflow we give it back.
        let off = self.write_offset.fetch_add(total, Ordering::AcqRel);
        if off + total > self.capacity {
            // Undo the reservation so the log does not appear partially full.
            self.write_offset.fetch_sub(total, Ordering::AcqRel);
            return Err(DbError::LogFull);
        }

        // Signal that this slot is reserved but not yet written.
        self.inflight.fetch_add(1, Ordering::Relaxed);

        // Write the 24-byte header as a single unaligned store, then copy key and value.
        #[repr(C, packed)]
        struct Hdr { magic: u32, vlen: u32, prev: u64, height: u64 }
        unsafe {
            let base = self.mmap.as_ptr().add(off as usize) as *mut u8;
            std::ptr::write_unaligned(base as *mut Hdr, Hdr {
                magic:  CMAG.to_le(),
                vlen:   (value.len() as u32).to_le(),
                prev:   prev_off.to_le(),
                height: height.to_le(),
            });
            std::ptr::copy_nonoverlapping(key.as_ptr(),   base.add(CHDR),      32);
            std::ptr::copy_nonoverlapping(value.as_ptr(), base.add(CHDR + 32), value.len());
        }

        // Signal that the write is complete.
        self.inflight.fetch_sub(1, Ordering::Release);
        Ok(off)
    }

    /// Append a tombstone record for `key` at block `height`.
    ///
    /// A tombstone uses the tombstone magic number (`CTOMB`) and `vlen = 0` so it
    /// occupies the minimum possible space in the log (header + key = 56 bytes).
    /// The fold thread recognises the tombstone magic, XORs out the key's
    /// existing accumulator contribution, and marks the index entry as deleted.
    ///
    /// After `commit()` + `ack.wait()`, `get(key)` returns `NotFound` and the
    /// key is excluded from `scan_prefix` and `scan_from_reverse` results.
    ///
    /// # Errors
    /// Returns [`crate::DbError::LogFull`] if the active segment has no room.
    #[inline(always)]
    pub fn del_versioned(&self, key: [u8; 32], prev_off: u64, height: u64) -> DbResult<u64> {
        // A tombstone has vlen = 0; total record size = CHDR + 32 bytes.
        let total = (CHDR + 32) as u64;
        let off   = self.write_offset.fetch_add(total, Ordering::AcqRel);
        if off + total > self.capacity {
            self.write_offset.fetch_sub(total, Ordering::AcqRel);
            return Err(crate::DbError::LogFull);
        }
        self.inflight.fetch_add(1, Ordering::AcqRel);
        unsafe {
            #[repr(C, packed)]
            struct Hdr { magic: u32, vlen: u32, prev: u64, height: u64 }
            let base = self.mmap.as_ptr().add(off as usize) as *mut u8;
            let hdr  = Hdr {
                magic:  CTOMB.to_le(),
                vlen:   0u32.to_le(),
                prev:   prev_off.to_le(),
                height: height.to_le(),
            };
            std::ptr::write_unaligned(base as *mut Hdr, hdr);
            std::ptr::copy_nonoverlapping(key.as_ptr(), base.add(CHDR), 32);
        }
        self.inflight.fetch_sub(1, Ordering::Release);
        Ok(off)
    }

    /// Fold the entire dirty range into the index and return the new state root.
    ///
    /// Equivalent to `commit_fold_until(index, prev_acc, write_offset, 0)`.
    /// The dirty range is `[committed_offset, write_offset)` at the moment of
    /// the call — any writes that land after the snapshot of `write_offset` are
    /// deferred to the next commit.
    ///
    /// Returns `(new_accumulator, blake3(new_accumulator))`.
    pub fn commit_fold(
        &self,
        index: &ShardIndex,
        prev_acc: [u8; 32],
    ) -> DbResult<([u8; 32], [u8; 32])> {
        self.commit_fold_until(index, prev_acc, self.write_offset.load(Ordering::Acquire), 0)
    }

    /// Fold the dirty range `[committed_offset, end_offset)` into the index.
    ///
    /// The `end_offset` parameter lets the caller pin a snapshot of the write
    /// frontier so that writes that race in after the block boundary are not
    /// accidentally included in this commit.
    ///
    /// `log_id` is passed through to the shard index for bookkeeping (e.g.
    /// tracking which segment last wrote each key).
    ///
    /// # Step-by-step
    ///
    /// 1. **Acquire commit lock** — only one commit may run at a time.
    ///
    /// 2. **Drain in-flight writes** — spin on `inflight == 0` so every
    ///    `put_versioned()` that reserved an offset inside `[start, end)` has
    ///    finished writing its data.
    ///
    /// 3. **Parse dirty slice** — walk the mmap from `start` to `end`, checking
    ///    the magic bytes of each record.  Collect `(offset, key, vlen)` tuples
    ///    into a `Vec` without copying any value data (zero-copy parse).
    ///
    /// 4. **Parallel blake3 hashing** — `rayon::par_iter` maps each record to
    ///    `(key, blake3(value), offset)`.  The value bytes are read via a raw
    ///    pointer into the mmap (safe because step 2 ensures no concurrent writes).
    ///
    /// 5. **Sequential dedup** — sort by offset; build a `per_block_count` map
    ///    to track how many times each key appeared; keep only the last
    ///    `(key → value_hash, offset)` entry so the index always holds the
    ///    highest-offset write for each key.
    ///
    /// 6. **Accumulator update + index upsert** — for each surviving key:
    ///    - If the key already exists in the committed index, read its old
    ///      value from the mmap and XOR out its `key XOR blake3(old_value)`
    ///      contribution from `prev_acc`.
    ///    - Patch the `prev_offset` field of the new record with the old offset
    ///      (completing the MVCC chain).
    ///    - XOR the new `key XOR blake3(new_value)` contribution into `new_acc`.
    ///    - Batch updates by shard index (`key[0]`) for parallelism.
    ///
    /// 7. **Parallel shard upserts** — `rayon::par_iter` over the 256 shard
    ///    batches; each shard acquires only its own lock.
    ///
    /// 8. **Advance committed pointer** — store `end_offset` into
    ///    `committed_offset` and persist it to the first 8 bytes of the mmap
    ///    for crash recovery, then issue an async flush.
    ///
    /// Returns `(new_accumulator, blake3(new_accumulator))`.
    pub fn commit_fold_until(
        &self,
        index: &ShardIndex,
        prev_acc: [u8; 32],
        end_offset: u64,
        log_id: u64,
    ) -> DbResult<([u8; 32], [u8; 32])> {
        let _guard = self.commit_lock.lock();
        let start = self.committed_offset.load(Ordering::Acquire) as usize;
        let end   = end_offset as usize;

        if start >= end {
            // Nothing to commit — return the current accumulator and its hash.
            return Ok((prev_acc, *blake3::hash(&prev_acc).as_bytes()));
        }

        // Step 2: Wait for any put_versioned() calls that have reserved a slot inside
        // [start, end) but have not yet finished writing their record bytes.  Without
        // this guard, a racing writer could leave a zero-magic gap that breaks parsing.
        while self.inflight.load(Ordering::Acquire) > 0 { std::hint::spin_loop(); }

        // Step 3: Parse dirty slice into (offset, key, vlen) descriptors.
        // Zero-copy: we record mmap offsets, not copies of the value data.
        // Pre-allocate with a rough estimate (average record ≈ CHDR + 32 + 64 bytes)
        // to avoid Vec reallocation during the hot parse loop.
        let mmap_ptr    = self.mmap.as_ptr() as usize;
        let dirty_bytes = end.saturating_sub(start);
        let estimated   = (dirty_bytes / (CHDR + 32 + 64)).max(64);
        let mut records: Vec<(usize, [u8; 32], usize)> = Vec::with_capacity(estimated);
        let mut tombstones: Vec<(usize, [u8; 32])> = Vec::new();

        let mut cur = start;
        while cur + CHDR + 32 <= end {
            let slice = &self.mmap[cur..];
            let magic = u32::from_le_bytes(slice[0..4].try_into().unwrap());
            if magic == CTOMB {
                // Tombstone: vlen is always 0, record size = CHDR + 32.
                let key: [u8; 32] = slice[CHDR..CHDR + 32].try_into().unwrap();
                tombstones.push((cur, key));
                cur += CHDR + 32;
                continue;
            }
            if magic != CMAG { break; }
            let vlen  = u32::from_le_bytes(slice[4..8].try_into().unwrap()) as usize;
            let total = CHDR + 32 + vlen;
            if cur + total > end { break; }
            let key: [u8; 32] = slice[CHDR..CHDR + 32].try_into().unwrap();
            records.push((cur, key, vlen));
            cur += total;
        }

        // Step 4: Parallel blake3 hashing — value bytes read via raw pointer.
        // Each rayon worker produces (key, blake3(value), record_offset).
        let mut hashed: Vec<([u8; 32], [u8; 32], u64)> = records
            .par_iter()
            .map(|&(off, key, vlen)| {
                let val = unsafe {
                    std::slice::from_raw_parts(
                        (mmap_ptr + off + CHDR + 32) as *const u8,
                        vlen,
                    )
                };
                (key, *blake3::hash(val).as_bytes(), off as u64)
            })
            .collect();

        // Step 5: Sort by offset, then dedup — keep the highest-offset write per key.
        // Also count how many times each key appeared in this dirty slice so the
        // index write-count can be incremented correctly.
        hashed.sort_unstable_by_key(|&(_, _, off)| off);
        let mut per_block_count: ahash::AHashMap<[u8; 32], u32> =
            ahash::AHashMap::with_capacity(hashed.len());
        for &(key, _, _) in &hashed { *per_block_count.entry(key).or_insert(0) += 1; }
        let mut latest: ahash::AHashMap<[u8; 32], ([u8; 32], u64)> =
            ahash::AHashMap::with_capacity(hashed.len());
        for (key, vh, off) in hashed {
            latest.insert(key, (vh, off));
        }

        // Step 6: Accumulator update and MVCC chain patching.
        //
        // For each key that was written in this block:
        //   a) If the key already has a committed entry, read its old value from
        //      the mmap, hash it, and XOR the old contribution out of new_acc.
        //   b) Patch prev_offset in the new record's header (bytes 8..16) to
        //      point to the old record, completing the MVCC chain.
        //   c) XOR the new contribution (key XOR blake3(new_value)) into new_acc.
        //   d) Batch the upsert keyed by shard index (key[0]) for parallel execution.
        //
        // Tombstone records (CTOMB) only perform step (a) — they XOR out the
        // old contribution and mark the entry deleted, but add nothing new.
        //
        // The old value hash is read from entry.value_hash (cached in the index
        // at the previous upsert) rather than re-reading from the mmap.
        
        // Type alias for shard batch entries to reduce complexity
        type ShardBatchEntry = (
            [u8; 32],  // key
            [u8; 32],  // value_hash
            u64,       // offset
            u32,       // write_count
            bool,      // deleted
        );
        
        let mut shard_batches: [Vec<ShardBatchEntry>; 256] =
            std::array::from_fn(|_| Vec::new());

        let mut new_acc = prev_acc;

        // Process tombstones first: a put + delete in the same batch ends up deleted.
        for &(off, key) in &tombstones {
            if let Some(old_entry) = index.get_entry(&key) {
                if !old_entry.deleted {
                    // XOR out the old contribution using the cached value hash.
                    for i in 0..32 { new_acc[i] ^= key[i] ^ old_entry.value_hash[i]; }
                }
            }
            let wc = index.count(&key) + 1;
            shard_batches[key[0] as usize].push((key, [0u8; 32], off as u64, wc, true));
        }

        for (&key, &(new_vh, off)) in &latest {
            let mut prev_offset = 0u64;
            if let Some(old_entry) = index.get_entry(&key) {
                if !old_entry.deleted {
                    // XOR out old contribution using the cached hash — no mmap read.
                    for i in 0..32 { new_acc[i] ^= key[i] ^ old_entry.value_hash[i]; }
                }
                prev_offset = old_entry.offset;
            }
            // XOR in the new contribution.
            for i in 0..32 { new_acc[i] ^= key[i] ^ new_vh[i]; }

            // Patch prev_offset into the record header at bytes 8..16.
            if prev_offset > 0 {
                unsafe {
                    let dst = (mmap_ptr + off as usize + 8) as *mut u8;
                    std::ptr::copy_nonoverlapping(prev_offset.to_le_bytes().as_ptr(), dst, 8);
                }
            }

            let block_puts = per_block_count.get(&key).copied().unwrap_or(1);
            let wc         = index.count(&key) + block_puts;
            let is_deleted = tombstones.iter().any(|(_, k)| k == &key);
            shard_batches[key[0] as usize].push((key, new_vh, off, wc, is_deleted));
        }

        // Step 7: Parallel shard upserts — store value_hash so future folds
        // can XOR out correctly without re-reading the mmap.
        shard_batches.par_iter_mut().enumerate().for_each(|(shard_idx, batch)| {
            if !batch.is_empty() {
                let shard = &index.shards[shard_idx];
                for &(key, vh, off, wc, deleted) in batch.iter() {
                    shard.upsert(key, off, wc, log_id, deleted, vh);
                }
            }
        });

        let root = *blake3::hash(&new_acc).as_bytes();

        // Step 8: Advance the committed pointer and persist it for crash recovery.
        self.committed_offset.store(end as u64, Ordering::Release);
        unsafe {
            let dst   = self.mmap.as_ptr() as *mut u8;
            let bytes = (end as u64).to_le_bytes();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, 8);
        }
        let _ = self.mmap.flush_async();

        Ok((new_acc, root))
    }

    /// Issue an asynchronous flush of the mmap to the underlying file.
    ///
    /// The OS will write dirty pages back to disk in the background.  Use this
    /// after `commit_fold_until` to reduce the window of data loss on a crash.
    pub fn flush(&self) { let _ = self.mmap.flush_async(); }

    /// Return the current write frontier (one past the last reserved byte).
    ///
    /// May be ahead of `committed_offset` while in-flight writes are landing.
    pub fn write_offset(&self) -> u64 { self.write_offset.load(Ordering::Acquire) }

    /// Return the current committed frontier (one past the last folded byte).
    ///
    /// Everything below this offset is reflected in the index.
    pub fn committed_offset(&self) -> u64 { self.committed_offset.load(Ordering::Acquire) }

    /// Return the raw base pointer of the mmap region.
    ///
    /// Used for zero-copy reads during log replay and by `commit_fold_until`
    /// to hash value bytes without copying them.
    pub fn mmap_ptr(&self) -> *const u8 { self.mmap.as_ptr() }

    /// Reset the log for reuse at the start of the next block.
    ///
    /// Spins until all in-flight `put_versioned()` calls have finished writing,
    /// then rewinds both `write_offset` and `committed_offset` to 8 (just past
    /// the 8-byte crash-recovery header) and zeroes the header bytes so the
    /// next `open()` sees a clean starting offset.
    pub fn reset(&self) {
        while self.inflight.load(Ordering::Acquire) > 0 {
            std::hint::spin_loop();
        }
        self.write_offset.store(8, Ordering::Release);
        self.committed_offset.store(8, Ordering::Release);
        unsafe { std::ptr::write_bytes(self.mmap.as_ptr() as *mut u8, 0, 8); }
    }

    /// Forcibly advance `committed_offset` to `off`.
    ///
    /// Also advances `write_offset` if it is currently behind `off`, ensuring
    /// the invariant `write_offset >= committed_offset` always holds.
    /// Used during segment replay to restore the committed frontier without
    /// re-running a fold.
    pub fn set_committed(&self, off: u64) {
        self.committed_offset.store(off, Ordering::Release);
        let woff = self.write_offset.load(Ordering::Acquire);
        if off > woff { self.write_offset.store(off, Ordering::Release); }
    }

    /// Scan the **unflushed** region `[committed_offset, write_offset)` for the
    /// last write to `key`, returning its value if found.
    ///
    /// This covers the gap between the most recent fold and the current
    /// write frontier: writes that have landed in the mmap via `put_versioned`
    /// but whose index entries have not yet been committed by a fold pass.
    ///
    /// The scan is strictly bounded to the current block's unflushed bytes.
    /// For well-behaved workloads this is small (one block's worth of writes).
    /// The last occurrence of `key` in the region is returned so that repeated
    /// writes to the same key within a block see the most recent value.
    ///
    /// Walks forward through the unflushed window rather than backwards because
    /// in-flight writes do not yet have `prev_offset` MVCC chain pointers
    /// patched in (that happens during the fold).
    pub(crate) fn scan_unflushed(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        let committed = self.committed_offset.load(Ordering::Acquire) as usize;
        let written   = self.write_offset.load(Ordering::Acquire) as usize;
        if written <= committed { return None; }

        let cap = self.capacity as usize;
        let ptr = self.mmap.as_ptr();
        let mut best: Option<Vec<u8>> = None;
        let mut cur = committed;

        while cur + CHDR + 32 <= written {
            let magic = u32::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(cur), 4)
            }.try_into().unwrap());

            if magic == CTOMB {
                let rec_key: [u8; 32] = unsafe {
                    std::slice::from_raw_parts(ptr.add(cur + CHDR), 32)
                }.try_into().unwrap();
                if rec_key == *key { best = None; } // tombstone wins
                cur += CHDR + 32;
                continue;
            }

            if magic != CMAG { break; }

            let vlen = u32::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(cur + 4), 4)
            }.try_into().unwrap()) as usize;
            let total = CHDR + 32 + vlen;
            if cur + total > written || cur + total > cap { break; }

            let rec_key: [u8; 32] = unsafe {
                std::slice::from_raw_parts(ptr.add(cur + CHDR), 32)
            }.try_into().unwrap();

            if rec_key == *key {
                best = Some(unsafe {
                    std::slice::from_raw_parts(ptr.add(cur + CHDR + 32), vlen).to_vec()
                });
            }
            cur += total;
        }
        best
    }

    /// Scan the entire unflushed region and return the **last** value seen for
    /// every key, as `(key, value)` pairs.
    ///
    /// Tombstones are returned as `(key, empty Vec)` so callers can distinguish
    /// "deleted in this batch" from "not present". Used by `scan_prefix` and
    /// `scan_from_reverse` to overlay in-flight writes on top of the committed
    /// index without requiring a fold.
    pub(crate) fn scan_all_unflushed(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let committed = self.committed_offset.load(Ordering::Acquire) as usize;
        let written   = self.write_offset.load(Ordering::Acquire) as usize;
        if written <= committed { return Vec::new(); }

        let cap = self.capacity as usize;
        let ptr = self.mmap.as_ptr();
        // Use a map to keep only the last write per key in this window.
        let mut map: ahash::AHashMap<[u8; 32], Vec<u8>> = ahash::AHashMap::new();
        let mut cur = committed;

        while cur + CHDR + 32 <= written {
            let magic = u32::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(cur), 4)
            }.try_into().unwrap());

            if magic == CTOMB {
                let key: [u8; 32] = unsafe {
                    std::slice::from_raw_parts(ptr.add(cur + CHDR), 32)
                }.try_into().unwrap();
                map.insert(key, Vec::new()); // empty = tombstone
                cur += CHDR + 32;
                continue;
            }

            if magic != CMAG { break; }

            let vlen = u32::from_le_bytes(unsafe {
                std::slice::from_raw_parts(ptr.add(cur + 4), 4)
            }.try_into().unwrap()) as usize;
            let total = CHDR + 32 + vlen;
            if cur + total > written || cur + total > cap { break; }

            let key: [u8; 32] = unsafe {
                std::slice::from_raw_parts(ptr.add(cur + CHDR), 32)
            }.try_into().unwrap();
            let val = unsafe {
                std::slice::from_raw_parts(ptr.add(cur + CHDR + 32), vlen).to_vec()
            };
            map.insert(key, val);
            cur += total;
        }
        map.into_iter().collect()
    }
}

// ── MmapRef — zero-copy value reference ──────────────────────────────────────

/// A zero-copy handle to a value stored in a `CommutativeLog` mmap.
///
/// On the hot path (committed index hit) this holds an `Arc<CommutativeLog>`
/// and a raw pointer into its mmap — no heap allocation. For values that live
/// in sealed segments or the unflushed active log, it falls back to a `Vec<u8>`
/// heap buffer. Either way callers use it identically via `Deref<Target=[u8]>`.
pub struct MmapRef {
    /// Keeps the mmap mapping alive when using the zero-copy path.
    _log:  Option<std::sync::Arc<CommutativeLog>>,
    /// Pointer into the mmap (zero-copy path) or into the heap Vec (fallback).
    ptr:   *const u8,
    /// Length of the value in bytes.
    len:   usize,
    /// Heap-allocated buffer for the fallback path. Kept alive here so `ptr`
    /// remains valid for the lifetime of `MmapRef`.
    _heap: Option<Vec<u8>>,
}

// SAFETY: CommutativeLog is Send + Sync; the pointed-to region is immutable.
unsafe impl Send for MmapRef {}
unsafe impl Sync for MmapRef {}

impl MmapRef {
    /// Wrap a heap-allocated `Vec<u8>` in a `MmapRef`.
    ///
    /// Used for values that come from sealed segments or the unflushed active
    /// log, where a zero-copy mmap reference is not possible.
    pub fn from_vec(v: Vec<u8>) -> Self {
        let ptr = v.as_ptr();
        let len = v.len();
        MmapRef { _log: None, ptr, len, _heap: Some(v) }
    }
}

impl std::ops::Deref for MmapRef {
    type Target = [u8];
    #[inline(always)]
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl AsRef<[u8]> for MmapRef {
    fn as_ref(&self) -> &[u8] { self }
}

impl std::fmt::Debug for MmapRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MmapRef({} bytes)", self.len)
    }
}

impl CommutativeLog {
    /// Return a zero-copy [`MmapRef`] for the value at `off`, or `None` if the
    /// record is invalid or is a tombstone.
    ///
    /// The returned reference borrows the mmap through the `Arc` — no heap
    /// allocation is needed. Use this on the hot read path when the caller only
    /// needs to inspect or hash the value without keeping a copy.
    pub fn value_ref(self: &std::sync::Arc<Self>, off: usize) -> Option<MmapRef> {
        let cap = self.capacity as usize;
        if off + CHDR + 32 > cap { return None; }
        let ptr = self.mmap.as_ptr();
        let magic = u32::from_le_bytes(unsafe {
            std::slice::from_raw_parts(ptr.add(off), 4)
        }.try_into().ok()?);
        if magic != CMAG { return None; }
        let vlen = u32::from_le_bytes(unsafe {
            std::slice::from_raw_parts(ptr.add(off + 4), 4)
        }.try_into().ok()?) as usize;
        let vs = off + CHDR + 32;
        if vs + vlen > cap { return None; }
        Some(MmapRef {
            _log:  Some(std::sync::Arc::clone(self)),
            ptr:   unsafe { ptr.add(vs) },
            len:   vlen,
            _heap: None,
        })
    }
}
