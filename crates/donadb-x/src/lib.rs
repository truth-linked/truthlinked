//! # DonaDbX — Lock-Free Storage Engine for Blockchain Validator State
//!
//! DonaDbX is a high-performance, append-only key-value store built for
//! blockchain validator state. It combines a lock-free write path, atomic
//! N-shard double-buffering, parallel BLAKE3 Merkle folding, and crash-safe
//! segment rotation into a single coherent API surface.
//!
//! ## Architecture
//!
//! The engine is composed of five cooperating subsystems:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                        DonaDbX API                           │
//! └───────────┬──────────────────────────────────┬───────────────┘
//!             │                                  │
//!   ┌─────────▼──────────┐            ┌──────────▼──────────┐
//!   │  1. ExecutionFrame │            │  3. DualBufferEngine │
//!   │  Isolated write    │            │  N-shard ArcSwap;    │
//!   │  arena; rollback   │            │  atomic buffer swap  │
//!   └─────────┬──────────┘            └──────┬───────────────┘
//!             │                             │
//!             │                  ┌──────────┼──────────────┐
//!             │                  │          │              │
//!   ┌─────────▼──────────┐  ┌────▼───────┐  ┌▼────────────┐
//!   │  2. CommutativeLog │  │ 4. Rayon   │  │ 5. Segment  │
//!   │  Lock-free mmap    │  │    fold    │  │    Manager  │
//!   │  fetch_add +       │  │  Parallel  │  │  Rotation,  │
//!   │  memcpy append     │  │  BLAKE3 +  │  │  manifest,  │
//!   │  posix_fallocate   │  │  XOR root  │  │  recovery   │
//!   └────────────────────┘  └────────────┘  └─────────────┘
//! ```
//!
//! | # | Subsystem | Role |
//! |---|-----------|------|
//! | 1 | [`ExecutionFrame`] | Isolated write arena with zero-copy rollback. Writes are visible via [`DonaDbX::get`] immediately; visible via the index after [`ExecutionFrame::commit`]. |
//! | 2 | [`commutative::CommutativeLog`] | Memory-mapped append log. One `fetch_add` reserves space; one `memcpy` fills it. `posix_fallocate` pre-allocates physical blocks so disk-full surfaces at segment creation, not mid-write. |
//! | 3 | `DualBufferEngine` | N shards (one per logical CPU), each with monotonically-growing logs. [`DonaDbX::commit`] snapshots all shards and launches parallel fold without blocking writers. |
//! | 4 | Rayon fold pool | After each commit, runs parallel `BLAKE3(value)` hashing across all shards simultaneously. Maintains a commutative XOR accumulator `key XOR BLAKE3(value)` for the state root. |
//! | 5 | `SegmentManager` | Rotates the active log to a sealed segment at the fill threshold. Writes a crash-safe JSON manifest via atomic `write-tmp → rename`. Replays on reopen. |
//!
//! ## Key design decisions
//!
//! **Lock-free writes.** [`DonaDbX::put`] performs a single `fetch_add` on the
//! shard's `write_offset` atomic to reserve a slot, then copies the payload in
//! with `memcpy`. No mutex is acquired on the hot write path.
//!
//! **Parallel fold.** [`DonaDbX::commit`] snapshots all shard write frontiers
//! and dispatches them to a Rayon thread pool for parallel processing. Each
//! shard is folded independently, maximizing CPU utilization.
//!
//! **Commutative Merkle root.** The state root is maintained as an XOR
//! accumulator over `key XOR BLAKE3(value)` for every key. Incremental updates
//! are O(1): XOR out the old contribution, XOR in the new one. The final root
//! is `BLAKE3(accumulator)`.
//!
//! **Immediate read visibility.** [`DonaDbX::get`] checks three sources in
//! order: (1) the shard index (O(1), covers folded writes), (2) an active-log
//! scan over the current unflushed batch (covers writes since the last fold),
//! (3) sealed segments (covers rotated history). In-batch reads are visible
//! immediately without waiting for the next `commit()`.
//!
//! **Crash recovery.** The first 8 bytes of `seg_active.log` store
//! `committed_offset` as a little-endian `u64`. On reopen, the engine scans
//! only the range `[8, committed_offset)`, rebuilding the index and XOR
//! accumulator from scratch. Partial writes above `committed_offset` are
//! silently discarded. No separate write-ahead log is needed.
//!
//! **Disk-full protection.** `posix_fallocate(2)` is called at segment
//! creation time. If the filesystem cannot allocate the required space,
//! [`DbError::Io`]`(ENOSPC)` is returned immediately — never as a `SIGBUS`
//! mid-write inside a validation loop.
//!
//! ## Quick start
//!
//! ```no_run
//! use donadb_x::{DonaDbX, Config};
//!
//! let db = DonaDbX::open("./state", Config::default()).unwrap();
//!
//! let key = [1u8; 32];
//! db.put(key, b"hello").unwrap();
//!
//! // commit() swaps the active buffer and launches an async fold.
//! let ack = db.commit(1).unwrap();
//!
//! // wait() blocks until the fold completes and returns the 32-byte state root.
//! let root = ack.wait();
//!
//! assert_eq!(db.get(&key).unwrap(), b"hello");
//! println!("state root: {}", hex::encode(root));
//! ```
//!
//! ## Multi-threaded writes with [`BlockWriter`]
//!
//! For high-throughput ingestion, acquire one [`BlockWriter`] per thread per
//! block. Each writer holds a direct `Arc<CommutativeLog>`, so writers on
//! different shards contend only on their own shard's `write_offset` atomic —
//! never on each other.
//!
//! ```no_run
//! use donadb_x::{DonaDbX, Config};
//! use std::sync::Arc;
//!
//! let db = Arc::new(DonaDbX::open("./state", Config::default()).unwrap());
//!
//! let handles: Vec<_> = (0..4).map(|shard_id| {
//!     let db = Arc::clone(&db);
//!     std::thread::spawn(move || {
//!         let writer = db.writer(shard_id);
//!         for i in 0u8..64 {
//!             let mut key = [0u8; 32];
//!             key[0] = shard_id as u8;
//!             key[1] = i;
//!             writer.put(key, &[i; 8]).unwrap();
//!         }
//!     })
//! }).collect();
//!
//! for h in handles { h.join().unwrap(); }
//! let root = db.commit(2).unwrap().wait();
//! println!("block 2 state root: {}", hex::encode(root));
//! ```
//!
//! ## Complexity summary
//!
//! | Operation | Complexity | Notes |
//! |-----------|------------|-------|
//! | [`put()`][DonaDbX::put] | O(1) | One `fetch_add` + one `memcpy`; no locks |
//! | [`get()`][DonaDbX::get] | O(1) + O(u) | O(1) index hit; O(u) unflushed scan on miss, where u = records in current batch |
//! | [`get_at()`][DonaDbX::get_at] | O(v) | MVCC chain walk over v versions of the key |
//! | [`commit()`][DonaDbX::commit] | O(1) enqueue | Swap is instantaneous; fold is async |
//! | [`state_root()`][DonaDbX::state_root] | O(1) | Reads the pre-maintained XOR accumulator |
//! | Segment rotation | O(n) amortised | Runs once at fill threshold per segment |
//! | Crash recovery | O(r) | Replays r committed records from the active log |

use thiserror::Error;

// ── Error type ────────────────────────────────────────────────────────────────

/// The unified error type for all DonaDbX operations.
///
/// All public methods return `DbResult<T>`, which is an alias for
/// `Result<T, DbError>`.
#[derive(Debug, Error)]
pub enum DbError {
    /// An underlying OS I/O error (file open, mmap, read, write, rename, …).
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// The active log has no remaining capacity for the requested write.
    ///
    /// This should not occur under normal operation because the segment
    /// manager rotates the log before it reaches capacity. If it does occur,
    /// increase `Config::buffer_size` or lower `Config::rotate_threshold`.
    #[error("Log full")]
    LogFull,

    /// A log record's magic number or length fields are invalid.
    ///
    /// This may indicate file corruption or an incomplete write from a
    /// previous crash. The crash-recovery path stops scanning at the first
    /// corrupt record, so partial trailing writes are safe.
    #[error("Corrupt")]
    Corrupt,

    /// The requested key does not exist in any committed log or sealed segment.
    #[error("Not found")]
    NotFound,

    /// A requested feature or configuration value is not supported.
    ///
    /// The attached `&'static str` identifies which feature was requested.
    #[error("Unsupported: {0}")]
    Unsupported(&'static str),
}

/// Convenience alias for `Result<T, DbError>`.
pub type DbResult<T> = Result<T, DbError>;

// ── Modules ───────────────────────────────────────────────────────────────────

/// Public index API: sharded hash-map for key → log-offset lookups.
pub mod index;

/// Public commutative-log API: lock-free, memory-mapped append log.
pub mod commutative;

/// In-process value cache — bounded DashMap populated by the fold thread.
pub(crate) mod value_cache;

/// String prefix index — secondary BTreeMap for lexicographic prefix scans.
pub mod string_index;

/// Segment management: rotation, manifest persistence, sealed-segment reads.
pub(crate) mod segment;

/// Double-buffering engine: atomic buffer swap and async Rayon fold pool.
pub(crate) mod dual_buffer;

/// Top-level engine: `DonaDbX`, `Config`, `CommitAck`, `ExecutionFrame`.
mod engine;

// ── Public re-exports ─────────────────────────────────────────────────────────

pub use engine::{DonaDbX, Config, CommitAck, ExecutionFrame, BlockWriter};
pub use commutative::MmapRef;
pub use string_index::StringIndex;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Construct a 32-byte key from a single discriminator byte.
    fn k(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    /// Small config suitable for unit tests: 4 MiB segments avoid exhausting
    /// disk space now that posix_fallocate pre-allocates physical blocks.
    fn test_cfg() -> Config {
        Config { buffer_size: 4 << 20, ..Default::default() }
    }

    /// Smoke test: write two keys, commit, then read both back.
    #[test]
    fn basic() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
        db.put(k(1), b"hello").unwrap();
        db.put(k(2), b"world").unwrap();
        db.commit(1).unwrap().wait();
        assert_eq!(db.get(&k(1)).unwrap(), b"hello");
        assert_eq!(db.get(&k(2)).unwrap(), b"world");
    }

    /// Writing the same key twice in one block should leave only the latest value.
    #[test]
    fn overwrite() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
        db.put(k(1), b"old").unwrap();
        db.put(k(1), b"new").unwrap();
        db.commit(1).unwrap().wait();
        assert_eq!(db.get(&k(1)).unwrap(), b"new");
    }

    /// Committed data must survive a process restart (simulated by dropping
    /// and reopening the `DonaDbX` instance against the same directory).
    #[test]
    fn crash_recovery() {
        let d = tempdir().unwrap();
        {
            let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
            db.put(k(1), b"ok").unwrap();
            db.commit(1).unwrap().wait();
        }
        let db2 = DonaDbX::open(d.path(), test_cfg()).unwrap();
        assert_eq!(db2.get(&k(1)).unwrap(), b"ok");
    }

    /// Writes inside an `ExecutionFrame` are visible to `get()` immediately via
    /// the active-log scan, and remain visible after `frame.commit()` once the
    /// fold has updated the index.
    #[test]
    fn frame_isolation() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
        let frame = db.begin_frame();
        frame.put(k(1), b"secret").unwrap();
        // Active-log scan: the write is in the mmap and readable immediately.
        assert_eq!(db.get(&k(1)).unwrap(), b"secret");
        frame.commit(1).unwrap().wait();
        // Still readable via the index after the fold.
        assert_eq!(db.get(&k(1)).unwrap(), b"secret");
    }

    /// Aborting a frame must roll back its writes and leave previously
    /// committed data intact.
    #[test]
    fn frame_abort() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
        db.put(k(1), b"committed").unwrap();
        db.commit(1).unwrap().wait();
        let frame = db.begin_frame();
        frame.put(k(1), b"aborted").unwrap();
        frame.abort();
        assert_eq!(db.get(&k(1)).unwrap(), b"committed");
    }

    /// A committed delete makes the key invisible to get().
    #[test]
    fn delete_committed() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
        db.put(k(1), b"alive").unwrap();
        db.commit(1).unwrap().wait();
        assert_eq!(db.get(&k(1)).unwrap(), b"alive");

        db.delete(k(1)).unwrap();
        db.commit(2).unwrap().wait();
        assert!(db.get(&k(1)).is_err());
    }

    /// A delete followed by a put in the next block resurrects the key.
    #[test]
    fn delete_then_resurrect() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
        db.put(k(1), b"v1").unwrap();
        db.commit(1).unwrap().wait();
        db.delete(k(1)).unwrap();
        db.commit(2).unwrap().wait();
        db.put(k(1), b"v2").unwrap();
        db.commit(3).unwrap().wait();
        assert_eq!(db.get(&k(1)).unwrap(), b"v2");
    }

    /// state_root changes on put, returns to prior value after delete,
    /// confirming the XOR accumulator correctly reverses the contribution.
    #[test]
    fn state_root_delete_reversal() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
        let root_empty = db.state_root();

        db.put(k(1), b"hello").unwrap();
        db.commit(1).unwrap().wait();
        let root_with = db.state_root();
        assert_ne!(root_empty, root_with);

        db.delete(k(1)).unwrap();
        db.commit(2).unwrap().wait();
        let root_after_delete = db.state_root();
        // After deleting the only key, the accumulator must return to empty.
        assert_eq!(root_empty, root_after_delete,
            "state root must be identical to empty after deleting the only key");
    }

    /// scan_prefix returns only matching, non-deleted keys in sorted order.
    #[test]
    fn scan_prefix_basic() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
        let mut k1 = [0u8; 32]; k1[0] = 0x01; k1[1] = 0x00;
        let mut k2 = [0u8; 32]; k2[0] = 0x01; k2[1] = 0x01;
        let mut k3 = [0u8; 32]; k3[0] = 0x02;
        db.put(k1, b"a").unwrap();
        db.put(k2, b"b").unwrap();
        db.put(k3, b"c").unwrap();
        db.commit(1).unwrap().wait();

        let results = db.scan_prefix(&[0x01]).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, k1);
        assert_eq!(results[1].0, k2);

        // Delete k1, scan should return only k2.
        db.delete(k1).unwrap();
        db.commit(2).unwrap().wait();
        let results = db.scan_prefix(&[0x01]).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, k2);
    }

    /// scan_from_reverse returns keys ≤ start in descending order.
    #[test]
    fn scan_from_reverse_basic() {
        let d = tempdir().unwrap();
        let db = DonaDbX::open(d.path(), test_cfg()).unwrap();
        let mut ka = [0u8; 32]; ka[0] = 0x10;
        let mut kb = [0u8; 32]; kb[0] = 0x20;
        let mut kc = [0u8; 32]; kc[0] = 0x30;
        db.put(ka, b"a").unwrap();
        db.put(kb, b"b").unwrap();
        db.put(kc, b"c").unwrap();
        db.commit(1).unwrap().wait();

        let results = db.scan_from_reverse(&kb).unwrap();
        assert_eq!(results.len(), 2);
        // Descending: kb first, then ka.
        assert_eq!(results[0].0, kb);
        assert_eq!(results[1].0, ka);
    }
}
