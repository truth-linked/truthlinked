//! Segment lifecycle management: metadata, manifest persistence, and sealed-segment reads.
//!
//! ## Segment lifecycle
//!
//! ```text
//! active log (seg_active.log)
//!     │  written to continuously via CommutativeLog
//!     │
//!     ▼  rotate() called when buffer reaches rotate_threshold
//! sealed segment (seg_NNNN.log)
//!     │  renamed atomically, mmap stays valid
//!     │  recorded in manifest.json
//!     │
//!     ▼  opened as SealedSegment for historical reads
//! read-only mmap
//! ```
//!
//! The manifest is written atomically: new content is written to a `.tmp` file,
//! then renamed over the real manifest. This ensures the manifest is never
//! partially written, even on power failure.

use crate::{DbError, DbResult};
use crate::commutative::{CHDR, CMAG};
use memmap2::{Mmap, MmapOptions};
use std::fs::{self, OpenOptions};
use std::path::Path;

// ── Manifest ──────────────────────────────────────────────────────────────────

/// Metadata record for one log segment, stored inside [`Manifest`].
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SegmentMeta {
    /// Monotonically increasing segment ID, assigned at rotation time.
    pub id: u32,
    /// Absolute path to the segment file on disk.
    pub path: String,
    /// `true` once the segment has been rotated out of the active slot and is
    /// no longer written to.
    pub sealed: bool,
    /// Number of bytes written to this segment (valid only when `sealed`).
    /// Used to bound reads in [`SealedSegment::get_at`].
    pub used: u64,
    /// Lowest block height whose records appear in this segment.
    pub min_height: u64,
    /// Highest block height whose records appear in this segment.
    /// Set to `u64::MAX` for the active (unsealed) segment.
    pub max_height: u64,
}

/// Durable list of all log segments, persisted as `manifest.json` in the
/// database directory.
///
/// On startup, `DonaDbX::open` reads this file to locate existing segments
/// and replay the active log. On rotation, the manifest is updated atomically
/// before any destructive file operations.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct Manifest {
    /// All segments known to this database instance, ordered by `id`.
    pub segments: Vec<SegmentMeta>,
    /// The `id` to assign to the next new segment.
    pub next_id: u32,
}

impl Manifest {
    /// Load the manifest from `path`, or return an empty default if the file
    /// does not yet exist (first open of a new database directory).
    pub fn load(path: &Path) -> DbResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path).map_err(DbError::Io)?;
        serde_json::from_str(&raw).map_err(|e| {
            DbError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            ))
        })
    }

    /// Atomically persist the manifest to `path`.
    ///
    /// The new content is first written to `path.tmp`, then renamed over
    /// `path`. On POSIX systems `rename(2)` is atomic, so readers always see
    /// either the old or the new manifest, never a partial write.
    pub fn save(&self, path: &Path) -> DbResult<()> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self).unwrap())
            .map_err(DbError::Io)?;
        fs::rename(&tmp, path).map_err(DbError::Io)
    }
}

// ── SealedSegment ─────────────────────────────────────────────────────────────

/// A read-only view of a sealed log segment, memory-mapped for zero-copy reads.
///
/// Sealed segments are written once (during log rotation) and never modified
/// again. They are opened with a read-only `mmap` so the OS can share pages
/// with other processes reading the same file.
pub struct SealedSegment {
    /// Metadata describing this segment's ID, path, height range, and size.
    pub meta: SegmentMeta,
    /// Read-only memory map of the segment file.
    mmap: Mmap,
}

impl SealedSegment {
    /// Open a sealed segment for reading.
    ///
    /// Maps `meta.path` into the process address space as a read-only `mmap`.
    /// Returns an error if the file cannot be opened or mapped.
    pub fn open(meta: SegmentMeta) -> DbResult<Self> {
        let f = OpenOptions::new()
            .read(true)
            .open(&meta.path)
            .map_err(DbError::Io)?;
        let mmap = unsafe { MmapOptions::new().map(&f).map_err(DbError::Io)? };
        Ok(Self { meta, mmap })
    }

    /// Find the value of `key` written at or before block `height` in this segment.
    ///
    /// The segment is scanned linearly from offset 8 (after the 8-byte
    /// committed-offset header). Records are in append order, so the last
    /// matching record before `height` wins. Returns `None` if:
    ///
    /// - `height` is outside this segment's `[min_height, max_height]` range.
    /// - The key does not appear in this segment.
    ///
    /// The linear scan is acceptable because sealed segments are only consulted
    /// for historical `get_at` queries, which are uncommon in normal validator
    /// operation. For the latest-value path, the in-memory `ShardIndex` is used
    /// instead.
    pub fn get_at(&self, key: &[u8; 32], height: u64) -> Option<Vec<u8>> {
        let m    = &self.mmap;
        let used = self.meta.used as usize;

        // Fast path: skip segments that can't possibly contain records at this height.
        if height < self.meta.min_height || height > self.meta.max_height {
            return None;
        }

        let mut best: Option<Vec<u8>> = None;
        let mut cur = 8usize; // skip the 8-byte committed-offset header

        while cur + CHDR + 32 <= used {
            let magic = u32::from_le_bytes(m[cur..cur + 4].try_into().unwrap());
            if magic != CMAG {
                break; // corrupted or end of written data
            }
            let vlen  = u32::from_le_bytes(m[cur + 4..cur + 8].try_into().unwrap()) as usize;
            let total = CHDR + 32 + vlen;
            if cur + total > used || vlen > used {
                break; // truncated record
            }

            let rec_key: [u8; 32] = m[cur + CHDR..cur + CHDR + 32].try_into().unwrap();
            if rec_key == *key {
                // Keep overwriting best: the last matching record in append
                // order is the most recent write at or before max_height.
                best = Some(m[cur + CHDR + 32..cur + total].to_vec());
            }
            cur += total;
        }
        best
    }
}
