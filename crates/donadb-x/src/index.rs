//! ShardIndex — 256-shard in-memory key→offset lookup table.
//!
//! ## Design
//!
//! Keys are 32-byte fixed-size hashes (validator state keys). The index is
//! split into 256 shards by the first byte of the key. This means:
//!
//! - Two concurrent readers/writers only contend if their keys share the same
//!   first byte — a 1-in-256 chance for random keys.
//! - The fold's parallel shard upsert can update all 256 shards concurrently
//!   with zero cross-shard interference.
//! - Each shard uses DashMap for lock-free concurrent access with fine-grained
//!   per-bucket locking.
//!
//! DashMap provides better concurrency than `Mutex<HashMap>` because readers
//! never block each other and writers only contend on the same hash bucket.

/// A single index entry mapping a key to its most recently committed record.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    /// The 32-byte key this entry belongs to.
    pub key: [u8; 32],
    /// Byte offset into the `CommutativeLog` mmap where this key's latest
    /// record starts.
    pub offset: u64,
    /// How many times this key has been written across all committed blocks.
    pub write_count: u32,
    /// Generation counter of the log segment that owns this entry.
    pub log_id: u64,
    /// `true` if the last committed operation for this key was a deletion.
    pub deleted: bool,
    /// `BLAKE3(value)` of the most recently committed value for this key.
    ///
    /// Cached here so the fold thread can XOR out the old accumulator
    /// contribution without re-reading the value bytes from the mmap.
    pub value_hash: [u8; 32],
}

/// One of 256 shards in the index. Each shard manages all keys whose first
/// byte equals the shard's index.
///
/// Uses DashMap for lock-free concurrent reads and writes. Multiple readers
/// can access the shard simultaneously without blocking, and writes use
/// fine-grained per-bucket locking.
pub struct Shard {
    /// Lock-free concurrent hash map using per-bucket RwLocks internally.
    /// Readers never block each other, and writers only block other operations
    /// on the same hash bucket.
    pub entries: dashmap::DashMap<[u8; 32], Entry>,
}

impl Shard {
    /// Create an empty shard with a small initial capacity.
    pub fn new() -> Self {
        Self { entries: dashmap::DashMap::with_capacity(64) }
    }

    /// Return the mmap offset of `key`'s latest committed record, or `None`.
    #[inline(always)]
    pub(crate) fn get(&self, key: &[u8; 32]) -> Option<u64> {
        self.entries.get(key).map(|e| e.offset)
    }

    /// Return a copy of the full `Entry` for `key`, or `None`.
    #[inline(always)]
    pub(crate) fn get_entry(&self, key: &[u8; 32]) -> Option<Entry> {
        self.entries.get(key).map(|e| *e.value())
    }

    /// Return the cumulative write count for `key`, or 0 if not present.
    #[inline(always)]
    pub(crate) fn get_count(&self, key: &[u8; 32]) -> u32 {
        self.entries.get(key).map(|e| e.write_count).unwrap_or(0)
    }

    /// Insert or update the entry for `key`.
    ///
    /// `value_hash` is `BLAKE3(value)` cached so the fold can XOR out the old
    /// accumulator contribution without re-reading value bytes from the mmap.
    #[inline(always)]
    pub fn upsert(&self, key: [u8; 32], offset: u64, write_count: u32, log_id: u64, deleted: bool, value_hash: [u8; 32]) {
        self.entries.insert(key, Entry { key, offset, write_count, log_id, deleted, value_hash });
    }

    /// Remove a key from this shard entirely (used during compaction cleanup).
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn remove(&self, key: &[u8; 32]) {
        self.entries.remove(key);
    }

    /// Number of distinct keys in this shard.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if this shard contains no keys.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Collect all entries as a `Vec` — used for iteration and replay.
    pub fn iter_all(&self) -> Vec<Entry> {
        self.entries.iter().map(|e| *e.value()).collect()
    }
}

impl Default for Shard {
    fn default() -> Self { Self::new() }
}

/// 256-shard in-memory index providing O(1) key→offset lookups.
///
/// All public methods delegate to the appropriate shard based on `key[0]`.
/// The index is rebuilt from the commit log on startup via `replay_into`.
pub struct ShardIndex {
    /// The 256 shards, indexed by the first byte of the key.
    pub shards: Box<[Shard; 256]>,
}

impl ShardIndex {
    /// Create an empty index with all 256 shards initialised.
    pub fn new() -> Self {
        let shards: Box<[Shard; 256]> = (0..256)
            .map(|_| Shard::new())
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        Self { shards }
    }

    /// Route to the shard responsible for `key`.
    #[inline(always)]
    pub(crate) fn shard(&self, key: &[u8; 32]) -> &Shard {
        &self.shards[key[0] as usize]
    }

    /// Return the mmap offset of `key`'s latest committed record, or `None`.
    #[inline(always)]
    pub fn get(&self, k: &[u8; 32]) -> Option<u64> {
        self.shard(k).get(k)
    }

    /// Return the full `Entry` for `key`, or `None`.
    ///
    /// Use this when you need both the offset and the `log_id` for staleness
    /// detection after a log rotation.
    #[inline(always)]
    pub fn get_entry(&self, k: &[u8; 32]) -> Option<Entry> {
        self.shard(k).get_entry(k)
    }

    /// Return the cumulative write count for `key`, or 0.
    #[inline(always)]
    pub fn count(&self, k: &[u8; 32]) -> u32 {
        self.shard(k).get_count(k)
    }

    /// Insert or update the entry for `key`. See [`Shard::upsert`].
    #[inline(always)]
    pub fn upsert(&self, k: [u8; 32], off: u64, wc: u32, log_id: u64) {
        self.shard(&k).upsert(k, off, wc, log_id, false, [0u8; 32]);
    }

    /// Insert or update an entry with an explicit `deleted` flag and cached `value_hash`.
    #[inline(always)]
    pub fn upsert_with_deleted(&self, k: [u8; 32], off: u64, wc: u32, log_id: u64, deleted: bool) {
        self.shard(&k).upsert(k, off, wc, log_id, deleted, [0u8; 32]);
    }

    /// Insert or update an entry with full metadata including cached value hash.
    #[inline(always)]
    pub fn upsert_full(&self, k: [u8; 32], off: u64, wc: u32, log_id: u64, deleted: bool, vh: [u8; 32]) {
        self.shard(&k).upsert(k, off, wc, log_id, deleted, vh);
    }

    /// Total number of distinct keys across all shards.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.len()).sum()
    }

    /// Returns `true` if the index contains no keys.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all entries from every shard.
    pub fn clear(&self) {
        for s in self.shards.iter() {
            s.entries.clear();
        }
    }

    /// Collect all entries across all shards into a single `Vec`.
    pub fn all_entries(&self) -> Vec<Entry> {
        let mut v = Vec::new();
        for s in self.shards.iter() {
            v.extend(s.iter_all());
        }
        v
    }
}

impl Default for ShardIndex {
    fn default() -> Self { Self::new() }
}
