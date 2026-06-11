//! Immutable sorted-string-table storage for DonaDB.
//!
//! DonaDB writes frozen memtables as SST files. Each file contains LZ4-compressed
//! data blocks, a sparse block index, a bloom filter, and a fixed footer with
//! offsets for the index and bloom sections. The reader validates every on-disk
//! length and offset before allocation so corrupted files are ignored instead of
//! crashing recovery.
//!
//! The SST level manager keeps three tiers: L0 for fresh flushes, L1 for merged
//! L0 output, and L2 for longer-lived compacted state. Newer readers are searched
//! first, so tombstones and overwritten keys shadow older values.

use blake3;
use bytes::Bytes;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

const BLOCK_SIZE: usize = 4096;
const BLOOM_BITS: usize = 10;
const INDEX_STRIDE: usize = 64;
const MAX_SST_KEY_LEN: usize = 16 * 1024 * 1024;
const MAX_SST_VALUE_LEN: usize = 128 * 1024 * 1024;
const MAX_SST_BLOCK_COMPRESSED_LEN: usize = 64 * 1024 * 1024;
const MAX_SST_INDEX_ENTRIES: usize = 50_000_000;
const MAX_SST_BLOOM_BYTES: usize = 512 * 1024 * 1024;

const TOMBSTONE_TAG: &[u8] = b"\x00TLDB_TOMBSTONE";

/// Compact probabilistic filter used to avoid unnecessary SST block reads.
pub struct BloomFilter {
    bits: Vec<u8>,
    n_bits: usize,
}

impl BloomFilter {
    /// Create a bloom filter sized for `n_keys`.
    pub fn new(n_keys: usize) -> Self {
        let n_bits = (n_keys * BLOOM_BITS).max(64);
        Self {
            bits: vec![0u8; (n_bits + 7) / 8],
            n_bits,
        }
    }

    fn hashes(key: &[u8]) -> [usize; 3] {
        let h = blake3::hash(key);
        let b = h.as_bytes();
        let h1 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(b[8..16].try_into().unwrap()).max(1);
        let h3 = h1.wrapping_add(h2.wrapping_mul(2));
        [h1 as usize, h1.wrapping_add(h2) as usize, h3 as usize]
    }

    /// Add `key` to the filter.
    pub fn insert(&mut self, key: &[u8]) {
        for h in Self::hashes(key) {
            let bit = h % self.n_bits;
            self.bits[bit / 8] |= 1 << (bit % 8);
        }
    }

    /// Return false only when `key` is definitely absent.
    pub fn may_contain(&self, key: &[u8]) -> bool {
        Self::hashes(key).iter().all(|&h| {
            let bit = h % self.n_bits;
            self.bits[bit / 8] & (1 << (bit % 8)) != 0
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + self.bits.len());
        b.extend_from_slice(&(self.n_bits as u64).to_le_bytes());
        b.extend_from_slice(&self.bits);
        b
    }

    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let n_bits_u64 = u64::from_le_bytes(data[0..8].try_into().ok()?);
        if n_bits_u64 == 0 || n_bits_u64 > (MAX_SST_BLOOM_BYTES as u64) * 8 {
            return None;
        }
        let n_bits = n_bits_u64 as usize;
        let expected_bytes = n_bits.div_ceil(8);
        if data.len() - 8 != expected_bytes {
            return None;
        }
        Some(Self {
            bits: data[8..].to_vec(),
            n_bits,
        })
    }
}

/// Write entries to one durable SST file.
///
/// Entries are sorted before writing. Tombstone values are stored verbatim so
/// deletes can shadow older values during later reads and compaction.
pub fn write_sst(path: &Path, mut entries: Vec<(Bytes, Bytes)>) -> io::Result<()> {
    entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

    let mut f = BufWriter::new(File::create(path)?);
    let mut bloom = BloomFilter::new(entries.len());
    let mut index: Vec<(Bytes, u64)> = Vec::new();
    let mut block_buf: Vec<u8> = Vec::with_capacity(BLOCK_SIZE * 2);
    let mut block_count = 0usize;
    let mut file_offset: u64 = 0;
    let mut block_start: u64 = 0;
    let mut first_key: Option<Bytes> = None;

    let flush_block = |f: &mut BufWriter<File>,
                       buf: &mut Vec<u8>,
                       offset: &mut u64,
                       index: &mut Vec<(Bytes, u64)>,
                       bs: &mut u64,
                       fk: &mut Option<Bytes>|
     -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let compressed = lz4_flex::compress_prepend_size(buf);
        if let Some(k) = fk.take() {
            index.push((k, *bs));
        }
        f.write_all(&(compressed.len() as u32).to_le_bytes())?;
        f.write_all(&compressed)?;
        *offset += 4 + compressed.len() as u64;
        *bs = *offset;
        buf.clear();
        Ok(())
    };

    for (key, val) in &entries {
        bloom.insert(key);
        if first_key.is_none() {
            first_key = Some(key.clone());
        }

        block_buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
        block_buf.extend_from_slice(key);
        block_buf.extend_from_slice(&(val.len() as u32).to_le_bytes());
        block_buf.extend_from_slice(val);
        block_count += 1;

        if block_buf.len() >= BLOCK_SIZE || block_count >= INDEX_STRIDE {
            flush_block(
                &mut f,
                &mut block_buf,
                &mut file_offset,
                &mut index,
                &mut block_start,
                &mut first_key,
            )?;
            block_count = 0;
        }
    }
    flush_block(
        &mut f,
        &mut block_buf,
        &mut file_offset,
        &mut index,
        &mut block_start,
        &mut first_key,
    )?;

    let index_offset = file_offset;
    f.write_all(&(index.len() as u64).to_le_bytes())?;
    let mut bloom_offset = index_offset + 8;
    for (k, off) in &index {
        f.write_all(&(k.len() as u32).to_le_bytes())?;
        f.write_all(k)?;
        f.write_all(&off.to_le_bytes())?;
        bloom_offset += (4 + k.len() + 8) as u64;
    }

    f.write_all(&bloom.to_bytes())?;

    f.write_all(&index_offset.to_le_bytes())?;
    f.write_all(&bloom_offset.to_le_bytes())?;
    f.write_all(&(entries.len() as u64).to_le_bytes())?;
    f.flush()?;
    f.get_ref().sync_all()?;
    Ok(())
}

/// Read-only handle for one SST file.
pub struct SstReader {
    path: PathBuf,
    file: Arc<File>,
    bloom: BloomFilter,
    index: Vec<(Bytes, u64)>,
}

impl SstReader {
    /// Open and validate an SST file.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = Arc::new(File::open(path)?);
        let mut f = file.try_clone()?;

        let file_len = f.metadata()?.len();
        if file_len < 24 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "sst too small"));
        }
        f.seek(SeekFrom::End(-24))?;
        let mut footer = [0u8; 24];
        f.read_exact(&mut footer)?;
        let index_offset = u64::from_le_bytes(footer[0..8].try_into().unwrap());
        let bloom_offset = u64::from_le_bytes(footer[8..16].try_into().unwrap());
        if index_offset > bloom_offset || bloom_offset > file_len.saturating_sub(24) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad sst footer offsets",
            ));
        }
        if bloom_offset < index_offset + 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad sst index section",
            ));
        }

        f.seek(SeekFrom::Start(index_offset))?;
        let mut cnt = [0u8; 8];
        f.read_exact(&mut cnt)?;
        let n_u64 = u64::from_le_bytes(cnt);
        if n_u64 > MAX_SST_INDEX_ENTRIES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sst index too large",
            ));
        }
        let n = n_u64 as usize;
        let mut index = Vec::with_capacity(n);
        for _ in 0..n {
            let mut kl = [0u8; 4];
            f.read_exact(&mut kl)?;
            let klen = u32::from_le_bytes(kl) as usize;
            if klen > MAX_SST_KEY_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sst index key too large",
                ));
            }
            let current = f.stream_position()?;
            if current + klen as u64 + 8 > bloom_offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sst index overruns bloom",
                ));
            }
            let mut kb = vec![0u8; klen];
            f.read_exact(&mut kb)?;
            let mut ob = [0u8; 8];
            f.read_exact(&mut ob)?;
            let off = u64::from_le_bytes(ob);
            if off + 4 > index_offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sst block offset out of range",
                ));
            }
            index.push((Bytes::from(kb), off));
        }

        let bloom_len_u64 = file_len - 24 - bloom_offset;
        if bloom_len_u64 > MAX_SST_BLOOM_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sst bloom too large",
            ));
        }
        let bloom_len = bloom_len_u64 as usize;
        f.seek(SeekFrom::Start(bloom_offset))?;
        let mut bb = vec![0u8; bloom_len];
        f.read_exact(&mut bb)?;
        let bloom = BloomFilter::from_bytes(&bb)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad bloom"))?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
            bloom,
            index,
        })
    }

    /// Return the raw value for `key`, including tombstones.
    pub fn get(&self, key: &[u8]) -> io::Result<Option<Bytes>> {
        if !self.bloom.may_contain(key) {
            return Ok(None);
        }

        let block_offset = match self.index.binary_search_by(|(k, _)| k.as_ref().cmp(key)) {
            Ok(i) => self.index[i].1,
            Err(0) => return Ok(None),
            Err(i) => self.index[i - 1].1,
        };

        let block = self.read_block(block_offset)?;
        Ok(scan_block(&block, key))
    }

    fn read_block(&self, offset: u64) -> io::Result<Vec<u8>> {
        let mut lb = [0u8; 4];
        self.file.read_exact_at(&mut lb, offset)?;
        let clen = u32::from_le_bytes(lb) as usize;
        let file_len = self.file.metadata()?.len();
        if clen == 0 || clen > MAX_SST_BLOCK_COMPRESSED_LEN || offset + 4 + clen as u64 > file_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad sst block length",
            ));
        }
        let mut compressed = vec![0u8; clen];
        self.file.read_exact_at(&mut compressed, offset + 4)?;
        lz4_flex::decompress_size_prepended(&compressed)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Iterate all entries in key order (including tombstones).
    pub fn iter_all(&self) -> io::Result<Vec<(Bytes, Bytes)>> {
        let mut f = self.file.try_clone()?;
        let file_len = f.metadata()?.len();
        if file_len < 24 {
            return Ok(vec![]);
        }
        f.seek(SeekFrom::End(-24))?;
        let mut footer = [0u8; 24];
        f.read_exact(&mut footer)?;
        let index_offset = u64::from_le_bytes(footer[0..8].try_into().unwrap());
        f.seek(SeekFrom::Start(0))?;

        let mut results = Vec::new();
        let mut offset = 0u64;
        loop {
            if offset >= index_offset {
                break;
            }
            let mut lb = [0u8; 4];
            if f.read_exact(&mut lb).is_err() {
                break;
            }
            let clen = u32::from_le_bytes(lb) as usize;
            if clen == 0
                || clen > MAX_SST_BLOCK_COMPRESSED_LEN
                || offset + 4 + clen as u64 > index_offset
            {
                break;
            }
            let mut compressed = vec![0u8; clen];
            if f.read_exact(&mut compressed).is_err() {
                break;
            }
            offset += 4 + clen as u64;
            let block = match lz4_flex::decompress_size_prepended(&compressed) {
                Ok(b) => b,
                Err(_) => break,
            };
            decode_block(&block, &mut results);
        }
        Ok(results)
    }

    fn decode_block_range(
        block: &[u8],
        start: &[u8],
        end: Option<&[u8]>,
        out: &mut Vec<(Bytes, Bytes)>,
    ) {
        let mut pos = 0;
        while pos + 8 <= block.len() {
            let klen = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if klen > MAX_SST_KEY_LEN || pos + klen + 4 > block.len() {
                break;
            }
            let k = &block[pos..pos + klen];
            pos += klen;
            let vlen = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if vlen > MAX_SST_VALUE_LEN || pos + vlen > block.len() {
                break;
            }
            let v = &block[pos..pos + vlen];
            pos += vlen;
            if k < start {
                continue;
            }
            if let Some(end) = end {
                if k >= end {
                    break;
                }
            }
            out.push((Bytes::copy_from_slice(k), Bytes::copy_from_slice(v)));
        }
    }

    pub fn scan_range(&self, start: &[u8], end: &[u8]) -> io::Result<Vec<(Bytes, Bytes)>> {
        if self.index.is_empty() {
            return Ok(vec![]);
        }
        let start_idx = match self.index.binary_search_by(|(k, _)| k.as_ref().cmp(start)) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let mut results = Vec::new();
        for i in start_idx..self.index.len() {
            let (first_key, offset) = &self.index[i];
            if first_key.as_ref() >= end {
                break;
            }
            let block = self.read_block(*offset)?;
            Self::decode_block_range(&block, start, Some(end), &mut results);
        }
        Ok(results)
    }

    fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
        if prefix.is_empty() {
            return None;
        }
        let mut end = prefix.to_vec();
        for i in (0..end.len()).rev() {
            if end[i] != 0xFF {
                end[i] += 1;
                end.truncate(i + 1);
                return Some(end);
            }
        }
        None
    }

    pub fn scan_prefix(&self, prefix: &[u8]) -> io::Result<Vec<(Bytes, Bytes)>> {
        let end = Self::prefix_end(prefix);
        if self.index.is_empty() {
            return Ok(vec![]);
        }
        let start_idx = match self.index.binary_search_by(|(k, _)| k.as_ref().cmp(prefix)) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let mut results = Vec::new();
        for i in start_idx..self.index.len() {
            let (first_key, offset) = &self.index[i];
            if let Some(ref end_key) = end {
                if first_key.as_ref() >= end_key.as_slice() {
                    break;
                }
            }
            let block = self.read_block(*offset)?;
            Self::decode_block_range(&block, prefix, end.as_deref(), &mut results);
        }
        Ok(results)
    }
}

fn scan_block(block: &[u8], key: &[u8]) -> Option<Bytes> {
    let mut pos = 0;
    while pos + 8 <= block.len() {
        let klen = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if klen > MAX_SST_KEY_LEN || pos + klen + 4 > block.len() {
            break;
        }
        let k = &block[pos..pos + klen];
        pos += klen;
        let vlen = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if vlen > MAX_SST_VALUE_LEN || pos + vlen > block.len() {
            break;
        }
        let v = &block[pos..pos + vlen];
        pos += vlen;
        if k == key {
            return Some(Bytes::copy_from_slice(v));
        }
        if k > key {
            break;
        }
    }
    None
}

fn decode_block(block: &[u8], out: &mut Vec<(Bytes, Bytes)>) {
    let mut pos = 0;
    while pos + 8 <= block.len() {
        let klen = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if klen > MAX_SST_KEY_LEN || pos + klen + 4 > block.len() {
            break;
        }
        let k = Bytes::copy_from_slice(&block[pos..pos + klen]);
        pos += klen;
        let vlen = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if vlen > MAX_SST_VALUE_LEN || pos + vlen > block.len() {
            break;
        }
        let v = Bytes::copy_from_slice(&block[pos..pos + vlen]);
        pos += vlen;
        out.push((k, v));
    }
}

/// Return true when `v` is DonaDB's encoded deletion marker.
pub fn is_tombstone(v: &[u8]) -> bool {
    v.starts_with(TOMBSTONE_TAG)
}

/// Encode a deletion marker with the compaction height that created it.
pub fn tombstone(height: u64) -> Bytes {
    let mut buf = Vec::with_capacity(TOMBSTONE_TAG.len() + 8);
    buf.extend_from_slice(TOMBSTONE_TAG);
    buf.extend_from_slice(&height.to_le_bytes());
    Bytes::from(buf)
}

/// Decode the compaction height from an encoded deletion marker.
pub fn tombstone_height(v: &[u8]) -> Option<u64> {
    if !v.starts_with(TOMBSTONE_TAG) {
        return None;
    }
    if v.len() < TOMBSTONE_TAG.len() + 8 {
        return None;
    }
    let start = TOMBSTONE_TAG.len();
    let mut b = [0u8; 8];
    b.copy_from_slice(&v[start..start + 8]);
    Some(u64::from_le_bytes(b))
}

const TOMBSTONE_TTL_COMPACTIONS: u64 = 1000;

struct Level {
    readers: RwLock<Vec<Arc<SstReader>>>,
    max_files: usize,
}

/// Multi-level SST store with newest-reader-wins lookup semantics.
pub struct SstLevel {
    dir: PathBuf,
    levels: Vec<Level>,
    next_id: AtomicU64,
    compacting: AtomicBool,
    current_height: AtomicU64,
}

impl SstReader {
    /// Return this reader's backing file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl SstLevel {
    /// Open an SST directory and load every valid level file.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;

        let l0_max = std::env::var("DONADB_L0_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4);
        let l1_max = std::env::var("DONADB_L1_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10);
        let l2_max = std::env::var("DONADB_L2_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(usize::MAX);
        let mut l0 = Vec::new();
        let mut l1 = Vec::new();
        let mut l2 = Vec::new();
        let mut max_id = 0u64;

        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "sst").unwrap_or(false))
            .collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                let parts: Vec<_> = stem.split('_').collect();
                if parts.len() == 2 {
                    if let Ok(id) = parts[1].parse::<u64>() {
                        max_id = max_id.max(id);
                    }
                    if let Ok(r) = SstReader::open(&path) {
                        match parts[0] {
                            "l0" => l0.push(Arc::new(r)),
                            "l1" => l1.push(Arc::new(r)),
                            "l2" => l2.push(Arc::new(r)),
                            _ => {}
                        }
                    }
                }
            }
        }
        l0.reverse();
        l1.reverse();
        l2.reverse();

        Ok(Self {
            dir: dir.to_path_buf(),
            levels: vec![
                Level {
                    readers: RwLock::new(l0),
                    max_files: l0_max,
                },
                Level {
                    readers: RwLock::new(l1),
                    max_files: l1_max,
                },
                Level {
                    readers: RwLock::new(l2),
                    max_files: l2_max,
                },
            ],
            next_id: AtomicU64::new(max_id + 1),
            compacting: AtomicBool::new(false),
            current_height: AtomicU64::new(0),
        })
    }

    fn level_paths(readers: &[Arc<SstReader>]) -> HashSet<PathBuf> {
        readers.iter().map(|r| r.path().to_path_buf()).collect()
    }

    fn merge_readers(
        readers: &[Arc<SstReader>],
        keep_tombstones: bool,
        current_height: u64,
    ) -> Vec<(Bytes, Bytes)> {
        let mut seen: BTreeMap<Bytes, Option<(Bytes, u64)>> = BTreeMap::new();
        for r in readers.iter() {
            if let Ok(all) = r.iter_all() {
                for (k, v) in all {
                    if seen.contains_key(&k) {
                        continue;
                    }
                    if is_tombstone(&v) {
                        if keep_tombstones {
                            let h = tombstone_height(&v).unwrap_or(0);
                            let h = if h == 0 { current_height } else { h };
                            seen.insert(k, Some((v, h)));
                        } else {
                            seen.insert(k, None);
                        }
                    } else {
                        seen.insert(k, Some((v, 0)));
                    }
                }
            }
        }

        seen.into_iter()
            .filter_map(|(k, v)| match v {
                Some((val, height)) if is_tombstone(&val) => {
                    if current_height.saturating_sub(height) >= TOMBSTONE_TTL_COMPACTIONS {
                        None
                    } else {
                        Some((k, val))
                    }
                }
                Some((val, _)) => Some((k, val)),
                None => None,
            })
            .collect()
    }

    /// Merge all levels into newest-visible raw entries.
    pub fn iter_all(&self) -> Vec<(Bytes, Bytes)> {
        let mut readers = Vec::new();
        for level in &self.levels {
            let r = level.readers.read().unwrap();
            readers.extend(r.iter().cloned());
        }
        let h = self.current_height.load(Ordering::Relaxed);
        Self::merge_readers(&readers, false, h)
    }

    fn write_level_file(&self, level: usize, entries: Vec<(Bytes, Bytes)>) -> io::Result<PathBuf> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let path = self.dir.join(format!("l{}_{}.sst", level, id));
        write_sst(&path, entries)?;
        Ok(path)
    }

    /// Flush frozen memtable entries to a new L0 SST.
    pub fn flush(self: &Arc<Self>, entries: Vec<(Bytes, Bytes)>) -> io::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let path = self.write_level_file(0, entries)?;
        let reader = Arc::new(SstReader::open(&path)?);
        self.levels[0].readers.write().unwrap().insert(0, reader);
        let l0 = self.levels[0].readers.read().unwrap().len();
        let l1 = self.levels[1].readers.read().unwrap().len();
        if l0 >= self.levels[0].max_files || l1 >= self.levels[1].max_files {
            let _ = self.compact_now();
        } else {
            self.maybe_compact_async();
        }
        Ok(())
    }

    /// Start background compaction when no compaction is currently running.
    pub fn maybe_compact_async(self: &Arc<Self>) {
        if self
            .compacting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let sst = Arc::clone(self);
        std::thread::spawn(move || {
            while sst.compact_once().is_ok() {
                let l0 = sst.levels[0].readers.read().unwrap().len();
                let l1 = sst.levels[1].readers.read().unwrap().len();
                if l0 < sst.levels[0].max_files && l1 < sst.levels[1].max_files {
                    break;
                }
            }
            sst.compacting.store(false, Ordering::Release);
        });
    }

    /// Force one compaction pass inline.
    pub fn compact_now(&self) -> io::Result<()> {
        self.compact_once()
    }

    fn compact_once(&self) -> io::Result<()> {
        let l0_len = self.levels[0].readers.read().unwrap().len();
        if l0_len >= self.levels[0].max_files {
            return self.compact_l0_to_l1();
        }
        let l1_len = self.levels[1].readers.read().unwrap().len();
        if l1_len >= self.levels[1].max_files {
            return self.compact_l1_to_l2();
        }
        Ok(())
    }

    fn compact_l0_to_l1(&self) -> io::Result<()> {
        let l0 = self.levels[0].readers.read().unwrap().clone();
        let mut readers = Vec::new();
        readers.extend(l0.iter().cloned());
        if readers.is_empty() {
            return Ok(());
        }

        let current_height = self.current_height.fetch_add(1, Ordering::Relaxed) + 1;
        let entries = Self::merge_readers(&readers, true, current_height);
        let new_path = self.write_level_file(1, entries)?;
        let new_reader = Arc::new(SstReader::open(&new_path)?);

        let remove_paths = Self::level_paths(&readers);
        {
            let mut l0_lock = self.levels[0].readers.write().unwrap();
            l0_lock.retain(|r| !remove_paths.contains(r.path()));
            let mut l1_lock = self.levels[1].readers.write().unwrap();
            l1_lock.insert(0, new_reader);
        }
        for p in remove_paths {
            let _ = std::fs::remove_file(p);
        }
        Ok(())
    }

    fn compact_l1_to_l2(&self) -> io::Result<()> {
        let l1 = self.levels[1].readers.read().unwrap().clone();
        let l2 = self.levels[2].readers.read().unwrap().clone();
        let mut readers = Vec::new();
        readers.extend(l1.iter().cloned());
        readers.extend(l2.iter().cloned());
        if readers.is_empty() {
            return Ok(());
        }

        let current_height = self.current_height.fetch_add(1, Ordering::Relaxed) + 1;
        let entries = Self::merge_readers(&readers, false, current_height);
        let new_path = self.write_level_file(2, entries)?;
        let new_reader = Arc::new(SstReader::open(&new_path)?);

        let remove_paths = Self::level_paths(&readers);
        {
            let mut l1_lock = self.levels[1].readers.write().unwrap();
            l1_lock.retain(|r| !remove_paths.contains(r.path()));
            let mut l2_lock = self.levels[2].readers.write().unwrap();
            l2_lock.retain(|r| !remove_paths.contains(r.path()));
            l2_lock.insert(0, new_reader);
        }
        for p in remove_paths {
            let _ = std::fs::remove_file(p);
        }
        Ok(())
    }

    /// Return the live value for `key`, or `None` when missing or tombstoned.
    pub fn get(&self, key: &[u8]) -> Option<Bytes> {
        for level in &self.levels {
            let readers = level.readers.read().unwrap();
            for r in readers.iter() {
                if let Ok(Some(v)) = r.get(key) {
                    if is_tombstone(&v) {
                        return None;
                    }
                    return Some(v);
                }
            }
        }
        None
    }

    fn merge_scan_range(&self, start: &[u8], end: &[u8]) -> Vec<(Bytes, Bytes)> {
        let mut seen: BTreeMap<Bytes, Option<Bytes>> = BTreeMap::new();
        for level in &self.levels {
            let readers = level.readers.read().unwrap();
            for r in readers.iter() {
                if let Ok(entries) = r.scan_range(start, end) {
                    for (k, v) in entries {
                        if seen.contains_key(&k) {
                            continue;
                        }
                        seen.insert(k, if is_tombstone(&v) { None } else { Some(v) });
                    }
                }
            }
        }
        seen.into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, val)))
            .collect()
    }

    fn merge_scan_prefix(&self, prefix: &[u8]) -> Vec<(Bytes, Bytes)> {
        let mut seen: BTreeMap<Bytes, Option<Bytes>> = BTreeMap::new();
        for level in &self.levels {
            let readers = level.readers.read().unwrap();
            for r in readers.iter() {
                if let Ok(entries) = r.scan_prefix(prefix) {
                    for (k, v) in entries {
                        if seen.contains_key(&k) {
                            continue;
                        }
                        seen.insert(k, if is_tombstone(&v) { None } else { Some(v) });
                    }
                }
            }
        }
        seen.into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, val)))
            .collect()
    }

    fn merge_scan_range_raw(&self, start: &[u8], end: &[u8]) -> Vec<(Bytes, Bytes)> {
        let mut seen: BTreeMap<Bytes, Bytes> = BTreeMap::new();
        for level in &self.levels {
            let readers = level.readers.read().unwrap();
            for r in readers.iter() {
                if let Ok(entries) = r.scan_range(start, end) {
                    for (k, v) in entries {
                        if seen.contains_key(&k) {
                            continue;
                        }
                        seen.insert(k, v);
                    }
                }
            }
        }
        seen.into_iter().collect()
    }

    fn merge_scan_prefix_raw(&self, prefix: &[u8]) -> Vec<(Bytes, Bytes)> {
        let mut seen: BTreeMap<Bytes, Bytes> = BTreeMap::new();
        for level in &self.levels {
            let readers = level.readers.read().unwrap();
            for r in readers.iter() {
                if let Ok(entries) = r.scan_prefix(prefix) {
                    for (k, v) in entries {
                        if seen.contains_key(&k) {
                            continue;
                        }
                        seen.insert(k, v);
                    }
                }
            }
        }
        seen.into_iter().collect()
    }

    /// Scan live values by raw key prefix.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Vec<(Bytes, Bytes)> {
        self.merge_scan_prefix(prefix)
    }

    /// Scan live values in raw key range `[start, end)`.
    pub fn scan_range(&self, start: &[u8], end: &[u8]) -> Vec<(Bytes, Bytes)> {
        self.merge_scan_range(start, end)
    }

    /// Scan raw values by prefix, including tombstones.
    pub fn scan_prefix_raw(&self, prefix: &[u8]) -> Vec<(Bytes, Bytes)> {
        self.merge_scan_prefix_raw(prefix)
    }

    /// Scan raw values in `[start, end)`, including tombstones.
    pub fn scan_range_raw(&self, start: &[u8], end: &[u8]) -> Vec<(Bytes, Bytes)> {
        self.merge_scan_range_raw(start, end)
    }

    /// Return the current SST file counts for L0, L1, and L2.
    pub fn stats(&self) -> (usize, usize, usize) {
        (
            self.levels[0].readers.read().unwrap().len(),
            self.levels[1].readers.read().unwrap().len(),
            self.levels[2].readers.read().unwrap().len(),
        )
    }
}
