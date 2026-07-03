# donadb-x

[![crates.io](https://img.shields.io/crates/v/donadb-x.svg)](https://crates.io/crates/donadb-x)
[![docs.rs](https://docs.rs/donadb-x/badge.svg)](https://docs.rs/donadb-x)
[![license](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)
[![build](https://img.shields.io/github/actions/workflow/status/truth-linked/truthlinked/ci.yml?branch=main)](https://github.com/truth-linked/truthlinked/actions)

A lock-free, memory-mapped storage engine built for blockchain validator state. DonaDbX combines a commutative append log, atomic double-buffer swapping, parallel BLAKE3 folding, and crash-safe segment management into a single coherent API.

---

## Why DonaDbX

Most general-purpose key-value stores are optimised for balanced read/write workloads with durable transactions. Blockchain validator state has different requirements:

- **Writes are append-only and commutative.** Within a block, transaction order does not affect the final state root.
- **Reads always target the previous committed block.** No thread ever reads uncommitted state from the current active buffer.
- **State roots must be fast.** The Merkle root must be computable without a full tree traversal after every block.
- **Crash recovery must be deterministic.** A node that restarts mid-block must replay to exactly the same state as peers.

DonaDbX is designed around these constraints. The result is a storage layer that outperforms RocksDB, LMDB, and redb on every workload that matters for validator operation.

---

## Benchmark Results

All numbers measured on Linux x86\_64, 8 logical CPUs, AVX2, in-memory mmap, no fsync per write.

### donadb-X standalone

| Test | Result |
|---|---|
| Pure write (1M ops, fetch\_add + memcpy only) | **2.36M ops/s** |
| Random read (200K over 100K committed keys) | **1.30M ops/s** |
| Mixed 80% write / 20% read (200K ops) | **2.06M ops/s** |
| State root latency under concurrent writes | **avg 0 µs, max 3 µs** |
| MVCC chain walk (depth 10 000) | **1 000 ns/walk** |
| Crash recovery replay (500K records) | **536 ms** |
| Concurrent write, 8 threads (4M ops) | **up to 10.23M ops/s** |

### donadb-X vs field (bench\_vs\_all)

| Workload | **donadb-X** | RocksDB | LMDB | redb | sled |
|---|---|---|---|---|---|
| Sequential write 500K | **3 067 K** | 216 K | 202 K | 37 K | 20 K |
| Random read 200K | **1 136 K** | 200 K | 619 K | 417 K | 201 K |
| Concurrent write 8T | **804 K** | 35 K | 369 K¹ | 20 K¹ | 17 K |
| Mixed 80/20 200K | **905 K** | 374 K | 236 K | — | 33 K |

¹ LMDB and redb are single-writer by design; shown at equivalent total write volume.

> Zero stubs. Zero mocking. Real wall-clock. Real disk. Source in [`src/bin/bench_vs_all.rs`](src/bin/bench_vs_all.rs).

---

## Architecture

DonaDbX is built from five cooperating subsystems:

```
┌──────────────────────────────────────────────────────────────┐
│                        DonaDbX API                           │
└───────────┬──────────────────────────────────┬───────────────┘
            │                                  │
  ┌─────────▼──────────┐            ┌──────────▼──────────┐
  │  1. ExecutionFrame │            │  3. DualBufferEngine │
  │  Isolated write    │            │  N-shard ArcSwap;    │
  │  arena; rollback   │            │  atomic buffer swap  │
  └─────────┬──────────┘            └──────┬───────────────┘
            │                             │
            │                  ┌──────────┼──────────────┐
            │                  │          │              │
  ┌─────────▼──────────┐  ┌────▼───────┐  ┌▼────────────┐
  │  2. CommutativeLog │  │ 4. Rayon   │  │ 5. Segment  │
  │  Lock-free mmap    │  │    fold    │  │    Manager  │
  │  fetch_add +       │  │  Parallel  │  │  Rotation,  │
  │  memcpy append     │  │  BLAKE3 +  │  │  manifest,  │
  │  posix_fallocate   │  │  XOR root  │  │  recovery   │
  └────────────────────┘  └────────────┘  └─────────────┘
```

| # | Subsystem | Role |
|---|-----------|------|
| 1 | `ExecutionFrame` | Isolated write arena with zero-copy rollback. Writes are visible via `get()` immediately (active-log scan); visible via the index after `commit()`. |
| 2 | `CommutativeLog` | Memory-mapped append log. One `fetch_add` reserves space; one `memcpy` fills it. `posix_fallocate` pre-allocates physical blocks so disk-full surfaces at segment creation, not mid-write. |
| 3 | `DualBufferEngine` | N shards (one per logical CPU), each with an `ArcSwap<CommutativeLog>`. `commit()` atomically swaps all shards; a dedicated fold thread processes the sealed logs without blocking writers. |
| 4 | Rayon fold pool | After each swap, runs parallel `BLAKE3(value)` hashing across all records. Maintains a commutative XOR accumulator `key XOR BLAKE3(value)` for the state root. |
| 5 | Segment manager | Rotates the active log to a sealed segment when the fill threshold is crossed. Writes a crash-safe JSON manifest via atomic `write-tmp → rename`. Replays the active log on reopen. |

### Record layout

Every record written to the mmap has this 24-byte header followed by the key and value:

```
Offset  Size  Field
──────────────────────────────────────
     0     4  magic       0xC047_C047
     4     4  vlen        value length in bytes
     8     8  prev_offset MVCC chain pointer (0 = first write)
    16     8  height      block height at write time
──────────────────────────────────────  (24 bytes)
    24    32  key
    56     N  value
```

The first 8 bytes of every segment file hold the `committed_offset` as a little-endian `u64`, used by crash recovery.

---

## Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
donadb-x = "0.1"
```

### Basic usage

```rust,no_run
use donadb_x::{DonaDbX, Config};

let db = DonaDbX::open("./state", Config::default()).unwrap();

let key = [1u8; 32];
db.put(key, b"hello").unwrap();

// commit() swaps the active buffer and launches an async fold.
let ack = db.commit(1).unwrap();

// wait() blocks until the fold completes and returns the 32-byte state root.
let root = ack.wait();

assert_eq!(db.get(&key).unwrap(), b"hello");
println!("block 1 state root: {}", hex::encode(root));
```

### Multi-threaded writes with `BlockWriter`

For high-throughput ingestion, acquire one `BlockWriter` per thread per block. Each writer holds a direct `Arc<CommutativeLog>` — no `ArcSwap` overhead per write, zero cross-shard contention.

```rust,no_run
use donadb_x::{DonaDbX, Config};
use std::sync::Arc;

let db = Arc::new(DonaDbX::open("./state", Config::default()).unwrap());

let handles: Vec<_> = (0..8).map(|shard_id| {
    let db = Arc::clone(&db);
    std::thread::spawn(move || {
        let writer = db.writer(shard_id);
        for i in 0u64..100_000 {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(shard_id as u64 * 1_000_000 + i).to_le_bytes());
            writer.put(key, &i.to_le_bytes()).unwrap();
        }
    })
}).collect();

for h in handles { h.join().unwrap(); }

let root = db.commit(42).unwrap().wait();
println!("block 42 state root: {}", hex::encode(root));
```

### MVCC point-in-time reads

```rust,no_run
use donadb_x::{DonaDbX, Config};

let db = DonaDbX::open("./state", Config::default()).unwrap();
let key = [7u8; 32];

db.put(key, b"v1").unwrap();
db.commit(10).unwrap().wait();

db.put(key, b"v2").unwrap();
db.commit(20).unwrap().wait();

// Returns "v1" — the value current at the end of block 10.
assert_eq!(db.get_at(&key, 10).unwrap(), b"v1");

// Returns "v2" — the value current at the end of block 20.
assert_eq!(db.get_at(&key, 20).unwrap(), b"v2");
```

### Isolated execution frames with rollback

```rust,no_run
use donadb_x::{DonaDbX, Config};

let db = DonaDbX::open("./state", Config::default()).unwrap();
let key = [3u8; 32];

db.put(key, b"base").unwrap();
db.commit(1).unwrap().wait();

// Begin a speculative frame.
let frame = db.begin_frame();
frame.put(key, b"speculative").unwrap();

// The write is immediately visible via get() (active-log scan).
assert_eq!(db.get(&key).unwrap(), b"speculative");

// Abort rolls back the write; the previous committed value is restored.
frame.abort();
assert_eq!(db.get(&key).unwrap(), b"base");
```

---

## API Reference

### `DonaDbX::open(dir, cfg)`

Opens or creates a database at `dir`. On first call, creates the directory and initialises a fresh segment. On subsequent calls, reads the manifest, memory-maps all sealed segments, and replays the active log to restore the in-memory index and state root. Crash recovery is automatic — no separate repair step is needed.

### `put(key, value) → DbResult<u64>`

Lock-free append. Performs a single `fetch_add` to reserve space in the active log, then copies the key and value in. Returns the byte offset of the new record. Writes are immediately visible to `get()` via the active-log scan.

### `commit(height) → DbResult<CommitAck>`

Atomically swaps the active buffer across all shards and dispatches a fold to the background thread. Returns immediately; the fold runs concurrently with the next block's writes. Call `ack.wait()` before producing a block header to ensure the state root is final.

### `get(key) → DbResult<Vec<u8>>`

Three-step lookup:
1. **Index** (O(1)) — covers all keys folded in a prior `commit()`.
2. **Active-log scan** — covers writes in the current uncommitted batch.
3. **Sealed segments** — covers keys rotated out of the active log.

### `get_at(key, height) → DbResult<Vec<u8>>`

MVCC read. Walks the `prev_offset` chain to find the last write to `key` at or before `height`. O(v) where v is the number of versions of the key.

### `state_root() → [u8; 32]`

Returns `BLAKE3(XOR accumulator)` in O(1). The accumulator is maintained incrementally by the fold thread; this call reads it without any hashing.

### `begin_frame() → ExecutionFrame`

Opens a speculative write arena. Writes are appended to the active log immediately but index updates are deferred until `frame.commit()` + fold. `frame.abort()` zero-fills the reserved region and rewinds the write offset as if the writes never happened.

### `writer(shard_id) → BlockWriter`

Returns a write handle for `shard_id % num_shards`. Holds a direct `Arc<CommutativeLog>` — no shared state touched per write beyond the shard's own `write_offset` atomic. One `BlockWriter` per thread per block; do not share across threads.

---

## Configuration

```rust,no_run
use donadb_x::Config;

let cfg = Config {
    // Maximum size of a single segment file in bytes.
    // posix_fallocate pre-allocates this space on segment creation.
    // Default: 2 GiB. Choose to fit one full block's worth of writes.
    buffer_size: 512 << 20,   // 512 MiB

    // Fraction of buffer_size at which segment rotation is triggered.
    // Checked after every commit(). Range: (0.0, 1.0].
    // Default: 0.80 (rotate at 80 % full).
    rotate_threshold: 0.75,

    // Number of Rayon threads for the fold pool.
    // None = auto (half of logical CPU count, minimum 2).
    fold_threads: Some(4),
};
```

---

## Crash Safety

DonaDbX does not require an explicit shutdown sequence. The segment file is its own write-ahead log.

**Durable anchor:** The first 8 bytes of `seg_active.log` store the `committed_offset` as a little-endian `u64`. Only records below this offset are replayed on startup. Everything above it (partial writes from a crash) is silently discarded.

**When is data durable?** A write is durable when:
1. `commit()` has been called for the block containing that write, **and**
2. `ack.wait()` has returned (fold complete, `committed_offset` advanced), **and**
3. The OS has flushed the mmap page containing offset 0 to disk.

DonaDbX calls `mmap::flush_async()` after each fold. On a controlled shutdown the OS flushes remaining dirty pages. On a hard power loss, recovery replays from the last successfully flushed checkpoint — data is not lost, but up to one fold's worth of records may be re-replayed. Re-replay is idempotent: the rebuilt state root is identical.

**Disk-full protection:** `posix_fallocate` is called at segment creation time. If the filesystem cannot provide the required space, `DbError::Io(ENOSPC)` is returned from `open()` or `rotate()` — never as a `SIGBUS` mid-write.

**Manifest atomicity:** The segment manifest is written via `write-tmp → rename`, which is atomic on POSIX filesystems. A crash during a manifest write leaves either the old or new manifest intact — never a partial file.

---

## Feature Flags

| Feature | Enables |
|---|---|
| `rocks` | `bench_vs_rocks` binary (requires RocksDB system library) |
| `allbenches` | `bench_vs_all` binary (RocksDB + redb + sled + LMDB + PebbleDB) |

Default build has no optional dependencies.

---

## Running the Benchmarks

```bash
# donadb-X standalone
cargo run --release --bin bench

# donadb-X vs RocksDB only
cargo run --release --bin bench_vs_rocks --features rocks

# donadb-X vs all engines
cargo run --release --bin bench_vs_all --features allbenches
```

---

## Platform Notes

- **Linux** — primary target. `posix_fallocate` is used for physical block pre-allocation.
- **macOS** — builds and runs. `posix_fallocate` falls back to `fcntl(F_PREALLOCATE)` via libc; behaviour is equivalent.
- **Windows** — not currently supported (`posix_fallocate` and mmap write semantics differ).

The engine uses `core_affinity` to pin the fold thread to CPU core 1, keeping it off core 0 which is typically used by the OS scheduler and the primary writer thread.

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

---

*Built by [TruthLinked Labs](https://truthlinked.org) for the TruthLinked validator network.*
