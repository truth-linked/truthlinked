# DonaDB

DonaDB is TruthLinked Labs' lightweight, crash-safe LSM storage engine for high-throughput post-quantum blockchain nodes. It provides an embeddable key-value store with WAL-backed durability, SSTable storage, block-oriented writes, compaction, and recovery paths designed for validator, explorer, and indexer workloads.

## Status

DonaDB is actively developed for the TruthLinked blockchain stack. The public crate is intended for storage-engine integration, benchmarking, and external review. APIs may evolve while the database matures.

## Features

- Crash-safe write-ahead logging.
- LSM-style SSTable storage with compaction.
- Block-aware write batches for blockchain persistence.
- Prefix scanning and point lookups.
- Lightweight dependency footprint.
- Test and stress binaries for throughput and crash-recovery validation.

## Quick Start

```rust
use donadb::{DonaDB, DonaDbConfig};

let dir = tempfile::tempdir()?;
let db = DonaDB::open(DonaDbConfig {
    data_dir: dir.path().to_path_buf(),
    ..DonaDbConfig::default()
})?;

db.put(b"hello", b"world")?;
let value = db.get(b"hello")?;
assert_eq!(value.as_deref(), Some(&b"world"[..]));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
