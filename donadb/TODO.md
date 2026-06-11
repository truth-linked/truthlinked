DonaDB Maintenance Notes

This file tracks storage-engine work that remains relevant after the RocksDB removal. Completed migration notes have been folded back into source documentation and tests.

Open items:

1. Tombstone retention policy
   DonaDB currently keeps tombstones through a conservative compaction window. Before enabling more aggressive garbage collection, prove that older SST files are fully shadowed and no historical query can still depend on the tombstone.

2. Long-run validation
   Keep running multi-hour and overnight workloads that combine validators, explorer/indexer reads, Axiom CLI writes, checkpoints, crash restarts, and compaction pressure.

3. Format versioning
   Add explicit WAL, snapshot, and SST format version markers before public compatibility guarantees are made.
