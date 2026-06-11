//! DonaDB PQ persistence stress for consensus storage.
//!
//! Generates PQ-sized TruthLinked transactions and commits the same finalized
//! blocks to N independent node data directories through `Persistence::save_block`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use truthlinked_consensus::{BatchHeader, Persistence};
use truthlinked_core::pq_execution::{Transaction, TransactionIntent};

const ML_DSA_65_PUBKEY_BYTES: usize = 1952;
const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

fn fill_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x = seed ^ 0x9e37_79b9_7f4a_7c15;
    while out.len() < len {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn account(seed: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&seed.to_le_bytes());
    *h.finalize().as_bytes()
}

fn pq_tx(block: u64, idx: usize, genesis_fingerprint: [u8; 32]) -> Transaction {
    let seed = block.wrapping_mul(1_000_003).wrapping_add(idx as u64);
    Transaction {
        sender: account(seed),
        intent: TransactionIntent::Transfer {
            recipient: account(seed.wrapping_add(1)),
            recipient_pubkey: Some(fill_bytes(seed ^ 0xA11CE, ML_DSA_65_PUBKEY_BYTES)),
            amount: 1_000 + (seed as u128 % 1_000_000),
        },
        signature: fill_bytes(seed ^ 0x51A7, ML_DSA_65_SIGNATURE_BYTES),
        nonce: block.wrapping_mul(10_000).wrapping_add(idx as u64),
        timestamp: 1_700_000_000 + block,
        genesis_fingerprint,
        expiration_height: block + 10_000,
    }
}

fn batch_hash(batch: &[Transaction]) -> [u8; 32] {
    let bytes = postcard::to_allocvec(batch).expect("serialize batch");
    *blake3::hash(&bytes).as_bytes()
}

fn header(height: u64, parent_hash: [u8; 32], batch: &[Transaction]) -> BatchHeader {
    let hash = batch_hash(batch);
    BatchHeader::new(
        height,
        parent_hash,
        hash,
        hash,
        account(height ^ 0x57A7E),
        1_700_000_000 + height,
        0,
        truthlinked_consensus::blockchain::PqFinalityCertificate::empty(
            height,
            0,
            hash,
            account(height ^ 0x57A7E),
        ),
        fill_bytes(height ^ 0xBEEF, ML_DSA_65_PUBKEY_BYTES),
        fill_bytes(height ^ 0xF00D, ML_DSA_65_SIGNATURE_BYTES),
        0,
    )
}

fn dir_size(path: &std::path::Path) -> u64 {
    fn walk(path: &std::path::Path, acc: &mut u64) {
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        if meta.is_file() {
            *acc += meta.len();
            return;
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            walk(&entry.path(), acc);
        }
    }
    let mut total = 0;
    walk(path, &mut total);
    total
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::set_var("DONADB_MEMTABLE_FLUSH", "5000");
        std::env::set_var("DONADB_L0_MAX", "2");
        std::env::set_var("DONADB_L1_MAX", "2");
        std::env::set_var("DONADB_L2_MAX", "2");
    }

    let args: Vec<String> = std::env::args().collect();
    let nodes: usize = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(10);
    let blocks: u64 = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(100);
    let txs_per_block: usize = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(200);
    let root = PathBuf::from(
        args.get(4)
            .cloned()
            .unwrap_or_else(|| "/tmp/truthlinked-donadb-pq-stress".to_string()),
    );

    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;

    let mut stores = Vec::with_capacity(nodes);
    for node in 0..nodes {
        let path = root.join(format!("node-{node:02}"));
        stores.push(Persistence::new(path)?);
    }

    let genesis_fingerprint = account(0xC0FFEE);
    let registry = HashMap::new();
    let mut parent = [0u8; 32];
    let mut first_tx_hash = None;
    let mut commit_ms = Vec::new();
    let started = Instant::now();

    for height in 1..=blocks {
        let batch: Vec<_> = (0..txs_per_block)
            .map(|idx| pq_tx(height, idx, genesis_fingerprint))
            .collect();
        if first_tx_hash.is_none() {
            first_tx_hash = Some(*blake3::hash(&postcard::to_allocvec(&batch[0])?).as_bytes());
        }
        let header = header(height, parent, &batch);
        parent = header.batch_hash;
        let results = vec!["success".to_string(); batch.len()];

        let t0 = Instant::now();
        for store in &stores {
            store.save_block(&header, &batch, &results, &registry)?;
        }
        let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
        commit_ms.push(elapsed);

        if height == 1 || height % 10 == 0 || height == blocks {
            let total_committed = height as usize * txs_per_block * nodes;
            println!(
                "height={} committed_copies={} last_commit_all_nodes_ms={:.2}",
                height, total_committed, elapsed
            );
        }
    }

    for store in &stores {
        store.finalize_block(blocks)?;
    }
    drop(stores);

    let total_tx_copies = blocks as usize * txs_per_block * nodes;
    let secs = started.elapsed().as_secs_f64().max(0.0001);
    let mut sorted = commit_ms.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = sorted[sorted.len() / 2];
    let p95 = sorted[((sorted.len() as f64 * 0.95) as usize).min(sorted.len() - 1)];
    let p99 = sorted[((sorted.len() as f64 * 0.99) as usize).min(sorted.len() - 1)];

    println!(
        "WRITE_SUMMARY nodes={} blocks={} txs_per_block={} tx_copies={} tx_copy_rate={:.0}/sec p50_all_nodes_ms={:.2} p95={:.2} p99={:.2}",
        nodes,
        blocks,
        txs_per_block,
        total_tx_copies,
        total_tx_copies as f64 / secs,
        p50,
        p95,
        p99
    );

    let first_hash = first_tx_hash.expect("at least one tx");
    let verify_started = Instant::now();
    let mut total_bytes = 0u64;
    for node in 0..nodes {
        let path = root.join(format!("node-{node:02}"));
        total_bytes += dir_size(&path);
        let store = Persistence::new(&path)?;
        assert_eq!(store.get_latest_block_height(), blocks);
        assert!(
            store.load_batch(1)?.is_some(),
            "node {node} missing block 1"
        );
        assert!(
            store.load_batch(blocks)?.is_some(),
            "node {node} missing tip block"
        );
        assert_eq!(
            store.verify_tx_index_integrity(blocks),
            (txs_per_block as u32, txs_per_block as u32, true),
            "node {node} tx index mismatch"
        );
        assert!(
            store.get_transaction_by_hash(&first_hash)?.is_some(),
            "node {node} missing first tx hash lookup"
        );
    }
    let verify_secs = verify_started.elapsed().as_secs_f64();
    println!(
        "VERIFY_SUMMARY nodes={} latest_height={} total_storage_mb={:.2} verify_secs={:.2}",
        nodes,
        blocks,
        total_bytes as f64 / (1024.0 * 1024.0),
        verify_secs
    );

    Ok(())
}
