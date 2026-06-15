//! Truthlinked Consensus Src Persistence
//!
//! Owns durable consensus storage, indexes, snapshots, and pruning.
//! Consensus changes are protocol-critical; preserve deterministic replay, recovery safety, and wire compatibility.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use tracing::info;
use truthlinked_state::constants::MAX_SNAPSHOTS_KEPT;

const RAW_BLOCK_RETENTION: u64 = 256;
const DONADB_DOMAIN: donadb::DomainId = 0;

#[derive(Debug)]
enum KvOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

struct StorageBackend {
    db: donadb::DonaDb,
}

impl StorageBackend {
    fn open(path: &Path) -> Result<Self, Box<dyn Error>> {
        let db_path = path.join("donadb");
        let db = donadb::DonaDb::open(donadb::DonaDbConfig {
            data_dir: db_path,
            shard_count: 256,
            compaction_threads: 4,
            block_cache_bytes: 128 * 1024 * 1024,
            write_buffer_bytes: 128 * 1024 * 1024,
        })?;
        Ok(Self { db })
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Box<dyn Error>> {
        self.db.set(DONADB_DOMAIN, key.to_vec(), value.to_vec(), 0);
        self.db.sync();
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        Ok(self.db.get(DONADB_DOMAIN, key)?.map(|v| v.to_vec()))
    }

    fn delete(&self, key: &[u8]) -> Result<(), Box<dyn Error>> {
        self.db.del(DONADB_DOMAIN, key, 0);
        self.db.sync();
        Ok(())
    }

    fn write_batch(&self, ops: Vec<KvOp>, height: u64, sync: bool) -> Result<(), Box<dyn Error>> {
        let mut batch = donadb::WriteBatch::new();
        for op in ops {
            match op {
                KvOp::Put(k, v) => batch.put(DONADB_DOMAIN, k, v),
                KvOp::Delete(k) => batch.del(DONADB_DOMAIN, k),
            }
        }
        self.db.write_batch(batch);
        if sync {
            self.db.finalize_block(height)?;
        }
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Box<dyn Error>> {
        Ok(self
            .db
            .scan_prefix_domain(DONADB_DOMAIN, prefix)?
            .into_iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect())
    }

    fn scan_from_reverse(&self, start: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Box<dyn Error>> {
        let mut rows: Vec<_> = self
            .db
            .scan_all(DONADB_DOMAIN)?
            .into_iter()
            .filter(|(k, _)| k.as_ref() <= start)
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        rows.sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
        Ok(rows)
    }

    fn compact(&self) -> Result<(), Box<dyn Error>> {
        self.db.sync();
        Ok(())
    }

    fn finalize_block(&self, height: u64) -> Result<(), Box<dyn Error>> {
        Ok(self.db.finalize_block(height)?)
    }

    fn metrics(&self) -> donadb::DonaDbMetrics {
        self.db.metrics()
    }

    fn checkpoint(&self, destination: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
        Ok(self.db.checkpoint(destination)?)
    }
}

// PeerId type alias (Dilithium pubkey)
pub type PeerId = Vec<u8>;

#[derive(Clone)]
pub struct Storage {
    backend: Arc<StorageBackend>,
    metrics: Option<Arc<truthlinked_state::metrics::Metrics>>,
    /// If true, never prune block data (archive/full node mode).
    full_node: bool,
}
impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        let path_ref = path.as_ref();
        std::fs::create_dir_all(path_ref)?;
        let backend = StorageBackend::open(path_ref)?;
        info!(
            "DonaDB storage initialized at {:?}",
            path_ref.join("donadb")
        );
        Ok(Self {
            backend: Arc::new(backend),
            metrics: None,
            full_node: false,
        })
    }

    pub fn set_full_node(&mut self, full: bool) {
        self.full_node = full;
        if full {
            tracing::info!("Storage: archive/full-node mode - no pruning");
        }
    }

    pub fn set_metrics(&mut self, metrics: Arc<truthlinked_state::metrics::Metrics>) {
        self.metrics = Some(metrics);
    }

    pub fn store(&self, key: String, value: Vec<u8>) -> Result<(), Box<dyn Error>> {
        if let Some(m) = &self.metrics {
            m.inc_storage_db_writes();
        }
        self.backend.put(key.as_bytes(), &value)?;
        Ok(())
    }

    pub fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        if let Some(m) = &self.metrics {
            m.inc_storage_db_reads();
        }
        self.backend.get(key.as_bytes())
    }

    pub fn delete(&self, key: &str) -> Result<(), Box<dyn Error>> {
        self.backend.delete(key.as_bytes())?;
        Ok(())
    }

    pub fn batch_write(
        &self,
        operations: Vec<(String, Option<Vec<u8>>)>,
    ) -> Result<(), Box<dyn Error>> {
        let ops = operations
            .into_iter()
            .map(|(key, value)| match value {
                Some(v) => KvOp::Put(key.into_bytes(), v),
                None => KvOp::Delete(key.into_bytes()),
            })
            .collect();
        self.backend.write_batch(ops, 0, true)?;
        Ok(())
    }

    /// Called once per finalized block - the single durability boundary.
    pub fn finalize_block(&self, _height: u64) -> Result<(), Box<dyn Error>> {
        self.backend.finalize_block(_height)
    }

    pub fn is_degraded(&self) -> bool {
        false
    }

    pub fn compact_wal(&self) -> Result<(), Box<dyn Error>> {
        self.backend.compact()
    }

    pub fn storage_metrics(&self) -> donadb::DonaDbMetrics {
        self.backend.metrics()
    }

    pub fn checkpoint<P: AsRef<Path>>(&self, destination: P) -> Result<(), Box<dyn Error>> {
        self.backend.checkpoint(destination)
    }

    pub fn get_latest_block_height(&self) -> u64 {
        if let Some(v) = self
            .retrieve("meta:latest_height")
            .ok()
            .flatten()
            .and_then(|v| v.try_into().ok())
            .map(u64::from_le_bytes)
        {
            if v > 0 {
                return v;
            }
        }

        let mut max = 0u64;
        for prefix in ["height:", "batch:"] {
            if let Ok(rows) = self.backend.scan_prefix(prefix.as_bytes()) {
                for (k, _) in rows {
                    if let Ok(s) = std::str::from_utf8(&k) {
                        if let Some(h) = s.strip_prefix(prefix) {
                            if let Ok(num) = h.parse::<u64>() {
                                max = max.max(num);
                            }
                        }
                    }
                }
            }
            if max > 0 {
                break;
            }
        }
        max
    }

    pub fn get_all_peers(&self) -> Result<Vec<PeerState>, Box<dyn Error>> {
        let mut peers = Vec::new();
        for (_, v) in self.backend.scan_prefix(b"peer:")? {
            if let Ok(p) = serde_json::from_slice::<PeerState>(&v) {
                peers.push(p);
            }
        }
        Ok(peers)
    }
    // Network state persistence

    /// Save peer state
    pub fn save_peer(
        &self,
        peer_id: &PeerId,
        addresses: &[String],
        is_seed: bool,
    ) -> Result<(), Box<dyn Error>> {
        let key = format!("peer:{}", hex::encode(peer_id));
        let state = PeerState {
            peer_id: hex::encode(peer_id),
            addresses: addresses.to_vec(),
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            is_seed,
        };
        let value = serde_json::to_vec(&state)?;
        self.store(key, value)?;
        Ok(())
    }

    /// Load peer state
    pub fn load_peer(&self, peer_id: &PeerId) -> Result<Option<PeerState>, Box<dyn Error>> {
        let key = format!("peer:{}", hex::encode(peer_id));
        match self.retrieve(&key)? {
            Some(data) => Ok(Some(serde_json::from_slice(&data)?)),
            None => Ok(None),
        }
    }

    /// Get all known peers
    // (implemented above via scan_prefix)

    /// Get seed nodes
    pub fn get_seed_nodes(&self) -> Result<Vec<(PeerId, Vec<String>)>, Box<dyn Error>> {
        let peers = self.get_all_peers()?;
        let seeds = peers
            .into_iter()
            .filter(|p| p.is_seed)
            .filter_map(|p| {
                // Parse peer_id from hex string
                let peer_id_bytes = hex::decode(&p.peer_id).ok()?;
                Some((peer_id_bytes, p.addresses))
            })
            .collect();
        Ok(seeds)
    }

    /// Prune old peers (older than max_age_secs)
    pub fn prune_old_peers(&self, max_age_secs: u64) -> Result<usize, Box<dyn Error>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let peers = self.get_all_peers()?;
        let mut pruned = 0;

        for peer in peers {
            if !peer.is_seed && (now - peer.last_seen) > max_age_secs {
                let key = format!("peer:{}", peer.peer_id);
                self.delete(&key)?;
                pruned += 1;
            }
        }

        if pruned > 0 {
            info!("Pruned {} old peers", pruned);
        }

        Ok(pruned)
    }
}

/// Persistent peer state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    pub peer_id: String,
    pub addresses: Vec<String>,
    pub last_seen: u64,
    pub is_seed: bool,
}

impl Storage {
    /// Save peer addresses to disk
    pub fn save_peers(&self, peers: &[PeerState]) -> Result<(), Box<dyn Error>> {
        let key = "peers:discovered";
        let value = postcard::to_allocvec(peers)?;
        self.store(key.to_string(), value)?;
        tracing::info!(" Saved {} peer addresses", peers.len());
        Ok(())
    }

    /// Load peer addresses from disk
    pub fn load_peers(&self) -> Result<Vec<PeerState>, Box<dyn Error>> {
        let key = "peers:discovered";
        match self.retrieve(key)? {
            Some(data) => {
                let peers: Vec<PeerState> = postcard::from_bytes(&data)?;
                tracing::info!(" Loaded {} peer addresses", peers.len());
                Ok(peers)
            }
            None => {
                tracing::info!(" No saved peers found");
                Ok(Vec::new())
            }
        }
    }

    /// Update peer last seen timestamp
    pub fn update_peer_seen(&self, peer_id: &str) -> Result<(), Box<dyn Error>> {
        let mut peers = self.load_peers()?;

        if let Some(peer) = peers.iter_mut().find(|p| p.peer_id == peer_id) {
            peer.last_seen = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
        }

        self.save_peers(&peers)?;
        Ok(())
    }

    /// Add or update peer
    pub fn add_peer(&self, peer_id: String, addresses: Vec<String>) -> Result<(), Box<dyn Error>> {
        let mut peers = self.load_peers()?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if let Some(peer) = peers.iter_mut().find(|p| p.peer_id == peer_id) {
            peer.addresses = addresses;
            peer.last_seen = now;
        } else {
            peers.push(PeerState {
                peer_id,
                addresses,
                last_seen: now,
                is_seed: false,
            });
        }

        self.save_peers(&peers)?;
        Ok(())
    }

    pub fn prune_stale_peers(&self) -> Result<usize, Box<dyn Error>> {
        let mut peers = self.load_peers()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let before = peers.len();
        peers.retain(|p| now - p.last_seen < 7 * 24 * 60 * 60);
        let removed = before - peers.len();

        if removed > 0 {
            self.save_peers(&peers)?;
            tracing::info!(" Pruned {} stale peers", removed);
        }

        Ok(removed)
    }

    pub fn save_batch_header(
        &self,
        header: &crate::blockchain::BatchHeader,
    ) -> Result<(), Box<dyn Error>> {
        let key = format!("header:{}", hex::encode(&header.batch_hash));
        let value = postcard::to_allocvec(header)?;
        self.store(key, value)?;

        // Also index by height for faster lookups
        let height_key = format!("height:{}", header.height);
        self.store(height_key, header.batch_hash.to_vec())?;
        self.store_anchor(header.height, &header.batch_hash)?;

        // Update latest height tracker (O(1) lookup on restart)
        self.store(
            "meta:latest_height".to_string(),
            header.height.to_le_bytes().to_vec(),
        )?;

        Ok(())
    }

    pub fn load_batch_header(
        &self,
        batch_hash: &[u8; 32],
    ) -> Result<Option<crate::blockchain::BatchHeader>, Box<dyn Error>> {
        let key = format!("header:{}", hex::encode(batch_hash));
        match self.retrieve(&key)? {
            Some(data) => {
                let header = postcard::from_bytes(&data)?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    pub fn load_batch_header_by_height(
        &self,
        height: u64,
    ) -> Result<Option<crate::blockchain::BatchHeader>, Box<dyn Error>> {
        match self.load_anchor_hash(height)? {
            Some(batch_hash) => self.load_batch_header(&batch_hash),
            None => Ok(None),
        }
    }

    pub fn store_anchor(&self, height: u64, batch_hash: &[u8; 32]) -> Result<(), Box<dyn Error>> {
        self.store(format!("anchor:{}", height), batch_hash.to_vec())?;
        self.store(format!("height:{}", height), batch_hash.to_vec())?;
        Ok(())
    }

    pub fn load_anchor_hash(&self, height: u64) -> Result<Option<[u8; 32]>, Box<dyn Error>> {
        let anchor_key = format!("anchor:{}", height);
        let height_key = format!("height:{}", height);
        let value = self
            .retrieve(&anchor_key)?
            .or_else(|| self.retrieve(&height_key).ok().flatten());
        match value {
            Some(hash_bytes) => {
                if hash_bytes.len() == 32 {
                    let mut batch_hash = [0u8; 32];
                    batch_hash.copy_from_slice(&hash_bytes);
                    Ok(Some(batch_hash))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub fn save_canonical_tip(&self, batch_hash: &[u8; 32]) -> Result<(), Box<dyn Error>> {
        self.store("canonical_tip".to_string(), batch_hash.to_vec())?;
        Ok(())
    }

    pub fn load_canonical_tip(&self) -> Result<Option<[u8; 32]>, Box<dyn Error>> {
        match self.backend.get(b"canonical_tip")? {
            Some(data) => {
                let slice: &[u8] = data.as_ref();
                let hash: [u8; 32] = slice.try_into().map_err(|_| "Invalid canonical tip")?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    // Transaction history storage
    pub fn save_transaction_history(
        &self,
        account_id: &[u8; 32],
        tx: &truthlinked_core::pq_execution::Transaction,
        tx_hash: [u8; 32],
        height: u64,
        batch_hash: &[u8; 32],
        status: &str,
    ) -> Result<(), Box<dyn Error>> {
        // Get current transaction count for this account
        let count_key = format!("tx_count:{}", hex::encode(account_id));
        let current_count = match self.retrieve(&count_key)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.try_into().map_err(|_| "Invalid count")?;
                u64::from_le_bytes(arr)
            }
            None => 0,
        };

        // Store by sequential index
        let key = format!("tx_history:{}:{}", hex::encode(account_id), current_count);

        #[derive(serde::Serialize, serde::Deserialize)]
        struct TxRecord {
            tx_hash: [u8; 32],
            sender: [u8; 32],
            intent: truthlinked_core::pq_execution::TransactionIntent,
            timestamp: u64,
            height: u64,
            batch_hash: [u8; 32],
            status: String,
        }

        let record = TxRecord {
            tx_hash,
            sender: tx.sender,
            intent: tx.intent.clone(),
            timestamp: tx.timestamp,
            height,
            batch_hash: *batch_hash,
            status: status.to_string(),
        };

        let value = postcard::to_allocvec(&record)?;
        self.store(key, value)?;

        // Increment transaction count
        let new_count = current_count + 1;
        self.store(count_key, new_count.to_le_bytes().to_vec())?;

        Ok(())
    }

    /// Optimized batch transaction indexing with compression.
    pub fn index_batch_transactions(
        &self,
        batch_height: u64,
        batch_hash: &[u8; 32],
        transactions: &[truthlinked_core::pq_execution::Transaction],
        results: &[String], // "success" or error message
        name_registry: &std::collections::HashMap<String, [u8; 32]>,
    ) -> Result<(), Box<dyn Error>> {
        let ops = self.build_batch_transaction_index_ops(
            batch_height,
            batch_hash,
            transactions,
            results,
            name_registry,
        )?;
        self.backend.write_batch(ops, batch_height, true)?;
        Ok(())
    }

    fn build_batch_transaction_index_ops(
        &self,
        batch_height: u64,
        batch_hash: &[u8; 32],
        transactions: &[truthlinked_core::pq_execution::Transaction],
        results: &[String],
        name_registry: &std::collections::HashMap<String, [u8; 32]>,
    ) -> Result<Vec<KvOp>, Box<dyn Error>> {
        let mut account_updates: std::collections::HashMap<[u8; 32], u64> =
            std::collections::HashMap::new();

        // Get current counts for all affected accounts
        let mut affected_accounts = std::collections::HashSet::new();
        for tx in transactions {
            affected_accounts.insert(tx.sender);
            // Add recipients based on transaction type
            match &tx.intent {
                truthlinked_core::pq_execution::TransactionIntent::Transfer {
                    recipient, ..
                } => {
                    affected_accounts.insert(*recipient);
                }
                truthlinked_core::pq_execution::TransactionIntent::TransferToName {
                    name, ..
                } => {
                    if let Some(account_id) = name_registry.get(name) {
                        affected_accounts.insert(*account_id);
                    }
                }
                truthlinked_core::pq_execution::TransactionIntent::BatchTransfer { transfers } => {
                    for transfer in transfers {
                        affected_accounts.insert(transfer.recipient);
                    }
                }
                truthlinked_core::pq_execution::TransactionIntent::BatchTransferToName {
                    transfers,
                } => {
                    for transfer in transfers {
                        if let Some(account_id) = name_registry.get(&transfer.name) {
                            affected_accounts.insert(*account_id);
                        }
                    }
                }
                truthlinked_core::pq_execution::TransactionIntent::TransferNFT {
                    recipient,
                    ..
                } => {
                    affected_accounts.insert(*recipient);
                }
                truthlinked_core::pq_execution::TransactionIntent::TokenTransfer {
                    recipient,
                    ..
                } => {
                    affected_accounts.insert(*recipient);
                }
                truthlinked_core::pq_execution::TransactionIntent::TokenMint {
                    recipient, ..
                } => {
                    affected_accounts.insert(*recipient);
                }
                _ => {}
            }
        }

        // Load current counts
        for account_id in &affected_accounts {
            let count_key = format!("tx_count:{}", hex::encode(account_id));
            let count = match self.retrieve(&count_key)? {
                Some(bytes) => {
                    let arr: [u8; 8] = bytes.try_into().map_err(|_| "Invalid count")?;
                    u64::from_le_bytes(arr)
                }
                None => 0,
            };
            account_updates.insert(*account_id, count);
        }

        // Compressed transaction record
        #[derive(serde::Serialize, serde::Deserialize)]
        struct CompactTxRecord {
            h: [u8; 32], // tx_hash
            s: [u8; 32], // sender
            i: u8,       // intent type (enum discriminant)
            d: Vec<u8>,  // compressed intent data
            t: u32,      // timestamp (u32 for space efficiency)
            b: [u8; 32], // batch_hash
            st: u8,      // status: 0=success, 1=error
        }

        let mut ops = Vec::new();

        // Index all transactions in batch
        for (tx_idx, (tx, status)) in transactions.iter().zip(results.iter()).enumerate() {
            let tx_hash = self.compute_tx_hash(tx);
            let (intent_type, intent_data) = self.compress_intent(&tx.intent)?;

            let record = CompactTxRecord {
                h: tx_hash,
                s: tx.sender,
                i: intent_type,
                d: intent_data,
                t: tx.timestamp as u32,
                b: *batch_hash,
                st: if status == "success" { 0 } else { 1 },
            };
            let value = postcard::to_allocvec(&record)?;

            // Index by sender
            let sender_count = account_updates
                .get_mut(&tx.sender)
                .ok_or("Missing sender tx_count")?;
            let sender_key = format!("tx_history:{}:{}", hex::encode(&tx.sender), sender_count);
            ops.push(KvOp::Put(sender_key.into_bytes(), value.clone()));
            *sender_count += 1;

            // Index by recipient if applicable
            match &tx.intent {
                truthlinked_core::pq_execution::TransactionIntent::BatchTransfer { transfers } => {
                    for transfer in transfers {
                        if let Some(recipient_count) = account_updates.get_mut(&transfer.recipient)
                        {
                            let recipient_key = format!(
                                "tx_history:{}:{}",
                                hex::encode(&transfer.recipient),
                                recipient_count
                            );
                            ops.push(KvOp::Put(recipient_key.into_bytes(), value.clone()));
                            *recipient_count += 1;
                        }
                    }
                }
                truthlinked_core::pq_execution::TransactionIntent::BatchTransferToName {
                    transfers,
                } => {
                    for transfer in transfers {
                        if let Some(recipient) = name_registry.get(&transfer.name) {
                            if let Some(recipient_count) = account_updates.get_mut(recipient) {
                                let recipient_key = format!(
                                    "tx_history:{}:{}",
                                    hex::encode(recipient),
                                    recipient_count
                                );
                                ops.push(KvOp::Put(recipient_key.into_bytes(), value.clone()));
                                *recipient_count += 1;
                            }
                        }
                    }
                }
                truthlinked_core::pq_execution::TransactionIntent::TransferToName {
                    name, ..
                } => {
                    if let Some(recipient) = name_registry.get(name) {
                        if let Some(recipient_count) = account_updates.get_mut(recipient) {
                            let recipient_key = format!(
                                "tx_history:{}:{}",
                                hex::encode(recipient),
                                recipient_count
                            );
                            ops.push(KvOp::Put(recipient_key.into_bytes(), value.clone()));
                            *recipient_count += 1;
                        }
                    }
                }
                _ => {
                    if let Some(recipient) = self.extract_recipient(&tx.intent) {
                        if let Some(recipient_count) = account_updates.get_mut(&recipient) {
                            let recipient_key = format!(
                                "tx_history:{}:{}",
                                hex::encode(&recipient),
                                recipient_count
                            );
                            ops.push(KvOp::Put(recipient_key.into_bytes(), value.clone()));
                            *recipient_count += 1;
                        }
                    }
                }
            }

            // Global index by height
            let global_key = format!("tx_by_height:{}:{}", batch_height, tx_idx);
            ops.push(KvOp::Put(global_key.into_bytes(), tx_hash.to_vec()));

            let result_key = format!("tx_result:{}:{}", batch_height, tx_idx);
            ops.push(KvOp::Put(
                result_key.into_bytes(),
                status.as_bytes().to_vec(),
            ));

            // Direct hash -> (height, idx) index for O(1) lookup
            let hash_index_key = format!("tx_hash_index:{}", hex::encode(tx_hash));
            let mut loc = [0u8; 12];
            loc[..8].copy_from_slice(&batch_height.to_le_bytes());
            loc[8..].copy_from_slice(&(tx_idx as u32).to_le_bytes());
            ops.push(KvOp::Put(hash_index_key.into_bytes(), loc.to_vec()));
        }

        // Update all counts
        for (account_id, count) in &account_updates {
            let count_key = format!("tx_count:{}", hex::encode(account_id));
            ops.push(KvOp::Put(
                count_key.into_bytes(),
                count.to_le_bytes().to_vec(),
            ));
        }

        // Batch height index
        let height_key = format!("batch_tx_count:{}", batch_height);
        ops.push(KvOp::Put(
            height_key.into_bytes(),
            (transactions.len() as u32).to_le_bytes().to_vec(),
        ));

        Ok(ops)
    }

    fn compute_tx_hash(&self, tx: &truthlinked_core::pq_execution::Transaction) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        if let Ok(bytes) = postcard::to_allocvec(tx) {
            hasher.update(&bytes);
        } else {
            hasher.update(&tx.sender);
            hasher.update(&tx.timestamp.to_le_bytes());
        }
        (*hasher.finalize().as_bytes()).into()
    }

    fn compute_tx_fee_summary(
        &self,
        tx: &truthlinked_core::pq_execution::Transaction,
    ) -> (u128, u128, u128, u128) {
        use truthlinked_core::constants::ONE_TLKD;
        use truthlinked_core::pq_execution::TransactionIntent;
        use truthlinked_governance::params as gp;

        let byte_fee = tx
            .byte_weight()
            .map(|bytes| (bytes as u128).saturating_mul(gp::get_u64(gp::PARAM_TX_BYTE_FEE) as u128))
            .unwrap_or(0);

        let (gas_fee, cu_fee): (u128, u128) = match &tx.intent {
            TransactionIntent::Transfer { .. } | TransactionIntent::TransferToName { .. } => (
                (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128).saturating_add(byte_fee),
                0,
            ),
            TransactionIntent::BatchTransfer { transfers } => (
                (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
                    .saturating_mul(transfers.len() as u128)
                    .saturating_add(byte_fee),
                0,
            ),
            TransactionIntent::BatchTransferToName { transfers } => (
                (gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
                    .saturating_mul(transfers.len() as u128)
                    .saturating_add(byte_fee),
                0,
            ),
            TransactionIntent::Claim { .. } => (0, gp::get_u64(gp::PARAM_GAS_CLAIM) as u128),
            TransactionIntent::Stake { .. } => (0, gp::get_u64(gp::PARAM_GAS_STAKE) as u128),
            TransactionIntent::Unstake { .. } => (0, gp::get_u64(gp::PARAM_GAS_UNSTAKE) as u128),
            TransactionIntent::WithdrawStake => (0, gp::get_u64(gp::PARAM_GAS_WITHDRAW) as u128),
            TransactionIntent::Unjail => (0, gp::get_u64(gp::PARAM_GAS_UNJAIL) as u128),
            TransactionIntent::RotateKey { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_ROTATE_KEY) as u128)
            }
            TransactionIntent::DepositCompute { .. }
            | TransactionIntent::WithdrawCompute { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
            }
            TransactionIntent::MintNFT { .. } => (0, gp::get_u64(gp::PARAM_GAS_MINT_NFT) as u128),
            TransactionIntent::TransferNFT { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER_NFT) as u128)
            }
            TransactionIntent::BurnNFT { .. } => (0, gp::get_u64(gp::PARAM_GAS_BURN_NFT) as u128),
            TransactionIntent::ApproveNFT { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_APPROVE_NFT) as u128)
            }
            TransactionIntent::DeployCell { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_DEPLOY_CELL) as u128)
            }
            TransactionIntent::DeployToken { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_DEPLOY_TOKEN) as u128)
            }
            TransactionIntent::UpgradeCell { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_UPGRADE_CELL) as u128)
            }
            TransactionIntent::CallCell { gas_limit, .. } => (0, *gas_limit as u128),
            TransactionIntent::CallCellChain { gas_limit, .. } => (0, *gas_limit as u128),
            TransactionIntent::TokenTransfer { .. }
            | TransactionIntent::TokenFreeze { .. }
            | TransactionIntent::TokenThaw { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TOKEN_TRANSFER) as u128)
            }
            TransactionIntent::TokenMint { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TOKEN_MINT) as u128)
            }
            TransactionIntent::TokenBurn { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TOKEN_BURN) as u128)
            }
            TransactionIntent::ProposeUrl { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
            }
            TransactionIntent::VoteUrl { .. } => (0, gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128),
            TransactionIntent::ReportMaliciousUrl { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
            }
            TransactionIntent::SubmitOracleCommit { .. }
            | TransactionIntent::SubmitOracleReveal { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
            }
            TransactionIntent::RegisterAgent { .. }
            | TransactionIntent::SuspendAgent { .. }
            | TransactionIntent::ReinstateAgent { .. }
            | TransactionIntent::RegisterMcpTool { .. }
            | TransactionIntent::RegisterMcpResource { .. }
            | TransactionIntent::RegisterMcpPrompt { .. }
            | TransactionIntent::McpToolCall { .. } => {
                (0, gp::get_u64(gp::PARAM_GAS_TRANSFER) as u128)
            }
            _ => (byte_fee, 0),
        };

        let compute_fee_tlkd = if cu_fee > 0 {
            let cu_per_tlkd = gp::get_u64(gp::PARAM_CU_PER_TLKD) as u128;
            if cu_per_tlkd == 0 {
                0
            } else {
                cu_fee
                    .saturating_mul(ONE_TLKD)
                    .saturating_add(cu_per_tlkd - 1)
                    / cu_per_tlkd
            }
        } else {
            0
        };
        let fee_paid_tlkd = gas_fee.saturating_add(compute_fee_tlkd);
        (gas_fee, cu_fee, compute_fee_tlkd, fee_paid_tlkd)
    }

    fn compress_intent(
        &self,
        intent: &truthlinked_core::pq_execution::TransactionIntent,
    ) -> Result<(u8, Vec<u8>), Box<dyn Error>> {
        use truthlinked_core::pq_execution::TransactionIntent;

        match intent {
            TransactionIntent::Transfer {
                recipient, amount, ..
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(recipient);
                data.extend_from_slice(&amount.to_le_bytes());
                Ok((1, data))
            }
            TransactionIntent::Stake { amount } => Ok((2, amount.to_le_bytes().to_vec())),
            TransactionIntent::Unstake { amount } => Ok((3, amount.to_le_bytes().to_vec())),
            TransactionIntent::TokenTransfer {
                token_cell,
                recipient,
                amount,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(token_cell);
                data.extend_from_slice(recipient);
                data.extend_from_slice(&amount.to_le_bytes());
                Ok((4, data))
            }
            _ => {
                // Fallback: serialize full intent
                Ok((255, postcard::to_allocvec(intent)?))
            }
        }
    }

    fn extract_recipient(
        &self,
        intent: &truthlinked_core::pq_execution::TransactionIntent,
    ) -> Option<[u8; 32]> {
        use truthlinked_core::pq_execution::TransactionIntent;

        match intent {
            TransactionIntent::Transfer { recipient, .. } => Some(*recipient),
            TransactionIntent::TransferNFT { recipient, .. } => Some(*recipient),
            TransactionIntent::TokenTransfer { recipient, .. } => Some(*recipient),
            TransactionIntent::TokenMint { recipient, .. } => Some(*recipient),
            TransactionIntent::PrivateBalanceWithdraw { recipient, .. } => Some(*recipient),
            _ => None,
        }
    }

    /// Fast transaction lookup by hash (O(1) via direct index)
    pub fn get_transaction_by_hash(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<serde_json::Value>, Box<dyn Error>> {
        let hash_index_key = format!("tx_hash_index:{}", hex::encode(tx_hash));
        if let Some(loc) = self.retrieve(&hash_index_key)? {
            if loc.len() == 12 {
                let height = u64::from_le_bytes(loc[..8].try_into()?);
                let tx_idx = u32::from_le_bytes(loc[8..].try_into()?) as usize;
                if let Some(tx) = self.load_transaction_details(height, tx_idx)? {
                    return Ok(Some(tx));
                }
            }
        }
        self.find_transaction_in_history(tx_hash)
    }

    fn find_transaction_in_history(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<serde_json::Value>, Box<dyn Error>> {
        #[derive(serde::Deserialize)]
        struct CompactTxRecord {
            h: [u8; 32],
            s: [u8; 32],
            i: u8,
            d: Vec<u8>,
            t: u32,
            b: [u8; 32],
            st: u8,
        }

        for (_key, value) in self.backend.scan_prefix(b"tx_history:")? {
            let Ok(record) = postcard::from_bytes::<CompactTxRecord>(&value) else {
                continue;
            };
            if &record.h != tx_hash {
                continue;
            }
            let intent_json = self.decompress_intent(record.i, &record.d)?;
            let intent_type = intent_json
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            let status = if record.st == 0 { "success" } else { "error" };
            let height = self
                .load_batch_header(&record.b)?
                .map(|header| header.height)
                .unwrap_or(0);
            let datetime = chrono::DateTime::from_timestamp(record.t as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Invalid timestamp".to_string());
            return Ok(Some(serde_json::json!({
                "tx_hash": hex::encode(record.h),
                "hash": hex::encode(record.h),
                "sender": hex::encode(record.s),
                "from": hex::encode(record.s),
                "intent": intent_json,
                "intent_type": intent_type,
                "height": height,
                "timestamp": record.t,
                "timestamp_human": datetime,
                "batch_hash": hex::encode(record.b),
                "status": status,
            })));
        }
        Ok(None)
    }

    /// Load all transactions indexed for a finalized block height.
    ///
    /// This uses the compact `tx_by_height:<height>:<idx>` index written when a
    /// block is committed. It is intentionally independent of the raw batch
    /// payload so RPC and explorer reads keep working after batch pruning.
    pub fn load_transactions_by_height(
        &self,
        height: u64,
    ) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        let prefix = format!("tx_by_height:{}:", height);
        let mut rows: Vec<(usize, [u8; 32])> = Vec::new();

        for (key, value) in self.backend.scan_prefix(prefix.as_bytes())? {
            if value.len() != 32 {
                continue;
            }
            let key_str = std::str::from_utf8(&key)?;
            let Some(idx_str) = key_str.strip_prefix(&prefix) else {
                continue;
            };
            let Ok(tx_idx) = idx_str.parse::<usize>() else {
                continue;
            };
            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(&value);
            rows.push((tx_idx, tx_hash));
        }

        rows.sort_by_key(|(tx_idx, _)| *tx_idx);

        let mut transactions = Vec::with_capacity(rows.len());
        for (tx_idx, tx_hash) in rows {
            if let Some(mut tx) = self.load_transaction_details(height, tx_idx)? {
                tx["tx_hash"] = serde_json::Value::String(hex::encode(tx_hash));
                transactions.push(tx);
            }
        }

        Ok(transactions)
    }

    /// Prefix lookup for transaction hashes (dev-friendly). Returns Err on ambiguity.
    pub fn get_transaction_by_hash_prefix(
        &self,
        prefix_hex: &str,
    ) -> Result<Option<serde_json::Value>, Box<dyn Error>> {
        if prefix_hex.len() < 8 {
            return Ok(None);
        }
        let mut match_loc: Option<Vec<u8>> = None;
        for (key, value) in self.backend.scan_prefix(b"tx_hash_index:")? {
            let key_str = std::str::from_utf8(&key)?;
            let Some(hash_hex) = key_str.strip_prefix("tx_hash_index:") else {
                continue;
            };
            if hash_hex.starts_with(prefix_hex) {
                if match_loc.is_some() {
                    return Err("Ambiguous tx hash prefix".into());
                }
                match_loc = Some(value);
            }
        }
        if let Some(loc) = match_loc {
            if loc.len() == 12 {
                let height = u64::from_le_bytes(loc[..8].try_into()?);
                let tx_idx = u32::from_le_bytes(loc[8..].try_into()?) as usize;
                return self.load_transaction_details(height, tx_idx);
            }
        }
        Ok(None)
    }

    pub fn load_transaction_history(
        &self,
        account_id: &[u8; 32],
        limit: usize,
        offset: usize,
    ) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        let count_key = format!("tx_count:{}", hex::encode(account_id));
        let count = match self.retrieve(&count_key)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.try_into().map_err(|_| "Invalid count")?;
                u64::from_le_bytes(arr)
            }
            None => return Ok(vec![]),
        };

        let mut transactions = Vec::new();
        let start = offset.min(count as usize);
        let end = (offset + limit).min(count as usize);

        for nonce in start..end {
            let key = format!("tx_history:{}:{}", hex::encode(account_id), nonce);
            if let Some(value) = self.retrieve(&key)? {
                #[derive(serde::Deserialize)]
                struct TxRecord {
                    tx_hash: [u8; 32],
                    sender: [u8; 32],
                    intent: truthlinked_core::pq_execution::TransactionIntent,
                    timestamp: u64,
                    height: u64,
                    batch_hash: [u8; 32],
                    status: String,
                }

                let record: TxRecord = postcard::from_bytes(&value)?;

                let intent_json = match &record.intent {
                    truthlinked_core::pq_execution::TransactionIntent::Transfer { recipient, recipient_pubkey, amount } => {
                        serde_json::json!({
                            "type": "Transfer",
                            "recipient_account_id": hex::encode(recipient),
                            "recipient_pubkey": hex::encode(recipient_pubkey.as_deref().unwrap_or_default()),
                            "amount": truthlinked_state::token::format_amount(*amount),
                            "amount_raw": amount.to_string(),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::BatchTransfer { transfers } => {
                        let transfers_json: Vec<serde_json::Value> = transfers
                            .iter()
                            .map(|t| {
                                serde_json::json!({
                                    "recipient_account_id": hex::encode(t.recipient),
                                    "recipient_pubkey": hex::encode(t.recipient_pubkey.as_deref().unwrap_or_default()),
                                    "amount": truthlinked_state::token::format_amount(t.amount),
                                    "amount_raw": t.amount.to_string(),
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "type": "BatchTransfer",
                            "transfers": transfers_json,
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::TransferToName { name, amount } => {
                        serde_json::json!({
                            "type": "TransferToName",
                            "name": name,
                            "amount": truthlinked_state::token::format_amount(*amount),
                            "amount_raw": amount.to_string(),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::DepositCompute { amount } => {
                        serde_json::json!({
                            "type": "DepositCompute",
                            "amount": truthlinked_state::token::format_amount(*amount),
                            "amount_raw": amount.to_string(),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::WithdrawCompute { amount } => {
                        serde_json::json!({
                            "type": "WithdrawCompute",
                            "amount": truthlinked_state::token::format_amount(*amount),
                            "amount_raw": amount.to_string(),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::BatchTransferToName { transfers } => {
                        let transfers_json: Vec<serde_json::Value> = transfers
                            .iter()
                            .map(|t| {
                                serde_json::json!({
                                    "name": t.name,
                                    "amount": truthlinked_state::token::format_amount(t.amount),
                                    "amount_raw": t.amount.to_string(),
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "type": "BatchTransferToName",
                            "transfers": transfers_json,
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::Claim { recipient, recipient_pubkey, amount } => {
                        serde_json::json!({
                            "type": "Claim",
                            "recipient_account_id": hex::encode(recipient),
                            "recipient_pubkey": hex::encode(recipient_pubkey.as_deref().unwrap_or_default()),
                            "amount": truthlinked_state::token::format_amount(*amount),
                            "amount_raw": amount.to_string(),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::RotateKey { new_pubkey } => {
                        serde_json::json!({
                            "type": "RotateKey",
                            "new_pubkey": hex::encode(new_pubkey),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::Stake { amount } => {
                        serde_json::json!({
                            "type": "Stake",
                            "amount": truthlinked_state::token::format_amount(*amount),
                            "amount_raw": amount.to_string(),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::Unstake { amount } => {
                        serde_json::json!({
                            "type": "Unstake",
                            "amount": truthlinked_state::token::format_amount(*amount),
                            "amount_raw": amount.to_string(),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::WithdrawStake => {
                        serde_json::json!({
                            "type": "WithdrawStake",
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::Unjail => {
                        serde_json::json!({
                            "type": "Unjail",
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::MintNFT { nft_id, name, metadata_uri, collection, royalty_bps, royalty_recipient } => {
                        serde_json::json!({
                            "type": "MintNFT",
                            "nft_id": hex::encode(nft_id),
                            "name": name,
                            "metadata_uri": metadata_uri,
                            "collection": collection.map(|c| hex::encode(c)),
                            "royalty_bps": royalty_bps,
                            "royalty_recipient": royalty_recipient.map(|r| hex::encode(r)),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::TransferNFT { nft_id, recipient, recipient_pubkey, sale_price } => {
                        serde_json::json!({
                            "type": "TransferNFT",
                            "nft_id": hex::encode(nft_id),
                            "recipient_account_id": hex::encode(recipient),
                            "recipient_pubkey": hex::encode(recipient_pubkey.as_deref().unwrap_or_default()),
                            "sale_price": sale_price.map(|p| truthlinked_state::token::format_amount(p)),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::BurnNFT { nft_id } => {
                        serde_json::json!({
                            "type": "BurnNFT",
                            "nft_id": hex::encode(nft_id),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::ApproveNFT { nft_id, approved } => {
                        serde_json::json!({
                            "type": "ApproveNFT",
                            "nft_id": hex::encode(nft_id),
                            "approved": approved.map(|a| hex::encode(a)),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::DeployCell { cell_id, .. } => {
                        serde_json::json!({
                            "type": "DeployCell",
                            "cell_id": hex::encode(cell_id),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::DeployToken { cell_id, name, symbol, .. } => {
                        serde_json::json!({
                            "type": "DeployToken",
                            "cell_id": hex::encode(cell_id),
                            "name": name,
                            "symbol": symbol,
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::CallCell { cell_id, calldata, .. } => {
                        let selector = calldata.get(0..4).map(hex::encode);
                        let call_kind = Self::call_kind_for(cell_id, calldata);
                        serde_json::json!({
                            "type": "CallCell",
                            "kind": call_kind.unwrap_or("CallCell"),
                            "cell_id": hex::encode(cell_id),
                            "selector": selector,
                            "call_kind": call_kind,
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::CallCellChain { calls, .. } => {
                        let calls_json: Vec<serde_json::Value> = calls
                            .iter()
                            .map(|call| {
                                let selector = call.calldata.get(0..4).map(hex::encode);
                                let call_kind = Self::call_kind_for(&call.cell_id, &call.calldata);
                                serde_json::json!({
                                    "cell_id": hex::encode(call.cell_id),
                                    "selector": selector,
                                    "call_kind": call_kind,
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "type": "CallCellChain",
                            "kind": "CallCellChain",
                            "num_calls": calls.len(),
                            "calls": calls_json,
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::UpgradeCell { cell_id, .. } => {
                        serde_json::json!({
                            "type": "UpgradeCell",
                            "cell_id": hex::encode(cell_id),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::TokenTransfer { token_cell, recipient, amount } => {
                        serde_json::json!({
                            "type": "TokenTransfer",
                            "token": hex::encode(token_cell),
                            "recipient": hex::encode(recipient),
                            "amount": amount.to_string(),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::TokenMint { token_cell, recipient, amount } => {
                        serde_json::json!({
                            "type": "TokenMint",
                            "token": hex::encode(token_cell),
                            "recipient": hex::encode(recipient),
                            "amount": amount.to_string(),
                        })
                    }
            truthlinked_core::pq_execution::TransactionIntent::TokenBurn { token_cell, amount } => {
                serde_json::json!({
                    "type": "TokenBurn",
                    "token": hex::encode(token_cell),
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::CloseCell { cell_id } => {
                serde_json::json!({
                    "type": "CloseCell",
                    "cell_id": hex::encode(cell_id),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ProposeCellUpgrade { cell_id, timelock_blocks, .. } => {
                serde_json::json!({
                    "type": "ProposeCellUpgrade",
                    "cell_id": hex::encode(cell_id),
                    "timelock_blocks": timelock_blocks,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ProposeCellOwnershipTransfer { cell_id, new_owner, timelock_blocks } => {
                serde_json::json!({
                    "type": "ProposeCellOwnershipTransfer",
                    "cell_id": hex::encode(cell_id),
                    "new_owner": hex::encode(new_owner),
                    "timelock_blocks": timelock_blocks,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ProposeCellMakeImmutable { cell_id, timelock_blocks } => {
                serde_json::json!({
                    "type": "ProposeCellMakeImmutable",
                    "cell_id": hex::encode(cell_id),
                    "timelock_blocks": timelock_blocks,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::VoteCellProposal { cell_id, approve } => {
                serde_json::json!({
                    "type": "VoteCellProposal",
                    "cell_id": hex::encode(cell_id),
                    "approve": approve,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ExecuteCellProposal { cell_id } => {
                serde_json::json!({
                    "type": "ExecuteCellProposal",
                    "cell_id": hex::encode(cell_id),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::TokenFreeze { token_cell, account } => {
                serde_json::json!({
                            "type": "TokenFreeze",
                            "token": hex::encode(token_cell),
                            "account": hex::encode(account),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::TokenThaw { token_cell, account } => {
                        serde_json::json!({
                            "type": "TokenThaw",
                            "token": hex::encode(token_cell),
                            "account": hex::encode(account),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::ProposeTokenAuthority { token_cell, .. } => {
                        serde_json::json!({
                            "type": "ProposeTokenAuthority",
                            "token": hex::encode(token_cell),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::VoteTokenAuthority { token_cell, approve } => {
                        serde_json::json!({
                            "type": "VoteTokenAuthority",
                            "token": hex::encode(token_cell),
                            "approve": approve,
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::CallSystem { controller, .. } => {
                        serde_json::json!({
                            "type": "CallSystem",
                            "controller": hex::encode(controller),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::ProposeUrl { url_pattern, bond_amount, voting_period_blocks } => {
                        serde_json::json!({
                            "type": "ProposeUrl",
                            "url_pattern": url_pattern,
                            "bond_amount": bond_amount.to_string(),
                            "voting_period_blocks": voting_period_blocks,
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::VoteUrl { url_pattern, approve } => {
                        serde_json::json!({
                            "type": "VoteUrl",
                            "url_pattern": url_pattern,
                            "approve": approve,
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::ReportMaliciousUrl { url_pattern, evidence } => {
                        serde_json::json!({
                            "type": "ReportMaliciousUrl",
                            "url_pattern": url_pattern,
                            "evidence": evidence,
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::TransferOwnership { cell_id, new_owner } => {
                        serde_json::json!({
                            "type": "TransferOwnership",
                            "cell_id": hex::encode(cell_id),
                            "new_owner": hex::encode(new_owner),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::AcceptOwnership { cell_id } => {
                        serde_json::json!({
                            "type": "AcceptOwnership",
                            "cell_id": hex::encode(cell_id),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::MakeImmutable { cell_id } => {
                        serde_json::json!({
                            "type": "MakeImmutable",
                            "cell_id": hex::encode(cell_id),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::RegisterMcpTool { tool_id: cell_id, name, .. } => {
                        serde_json::json!({ "type": "RegisterMcpTool", "cell_id": hex::encode(cell_id), "name": name })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::RegisterMcpResource { resource_id: cell_id, name, .. } => {
                        serde_json::json!({ "type": "RegisterMcpResource", "cell_id": hex::encode(cell_id), "name": name })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::RegisterMcpPrompt { prompt_id: cell_id, name, .. } => {
                        serde_json::json!({ "type": "RegisterMcpPrompt", "cell_id": hex::encode(cell_id), "name": name })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::RegisterAgent { agent_id, policy_cell_id, .. } => {
                        serde_json::json!({ "type": "RegisterAgent", "agent_id": hex::encode(agent_id), "policy": hex::encode(policy_cell_id) })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::SuspendAgent { agent_id, reason, .. } => {
                        serde_json::json!({ "type": "SuspendAgent", "agent_id": hex::encode(agent_id), "reason": reason })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::ReinstateAgent { agent_id, .. } => {
                        serde_json::json!({ "type": "ReinstateAgent", "agent_id": hex::encode(agent_id) })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::McpToolCall { agent_id, tool_id, .. } => {
                        serde_json::json!({ "type": "McpToolCall", "agent_id": hex::encode(agent_id), "tool_id": hex::encode(tool_id) })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::PrivateBalanceInit { cell_id, agent_id, .. } => {
                        serde_json::json!({ "type": "PrivateBalanceInit", "cell_id": hex::encode(cell_id), "agent_id": hex::encode(agent_id) })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::PrivateBalanceDeposit { cell_id, agent_id, amount, .. } => {
                        serde_json::json!({ "type": "PrivateBalanceDeposit", "cell_id": hex::encode(cell_id), "agent_id": hex::encode(agent_id), "amount": amount.to_string() })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::PrivateBalanceWithdraw { cell_id, agent_id, recipient, amount, .. } => {
                        serde_json::json!({ "type": "PrivateBalanceWithdraw", "cell_id": hex::encode(cell_id), "agent_id": hex::encode(agent_id), "recipient": hex::encode(recipient), "amount": amount.to_string() })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::PrivateBalanceConfidentialTransfer { sender_cell_id, sender_agent_id, recipient_cell_id, amount_commitment, stark_proof, .. } => {
                        serde_json::json!({
                            "type": "PrivateBalanceConfidentialTransfer",
                            "sender_cell_id": hex::encode(sender_cell_id),
                            "sender_agent_id": hex::encode(sender_agent_id),
                            "recipient_cell_id": hex::encode(recipient_cell_id),
                            "amount_commitment": hex::encode(amount_commitment),
                            "stark_proof": {
                                "len": stark_proof.len(),
                                "hash": hex::encode(blake3::hash(stark_proof).as_bytes()),
                            },
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::SetCellVisibility { cell_id, visibility } => {
                        serde_json::json!({ "type": "SetCellVisibility", "cell_id": hex::encode(cell_id), "visibility": visibility })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::SubmitOracleCommit { request_id, commit_hash } => {
                        serde_json::json!({
                            "type": "SubmitOracleCommit",
                            "request_id": hex::encode(request_id),
                            "commit_hash": hex::encode(commit_hash),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::SubmitOracleReveal { request_id, response_status, response_body } => {
                        serde_json::json!({
                            "type": "SubmitOracleReveal",
                            "request_id": hex::encode(request_id),
                            "response_status": response_status,
                            "response_body_len": response_body.len(),
                        })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::WrapTLKD { amount } => {
                        serde_json::json!({ "type": "WrapTLKD", "amount": amount.to_string() })
                    }
                    truthlinked_core::pq_execution::TransactionIntent::UnwrapTLKD { amount } => {
                        serde_json::json!({ "type": "UnwrapTLKD", "amount": amount.to_string() })
                    }
                };

                let datetime = chrono::DateTime::from_timestamp(record.timestamp as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Invalid timestamp".to_string());

                let tx_json = serde_json::json!({
                    "tx_hash": hex::encode(record.tx_hash),
                    "sender": hex::encode(record.sender),
                    "intent": intent_json,
                    "timestamp": record.timestamp,
                    "timestamp_human": datetime,
                    "height": record.height,
                    "batch_hash": hex::encode(record.batch_hash),
                    "status": record.status,
                });

                transactions.push(tx_json);
            }
        }

        Ok(transactions)
    }

    /// Optimized transaction history loading with decompression
    /// Load recent unique user transactions from compact account history indexes.
    ///
    /// Finalized transactions are written into sender and recipient histories.
    /// This method scans those compact records, de-duplicates by transaction hash,
    /// and sorts by timestamp so RPC consumers can render a global latest feed
    /// even when old raw batch payloads have been pruned.
    pub fn load_recent_transactions(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<serde_json::Value>, u64), Box<dyn Error>> {
        #[derive(serde::Deserialize)]
        struct CompactTxRecord {
            h: [u8; 32],
            s: [u8; 32],
            i: u8,
            d: Vec<u8>,
            t: u32,
            b: [u8; 32],
            st: u8,
        }

        let mut unique = std::collections::HashMap::<[u8; 32], serde_json::Value>::new();
        for (_key, value) in self.backend.scan_prefix(b"tx_history:")? {
            let Ok(record) = postcard::from_bytes::<CompactTxRecord>(&value) else {
                continue;
            };
            if unique.contains_key(&record.h) {
                continue;
            }
            let intent_json = self.decompress_intent(record.i, &record.d)?;
            let intent_type = intent_json
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            let status = if record.st == 0 { "success" } else { "error" };
            let height = self
                .load_batch_header(&record.b)?
                .map(|header| header.height)
                .unwrap_or(0);
            let datetime = chrono::DateTime::from_timestamp(record.t as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Invalid timestamp".to_string());
            unique.insert(
                record.h,
                serde_json::json!({
                    "tx_hash": hex::encode(record.h),
                    "sender": hex::encode(record.s),
                    "from": hex::encode(record.s),
                    "intent": intent_json,
                    "intent_type": intent_type,
                    "height": height,
                    "timestamp": record.t,
                    "timestamp_human": datetime,
                    "batch_hash": hex::encode(record.b),
                    "status": status,
                }),
            );
        }

        let mut transactions: Vec<_> = unique.into_values().collect();
        transactions.sort_by(|a, b| {
            b.get("timestamp")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .cmp(&a.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0))
        });
        let total = transactions.len() as u64;
        let start = offset.min(transactions.len());
        let end = (start + limit).min(transactions.len());
        Ok((transactions[start..end].to_vec(), total))
    }

    pub fn load_optimized_transaction_history(
        &self,
        account_id: &[u8; 32],
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<serde_json::Value>, u64), Box<dyn Error>> {
        let count_key = format!("tx_count:{}", hex::encode(account_id));
        let count = match self.retrieve(&count_key)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.try_into().map_err(|_| "Invalid count")?;
                u64::from_le_bytes(arr)
            }
            None => return Ok((vec![], 0)),
        };

        let mut transactions = Vec::new();
        let start = offset.min(count as usize);
        let end = (offset + limit).min(count as usize);

        #[derive(serde::Deserialize)]
        struct CompactTxRecord {
            h: [u8; 32], // tx_hash
            s: [u8; 32], // sender
            i: u8,       // intent type
            d: Vec<u8>,  // compressed intent data
            t: u32,      // timestamp
            b: [u8; 32], // batch_hash
            st: u8,      // status
        }

        for nonce in start..end {
            let key = format!("tx_history:{}:{}", hex::encode(account_id), nonce);
            if let Some(value) = self.retrieve(&key)? {
                let record: CompactTxRecord = postcard::from_bytes(&value)?;

                let intent_json = self.decompress_intent(record.i, &record.d)?;
                let status = if record.st == 0 { "success" } else { "error" };

                let datetime = chrono::DateTime::from_timestamp(record.t as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Invalid timestamp".to_string());

                let tx_json = serde_json::json!({
                    "tx_hash": hex::encode(record.h),
                    "sender": hex::encode(record.s),
                    "intent": intent_json,
                    "timestamp": record.t,
                    "timestamp_human": datetime,
                    "batch_hash": hex::encode(record.b),
                    "status": status,
                });

                transactions.push(tx_json);
            }
        }

        Ok((transactions, count))
    }

    fn decompress_intent(
        &self,
        intent_type: u8,
        data: &[u8],
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        match intent_type {
            1 => {
                // Transfer
                if data.len() >= 48 {
                    let recipient = &data[0..32];
                    let amount = u128::from_le_bytes(data[32..48].try_into()?);
                    Ok(serde_json::json!({
                        "type": "Transfer",
                        "recipient": hex::encode(recipient),
                        "amount": truthlinked_state::token::format_amount(amount),
                    }))
                } else {
                    Err("Invalid transfer data".into())
                }
            }
            2 => {
                // Stake
                if data.len() >= 16 {
                    let amount = u128::from_le_bytes(data[0..16].try_into()?);
                    Ok(serde_json::json!({
                        "type": "Stake",
                        "amount": truthlinked_state::token::format_amount(amount),
                    }))
                } else {
                    Err("Invalid stake data".into())
                }
            }
            4 => {
                // TokenTransfer
                if data.len() >= 80 {
                    let token = &data[0..32];
                    let recipient = &data[32..64];
                    let amount = u128::from_le_bytes(data[64..80].try_into()?);
                    Ok(serde_json::json!({
                        "type": "TokenTransfer",
                        "token": hex::encode(token),
                        "recipient": hex::encode(recipient),
                        "amount": amount.to_string(),
                    }))
                } else {
                    Err("Invalid token transfer data".into())
                }
            }
            255 => {
                // Fallback: full serialization
                let intent: truthlinked_core::pq_execution::TransactionIntent =
                    postcard::from_bytes(data)?;
                Ok(serde_json::json!({ "type": "Complex", "data": format!("{:?}", intent) }))
            }
            _ => Ok(serde_json::json!({ "type": "Unknown" })),
        }
    }

    fn load_transaction_details(
        &self,
        height: u64,
        tx_idx: usize,
    ) -> Result<Option<serde_json::Value>, Box<dyn Error>> {
        if let Some(batch) = self.load_batch(height)? {
            if tx_idx < batch.len() {
                let tx = &batch[tx_idx];
                let tx_hash = self.compute_tx_hash(tx);

                let result_key = format!("tx_result:{}:{}", height, tx_idx);
                let result = self
                    .retrieve(&result_key)?
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .unwrap_or_else(|| "success".to_string());
                let is_success = result == "success";
                let (gas_fee, cu_fee, compute_fee_tlkd, fee_paid_tlkd) = if is_success {
                    self.compute_tx_fee_summary(tx)
                } else {
                    (0, 0, 0, 0)
                };
                let mut tx_json = serde_json::json!({
                    "tx_hash": hex::encode(tx_hash),
                    "sender": hex::encode(tx.sender),
                    "timestamp": tx.timestamp,
                    "height": height,
                    "status": if is_success { "confirmed" } else { "error" },
                    "success": is_success,
                    "error": if is_success { serde_json::Value::Null } else { serde_json::Value::String(result) },
                    "intent": self.serialize_intent_json(&tx.intent),
                    "gas_fee": gas_fee.to_string(),
                    "fee_paid_tlkd": fee_paid_tlkd.to_string(),
                });
                if let Some(events) = self.staking_events_from_intent(&tx.intent) {
                    tx_json["events"] = serde_json::Value::Array(events);
                }

                return Ok(Some(tx_json));
            }
        }
        Ok(None)
    }

    fn selector_of(name: &str) -> [u8; 4] {
        let mut hash: u32 = 0x811c9dc5;
        for byte in name.as_bytes() {
            hash ^= *byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
        hash.to_le_bytes()
    }

    fn selector_matches(selector: &[u8; 4], name: &str) -> bool {
        selector == &Self::selector_of(name)
    }

    fn call_kind_for(cell_id: &[u8; 32], calldata: &[u8]) -> Option<&'static str> {
        if *cell_id == truthlinked_core::pq_execution::staking_system_cell_id() {
            let selector: [u8; 4] = calldata.get(0..4)?.try_into().ok()?;
            if Self::selector_matches(&selector, "stake") {
                return Some("Stake");
            }
            if Self::selector_matches(&selector, "unstake") {
                return Some("Unstake");
            }
            if Self::selector_matches(&selector, "withdraw") {
                return Some("Withdraw");
            }
            if Self::selector_matches(&selector, "unjail") {
                return Some("Unjail");
            }
            if Self::selector_matches(&selector, "delegate_add") {
                return Some("DelegateAdd");
            }
            if Self::selector_matches(&selector, "delegate_remove") {
                return Some("DelegateRemove");
            }
            if Self::selector_matches(&selector, "stake_for") {
                return Some("StakeFor");
            }
            if Self::selector_matches(&selector, "unstake_for") {
                return Some("UnstakeFor");
            }
            if Self::selector_matches(&selector, "withdraw_for") {
                return Some("WithdrawFor");
            }
            if Self::selector_matches(&selector, "unjail_for") {
                return Some("UnjailFor");
            }
            return None;
        }
        if *cell_id == truthlinked_core::pq_execution::staking_system_cell_id() {
            let selector: [u8; 4] = calldata.get(0..4)?.try_into().ok()?;
            if Self::selector_matches(&selector, "lock") {
                return Some("VeLock");
            }
            if Self::selector_matches(&selector, "unlock") {
                return Some("VeUnlock");
            }
            if Self::selector_matches(&selector, "extend") {
                return Some("VeExtend");
            }
            return None;
        }
        if *cell_id == truthlinked_core::pq_execution::treasury_system_cell_id() {
            let selector: [u8; 4] = calldata.get(0..4)?.try_into().ok()?;
            if Self::selector_matches(&selector, "propose_spend") {
                return Some("TreasuryProposeSpend");
            }
            if Self::selector_matches(&selector, "vote_spend") {
                return Some("TreasuryVoteSpend");
            }
            if Self::selector_matches(&selector, "execute_spend") {
                return Some("TreasuryExecuteSpend");
            }
            return None;
        }
        if *cell_id == truthlinked_core::pq_execution::governance_system_cell_id() {
            let selector: [u8; 4] = calldata.get(0..4)?.try_into().ok()?;
            if Self::selector_matches(&selector, "propose_param") {
                return Some("GovernanceProposeParam");
            }
            if Self::selector_matches(&selector, "vote_param") {
                return Some("GovernanceVoteParam");
            }
            if Self::selector_matches(&selector, "execute_param") {
                return Some("GovernanceExecuteParam");
            }
            if Self::selector_matches(&selector, "get_param") {
                return Some("GovernanceGetParam");
            }
            return None;
        }
        if *cell_id == truthlinked_core::pq_execution::name_registry_system_cell_id() {
            let selector: [u8; 4] = calldata.get(0..4)?.try_into().ok()?;
            if Self::selector_matches(&selector, "propose_name") {
                return Some("NamePropose");
            }
            if Self::selector_matches(&selector, "vote_name") {
                return Some("NameVote");
            }
            if Self::selector_matches(&selector, "renew_name") {
                return Some("NameRenew");
            }
            if Self::selector_matches(&selector, "transfer_name") {
                return Some("NameTransfer");
            }
            return None;
        }
        if *cell_id == truthlinked_core::pq_execution::token_governance_system_cell_id() {
            let selector: [u8; 4] = calldata.get(0..4)?.try_into().ok()?;
            if Self::selector_matches(&selector, "propose_authority") {
                return Some("TokenProposeAuthority");
            }
            if Self::selector_matches(&selector, "vote_authority") {
                return Some("TokenVoteAuthority");
            }
            return None;
        }
        if *cell_id == truthlinked_core::pq_execution::oracle_governance_system_cell_id() {
            let selector: [u8; 4] = calldata.get(0..4)?.try_into().ok()?;
            if Self::selector_matches(&selector, "propose_url") {
                return Some("OracleProposeUrl");
            }
            if Self::selector_matches(&selector, "vote_url") {
                return Some("OracleVoteUrl");
            }
            if Self::selector_matches(&selector, "report_malicious") {
                return Some("OracleReportMalicious");
            }
            if Self::selector_matches(&selector, "propose_schema") {
                return Some("OracleProposeSchema");
            }
            if Self::selector_matches(&selector, "vote_schema") {
                return Some("OracleVoteSchema");
            }
            return None;
        }
        if *cell_id == truthlinked_core::pq_execution::usdc_system_cell_id() {
            let selector: [u8; 4] = calldata.get(0..4)?.try_into().ok()?;
            if Self::selector_matches(&selector, "init") {
                return Some("USDCInit");
            }
            if Self::selector_matches(&selector, "set_authorities") {
                return Some("USDCSetAuthorities");
            }
            if Self::selector_matches(&selector, "token_cell") {
                return Some("USDCTokenCell");
            }
            if Self::selector_matches(&selector, "transfer") {
                return Some("USDCTransfer");
            }
            if Self::selector_matches(&selector, "transfer_from") {
                return Some("USDCTransferFrom");
            }
            if Self::selector_matches(&selector, "balance_of") {
                return Some("USDCBalanceOf");
            }
            if Self::selector_matches(&selector, "mint") {
                return Some("USDCMint");
            }
            if Self::selector_matches(&selector, "burn") {
                return Some("USDCBurn");
            }
            if Self::selector_matches(&selector, "freeze") {
                return Some("USDCFreeze");
            }
            if Self::selector_matches(&selector, "thaw") {
                return Some("USDCThaw");
            }
            if Self::selector_matches(&selector, "buy_cu") {
                return Some("BuyCU");
            }
            if Self::selector_matches(&selector, "name") {
                return Some("USDCName");
            }
            if Self::selector_matches(&selector, "symbol") {
                return Some("USDCSymbol");
            }
            if Self::selector_matches(&selector, "decimals") {
                return Some("USDCDecimals");
            }
            return None;
        }
        if *cell_id == truthlinked_core::pq_execution::usdt_system_cell_id() {
            let selector: [u8; 4] = calldata.get(0..4)?.try_into().ok()?;
            if Self::selector_matches(&selector, "init") {
                return Some("USDTInit");
            }
            if Self::selector_matches(&selector, "set_authorities") {
                return Some("USDTSetAuthorities");
            }
            if Self::selector_matches(&selector, "token_cell") {
                return Some("USDTTokenCell");
            }
            if Self::selector_matches(&selector, "transfer") {
                return Some("USDTTransfer");
            }
            if Self::selector_matches(&selector, "transfer_from") {
                return Some("USDTTransferFrom");
            }
            if Self::selector_matches(&selector, "balance_of") {
                return Some("USDTBalanceOf");
            }
            if Self::selector_matches(&selector, "mint") {
                return Some("USDTMint");
            }
            if Self::selector_matches(&selector, "burn") {
                return Some("USDTBurn");
            }
            if Self::selector_matches(&selector, "freeze") {
                return Some("USDTFreeze");
            }
            if Self::selector_matches(&selector, "thaw") {
                return Some("USDTThaw");
            }
            if Self::selector_matches(&selector, "name") {
                return Some("USDTName");
            }
            if Self::selector_matches(&selector, "symbol") {
                return Some("USDTSymbol");
            }
            if Self::selector_matches(&selector, "decimals") {
                return Some("USDTDecimals");
            }
            return None;
        }
        let mcp_policy_id =
            truthlinked_core::pq_execution::system_cell_id("truthlinked-mcp-policy-v1");
        if *cell_id == mcp_policy_id {
            match calldata.len() {
                120 => return Some("McpPolicyCheck"),
                65 => return Some("McpSetToolPermission"),
                88 => return Some("McpSetPolicy"),
                64 => return Some("McpTransferOwner"),
                _ => return None,
            }
        }
        None
    }

    fn ensure_kind(value: &mut serde_json::Value) {
        if let serde_json::Value::Object(map) = value {
            if map.contains_key("kind") {
                return;
            }
            if let Some(kind) = map.get("type").and_then(|val| val.as_str()) {
                map.insert(
                    "kind".to_string(),
                    serde_json::Value::String(kind.to_string()),
                );
            }
        }
    }

    fn serialize_intent_json(
        &self,
        intent: &truthlinked_core::pq_execution::TransactionIntent,
    ) -> serde_json::Value {
        fn hex_keys(keys: &[[u8; 32]]) -> Vec<String> {
            keys.iter().map(|k| hex::encode(k)).collect()
        }
        fn hash_and_len(bytes: &[u8]) -> serde_json::Value {
            let mut hasher = blake3::Hasher::new();
            hasher.update(bytes);
            let hash: [u8; 32] = hasher.finalize().into();
            serde_json::json!({
                "len": bytes.len(),
                "hash": hex::encode(hash),
            })
        }
        let mut value = match intent {
            truthlinked_core::pq_execution::TransactionIntent::Transfer {
                recipient,
                amount,
                ..
            } => {
                serde_json::json!({
                    "type": "Transfer",
                    "recipient": hex::encode(recipient),
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::TransferToName { name, amount } => {
                serde_json::json!({
                    "type": "TransferToName",
                    "name": name,
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::BatchTransfer { transfers } => {
                let transfers_json: Vec<serde_json::Value> = transfers
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "recipient": hex::encode(t.recipient),
                            "amount": t.amount.to_string(),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "type": "BatchTransfer",
                    "transfers": transfers_json,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::BatchTransferToName {
                transfers,
            } => {
                let transfers_json: Vec<serde_json::Value> = transfers
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "name": t.name,
                            "amount": t.amount.to_string(),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "type": "BatchTransferToName",
                    "transfers": transfers_json,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::Claim {
                recipient, amount, ..
            } => {
                serde_json::json!({
                    "type": "Claim",
                    "recipient": hex::encode(recipient),
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::RotateKey { new_pubkey } => {
                serde_json::json!({
                    "type": "RotateKey",
                    "new_pubkey": hex::encode(new_pubkey),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::DepositCompute { amount } => {
                serde_json::json!({
                    "type": "DepositCompute",
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::WithdrawCompute { amount } => {
                serde_json::json!({
                    "type": "WithdrawCompute",
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::Stake { amount } => {
                serde_json::json!({
                    "type": "Stake",
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::Unstake { amount } => {
                serde_json::json!({
                    "type": "Unstake",
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::WithdrawStake => {
                serde_json::json!({ "type": "WithdrawStake" })
            }
            truthlinked_core::pq_execution::TransactionIntent::Unjail => {
                serde_json::json!({ "type": "Unjail" })
            }
            truthlinked_core::pq_execution::TransactionIntent::MintNFT {
                nft_id,
                name,
                metadata_uri,
                collection,
                royalty_bps,
                royalty_recipient,
            } => {
                serde_json::json!({
                    "type": "MintNFT",
                    "nft_id": hex::encode(nft_id),
                    "name": name,
                    "metadata_uri": metadata_uri,
                    "collection": collection.as_ref().map(hex::encode),
                    "royalty_bps": royalty_bps,
                    "royalty_recipient": royalty_recipient.as_ref().map(hex::encode),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::TransferNFT {
                nft_id,
                recipient,
                sale_price,
                ..
            } => {
                serde_json::json!({
                    "type": "TransferNFT",
                    "nft_id": hex::encode(nft_id),
                    "recipient": hex::encode(recipient),
                    "sale_price": sale_price.as_ref().map(|v| v.to_string()),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::BurnNFT { nft_id } => {
                serde_json::json!({
                    "type": "BurnNFT",
                    "nft_id": hex::encode(nft_id),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ApproveNFT { nft_id, approved } => {
                serde_json::json!({
                    "type": "ApproveNFT",
                    "nft_id": hex::encode(nft_id),
                    "approved": approved.as_ref().map(hex::encode),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::DeployCell {
                cell_id,
                bytecode,
                initial_balance,
                declared_reads,
                declared_writes,
                commutative_keys,
                storage_key_specs,
                oracle_schema_ids,
            } => {
                serde_json::json!({
                    "type": "DeployCell",
                    "cell_id": hex::encode(cell_id),
                    "initial_balance": initial_balance.to_string(),
                    "bytecode": hash_and_len(bytecode),
                    "declared_reads": hex_keys(declared_reads),
                    "declared_writes": hex_keys(declared_writes),
                    "commutative_keys": hex_keys(commutative_keys),
                    "storage_key_specs": storage_key_specs.iter().map(|s| serde_json::json!({
                        "offset": s.offset,
                        "len": s.len,
                    })).collect::<Vec<_>>(),
                    "oracle_schema_ids": hex_keys(oracle_schema_ids),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::DeployToken {
                cell_id,
                name,
                symbol,
                decimals,
                total_supply,
                transfer_fee_bps,
                transfer_fee_recipient,
                non_transferable,
            } => {
                serde_json::json!({
                    "type": "DeployToken",
                    "cell_id": hex::encode(cell_id),
                    "name": name,
                    "symbol": symbol,
                    "decimals": decimals,
                    "total_supply": total_supply.to_string(),
                    "transfer_fee_bps": transfer_fee_bps,
                    "transfer_fee_recipient": transfer_fee_recipient.as_ref().map(hex::encode),
                    "non_transferable": non_transferable,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::CallCell {
                cell_id,
                calldata,
                value,
                gas_limit,
            } => {
                serde_json::json!({
                    "type": "CallCell",
                    "cell_id": hex::encode(cell_id),
                    "value": value.to_string(),
                    "gas_limit": gas_limit,
                    "calldata": hash_and_len(calldata),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::CallCellChain {
                calls,
                gas_limit,
            } => {
                let calls_json = calls
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "cell_id": hex::encode(c.cell_id),
                            "value": c.value.to_string(),
                            "use_result_from": c.use_result_from,
                            "calldata": hash_and_len(&c.calldata),
                        })
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({
                    "type": "CallCellChain",
                    "gas_limit": gas_limit,
                    "calls": calls_json,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::UpgradeCell {
                cell_id,
                new_bytecode,
                new_declared_reads,
                new_declared_writes,
                new_commutative_keys,
                new_storage_key_specs,
                new_oracle_schema_ids,
            } => {
                serde_json::json!({
                    "type": "UpgradeCell",
                    "cell_id": hex::encode(cell_id),
                    "bytecode": hash_and_len(new_bytecode),
                    "declared_reads": hex_keys(new_declared_reads),
                    "declared_writes": hex_keys(new_declared_writes),
                    "commutative_keys": hex_keys(new_commutative_keys),
                    "storage_key_specs": new_storage_key_specs.iter().map(|s| serde_json::json!({
                        "offset": s.offset,
                        "len": s.len,
                    })).collect::<Vec<_>>(),
                    "oracle_schema_ids": hex_keys(new_oracle_schema_ids),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::TransferOwnership {
                cell_id,
                new_owner,
            } => {
                serde_json::json!({
                    "type": "TransferOwnership",
                    "cell_id": hex::encode(cell_id),
                    "new_owner": hex::encode(new_owner),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::AcceptOwnership { cell_id } => {
                serde_json::json!({
                    "type": "AcceptOwnership",
                    "cell_id": hex::encode(cell_id),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::MakeImmutable { cell_id } => {
                serde_json::json!({
                    "type": "MakeImmutable",
                    "cell_id": hex::encode(cell_id),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::CloseCell { cell_id } => {
                serde_json::json!({
                    "type": "CloseCell",
                    "cell_id": hex::encode(cell_id),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ProposeCellUpgrade {
                cell_id,
                timelock_blocks,
                ..
            } => {
                serde_json::json!({
                    "type": "ProposeCellUpgrade",
                    "cell_id": hex::encode(cell_id),
                    "timelock_blocks": timelock_blocks,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ProposeCellOwnershipTransfer {
                cell_id,
                new_owner,
                timelock_blocks,
            } => {
                serde_json::json!({
                    "type": "ProposeCellOwnershipTransfer",
                    "cell_id": hex::encode(cell_id),
                    "new_owner": hex::encode(new_owner),
                    "timelock_blocks": timelock_blocks,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ProposeCellMakeImmutable {
                cell_id,
                timelock_blocks,
            } => {
                serde_json::json!({
                    "type": "ProposeCellMakeImmutable",
                    "cell_id": hex::encode(cell_id),
                    "timelock_blocks": timelock_blocks,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::VoteCellProposal {
                cell_id,
                approve,
            } => {
                serde_json::json!({
                    "type": "VoteCellProposal",
                    "cell_id": hex::encode(cell_id),
                    "approve": approve,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ExecuteCellProposal { cell_id } => {
                serde_json::json!({
                    "type": "ExecuteCellProposal",
                    "cell_id": hex::encode(cell_id),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::TokenTransfer {
                token_cell,
                recipient,
                amount,
            } => {
                serde_json::json!({
                    "type": "TokenTransfer",
                    "token_cell": hex::encode(token_cell),
                    "recipient": hex::encode(recipient),
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::TokenMint {
                token_cell,
                recipient,
                amount,
            } => {
                serde_json::json!({
                    "type": "TokenMint",
                    "token_cell": hex::encode(token_cell),
                    "recipient": hex::encode(recipient),
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::TokenBurn { token_cell, amount } => {
                serde_json::json!({
                    "type": "TokenBurn",
                    "token_cell": hex::encode(token_cell),
                    "amount": amount.to_string(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::TokenFreeze {
                token_cell,
                account,
            } => {
                serde_json::json!({
                    "type": "TokenFreeze",
                    "token_cell": hex::encode(token_cell),
                    "account": hex::encode(account),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::TokenThaw {
                token_cell,
                account,
            } => {
                serde_json::json!({
                    "type": "TokenThaw",
                    "token_cell": hex::encode(token_cell),
                    "account": hex::encode(account),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ProposeTokenAuthority {
                token_cell,
                set_mint_authority,
                new_mint_authority,
                set_freeze_authority,
                new_freeze_authority,
                voting_period_blocks,
            } => {
                serde_json::json!({
                    "type": "ProposeTokenAuthority",
                    "token_cell": hex::encode(token_cell),
                    "set_mint_authority": set_mint_authority,
                    "new_mint_authority": hex::encode(new_mint_authority),
                    "set_freeze_authority": set_freeze_authority,
                    "new_freeze_authority": hex::encode(new_freeze_authority),
                    "voting_period_blocks": voting_period_blocks,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::VoteTokenAuthority {
                token_cell,
                approve,
            } => {
                serde_json::json!({
                    "type": "VoteTokenAuthority",
                    "token_cell": hex::encode(token_cell),
                    "approve": approve,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::CallSystem {
                controller,
                calldata,
            } => {
                serde_json::json!({
                    "type": "CallSystem",
                    "controller": hex::encode(controller),
                    "calldata": hash_and_len(calldata),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ProposeUrl {
                url_pattern,
                bond_amount,
                voting_period_blocks,
            } => {
                serde_json::json!({
                    "type": "ProposeUrl",
                    "url_pattern": url_pattern,
                    "bond_amount": bond_amount.to_string(),
                    "voting_period_blocks": voting_period_blocks,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::VoteUrl {
                url_pattern,
                approve,
            } => {
                serde_json::json!({
                    "type": "VoteUrl",
                    "url_pattern": url_pattern,
                    "approve": approve,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ReportMaliciousUrl {
                url_pattern,
                evidence,
            } => {
                serde_json::json!({
                    "type": "ReportMaliciousUrl",
                    "url_pattern": url_pattern,
                    "evidence": evidence,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::SetCellVisibility {
                cell_id,
                visibility,
            } => {
                serde_json::json!({
                    "type": "SetCellVisibility",
                    "cell_id": hex::encode(cell_id),
                    "visibility": visibility,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::RegisterMcpTool {
                tool_id,
                bytecode,
                name,
                input_schema_json,
                category,
                declared_reads,
                declared_writes,
                commutative_keys,
                oracle_schema_ids,
                registry_id,
            } => {
                serde_json::json!({
                    "type": "RegisterMcpTool",
                    "tool_id": hex::encode(tool_id),
                    "registry_id": hex::encode(registry_id),
                    "name": name,
                    "category": category,
                    "bytecode": hash_and_len(bytecode),
                    "input_schema": hash_and_len(input_schema_json),
                    "declared_reads": hex_keys(declared_reads),
                    "declared_writes": hex_keys(declared_writes),
                    "commutative_keys": hex_keys(commutative_keys),
                    "oracle_schema_ids": hex_keys(oracle_schema_ids),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::RegisterMcpResource {
                resource_id,
                bytecode,
                name,
                uri_scheme,
                mime_type,
                initial_data,
                declared_reads,
                declared_writes,
                oracle_schema_ids,
                registry_id,
            } => {
                serde_json::json!({
                    "type": "RegisterMcpResource",
                    "resource_id": hex::encode(resource_id),
                    "registry_id": hex::encode(registry_id),
                    "name": name,
                    "uri_scheme": uri_scheme,
                    "mime_type": mime_type,
                    "bytecode": hash_and_len(bytecode),
                    "initial_data_entries": initial_data.len(),
                    "declared_reads": hex_keys(declared_reads),
                    "declared_writes": hex_keys(declared_writes),
                    "oracle_schema_ids": hex_keys(oracle_schema_ids),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::RegisterMcpPrompt {
                prompt_id,
                name,
                template_bytes,
                arguments,
                registry_id,
            } => {
                serde_json::json!({
                    "type": "RegisterMcpPrompt",
                    "prompt_id": hex::encode(prompt_id),
                    "registry_id": hex::encode(registry_id),
                    "name": name,
                    "template": hash_and_len(template_bytes),
                    "arguments": arguments.iter().map(|(name, ty, required)| serde_json::json!({
                        "name": name,
                        "type": ty,
                        "required": required,
                    })).collect::<Vec<_>>(),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::RegisterAgent {
                agent_id,
                policy_cell_id,
                agent_registry_id,
            } => {
                serde_json::json!({
                    "type": "RegisterAgent",
                    "agent_id": hex::encode(agent_id),
                    "policy_cell_id": hex::encode(policy_cell_id),
                    "agent_registry_id": hex::encode(agent_registry_id),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::SuspendAgent {
                agent_id,
                agent_registry_id,
                reason,
            } => {
                serde_json::json!({
                    "type": "SuspendAgent",
                    "agent_id": hex::encode(agent_id),
                    "agent_registry_id": hex::encode(agent_registry_id),
                    "reason": reason,
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::ReinstateAgent {
                agent_id,
                agent_registry_id,
            } => {
                serde_json::json!({
                    "type": "ReinstateAgent",
                    "agent_id": hex::encode(agent_id),
                    "agent_registry_id": hex::encode(agent_registry_id),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::McpToolCall {
                agent_id,
                tool_id,
                tool_calldata,
                value,
                gas_limit,
                policy_cell_id,
                action_log_id,
                timestamp,
            } => {
                serde_json::json!({
                    "type": "McpToolCall",
                    "agent_id": hex::encode(agent_id),
                    "tool_id": hex::encode(tool_id),
                    "policy_cell_id": hex::encode(policy_cell_id),
                    "action_log_id": action_log_id.as_ref().map(hex::encode),
                    "value": value.to_string(),
                    "gas_limit": gas_limit,
                    "timestamp": timestamp,
                    "tool_calldata": hash_and_len(tool_calldata),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::PrivateBalanceInit {
                cell_id,
                agent_id,
                encrypted_balance,
                commitment,
                commit_nonce,
            } => {
                serde_json::json!({
                    "type": "PrivateBalanceInit",
                    "cell_id": hex::encode(cell_id),
                    "agent_id": hex::encode(agent_id),
                    "encrypted_balance": hash_and_len(encrypted_balance),
                    "commitment": hex::encode(commitment),
                    "commit_nonce": hex::encode(commit_nonce),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::PrivateBalanceDeposit {
                cell_id,
                agent_id,
                amount,
                new_encrypted_balance,
                new_commitment,
                new_commit_nonce,
                old_commitment,
            } => {
                serde_json::json!({
                    "type": "PrivateBalanceDeposit",
                    "cell_id": hex::encode(cell_id),
                    "agent_id": hex::encode(agent_id),
                    "amount": amount.to_string(),
                    "new_encrypted_balance": hash_and_len(new_encrypted_balance),
                    "new_commitment": hex::encode(new_commitment),
                    "new_commit_nonce": hex::encode(new_commit_nonce),
                    "old_commitment": hex::encode(old_commitment),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::PrivateBalanceWithdraw {
                cell_id,
                agent_id,
                amount,
                recipient,
                new_encrypted_balance,
                new_commitment,
                new_commit_nonce,
                old_commitment,
            } => {
                serde_json::json!({
                    "type": "PrivateBalanceWithdraw",
                    "cell_id": hex::encode(cell_id),
                    "agent_id": hex::encode(agent_id),
                    "recipient": hex::encode(recipient),
                    "amount": amount.to_string(),
                    "new_encrypted_balance": hash_and_len(new_encrypted_balance),
                    "new_commitment": hex::encode(new_commitment),
                    "new_commit_nonce": hex::encode(new_commit_nonce),
                    "old_commitment": hex::encode(old_commitment),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::PrivateBalanceConfidentialTransfer {
                sender_cell_id,
                sender_agent_id,
                recipient_cell_id,
                amount_commitment,
                stark_proof,
                sender_new_encrypted,
                sender_new_commitment,
                sender_new_commit_nonce,
                sender_old_commitment,
                recipient_new_encrypted,
                recipient_new_commitment,
                recipient_new_commit_nonce,
                recipient_old_commitment,
            } => {
                serde_json::json!({
                    "type": "PrivateBalanceConfidentialTransfer",
                    "sender_cell_id": hex::encode(sender_cell_id),
                    "sender_agent_id": hex::encode(sender_agent_id),
                    "recipient_cell_id": hex::encode(recipient_cell_id),
                    "amount_commitment": hex::encode(amount_commitment),
                    "stark_proof": {
                        "len": stark_proof.len(),
                        "hash": hex::encode(blake3::hash(stark_proof).as_bytes()),
                    },
                    "sender_new_encrypted": hash_and_len(sender_new_encrypted),
                    "sender_new_commitment": hex::encode(sender_new_commitment),
                    "sender_new_commit_nonce": hex::encode(sender_new_commit_nonce),
                    "sender_old_commitment": hex::encode(sender_old_commitment),
                    "recipient_new_encrypted": hash_and_len(recipient_new_encrypted),
                    "recipient_new_commitment": hex::encode(recipient_new_commitment),
                    "recipient_new_commit_nonce": hex::encode(recipient_new_commit_nonce),
                    "recipient_old_commitment": hex::encode(recipient_old_commitment),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::SubmitOracleCommit {
                request_id,
                commit_hash,
            } => {
                serde_json::json!({
                    "type": "SubmitOracleCommit",
                    "request_id": hex::encode(request_id),
                    "commit_hash": hex::encode(commit_hash),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::SubmitOracleReveal {
                request_id,
                response_body,
                response_status,
            } => {
                serde_json::json!({
                    "type": "SubmitOracleReveal",
                    "request_id": hex::encode(request_id),
                    "response_status": response_status,
                    "response_body": hash_and_len(response_body),
                })
            }
            truthlinked_core::pq_execution::TransactionIntent::WrapTLKD { amount } => {
                serde_json::json!({ "type": "WrapTLKD", "amount": amount.to_string() })
            }
            truthlinked_core::pq_execution::TransactionIntent::UnwrapTLKD { amount } => {
                serde_json::json!({ "type": "UnwrapTLKD", "amount": amount.to_string() })
            }
        };
        Self::ensure_kind(&mut value);
        value
    }

    pub fn save_snapshot(
        &self,
        snapshot: &crate::snapshot::StateSnapshot,
    ) -> Result<(), Box<dyn Error>> {
        let key = format!("snapshot:{}", snapshot.height);
        let value = postcard::to_allocvec(snapshot)?;
        self.store(key, value)?;

        self.store(
            "latest_snapshot_height".to_string(),
            snapshot.height.to_le_bytes().to_vec(),
        )?;

        // Save as checkpoint if it has sufficient signatures
        let checkpoint = crate::snapshot::Checkpoint::from_snapshot(snapshot.clone());
        if checkpoint.verify().is_ok() {
            let checkpoint_data = postcard::to_allocvec(&checkpoint)?;
            self.store("checkpoint:latest".to_string(), checkpoint_data)?;
            tracing::info!(" Saved checkpoint at height {}", snapshot.height);
        }

        self.prune_old_snapshots(snapshot.height)?;

        // Every finalized block has a recovery snapshot, but keeping a modest raw
        // block window avoids heavy snapshot recovery for short live lag.
        if !self.full_node {
            let keep_from = snapshot.height.saturating_sub(RAW_BLOCK_RETENTION);
            if keep_from > 0 {
                let _ = self.prune_blocks(keep_from);
            }
        }

        Ok(())
    }

    fn staking_events_from_intent(
        &self,
        intent: &truthlinked_core::pq_execution::TransactionIntent,
    ) -> Option<Vec<serde_json::Value>> {
        match intent {
            truthlinked_core::pq_execution::TransactionIntent::Stake { amount } => {
                Some(vec![serde_json::json!({
                    "type": "Stake",
                    "amount": amount.to_string(),
                })])
            }
            truthlinked_core::pq_execution::TransactionIntent::Unstake { amount } => {
                Some(vec![serde_json::json!({
                    "type": "Unstake",
                    "amount": amount.to_string(),
                })])
            }
            truthlinked_core::pq_execution::TransactionIntent::WithdrawStake => {
                Some(vec![serde_json::json!({
                    "type": "Withdraw",
                })])
            }
            truthlinked_core::pq_execution::TransactionIntent::Unjail => {
                Some(vec![serde_json::json!({
                    "type": "Unjail",
                })])
            }
            _ => None,
        }
    }

    pub fn load_snapshot(
        &self,
        height: u64,
    ) -> Result<Option<crate::snapshot::StateSnapshot>, Box<dyn Error>> {
        let key = format!("snapshot:{}", height);
        match self.retrieve(&key)? {
            Some(data) => {
                let snapshot = postcard::from_bytes(&data)?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    }

    pub fn get_latest_snapshot(
        &self,
    ) -> Result<Option<crate::snapshot::StateSnapshot>, Box<dyn Error>> {
        match self.backend.get(b"latest_snapshot_height")? {
            Some(data) => {
                let height = u64::from_le_bytes(<[u8; 8]>::try_from(data.as_ref())?);
                self.load_snapshot(height)
            }
            None => Ok(None),
        }
    }

    /// Alias for get_latest_snapshot
    pub fn load_latest_snapshot(
        &self,
    ) -> Result<Option<crate::snapshot::StateSnapshot>, Box<dyn Error>> {
        self.get_latest_snapshot()
    }

    /// Load latest snapshot at or before given height.
    /// Uses the stored `latest_snapshot_height` index - O(1), no scan.
    pub fn load_latest_snapshot_before(
        &self,
        height: u64,
    ) -> Result<Option<crate::snapshot::StateSnapshot>, Box<dyn Error>> {
        if let Some(data) = self.backend.get(b"latest_snapshot_height")? {
            let latest = u64::from_le_bytes(<[u8; 8]>::try_from(data.as_ref())?);
            if latest <= height {
                return self.load_snapshot(latest);
            }
        }
        let start = format!("snapshot:{}", height);
        for (k, v) in self.backend.scan_from_reverse(start.as_bytes())? {
            if !k.starts_with(b"snapshot:") {
                break;
            }
            let snapshot: crate::snapshot::StateSnapshot = postcard::from_bytes(&v)?;
            if snapshot.height <= height {
                return Ok(Some(snapshot));
            }
        }
        Ok(None)
    }

    /// Prune raw block data (batch bytes + tx-by-height index) for blocks older than
    /// `keep_from`. Headers and per-account tx history are kept - they are needed for
    /// chain verification and address queries. Snapshots cover the pruned state.
    ///
    /// Called automatically after each snapshot save unless `--full` is set.
    pub fn prune_blocks(&self, keep_from: u64) -> Result<usize, Box<dyn Error>> {
        if keep_from == 0 {
            return Ok(0);
        }
        let mut ops = Vec::new();
        let mut pruned = 0usize;

        for prefix in ["batch:", "tx_by_height:", "batch_tx_count:", "results:"] {
            for (k, _) in self.backend.scan_prefix(prefix.as_bytes())? {
                let Ok(s) = std::str::from_utf8(&k) else {
                    continue;
                };
                let rest = s.strip_prefix(prefix).unwrap_or_default();
                let h = rest
                    .split(':')
                    .next()
                    .and_then(|x| x.parse::<u64>().ok())
                    .unwrap_or(u64::MAX);
                if h >= keep_from {
                    continue;
                }
                if prefix == "batch:" {
                    pruned += 1;
                }
                ops.push(KvOp::Delete(k));
            }
        }

        if !ops.is_empty() {
            self.backend.write_batch(ops, keep_from, true)?;
            tracing::info!("Pruned {} blocks (kept from height {})", pruned, keep_from);
        }
        Ok(pruned)
    }

    fn prune_old_snapshots(&self, _current_height: u64) -> Result<(), Box<dyn Error>> {
        let keep = MAX_SNAPSHOTS_KEPT.max(1);
        let mut heights = Vec::new();
        for (k, _) in self.backend.scan_prefix(b"snapshot:")? {
            let Ok(s) = std::str::from_utf8(&k) else {
                continue;
            };
            if let Some(h_str) = s.strip_prefix("snapshot:") {
                if let Ok(height) = h_str.parse::<u64>() {
                    heights.push(height);
                }
            }
        }
        if heights.len() <= keep {
            return Ok(());
        }
        heights.sort_unstable();
        let prune_count = heights.len().saturating_sub(keep);
        let ops = heights
            .iter()
            .take(prune_count)
            .map(|height| KvOp::Delete(format!("snapshot:{}", height).into_bytes()))
            .collect();
        self.backend.write_batch(ops, _current_height, true)?;
        tracing::info!(
            "Pruned {} old snapshots (kept newest {})",
            prune_count,
            keep
        );
        Ok(())
    }

    /// Commit a finalized block through DonaDB-backed storage, then sync.
    /// This is the hot path - use this instead of calling save_batch/save_batch_header/index separately.
    pub fn save_block(
        &self,
        header: &crate::blockchain::BatchHeader,
        batch: &crate::Batch,
        results: &[String],
        name_registry: &std::collections::HashMap<String, [u8; 32]>,
    ) -> Result<(), Box<dyn Error>> {
        let batch_val = postcard::to_allocvec(&(&header.batch_hash, batch))
            .map_err(|e| format!("Serialization failed: {}", e))?;
        let header_val = postcard::to_allocvec(header)?;
        let results_val = postcard::to_allocvec(results)?;
        let mut ops = vec![
            KvOp::Put(format!("batch:{}", header.height).into_bytes(), batch_val),
            KvOp::Put(
                format!("header:{}", hex::encode(&header.batch_hash)).into_bytes(),
                header_val,
            ),
            KvOp::Put(
                format!("height:{}", header.height).into_bytes(),
                header.batch_hash.to_vec(),
            ),
            KvOp::Put(
                format!("anchor:{}", header.height).into_bytes(),
                header.batch_hash.to_vec(),
            ),
            KvOp::Put(
                b"meta:latest_height".to_vec(),
                header.height.to_le_bytes().to_vec(),
            ),
            KvOp::Put(
                format!("results:{}", header.height).into_bytes(),
                results_val,
            ),
        ];
        ops.extend(self.build_batch_transaction_index_ops(
            header.height,
            &header.batch_hash,
            batch,
            results,
            name_registry,
        )?);
        self.backend.write_batch(ops, header.height, true)?;
        Ok(())
    }

    pub fn save_block_results(
        &self,
        height: u64,
        results: &[String],
    ) -> Result<(), Box<dyn Error>> {
        let value = postcard::to_allocvec(results)?;
        self.store(format!("results:{}", height), value)?;
        Ok(())
    }

    pub fn load_block_results(&self, height: u64) -> Result<Option<Vec<String>>, Box<dyn Error>> {
        match self.retrieve(&format!("results:{}", height))? {
            Some(data) => Ok(Some(postcard::from_bytes(&data)?)),
            None => Ok(None),
        }
    }

    /// Save finalized batch to disk
    pub fn save_batch(
        &self,
        height: u64,
        batch_hash: &[u8; 32],
        batch: &crate::Batch,
    ) -> Result<(), Box<dyn Error>> {
        let key = format!("batch:{}", height);
        let value = postcard::to_allocvec(&(batch_hash, batch))
            .map_err(|e| format!("Serialization failed: {}", e))?;
        self.store(key, value)?;
        Ok(())
    }

    /// Load batch from disk
    pub fn load_batch(&self, height: u64) -> Result<Option<crate::Batch>, Box<dyn Error>> {
        let key = format!("batch:{}", height);
        if let Some(value) = self.retrieve(&key)? {
            let (_hash, batch): ([u8; 32], crate::Batch) = postcard::from_bytes(&value)
                .map_err(|e| format!("Deserialization failed: {}", e))?;
            Ok(Some(batch))
        } else {
            Ok(None)
        }
    }

    /// Save blockchain header to disk
    pub fn save_header(
        &self,
        height: u64,
        header: &crate::blockchain::BatchHeader,
    ) -> Result<(), Box<dyn Error>> {
        let key = format!("header:{}", height);
        let value =
            postcard::to_allocvec(header).map_err(|e| format!("Serialization failed: {}", e))?;
        self.store(key, value)?;
        Ok(())
    }

    /// Load header from disk
    pub fn load_header(
        &self,
        height: u64,
    ) -> Result<Option<crate::blockchain::BatchHeader>, Box<dyn Error>> {
        let key = format!("header:{}", height);
        if let Some(value) = self.retrieve(&key)? {
            let header: crate::blockchain::BatchHeader = postcard::from_bytes(&value)
                .map_err(|e| format!("Deserialization failed: {}", e))?;
            Ok(Some(header))
        } else {
            Ok(None)
        }
    }

    /// Get highest stored height
    pub fn get_highest_height(&self) -> Result<u64, Box<dyn Error>> {
        let mut max_h = 0u64;
        for (k, _) in self.backend.scan_prefix(b"header:")? {
            if let Ok(s) = std::str::from_utf8(&k) {
                if let Some(h) = s
                    .strip_prefix("header:")
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    max_h = max_h.max(h);
                }
            }
        }
        Ok(max_h)
    }
}

// ── Block Introspection ───────────────────────────────────────────────────────
// All methods use storage key scans directly - no deserialization into RAM,
// no state replay. Safe to call at any time without affecting consensus.

/// Describes the health of a single stored block.
#[derive(Debug, Clone)]
pub struct BlockPresence {
    pub height: u64,
    pub has_header: bool,
    pub has_batch: bool,
    /// Stored tx count from the `batch_tx_count:<h>` index key.
    pub indexed_tx_count: Option<u32>,
}

impl BlockPresence {
    pub fn is_complete(&self) -> bool {
        self.has_header && self.has_batch
    }
}

impl Storage {
    fn scan_height_keys(&self, prefix: &str, from: u64, to: u64) -> Vec<u64> {
        let Ok(rows) = self.backend.scan_prefix(prefix.as_bytes()) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for (k, _) in rows {
            let Ok(s) = std::str::from_utf8(&k) else {
                continue;
            };
            let Some(rest) = s.strip_prefix(prefix) else {
                continue;
            };
            let h = rest.split(':').next().and_then(|x| x.parse::<u64>().ok());
            if let Some(h) = h {
                if h >= from && h <= to {
                    found.push(h);
                }
            }
        }
        found.sort_unstable();
        found
    }

    /// Scan which heights have a `batch:<h>` key present, without deserializing.
    /// Returns a sorted vec of heights found in [from, to].
    pub fn scan_batch_presence(&self, from: u64, to: u64) -> Vec<u64> {
        self.scan_height_keys("batch:", from, to)
    }

    /// Scan which heights have a `height:<h>` (header hash index) key present.
    pub fn scan_header_presence(&self, from: u64, to: u64) -> Vec<u64> {
        self.scan_height_keys("height:", from, to)
    }

    /// For each height in [from, to], return a BlockPresence describing what's stored.
    /// Uses only key existence checks + one tiny value read for tx count - no full deserialization.
    pub fn introspect_block_range(&self, from: u64, to: u64) -> Vec<BlockPresence> {
        let batches: std::collections::HashSet<u64> =
            self.scan_batch_presence(from, to).into_iter().collect();
        let headers: std::collections::HashSet<u64> =
            self.scan_header_presence(from, to).into_iter().collect();

        (from..=to)
            .map(|h| {
                let indexed_tx_count = self
                    .retrieve(&format!("batch_tx_count:{}", h))
                    .ok()
                    .flatten()
                    .and_then(|v| {
                        let arr: [u8; 4] = v.try_into().ok()?;
                        Some(u32::from_le_bytes(arr))
                    });

                BlockPresence {
                    height: h,
                    has_header: headers.contains(&h),
                    has_batch: batches.contains(&h),
                    indexed_tx_count,
                }
            })
            .collect()
    }

    /// Return heights in [from, to] that are missing either their header or batch.
    pub fn find_missing_blocks(&self, from: u64, to: u64) -> Vec<u64> {
        self.introspect_block_range(from, to)
            .into_iter()
            .filter(|p| !p.is_complete())
            .map(|p| p.height)
            .collect()
    }

    /// Count how many `tx_by_height:<h>:*` index entries exist for a height,
    /// without loading the actual transactions.
    pub fn count_indexed_txs_at_height(&self, height: u64) -> u32 {
        if let Some(v) = self
            .retrieve(&format!("batch_tx_count:{}", height))
            .ok()
            .flatten()
        {
            if let Ok(b) = <[u8; 4]>::try_from(v) {
                return u32::from_le_bytes(b);
            }
        }
        self.backend
            .scan_prefix(format!("tx_by_height:{}:", height).as_bytes())
            .map(|rows| rows.len() as u32)
            .unwrap_or(0)
    }

    /// Verify that the stored tx index count matches the batch's actual tx count
    /// by comparing `batch_tx_count:<h>` against the number of `tx_by_height:<h>:*` keys.
    /// Returns (stored_count, indexed_count, matches).
    pub fn verify_tx_index_integrity(&self, height: u64) -> (u32, u32, bool) {
        let stored = self
            .retrieve(&format!("batch_tx_count:{}", height))
            .ok()
            .flatten()
            .and_then(|v| {
                let arr: [u8; 4] = v.try_into().ok()?;
                Some(u32::from_le_bytes(arr))
            })
            .unwrap_or(0);
        let indexed = self
            .backend
            .scan_prefix(format!("tx_by_height:{}:", height).as_bytes())
            .map(|rows| rows.len() as u32)
            .unwrap_or(0);
        (stored, indexed, stored == indexed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_tx(
        sender_seed: u8,
        recipient_seed: u8,
        nonce: u64,
    ) -> truthlinked_core::pq_execution::Transaction {
        let sender = [sender_seed; 32];
        let recipient = [recipient_seed; 32];
        truthlinked_core::pq_execution::Transaction {
            sender,
            intent: truthlinked_core::pq_execution::TransactionIntent::Transfer {
                recipient,
                recipient_pubkey: None,
                amount: 100 + nonce as u128,
            },
            signature: vec![sender_seed; 96],
            nonce,
            timestamp: 1_700_000_000 + nonce,
            genesis_fingerprint: [9u8; 32],
            expiration_height: u64::MAX,
        }
    }

    fn test_header(height: u64, batch: &crate::Batch) -> crate::blockchain::BatchHeader {
        let batch_hash: [u8; 32] = blake3::hash(&postcard::to_allocvec(batch).unwrap()).into();
        crate::blockchain::BatchHeader::new(
            height,
            if height == 0 {
                [0u8; 32]
            } else {
                [height as u8 - 1; 32]
            },
            batch_hash,
            batch_hash,
            [height as u8; 32],
            1_700_000_000 + height,
            0,
            crate::blockchain::PqFinalityCertificate::empty(
                height,
                0,
                batch_hash,
                [height as u8; 32],
            ),
            vec![height as u8; 32],
            vec![height as u8; 96],
            0,
        )
    }

    #[test]
    fn donadb_save_block_survives_reopen_and_preserves_tx_indexes() {
        let dir = TempDir::new().unwrap();
        let batch = vec![test_tx(1, 2, 1), test_tx(2, 1, 1), test_tx(1, 3, 2)];
        let header = test_header(7, &batch);
        let results = vec!["success".to_string(); batch.len()];
        let registry = std::collections::HashMap::new();
        let tx_hash = Storage::new(dir.path()).unwrap().compute_tx_hash(&batch[0]);

        {
            let storage = Storage::new(dir.path()).unwrap();
            storage
                .save_block(&header, &batch, &results, &registry)
                .unwrap();
            assert_eq!(storage.get_latest_block_height(), 7);
            assert_eq!(storage.load_batch(7).unwrap().unwrap().len(), 3);
            assert_eq!(storage.verify_tx_index_integrity(7), (3, 3, true));
        }

        let reopened = Storage::new(dir.path()).unwrap();
        assert_eq!(reopened.get_latest_block_height(), 7);
        assert_eq!(reopened.load_block_results(7).unwrap().unwrap(), results);
        assert!(reopened.load_batch_header_by_height(7).unwrap().is_some());
        assert_eq!(reopened.load_batch(7).unwrap().unwrap().len(), 3);
        assert_eq!(reopened.verify_tx_index_integrity(7), (3, 3, true));
        let tx = reopened.get_transaction_by_hash(&tx_hash).unwrap().unwrap();
        assert_eq!(tx["height"], 7);
        assert_eq!(tx["tx_hash"], hex::encode(tx_hash));
        assert!(reopened
            .get_transaction_by_hash_prefix(&hex::encode(tx_hash)[..12])
            .unwrap()
            .is_some());
    }

    #[test]
    fn donadb_prunes_raw_blocks_but_keeps_headers_and_latest_height() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let registry = std::collections::HashMap::new();
        for height in 1..=6 {
            let batch = vec![test_tx(height as u8, height as u8 + 1, height)];
            let header = test_header(height, &batch);
            storage
                .save_block(&header, &batch, &["success".to_string()], &registry)
                .unwrap();
        }

        assert_eq!(storage.get_latest_block_height(), 6);
        assert_eq!(storage.prune_blocks(4).unwrap(), 3);
        assert!(storage.load_batch_header_by_height(2).unwrap().is_some());
        assert!(storage.load_batch(2).unwrap().is_none());
        assert!(storage.load_batch(4).unwrap().is_some());
        assert_eq!(storage.get_latest_block_height(), 6);
    }

    #[test]
    fn donadb_handles_sequential_block_pressure() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new(dir.path()).unwrap();
        let registry = std::collections::HashMap::new();
        for height in 1..=128u64 {
            let batch: crate::Batch = (0..8)
                .map(|i| test_tx((height % 200) as u8, (i + 1) as u8, height * 10 + i as u64))
                .collect();
            let header = test_header(height, &batch);
            let results = vec!["success".to_string(); batch.len()];
            storage
                .save_block(&header, &batch, &results, &registry)
                .unwrap();
            assert_eq!(storage.verify_tx_index_integrity(height), (8, 8, true));
        }
        storage.finalize_block(128).unwrap();
        drop(storage);
        let reopened = Storage::new(dir.path()).unwrap();
        assert_eq!(reopened.get_latest_block_height(), 128);
        assert_eq!(reopened.load_batch(128).unwrap().unwrap().len(), 8);
        assert_eq!(reopened.verify_tx_index_integrity(128), (8, 8, true));
    }

    #[test]
    fn load_latest_state_uses_snapshot() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new(dir.path()).unwrap();

        let mut state = truthlinked_state::pq_execution::State::genesis();
        let pk = vec![7u8; 1952];
        let id = truthlinked_core::pq_identity::account_id_from_pubkey(&pk);
        state.accounts.insert(
            id,
            truthlinked_runtime::types::AccountRecord {
                pubkey_bytes: pk,
                balance: 1234,
                compute_escrow_tlkd: 0,
                nonce: 0,
                nfts: vec![],
            },
        );

        let snapshot = crate::snapshot::StateSnapshot::from_state(1, &state);
        storage.save_snapshot(&snapshot).unwrap();

        let restored = storage
            .load_latest_snapshot()
            .unwrap()
            .expect("snapshot restored");
        assert_eq!(restored.height, 1);
        assert!(restored.accounts.contains_key(&id));
    }
}
