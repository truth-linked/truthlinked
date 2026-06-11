//! Truthlinked State Src Metrics
//!
//! Owns state and execution metrics collected for observability.
//! State changes are consensus-sensitive and must preserve deterministic execution and serialization.

// Metrics - Prometheus text format (minimal, dependency-free)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

lazy_static::lazy_static! {
    static ref GLOBAL_METRICS: Arc<Metrics> = Arc::new(Metrics::new());
}

pub fn global() -> Arc<Metrics> {
    GLOBAL_METRICS.clone()
}

pub struct Metrics {
    start_time: Instant,
    // Gauges
    height: AtomicU64,
    finalized_height: AtomicU64,
    mempool_size: AtomicU64,
    peer_count: AtomicU64,
    avg_block_time_ms: AtomicU64,
    tps_1min: AtomicU64,
    tps_5min: AtomicU64,
    ingress_connections: AtomicU64,
    ack_connections: AtomicU64,
    // Counters
    rpc_requests: AtomicU64,
    rpc_errors: AtomicU64,
    storage_wal_writes: AtomicU64,
    storage_db_writes: AtomicU64,
    storage_db_reads: AtomicU64,
    storage_errors: AtomicU64,
    tx_submitted: AtomicU64,
    tx_applied: AtomicU64,
    tx_failed: AtomicU64,
    ingress_connections_total: AtomicU64,
    ingress_messages_total: AtomicU64,
    ingress_rejected_total: AtomicU64,
    ack_connections_total: AtomicU64,
    ack_messages_total: AtomicU64,
    ack_rejected_total: AtomicU64,
    ack_invalid_total: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            height: AtomicU64::new(0),
            finalized_height: AtomicU64::new(0),
            mempool_size: AtomicU64::new(0),
            peer_count: AtomicU64::new(0),
            avg_block_time_ms: AtomicU64::new(0),
            tps_1min: AtomicU64::new(0),
            tps_5min: AtomicU64::new(0),
            ingress_connections: AtomicU64::new(0),
            ack_connections: AtomicU64::new(0),
            rpc_requests: AtomicU64::new(0),
            rpc_errors: AtomicU64::new(0),
            storage_wal_writes: AtomicU64::new(0),
            storage_db_writes: AtomicU64::new(0),
            storage_db_reads: AtomicU64::new(0),
            storage_errors: AtomicU64::new(0),
            tx_submitted: AtomicU64::new(0),
            tx_applied: AtomicU64::new(0),
            tx_failed: AtomicU64::new(0),
            ingress_connections_total: AtomicU64::new(0),
            ingress_messages_total: AtomicU64::new(0),
            ingress_rejected_total: AtomicU64::new(0),
            ack_connections_total: AtomicU64::new(0),
            ack_messages_total: AtomicU64::new(0),
            ack_rejected_total: AtomicU64::new(0),
            ack_invalid_total: AtomicU64::new(0),
        }
    }

    pub fn set_height(&self, height: u64) {
        self.height.store(height, Ordering::Relaxed);
    }

    pub fn set_finalized_height(&self, height: u64) {
        self.finalized_height.store(height, Ordering::Relaxed);
    }

    pub fn set_mempool_size(&self, size: u64) {
        self.mempool_size.store(size, Ordering::Relaxed);
    }

    pub fn set_peer_count(&self, count: u64) {
        self.peer_count.store(count, Ordering::Relaxed);
    }

    pub fn set_avg_block_time_ms(&self, ms: u64) {
        self.avg_block_time_ms.store(ms, Ordering::Relaxed);
    }

    pub fn set_tps_1min(&self, tps: u64) {
        self.tps_1min.store(tps, Ordering::Relaxed);
    }

    pub fn set_tps_5min(&self, tps: u64) {
        self.tps_5min.store(tps, Ordering::Relaxed);
    }

    pub fn inc_ingress_connections(&self) {
        self.ingress_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_ingress_connections(&self) {
        self.ingress_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_connections_total(&self) {
        self.ingress_connections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_messages_total(&self) {
        self.ingress_messages_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_rejected_total(&self) {
        self.ingress_rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ack_connections(&self) {
        self.ack_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_ack_connections(&self) {
        self.ack_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_ack_connections_total(&self) {
        self.ack_connections_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ack_messages_total(&self) {
        self.ack_messages_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ack_rejected_total(&self) {
        self.ack_rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ack_invalid_total(&self) {
        self.ack_invalid_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rpc_requests(&self) {
        self.rpc_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rpc_errors(&self) {
        self.rpc_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_wal_writes(&self) {
        self.storage_wal_writes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_db_writes(&self) {
        self.storage_db_writes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_db_reads(&self) {
        self.storage_db_reads.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_errors(&self) {
        self.storage_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_submitted(&self) {
        self.tx_submitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_applied(&self) {
        self.tx_applied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_failed(&self) {
        self.tx_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_tx_applied(&self, n: u64) {
        self.tx_applied.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_tx_failed(&self, n: u64) {
        self.tx_failed.fetch_add(n, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let uptime = self.start_time.elapsed().as_secs();
        let mut out = String::new();
        out.push_str("# TYPE truthlinked_uptime_seconds counter\n");
        out.push_str(&format!("truthlinked_uptime_seconds {}\n", uptime));
        out.push_str("# TYPE truthlinked_height gauge\n");
        out.push_str(&format!(
            "truthlinked_height {}\n",
            self.height.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE chain_height gauge\n");
        out.push_str(&format!(
            "chain_height {}\n",
            self.height.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_finalized_height gauge\n");
        out.push_str(&format!(
            "truthlinked_finalized_height {}\n",
            self.finalized_height.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE chain_finalized_height gauge\n");
        out.push_str(&format!(
            "chain_finalized_height {}\n",
            self.finalized_height.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_mempool_size gauge\n");
        out.push_str(&format!(
            "truthlinked_mempool_size {}\n",
            self.mempool_size.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE mempool_size gauge\n");
        out.push_str(&format!(
            "mempool_size {}\n",
            self.mempool_size.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_peer_count gauge\n");
        out.push_str(&format!(
            "truthlinked_peer_count {}\n",
            self.peer_count.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE peer_count gauge\n");
        out.push_str(&format!(
            "peer_count {}\n",
            self.peer_count.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_avg_block_time_ms gauge\n");
        out.push_str(&format!(
            "truthlinked_avg_block_time_ms {}\n",
            self.avg_block_time_ms.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_tps_1min gauge\n");
        out.push_str(&format!(
            "truthlinked_tps_1min {}\n",
            self.tps_1min.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_tps_5min gauge\n");
        out.push_str(&format!(
            "truthlinked_tps_5min {}\n",
            self.tps_5min.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE avg_tps gauge\n");
        out.push_str(&format!(
            "avg_tps {}\n",
            self.tps_1min.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_ingress_connections gauge\n");
        out.push_str(&format!(
            "truthlinked_ingress_connections {}\n",
            self.ingress_connections.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_ingress_connections_total counter\n");
        out.push_str(&format!(
            "truthlinked_ingress_connections_total {}\n",
            self.ingress_connections_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_ingress_messages_total counter\n");
        out.push_str(&format!(
            "truthlinked_ingress_messages_total {}\n",
            self.ingress_messages_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_ingress_rejected_total counter\n");
        out.push_str(&format!(
            "truthlinked_ingress_rejected_total {}\n",
            self.ingress_rejected_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_ack_connections gauge\n");
        out.push_str(&format!(
            "truthlinked_ack_connections {}\n",
            self.ack_connections.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_ack_connections_total counter\n");
        out.push_str(&format!(
            "truthlinked_ack_connections_total {}\n",
            self.ack_connections_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_ack_messages_total counter\n");
        out.push_str(&format!(
            "truthlinked_ack_messages_total {}\n",
            self.ack_messages_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_ack_rejected_total counter\n");
        out.push_str(&format!(
            "truthlinked_ack_rejected_total {}\n",
            self.ack_rejected_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_ack_invalid_total counter\n");
        out.push_str(&format!(
            "truthlinked_ack_invalid_total {}\n",
            self.ack_invalid_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_rpc_requests_total counter\n");
        out.push_str(&format!(
            "truthlinked_rpc_requests_total {}\n",
            self.rpc_requests.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_rpc_errors_total counter\n");
        out.push_str(&format!(
            "truthlinked_rpc_errors_total {}\n",
            self.rpc_errors.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_storage_wal_writes_total counter\n");
        out.push_str(&format!(
            "truthlinked_storage_wal_writes_total {}\n",
            self.storage_wal_writes.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_storage_db_writes_total counter\n");
        out.push_str(&format!(
            "truthlinked_storage_db_writes_total {}\n",
            self.storage_db_writes.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_storage_db_reads_total counter\n");
        out.push_str(&format!(
            "truthlinked_storage_db_reads_total {}\n",
            self.storage_db_reads.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_storage_errors_total counter\n");
        out.push_str(&format!(
            "truthlinked_storage_errors_total {}\n",
            self.storage_errors.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_tx_submitted_total counter\n");
        out.push_str(&format!(
            "truthlinked_tx_submitted_total {}\n",
            self.tx_submitted.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_tx_applied_total counter\n");
        out.push_str(&format!(
            "truthlinked_tx_applied_total {}\n",
            self.tx_applied.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE truthlinked_tx_failed_total counter\n");
        out.push_str(&format!(
            "truthlinked_tx_failed_total {}\n",
            self.tx_failed.load(Ordering::Relaxed)
        ));
        out
    }
}
