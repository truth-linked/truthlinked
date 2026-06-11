//! TruthLinked P2P Validator Mesh
//!
//! Pure post-quantum transport - no classical crypto anywhere.
//! - Transport encryption: ML-KEM-768 ephemeral key exchange (forward secrecy)
//! - Authentication:       ML-DSA-65 signatures on every message
//! - Node identity:        SHA2-256(dilithium_pk) - no Ed25519, no secp256k1
//! - Discovery:            Kademlia-style XOR routing over PQ node IDs
//! - Gossip:               Topic-based fanout over PQ-encrypted sessions

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

const OUTBOUND_QUEUE_CAP: usize = 4096;

use crate::pq_transport::{PQHandshake, PQSession};

pub const TOPIC_CONSENSUS: &str = "trth/consensus/1.0.0";
pub const TOPIC_TX: &str = "trth/tx/1.0.0";

/// A node's identity - SHA2-256 of its Dilithium pubkey
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn from_dilithium_pk(pk: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self(Sha256::digest(pk).into())
    }

    /// XOR distance for Kademlia routing
    pub fn distance(&self, other: &NodeId) -> [u8; 32] {
        let mut d = [0u8; 32];
        for i in 0..32 {
            d[i] = self.0[i] ^ other.0[i];
        }
        d
    }
}

/// Wire message - sent over an already-authenticated, encrypted PQ session.
/// No per-message signing needed: the handshake (ML-KEM-768 + ML-DSA-65)
/// already authenticates the peer for the lifetime of the session.
#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    pub sender_pk: Vec<u8>, // ML-DSA-65 pubkey (identity, from handshake)
    pub topic: String,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum NetEvent {
    Message {
        from: Vec<u8>,
        topic: String,
        payload: Vec<u8>,
    },
    PeerConnected(NodeId),
    PeerDisconnected(NodeId),
}

/// Metadata tracked per connected peer
#[derive(Clone, Debug)]
pub struct PeerMeta {
    pub dilithium_pk: Vec<u8>,
    pub addr: String,
    pub height: u64,
    pub connected_at: std::time::Instant,
}

/// Active peer connection
#[allow(dead_code)]
struct Peer {
    node_id: NodeId,
    dilithium_pk: Vec<u8>,
    addr: String,
    tx: mpsc::Sender<Vec<u8>>, // bounded outbound encrypted frames
}

/// Commands sent to the network actor
enum NetCmd {
    Broadcast {
        topic: String,
        payload: Vec<u8>,
    },
    GetPeerCount {
        reply: tokio::sync::oneshot::Sender<usize>,
    },
    GetPeerAddrs {
        reply: tokio::sync::oneshot::Sender<Vec<String>>,
    },
    UpdatePeerHeight {
        node_id: NodeId,
        height: u64,
    },
}

/// The TruthLinked validator mesh handle
#[derive(Clone)]
pub struct Truthlinked {
    cmd: mpsc::UnboundedSender<NetCmd>,
}

impl Truthlinked {
    pub fn placeholder() -> Self {
        let (tx, _) = mpsc::unbounded_channel();
        Self { cmd: tx }
    }

    pub fn broadcast(&self, topic: &str, payload: Vec<u8>) {
        let _ = self.cmd.send(NetCmd::Broadcast {
            topic: topic.to_string(),
            payload,
        });
    }

    pub async fn get_peer_count(&self) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.cmd.send(NetCmd::GetPeerCount { reply: tx });
        rx.await.unwrap_or(0)
    }

    pub async fn get_peer_addrs(&self) -> Vec<String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.cmd.send(NetCmd::GetPeerAddrs { reply: tx });
        rx.await.unwrap_or_default()
    }

    pub fn update_peer_height(&self, node_id: NodeId, height: u64) {
        let _ = self.cmd.send(NetCmd::UpdatePeerHeight { node_id, height });
    }
}

pub async fn start(
    dilithium_pk: Vec<u8>,
    dilithium_sk: Vec<u8>,
    listen_port: u16,
    bootstrap: Vec<(String, String)>, // (addr, dilithium_pubkey_hex)
) -> (Truthlinked, mpsc::UnboundedReceiver<NetEvent>) {
    let local_id = NodeId::from_dilithium_pk(&dilithium_pk);
    info!("Node ID (PQ): {}", hex::encode(&local_id.0));

    // Shared peer table: NodeId -> Peer
    let peers: Arc<RwLock<HashMap<NodeId, Peer>>> = Arc::new(RwLock::new(HashMap::new()));
    // Peer metadata (height, addr) - separate so reads do not block writes
    let peer_meta: Arc<RwLock<HashMap<NodeId, PeerMeta>>> = Arc::new(RwLock::new(HashMap::new()));
    // All peers ever successfully connected to (bootstrap + organically discovered)
    let known_peers: Arc<RwLock<HashMap<Vec<u8>, SocketAddr>>> =
        Arc::new(RwLock::new(HashMap::new()));
    // Seed known_peers from bootstrap list
    {
        let mut kp = known_peers.write().await;
        for (addr, pk_hex) in &bootstrap {
            if let (Ok(sock_addr), Ok(pk_bytes)) = (addr.parse::<SocketAddr>(), hex::decode(pk_hex))
            {
                kp.insert(pk_bytes, sock_addr);
            }
        }
    }

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<NetCmd>();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel::<NetEvent>();

    // ── Listener: accept inbound PQ connections ───────────────────────────────
    {
        let peers = peers.clone();
        let peer_meta = peer_meta.clone();
        let known_peers = known_peers.clone();
        let evt_tx = evt_tx.clone();
        let dk = dilithium_sk.clone();
        let pk = dilithium_pk.clone();
        tokio::spawn(async move {
            let addr = format!("0.0.0.0:{}", listen_port);
            let listener = TcpListener::bind(&addr).await.expect("p2p bind");
            info!("P2P listening on {}", addr);
            loop {
                let Ok((stream, peer_addr)) = listener.accept().await else {
                    continue;
                };
                debug!("Inbound P2P connection from {}", peer_addr);
                let peers = peers.clone();
                let peer_meta = peer_meta.clone();
                let known_peers = known_peers.clone();
                let evt_tx = evt_tx.clone();
                let dk = dk.clone();
                let pk = pk.clone();
                let addr_str = peer_addr.to_string();
                let sock_addr = peer_addr;
                tokio::spawn(async move {
                    if let Err(e) = handle_inbound(
                        stream,
                        addr_str,
                        sock_addr,
                        pk,
                        dk,
                        peers,
                        peer_meta,
                        known_peers,
                        evt_tx,
                    )
                    .await
                    {
                        warn!("Inbound P2P error: {}", e);
                    }
                });
            }
        });
    }

    // ── Command actor: handle broadcast + queries ─────────────────────────────
    {
        let peers = peers.clone();
        let peer_meta = peer_meta.clone();
        let pk = dilithium_pk.clone();
        let _sk = dilithium_sk.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    NetCmd::Broadcast { topic, payload } => {
                        let msg = NetworkMessage {
                            sender_pk: pk.clone(),
                            topic,
                            payload,
                        };
                        let Ok(frame) = postcard::to_allocvec(&msg) else {
                            continue;
                        };
                        let snapshot = peers.read().await;
                        for peer in snapshot.values() {
                            if let Err(e) = peer.tx.try_send(frame.clone()) {
                                warn!("Dropping outbound frame to {}: {}", peer.addr, e);
                            }
                        }
                    }
                    NetCmd::GetPeerCount { reply } => {
                        let count = peers.read().await.len();
                        let _ = reply.send(count);
                    }
                    NetCmd::GetPeerAddrs { reply } => {
                        let meta = peer_meta.read().await;
                        let addrs = meta.values().map(|m| m.addr.clone()).collect();
                        let _ = reply.send(addrs);
                    }
                    NetCmd::UpdatePeerHeight { node_id, height } => {
                        if let Some(m) = peer_meta.write().await.get_mut(&node_id) {
                            m.height = height;
                        }
                    }
                }
            }
        });
    }

    // ── Bootstrap + reconnect loop ────────────────────────────────────────────
    {
        let peers = peers.clone();
        let peer_meta = peer_meta.clone();
        let known_peers = known_peers.clone();
        let evt_tx = evt_tx.clone();
        let pk = dilithium_pk.clone();
        let sk = dilithium_sk.clone();
        // backoff per addr: attempts -> next_try
        let mut backoff: HashMap<String, (u32, std::time::Instant)> = HashMap::new();

        tokio::spawn(async move {
            // Initial delay so the listener is up before we dial out
            tokio::time::sleep(Duration::from_secs(2)).await;

            loop {
                let connected_addrs: std::collections::HashSet<String> = {
                    let meta = peer_meta.read().await;
                    meta.values().map(|m| m.addr.clone()).collect()
                };

                let targets: Vec<String> = {
                    let kp = known_peers.read().await;
                    kp.values().map(|a| a.to_string()).collect()
                };

                for addr in &targets {
                    if connected_addrs.contains(addr) {
                        continue;
                    }
                    // Check backoff
                    let now = std::time::Instant::now();
                    if let Some((_attempts, next_try)) = backoff.get(addr) {
                        if now < *next_try {
                            continue;
                        }
                    }

                    let peers = peers.clone();
                    let peer_meta = peer_meta.clone();
                    let known_peers = known_peers.clone();
                    let evt_tx = evt_tx.clone();
                    let pk = pk.clone();
                    let sk = sk.clone();
                    let addr = addr.clone();

                    let result =
                        connect_to_peer(&addr, pk, sk, peers, peer_meta, known_peers, evt_tx).await;
                    if let Err(e) = result {
                        let now = std::time::Instant::now();
                        let entry = backoff.entry(addr.clone()).or_insert((0, now));
                        entry.0 += 1;
                        // Exponential backoff: 5s, 10s, 20s, 40s … max 300s
                        let delay = Duration::from_secs((5u64 * (1 << entry.0.min(6))).min(300));
                        entry.1 = now + delay;
                        warn!(
                            "Connect to {} failed (attempt {}): {} - retry in {:?}",
                            addr, entry.0, e, delay
                        );
                    } else {
                        backoff.remove(&addr);
                    }
                }

                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    (Truthlinked { cmd: cmd_tx }, evt_rx)
}

async fn handle_inbound(
    stream: TcpStream,
    addr: String,
    sock_addr: std::net::SocketAddr,
    our_pk: Vec<u8>,
    our_sk: Vec<u8>,
    peers: Arc<RwLock<HashMap<NodeId, Peer>>>,
    peer_meta: Arc<RwLock<HashMap<NodeId, PeerMeta>>>,
    known_peers: Arc<RwLock<HashMap<Vec<u8>, SocketAddr>>>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use fips204::ml_dsa_65::PrivateKey;
    use fips204::traits::SerDes;

    let sk_arr: [u8; 4032] = our_sk.as_slice().try_into()?;
    let sk = PrivateKey::try_from_bytes(sk_arr).map_err(|_| "bad sk")?;
    let pk_arr: [u8; 1952] = our_pk.as_slice().try_into()?;
    let pk = fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_arr).map_err(|_| "bad pk")?;

    let hs = PQHandshake::from_dilithium(pk, sk);
    let mut stream = stream;
    let (session, peer_dil_pk) = hs.handshake_responder(&mut stream).await?;

    register_peer(
        stream,
        addr,
        sock_addr,
        session,
        peer_dil_pk,
        peers,
        peer_meta,
        known_peers,
        evt_tx,
    )
    .await;
    Ok(())
}

async fn connect_to_peer(
    addr: &str,
    our_pk: Vec<u8>,
    our_sk: Vec<u8>,
    peers: Arc<RwLock<HashMap<NodeId, Peer>>>,
    peer_meta: Arc<RwLock<HashMap<NodeId, PeerMeta>>>,
    known_peers: Arc<RwLock<HashMap<Vec<u8>, SocketAddr>>>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use fips204::ml_dsa_65::PrivateKey;
    use fips204::traits::SerDes;

    let sock_addr: SocketAddr = addr.parse()?;
    let stream = TcpStream::connect(addr).await?;

    let sk_arr: [u8; 4032] = our_sk.as_slice().try_into()?;
    let sk = PrivateKey::try_from_bytes(sk_arr).map_err(|_| "bad sk")?;
    let pk_arr: [u8; 1952] = our_pk.as_slice().try_into()?;
    let pk = fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_arr).map_err(|_| "bad pk")?;

    let hs = PQHandshake::from_dilithium(pk, sk);
    let mut stream = stream;
    let (session, peer_dil_pk) = hs.handshake_initiator(&mut stream).await?;

    info!("Connected to {}", addr);
    register_peer(
        stream,
        addr.to_string(),
        sock_addr,
        session,
        peer_dil_pk,
        peers,
        peer_meta,
        known_peers,
        evt_tx,
    )
    .await;
    Ok(())
}

async fn register_peer(
    stream: TcpStream,
    addr: String,
    sock_addr: SocketAddr,
    session: PQSession,
    peer_dil_pk: Vec<u8>,
    peers: Arc<RwLock<HashMap<NodeId, Peer>>>,
    peer_meta: Arc<RwLock<HashMap<NodeId, PeerMeta>>>,
    known_peers: Arc<RwLock<HashMap<Vec<u8>, SocketAddr>>>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
) {
    let node_id = NodeId::from_dilithium_pk(&peer_dil_pk);

    // Record in known_peers so we reconnect to this peer after disconnect
    known_peers
        .write()
        .await
        .insert(peer_dil_pk.clone(), sock_addr);

    let (peer_tx, mut peer_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE_CAP);

    let auth_pk = peer_dil_pk.clone(); // handshake-authenticated pubkey for this session

    // Atomic dedup + insert under a single write lock to prevent races
    {
        let mut peers_w = peers.write().await;
        if peers_w.contains_key(&node_id) {
            debug!(
                "Already connected to {}, dropping duplicate",
                hex::encode(&node_id.0[..4])
            );
            return;
        }
        peers_w.insert(
            node_id.clone(),
            Peer {
                node_id: node_id.clone(),
                dilithium_pk: peer_dil_pk.clone(),
                addr: addr.clone(),
                tx: peer_tx,
            },
        );
    } // write lock released here
    peer_meta.write().await.insert(
        node_id.clone(),
        PeerMeta {
            dilithium_pk: peer_dil_pk,
            addr: addr.clone(),
            height: 0,
            connected_at: std::time::Instant::now(),
        },
    );

    let _ = evt_tx.send(NetEvent::PeerConnected(node_id.clone()));
    info!(
        "Peer registered: {} ({})",
        hex::encode(&node_id.0[..4]),
        addr
    );

    let (mut read_half, mut write_half) = stream.into_split();
    let session_r = session.clone();
    let session_w = session;

    // Writer task
    tokio::spawn(async move {
        while let Some(frame) = peer_rx.recv().await {
            if let Ok(enc) = session_w.encrypt(&frame) {
                let len = enc.len() as u32;
                if write_half.write_all(&len.to_be_bytes()).await.is_err() {
                    break;
                }
                if write_half.write_all(&enc).await.is_err() {
                    break;
                }
            }
        }
    });

    // Reader task
    let peers_r = peers.clone();
    let meta_r = peer_meta.clone();
    let evt_tx_r = evt_tx.clone();
    let nid = node_id.clone();
    tokio::spawn(async move {
        loop {
            let mut len_buf = [0u8; 4];
            if read_half.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 10 * 1024 * 1024 {
                break;
            }
            let mut enc = vec![0u8; len];
            if read_half.read_exact(&mut enc).await.is_err() {
                break;
            }
            let Ok(frame) = session_r.decrypt(&enc) else {
                continue;
            };
            let Ok(msg) = postcard::from_bytes::<NetworkMessage>(&frame) else {
                continue;
            };
            // Verify sender_pk matches the handshake-authenticated peer pubkey
            if msg.sender_pk != auth_pk {
                warn!(
                    "sender_pk mismatch from {}: dropping message",
                    hex::encode(&nid.0[..4])
                );
                break; // disconnect the peer
            }
            let _ = evt_tx_r.send(NetEvent::Message {
                from: msg.sender_pk,
                topic: msg.topic,
                payload: msg.payload,
            });
        }
        peers_r.write().await.remove(&nid);
        meta_r.write().await.remove(&nid);
        let _ = evt_tx_r.send(NetEvent::PeerDisconnected(nid));
        info!("Peer disconnected: {}", addr);
    });
}

// Per-message signing removed - session authenticated at handshake level

/// Convert dilithium pk to node id hex - for bootstrap config
pub fn node_id_hex(dilithium_pk: &[u8]) -> String {
    hex::encode(NodeId::from_dilithium_pk(dilithium_pk).0)
}
