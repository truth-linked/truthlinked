//! Truthlinked Net Src Ingress
//!
//! Owns network ingress validation before messages reach consensus.
//! Transport changes must avoid blocking consensus progress and preserve authenticated peer identity.

// Ingress Server - Single Entry Point for All Transactions
// Validator ingress ports are configured per node.
// Receives raw transactions from users/clients

use async_trait::async_trait;
use futures_util::StreamExt;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::{accept_async_with_config, tungstenite::Message};
use truthlinked_core::pq_execution::Transaction;
use truthlinked_governance::params as gp;

struct MessageRateLimiter {
    timestamps: VecDeque<Instant>,
    max_per_sec: u32,
}

impl MessageRateLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self {
            timestamps: VecDeque::new(),
            max_per_sec,
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(1);
        while self
            .timestamps
            .front()
            .map_or(false, |t| now.duration_since(*t) >= window)
        {
            self.timestamps.pop_front();
        }
        if self.timestamps.len() >= self.max_per_sec as usize {
            return false;
        }
        self.timestamps.push_back(now);
        true
    }
}

#[inline]
fn message_too_large(len: usize) -> bool {
    len > gp::get_usize(gp::PARAM_INGRESS_MAX_MESSAGE_BYTES)
}

pub struct IngressServer {
    port: u16,
    handler: Arc<dyn IngressHandler>,
}

impl IngressServer {
    pub fn new(port: u16, handler: Arc<dyn IngressHandler>) -> Self {
        Self { port, handler }
    }

    /// Start ingress server - accepts WebSocket connections from clients
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        let connection_limiter = Arc::new(Semaphore::new(gp::get_usize(
            gp::PARAM_INGRESS_MAX_CONNECTIONS,
        )));
        tracing::info!(" Ingress server listening on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let handler = self.handler.clone();
            let limiter = connection_limiter.clone();

            tokio::spawn(async move {
                let permit = match limiter.try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!("Ingress connection rejected (capacity): {}", peer_addr);
                        truthlinked_state::metrics::global().inc_ingress_rejected_total();
                        return;
                    }
                };

                truthlinked_state::metrics::global().inc_ingress_connections_total();
                truthlinked_state::metrics::global().inc_ingress_connections();
                tracing::debug!(" Client connected: {}", peer_addr);

                let ws_config = WebSocketConfig {
                    max_message_size: Some(gp::get_usize(gp::PARAM_INGRESS_MAX_MESSAGE_BYTES)),
                    max_frame_size: Some(gp::get_usize(gp::PARAM_INGRESS_MAX_MESSAGE_BYTES)),
                    ..Default::default()
                };

                match accept_async_with_config(stream, Some(ws_config)).await {
                    Ok(ws) => {
                        if let Err(e) = handle_client_connection(ws, handler).await {
                            tracing::error!("Client connection error: {}", e);
                        }
                    }
                    Err(e) => tracing::error!("WebSocket handshake failed: {}", e),
                }

                drop(permit);
                truthlinked_state::metrics::global().dec_ingress_connections();
            });
        }
    }
}

/// Handle client connection - receives transactions from users
#[async_trait]
pub trait IngressHandler: Send + Sync {
    async fn submit_transaction(&self, tx: Transaction) -> Result<[u8; 32], String>;
}

async fn handle_client_connection(
    mut ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    handler: Arc<dyn IngressHandler>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rate_limiter =
        MessageRateLimiter::new(gp::get_u32(gp::PARAM_INGRESS_MAX_MESSAGES_PER_SECOND));

    while let Some(msg) = ws.next().await {
        match msg? {
            Message::Binary(data) => {
                if message_too_large(data.len()) {
                    tracing::warn!("Ingress message too large: {} bytes", data.len());
                    truthlinked_state::metrics::global().inc_ingress_rejected_total();
                    let _ = ws
                        .close(Some(CloseFrame {
                            code: CloseCode::Size,
                            reason: "message too big".into(),
                        }))
                        .await;
                    break;
                }

                if !rate_limiter.allow() {
                    tracing::warn!("Ingress rate limit exceeded");
                    truthlinked_state::metrics::global().inc_ingress_rejected_total();
                    let _ = ws
                        .close(Some(CloseFrame {
                            code: CloseCode::Policy,
                            reason: "rate limit exceeded".into(),
                        }))
                        .await;
                    break;
                }

                truthlinked_state::metrics::global().inc_ingress_messages_total();

                // Deserialize transaction
                match postcard::from_bytes::<Transaction>(&data) {
                    Ok(tx) => {
                        tracing::debug!(" Received TX from client");
                        // First validator to see TX - no prior signature
                        truthlinked_state::metrics::global().inc_tx_submitted();
                        let _ = handler.submit_transaction(tx).await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to deserialize TX: {}", e);
                        truthlinked_state::metrics::global().inc_ingress_rejected_total();
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn ingress_rate_limiter_blocks_after_max() {
        let mut limiter = MessageRateLimiter::new(3);
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());

        // Simulate time passing by clearing old timestamps
        std::thread::sleep(Duration::from_millis(1100));
        assert!(limiter.allow());
    }

    #[test]
    fn ingress_message_too_large_guard() {
        let _ = truthlinked_state::pq_execution::State::genesis();
        assert!(!message_too_large(gp::get_usize(
            gp::PARAM_INGRESS_MAX_MESSAGE_BYTES
        )));
        assert!(message_too_large(
            gp::get_usize(gp::PARAM_INGRESS_MAX_MESSAGE_BYTES) + 1
        ));
    }
}
