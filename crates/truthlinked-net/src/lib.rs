//! Post-quantum networking primitives for TruthLinked validators and nodes.
//!
//! The networking layer owns peer discovery, ingress handling, authenticated
//! post-quantum handshakes, encrypted transport sessions, and TCP socket tuning.
//! Transport changes must preserve peer identity and avoid blocking consensus
//! progress under bursty transaction load.

pub mod discovery;
pub mod ingress;
pub mod network;
pub mod pq_transport;
pub mod tcp_config;
