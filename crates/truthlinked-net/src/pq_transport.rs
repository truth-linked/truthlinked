//! Truthlinked Net Src Pq Transport
//!
//! Owns post-quantum encrypted transport handshakes and framing.
//! Transport changes must avoid blocking consensus progress and preserve authenticated peer identity.

// Post-Quantum Transport Layer - Pure Kyber encryption for libp2p
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips204::ml_dsa_65::{
    self, PrivateKey as DilithiumPrivateKey, PublicKey as DilithiumPublicKey,
};
use fips204::traits::{SerDes as DilithiumSerDes, Signer, Verifier};
use sha2::{Digest, Sha256};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use truthlinked_governance::params as gp;

/// Post-quantum secure session using Kyber + AES-GCM
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct PQSession {
    shared_secret: [u8; 32],
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_nonce_counter: Arc<AtomicU64>,
    rx_nonce_counter: Arc<AtomicU64>,
    created_at: Arc<std::sync::RwLock<std::time::Instant>>,
}

impl PQSession {
    /// Initiator side: encapsulate and derive keys
    pub fn new_initiator(peer_encaps_key: &[u8; 1184]) -> Result<(Self, [u8; 1088]), String> {
        let ek = ml_kem_768::EncapsKey::try_from_bytes(*peer_encaps_key)
            .map_err(|_| "Invalid encaps key")?;

        let (ssk, ct) = ek.try_encaps().map_err(|_| "Encapsulation failed")?;

        let shared_secret = ssk.into_bytes();

        // Derive keys directly from shared secret (no additional session nonce needed)
        // The Kyber shared secret is already unique per session
        let (tx_key, rx_key) = Self::derive_keys(&shared_secret, true);

        Ok((
            Self {
                shared_secret,
                tx_key,
                rx_key,
                tx_nonce_counter: Arc::new(AtomicU64::new(0)),
                rx_nonce_counter: Arc::new(AtomicU64::new(0)),
                created_at: Arc::new(std::sync::RwLock::new(std::time::Instant::now())),
            },
            ct.into_bytes(),
        ))
    }

    /// Responder side: decapsulate and derive keys
    pub fn new_responder(
        decaps_key: &ml_kem_768::DecapsKey,
        ciphertext: &[u8; 1088],
    ) -> Result<Self, String> {
        let ct = ml_kem_768::CipherText::try_from_bytes(*ciphertext)
            .map_err(|_| "Invalid ciphertext")?;

        let ssk = decaps_key
            .try_decaps(&ct)
            .map_err(|_| "Decapsulation failed")?;

        let shared_secret = ssk.into_bytes();

        // Derive keys directly from shared secret (no additional session nonce needed)
        // The Kyber shared secret is already unique per session
        let (tx_key, rx_key) = Self::derive_keys(&shared_secret, false);

        Ok(Self {
            shared_secret,
            tx_key,
            rx_key,
            tx_nonce_counter: Arc::new(AtomicU64::new(0)),
            rx_nonce_counter: Arc::new(AtomicU64::new(0)),
            created_at: Arc::new(std::sync::RwLock::new(std::time::Instant::now())),
        })
    }

    /// Derive separate TX/RX keys from shared secret
    pub fn derive_keys(shared_secret: &[u8; 32], is_initiator: bool) -> ([u8; 32], [u8; 32]) {
        let mut hasher = Sha256::new();
        hasher.update(b"truthlinked-pq-transport-v1");
        hasher.update(shared_secret);
        hasher.update(if is_initiator {
            b"initiator"
        } else {
            b"responder"
        });
        let master = hasher.finalize();

        let mut tx_hasher = Sha256::new();
        tx_hasher.update(&master);
        tx_hasher.update(b"tx");
        let tx_key: [u8; 32] = tx_hasher.finalize().into();

        let mut rx_hasher = Sha256::new();
        rx_hasher.update(&master);
        rx_hasher.update(b"rx");
        let rx_key: [u8; 32] = rx_hasher.finalize().into();

        if is_initiator {
            (tx_key, rx_key)
        } else {
            (rx_key, tx_key)
        }
    }

    /// Encrypt data using AES-256-GCM with Kyber-derived key
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let cipher = Aes256Gcm::new_from_slice(&self.tx_key)
            .map_err(|e| format!("Cipher init failed: {}", e))?;

        let nonce_val = self.tx_nonce_counter.fetch_add(1, Ordering::SeqCst);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&nonce_val.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data using AES-256-GCM with Kyber-derived key
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("Data too short".into());
        }

        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let cipher = Aes256Gcm::new_from_slice(&self.rx_key)
            .map_err(|e| format!("Cipher init failed: {}", e))?;

        let nonce = Nonce::from_slice(&data[..12]);

        cipher
            .decrypt(nonce, &data[12..])
            .map_err(|e| format!("Decryption failed: {}", e))
    }

    /// Check if session needs key rotation (5 minutes)
    pub fn needs_rotation(&self) -> bool {
        if let Ok(created) = self.created_at.read() {
            created.elapsed() > std::time::Duration::from_secs(300)
        } else {
            false
        }
    }

    /// Rotate to new session keys (called after successful re-keying)
    pub fn rotate_keys(&mut self, new_shared_secret: [u8; 32], is_initiator: bool) {
        let (tx_key, rx_key) = Self::derive_keys(&new_shared_secret, is_initiator);

        self.shared_secret = new_shared_secret;
        self.tx_key = tx_key;
        self.rx_key = rx_key;
        self.tx_nonce_counter.store(0, Ordering::SeqCst);
        self.rx_nonce_counter.store(0, Ordering::SeqCst);

        if let Ok(mut created) = self.created_at.write() {
            *created = std::time::Instant::now();
        }
    }
}

/// Handshake protocol with authentication
/// Returns (PQSession, authenticated_peer_id)
pub struct PQHandshake {
    pub encaps_key: ml_kem_768::EncapsKey,
    pub decaps_key: ml_kem_768::DecapsKey,
    pub dilithium_pk: DilithiumPublicKey,
    pub dilithium_sk: DilithiumPrivateKey,
}

impl PQHandshake {
    pub fn new() -> Self {
        let (ek, dk) = ml_kem_768::KG::try_keygen().expect("Kyber keygen failed");
        let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut rand::thread_rng())
            .expect("Dilithium keygen failed");
        Self {
            encaps_key: ek,
            decaps_key: dk,
            dilithium_pk: pk,
            dilithium_sk: sk,
        }
    }

    pub fn from_dilithium(
        pk: fips204::ml_dsa_65::PublicKey,
        sk: fips204::ml_dsa_65::PrivateKey,
    ) -> Self {
        let (ek, dk) = fips203::ml_kem_768::KG::try_keygen().expect("Kyber keygen failed");
        Self {
            encaps_key: ek,
            decaps_key: dk,
            dilithium_pk: pk,
            dilithium_sk: sk,
        }
    }
    pub fn from_keypair(keypair: &truthlinked_core::pq_identity::DualKeypair) -> Self {
        Self {
            encaps_key: keypair.kyber_ek.clone(),
            decaps_key: keypair.kyber_dk.clone(),
            dilithium_pk: keypair.dilithium_pk.clone(),
            dilithium_sk: keypair.dilithium_sk.clone(),
        }
    }

    /// Perform handshake as initiator with EPHEMERAL Kyber keys + STATIC Dilithium authentication
    /// Returns (PQSession, authenticated_peer_dilithium_pubkey)
    /// CRITICAL: Uses ephemeral Kyber keys for forward secrecy
    pub async fn handshake_initiator<S>(
        &self,
        stream: &mut S,
    ) -> Result<(PQSession, Vec<u8>), io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // CRITICAL: Generate EPHEMERAL Kyber keypair for this session only
        let (ephemeral_ek, ephemeral_dk) = ml_kem_768::KG::try_keygen()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Ephemeral keygen failed"))?;

        // Send our EPHEMERAL encaps key + STATIC Dilithium public key
        let our_ephemeral_ek = ephemeral_ek.clone().into_bytes();
        let our_dilithium_pk = self.dilithium_pk.clone().into_bytes();

        stream.write_u32(our_ephemeral_ek.len() as u32).await?;
        stream.write_all(&our_ephemeral_ek).await?;
        stream.write_u32(our_dilithium_pk.len() as u32).await?;
        stream.write_all(&our_dilithium_pk).await?;

        // Sign EPHEMERAL key with STATIC Dilithium key to prove identity
        let mut msg = Vec::new();
        msg.extend_from_slice(b"truthlinked-ephemeral-handshake-v2");
        msg.extend_from_slice(&our_ephemeral_ek);
        let signature = self
            .dilithium_sk
            .try_sign(&msg, b"ephemeral-handshake")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Sign failed: {:?}", e)))?;

        stream.write_u32(signature.len() as u32).await?;
        stream.write_all(&signature).await?;
        stream.flush().await?;

        // Receive peer's EPHEMERAL encaps key + STATIC Dilithium public key + signature
        let ek_len = stream.read_u32().await?;
        if ek_len != 1184 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid ephemeral key length",
            ));
        }
        let mut peer_ephemeral_ek = [0u8; 1184];
        stream.read_exact(&mut peer_ephemeral_ek).await?;

        let pk_len = stream.read_u32().await?;
        if pk_len != 1952 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid pubkey length",
            ));
        }
        let mut peer_dilithium_pk = [0u8; 1952];
        stream.read_exact(&mut peer_dilithium_pk).await?;

        let sig_len = stream.read_u32().await?;
        if sig_len != 3309 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid signature length",
            ));
        }
        let mut peer_signature = [0u8; 3309];
        stream.read_exact(&mut peer_signature).await?;

        // Verify peer's STATIC Dilithium signature on their EPHEMERAL key
        let mut peer_msg = Vec::new();
        peer_msg.extend_from_slice(b"truthlinked-ephemeral-handshake-v2");
        peer_msg.extend_from_slice(&peer_ephemeral_ek);

        let peer_pk = DilithiumPublicKey::try_from_bytes(peer_dilithium_pk)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid peer pubkey"))?;

        if !peer_pk.verify(&peer_msg, &peer_signature, b"ephemeral-handshake") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Ephemeral handshake authentication failed",
            ));
        }

        // Encapsulate using peer's EPHEMERAL key (forward secrecy!)
        let peer_ek = ml_kem_768::EncapsKey::try_from_bytes(peer_ephemeral_ek).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid peer ephemeral encaps key",
            )
        })?;

        let (ssk1, ct1) = peer_ek
            .try_encaps()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encapsulation 1 failed"))?;

        // Send our ciphertext to peer
        let ct1_bytes = ct1.into_bytes();
        stream.write_u32(ct1_bytes.len() as u32).await?;
        stream.write_all(&ct1_bytes).await?;
        stream.flush().await?;

        // Receive peer's ciphertext (they encapsulate with our ephemeral key)
        let ct2_len = stream.read_u32().await?;
        if ct2_len != 1088 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid ciphertext 2 length",
            ));
        }
        let mut ct2_bytes = [0u8; 1088];
        stream.read_exact(&mut ct2_bytes).await?;

        // Decapsulate peer's ciphertext with our ephemeral private key
        let ct2 = ml_kem_768::CipherText::try_from_bytes(ct2_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid ciphertext 2"))?;

        let ssk2 = ephemeral_dk
            .try_decaps(&ct2)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Decapsulation 2 failed"))?;

        // Combine both shared secrets for double ratchet-like security
        let shared_secret1 = ssk1.into_bytes();
        let shared_secret2 = ssk2.into_bytes();

        // Generate session nonce for additional entropy
        let mut session_nonce = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut session_nonce);

        stream.write_all(&session_nonce).await?;
        stream.flush().await?;

        let mut peer_session_nonce = [0u8; 32];
        stream.read_exact(&mut peer_session_nonce).await?;

        // CRITICAL: Use HKDF for secure nonce mixing (prevents weak RNG attacks)
        // Use lexicographic order for consistency
        use hkdf::Hkdf;
        use sha2::Sha256;

        let (nonce_first, nonce_second) = if session_nonce < peer_session_nonce {
            (session_nonce, peer_session_nonce)
        } else {
            (peer_session_nonce, session_nonce)
        };

        let hk = Hkdf::<Sha256>::new(None, &[nonce_first, nonce_second].concat());
        let mut final_session_nonce = [0u8; 32];
        hk.expand(b"truthlinked-session-nonce-v2", &mut final_session_nonce)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "HKDF expand failed"))?;

        // Derive master key from BOTH ephemeral shared secrets + session nonces
        // CRITICAL: Use lexicographic order of pubkeys for consistency
        let (pk_first, pk_second) = if our_dilithium_pk < peer_dilithium_pk {
            (&our_dilithium_pk, &peer_dilithium_pk)
        } else {
            (&peer_dilithium_pk, &our_dilithium_pk)
        };

        let mut hasher = Sha256::new();
        hasher.update(b"truthlinked-pq-ephemeral-v2");
        hasher.update(&shared_secret1);
        hasher.update(&shared_secret2);
        hasher.update(&final_session_nonce);
        hasher.update(pk_first);
        hasher.update(pk_second);
        let master = hasher.finalize();

        // Derive directional keys (initiator sends on A→B, receives on B→A)
        let mut tx_hasher = Sha256::new();
        tx_hasher.update(&master);
        tx_hasher.update(b"A-to-B");
        let tx_key: [u8; 32] = tx_hasher.finalize().into();

        let mut rx_hasher = Sha256::new();
        rx_hasher.update(&master);
        rx_hasher.update(b"B-to-A");
        let rx_key: [u8; 32] = rx_hasher.finalize().into();

        // Use combined shared secret for session (for potential rekeying)
        let mut combined_secret = [0u8; 32];
        for i in 0..32 {
            combined_secret[i] = shared_secret1[i] ^ shared_secret2[i];
        }

        let session = PQSession {
            shared_secret: combined_secret,
            tx_key,
            rx_key,
            tx_nonce_counter: Arc::new(AtomicU64::new(0)),
            rx_nonce_counter: Arc::new(AtomicU64::new(0)),
            created_at: Arc::new(std::sync::RwLock::new(std::time::Instant::now())),
        };

        tracing::info!(" Ephemeral handshake completed as initiator with forward secrecy");
        Ok((session, peer_dilithium_pk.to_vec()))
    }

    /// Perform handshake as responder with EPHEMERAL Kyber keys + STATIC Dilithium authentication
    /// Returns (PQSession, authenticated_peer_dilithium_pubkey)
    /// CRITICAL: Uses ephemeral Kyber keys for forward secrecy
    pub async fn handshake_responder<S>(
        &self,
        stream: &mut S,
    ) -> Result<(PQSession, Vec<u8>), io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Receive peer's EPHEMERAL encaps key + STATIC Dilithium public key + signature
        let ek_len = stream.read_u32().await?;
        if ek_len != 1184 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid ephemeral key length",
            ));
        }
        let mut peer_ephemeral_ek = [0u8; 1184];
        stream.read_exact(&mut peer_ephemeral_ek).await?;

        let pk_len = stream.read_u32().await?;
        if pk_len != 1952 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid pubkey length",
            ));
        }
        let mut peer_dilithium_pk = [0u8; 1952];
        stream.read_exact(&mut peer_dilithium_pk).await?;

        let sig_len = stream.read_u32().await?;
        if sig_len != 3309 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid signature length",
            ));
        }
        let mut peer_signature = [0u8; 3309];
        stream.read_exact(&mut peer_signature).await?;

        // Verify peer's STATIC Dilithium signature on their EPHEMERAL key
        let mut peer_msg = Vec::new();
        peer_msg.extend_from_slice(b"truthlinked-ephemeral-handshake-v2");
        peer_msg.extend_from_slice(&peer_ephemeral_ek);

        let peer_pk = DilithiumPublicKey::try_from_bytes(peer_dilithium_pk)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid peer pubkey"))?;

        if !peer_pk.verify(&peer_msg, &peer_signature, b"ephemeral-handshake") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Ephemeral handshake authentication failed",
            ));
        }

        // CRITICAL: Generate EPHEMERAL Kyber keypair for this session only
        let (ephemeral_ek, ephemeral_dk) = ml_kem_768::KG::try_keygen()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Ephemeral keygen failed"))?;

        // Send our EPHEMERAL encaps key + STATIC Dilithium public key
        let our_ephemeral_ek = ephemeral_ek.clone().into_bytes();
        let our_dilithium_pk = self.dilithium_pk.clone().into_bytes();

        stream.write_u32(our_ephemeral_ek.len() as u32).await?;
        stream.write_all(&our_ephemeral_ek).await?;
        stream.write_u32(our_dilithium_pk.len() as u32).await?;
        stream.write_all(&our_dilithium_pk).await?;

        // Sign our EPHEMERAL encaps key with STATIC Dilithium key
        let mut msg = Vec::new();
        msg.extend_from_slice(b"truthlinked-ephemeral-handshake-v2");
        msg.extend_from_slice(&our_ephemeral_ek);
        let signature = self
            .dilithium_sk
            .try_sign(&msg, b"ephemeral-handshake")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Sign failed: {:?}", e)))?;

        stream.write_u32(signature.len() as u32).await?;
        stream.write_all(&signature).await?;
        stream.flush().await?;

        // Receive peer's ciphertext (they encapsulate with our ephemeral key)
        let ct1_len = stream.read_u32().await?;
        if ct1_len != 1088 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid ciphertext 1 length",
            ));
        }
        let mut ct1_bytes = [0u8; 1088];
        stream.read_exact(&mut ct1_bytes).await?;

        // Decapsulate peer's ciphertext with our ephemeral private key
        let ct1 = ml_kem_768::CipherText::try_from_bytes(ct1_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid ciphertext 1"))?;

        let ssk1 = ephemeral_dk
            .try_decaps(&ct1)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Decapsulation 1 failed"))?;

        // Encapsulate using peer's EPHEMERAL key (forward secrecy!)
        let peer_ek = ml_kem_768::EncapsKey::try_from_bytes(peer_ephemeral_ek).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid peer ephemeral encaps key",
            )
        })?;

        let (ssk2, ct2) = peer_ek
            .try_encaps()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encapsulation 2 failed"))?;

        // Send our ciphertext to peer
        let ct2_bytes = ct2.into_bytes();
        stream.write_u32(ct2_bytes.len() as u32).await?;
        stream.write_all(&ct2_bytes).await?;
        stream.flush().await?;

        // Combine both shared secrets for double ratchet-like security
        let shared_secret1 = ssk1.into_bytes();
        let shared_secret2 = ssk2.into_bytes();

        // Session nonce exchange
        let mut session_nonce = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut session_nonce);

        // Receive peer's session nonce first (initiator sends first)
        let mut peer_session_nonce = [0u8; 32];
        stream.read_exact(&mut peer_session_nonce).await?;

        // Send our session nonce
        stream.write_all(&session_nonce).await?;
        stream.flush().await?;

        // CRITICAL: Use HKDF for secure nonce mixing (prevents weak RNG attacks)
        // Use lexicographic order for consistency
        use hkdf::Hkdf;
        use sha2::Sha256;

        let (nonce_first, nonce_second) = if session_nonce < peer_session_nonce {
            (session_nonce, peer_session_nonce)
        } else {
            (peer_session_nonce, session_nonce)
        };

        let hk = Hkdf::<Sha256>::new(None, &[nonce_first, nonce_second].concat());
        let mut final_session_nonce = [0u8; 32];
        hk.expand(b"truthlinked-session-nonce-v2", &mut final_session_nonce)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "HKDF expand failed"))?;

        // Derive master key from BOTH ephemeral shared secrets + session nonces
        // CRITICAL: Use lexicographic order of pubkeys for consistency
        let (pk_first, pk_second) = if our_dilithium_pk < peer_dilithium_pk {
            (&our_dilithium_pk, &peer_dilithium_pk)
        } else {
            (&peer_dilithium_pk, &our_dilithium_pk)
        };

        let mut hasher = Sha256::new();
        hasher.update(b"truthlinked-pq-ephemeral-v2");
        hasher.update(&shared_secret1);
        hasher.update(&shared_secret2);
        hasher.update(&final_session_nonce);
        hasher.update(pk_first);
        hasher.update(pk_second);
        let master = hasher.finalize();

        // Derive directional keys (responder sends on B→A, receives on A→B)
        let mut tx_hasher = Sha256::new();
        tx_hasher.update(&master);
        tx_hasher.update(b"B-to-A");
        let tx_key: [u8; 32] = tx_hasher.finalize().into();

        let mut rx_hasher = Sha256::new();
        rx_hasher.update(&master);
        rx_hasher.update(b"A-to-B");
        let rx_key: [u8; 32] = rx_hasher.finalize().into();

        // Use combined shared secret for session (for potential rekeying)
        let mut combined_secret = [0u8; 32];
        for i in 0..32 {
            combined_secret[i] = shared_secret1[i] ^ shared_secret2[i];
        }

        let session = PQSession {
            shared_secret: combined_secret,
            tx_key,
            rx_key,
            tx_nonce_counter: Arc::new(AtomicU64::new(0)),
            rx_nonce_counter: Arc::new(AtomicU64::new(0)),
            created_at: Arc::new(std::sync::RwLock::new(std::time::Instant::now())),
        };

        tracing::info!(" Ephemeral handshake completed as responder with forward secrecy");
        Ok((session, peer_dilithium_pk.to_vec()))
    }
}

/// Encrypted stream wrapper
pub struct PQStream<S> {
    pub(crate) inner: S,
    pub(crate) session: PQSession,
}

impl<S> PQStream<S>
where
    S: AsyncWrite + Unpin,
{
    pub async fn write_encrypted(&mut self, data: &[u8]) -> Result<(), io::Error> {
        if data.len() > gp::get_usize(gp::PARAM_CHUNK_SIZE) {
            // Send in chunks
            let num_chunks = (data.len() + gp::get_usize(gp::PARAM_CHUNK_SIZE) - 1)
                / gp::get_usize(gp::PARAM_CHUNK_SIZE);
            self.inner.write_u32(num_chunks as u32).await?;

            for chunk in data.chunks(gp::get_usize(gp::PARAM_CHUNK_SIZE)) {
                let encrypted = self
                    .session
                    .encrypt(chunk)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                self.inner.write_u32(encrypted.len() as u32).await?;
                self.inner.write_all(&encrypted).await?;
            }
            self.inner.flush().await?;
        } else {
            // Single message
            self.inner.write_u32(1).await?;

            let encrypted = self
                .session
                .encrypt(data)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            self.inner.write_u32(encrypted.len() as u32).await?;
            self.inner.write_all(&encrypted).await?;
            self.inner.flush().await?;
        }
        Ok(())
    }
}

impl<S> PQStream<S>
where
    S: AsyncRead + Unpin,
{
    pub async fn read_encrypted(&mut self) -> Result<Vec<u8>, io::Error> {
        // Read number of chunks
        let num_chunks = self.inner.read_u32().await?;

        if num_chunks == 0 || num_chunks > 10000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid chunk count",
            ));
        }

        let mut result = Vec::new();

        for _ in 0..num_chunks {
            let len = self.inner.read_u32().await?;
            if len > 10 * 1024 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Chunk too large",
                ));
            }

            let mut encrypted = vec![0u8; len as usize];
            self.inner.read_exact(&mut encrypted).await?;

            let decrypted = self
                .session
                .decrypt(&encrypted)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            result.extend_from_slice(&decrypted);
        }

        Ok(result)
    }
}

impl<S> PQStream<S> {
    pub fn new(inner: S, session: PQSession) -> Self {
        Self { inner, session }
    }
}
