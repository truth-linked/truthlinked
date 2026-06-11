//! Post-quantum identity helpers for TruthLinked accounts.
//!
//! The module provides ML-DSA signing, ML-KEM key material, deterministic account
//! derivation, and keyfile helpers shared by node and CLI code. Signing contexts
//! are domain-separated through constants from `truthlinked_core::constants`.

use fips203::ml_kem_768;
use fips203::traits::SerDes as KyberSerDes;
use fips203::traits::{Decaps, Encaps, KeyGen};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::constants::{GENERIC_SIGN_CONTEXT, TX_SIGN_CONTEXT};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQKeypair {
    pub secret: Vec<u8>,
    pub public: Vec<u8>,
}

#[derive(Clone)]
pub struct DualKeypair {
    pub dilithium_pk: ml_dsa_65::PublicKey,
    pub dilithium_sk: ml_dsa_65::PrivateKey,
    pub kyber_ek: ml_kem_768::EncapsKey,
    pub kyber_dk: ml_kem_768::DecapsKey,
    pub mnemonic: String,
}

impl PQKeypair {
    pub fn generate() -> Self {
        let (pk, sk) =
            ml_dsa_65::try_keygen_with_rng(&mut rand::thread_rng()).expect("Key generation failed");

        Self {
            secret: sk.into_bytes().to_vec(),
            public: pk.into_bytes().to_vec(),
        }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut rng).expect("Key generation failed");

        Self {
            secret: sk.into_bytes().to_vec(),
            public: pk.into_bytes().to_vec(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sk_bytes: [u8; 4032] = self
            .secret
            .as_slice()
            .try_into()
            .expect("Invalid secret key length");
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).expect("Invalid secret key");

        sk.try_sign(message, GENERIC_SIGN_CONTEXT)
            .expect("Signing failed")
            .to_vec()
    }

    pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        let pk_bytes: [u8; 1952] = match public_key.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sig_bytes: [u8; 3309] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        if let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes) {
            pk.verify(message, &sig_bytes, GENERIC_SIGN_CONTEXT)
        } else {
            false
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize: {}", e))?;
        fs::write(path, json).map_err(|e| format!("Failed to write file: {}", e))?;
        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;
        serde_json::from_str(&json).map_err(|e| format!("Failed to deserialize: {}", e))
    }
}

impl DualKeypair {
    pub fn generate() -> Self {
        let (pk, sk) =
            ml_dsa_65::try_keygen_with_rng(&mut rand::thread_rng()).expect("Key generation failed");
        let (ek, dk) = ml_kem_768::KG::try_keygen().expect("Kyber key generation failed");

        Self {
            dilithium_pk: pk,
            dilithium_sk: sk,
            kyber_ek: ek,
            kyber_dk: dk,
            mnemonic: String::from("random-generation"),
        }
    }

    pub fn from_mnemonic(mnemonic: String) -> Self {
        Self::from_mnemonic_with_passphrase(mnemonic, "")
    }

    pub fn from_mnemonic_with_passphrase(mnemonic: String, passphrase: &str) -> Self {
        let seed = Self::mnemonic_to_seed(&mnemonic, passphrase);

        let dilithium_seed = Self::derive_child_seed(&seed, b"dilithium");
        let mut rng = ChaCha20Rng::from_seed(dilithium_seed);
        let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut rng).expect("Key generation failed");

        let kyber_seed = Self::derive_child_seed(&seed, b"kyber");
        let mut kyber_rng = ChaCha20Rng::from_seed(kyber_seed);
        let (ek, dk) = ml_kem_768::KG::try_keygen_with_rng(&mut kyber_rng)
            .expect("Kyber key generation failed");

        Self {
            dilithium_pk: pk,
            dilithium_sk: sk,
            kyber_ek: ek,
            kyber_dk: dk,
            mnemonic,
        }
    }

    fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;

        let salt = format!("mnemonic{}", passphrase);
        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);
        seed
    }

    fn derive_child_seed(master_seed: &[u8], context: &[u8]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(context), master_seed);
        let mut okm = [0u8; 32];
        hk.expand(b"truthlinked-v1", &mut okm)
            .expect("HKDF expand failed");
        okm
    }

    pub fn save_with_password<P: AsRef<Path>>(
        &self,
        path: P,
        password: Option<&str>,
    ) -> Result<(), String> {
        let data = serde_json::json!({
            "mnemonic": self.mnemonic,
            "dilithium_public": hex::encode(self.dilithium_pk.clone().into_bytes()),
            "kyber_encaps_key": hex::encode(self.kyber_ek.clone().into_bytes()),
            "dilithium_secret": hex::encode(self.dilithium_sk.clone().into_bytes()),
            "kyber_decaps_key": hex::encode(self.kyber_dk.clone().into_bytes()),
        });

        let json_str = serde_json::to_string_pretty(&data)
            .map_err(|e| format!("Failed to serialize keypair: {}", e))?;

        let final_data = if let Some(pwd) = password {
            let encrypted = Self::encrypt_keyfile(&json_str, pwd)?;
            serde_json::to_string_pretty(&serde_json::json!({
                "encrypted": true,
                "version": 1,
                "data": encrypted,
            }))
            .map_err(|e| format!("Failed to wrap encrypted keypair: {}", e))?
        } else {
            json_str
        };

        let path_ref = path.as_ref();
        fs::write(path_ref, final_data).map_err(|e| e.to_string())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path_ref)
                .map_err(|e| e.to_string())?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path_ref, perms).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    fn encrypt_keyfile(plaintext: &str, password: &str) -> Result<String, String> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use rand::RngCore;

        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let mut key = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|e| format!("Argon2 failed: {}", e))?;

        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher init failed: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("Encrypt failed: {}", e))?;

        let payload = serde_json::json!({
            "salt": hex::encode(salt),
            "nonce": hex::encode(nonce_bytes),
            "ciphertext": hex::encode(ciphertext),
        });

        Ok(payload.to_string())
    }

    fn decrypt_keyfile(payload: &str, password: &str) -> Result<String, String> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let obj: serde_json::Value = serde_json::from_str(payload)
            .map_err(|e| format!("Invalid encrypted keyfile: {}", e))?;

        let salt_hex = obj
            .get("salt")
            .and_then(|v| v.as_str())
            .ok_or("Missing salt")?;
        let nonce_hex = obj
            .get("nonce")
            .and_then(|v| v.as_str())
            .ok_or("Missing nonce")?;
        let ct_hex = obj
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or("Missing ciphertext")?;

        let salt = hex::decode(salt_hex).map_err(|e| format!("Invalid salt: {}", e))?;
        let nonce = hex::decode(nonce_hex).map_err(|e| format!("Invalid nonce: {}", e))?;
        let ciphertext = hex::decode(ct_hex).map_err(|e| format!("Invalid ciphertext: {}", e))?;

        let mut key = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|e| format!("Argon2 failed: {}", e))?;

        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher init failed: {}", e))?;

        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| format!("Decrypt failed: {}", e))?;

        String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
    }

    pub fn load_with_password<P: AsRef<Path>>(
        path: P,
        password: Option<&str>,
    ) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let json =
            fs::read_to_string(path_ref).map_err(|e| format!("Failed to read file: {}", e))?;

        let wrapper: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| format!("Failed to parse keypair: {}", e))?;

        let is_encrypted = wrapper
            .get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let data_json = if is_encrypted {
            let pwd = password.ok_or("Password required")?;
            let payload = wrapper
                .get("data")
                .and_then(|v| v.as_str())
                .ok_or("Missing data")?;
            Self::decrypt_keyfile(payload, pwd)?
        } else {
            json
        };

        let obj: serde_json::Value = serde_json::from_str(&data_json)
            .map_err(|e| format!("Failed to parse keypair: {}", e))?;

        let mnemonic = obj
            .get("mnemonic")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dilithium_public = obj
            .get("dilithium_public")
            .and_then(|v| v.as_str())
            .ok_or("Missing dilithium_public")?;
        let dilithium_secret = obj
            .get("dilithium_secret")
            .and_then(|v| v.as_str())
            .ok_or("Missing dilithium_secret")?;

        let pk_bytes: [u8; 1952] = hex::decode(dilithium_public)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "Invalid public key length")?;
        let sk_bytes: [u8; 4032] = hex::decode(dilithium_secret)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "Invalid secret key length")?;

        let dilithium_pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
            .map_err(|e| format!("Invalid public key: {:?}", e))?;
        let dilithium_sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
            .map_err(|e| format!("Invalid secret key: {:?}", e))?;

        let kyber_encaps_key = obj.get("kyber_encaps_key").and_then(|v| v.as_str());
        let kyber_decaps_key = obj.get("kyber_decaps_key").and_then(|v| v.as_str());

        let (kyber_ek, kyber_dk) = match (kyber_encaps_key, kyber_decaps_key) {
            (Some(ek_hex), Some(dk_hex)) => {
                let ek_bytes: [u8; 1184] = hex::decode(ek_hex)
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "Invalid encaps key length")?;
                let dk_bytes: [u8; 2400] = hex::decode(dk_hex)
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "Invalid decaps key length")?;
                let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes)
                    .map_err(|e| format!("Invalid encaps key: {:?}", e))?;
                let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes)
                    .map_err(|e| format!("Invalid decaps key: {:?}", e))?;
                (ek, dk)
            }
            _ => {
                if mnemonic.is_empty() {
                    return Err("Missing kyber keys and mnemonic".to_string());
                }
                let derived = Self::from_mnemonic(mnemonic.clone());
                (derived.kyber_ek, derived.kyber_dk)
            }
        };

        Ok(Self {
            dilithium_pk,
            dilithium_sk,
            kyber_ek,
            kyber_dk,
            mnemonic,
        })
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let json =
            fs::read_to_string(path_ref).map_err(|e| format!("Failed to read file: {}", e))?;

        let wrapper: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| format!("Failed to parse keypair: {}", e))?;

        let is_encrypted = wrapper
            .get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if is_encrypted {
            let password = rpassword::prompt_password("Enter password: ")
                .map_err(|e| format!("Failed to read password: {}", e))?;
            Self::load_with_password(path_ref, Some(&password))
        } else {
            Self::load_with_password(path_ref, None)
        }
    }

    pub fn sign_transaction(
        &self,
        tx: &crate::pq_execution::Transaction,
    ) -> Result<crate::pq_execution::Transaction, String> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&(tx.genesis_fingerprint.len() as u32).to_le_bytes());
        msg.extend_from_slice(&tx.genesis_fingerprint);
        msg.extend_from_slice(&(tx.sender.len() as u32).to_le_bytes());
        msg.extend_from_slice(&tx.sender);
        msg.extend_from_slice(&tx.nonce.to_le_bytes());
        msg.extend_from_slice(&tx.timestamp.to_le_bytes());
        msg.extend_from_slice(&tx.expiration_height.to_le_bytes());

        let intent_bytes = postcard::to_allocvec(&tx.intent)
            .map_err(|e| format!("Failed to serialize intent: {}", e))?;
        msg.extend_from_slice(&(intent_bytes.len() as u32).to_le_bytes());
        msg.extend_from_slice(&intent_bytes);

        let signature = (&self.dilithium_sk)
            .try_sign(&msg, TX_SIGN_CONTEXT)
            .map_err(|e| format!("Signing failed: {:?}", e))?
            .to_vec();

        Ok(crate::pq_execution::Transaction {
            sender: tx.sender,
            intent: tx.intent.clone(),
            signature,
            nonce: tx.nonce,
            timestamp: tx.timestamp,
            genesis_fingerprint: tx.genesis_fingerprint,
            expiration_height: tx.expiration_height,
        })
    }
}

pub fn account_id_from_pubkey(pubkey: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"truthlinked-account-id-v1");
    hasher.update(pubkey);
    hasher.finalize().into()
}

fn build_tx_signing_message(
    genesis_fingerprint: [u8; 32],
    sender: [u8; 32],
    timestamp: u64,
    expiration_height: u64,
    intent_bytes: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&(genesis_fingerprint.len() as u32).to_le_bytes());
    msg.extend_from_slice(&genesis_fingerprint);
    msg.extend_from_slice(&(sender.len() as u32).to_le_bytes());
    msg.extend_from_slice(&sender);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    msg.extend_from_slice(&expiration_height.to_le_bytes());
    msg.extend_from_slice(&(intent_bytes.len() as u32).to_le_bytes());
    msg.extend_from_slice(intent_bytes);
    msg
}

pub fn sign_transaction(
    genesis_fingerprint: [u8; 32],
    sender: [u8; 32],
    timestamp: u64,
    expiration_height: u64,
    intent: &[u8],
    dilithium_sk: &ml_dsa_65::PrivateKey,
) -> Vec<u8> {
    let msg = build_tx_signing_message(
        genesis_fingerprint,
        sender,
        timestamp,
        expiration_height,
        intent,
    );

    dilithium_sk
        .try_sign(&msg, TX_SIGN_CONTEXT)
        .expect("Signing failed")
        .to_vec()
}

pub fn kyber_encapsulate(encaps_key: &ml_kem_768::EncapsKey) -> ([u8; 1088], [u8; 32]) {
    let (ssk, ct) = encaps_key.try_encaps().expect("Encapsulation failed");
    (ct.into_bytes(), ssk.into_bytes())
}

pub fn kyber_decapsulate(decaps_key: &ml_kem_768::DecapsKey, ciphertext: &[u8; 1088]) -> [u8; 32] {
    let ct = ml_kem_768::CipherText::try_from_bytes(*ciphertext).expect("Invalid ciphertext");
    decaps_key
        .try_decaps(&ct)
        .expect("Decapsulation failed")
        .into_bytes()
}
