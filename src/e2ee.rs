//! End-to-end encryption primitives (E2EE).
//!
//! Goal: TET-Core routes ciphertext only. Workers decrypt on-device.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead as _, KeyInit as _};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, thiserror::Error)]
pub enum E2eeError {
    #[error("invalid encoding: {0}")]
    Encoding(String),
    #[error("crypto failure")]
    Crypto,
}

fn is_prod() -> bool {
    std::env::var("TET_PROD")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || std::env::var("TET_MAINNET")
            .ok()
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

/// Phase 1.8.1: Local-dev symmetric fallback for explicit worker ids.
///
/// This is **NOT** used in production flows; callers must opt-in.
#[cfg(debug_assertions)]
pub const DEV_MODE_WORKER_ID: &str = "nexus_worker_01";
#[cfg(debug_assertions)]
pub const DEV_MODE_EPHEMERAL_SENTINEL: &str = "DEV_MODE_SYMM";

#[cfg(debug_assertions)]
fn dev_mode_key_bytes() -> [u8; 32] {
    use sha2::Digest as _;
    let h = sha2::Sha256::digest(b"dev_secret_key");
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..]);
    out
}

#[cfg(debug_assertions)]
pub fn encrypt_dev_mode_symmetric(
    nonce12: [u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    if is_prod() {
        panic!("CRITICAL SECURITY VIOLATION: Dev-mode E2EE keys accessed in production!");
    }
    let key_bytes = dev_mode_key_bytes();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    cipher
        .encrypt(Nonce::from_slice(&nonce12), plaintext)
        .map_err(|_| E2eeError::Crypto)
}

#[cfg(debug_assertions)]
pub fn decrypt_dev_mode_symmetric(
    nonce12: [u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    if is_prod() {
        panic!("CRITICAL SECURITY VIOLATION: Dev-mode E2EE keys accessed in production!");
    }
    let key_bytes = dev_mode_key_bytes();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    cipher
        .decrypt(Nonce::from_slice(&nonce12), ciphertext)
        .map_err(|_| E2eeError::Crypto)
}

pub fn gen_worker_static_keypair() -> (StaticSecret, PublicKey) {
    let sk = StaticSecret::random_from_rng(rand_core::OsRng);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

pub fn decode_x25519_pub_b64(b64: &str) -> Result<PublicKey, E2eeError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| E2eeError::Encoding(format!("x25519 pub b64 decode: {e}")))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| E2eeError::Encoding("x25519 pub len".into()))?;
    Ok(PublicKey::from(arr))
}

pub fn decode_x25519_static_sk_b64(b64: &str) -> Result<StaticSecret, E2eeError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| E2eeError::Encoding(format!("x25519 sk b64 decode: {e}")))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| E2eeError::Encoding("x25519 sk len".into()))?;
    Ok(StaticSecret::from(arr))
}

pub fn encode_x25519_pub_b64(pk: &PublicKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(pk.as_bytes())
}

fn derive_key_hybrid(x25519_shared: [u8; 32], mlkem_shared: &[u8], context: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + mlkem_shared.len());
    ikm.extend_from_slice(&x25519_shared);
    ikm.extend_from_slice(mlkem_shared);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 32];
    let _ = hk.expand(context, &mut out);
    out
}

pub fn decode_mlkem_pub_b64(b64: &str) -> Result<Vec<u8>, E2eeError> {
    let clean_b64 = b64.replace(['\n', '\r'], "").trim().to_string();
    base64::engine::general_purpose::STANDARD
        .decode(clean_b64.as_bytes())
        .map_err(|e| E2eeError::Encoding(format!("mlkem pub b64 decode: {e}")))
}

pub fn decode_mlkem_ct_b64(b64: &str) -> Result<Vec<u8>, E2eeError> {
    let clean_b64 = b64.replace(['\n', '\r'], "").trim().to_string();
    base64::engine::general_purpose::STANDARD
        .decode(clean_b64.as_bytes())
        .map_err(|e| E2eeError::Encoding(format!("mlkem ct b64 decode: {e}")))
}

pub fn decode_mlkem_sk_b64(b64: &str) -> Result<Vec<u8>, E2eeError> {
    let clean_b64 = b64.replace(['\n', '\r'], "").trim().to_string();
    base64::engine::general_purpose::STANDARD
        .decode(clean_b64.as_bytes())
        .map_err(|e| E2eeError::Encoding(format!("mlkem sk b64 decode: {e}")))
}

pub fn encode_mlkem_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Encrypt plaintext for a worker using (client_ephemeral_sk, worker_static_pk).
pub fn encrypt_for_worker(
    client_ephemeral_sk: &StaticSecret,
    worker_static_pk: &PublicKey,
    worker_mlkem_pubkey_bytes: &[u8],
    nonce12: [u8; 12],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), E2eeError> {
    let shared = client_ephemeral_sk
        .diffie_hellman(worker_static_pk)
        .to_bytes();
    let pk = kyber768::PublicKey::from_bytes(worker_mlkem_pubkey_bytes)
        .map_err(|_| E2eeError::Encoding("mlkem pub from_bytes".into()))?;
    // NOTE: pqcrypto-kyber returns (SharedSecret, Ciphertext).
    let (kem_ss, kem_ct) = kyber768::encapsulate(&pk);

    let key_bytes = derive_key_hybrid(shared, kem_ss.as_bytes(), b"tet-e2ee-hybrid-v1");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce12), plaintext)
        .map_err(|_| E2eeError::Crypto)?;
    Ok((ct, kem_ct.as_bytes().to_vec()))
}

/// Decrypt ciphertext on the worker using (worker_static_sk, client_ephemeral_pk).
pub fn decrypt_on_worker(
    worker_static_sk: &StaticSecret,
    client_ephemeral_pk: &PublicKey,
    worker_mlkem_sk_bytes: &[u8],
    mlkem_ciphertext_bytes: &[u8],
    nonce12: [u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let shared = worker_static_sk
        .diffie_hellman(client_ephemeral_pk)
        .to_bytes();
    // Kyber768 ciphertext must be exactly 1088 bytes.
    let sk = kyber768::SecretKey::from_bytes(worker_mlkem_sk_bytes)
        .map_err(|_| E2eeError::Encoding("mlkem sk from_bytes".into()))?;
    let kem_ct = kyber768::Ciphertext::from_bytes(mlkem_ciphertext_bytes)
        .map_err(|_| E2eeError::Encoding("mlkem ct from_bytes".into()))?;
    let kem_ss = kyber768::decapsulate(&kem_ct, &sk);

    let key_bytes = derive_key_hybrid(shared, kem_ss.as_bytes(), b"tet-e2ee-hybrid-v1");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    cipher
        .decrypt(Nonce::from_slice(&nonce12), ciphertext)
        .map_err(|_| E2eeError::Crypto)
}

/// Encrypt a response on the worker using (worker_static_sk, client_ephemeral_pk).
pub fn encrypt_on_worker(
    worker_static_sk: &StaticSecret,
    client_ephemeral_pk: &PublicKey,
    client_mlkem_pubkey_bytes: &[u8],
    nonce12: [u8; 12],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), E2eeError> {
    let shared = worker_static_sk
        .diffie_hellman(client_ephemeral_pk)
        .to_bytes();
    let pk = kyber768::PublicKey::from_bytes(client_mlkem_pubkey_bytes)
        .map_err(|_| E2eeError::Encoding("mlkem pub from_bytes".into()))?;
    // NOTE: pqcrypto-kyber returns (SharedSecret, Ciphertext).
    let (kem_ss, kem_ct) = kyber768::encapsulate(&pk);
    let key_bytes = derive_key_hybrid(shared, kem_ss.as_bytes(), b"tet-e2ee-hybrid-v1");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce12), plaintext)
        .map_err(|_| E2eeError::Crypto)?;
    Ok((ct, kem_ct.as_bytes().to_vec()))
}

/// Decrypt a response on the client using (client_ephemeral_sk, worker_static_pk).
pub fn decrypt_on_client(
    client_ephemeral_sk: &StaticSecret,
    worker_static_pk: &PublicKey,
    client_mlkem_sk_bytes: &[u8],
    mlkem_ciphertext_bytes: &[u8],
    nonce12: [u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let shared = client_ephemeral_sk
        .diffie_hellman(worker_static_pk)
        .to_bytes();
    let sk = kyber768::SecretKey::from_bytes(client_mlkem_sk_bytes)
        .map_err(|_| E2eeError::Encoding("mlkem sk from_bytes".into()))?;
    let kem_ct = kyber768::Ciphertext::from_bytes(mlkem_ciphertext_bytes)
        .map_err(|_| E2eeError::Encoding("mlkem ct from_bytes".into()))?;
    let kem_ss = kyber768::decapsulate(&kem_ct, &sk);

    let key_bytes = derive_key_hybrid(shared, kem_ss.as_bytes(), b"tet-e2ee-hybrid-v1");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    cipher
        .decrypt(Nonce::from_slice(&nonce12), ciphertext)
        .map_err(|_| E2eeError::Crypto)
}
