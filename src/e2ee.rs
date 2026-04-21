//! End-to-end encryption primitives (E2EE).
//!
//! Goal: TET-Core routes ciphertext only. Workers decrypt on-device.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead as _, KeyInit as _};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, thiserror::Error)]
pub enum E2eeError {
    #[error("invalid encoding")]
    Encoding,
    #[error("crypto failure")]
    Crypto,
}

pub fn gen_worker_static_keypair() -> (StaticSecret, PublicKey) {
    let sk = StaticSecret::random_from_rng(rand_core::OsRng);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

pub fn decode_x25519_pub_b64(b64: &str) -> Result<PublicKey, E2eeError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| E2eeError::Encoding)?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| E2eeError::Encoding)?;
    Ok(PublicKey::from(arr))
}

pub fn encode_x25519_pub_b64(pk: &PublicKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(pk.as_bytes())
}

fn derive_key(shared: [u8; 32], context: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut out = [0u8; 32];
    let _ = hk.expand(context, &mut out);
    out
}

/// Encrypt plaintext for a worker using (client_ephemeral_sk, worker_static_pk).
pub fn encrypt_for_worker(
    client_ephemeral_sk: &StaticSecret,
    worker_static_pk: &PublicKey,
    nonce12: [u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let shared = client_ephemeral_sk
        .diffie_hellman(worker_static_pk)
        .to_bytes();
    let key_bytes = derive_key(shared, b"tet-e2ee-v1");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    cipher
        .encrypt(Nonce::from_slice(&nonce12), plaintext)
        .map_err(|_| E2eeError::Crypto)
}

/// Decrypt ciphertext on the worker using (worker_static_sk, client_ephemeral_pk).
pub fn decrypt_on_worker(
    worker_static_sk: &StaticSecret,
    client_ephemeral_pk: &PublicKey,
    nonce12: [u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let shared = worker_static_sk
        .diffie_hellman(client_ephemeral_pk)
        .to_bytes();
    let key_bytes = derive_key(shared, b"tet-e2ee-v1");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    cipher
        .decrypt(Nonce::from_slice(&nonce12), ciphertext)
        .map_err(|_| E2eeError::Crypto)
}

/// Encrypt a response on the worker using (worker_static_sk, client_ephemeral_pk).
pub fn encrypt_on_worker(
    worker_static_sk: &StaticSecret,
    client_ephemeral_pk: &PublicKey,
    nonce12: [u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let shared = worker_static_sk
        .diffie_hellman(client_ephemeral_pk)
        .to_bytes();
    let key_bytes = derive_key(shared, b"tet-e2ee-v1");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    cipher
        .encrypt(Nonce::from_slice(&nonce12), plaintext)
        .map_err(|_| E2eeError::Crypto)
}
