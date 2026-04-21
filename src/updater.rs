//! Secure auto-updater prototype (signed manifest).
//!
//! This module does not download or apply updates yet. It defines a verifiable manifest format
//! that can be used to roll out protocol upgrades safely.

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub v: u32,
    pub channel: String, // "stable" | "beta"
    pub version: String,
    pub published_unix_ms: u64,
    pub url: String,
    pub sha256_hex: String,
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid key")]
    InvalidKey,
}

#[allow(dead_code)]
pub fn verify_manifest_ed25519(
    verifying_key_bytes: &[u8],
    signature_bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<(), UpdateError> {
    let vk: VerifyingKey = VerifyingKey::from_bytes(
        verifying_key_bytes
            .try_into()
            .map_err(|_| UpdateError::InvalidKey)?,
    )
    .map_err(|_| UpdateError::InvalidKey)?;
    let sig = Signature::from_slice(signature_bytes).map_err(|_| UpdateError::InvalidSignature)?;
    vk.verify(manifest_bytes, &sig)
        .map_err(|_| UpdateError::InvalidSignature)?;
    Ok(())
}
