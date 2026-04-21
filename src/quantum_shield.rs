//! TET Quantum Shield (hybrid signatures).
//!
//! Post-quantum signatures are standardized to **ML-DSA-44 (FIPS 204)** across the entire stack.

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

#[derive(Debug, thiserror::Error)]
pub enum HybridSigError {
    #[error("missing signature")]
    Missing,
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("ed25519 verification failed")]
    Ed25519Failed,
    #[error("pqc verification failed (ml-dsa-44)")]
    PqcMldsaFailed,
}

pub fn pqc_active() -> bool {
    std::env::var("TET_PQC_ACTIVE")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn verify_ed25519(pubkey_hex: &str, sig_b64: &str, msg: &[u8]) -> Result<(), HybridSigError> {
    let pk = hex::decode(pubkey_hex).map_err(|_| HybridSigError::InvalidEncoding)?;
    let pk: [u8; 32] = pk.try_into().map_err(|_| HybridSigError::InvalidEncoding)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| HybridSigError::InvalidEncoding)?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.as_bytes())
        .map_err(|_| HybridSigError::InvalidEncoding)?;
    let sig = Signature::from_slice(&sig).map_err(|_| HybridSigError::InvalidEncoding)?;
    vk.verify(msg, &sig)
        .map_err(|_| HybridSigError::Ed25519Failed)?;
    Ok(())
}

pub fn verify_pqc_mldsa44(
    mldsa_pubkey_b64: &str,
    sig_b64: &str,
    msg: &[u8],
) -> Result<(), HybridSigError> {
    crate::wallet::verify_mldsa44_b64(mldsa_pubkey_b64, sig_b64, msg)
        .map_err(|_| HybridSigError::PqcMldsaFailed)
}

pub fn verify_hybrid(
    wallet_id_hex: &str,
    ed25519_sig_b64: Option<&str>,
    mldsa_pubkey_b64: Option<&str>,
    mldsa_sig_b64: Option<&str>,
    msg: &[u8],
) -> Result<(), HybridSigError> {
    let sig = ed25519_sig_b64.ok_or(HybridSigError::Missing)?;
    verify_ed25519(wallet_id_hex, sig, msg)?;

    if pqc_active() {
        let pk = mldsa_pubkey_b64.ok_or(HybridSigError::Missing)?;
        let ps = mldsa_sig_b64.ok_or(HybridSigError::Missing)?;
        verify_pqc_mldsa44(pk, ps, msg)?;
    }
    Ok(())
}
