use base64::Engine as _;
use bip39::{Language, Mnemonic};
use dilithium::{DilithiumSignature, MlDsaKeyPair, ML_DSA_44};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    #[error("hkdf expand failed")]
    HkdfFailed,
    #[error("ml-dsa signing failed")]
    MldsaSignFailed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletInfo {
    /// Ed25519 verifying key (hex) — on-ledger wallet id when used as `active_wallet`.
    pub address_hex: String,
    /// ML-DSA-44 public key (raw FIPS 204 bytes, base64) — deterministic from the same BIP39 seed as Ed25519.
    pub dilithium_pubkey_b64: String,
    pub mnemonic_12: Option<String>,
}

fn signing_key_from_mnemonic(m: &Mnemonic) -> SigningKey {
    // BIP-39 seed is 64 bytes; we deterministically map it to an Ed25519 signing key.
    let seed = Zeroizing::new(m.to_seed(""));
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&seed[..32]);
    SigningKey::from_bytes(&sk)
}

/// HKDF-derived 32-byte seed for ML-DSA-44 (must match `tetMldsa44Seed32` in the wallet bundle).
pub fn mldsa44_seed32_from_mnemonic(mnemonic: &str) -> Result<[u8; 32], WalletError> {
    let m = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|_| WalletError::InvalidMnemonic)?;
    let seed = Zeroizing::new(m.to_seed(""));
    let hk = Hkdf::<Sha256>::new(None, seed.as_ref());
    let mut out = [0u8; 32];
    hk.expand(b"tet:pqc:mldsa44-seed:v1", &mut out)
        .map_err(|_| WalletError::HkdfFailed)?;
    Ok(out)
}

pub fn mldsa44_keypair_from_mnemonic(mnemonic: &str) -> Result<MlDsaKeyPair, WalletError> {
    let seed32 = mldsa44_seed32_from_mnemonic(mnemonic)?;
    Ok(MlDsaKeyPair::generate_deterministic(ML_DSA_44, &seed32))
}

fn dilithium_pubkey_b64_from_mnemonic(m: &Mnemonic) -> Result<String, WalletError> {
    let phrase = m.to_string();
    let kp = mldsa44_keypair_from_mnemonic(&phrase)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(kp.public_key()))
}

/// Deterministic signing randomness (32 B) so browser and core produce identical ML-DSA-44 signatures.
pub fn mldsa44_signing_rnd(msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tet:mldsa44-signing-rnd:v1");
    h.update(msg);
    h.finalize().into()
}

/// Sign `msg` with ML-DSA-44 using deterministic `rnd` (see `mldsa44_signing_rnd`).
pub fn mldsa44_sign_deterministic(kp: &MlDsaKeyPair, msg: &[u8]) -> Result<Vec<u8>, WalletError> {
    let rnd = mldsa44_signing_rnd(msg);
    let sig = kp
        .sign_deterministic(msg, b"", &rnd)
        .map_err(|_| WalletError::MldsaSignFailed)?;
    Ok(sig.as_bytes().to_vec())
}

/// Verify detached ML-DSA-44 (FIPS 204) signature; `pubkey_b64` / `sig_b64` are STANDARD base64.
pub fn verify_mldsa44_b64(pubkey_b64: &str, sig_b64: &str, msg: &[u8]) -> Result<(), String> {
    let pk = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64.trim().as_bytes())
        .map_err(|e| e.to_string())?;
    if pk.len() != ML_DSA_44.public_key_bytes() {
        return Err(format!(
            "mldsa pubkey must be {} bytes (got {})",
            ML_DSA_44.public_key_bytes(),
            pk.len()
        ));
    }
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim().as_bytes())
        .map_err(|e| e.to_string())?;
    if sig_bytes.len() != ML_DSA_44.signature_bytes() {
        return Err(format!(
            "mldsa signature must be {} bytes (got {})",
            ML_DSA_44.signature_bytes(),
            sig_bytes.len()
        ));
    }
    let sig = DilithiumSignature::from_slice(&sig_bytes);
    if !MlDsaKeyPair::verify(&pk, &sig, msg, b"", ML_DSA_44) {
        return Err("invalid ml-dsa-44 signature".into());
    }
    Ok(())
}

fn wallet_info_from_mnemonic(m: Mnemonic, include_words: bool) -> Result<WalletInfo, WalletError> {
    let sk = signing_key_from_mnemonic(&m);
    let vk = sk.verifying_key();
    let dil = dilithium_pubkey_b64_from_mnemonic(&m)?;
    Ok(WalletInfo {
        address_hex: hex::encode(vk.to_bytes()),
        dilithium_pubkey_b64: dil,
        mnemonic_12: include_words.then(|| m.to_string()),
    })
}

/// Deprecated for HTTP/browser flows (non-custodial clients generate locally). Kept for tests and tooling.
#[allow(dead_code)]
pub fn generate_mnemonic_12() -> Result<WalletInfo, WalletError> {
    let mut entropy = [0u8; 16]; // 128-bit => 12 words
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|_| WalletError::InvalidMnemonic)?;
    wallet_info_from_mnemonic(mnemonic, true)
}

pub fn recover_from_mnemonic_12(mnemonic: &str) -> Result<WalletInfo, WalletError> {
    let m = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|_| WalletError::InvalidMnemonic)?;
    wallet_info_from_mnemonic(m, false)
}

/// Ed25519 signing key (first 32 bytes of BIP39 seed) — matches browser `wallet_client_bundled.js`.
pub fn ed25519_signing_key_from_mnemonic(mnemonic: &str) -> Result<SigningKey, WalletError> {
    let m = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|_| WalletError::InvalidMnemonic)?;
    Ok(signing_key_from_mnemonic(&m))
}

// ── Hybrid auth messages (Ed25519 + ML-DSA-44 both sign the same UTF-8 bytes) ─────────────────────

/// Canonical bytes for `POST /wallet/transfer` hybrid auth (`mldsa_pubkey_b64` binds the PQC key).
pub fn transfer_hybrid_auth_message_bytes(
    to_wallet: &str,
    amount_micro: u64,
    nonce: u64,
    mldsa_pubkey_b64: &str,
) -> Vec<u8> {
    let t = to_wallet.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    format!("tet xfer hybrid v1|{t}|{amount_micro}|{nonce}|{p}").into_bytes()
}

pub fn founder_genesis_hybrid_auth_message_bytes(
    founder_wallet_id: &str,
    mldsa_pubkey_b64: &str,
) -> Vec<u8> {
    let w = founder_wallet_id.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    format!("tet founder genesis hybrid v1|{w}|{p}").into_bytes()
}

pub fn genesis_1k_claim_hybrid_auth_message_bytes(wallet_id: &str, mldsa_pubkey_b64: &str) -> Vec<u8> {
    let w = wallet_id.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    format!("tet genesis1k claim hybrid v1|{w}|{p}").into_bytes()
}

pub fn founder_withdraw_treasury_hybrid_auth_message_bytes(
    founder_wallet_id: &str,
    amount_micro: u64,
    nonce: u64,
    mldsa_pubkey_b64: &str,
) -> Vec<u8> {
    let w = founder_wallet_id.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    format!("tet founder withdraw treasury hybrid v1|{w}|{amount_micro}|{nonce}|{p}").into_bytes()
}

/// Enterprise inference hybrid auth message.
///
/// This cryptographically binds payment authorization to the exact job requested.
/// Both Ed25519 and ML-DSA-44 must sign the same canonical UTF-8 bytes.
pub fn enterprise_inference_hybrid_auth_message_bytes(
    enterprise_wallet_id: &str,
    nonce: u64,
    amount_micro: u64,
    prompt_sha256_hex: &str,
    model: &str,
    attestation_required: bool,
    mldsa_pubkey_b64: &str,
) -> Vec<u8> {
    let w = enterprise_wallet_id.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    let h = prompt_sha256_hex.trim().to_ascii_lowercase();
    let m = model.trim();
    let att = if attestation_required { 1u8 } else { 0u8 };
    format!("tet enterprise inference v1|{w}|{nonce}|{amount_micro}|{h}|{m}|{att}|{p}").into_bytes()
}
