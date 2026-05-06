use base64::Engine as _;
use bip39::{Language, Mnemonic};
use dilithium::{DilithiumMode, DilithiumSignature, ML_DSA_44, ML_DSA_65, ML_DSA_87, MlDsaKeyPair};
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
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
    /// ML-DSA public key (raw FIPS 204 bytes, STANDARD base64). Default generation: ML-DSA-65 (`TET_MLDSA_SECURITY_LEVEL`).
    pub dilithium_pubkey_b64: String,
    pub mnemonic_12: Option<String>,
}

fn signing_key_from_mnemonic(m: &Mnemonic) -> SigningKey {
    let seed = Zeroizing::new(m.to_seed(""));
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&seed[..32]);
    SigningKey::from_bytes(&sk)
}

/// Active ML-DSA parameter set for **new** keys from mnemonic (`44`, `65`, `87`). Default: **65** (ML-DSA-65 / Dilithium3).
pub fn active_mldsa_mode() -> DilithiumMode {
    match std::env::var("TET_MLDSA_SECURITY_LEVEL")
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("44") => ML_DSA_44,
        Some("87") => ML_DSA_87,
        Some("65") | None => ML_DSA_65,
        _ => ML_DSA_65,
    }
}

fn hkdf_info_for_mode(mode: DilithiumMode) -> &'static [u8] {
    match mode {
        DilithiumMode::Dilithium2 => b"tet:pqc:mldsa44-seed:v1",
        DilithiumMode::Dilithium3 => b"tet:pqc:mldsa65-seed:v1",
        DilithiumMode::Dilithium5 => b"tet:pqc:mldsa87-seed:v1",
    }
}

/// HKDF-derived 32-byte seed for ML-DSA (matches browser `tetMldsaSeed32` / level-specific info string).
pub fn mldsa_seed32_from_mnemonic_for_mode(
    mnemonic: &str,
    mode: DilithiumMode,
) -> Result<[u8; 32], WalletError> {
    let m = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|_| WalletError::InvalidMnemonic)?;
    let seed = Zeroizing::new(m.to_seed(""));
    let hk = Hkdf::<Sha256>::new(None, seed.as_ref());
    let mut out = [0u8; 32];
    hk.expand(hkdf_info_for_mode(mode), &mut out)
        .map_err(|_| WalletError::HkdfFailed)?;
    Ok(out)
}

pub fn mldsa_seed32_from_mnemonic(mnemonic: &str) -> Result<[u8; 32], WalletError> {
    mldsa_seed32_from_mnemonic_for_mode(mnemonic, active_mldsa_mode())
}

/// HKDF seed for ML-DSA-44 only (legacy tests / `TET_MLDSA_SECURITY_LEVEL=44`).
pub fn mldsa44_seed32_from_mnemonic(mnemonic: &str) -> Result<[u8; 32], WalletError> {
    mldsa_seed32_from_mnemonic_for_mode(mnemonic, ML_DSA_44)
}

pub fn mldsa_keypair_from_mnemonic(mnemonic: &str) -> Result<MlDsaKeyPair, WalletError> {
    let mode = active_mldsa_mode();
    let seed32 = mldsa_seed32_from_mnemonic_for_mode(mnemonic, mode)?;
    Ok(MlDsaKeyPair::generate_deterministic(mode, &seed32))
}

pub fn mldsa44_keypair_from_mnemonic(mnemonic: &str) -> Result<MlDsaKeyPair, WalletError> {
    let seed32 = mldsa_seed32_from_mnemonic_for_mode(mnemonic, ML_DSA_44)?;
    Ok(MlDsaKeyPair::generate_deterministic(ML_DSA_44, &seed32))
}

fn dilithium_pubkey_b64_from_mnemonic(m: &Mnemonic) -> Result<String, WalletError> {
    let phrase = m.to_string();
    let kp = mldsa_keypair_from_mnemonic(&phrase)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(kp.public_key()))
}

/// Deterministic signing randomness per ML-DSA mode (matches browser `tetMldsaSigningRnd`).
pub fn mldsa_signing_rnd(mode: DilithiumMode, msg: &[u8]) -> [u8; 32] {
    let label: &[u8] = match mode {
        DilithiumMode::Dilithium2 => b"tet:mldsa44-signing-rnd:v1",
        DilithiumMode::Dilithium3 => b"tet:mldsa65-signing-rnd:v1",
        DilithiumMode::Dilithium5 => b"tet:mldsa87-signing-rnd:v1",
    };
    let mut h = Sha256::new();
    h.update(label);
    h.update(msg);
    h.finalize().into()
}

pub fn mldsa_sign_deterministic(kp: &MlDsaKeyPair, msg: &[u8]) -> Result<Vec<u8>, WalletError> {
    let rnd = mldsa_signing_rnd(kp.mode(), msg);
    let sig = kp
        .sign_deterministic(msg, b"", &rnd)
        .map_err(|_| WalletError::MldsaSignFailed)?;
    Ok(sig.as_bytes().to_vec())
}

/// Legacy ML-DSA-44 deterministic sign (tests / compatibility).
pub fn mldsa44_sign_deterministic(kp: &MlDsaKeyPair, msg: &[u8]) -> Result<Vec<u8>, WalletError> {
    let rnd = mldsa_signing_rnd(ML_DSA_44, msg);
    let sig = kp
        .sign_deterministic(msg, b"", &rnd)
        .map_err(|_| WalletError::MldsaSignFailed)?;
    Ok(sig.as_bytes().to_vec())
}

pub fn infer_mldsa_mode_from_raw_pubkey(pk: &[u8]) -> Option<DilithiumMode> {
    if pk.len() == ML_DSA_44.public_key_bytes() {
        Some(ML_DSA_44)
    } else if pk.len() == ML_DSA_65.public_key_bytes() {
        Some(ML_DSA_65)
    } else if pk.len() == ML_DSA_87.public_key_bytes() {
        Some(ML_DSA_87)
    } else {
        None
    }
}

/// Verify detached ML-DSA signature; pubkey/sig are STANDARD base64 over **raw** FIPS-204 bytes (no mode prefix).
pub fn verify_mldsa_b64(pubkey_b64: &str, sig_b64: &str, msg: &[u8]) -> Result<(), String> {
    let pk = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64.trim().as_bytes())
        .map_err(|e| e.to_string())?;
    let mode = infer_mldsa_mode_from_raw_pubkey(&pk).ok_or_else(|| {
        format!(
            "mldsa pubkey must be {} / {} / {} bytes (got {})",
            ML_DSA_44.public_key_bytes(),
            ML_DSA_65.public_key_bytes(),
            ML_DSA_87.public_key_bytes(),
            pk.len()
        )
    })?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim().as_bytes())
        .map_err(|e| e.to_string())?;
    if sig_bytes.len() != mode.signature_bytes() {
        return Err(format!(
            "mldsa signature must be {} bytes for this level (got {})",
            mode.signature_bytes(),
            sig_bytes.len()
        ));
    }
    let sig = DilithiumSignature::from_slice(&sig_bytes);
    if !MlDsaKeyPair::verify(&pk, &sig, msg, b"", mode) {
        return Err("invalid ml-dsa signature".into());
    }
    Ok(())
}

/// Verify ML-DSA-44 only (narrower errors for legacy callers).
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
    verify_mldsa_b64(pubkey_b64, sig_b64, msg)
}

pub fn verify_ed25519_hex_message(from_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), String> {
    let pk = hex::decode(from_hex.trim()).map_err(|e| e.to_string())?;
    let vk_arr: [u8; 32] = pk.try_into().map_err(|_| {
        "from_address must be 64 hex chars (32-byte Ed25519 public key)".to_string()
    })?;
    let vk =
        VerifyingKey::from_bytes(&vk_arr).map_err(|e| format!("invalid from_address key: {e}"))?;
    let sig_bytes = hex::decode(sig_hex.trim()).map_err(|e| e.to_string())?;
    if sig_bytes.len() != 64 {
        return Err("signature must be 128 hex chars (64 bytes)".to_string());
    }
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| format!("invalid signature bytes: {e}"))?;
    vk.verify(msg, &sig)
        .map_err(|e| format!("invalid signature: {e}"))
}

/// Ed25519 + ML-DSA over [`transfer_hybrid_auth_message_bytes`] — both must verify (AND).
pub fn verify_dual_signed_transfer(
    from_wallet_hex: &str,
    to_wallet: &str,
    amount_micro: u64,
    nonce: u64,
    ed25519_sig_hex: &str,
    mldsa_pubkey_b64: &str,
    mldsa_sig_b64: &str,
) -> Result<(), String> {
    let msg = transfer_hybrid_auth_message_bytes(to_wallet, amount_micro, nonce, mldsa_pubkey_b64);
    verify_ed25519_hex_message(from_wallet_hex, &msg, ed25519_sig_hex)?;
    verify_mldsa_b64(mldsa_pubkey_b64, mldsa_sig_b64, &msg)?;
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
    let mut entropy = [0u8; 16];
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

pub fn ed25519_signing_key_from_mnemonic(mnemonic: &str) -> Result<SigningKey, WalletError> {
    let m = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|_| WalletError::InvalidMnemonic)?;
    Ok(signing_key_from_mnemonic(&m))
}

// ── Hybrid auth messages (Ed25519 + ML-DSA both sign the same UTF-8 bytes) ────────────────────────

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

pub fn genesis_1k_claim_hybrid_auth_message_bytes(
    wallet_id: &str,
    mldsa_pubkey_b64: &str,
) -> Vec<u8> {
    let w = wallet_id.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    format!("tet genesis1k claim hybrid v1|{w}|{p}").into_bytes()
}

pub fn initial_airdrop_claim_hybrid_auth_message_bytes(
    wallet_id: &str,
    mldsa_pubkey_b64: &str,
) -> Vec<u8> {
    let w = wallet_id.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    format!("tet initial airdrop claim hybrid v1|{w}|{p}").into_bytes()
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

/// Hybrid signed payload for `POST /ai/infer` and `POST /ai/utility` (Ed25519 + ML-DSA), **always** on mainnet nodes.
/// Must stay byte-for-byte aligned with Sovereign OS `ai_infer_hybrid.ts`.
/// Canonical preimage for `POST /ledger/stake` worker bond (must match Sovereign OS signing).
pub fn worker_bond_stake_hybrid_auth_message_bytes(
    wallet_id_hex: &str,
    amount_micro: u64,
    nonce: u64,
    mldsa_pubkey_b64: &str,
) -> Vec<u8> {
    let w = wallet_id_hex.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    format!("tet worker bond stake v1|{w}|{amount_micro}|{nonce}|{p}").into_bytes()
}

/// Canonical preimage for `POST /ledger/unstake` worker bond release.
pub fn worker_bond_unstake_hybrid_auth_message_bytes(
    wallet_id_hex: &str,
    amount_micro: u64,
    nonce: u64,
    mldsa_pubkey_b64: &str,
) -> Vec<u8> {
    let w = wallet_id_hex.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    format!("tet worker bond unstake v1|{w}|{amount_micro}|{nonce}|{p}").into_bytes()
}

pub fn ai_infer_hybrid_auth_message_bytes(
    wallet_id_hex: &str,
    prompt: &str,
    flops: u64,
    nonce: u64,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let w = wallet_id_hex.trim().to_ascii_lowercase();
    let ph = hex::encode(Sha256::digest(prompt.as_bytes()));
    format!("tet ai infer hybrid v1|{w}|{flops}|{nonce}|{ph}").into_bytes()
}
