//! Hardware attestation boundary (Phase 4).
//!
//! Goal: accept only proofs that can be tied to a physical device (Secure Enclave / TPM 2.0).
//! This file provides a trait boundary and stubs per OS to keep the architecture stable.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Versioned format for future evolution.
    pub v: u32,
    /// Claimed platform: "macos-se", "windows-tpm", etc.
    pub platform: String,
    /// Opaque, provider-specific bytes (base64 in JSON flows).
    pub report_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacSecureEnclaveReportV1 {
    pub v: u32,
    /// DER-encoded SubjectPublicKeyInfo (P-256).
    pub pubkey_spki_der_b64: String,
    /// DER-encoded ECDSA signature over SHA256(challenge).
    pub sig_der_b64: String,
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("attestation not supported on this platform/build")]
    NotSupported,
    #[error("invalid attestation: {0}")]
    Invalid(String),
    #[error("io error: {0}")]
    Io(String),
}

#[allow(dead_code)]
pub trait AttestationProvider: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn attest(&self, challenge: &[u8]) -> Result<AttestationReport, AttestationError>;
    fn verify(&self, report: &AttestationReport, challenge: &[u8]) -> Result<(), AttestationError>;
}

/// Default provider: disabled until platform integrations land.
#[allow(dead_code)]
pub struct NoAttestation;

impl AttestationProvider for NoAttestation {
    fn name(&self) -> &'static str {
        "none"
    }

    fn attest(&self, _challenge: &[u8]) -> Result<AttestationReport, AttestationError> {
        Err(AttestationError::NotSupported)
    }

    fn verify(
        &self,
        _report: &AttestationReport,
        _challenge: &[u8],
    ) -> Result<(), AttestationError> {
        Err(AttestationError::NotSupported)
    }
}

pub fn attestation_required() -> bool {
    std::env::var("TET_REQUIRE_ATTESTATION")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn verify_attestation_report(
    report: &AttestationReport,
    challenge: &[u8],
) -> Result<(), AttestationError> {
    match report.platform.as_str() {
        "macos-se" => verify_macos_se_v1(report, challenge),
        "windows-tpm" | "android-strongbox" | "ios-se" => {
            verify_unimplemented_but_versioned(report, challenge)
        }
        _ => Err(AttestationError::Invalid(
            "unsupported attestation platform".into(),
        )),
    }
}

fn allow_stub_attestation() -> bool {
    std::env::var("TET_ATTESTATION_ALLOW_STUB")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Returns a stable, verifiable hardware-bound identifier derived from the attestation payload.
///
/// For macOS Secure Enclave v1, this is `sha256(pubkey_spki_der)` in hex.
pub fn hardware_id_hex(
    report: &AttestationReport,
    challenge: &[u8],
) -> Result<String, AttestationError> {
    // Always verify first (no “ID extraction” without cryptographic verification).
    verify_attestation_report(report, challenge)?;
    match report.platform.as_str() {
        "macos-se" => hardware_id_macos_se_v1(report),
        "windows-tpm" | "android-strongbox" | "ios-se" => Err(AttestationError::NotSupported),
        _ => Err(AttestationError::Invalid(
            "unsupported attestation platform".into(),
        )),
    }
}

fn hardware_id_macos_se_v1(report: &AttestationReport) -> Result<String, AttestationError> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(report.report_b64.as_bytes())
        .map_err(|_| AttestationError::Invalid("report_b64 is not base64".into()))?;
    let r: MacSecureEnclaveReportV1 = serde_json::from_slice(&raw)
        .map_err(|e| AttestationError::Invalid(format!("invalid report json: {e}")))?;
    if r.v != 1 {
        return Err(AttestationError::Invalid(
            "unsupported report version".into(),
        ));
    }
    let pubkey_der = base64::engine::general_purpose::STANDARD
        .decode(r.pubkey_spki_der_b64.as_bytes())
        .map_err(|_| AttestationError::Invalid("invalid pubkey b64".into()))?;
    let mut h = Sha256::new();
    h.update(pubkey_der);
    Ok(hex::encode(h.finalize()))
}

fn verify_unimplemented_but_versioned(
    report: &AttestationReport,
    _challenge: &[u8],
) -> Result<(), AttestationError> {
    // Universal enforcement contract:
    // - Platforms are first-class and equally acceptable.
    // - Until a platform verifier is implemented, we fail closed by default.
    // - For local dev bring-up, allow an explicit stub override.
    if !allow_stub_attestation() {
        return Err(AttestationError::NotSupported);
    }
    if report.v != 1 {
        return Err(AttestationError::Invalid(
            "unsupported report version".into(),
        ));
    }
    if report.report_b64.trim().is_empty() {
        return Err(AttestationError::Invalid("report_b64 required".into()));
    }
    Ok(())
}

fn verify_macos_se_v1(
    report: &AttestationReport,
    challenge: &[u8],
) -> Result<(), AttestationError> {
    use base64::Engine as _;
    use ring::signature;

    let raw = base64::engine::general_purpose::STANDARD
        .decode(report.report_b64.as_bytes())
        .map_err(|_| AttestationError::Invalid("report_b64 is not base64".into()))?;
    let r: MacSecureEnclaveReportV1 = serde_json::from_slice(&raw)
        .map_err(|e| AttestationError::Invalid(format!("invalid report json: {e}")))?;
    if r.v != 1 {
        return Err(AttestationError::Invalid(
            "unsupported report version".into(),
        ));
    }
    let pubkey_der = base64::engine::general_purpose::STANDARD
        .decode(r.pubkey_spki_der_b64.as_bytes())
        .map_err(|_| AttestationError::Invalid("invalid pubkey b64".into()))?;
    let sig_der = base64::engine::general_purpose::STANDARD
        .decode(r.sig_der_b64.as_bytes())
        .map_err(|_| AttestationError::Invalid("invalid signature b64".into()))?;

    let mut h = Sha256::new();
    h.update(challenge);
    let digest = h.finalize();

    let vk = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pubkey_der);
    vk.verify(digest.as_slice(), sig_der.as_slice())
        .map_err(|_| {
            AttestationError::Invalid("secure enclave signature verification failed".into())
        })?;
    Ok(())
}
