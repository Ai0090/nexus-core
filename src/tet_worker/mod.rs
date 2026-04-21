//! Proof-of-Compute (PoC) stub + worker response verification (Phase 2 Worker Protocol).
//!
//! Workers run small deterministic "inference" and sign `(task_hash || result_hash || hardware_id)`.

use crate::quantum_shield;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub fn hardware_id_sha256_hex_best_effort() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Collect physical-ish identifiers (best-effort). No UUIDs.
    let mut parts = Vec::new();
    if let Some(ma) = mac_address::get_mac_address()? {
        parts.push(format!("mac={ma}"));
    }
    let _sys = sysinfo::System::new_all();
    parts.push(format!("host={}", sysinfo::System::host_name().unwrap_or_default()));
    parts.push(format!("os={}", sysinfo::System::os_version().unwrap_or_default()));
    parts.push(format!(
        "kernel={}",
        sysinfo::System::kernel_version().unwrap_or_default()
    ));

    let joined = parts.join("|");
    let mut h = Sha256::new();
    h.update(b"tet-hardware-id:v1");
    h.update(joined.as_bytes());
    Ok(hex::encode(h.finalize()))
}

/// Deterministic pseudo–AI output for PoC (no external model).
pub fn poc_infer(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"tet-poc-infer:v1");
    h.update(input.as_bytes());
    let digest = h.finalize();
    format!(
        "PoC:TET stub inference → {}… ({} bytes)",
        hex::encode(&digest[..8]),
        input.len()
    )
}

pub fn task_sha256_hex(model: &str, input: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"tet-ai-task:v1");
    h.update(model.as_bytes());
    h.update([0u8]);
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

pub fn result_sha256_hex(output: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"tet-ai-result:v1");
    h.update(output.as_bytes());
    hex::encode(h.finalize())
}

pub fn worker_sign_message(
    task_sha256_hex: &str,
    result_sha256_hex: &str,
    hardware_id_hex: &str,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        task_sha256_hex.len() + result_sha256_hex.len() + hardware_id_hex.len() + 2,
    );
    v.extend_from_slice(task_sha256_hex.as_bytes());
    v.push(b'|');
    v.extend_from_slice(result_sha256_hex.as_bytes());
    v.push(b'|');
    v.extend_from_slice(hardware_id_hex.as_bytes());
    v
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerProofV1 {
    pub hardware_id_hex: String,
    pub task_sha256_hex: String,
    pub result_sha256_hex: String,
    pub output_text: String,
    pub ed25519_sig_b64: String,
    pub poe_stub_b64: String,
}

pub fn poe_execution_stub_b64(task_sha256_hex: &str, result_sha256_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"ZK-PoE:v1:stub");
    h.update(task_sha256_hex.as_bytes());
    h.update(result_sha256_hex.as_bytes());
    let digest = hex::encode(h.finalize());
    let payload = serde_json::json!({
        "scheme": "tet-zkp-poe-stub-v1",
        "commitment_sha256_hex": digest,
    });
    base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&payload).unwrap_or_default())
}

pub fn verify_poe_stub(
    poe_stub_b64: &str,
    task_sha256_hex: &str,
    result_sha256_hex: &str,
) -> Result<(), String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(poe_stub_b64.as_bytes())
        .map_err(|_| "poe: invalid base64".to_string())?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("poe: json: {e}"))?;
    let got = v
        .get("commitment_sha256_hex")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "poe: missing commitment".to_string())?;
    let mut h = Sha256::new();
    h.update(b"ZK-PoE:v1:stub");
    h.update(task_sha256_hex.as_bytes());
    h.update(result_sha256_hex.as_bytes());
    let want = hex::encode(h.finalize());
    if got != want {
        return Err("poe: commitment mismatch".into());
    }
    Ok(())
}

pub fn verify_worker_proof(ed25519_pubkey_hex: &str, proof: &WorkerProofV1) -> Result<(), String> {
    if result_sha256_hex(&proof.output_text) != proof.result_sha256_hex {
        return Err("result hash mismatch".into());
    }
    let msg = worker_sign_message(
        &proof.task_sha256_hex,
        &proof.result_sha256_hex,
        &proof.hardware_id_hex,
    );
    quantum_shield::verify_ed25519(ed25519_pubkey_hex, &proof.ed25519_sig_b64, &msg)
        .map_err(|e| e.to_string())?;
    verify_poe_stub(
        &proof.poe_stub_b64,
        &proof.task_sha256_hex,
        &proof.result_sha256_hex,
    )?;
    Ok(())
}

/// Full verification: pubkey, hashes vs model/input/output, PoE, signature.
pub fn verify_worker_proof_full(
    ed25519_pubkey_hex: &str,
    model: &str,
    input: &str,
    proof: &WorkerProofV1,
) -> Result<(), String> {
    let t = task_sha256_hex(model, input);
    if t != proof.task_sha256_hex {
        return Err("task hash mismatch".into());
    }
    if result_sha256_hex(&proof.output_text) != proof.result_sha256_hex {
        return Err("result hash mismatch".into());
    }
    verify_worker_proof(ed25519_pubkey_hex, proof)?;
    Ok(())
}
