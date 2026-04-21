//! Signed ledger snapshot replication (Passive Guardians over libp2p gossip).
//!
//! When `TET_REPLICA_SK_HEX` (32-byte secret key, hex) is set, each successful `tet_ledger.json`
//! snapshot emits a `LedgerGossip::StateSnapshotSigned` message for workers to archive.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use std::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;

static P2P_TX: Mutex<Option<UnboundedSender<Vec<u8>>>> = Mutex::new(None);

pub fn set_p2p_sender(tx: Option<UnboundedSender<Vec<u8>>>) {
    *P2P_TX
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = tx;
}

pub fn state_update_signing_message(sha256_hex: &str) -> String {
    format!("tet-state-v1|{sha256_hex}")
}

pub fn verify_state_snapshot_signed(
    sha256_hex: &str,
    snapshot_b64: &str,
    ed25519_pubkey_hex: &str,
    ed25519_sig_b64: &str,
) -> Result<Vec<u8>, String> {
    let msg = state_update_signing_message(sha256_hex);
    crate::quantum_shield::verify_ed25519(ed25519_pubkey_hex, ed25519_sig_b64, msg.as_bytes())
        .map_err(|e| e.to_string())?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(snapshot_b64.as_bytes())
        .map_err(|_| "snapshot_b64 decode failed".to_string())?;
    let mut h = Sha256::new();
    h.update(&raw);
    let got = hex::encode(h.finalize());
    if got != sha256_hex {
        return Err("snapshot sha256 mismatch".into());
    }
    Ok(raw)
}

pub fn emit_signed_state_update(snapshot_bytes: &[u8]) {
    let Ok(sk_hex) = std::env::var("TET_REPLICA_SK_HEX") else {
        return;
    };
    let sk_hex = sk_hex.trim();
    if sk_hex.len() != 64 {
        return;
    }
    let Ok(sk_bytes) = hex::decode(sk_hex) else {
        return;
    };
    let Ok(arr) = <[u8; 32]>::try_from(sk_bytes.as_slice()) else {
        return;
    };
    let signing_key = SigningKey::from_bytes(&arr);
    let vk = signing_key.verifying_key();

    let mut h = Sha256::new();
    h.update(snapshot_bytes);
    let sha256_hex = hex::encode(h.finalize());
    let msg = state_update_signing_message(&sha256_hex);
    let sig = signing_key.sign(msg.as_bytes());
    let gossip = serde_json::json!({
        "t": "state_snapshot_signed",
        "sha256_hex": sha256_hex,
        "snapshot_b64": base64::engine::general_purpose::STANDARD.encode(snapshot_bytes),
        "ed25519_pubkey_hex": hex::encode(vk.as_bytes()),
        "ed25519_sig_b64": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
    });
    let Ok(bytes) = serde_json::to_vec(&gossip) else {
        return;
    };
    let tx = P2P_TX.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sender) = tx.as_ref() else {
        return;
    };
    let _ = sender.send(bytes);
    eprintln!("[REPL] StateUpdate broadcast sha256={sha256_hex}");
}

pub fn guardian_store_verified_snapshot(snapshot_bytes: &[u8], sha256_hex: &str) {
    let dir = std::env::var("TET_GUARDIAN_DIR").unwrap_or_else(|_| "tet_guardian_store".into());
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("[REPL][guardian] mkdir failed: {e}");
        return;
    }
    let path = std::path::Path::new(&dir).join(format!("ledger_{sha256_hex}.json"));
    if let Err(e) = std::fs::write(&path, snapshot_bytes) {
        eprintln!("[REPL][guardian] write failed: {e}");
        return;
    }
    eprintln!("[REPL][guardian] snapshot stored {}", path.display());
}
