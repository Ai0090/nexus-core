//! Node-local ML-DSA-65 material (auxiliary to wallet mnemonic-derived keys).

use base64::Engine as _;
use dilithium::{ML_DSA_65, MlDsaKeyPair};
use rand_core::{OsRng, RngCore as _};
use std::path::{Path, PathBuf};

const PK_FILE: &str = "node_mldsa65_pubkey.b64";
const SK_FILE: &str = "node_mldsa65_secret.raw";

fn paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join(PK_FILE), dir.join(SK_FILE))
}

/// Ensures `node_mldsa65_*` files exist under `db_dir` (same directory as the sled ledger).
pub fn ensure_node_mldsa_keystore(db_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(db_dir).map_err(|e| e.to_string())?;
    let (pk_path, sk_path) = paths(db_dir);
    if pk_path.is_file() && sk_path.is_file() {
        return Ok(());
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let kp = MlDsaKeyPair::generate_deterministic(ML_DSA_65, &seed);
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(kp.public_key());
    std::fs::write(&pk_path, pk_b64.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::write(&sk_path, kp.private_key()).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&sk_path)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&sk_path, perms).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Short status line for `/v1/vision/pqc/status` when `TET_DB_DIR` is set.
pub fn node_keystore_status_from_env() -> serde_json::Value {
    let Some(raw) = std::env::var("TET_DB_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
    else {
        return serde_json::json!({ "node_mldsa65_keystore": "unknown (set TET_DB_DIR)" });
    };
    let dir = Path::new(raw.trim());
    let (pk_path, sk_path) = paths(dir);
    let ok = pk_path.is_file() && sk_path.is_file();
    serde_json::json!({
        "node_mldsa65_keystore": if ok { "present" } else { "missing" },
        "path_pubkey_b64": pk_path.display().to_string(),
        "path_secret_raw": sk_path.display().to_string(),
    })
}
