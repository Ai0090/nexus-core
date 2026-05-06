//! Bridges whitepaper “PQC-first” narrative onto the hybrid stack (`quantum_shield`, `wallet` ML-DSA).

pub fn status_json() -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "mldsa_profile_default".into(),
        serde_json::json!("ML-DSA-65 (FIPS 204; Dilithium3)"),
    );
    m.insert(
        "mldsa_levels_accepted".into(),
        serde_json::json!("ML-DSA-44 / ML-DSA-65 / ML-DSA-87 (pubkey length inference)"),
    );
    m.insert(
        "stack".into(),
        serde_json::json!(
            "dilithium-rs via wallet.rs / tet-signer / @noble/post-quantum (browser)"
        ),
    );
    m.insert(
        "pqc_active".into(),
        serde_json::json!(crate::quantum_shield::pqc_active()),
    );
    m.insert(
        "transaction_verification".into(),
        serde_json::json!(
            "Hybrid AND: Ed25519 wallet id + ML-DSA detached signature on shared canonical bytes"
        ),
    );
    m.insert(
        "genesis_pqc_track".into(),
        serde_json::json!("Founder/enrollment flows carry ml-dsa pubkey material (existing REST)"),
    );
    m.insert(
        "env_generation_level".into(),
        serde_json::json!(
            std::env::var("TET_MLDSA_SECURITY_LEVEL").unwrap_or_else(|_| "65 (default)".into())
        ),
    );
    if let serde_json::Value::Object(ks) = tet_core::pqc_keystore::node_keystore_status_from_env() {
        for (k, v) in ks {
            m.insert(k, v);
        }
    }
    serde_json::Value::Object(m)
}
