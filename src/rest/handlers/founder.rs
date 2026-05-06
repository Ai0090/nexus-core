use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::{
    ledger::LedgerError,
    rest::{FounderGenesisReq, FounderWithdrawTreasuryReq, RestState},
};

pub async fn post_founder_withdraw_treasury(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<FounderWithdrawTreasuryReq>,
) -> axum::response::Response {
    let wid = req.founder_wallet_id.trim().to_ascii_lowercase();
    if wid.len() != 64 || !wid.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            "founder_wallet_id must be 64 hex characters (Ed25519 verifying key)",
        )
            .into_response();
    }
    let configured = match state.ledger.founder_wallet_public() {
        Ok(f) => f.trim().to_ascii_lowercase(),
        Err(_) => String::new(),
    };
    if configured.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "founder wallet not configured on ledger",
        )
            .into_response();
    }
    if wid != configured {
        return (
            StatusCode::FORBIDDEN,
            "founder_wallet_id must match the ledger founder wallet",
        )
            .into_response();
    }
    const MAX_B64_FIELD: usize = 16_384;
    if req.mldsa_pubkey_b64.len() > MAX_B64_FIELD || req.mldsa_signature_b64.len() > MAX_B64_FIELD {
        return (
            StatusCode::BAD_REQUEST,
            "mldsa_pubkey_b64 or mldsa_signature_b64 exceeds maximum length",
        )
            .into_response();
    }
    let sig_b64 = headers
        .get("x-tet-founder-ed25519-sig-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if sig_b64.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            "missing x-tet-founder-ed25519-sig-b64 (hybrid founder withdraw)",
        )
            .into_response();
    }
    if !(req.amount_tet.is_finite()) || req.amount_tet <= 0.0 {
        return (StatusCode::BAD_REQUEST, "amount_tet must be > 0").into_response();
    }
    let amount_micro =
        ((req.amount_tet * crate::ledger::STEVEMON as f64).round() as i128).max(0) as u64;
    if amount_micro == 0 {
        return (StatusCode::BAD_REQUEST, "amount_tet too small").into_response();
    }
    let msg = crate::wallet::founder_withdraw_treasury_hybrid_auth_message_bytes(
        &wid,
        amount_micro,
        req.nonce,
        &req.mldsa_pubkey_b64,
    );
    if let Err(e) = crate::quantum_shield::verify_ed25519(&wid, sig_b64, &msg) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid founder ed25519 signature: {e}"),
        )
            .into_response();
    }
    if let Err(e) =
        crate::wallet::verify_mldsa_b64(&req.mldsa_pubkey_b64, &req.mldsa_signature_b64, &msg)
    {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid founder ml-dsa signature: {e}"),
        )
            .into_response();
    }
    match state
        .ledger
        .withdraw_treasury_to_founder(amount_micro, req.nonce)
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "amount_micro": amount_micro})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e:?}")).into_response(),
    }
}

pub async fn post_founder_genesis(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<FounderGenesisReq>,
) -> axum::response::Response {
    let wid = req.founder_wallet_id.trim().to_ascii_lowercase();
    if wid.len() != 64 || !wid.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            "founder_wallet_id must be 64 hex characters (Ed25519 verifying key)",
        )
            .into_response();
    }
    let configured = match state.ledger.founder_wallet_public() {
        Ok(f) => f.trim().to_ascii_lowercase(),
        Err(_) => String::new(),
    };
    if configured.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "founder wallet not configured on ledger",
        )
            .into_response();
    }
    if wid != configured {
        return (
            StatusCode::FORBIDDEN,
            "founder_wallet_id must match the ledger founder wallet",
        )
            .into_response();
    }
    const MAX_B64_FIELD: usize = 16_384;
    if req.mldsa_pubkey_b64.len() > MAX_B64_FIELD || req.mldsa_signature_b64.len() > MAX_B64_FIELD {
        return (
            StatusCode::BAD_REQUEST,
            "mldsa_pubkey_b64 or mldsa_signature_b64 exceeds maximum length",
        )
            .into_response();
    }
    let sig_b64 = headers
        .get("x-tet-founder-ed25519-sig-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if sig_b64.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            "missing x-tet-founder-ed25519-sig-b64 (hybrid founder genesis)",
        )
            .into_response();
    }
    let msg = crate::wallet::founder_genesis_hybrid_auth_message_bytes(&wid, &req.mldsa_pubkey_b64);
    if let Err(e) = crate::quantum_shield::verify_ed25519(&wid, sig_b64, &msg) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid founder ed25519 signature: {e}"),
        )
            .into_response();
    }
    if let Err(e) =
        crate::wallet::verify_mldsa_b64(&req.mldsa_pubkey_b64, &req.mldsa_signature_b64, &msg)
    {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid founder ml-dsa signature: {e}"),
        )
            .into_response();
    }
    match state.ledger.apply_genesis_allocation(&wid) {
        Ok(summary) => {
            let tet = |micro: u64| micro as f64 / crate::ledger::STEVEMON as f64;
            eprintln!(
                "\n\
╔══════════════════════════════════════════════════════════════════════════════╗\n\
║  TET GENESIS BLOCK — PHASE 1 FOUNDER PREMINE (2.5B TET)                      ║\n\
╠══════════════════════════════════════════════════════════════════════════════╣\n\
║  Tokenomics                                                                  ║\n\
╚══════════════════════════════════════════════════════════════════════════════╝"
            );
            eprintln!(
                "  · Founder genesis → {} TET  wallet={}",
                tet(summary.founder_allocation_micro),
                summary.founder_wallet_id
            );
            eprintln!(
                "  · DEX treasury     → {} TET",
                tet(summary.dex_treasury_allocation_micro)
            );
            eprintln!(
                "  · Worker pool      → {} TET  wallet={}",
                tet(summary.worker_pool_allocation_micro),
                crate::ledger::WALLET_SYSTEM_WORKER_POOL
            );
            eprintln!(
                "  · TOTAL SUPPLY     = {} TET (micro={}) — HARD CAP {}\n",
                tet(summary.total_supply_micro),
                summary.total_supply_micro,
                tet(crate::ledger::MAX_SUPPLY_MICRO),
            );
            (StatusCode::OK, Json(summary)).into_response()
        }
        Err(LedgerError::GenesisAlreadyApplied) => {
            eprintln!(
                "[GENESIS] rejected duplicate POST /founder/genesis (409): one-shot genesis already applied"
            );
            (
                StatusCode::CONFLICT,
                "genesis already applied: total supply must be zero",
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn get_founder_audit_csv(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let w = headers
        .get("x-tet-wallet-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::UNAUTHORIZED, "missing/invalid x-tet-wallet-id").into_response();
    }
    let founder = state.ledger.founder_wallet_public().unwrap_or_default();
    if founder.is_empty() || w != founder {
        return (StatusCode::UNAUTHORIZED, "founder only").into_response();
    }
    let limit = std::env::var("TET_FOUNDER_AUDIT_CSV_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(20_000);
    match state.ledger.audit_csv_export(limit) {
        Ok(csv) => (
            StatusCode::OK,
            [("content-type", "text/csv; charset=utf-8")],
            csv,
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}
