//! REST scaffolding for whitepaper Phase 0–2 modules (`crate::vision`).

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;

use crate::rest::{RestState, helpers::std_lock};

#[derive(Debug, Deserialize)]
pub struct InferEstimateQuery {
    /// Declared inference FLOPs (required — §4.2 uses exact C_flops only).
    #[serde(default)]
    pub flops: Option<u64>,
}

pub async fn get_vision_caac_profile() -> impl IntoResponse {
    let p = crate::vision::caac::profile();
    (StatusCode::OK, Json(p)).into_response()
}

pub async fn get_vision_caac_challenge() -> impl IntoResponse {
    let c = crate::vision::caac::generate_hardware_challenge();
    (StatusCode::OK, Json(c)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct CaacCompleteReq {
    pub wallet: String,
    pub seed_hex: String,
    /// Lowercase hex from [`crate::vision::caac::compute_challenge_digest`].
    pub digest_hex: String,
    /// Wall time on worker while executing the challenge (ms).
    pub client_latency_ms: u64,
}

pub async fn post_vision_caac_complete(
    State(state): State<RestState>,
    Json(req): Json<CaacCompleteReq>,
) -> impl IntoResponse {
    let w = req.wallet.trim().to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"BAD_WALLET","message":"wallet must be 64 hex chars"})),
        )
            .into_response();
    }
    let expected = match crate::vision::caac::compute_challenge_digest(&req.seed_hex) {
        Ok(x) => x,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"BAD_SEED","message": e})),
            )
                .into_response();
        }
    };
    if !expected.eq_ignore_ascii_case(req.digest_hex.trim()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"DIGEST_MISMATCH"})),
        )
            .into_response();
    }
    let bond = state.ledger.worker_bond_micro(&w).unwrap_or(0);
    if bond < crate::ledger::MIN_WORKER_STAKE_MICRO {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error":"WORKER_BOND_REQUIRED",
                "min_worker_bond_tet": (crate::ledger::MIN_WORKER_STAKE_MICRO as f64) / (crate::ledger::STEVEMON as f64),
            })),
        )
            .into_response();
    }
    let role = crate::vision::caac::role_from_latency_ms(req.client_latency_ms);
    let tag = crate::vision::caac::role_to_tag(role);
    let server_wall_ms = crate::vision::caac::measure_challenge_wall_ms(&req.seed_hex).unwrap_or(0);
    let rec = crate::ledger::CaacWorkerRecord {
        role: tag.to_string(),
        latency_ms: req.client_latency_ms,
        seed_hex: req.seed_hex.trim().to_ascii_lowercase(),
        server_wall_ms,
    };
    if let Err(e) = state.ledger.caac_put_worker_record(&w, &rec) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"LEDGER","message": e.to_string()})),
        )
            .into_response();
    }
    {
        let mut reg = std_lock(&state.workers);
        reg.set_caac_role(&w, tag.to_string());
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "role": tag,
            "server_wall_ms": server_wall_ms,
        })),
    )
        .into_response()
}

pub async fn get_vision_caac_worker(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let w = wallet.trim().to_ascii_lowercase();
    let ledger_rec = state.ledger.caac_get_worker_record(&w);
    let registry_caac_role = std_lock(&state.workers)
        .by_wallet
        .get(&w)
        .and_then(|e| e.caac_role.clone());
    (
        StatusCode::OK,
        Json(json!({
            "wallet": w,
            "ledger": ledger_rec,
            "registry_caac_role": registry_caac_role,
        })),
    )
        .into_response()
}

pub async fn get_vision_oracle_zk_court_alerts() -> impl IntoResponse {
    let alerts = crate::vision::zk_court::list_zk_court_logs();
    (
        StatusCode::OK,
        Json(json!({
            "alerts": alerts,
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct OptimisticVerifyReq {
    pub worker_id: String,
    pub commitment_b64: String,
    pub proof_b64: String,
}

pub async fn post_vision_zk_court_verify_optimistic(
    State(state): State<RestState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<OptimisticVerifyReq>,
) -> impl IntoResponse {
    if let Err(r) = crate::rest::helpers::require_admin_bearer(&headers) {
        return r;
    }
    let commitment =
        match base64::engine::general_purpose::STANDARD.decode(req.commitment_b64.trim()) {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error":"BAD_COMMITMENT_B64","message": e.to_string()})),
                )
                    .into_response();
            }
        };
    let proof = match base64::engine::general_purpose::STANDARD.decode(req.proof_b64.trim()) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"BAD_PROOF_B64","message": e.to_string()})),
            )
                .into_response();
        }
    };
    match crate::vision::zk_court::execute_optimistic_slash_if_fraud(
        state.ledger.as_ref(),
        &state.workers,
        req.worker_id.trim(),
        &commitment,
        &proof,
    ) {
        Ok(None) => (
            StatusCode::OK,
            Json(json!({"valid": true, "slashed": false})),
        )
            .into_response(),
        Ok(Some(p)) => (
            StatusCode::OK,
            Json(json!({
                "valid": false,
                "slashed": true,
                "worker_id": p.worker_id,
                "punishment": p.punishment,
                "offense": p.offense,
                "timestamp": p.timestamp,
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

pub async fn get_vision_zk_court_params() -> impl IntoResponse {
    (StatusCode::OK, Json(crate::vision::zk_court::params_json())).into_response()
}

pub async fn get_vision_zk_court_challenges() -> impl IntoResponse {
    let v = crate::vision::zk_court::list_open();
    (StatusCode::OK, Json(v)).into_response()
}

pub async fn post_vision_zk_court_challenge(
    State(state): State<RestState>,
    Json(req): Json<crate::vision::zk_court::ChallengeSubmitReq>,
) -> impl IntoResponse {
    match crate::vision::zk_court::run_challenge_pipeline(state.ledger.as_ref(), &req).await {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

pub async fn get_vision_pqc_status() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(crate::vision::pqc_bridge::status_json()),
    )
        .into_response()
}

pub async fn get_vision_thermo_genesis() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(crate::vision::thermo_genesis::genesis_vision_json()),
    )
        .into_response()
}

pub async fn get_vision_ai_infer_estimate(
    Query(q): Query<InferEstimateQuery>,
) -> impl IntoResponse {
    let Some(flops) = q.flops else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "FLOPS_REQUIRED",
                "message": "Query parameter `flops` is required for thermodynamic §4.2 estimate (prompt-length heuristics removed).",
            })),
        )
            .into_response();
    };
    let est = crate::vision::thermo_genesis::estimate_ai_infer_cost_micro(flops as u128);
    (StatusCode::OK, Json(est)).into_response()
}

pub async fn get_vision_network_config(State(state): State<RestState>) -> impl IntoResponse {
    let boot = crate::vision::fluid_net::bootnode_addrs_from_env();
    let workers = std_lock(&state.workers).active_count(60_000);
    let p2p_enabled = state.p2p_client.is_some();
    let connected_peers = match state.p2p_client.as_ref() {
        Some(c) => match c.connected_peers_count().await {
            Ok(n) => n,
            Err(e) => {
                log::error!("[vision] connected_peers_count failed: {e}");
                0
            }
        },
        None => 0,
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "bootnodes": boot,
            "active_workers_registry": workers,
            "connected_peers": connected_peers,
            "p2p_enabled": p2p_enabled,
            "p2p_listen_env": "TET_P2P_LISTEN (default /ip4/0.0.0.0/tcp/0)",
            "bootnode_env": ["TET_BOOTNODES", "BOOTNODES"],
            "http_bind_env": "TET_REST_BIND (default now 0.0.0.0:{PORT})",
        })),
    )
        .into_response()
}
