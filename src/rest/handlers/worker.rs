use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Serialize;

use crate::rest::state::E2eeJobV1;
use crate::rest::{
    ComputeE2eeResultResp, ComputeE2eeSubmitReq, ComputeE2eeSubmitResp, RestState,
    WorkerE2eeCompleteReq, WorkerE2eeNextResp, WorkerRegisterReq,
    helpers::{std_lock, verify_envelope_v1},
};
use rand_core::RngCore as _;

async fn post_worker_register_impl(
    State(state): State<RestState>,
    Json(req): Json<WorkerRegisterReq>,
) -> impl IntoResponse {
    let w_lower = req.wallet.trim().to_ascii_lowercase();
    if w_lower.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "WALLET_REQUIRED",
                "message": "wallet required"
            })),
        )
            .into_response();
    }
    // Founder must never be treated as a worker (no auto-grant, no heartbeat registry).
    if let Ok(founder) = state.ledger.founder_wallet_public()
        && !founder.trim().is_empty()
        && founder.trim().to_ascii_lowercase() == w_lower
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "FOUNDER_WORKER_FORBIDDEN",
                "message": "founder wallet cannot register as a worker"
            })),
        )
            .into_response();
    }
    // If the wallet has a founding cert (verified hardware attestation), enforce hardware_id match.
    if let Ok(cert) = state.ledger.get_founding_cert(&w_lower)
        && cert.hardware_id_hex.trim() != req.hardware_id_hex.trim()
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "ATTESTATION_HARDWARE_MISMATCH",
                "message": "hardware_id_hex does not match founding certificate",
            })),
        )
            .into_response();
    }
    // Genesis Guardians auto-grant: first N workers get a fixed grant from `system:worker_pool`.
    // This runs on first connect/heartbeat attempt so the economy is fully automated.
    let bond = state.ledger.worker_bond_micro(&w_lower).unwrap_or(0);
    if bond < crate::ledger::MIN_WORKER_STAKE_MICRO {
        let granted = state
            .ledger
            .grant_genesis_guardian_if_eligible(&w_lower)
            .unwrap_or(false);
        if granted {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "GRANT_ISSUED_STAKE_REQUIRED",
                    "message": "Genesis Guardian grant issued. Please stake and retry worker registration.",
                    "grant_tet": (crate::ledger::GENESIS_GUARDIAN_GRANT_MICRO as f64) / (crate::ledger::STEVEMON as f64),
                    "min_worker_bond_tet": (crate::ledger::MIN_WORKER_STAKE_MICRO as f64)
                        / (crate::ledger::STEVEMON as f64),
                })),
            )
                .into_response();
        }
        // Economic security wall: workers must maintain minimum stake.
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "WORKER_NOT_STAKED",
                "message": "insufficient stake to register heartbeat",
                "min_worker_bond_tet": (crate::ledger::MIN_WORKER_STAKE_MICRO as f64)
                    / (crate::ledger::STEVEMON as f64),
            })),
        )
            .into_response();
    }
    let mut w = std_lock(&state.workers);
    match w.heartbeat(
        &w_lower,
        &req.hardware_id_hex,
        &req.ed25519_pubkey_hex,
        req.x25519_pubkey_b64.as_deref(),
        req.mlkem_pubkey_b64.as_deref(),
        req.tflops_est.unwrap_or(1.0),
    ) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "WORKER_REGISTER_REJECTED", "message": e})),
        )
            .into_response(),
    }
}

async fn get_worker_model_status_impl() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(crate::worker_ai::model_status_v1().await),
    )
        .into_response()
}

async fn post_worker_model_download_impl() -> impl IntoResponse {
    // Fire-and-forget background download (single-flight is enforced inside worker_ai).
    tokio::spawn(async move {
        let _ = crate::worker_ai::start_model_download().await;
    });
    (StatusCode::ACCEPTED, Json(serde_json::json!({"ok": true}))).into_response()
}

pub async fn get_worker_ai_engine_status() -> impl IntoResponse {
    #[derive(serde::Serialize)]
    struct R {
        connected: bool,
        base_url: String,
        message: String,
    }

    let base = crate::rest::helpers::ollama_url_base();
    let url = format!("{}/api/tags", base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build();
    let ok = if let Ok(c) = client {
        match c.get(url).send().await {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        }
    } else {
        false
    };
    (
        axum::http::StatusCode::OK,
        axum::Json(R {
            connected: ok,
            base_url: base,
            message: if ok {
                "Ollama connected.".into()
            } else {
                "Ollama offline. Download & install Ollama to accept enterprise tasks.".into()
            },
        }),
    )
}

pub(crate) async fn enqueue_compute_e2ee_job(
    state: RestState,
    req: ComputeE2eeSubmitReq,
) -> axum::response::Response {
    let worker_wallet = req.worker_wallet.trim().to_string();
    if worker_wallet.is_empty() {
        return (StatusCode::BAD_REQUEST, "worker_wallet required").into_response();
    }

    // Ensure worker exists and has an X25519 + ML-KEM pubkey registered (for clients to trust).
    let reg = std_lock(&state.workers);
    let Some(w) = reg.by_wallet.get(&worker_wallet) else {
        return (StatusCode::BAD_REQUEST, "unknown worker_wallet").into_response();
    };
    if w.x25519_pubkey_b64.as_deref().unwrap_or("").is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "worker has no x25519_pubkey_b64 registered",
        )
            .into_response();
    }
    if w.mlkem_pubkey_b64.as_deref().unwrap_or("").is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "worker has no mlkem_pubkey_b64 registered",
        )
            .into_response();
    }
    drop(reg);

    // Cryptographically strong job id (no UUID shortcuts).
    let mut rbytes = [0u8; 16];
    let mut rng = rand_core::OsRng;
    rng.fill_bytes(&mut rbytes);
    let job_id = hex::encode(rbytes);

    let job = E2eeJobV1 {
        v: 1,
        job_id: job_id.clone(),
        worker_wallet: worker_wallet.clone(),
        // Payload: client ephemeral pk + nonce + ciphertext (all b64 in request).
        client_ephemeral_pub_b64: req.client_ephemeral_pub_b64.clone(),
        client_mlkem_pub_b64: req.client_mlkem_pub_b64.clone(),
        nonce_b64: req.nonce_b64.clone(),
        ciphertext_b64: req.ciphertext_b64.clone(),
        mlkem_ciphertext_b64: req.mlkem_ciphertext_b64.clone(),
        // Results are filled by worker callback.
        created_at_ms: crate::worker_network::now_ms(),
        completed: false,
        result_nonce_b64: None,
        result_ciphertext_b64: None,
        result_mlkem_ciphertext_b64: None,
    };

    let mut q = std_lock(&state.e2ee_jobs);
    q.jobs.insert(job_id.clone(), job.clone());
    q.pending_by_worker
        .entry(worker_wallet)
        .or_default()
        .push_back(job_id.clone());
    drop(q);

    (
        StatusCode::OK,
        Json(ComputeE2eeSubmitResp {
            job_id,
            status: "queued".into(),
        }),
    )
        .into_response()
}

async fn post_v1_compute_e2ee_submit_impl(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(req): Json<ComputeE2eeSubmitReq>,
) -> axum::response::Response {
    if let Err(e) = verify_envelope_v1(&req.payment) {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }
    enqueue_compute_e2ee_job(state, req).await
}

async fn get_v1_compute_e2ee_result_impl(
    State(state): State<RestState>,
    Path(job_id): Path<String>,
) -> axum::response::Response {
    let q = std_lock(&state.e2ee_jobs);
    let Some(j) = q.jobs.get(job_id.trim()) else {
        return (StatusCode::NOT_FOUND, "job not found").into_response();
    };
    let status = if j.completed { "done" } else { "pending" };
    (
        StatusCode::OK,
        Json(ComputeE2eeResultResp {
            job_id: j.job_id.clone(),
            status: status.into(),
            result_nonce_b64: j.result_nonce_b64.clone(),
            result_ciphertext_b64: j.result_ciphertext_b64.clone(),
        }),
    )
        .into_response()
}

async fn get_worker_e2ee_next_impl(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> axum::response::Response {
    let wallet = wallet.trim().to_string();
    if wallet.is_empty() {
        return (StatusCode::BAD_REQUEST, "wallet required").into_response();
    }
    let mut q = std_lock(&state.e2ee_jobs);
    loop {
        let next_id = {
            q.pending_by_worker
                .get_mut(&wallet)
                .and_then(|p| p.pop_front())
        };
        let Some(job_id) = next_id else {
            return (StatusCode::NO_CONTENT, "").into_response();
        };
        let j_opt = q.jobs.get(&job_id).cloned();
        if let Some(j) = j_opt
            && !j.completed
        {
            return (
                StatusCode::OK,
                Json(WorkerE2eeNextResp {
                    job_id: j.job_id,
                    client_ephemeral_pub_b64: j.client_ephemeral_pub_b64,
                    nonce_b64: j.nonce_b64,
                    ciphertext_b64: j.ciphertext_b64,
                }),
            )
                .into_response();
        }
    }
}

async fn post_worker_e2ee_complete_impl(
    State(state): State<RestState>,
    Json(req): Json<WorkerE2eeCompleteReq>,
) -> axum::response::Response {
    let wallet = req.wallet.trim();
    let job_id = req.job_id.trim();
    if wallet.is_empty() || job_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "wallet and job_id required").into_response();
    }
    let mut q = std_lock(&state.e2ee_jobs);
    let Some(j) = q.jobs.get_mut(job_id) else {
        return (StatusCode::NOT_FOUND, "job not found").into_response();
    };
    if j.worker_wallet != wallet {
        return (StatusCode::FORBIDDEN, "wrong worker").into_response();
    }
    j.completed = true;
    j.result_nonce_b64 = Some(req.result_nonce_b64);
    j.result_ciphertext_b64 = Some(req.result_ciphertext_b64);
    j.result_mlkem_ciphertext_b64 = Some(req.result_mlkem_ciphertext_b64);
    (StatusCode::OK, "ok").into_response()
}

async fn get_worker_stats_impl(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    #[derive(Serialize)]
    struct R {
        wallet: String,
        online: bool,
        tflops_est: f64,
        last_seen_ms: u128,
        #[serde(skip_serializing_if = "Option::is_none")]
        caac_role: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        caac_latency_ms: Option<u64>,
    }
    let ttl = std::env::var("TET_WORKER_HEARTBEAT_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(120_000);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let entry = {
        let reg = std_lock(&state.workers);
        reg.by_wallet.get(wallet.trim()).cloned()
    };
    if let Some(e) = entry {
        let online = now_ms.saturating_sub(e.last_seen_ms) <= ttl;
        let ledger_caac = state.ledger.caac_get_worker_record(wallet.trim());
        let caac_role = ledger_caac
            .as_ref()
            .map(|r| r.role.clone())
            .or_else(|| e.caac_role.clone());
        let caac_latency_ms = ledger_caac.map(|r| r.latency_ms);
        (
            StatusCode::OK,
            Json(R {
                wallet: e.wallet,
                online,
                tflops_est: e.tflops_est,
                last_seen_ms: e.last_seen_ms,
                caac_role,
                caac_latency_ms,
            }),
        )
            .into_response()
    } else {
        (StatusCode::NOT_FOUND, "worker not found").into_response()
    }
}

async fn get_worker_pending_impl(Path(wallet): Path<String>) -> impl IntoResponse {
    let _ = wallet;
    #[derive(Serialize)]
    struct R {
        pending_stevemon_micro: u64,
    }
    // Stub: real pending queue lands in Phase 4 (escrow/settlement).
    (
        StatusCode::OK,
        Json(R {
            pending_stevemon_micro: 0,
        }),
    )
        .into_response()
}

#[derive(Serialize)]
struct WorkerCockpitDaemonResp {
    enabled: bool,
    poll_ms: u64,
    current_task_count: u64,
}

#[derive(Serialize)]
struct WorkerCockpitHardwareResp {
    gpu_detected: bool,
    gpu_hint: String,
    tflops_est: f64,
    caac_latency_ms: Option<u64>,
    server_wall_ms: Option<u64>,
    cpu_logical_cores: u32,
    ram_total_bytes: u64,
}

#[derive(Serialize)]
struct WorkerCockpitResp {
    wallet: String,
    role: String,
    online: bool,
    balance_micro: u64,
    estimated_total_rewards_micro: u64,
    processed_task_count: u64,
    zk_success_count: u64,
    daemon: WorkerCockpitDaemonResp,
    hardware: WorkerCockpitHardwareResp,
    last_seen_ms: Option<u128>,
}

fn env_truthy(name: &str, default: bool) -> bool {
    match std::env::var(name).ok().as_deref().map(str::trim) {
        Some("0") | Some("false") | Some("FALSE") | Some("no") | Some("NO") => false,
        Some("") => default,
        Some(_) => true,
        None => default,
    }
}

fn estimate_tflops_from_caac(
    registry_tflops: f64,
    role: &str,
    gpu_detected: bool,
    cpu_logical_cores: u32,
    ram_total_bytes: u64,
) -> f64 {
    if registry_tflops.is_finite() && registry_tflops > 0.0 {
        return registry_tflops;
    }
    let ram_gib = (ram_total_bytes as f64) / (1024.0 * 1024.0 * 1024.0);
    let cpu_floor = (cpu_logical_cores as f64 * 0.08).max(0.1);
    let gpu_bonus = if gpu_detected { 8.0 } else { 0.0 };
    let role_bonus = if role.eq_ignore_ascii_case("POC") {
        1.5
    } else {
        0.0
    };
    (cpu_floor + gpu_bonus + role_bonus + ram_gib.min(128.0) * 0.01).max(0.0)
}

async fn get_worker_cockpit_impl(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let wallet = wallet.trim().to_ascii_lowercase();
    if wallet.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "WALLET_REQUIRED",
                "message": "wallet required"
            })),
        )
            .into_response();
    }

    let ttl = std::env::var("TET_WORKER_HEARTBEAT_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(120_000);
    let now_ms = crate::worker_network::now_ms();
    let entry = {
        let reg = std_lock(&state.workers);
        reg.by_wallet.get(&wallet).cloned()
    };
    let online = entry
        .as_ref()
        .map(|e| now_ms.saturating_sub(e.last_seen_ms) <= ttl)
        .unwrap_or(false);

    let ledger_caac = state.ledger.caac_get_worker_record(&wallet);
    let local_profile = crate::vision::caac::profile();
    let local_role = crate::vision::caac::role_to_tag(local_profile.role).to_string();
    let role = ledger_caac
        .as_ref()
        .map(|r| r.role.trim().to_ascii_uppercase())
        .filter(|r| !r.is_empty())
        .or_else(|| entry.as_ref().and_then(|e| e.caac_role.clone()))
        .unwrap_or(local_role);

    let balance_micro = state.ledger.balance_micro(&wallet).unwrap_or(0);
    let (processed_task_count, zk_success_count, current_task_count) = state
        .ledger
        .ai_workload_cockpit_counts_for_worker(&wallet)
        .unwrap_or((0, 0, 0));
    let estimated_total_rewards_micro = balance_micro;
    let daemon = WorkerCockpitDaemonResp {
        enabled: env_truthy("TET_WORKER_DAEMON", true),
        poll_ms: std::env::var("TET_WORKER_DAEMON_POLL_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(2_000),
        current_task_count,
    };

    let registry_tflops = entry.as_ref().map(|e| e.tflops_est).unwrap_or(0.0);
    let tflops_est = estimate_tflops_from_caac(
        registry_tflops,
        &role,
        local_profile.hw.gpu_detected,
        local_profile.hw.cpu_logical_cores,
        local_profile.hw.ram_total_bytes,
    );
    let hardware = WorkerCockpitHardwareResp {
        gpu_detected: local_profile.hw.gpu_detected,
        gpu_hint: local_profile.hw.gpu_hint,
        tflops_est,
        caac_latency_ms: ledger_caac.as_ref().map(|r| r.latency_ms),
        server_wall_ms: ledger_caac.as_ref().map(|r| r.server_wall_ms),
        cpu_logical_cores: local_profile.hw.cpu_logical_cores,
        ram_total_bytes: local_profile.hw.ram_total_bytes,
    };

    (
        StatusCode::OK,
        Json(WorkerCockpitResp {
            wallet,
            role,
            online,
            balance_micro,
            estimated_total_rewards_micro,
            processed_task_count,
            zk_success_count,
            daemon,
            hardware,
            last_seen_ms: entry.as_ref().map(|e| e.last_seen_ms),
        }),
    )
        .into_response()
}

pub async fn post_worker_register(
    State(state): State<RestState>,
    Json(req): Json<WorkerRegisterReq>,
) -> impl IntoResponse {
    post_worker_register_impl(State(state), Json(req)).await
}

pub async fn get_worker_model_status() -> impl IntoResponse {
    get_worker_model_status_impl().await
}

pub async fn post_worker_model_download() -> impl IntoResponse {
    post_worker_model_download_impl().await
}

pub async fn post_v1_compute_e2ee_submit(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<ComputeE2eeSubmitReq>,
) -> axum::response::Response {
    post_v1_compute_e2ee_submit_impl(State(state), headers, Json(req)).await
}

pub async fn get_v1_compute_e2ee_result(
    State(state): State<RestState>,
    Path(job_id): Path<String>,
) -> axum::response::Response {
    get_v1_compute_e2ee_result_impl(State(state), Path(job_id)).await
}

pub async fn get_worker_e2ee_next(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> axum::response::Response {
    get_worker_e2ee_next_impl(State(state), Path(wallet)).await
}

pub async fn post_worker_e2ee_complete(
    State(state): State<RestState>,
    Json(req): Json<WorkerE2eeCompleteReq>,
) -> axum::response::Response {
    post_worker_e2ee_complete_impl(State(state), Json(req)).await
}

pub async fn get_worker_stats(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    get_worker_stats_impl(State(state), Path(wallet)).await
}

pub async fn get_worker_pending(Path(wallet): Path<String>) -> impl IntoResponse {
    get_worker_pending_impl(Path(wallet)).await
}

pub async fn get_worker_cockpit(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    get_worker_cockpit_impl(State(state), Path(wallet)).await
}
