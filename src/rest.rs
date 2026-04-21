use crate::ai_proxy::AiProxyReq;
use crate::attestation::{AttestationReport, hardware_id_hex, verify_attestation_report};
use crate::conductor::{
    OrchestratePlan, OrchestrateRunResult, ShardSpec, shard_ai_inference, shard_scientific_grid,
    shard_video_rendering,
};
use crate::ledger::{FoundingMemberCert, Ledger, LedgerError, MAX_SUPPLY_MICRO, STEVEMON};
use crate::p2p_dex::{DexEngine, Side as DexSide, escrow_wallet_for_order};
use crate::protocol::{SignedTxEnvelopeV1, TxV1};
use crate::worker_network::{NetworkPowerSnapshot, NetworkStats, WorkerRegistry};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use base64::Engine as _;
use rand_core::RngCore as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::Duration;
use sysinfo::System;
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, CorsLayer};

fn ollama_url_base() -> String {
    std::env::var("TET_OLLAMA_URL_BASE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11434".into())
}

fn ollama_timeout() -> Duration {
    let sec = std::env::var("TET_OLLAMA_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s > 0 && s <= 3600)
        .unwrap_or(120);
    Duration::from_secs(sec)
}

async fn ollama_generate(model: &str, prompt: &str) -> Result<String, String> {
    #[derive(Serialize)]
    struct Req<'a> {
        model: &'a str,
        prompt: &'a str,
        stream: bool,
    }
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        response: String,
    }
    let base = ollama_url_base();
    let url = format!("{}/api/generate", base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(ollama_timeout())
        .build()
        .map_err(|e| e.to_string())?;
    let r = client
        .post(url)
        .json(&Req {
            model,
            prompt,
            stream: false,
        })
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = r.status();
    let body = r.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("ollama HTTP {}: {}", status.as_u16(), body.trim()));
    }
    let v: Resp = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    Ok(v.response)
}

async fn get_worker_ai_engine_status() -> impl IntoResponse {
    #[derive(Serialize)]
    struct R {
        connected: bool,
        base_url: String,
        message: String,
    }
    let base = ollama_url_base();
    let url = format!("{}/api/tags", base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
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
        StatusCode::OK,
        Json(R {
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

/// Poisoned mutex recovery: never panic the HTTP server on `lock()` poison.
#[inline]
fn std_lock<'a, T>(m: &'a StdMutex<T>) -> MutexGuard<'a, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct E2eeJobV1 {
    v: u32,
    job_id: String,
    worker_wallet: String,
    client_ephemeral_pub_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
    created_at_ms: u128,
    completed: bool,
    result_nonce_b64: Option<String>,
    result_ciphertext_b64: Option<String>,
}

#[derive(Default)]
pub struct E2eeJobQueue {
    jobs: std::collections::HashMap<String, E2eeJobV1>,
    pending_by_worker: std::collections::HashMap<String, std::collections::VecDeque<String>>,
}

#[derive(Clone)]
pub struct RestState {
    pub ledger: Arc<Ledger>,
    pub p2p_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    pub http_ratelimit: Arc<Mutex<HttpRateLimit>>,
    pub workers: Arc<StdMutex<WorkerRegistry>>,
    pub e2ee_jobs: Arc<StdMutex<E2eeJobQueue>>,
    pub dex: Arc<StdMutex<DexEngine>>,
    pub genesis_1k_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug)]
pub struct HttpRateLimit {
    window_start: std::time::Instant,
    count: u64,
    max_per_sec: u64,
}

impl HttpRateLimit {
    pub fn new(max_per_sec: u64) -> Self {
        Self {
            window_start: std::time::Instant::now(),
            count: 0,
            max_per_sec: max_per_sec.max(1),
        }
    }
}

pub async fn serve(state: RestState, addr: SocketAddr) -> Result<(), std::io::Error> {
    // Production-safe CORS: disabled by default (same-origin hosting does not need CORS).
    // Enable cross-origin explicitly via `TET_CORS_ORIGINS`, a comma-separated allowlist.
    let cors = std::env::var("TET_CORS_ORIGINS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .map(|origins| {
            let origins = Arc::new(origins);
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(move |origin, _req| {
                    let o = origin.to_str().unwrap_or("");
                    origins.iter().any(|x| x == o)
                }))
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::HeaderName::from_static("x-api-key"),
                    axum::http::header::HeaderName::from_static("x-tet-wallet-id"),
                    axum::http::header::HeaderName::from_static("x-tet-ed25519-sig-b64"),
                    axum::http::header::HeaderName::from_static("x-tet-mldsa-pubkey-b64"),
                    axum::http::header::HeaderName::from_static("x-tet-mldsa-sig-b64"),
                ])
        });

    let mw_state = state.clone();
    let shutdown_state = state.clone();
    let mut app = Router::new()
        .route("/", get(get_index))
        // Marketing home (/) is strictly separated from the operator app (/app).
        .route("/app", get(get_worker_app))
        // Keep the legacy core UI accessible at a non-root path.
        .route("/core", get(get_ui))
        // Back-compat for old deep links from early builds.
        .route("/worker_dashboard.html", get(get_worker_app_redirect))
        .route("/founder", get(get_founder_terminal))
        .route("/assets/founder_terminal.js", get(get_founder_terminal_js))
        .route(
            "/assets/wallet_client_bundled.js",
            get(get_wallet_client_bundled_js),
        )
        .route("/assets/ui.js", get(get_ui_js))
        .route("/assets/tet_sdk.js", get(get_tet_sdk_js))
        .route("/assets/tet_sdk_node.mjs", get(get_tet_sdk_node_mjs))
        .route("/status", get(get_status))
        .route("/logout", post(post_logout))
        .route("/telemetry/local", get(get_local_telemetry))
        .route(
            "/wallet/mnemonic/new",
            get(get_wallet_mnemonic_new).post(post_wallet_new),
        )
        .route("/wallet/mnemonic/recover", post(post_wallet_recover))
        .route("/wallet/active", post(post_wallet_set_active))
        .route("/wallet/nonce/:wallet", get(get_wallet_transfer_nonce))
        .route("/wallet/transfer", post(post_wallet_transfer))
        .route("/wallet/stake", post(post_wallet_stake))
        .route("/wallet/slash", post(post_wallet_slash))
        .route("/signer/link", post(post_signer_link))
        .route("/founding/enroll", post(post_founding_enroll))
        .route("/founding/cert/:wallet", get(get_founding_cert))
        .route("/ledger/me", get(get_ledger_me))
        .route("/genesis/1000/status", get(get_genesis_1k_status))
        .route("/genesis/1000/claim", post(post_genesis_1k_claim))
        .route("/ledger/balance/:wallet", get(get_ledger_balance))
        .route("/ledger/transfer", post(post_transfer_enveloped))
        .route("/ledger/mint_demo", post(post_mint_demo))
        .route("/ledger/proof", get(get_proofs))
        .route("/ledger/proof/:id", get(get_proof_by_id))
        .route(
            "/ledger/genesis_bridge",
            post(post_genesis_bridge_enveloped),
        )
        .route("/tx/submit", post(post_tx_submit))
        .route("/ai/pricing", get(get_ai_pricing))
        .route("/ai/proxy", post(post_ai_proxy))
        .route("/ai/utility", post(post_ai_utility))
        .route("/enterprise/inference", post(post_enterprise_inference))
        .route("/worker/register", post(post_worker_register))
        .route("/worker/model/status", get(get_worker_model_status))
        .route("/worker/model/download", post(post_worker_model_download))
        .route("/worker/ai_engine/status", get(get_worker_ai_engine_status))
        .route("/v1/compute_e2ee/submit", post(post_v1_compute_e2ee_submit))
        .route(
            "/v1/compute_e2ee/result/:job_id",
            get(get_v1_compute_e2ee_result),
        )
        .route("/worker/e2ee/next/:wallet", get(get_worker_e2ee_next))
        .route("/worker/e2ee/complete", post(post_worker_e2ee_complete))
        .route("/worker/stats/:wallet", get(get_worker_stats))
        .route("/worker/pending/:wallet", get(get_worker_pending))
        .route("/network/power", get(get_network_power))
        .route("/network/stats", get(get_network_stats))
        .route("/v1/compute", post(post_v1_compute))
        // ---------------- Phase X: P2P DEX (Isolated) ----------------
        .route("/dex/order/place", post(post_dex_order_place))
        .route("/dex/order/cancel", post(post_dex_order_cancel))
        .route("/dex/take", post(post_dex_take))
        .route("/dex/trade/complete", post(post_dex_trade_complete))
        .route("/dex/settlement/confirm", post(post_dex_settlement_confirm))
        .route("/dex/sweep/refunds", post(post_dex_sweep_refunds))
        .route("/dex/orderbook", get(get_dex_orderbook))
        .route("/ledger/recover-from-guardian", post(post_ledger_recover_from_guardian))
        .route("/v1/b2b/compute", post(post_v1_b2b_compute))
        .route("/founder/audit.csv", get(get_founder_audit_csv))
        .route("/founder/genesis", post(post_founder_genesis))
        .route("/founder/withdraw_treasury", post(post_founder_withdraw_treasury))
        .route("/system/update", get(get_system_update))
        .route("/phase4/tee/status", get(get_phase4_tee_status))
        .route(
            "/phase4/marketplace/status",
            get(get_phase4_marketplace_status),
        )
        .route(
            "/phase4/render-farm/status",
            get(get_phase4_render_farm_status),
        )
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            mw_state,
            global_http_ratelimit,
        ));
    if let Some(cors) = cors {
        app = app.layer(cors);
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            // Graceful shutdown on SIGTERM/SIGINT/CTRL-C.
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut term = signal(SignalKind::terminate()).ok();
                let mut int = signal(SignalKind::interrupt()).ok();
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = async { if let Some(s) = term.as_mut() { let _ = s.recv().await; } } => {},
                    _ = async { if let Some(s) = int.as_mut() { let _ = s.recv().await; } } => {},
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            eprintln!("[SHUTDOWN] Signal received. Flushing ledger…");
            shutdown_state.ledger.flush_and_snapshot_best_effort();
            eprintln!("[SHUTDOWN] Ledger flushed. Goodbye.");
        })
        .await
}

async fn post_enterprise_inference(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> axum::response::Response {
    // Envelope verification includes strict enterprise canonical signature binding.
    let _tx_bytes = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "INVALID_ENVELOPE",
                    "message": e,
                })),
            )
                .into_response()
        }
    };
    let TxV1::EnterpriseInference {
        enterprise_wallet_id,
        prompt,
        model,
        amount_micro,
        nonce: _nonce,
        prompt_sha256_hex,
        attestation_required,
    } = env.tx.clone()
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "WRONG_TX_KIND",
                "message": "expected tx.kind=enterprise_inference",
            })),
        )
            .into_response();
    };
    let w = enterprise_wallet_id.trim().to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "INVALID_ENTERPRISE_WALLET",
                "message": "enterprise_wallet_id must be 64 hex characters",
            })),
        )
            .into_response();
    }
    // Stateless + zero-trust: identity is entirely bound to the envelope signature.
    // Require the envelope pubkey to match the declared wallet id.
    if env.sig.ed25519_pubkey_hex.trim().to_ascii_lowercase() != w {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "ACTIVE_WALLET_MISMATCH",
                "message": "enterprise_wallet_id must match envelope pubkey",
            })),
        )
            .into_response();
    }
    let prompt_txt = prompt.trim().to_string();
    if prompt_txt.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "PROMPT_REQUIRED",
                "message": "prompt required",
            })),
        )
            .into_response();
    }
    // Enforce crypto-binding: server computes prompt hash and must match signed `prompt_sha256_hex`.
    let prompt_hash = hex::encode(sha2::Sha256::digest(prompt_txt.as_bytes()));
    if prompt_hash != prompt_sha256_hex.trim().to_ascii_lowercase() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "PROMPT_HASH_MISMATCH",
                "message": "prompt does not match prompt_sha256_hex",
            })),
        )
            .into_response();
    }

    // Enterprise engine standard: Ollama must be running locally on worker nodes.

    // Select an active worker (best TFLOPS within TTL).
    let ttl_ms = std::env::var("TET_WORKER_HEARTBEAT_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(60_000);
    let now_ms = crate::worker_network::now_ms();
    let picked_worker_wallet: Option<String> = {
        let reg = std_lock(&state.workers);
        reg.by_wallet
            .values()
            .filter(|e| now_ms.saturating_sub(e.last_seen_ms) <= ttl_ms)
            .filter(|e| {
                if !attestation_required {
                    return true;
                }
                // Attestation routing: only workers with a verified founding cert AND matching hardware id.
                match state.ledger.get_founding_cert(&e.wallet) {
                    Ok(c) => c.hardware_id_hex.trim() == e.hardware_id_hex.trim(),
                    Err(_) => false,
                }
            })
            .max_by(|a, b| {
                a.tflops_est
                    .partial_cmp(&b.tflops_est)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|e| e.wallet.clone())
    };
    let Some(worker_wallet) = picked_worker_wallet else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "NO_ACTIVE_WORKERS",
                "message": if attestation_required {
                    "0 Active Worker Nodes found (attestation required)."
                } else {
                    "0 Active Worker Nodes found."
                },
            })),
        )
            .into_response();
    };

    // Enforce worker stake eligibility.
    let worker_staked = state.ledger.staked_balance_micro(&worker_wallet).unwrap_or(0);
    if worker_staked < crate::ledger::MIN_STAKE_AMOUNT_MICRO {
        let mut reg = std_lock(&state.workers);
        reg.remove_wallet(&worker_wallet);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "WORKER_NOT_STAKED",
                "message": "No staked worker is currently eligible to process enterprise tasks.",
            })),
        )
            .into_response();
    }

    // Execute inference via Ollama (async HTTP).
    let requested_model = model.trim();
    let want_model = if requested_model.is_empty() { "llama3" } else { requested_model };
    let out = match ollama_generate(want_model, &prompt_txt).await {
        Ok(t) => t,
        Err(e) => {
            // Graceful fallback: never crash if Ollama isn't installed/running.
            let msg = e.to_string();
            let is_offline = msg.to_ascii_lowercase().contains("connection")
                || msg.to_ascii_lowercase().contains("refused")
                || msg.to_ascii_lowercase().contains("timed out")
                || msg.to_ascii_lowercase().contains("dns");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": if is_offline { "AI_ENGINE_NOT_RUNNING" } else { "AI_ENGINE_ERROR" },
                    "message": if is_offline {
                        "Worker node AI engine (Ollama) is not running."
                    } else {
                        "Worker node AI engine (Ollama) request failed."
                    },
                    "detail": msg,
                })),
            )
                .into_response();
        }
    };

    // Settle payment AFTER success using golden rule 80/15/5.
    let burn_wallet = state.ledger.ai_burn_wallet();
    let (worker_micro, treasury_micro, burn_micro) = match state
        .ledger
        .settle_ai_utility_payment(&w, &worker_wallet, amount_micro, &burn_wallet)
    {
        Ok(v) => v,
        Err(LedgerError::InsufficientFunds) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "INSUFFICIENT_FUNDS",
                    "message": "insufficient spendable balance",
                })),
            )
                .into_response();
        }
        Err(LedgerError::AttestationRequired) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "ATTESTATION_REQUIRED",
                    "message": "wallet transfers require attestation in this environment",
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "LEDGER_ERROR",
                    "message": e.to_string(),
                })),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "enterprise_wallet_id": w,
            "worker_wallet": worker_wallet,
            "spent_tet_micro": amount_micro,
            "worker_micro": worker_micro,
            "treasury_micro": treasury_micro,
            "burn_micro": burn_micro,
            "burn_wallet": burn_wallet,
            "model": want_model,
            "attestation_required": attestation_required,
            "response": out,
        })),
    )
        .into_response()
}

async fn get_index() -> impl IntoResponse {
    let csp = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; \
script-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'";
    (
        [
            ("content-security-policy", csp),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
        ],
        Html(include_str!("index.html")),
    )
}

async fn post_logout(State(state): State<RestState>) -> impl IntoResponse {
    // V1.0 safety: force a best-effort flush/snapshot on explicit logout.
    // (The client also clears local storage; this guarantees disk persistence.)
    state.ledger.flush_and_snapshot_best_effort();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true
        })),
    )
}

#[derive(Debug, Deserialize)]
struct AiPricingQuery {
    model: String,
    input: String,
}

async fn get_ai_pricing(
    Query(q): Query<AiPricingQuery>,
) -> axum::response::Response {
    (StatusCode::OK, Json(crate::ai_proxy::handle_ai_pricing(q.model.trim(), q.input.as_str())))
        .into_response()
}

async fn global_http_ratelimit(
    State(state): State<RestState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    let mut rl = state.http_ratelimit.lock().await;
    let now = std::time::Instant::now();
    if now.duration_since(rl.window_start) >= Duration::from_secs(1) {
        rl.window_start = now;
        rl.count = 0;
    }
    rl.count = rl.count.saturating_add(1);
    if rl.count > rl.max_per_sec {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    drop(rl);
    next.run(req).await
}

#[allow(clippy::result_large_err)]
fn require_api_key(headers: &HeaderMap) -> Result<(), axum::response::Response> {
    let want = std::env::var("TET_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "TET_API_KEY is not configured",
            )
                .into_response()
        })?;
    let got = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if got != want {
        return Err((StatusCode::UNAUTHORIZED, "invalid api key").into_response());
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn require_hybrid_sig(
    headers: &HeaderMap,
    wallet_id_hex: &str,
    msg: &[u8],
) -> Result<(), axum::response::Response> {
    if !crate::quantum_shield::pqc_active() {
        // In v1.0, signatures are only enforced when PQC mode is enabled.
        return Ok(());
    }
    let ed = headers
        .get("x-tet-ed25519-sig-b64")
        .and_then(|v| v.to_str().ok());
    let mldsa_pk = headers
        .get("x-tet-mldsa-pubkey-b64")
        .and_then(|v| v.to_str().ok());
    let mldsa_sig = headers
        .get("x-tet-mldsa-sig-b64")
        .and_then(|v| v.to_str().ok());
    if let Err(e) =
        crate::quantum_shield::verify_hybrid(wallet_id_hex, ed, mldsa_pk, mldsa_sig, msg)
    {
        return Err((StatusCode::UNAUTHORIZED, e.to_string()).into_response());
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn require_dex_hybrid_sig_strict(
    headers: &HeaderMap,
    ed25519_pubkey_hex: &str,
    msg: &[u8],
    who: &str,
) -> Result<(), axum::response::Response> {
    let ed_sig_k = format!("x-tet-{who}-ed25519-sig-b64");
    let mldsa_pk_k = format!("x-tet-{who}-mldsa-pubkey-b64");
    let mldsa_sig_k = format!("x-tet-{who}-mldsa-sig-b64");
    let ed_sig = headers
        .get(ed_sig_k.as_str())
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::FORBIDDEN, "missing ed25519 signature").into_response())?;
    let mldsa_pk_b64 = headers
        .get(mldsa_pk_k.as_str())
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::FORBIDDEN, "missing mldsa public key").into_response())?;
    let mldsa_sig_b64 = headers
        .get(mldsa_sig_k.as_str())
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::FORBIDDEN, "missing mldsa signature").into_response())?;

    crate::quantum_shield::verify_ed25519(ed25519_pubkey_hex, ed_sig, msg)
        .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()).into_response())?;
    crate::wallet::verify_mldsa44_b64(mldsa_pk_b64, mldsa_sig_b64, msg)
        .map_err(|e| (StatusCode::FORBIDDEN, e).into_response())?;
    Ok(())
}

fn mainnet_strict() -> bool {
    std::env::var("TET_MAINNET")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn verify_envelope_v1(env: &SignedTxEnvelopeV1) -> Result<Vec<u8>, String> {
    if env.v != 1 {
        return Err("unsupported envelope version".into());
    }
    // Canonical message bytes for hybrid signatures:
    // - Default: JSON serialization of `tx` (stable enough for internal SDKs).
    // - EnterpriseInference: strict domain-separated UTF-8 binding to job fields.
    let tx_bytes = match &env.tx {
        TxV1::EnterpriseInference {
            enterprise_wallet_id,
            model,
            amount_micro,
            nonce,
            prompt_sha256_hex,
            attestation_required,
            ..
        } => crate::wallet::enterprise_inference_hybrid_auth_message_bytes(
            enterprise_wallet_id,
            *nonce,
            *amount_micro,
            prompt_sha256_hex,
            model,
            *attestation_required,
            &env.sig.mldsa_pubkey_b64,
        ),
        _ => serde_json::to_vec(&env.tx).map_err(|_| "tx serialization failed")?,
    };

    // Mainnet requires PQC and attestation.
    if mainnet_strict() {
        if !crate::quantum_shield::pqc_active() {
            return Err("PQC must be active on mainnet".into());
        }
        // Absolute: no attestation stubs on mainnet.
        let stub = std::env::var("TET_ATTESTATION_ALLOW_STUB")
            .ok()
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if stub {
            return Err("attestation stubs are forbidden on mainnet".into());
        }
        // PQC algorithm is standardized to ML-DSA-44; the only remaining toggle is whether PQC is active.
    }

    crate::quantum_shield::verify_ed25519(
        &env.sig.ed25519_pubkey_hex,
        &env.sig.ed25519_sig_b64,
        &tx_bytes,
    )
    .map_err(|e| e.to_string())?;

    // ML-DSA-44 signature is mandatory when PQC is active (and always on mainnet).
    if crate::quantum_shield::pqc_active() || mainnet_strict() {
        crate::wallet::verify_mldsa44_b64(&env.sig.mldsa_pubkey_b64, &env.sig.mldsa_sig_b64, &tx_bytes)?;
    }

    let must_attest = mainnet_strict() || crate::attestation::attestation_required();
    if must_attest {
        if env.attestation.platform.is_empty() || env.attestation.report_b64.is_empty() {
            return Err("attestation required".into());
        }
        let report = AttestationReport {
            v: 1,
            platform: env.attestation.platform.clone(),
            report_b64: env.attestation.report_b64.clone(),
        };
        verify_attestation_report(&report, &tx_bytes).map_err(|e| e.to_string())?;
    }

    Ok(tx_bytes)
}

// ---------------- Phase X: DEX API ----------------

#[derive(Debug, Deserialize)]
pub(crate) struct DexOrderPlaceReq {
    pub(crate) maker_wallet: String,
    pub(crate) side: String, // "buy" | "sell"
    pub(crate) quote_asset: String,
    pub(crate) price_quote_per_tet: u64,
    pub(crate) tet_micro_total: u64,
    #[serde(default)]
    pub(crate) ttl_sec: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DexOrderPlaceResp {
    order_id: String,
    escrow_wallet: String,
    status: String,
}

pub(crate) async fn post_dex_order_place(
    State(state): State<RestState>,
    Json(req): Json<DexOrderPlaceReq>,
) -> axum::response::Response {
    let side = match req.side.trim().to_ascii_lowercase().as_str() {
        "buy" => DexSide::BuyTET,
        "sell" => DexSide::SellTET,
        _ => return (StatusCode::BAD_REQUEST, "side must be buy|sell").into_response(),
    };
    let ttl = Duration::from_secs(req.ttl_sec.unwrap_or(15 * 60).clamp(30, 86_400));

    let mut dex = std_lock(&state.dex);
    match dex.place_maker_order(
        &state.ledger,
        req.maker_wallet.trim(),
        side,
        req.quote_asset.trim(),
        req.price_quote_per_tet,
        req.tet_micro_total,
        ttl,
    ) {
        Ok(o) => {
            let escrow_wallet = escrow_wallet_for_order(&o.id);
            eprintln!("[DEX] Order Placed: {}", o.id);
            (
                StatusCode::OK,
                Json(DexOrderPlaceResp {
                    order_id: o.id,
                    escrow_wallet,
                    status: "placed".into(),
                }),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DexOrderCancelReq {
    pub(crate) order_id: String,
    pub(crate) maker_wallet: String,
}

#[derive(Debug, Serialize)]
struct DexOrderCancelResp {
    order_id: String,
    status: String,
}

pub(crate) async fn post_dex_order_cancel(
    State(state): State<RestState>,
    Json(req): Json<DexOrderCancelReq>,
) -> axum::response::Response {
    let mut dex = std_lock(&state.dex);
    match dex.cancel_maker_order(
        &state.ledger,
        req.order_id.trim(),
        req.maker_wallet.trim(),
    ) {
        Ok(o) => (
            StatusCode::OK,
            Json(DexOrderCancelResp {
                order_id: o.id,
                status: "cancelled".into(),
            }),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DexTakeReq {
    pub(crate) taker_wallet: String,
    pub(crate) side: String, // taker intent: "buy" | "sell"
    pub(crate) quote_asset: String,
    pub(crate) tet_micro: u64,
    #[serde(default)]
    pub(crate) max_price_quote_per_tet: Option<u64>,
    #[serde(default)]
    pub(crate) settlement_ttl_sec: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DexTakeResp {
    trade_id: String,
    order_id: String,
    status: String,
    deadline_at_ms: u128,
}

pub(crate) async fn post_dex_take(
    State(state): State<RestState>,
    Json(req): Json<DexTakeReq>,
) -> axum::response::Response {
    let side = match req.side.trim().to_ascii_lowercase().as_str() {
        "buy" => DexSide::BuyTET,
        "sell" => DexSide::SellTET,
        _ => return (StatusCode::BAD_REQUEST, "side must be buy|sell").into_response(),
    };
    let ttl = Duration::from_secs(req.settlement_ttl_sec.unwrap_or(20 * 60).clamp(30, 86_400));

    let mut dex = std_lock(&state.dex);
    match dex.take_best(
        &state.ledger,
        req.taker_wallet.trim(),
        side,
        req.quote_asset.trim(),
        req.tet_micro,
        req.max_price_quote_per_tet,
        ttl,
    ) {
        Ok(t) => {
            eprintln!("[DEX] Trade Created: {} order={}", t.id, t.order_id);
            (
                StatusCode::OK,
                Json(DexTakeResp {
                    trade_id: t.id,
                    order_id: t.order_id,
                    status: "pending_settlement".into(),
                    deadline_at_ms: t.deadline_at_ms,
                }),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DexTradeCompleteReq {
    pub(crate) trade_id: String,
    pub(crate) solana_usdc_txid: String,
    pub(crate) maker_ed25519_pubkey_hex: String,
    pub(crate) taker_ed25519_pubkey_hex: String,
}

#[derive(Debug, Serialize)]
struct DexTradeCompleteResp {
    trade_id: String,
    status: String,
}

pub(crate) async fn post_dex_trade_complete(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<DexTradeCompleteReq>,
) -> axum::response::Response {
    let trade = {
        let dex = std_lock(&state.dex);
        dex.get_trade(req.trade_id.trim())
    };
    let Some(trade) = trade else {
        return (StatusCode::NOT_FOUND, "trade not found").into_response();
    };

    // Solana settlement gate (must precede hybrid signature verification).
    if !trade.settlement_finalized {
        return (
            StatusCode::FORBIDDEN,
            "payment settlement not finalized; call POST /dex/settlement/confirm first",
        )
            .into_response();
    }
    let txid = req.solana_usdc_txid.trim();
    if txid.is_empty() {
        return (StatusCode::BAD_REQUEST, "solana_usdc_txid required").into_response();
    }
    if trade.solana_usdc_txid.as_deref() != Some(txid) {
        return (
            StatusCode::CONFLICT,
            "solana_usdc_txid does not match finalized settlement",
        )
            .into_response();
    }

    // Strict quantum gate: always require Ed25519 + Dilithium2 for BOTH parties.
    let msg = DexEngine::trade_complete_message_v1(&trade, txid);
    if let Err(r) = require_dex_hybrid_sig_strict(
        &headers,
        req.maker_ed25519_pubkey_hex.trim(),
        &msg,
        "maker",
    ) {
        return r;
    }
    if let Err(r) = require_dex_hybrid_sig_strict(
        &headers,
        req.taker_ed25519_pubkey_hex.trim(),
        &msg,
        "taker",
    ) {
        return r;
    }

    {
        let mut dex = std_lock(&state.dex);
        match dex.complete_trade_release_to_taker(&state.ledger, req.trade_id.trim()) {
            Ok(t) => {
                eprintln!("[DEX] Quantum Sig Verified for Trade: {}", t.id);
                eprintln!("[DEX] Trade Completed: {}", t.id);
                (
                    StatusCode::OK,
                    Json(DexTradeCompleteResp {
                        trade_id: t.id,
                        status: "completed".into(),
                    }),
                )
                    .into_response()
            }
            Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DexSettlementConfirmReq {
    pub(crate) trade_id: String,
    pub(crate) solana_usdc_txid: String,
}

#[derive(Debug, Serialize)]
struct DexSettlementConfirmResp {
    trade_id: String,
    status: String,
}

pub(crate) async fn post_dex_settlement_confirm(
    State(state): State<RestState>,
    Json(req): Json<DexSettlementConfirmReq>,
) -> axum::response::Response {
    let mut dex = std_lock(&state.dex);
    match dex.confirm_solana_settlement(req.trade_id.trim(), req.solana_usdc_txid.trim()) {
        Ok(t) => {
            eprintln!(
                "[DEX] Settlement Finalized: trade={} txid={}",
                t.id,
                req.solana_usdc_txid.trim()
            );
            (
                StatusCode::OK,
                Json(DexSettlementConfirmResp {
                    trade_id: t.id,
                    status: "settlement_finalized".into(),
                }),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DexSweepRefundsReq {
    #[serde(default)]
    pub(crate) now_ms: Option<u128>,
}

#[derive(Debug, Serialize)]
struct DexSweepRefundsResp {
    refunded_trade_ids: Vec<String>,
}

pub(crate) async fn post_dex_sweep_refunds(
    State(state): State<RestState>,
    Json(req): Json<DexSweepRefundsReq>,
) -> axum::response::Response {
    let now = req.now_ms.unwrap_or_else(|| crate::worker_network::now_ms());
    let mut dex = std_lock(&state.dex);
    match dex.refund_expired_trades(&state.ledger, now) {
        Ok(ids) => {
            for id in &ids {
                eprintln!("[DEX] Trade Refunded (timeout): {id}");
            }
            (StatusCode::OK, Json(DexSweepRefundsResp { refunded_trade_ids: ids })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, Serialize)]
struct DexOrderbookEntry {
    order_id: String,
    maker_wallet: String,
    side: String,
    quote_asset: String,
    price_quote_per_tet: u64,
    tet_micro_remaining: u64,
    expires_at_ms: u128,
}

pub(crate) async fn get_dex_orderbook(State(state): State<RestState>) -> axum::response::Response {
    let now = crate::worker_network::now_ms();
    let mut out = Vec::new();
    let dex = std_lock(&state.dex);
    for o in dex.list_active_orders(now) {
        out.push(DexOrderbookEntry {
            order_id: o.id.clone(),
            maker_wallet: o.maker_wallet.clone(),
            side: match o.side {
                DexSide::BuyTET => "buy".into(),
                DexSide::SellTET => "sell".into(),
            },
            quote_asset: o.quote_asset.clone(),
            price_quote_per_tet: o.price_quote_per_tet,
            tet_micro_remaining: o.tet_micro_remaining,
            expires_at_ms: o.expires_at_ms,
        });
    }
    (StatusCode::OK, Json(out)).into_response()
}

#[derive(Debug, Deserialize)]
struct GuardianRecoverReq {
    sha256_hex: String,
    snapshot_b64: String,
    ed25519_pubkey_hex: String,
    ed25519_sig_b64: String,
}

async fn post_ledger_recover_from_guardian(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(req): Json<GuardianRecoverReq>,
) -> axum::response::Response {
    match crate::replication::verify_state_snapshot_signed(
        req.sha256_hex.trim(),
        req.snapshot_b64.trim(),
        req.ed25519_pubkey_hex.trim(),
        req.ed25519_sig_b64.trim(),
    ) {
        Ok(bytes) => match state.ledger.import_snapshot_json_v1(&bytes) {
            Ok(()) => {
                eprintln!(
                    "[REPL] Ledger restored from guardian sha256={}",
                    req.sha256_hex.trim()
                );
                (StatusCode::OK, "restored").into_response()
            }
            Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::UNAUTHORIZED, e).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct B2bChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct B2bComputeReq {
    model: String,
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    messages: Option<Vec<B2bChatMessage>>,
    payment: SignedTxEnvelopeV1,
}

fn b2b_flatten_input(input: Option<&str>, messages: Option<&[B2bChatMessage]>) -> String {
    if let Some(s) = input {
        let t = s.trim();
        if !t.is_empty() {
            return s.to_string();
        }
    }
    let Some(msgs) = messages.filter(|m| !m.is_empty()) else {
        return String::new();
    };
    msgs.iter()
        .map(|m| format!("{}: {}", m.role.trim(), m.content))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn post_v1_b2b_compute(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<B2bComputeReq>,
) -> axum::response::Response {
    let org = headers
        .get("x-b2b-org-wallet")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if org.is_empty() {
        return (StatusCode::BAD_REQUEST, "x-b2b-org-wallet header required").into_response();
    }
    let min = std::env::var("TET_B2B_MIN_BALANCE_MICRO")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1_000_000);
    let bal = state.ledger.balance_micro(org).unwrap_or(0);
    if bal < min {
        return (
            StatusCode::PAYMENT_REQUIRED,
            format!("insufficient TET balance: need >= {min} stevemon micro"),
        )
            .into_response();
    }
    if let Err(e) = verify_envelope_v1(&req.payment) {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }
    let input_plain = b2b_flatten_input(req.input.as_deref(), req.messages.as_deref());
    if input_plain.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "input or messages required").into_response();
    }

    let ttl_ms = std::env::var("TET_WORKER_HEARTBEAT_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(120_000);
    let now_ms = crate::worker_network::now_ms();
    let picked: Option<(String, String)> = {
        let reg = std_lock(&state.workers);
        reg.by_wallet
            .values()
            .filter(|e| now_ms.saturating_sub(e.last_seen_ms) <= ttl_ms)
            .filter(|e| {
                e.x25519_pubkey_b64
                    .as_deref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false)
            })
            .max_by(|a, b| {
                a.tflops_est
                    .partial_cmp(&b.tflops_est)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|e| (e.wallet.clone(), e.x25519_pubkey_b64.clone().unwrap_or_default()))
    };
    let Some((worker_wallet, worker_pk_b64)) = picked else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no active workers with x25519 keys").into_response();
    };
    if worker_pk_b64.trim().is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, "no active workers with x25519 keys").into_response();
    }

    let wpk = match crate::e2ee::decode_x25519_pub_b64(worker_pk_b64.trim()) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "bad worker x25519 key").into_response(),
    };
    let (eph_sk, eph_pk) = crate::e2ee::gen_worker_static_keypair();
    let mut nonce12 = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce12);
    let task = serde_json::json!({
        "kind": "tet_b2b_infer_v1",
        "model": req.model,
        "input": input_plain,
    });
    let pt = serde_json::to_vec(&task).unwrap_or_default();
    let ct = match crate::e2ee::encrypt_for_worker(&eph_sk, &wpk, nonce12, &pt) {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed").into_response(),
    };
    let inner = ComputeE2eeSubmitReq {
        worker_wallet,
        client_ephemeral_pub_b64: crate::e2ee::encode_x25519_pub_b64(&eph_pk),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce12),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ct),
        payment: req.payment,
    };
    eprintln!("[B2B] compute queued org={org} worker={}", inner.worker_wallet);
    enqueue_compute_e2ee_job(state, inner).await
}

#[derive(Debug, Deserialize)]
struct MintDemoReq {
    amount_tet: f64,
    /// Any bytes to bind in the proof hash preimage (demo input).
    energy_note: Option<String>,
}

async fn get_ui() -> impl IntoResponse {
    // Allow localhost signer bridge for biometric signing.
    let csp = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; \
script-src 'self'; connect-src 'self' http://127.0.0.1:5791; img-src 'self' data:; style-src 'self' 'unsafe-inline'";
    (
        [
            ("content-security-policy", csp),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
        ],
        Html(include_str!("ui.html")),
    )
}

async fn get_worker_app() -> impl IntoResponse {
    // `worker_dashboard.html` is an operator console that needs inline CSS/JS and
    // may call localhost signer bridges; keep CSP permissive enough for V1.
    let csp = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; \
script-src 'self' 'unsafe-inline'; connect-src 'self' http://127.0.0.1:5791; img-src 'self' data:; style-src 'self' 'unsafe-inline'";
    (
        [
            ("content-security-policy", csp),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
        ],
        Html(include_str!("../../worker_dashboard.html")),
    )
}

async fn get_worker_app_redirect() -> impl IntoResponse {
    (
        StatusCode::MOVED_PERMANENTLY,
        [("location", "/app")],
        "",
    )
        .into_response()
}

async fn get_ui_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("ui.js"),
    )
}

async fn get_tet_sdk_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("tet_sdk.js"),
    )
}

async fn get_tet_sdk_node_mjs() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("tet_sdk_node.mjs"),
    )
}

async fn get_founder_terminal() -> impl IntoResponse {
    let csp = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; \
script-src 'self'; connect-src 'self' http://127.0.0.1:5010 http://127.0.0.1:5791; img-src 'self' data:; \
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
font-src 'self' https://fonts.gstatic.com data:;";
    (
        [
            ("content-security-policy", csp),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
        ],
        Html(include_str!("secret_founder_terminal.html")),
    )
}

async fn get_founder_terminal_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("founder_terminal.js"),
    )
}

async fn get_wallet_client_bundled_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("cache-control", "public, max-age=3600"),
        ],
        include_str!("wallet_client_bundled.js"),
    )
}

async fn get_status(State(state): State<RestState>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct R {
        founder_wallet_id: String,
        pqc_active: bool,
        attestation_required: bool,
        guardian_count: u64,
        fee_total_tet: f64,
        cost_guard_limit_usd: f64,
        cost_guard_used_usd: f64,
        /// Off-ledger USDC settlement (Solana) deposit address for DEX buyers; from `TET_DEX_SOLANA_USDC_ADDRESS`.
        #[serde(skip_serializing_if = "Option::is_none")]
        dex_usdc_settlement_solana_address: Option<String>,
    }
    let founder = state.ledger.founder_wallet_public().unwrap_or_default();
    let guardian_count = state.ledger.founding_guardian_count().unwrap_or(0);
    let fee_total = state.ledger.fee_total_micro().unwrap_or(0);
    let fee_total_tet = fee_total as f64 / STEVEMON as f64;
    let limit = std::env::var("TET_COST_GUARD_USD_LIMIT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(50.0);
    let month = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let month_index = secs / (86_400 * 30);
        format!("m{month_index}")
    };
    let used_micro = state
        .ledger
        .ai_cost_month_micro_usd_get(&month)
        .unwrap_or(0);
    let used = used_micro as f64 / 1_000_000.0;
    /// Default treasury USDC (Solana) when env unset — Genesis / DEX settlement display.
    const DEFAULT_DEX_SOLANA_USDC: &str = "6kWEkvZgs1RLthwDfaBPuu1iK5uxSRziWBwYuySWx3rN";
    let dex_usdc_settlement_solana_address = std::env::var("TET_DEX_SOLANA_USDC_ADDRESS")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| Some(DEFAULT_DEX_SOLANA_USDC.to_string()));
    (
        StatusCode::OK,
        Json(R {
            founder_wallet_id: founder.clone(),
            pqc_active: crate::quantum_shield::pqc_active(),
            attestation_required: crate::attestation::attestation_required(),
            guardian_count,
            fee_total_tet,
            cost_guard_limit_usd: limit,
            cost_guard_used_usd: used,
            dex_usdc_settlement_solana_address,
        }),
    )
        .into_response()
}

async fn post_signer_link(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> impl IntoResponse {
    if env.v != 1 {
        return (StatusCode::BAD_REQUEST, "unsupported envelope version").into_response();
    }

    // Always require an attestation proof for signer↔core linking so the UI badge is meaningful.
    if env.attestation.platform.is_empty() || env.attestation.report_b64.is_empty() {
        return (StatusCode::UNAUTHORIZED, "attestation required").into_response();
    }

    let tx_bytes = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };
    let report = AttestationReport {
        v: 1,
        platform: env.attestation.platform.clone(),
        report_b64: env.attestation.report_b64.clone(),
    };
    if let Err(e) = verify_attestation_report(&report, &tx_bytes) {
        return (StatusCode::UNAUTHORIZED, e.to_string()).into_response();
    }

    let TxV1::SignerLink { wallet_id } = env.tx else {
        return (StatusCode::BAD_REQUEST, "expected signer_link tx").into_response();
    };
    if wallet_id.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "wallet_id required").into_response();
    }
    // Stateless server: do not store per-client wallet state server-side.
    // The signature + attestation on this request is the only proof required.
    let _ = state; // keep signature stable; state may be used later for audit logging.
    (StatusCode::OK, "ok").into_response()
}

#[derive(Debug, Deserialize)]
struct WalletRecoverReq {
    mnemonic_12: String,
}

/// `GET /wallet/mnemonic/new` — **deprecated**. Mnemonics must never be minted or transmitted from the core (non-custodial).
async fn get_wallet_mnemonic_new() -> impl IntoResponse {
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "DEPRECATED",
            "message": "Server-assisted mnemonic generation is disabled. Load /assets/wallet_client_bundled.js and generate client-side.",
        })),
    )
        .into_response()
}

async fn post_wallet_new() -> impl IntoResponse {
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "DEPRECATED",
            "message": "Server-assisted wallet creation is disabled. Use client-side BIP39 + POST /wallet/active_public with wallet_id only.",
        })),
    )
        .into_response()
}

// Server is English-only; keep protocol stable.

async fn post_wallet_recover(Json(_req): Json<WalletRecoverReq>) -> impl IntoResponse {
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "DEPRECATED",
            "message": "Server-side mnemonic recovery is disabled. Use client-side BIP39 + POST /wallet/active_public with wallet_id only.",
        })),
    )
        .into_response()
}

async fn post_wallet_set_active(
    State(_state): State<RestState>,
    Json(_req): Json<WalletRecoverReq>,
) -> impl IntoResponse {
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "DEPRECATED",
            "message": "Server-side mnemonic activation is disabled. Use POST /wallet/active_public with wallet_id only.",
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct WalletTransferSignedReq {
    from_address: String,
    to_address: String,
    amount_tet: f64,
    nonce: u64,
    signature: String,
    /// ML-DSA-44 public key (raw, STANDARD base64) — must match the mnemonic-derived PQC identity.
    mldsa_pubkey_b64: String,
    /// ML-DSA-44 signature (raw, STANDARD base64) over `transfer_hybrid_auth_message_bytes`.
    mldsa_signature_b64: String,
}

#[derive(Debug, Deserialize)]
struct WalletStakeSignedReq {
    wallet_id: String,
    amount_tet: f64,
    nonce: u64,
    /// Ed25519 signature (128 hex chars) over `tet stake hybrid v1|...`
    ed25519_sig_hex: String,
    /// ML-DSA-44 public key (STANDARD base64)
    mldsa_pubkey_b64: String,
    /// ML-DSA-44 signature (STANDARD base64) over the same stake message
    mldsa_sig_b64: String,
}

#[derive(Debug, Deserialize)]
struct WalletSlashReq {
    wallet_id: String,
    amount_tet: f64,
}

fn verify_ed25519_hex_on_message(from_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), String> {
    let pk = hex::decode(from_hex.trim()).map_err(|e| e.to_string())?;
    let vk_arr: [u8; 32] = pk
        .try_into()
        .map_err(|_| "from_address must be 64 hex chars (32-byte Ed25519 public key)".to_string())?;
    let vk = VerifyingKey::from_bytes(&vk_arr).map_err(|e| format!("invalid from_address key: {e}"))?;
    let sig_bytes = hex::decode(sig_hex.trim()).map_err(|e| e.to_string())?;
    if sig_bytes.len() != 64 {
        return Err("signature must be 128 hex chars (64 bytes)".to_string());
    }
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| format!("invalid signature bytes: {e}"))?;
    vk.verify(msg, &sig)
        .map_err(|e| format!("invalid signature: {e}"))
}

fn verify_wallet_transfer_hybrid(
    from_hex: &str,
    to: &str,
    amount_micro: u64,
    nonce: u64,
    sig_hex: &str,
    mldsa_pubkey_b64: &str,
    mldsa_sig_b64: &str,
) -> Result<(), String> {
    let msg =
        crate::wallet::transfer_hybrid_auth_message_bytes(to, amount_micro, nonce, mldsa_pubkey_b64);
    verify_ed25519_hex_on_message(from_hex, &msg, sig_hex)?;
    crate::wallet::verify_mldsa44_b64(mldsa_pubkey_b64, mldsa_sig_b64, &msg)?;
    Ok(())
}

fn stake_hybrid_auth_message_bytes(
    wallet_id_hex: &str,
    amount_micro: u64,
    nonce: u64,
    mldsa_pubkey_b64: &str,
) -> Vec<u8> {
    let w = wallet_id_hex.trim().to_ascii_lowercase();
    let p = mldsa_pubkey_b64.trim();
    format!("tet stake hybrid v1|{w}|{amount_micro}|{nonce}|{p}").into_bytes()
}

async fn get_wallet_transfer_nonce(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let w = wallet.trim().to_ascii_lowercase();
    if w.is_empty() {
        return (StatusCode::BAD_REQUEST, "wallet required").into_response();
    }
    if w.len() > 128 {
        return (StatusCode::BAD_REQUEST, "wallet id too long").into_response();
    }
    match state.ledger.wallet_last_transfer_nonce(&w) {
        Ok(last) => {
            let next = last.saturating_add(1);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "wallet_id": w,
                    "last_nonce": last,
                    "next_nonce": next,
                })),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// `POST /wallet/transfer` — hybrid-signed transfer (Ed25519 + ML-DSA-44) with monotonic `nonce` (replay-safe).
/// **No `x-api-key`.** Both signatures cover `tet xfer hybrid v1|...` (see `wallet::transfer_hybrid_auth_message_bytes`).
async fn post_wallet_transfer(
    State(state): State<RestState>,
    Json(req): Json<WalletTransferSignedReq>,
) -> axum::response::Response {
    const MAX_ADDR_CHARS: usize = 256;
    const MAX_SIG_HEX_CHARS: usize = 200;
    const MAX_B64_FIELD: usize = 16_384;
    if req.from_address.len() > MAX_ADDR_CHARS
        || req.to_address.len() > MAX_ADDR_CHARS
        || req.signature.len() > MAX_SIG_HEX_CHARS
        || req.mldsa_pubkey_b64.len() > MAX_B64_FIELD
        || req.mldsa_signature_b64.len() > MAX_B64_FIELD
    {
        return (
            StatusCode::BAD_REQUEST,
            "from_address, to_address, signature, or PQC fields exceed maximum length",
        )
            .into_response();
    }
    let from = req.from_address.trim().to_ascii_lowercase();
    let to = req.to_address.trim().to_ascii_lowercase();
    if from.len() != 64 || !from.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            "from_address must be 64 hex characters (Ed25519 verifying key)",
        )
            .into_response();
    }
    if to.is_empty() {
        return (StatusCode::BAD_REQUEST, "to_address required").into_response();
    }
    if from == to {
        return (StatusCode::BAD_REQUEST, "cannot transfer to self").into_response();
    }
    if req.nonce == 0 {
        return (StatusCode::BAD_REQUEST, "nonce must be greater than last committed nonce").into_response();
    }
    if !req.amount_tet.is_finite() || req.amount_tet <= 0.0 {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    let amount_micro = (req.amount_tet * STEVEMON as f64).round().max(0.0) as u64;
    if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    if let Err(e) = verify_wallet_transfer_hybrid(
        &from,
        &to,
        amount_micro,
        req.nonce,
        &req.signature,
        &req.mldsa_pubkey_b64,
        &req.mldsa_signature_b64,
    ) {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }

    match state.ledger.transfer_with_fee_attested(
        from.as_str(),
        to.as_str(),
        amount_micro,
        Some(100),
        None,
        Some(req.nonce),
    ) {
        Ok((net_micro, fee_micro)) => {
            if let Some(tx) = state.p2p_tx.as_ref()
                && let Ok(bytes) =
                    serde_json::to_vec(&crate::network::LedgerGossip::TransferAnnounce {
                        signer_wallet_id: from.clone(),
                        from_peer_id: from.clone(),
                        to_peer_id: to.clone(),
                        amount_micro,
                        fee_micro,
                        ed25519_sig_b64: None,
                            mldsa_pubkey_b64: None,
                            mldsa_sig_b64: None,
                    })
            {
                let _ = tx.send(bytes);
            }
            #[derive(Serialize)]
            struct WalletTransferResp {
                from_wallet_id: String,
                to_wallet_id: String,
                amount_micro: u64,
                net_micro: u64,
                fee_micro: u64,
            }
            (
                StatusCode::OK,
                Json(WalletTransferResp {
                    from_wallet_id: from.clone(),
                    to_wallet_id: to,
                    amount_micro,
                    net_micro,
                    fee_micro,
                }),
            )
                .into_response()
        }
        Err(LedgerError::InsufficientFunds) => {
            (StatusCode::BAD_REQUEST, "Insufficient funds").into_response()
        }
        Err(LedgerError::AttestationRequired) => (
            StatusCode::FORBIDDEN,
            "wallet transfers require attestation in this environment",
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_wallet_stake(
    State(state): State<RestState>,
    Json(req): Json<WalletStakeSignedReq>,
) -> axum::response::Response {
    const MAX_B64_FIELD: usize = 16_384;
    if req.wallet_id.len() > 256
        || req.ed25519_sig_hex.len() > 200
        || req.mldsa_pubkey_b64.len() > MAX_B64_FIELD
        || req.mldsa_sig_b64.len() > MAX_B64_FIELD
    {
        return (StatusCode::BAD_REQUEST, "fields exceed maximum length").into_response();
    }
    let w = req.wallet_id.trim().to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
    }
    if req.nonce == 0 {
        return (StatusCode::BAD_REQUEST, "nonce must be > 0").into_response();
    }
    if !req.amount_tet.is_finite() || req.amount_tet <= 0.0 {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    let amount_micro = (req.amount_tet * STEVEMON as f64).round().max(0.0) as u64;
    if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    let msg = stake_hybrid_auth_message_bytes(&w, amount_micro, req.nonce, &req.mldsa_pubkey_b64);
    if let Err(e) = verify_ed25519_hex_on_message(&w, &msg, &req.ed25519_sig_hex) {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }
    if let Err(e) = crate::wallet::verify_mldsa44_b64(&req.mldsa_pubkey_b64, &req.mldsa_sig_b64, &msg) {
        return (StatusCode::UNAUTHORIZED, e.to_string()).into_response();
    }
    match state.ledger.stake_micro(&w, amount_micro, Some(req.nonce)) {
        Ok((staked_micro, new_stake_micro)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "wallet_id": w,
                "staked_micro": staked_micro,
                "new_stake_micro": new_stake_micro,
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_wallet_slash(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<WalletSlashReq>,
) -> axum::response::Response {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
    let w = req.wallet_id.trim().to_ascii_lowercase();
    if w.is_empty() || w.len() > 256 {
        return (StatusCode::BAD_REQUEST, "wallet_id required").into_response();
    }
    if !req.amount_tet.is_finite() || req.amount_tet <= 0.0 {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    let amount_micro = (req.amount_tet * STEVEMON as f64).round().max(0.0) as u64;
    if amount_micro == 0 {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    match state.ledger.slash_stake_micro(&w, amount_micro) {
        Ok((slashed_micro, new_stake_micro)) => {
            if new_stake_micro < crate::ledger::WORKER_MIN_STAKE_MICRO {
                let mut reg = std_lock(&state.workers);
                reg.remove_wallet(&w);
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "wallet_id": w,
                    "slashed_micro": slashed_micro,
                    "new_stake_micro": new_stake_micro,
                    "min_required_stake_micro": crate::ledger::WORKER_MIN_STAKE_MICRO,
                })),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn get_local_telemetry() -> impl IntoResponse {
    #[derive(Serialize)]
    struct T {
        cpu_usage_pct: f32,
        mem_used_bytes: u64,
        mem_total_bytes: u64,
    }
    let mut sys = System::new_all();
    sys.refresh_all();
    let cpu = sys.global_cpu_usage();
    let mem_total = sys.total_memory().saturating_mul(1024);
    let mem_used = sys.used_memory().saturating_mul(1024);
    (
        StatusCode::OK,
        Json(T {
            cpu_usage_pct: cpu,
            mem_used_bytes: mem_used,
            mem_total_bytes: mem_total,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct LedgerMeQuery {
    wallet_id: String,
}

async fn get_ledger_me(
    State(state): State<RestState>,
    axum::extract::Query(q): axum::extract::Query<LedgerMeQuery>,
) -> impl IntoResponse {
    #[derive(Serialize)]
    struct R {
        wallet_id: String,
        balance_tet: f64,
        locked_balance_tet: f64,
        staked_balance_tet: f64,
        fee_total_tet: f64,
        total_supply_tet: f64,
        total_burned_tet: f64,
        is_founder: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        founder_genesis_balance_tet: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        founder_genesis_locked_tet: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        founder_genesis_unlocked_tet: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        founder_genesis_unlocks_at_ms: Option<u128>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dex_treasury_earnings_tet: Option<f64>,
    }
    let wallet = q.wallet_id.trim().to_ascii_lowercase();
    if wallet.len() != 64 || !wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
    }
    let bal = state.ledger.balance_micro(&wallet).unwrap_or(0);
    let locked = state
        .ledger
        .locked_balance_micro_now(&wallet)
        .unwrap_or(0);
    let staked = state.ledger.staked_balance_micro(&wallet).unwrap_or(0);
    let fee = state.ledger.fee_total_micro().unwrap_or(0);
    let sup = state.ledger.total_supply_micro().unwrap_or(0);
    let burned = state.ledger.total_burned_micro().unwrap_or(0);
    let founder = state.ledger.founder_wallet_public().unwrap_or_default();
    let is_founder = !founder.is_empty() && founder == wallet;

    let (fg_bal, fg_locked, fg_unlocked, fg_unlocks_at, dex_earn) = if is_founder {
        let unlock_at = state.ledger.founder_genesis_unlock_at_ms().ok();
        let locked_micro = state.ledger.founder_genesis_locked_micro().unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let locked_now = match unlock_at {
            Some(t) if t > now => locked_micro,
            _ => 0,
        };
        let unlocked_now = crate::ledger::GENESIS_FOUNDER_SHARE_MICRO.saturating_sub(locked_now);
        let dex_bal = state
            .ledger
            .balance_micro(crate::ledger::WALLET_DEX_TREASURY)
            .unwrap_or(0);
        (
            Some(crate::ledger::GENESIS_FOUNDER_SHARE_MICRO as f64 / STEVEMON as f64),
            Some(locked_now as f64 / STEVEMON as f64),
            Some(unlocked_now as f64 / STEVEMON as f64),
            unlock_at,
            Some(dex_bal as f64 / STEVEMON as f64),
        )
    } else {
        (None, None, None, None, None)
    };
    (
        StatusCode::OK,
        Json(R {
            wallet_id: wallet,
            balance_tet: bal as f64 / STEVEMON as f64,
            locked_balance_tet: locked as f64 / STEVEMON as f64,
            staked_balance_tet: staked as f64 / STEVEMON as f64,
            fee_total_tet: fee as f64 / STEVEMON as f64,
            total_supply_tet: sup as f64 / STEVEMON as f64,
            total_burned_tet: burned as f64 / STEVEMON as f64,
            is_founder,
            founder_genesis_balance_tet: fg_bal,
            founder_genesis_locked_tet: fg_locked,
            founder_genesis_unlocked_tet: fg_unlocked,
            founder_genesis_unlocks_at_ms: fg_unlocks_at,
            dex_treasury_earnings_tet: dex_earn,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct WalletIdQuery {
    wallet_id: String,
}

async fn get_genesis_1k_status(
    State(state): State<RestState>,
    axum::extract::Query(q): axum::extract::Query<WalletIdQuery>,
) -> impl IntoResponse {
    let w = q.wallet_id.trim().to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
    }
    match state.ledger.genesis_1k_status(&w) {
        Ok(s) => (StatusCode::OK, Json(s)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_genesis_1k_claim(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let _guard = state.genesis_1k_lock.lock().await;
    let w = headers
        .get("x-tet-wallet-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "missing/invalid x-tet-wallet-id").into_response();
    }
    let sig_b64 = headers
        .get("x-tet-ed25519-sig-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let mldsa_pk_b64 = headers
        .get("x-tet-mldsa-pubkey-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let mldsa_sig_b64 = headers
        .get("x-tet-mldsa-sig-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if sig_b64.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            "missing x-tet-ed25519-sig-b64 (hybrid genesis1k claim)",
        )
            .into_response();
    }
    if mldsa_pk_b64.is_empty() || mldsa_sig_b64.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            "missing x-tet-mldsa-pubkey-b64 or x-tet-mldsa-sig-b64 (hybrid genesis1k claim)",
        )
            .into_response();
    }
    let msg = crate::wallet::genesis_1k_claim_hybrid_auth_message_bytes(&w, mldsa_pk_b64);
    if let Err(e) = crate::quantum_shield::verify_ed25519(&w, sig_b64, &msg) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid genesis 1k claim ed25519 signature: {e}"),
        )
            .into_response();
    }
    if let Err(e) = crate::wallet::verify_mldsa44_b64(mldsa_pk_b64, mldsa_sig_b64, &msg) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid genesis 1k claim ml-dsa signature: {e}"),
        )
            .into_response();
    }
    match state.ledger.genesis_1k_claim(&w) {
        Ok(slot) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "slot": slot,
                "bonus_tet": crate::ledger::GENESIS_1K_BONUS_TET,
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct AiUtilityReq {
    prompt: String,
}

async fn post_ai_utility(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<AiUtilityReq>,
) -> impl IntoResponse {
    if req.prompt.len() > 24_576 {
        return (
            StatusCode::BAD_REQUEST,
            "prompt exceeds maximum length (24KiB)",
        )
            .into_response();
    }
    // --- V8 wiring: real heavy inference path (Candle / GGUF) ---
    // We only charge/burn AFTER a successful inference. If inference fails, no payment is taken.
    let prompt = req.prompt.trim().to_string();
    if prompt.is_empty() {
        return (StatusCode::BAD_REQUEST, "prompt required").into_response();
    }

    // Ensure heavy model is ready (UI gating should enforce this too).
    let ms = crate::worker_ai::model_status_v1().await;
    if !ms.ready {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "AI_BRAIN_NOT_READY",
                "message": "AI Brain not ready. Download the model first in Worker Dashboard.",
                "status": ms,
            })),
        )
            .into_response();
    }

    let w = headers
        .get("x-tet-wallet-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "missing/invalid x-tet-wallet-id").into_response();
    }

    // Require at least one active worker heartbeat so the economics match the UI story.
    let ttl_ms = std::env::var("TET_WORKER_HEARTBEAT_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(60_000);
    let now_ms = crate::worker_network::now_ms();
    let picked_worker_wallet: Option<String> = {
        let reg = std_lock(&state.workers);
        reg.by_wallet
            .values()
            .filter(|e| now_ms.saturating_sub(e.last_seen_ms) <= ttl_ms)
            .max_by(|a, b| {
                a.tflops_est
                    .partial_cmp(&b.tflops_est)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|e| e.wallet.clone())
    };
    let Some(worker_wallet) = picked_worker_wallet else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "NO_ACTIVE_WORKERS",
                "message": "0 Active Worker Nodes found.",
            })),
        )
            .into_response();
    };

    // Enforce minimum stake at time of task routing (worker could be slashed after registering).
    let worker_staked = state.ledger.staked_balance_micro(&worker_wallet).unwrap_or(0);
    if worker_staked < crate::ledger::MIN_STAKE_AMOUNT_MICRO {
        let mut reg = std_lock(&state.workers);
        reg.remove_wallet(&worker_wallet);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "WORKER_NOT_STAKED",
                "message": "No staked worker is currently eligible to process AI tasks.",
            })),
        )
            .into_response();
    }

    // Run heavy local inference on a blocking thread.
    let infer = tokio::task::spawn_blocking(move || crate::worker_ai::run_local_inference(&prompt))
        .await;
    let out = match infer {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            // Economic enforcement: worker failure -> slash 5% of stake and revoke active status.
            let st = state.ledger.staked_balance_micro(&worker_wallet).unwrap_or(0);
            if st > 0 {
                let slash_micro = (st as u128 * crate::ledger::SLASHING_PENALTY_BPS as u128 / 10_000u128)
                    as u64;
                let _ = state.ledger.slash_stake_micro(&worker_wallet, slash_micro.max(1));
            }
            let mut reg = std_lock(&state.workers);
            reg.remove_wallet(&worker_wallet);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "INFERENCE_FAILED",
                    "message": e.to_string(),
                })),
            )
                .into_response();
        }
        Err(e) => {
            let st = state.ledger.staked_balance_micro(&worker_wallet).unwrap_or(0);
            if st > 0 {
                let slash_micro = (st as u128 * crate::ledger::SLASHING_PENALTY_BPS as u128 / 10_000u128)
                    as u64;
                let _ = state.ledger.slash_stake_micro(&worker_wallet, slash_micro.max(1));
            }
            let mut reg = std_lock(&state.workers);
            reg.remove_wallet(&worker_wallet);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "INFERENCE_JOIN_FAILED",
                    "message": e.to_string(),
                })),
            )
                .into_response();
        }
    };

    // Settle user payment AFTER success (explicit DePIN split; no hidden protocol fees).
    let burn_wallet = state.ledger.ai_burn_wallet();
    let gross = STEVEMON; // 1 TET
    let (worker_micro, treasury_micro, burn_micro) = match state
        .ledger
        .settle_ai_utility_payment(&w, &worker_wallet, gross, &burn_wallet)
    {
        Ok(v) => v,
        Err(LedgerError::InsufficientFunds) => {
            return (StatusCode::BAD_REQUEST, "insufficient spendable balance (need 1 TET)")
                .into_response();
        }
        Err(LedgerError::AttestationRequired) => {
            return (
                StatusCode::FORBIDDEN,
                "wallet transfers require attestation in this environment",
            )
                .into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let payload = serde_json::json!({
        "v": 1,
        "kind": "utility_heavy_infer_v1",
        "worker_wallet": worker_wallet,
        "burn_wallet": burn_wallet,
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let _ = payload_bytes; // retained for future proof binding

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "spent_tet_micro": gross,
            "worker_micro": worker_micro,
            "network_fee_micro": treasury_micro.saturating_add(burn_micro),
            "treasury_micro": treasury_micro,
            "burn_micro": burn_micro,
            "burn_wallet": burn_wallet,
            "reward_worker_wallet": worker_wallet,
            "note": "Heavy AI: inference succeeded; payment settled after success (80% worker / 15% treasury / 5% burn).",
            "response": out,
        })),
    )
        .into_response()
}

async fn get_ledger_balance(
    State(state): State<RestState>,
    headers: HeaderMap,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
    #[derive(Serialize)]
    struct R {
        wallet_id: String,
        balance_tet: f64,
        locked_balance_tet: f64,
    }
    let w = wallet.trim();
    let bal = state.ledger.balance_micro(w).unwrap_or(0);
    let locked = state.ledger.locked_balance_micro_now(w).unwrap_or(0);
    (
        StatusCode::OK,
        Json(R {
            wallet_id: wallet,
            balance_tet: bal as f64 / STEVEMON as f64,
            locked_balance_tet: locked as f64 / STEVEMON as f64,
        }),
    )
        .into_response()
}

async fn post_transfer_enveloped(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> impl IntoResponse {
    let _tx_bytes = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };
    let TxV1::Transfer {
        from_wallet,
        to_wallet,
        amount_micro,
        fee_bps,
    } = env.tx.clone()
    else {
        return (StatusCode::BAD_REQUEST, "expected transfer tx").into_response();
    };
    if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "amount exceeds hard cap").into_response();
    }
    let att = AttestationReport {
        v: 1,
        platform: env.attestation.platform.clone(),
        report_b64: env.attestation.report_b64.clone(),
    };
    match state.ledger.transfer_with_fee_attested(
        &from_wallet,
        &to_wallet,
        amount_micro,
        Some(fee_bps),
        Some(&att),
        None,
    ) {
        Ok((net, fee)) => {
            #[derive(Serialize)]
            struct R {
                net_micro: u64,
                fee_micro: u64,
            }
            if let Some(tx) = state.p2p_tx.as_ref()
                && let Ok(bytes) =
                    serde_json::to_vec(&crate::network::LedgerGossip::TransferAnnounce {
                        signer_wallet_id: from_wallet.clone(),
                        from_peer_id: from_wallet.clone(),
                        to_peer_id: to_wallet.clone(),
                        amount_micro,
                        fee_micro: fee,
                        ed25519_sig_b64: Some(env.sig.ed25519_sig_b64.clone()),
                        mldsa_pubkey_b64: Some(env.sig.mldsa_pubkey_b64.clone()),
                        mldsa_sig_b64: Some(env.sig.mldsa_sig_b64.clone()),
                    })
            {
                let _ = tx.send(bytes);
            }
            (
                StatusCode::OK,
                Json(R {
                    net_micro: net,
                    fee_micro: fee,
                }),
            )
                .into_response()
        }
        Err(LedgerError::InsufficientFunds) => {
            (StatusCode::BAD_REQUEST, "insufficient funds").into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_mint_demo(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<MintDemoReq>,
) -> impl IntoResponse {
    if !req.amount_tet.is_finite() || req.amount_tet <= 0.0 {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    if req.amount_tet > 10_000_000_000.0 {
        return (StatusCode::BAD_REQUEST, "amount exceeds hard cap").into_response();
    }
    let gross_micro = (req.amount_tet * STEVEMON as f64).round().max(0.0) as u64;
    if gross_micro == 0 || gross_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "amount exceeds hard cap").into_response();
    }
    let note = req.energy_note.unwrap_or_default();
    let payload = format!("energy_note:{note}").into_bytes();
    let wallet = headers
        .get("x-tet-wallet-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if wallet.len() != 64 || !wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "missing/invalid x-tet-wallet-id").into_response();
    }
    let msg = format!(
        "tet-tx-v1|mint_demo|to={}|gross_micro={}|payload_sha256={}",
        wallet,
        gross_micro,
        hex::encode(sha2::Sha256::digest(&payload))
    );
    if let Err(r) = require_hybrid_sig(&headers, &wallet, msg.as_bytes()) {
        return r;
    }
    let ed_sig = headers
        .get("x-tet-ed25519-sig-b64")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mldsa_pk = headers
        .get("x-tet-mldsa-pubkey-b64")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mldsa_sig = headers
        .get("x-tet-mldsa-sig-b64")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    match state
        .ledger
        .mint_reward_with_proof(&wallet, gross_micro, &payload, None, false)
    {
        Ok((_gross, _net, _fee, proof_id)) => {
            if let Ok(p) = state.ledger.get_proof(proof_id) {
                if let Some(tx) = state.p2p_tx.as_ref()
                    && let Ok(bytes) =
                        serde_json::to_vec(&crate::network::LedgerGossip::ProofAnnounce {
                            signer_wallet_id: wallet.clone(),
                            id: p.id,
                            hash_sha256_hex: p.hash_sha256_hex.clone(),
                            ed25519_sig_b64: ed_sig.clone(),
                            mldsa_pubkey_b64: mldsa_pk.clone(),
                            mldsa_sig_b64: mldsa_sig.clone(),
                        })
                {
                    let _ = tx.send(bytes);
                }
                (StatusCode::OK, Json(p)).into_response()
            } else {
                (StatusCode::OK, "ok").into_response()
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_genesis_bridge_enveloped(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> impl IntoResponse {
    let _tx_bytes = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };
    let founder = state.ledger.founder_wallet_public().unwrap_or_default();
    let TxV1::GenesisBridge {
        founder_wallet,
        to_wallet,
        amount_micro,
    } = env.tx.clone()
    else {
        return (StatusCode::BAD_REQUEST, "expected genesis_bridge tx").into_response();
    };
    if founder_wallet != founder {
        return (StatusCode::UNAUTHORIZED, "founder wallet required").into_response();
    }
    if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "amount exceeds hard cap").into_response();
    }
    let att = AttestationReport {
        v: 1,
        platform: env.attestation.platform.clone(),
        report_b64: env.attestation.report_b64.clone(),
    };
    match state.ledger.transfer_with_fee_attested(
        &founder_wallet,
        &to_wallet,
        amount_micro,
        Some(50),
        Some(&att),
        None,
    ) {
        Ok((net, fee)) => (
            StatusCode::OK,
            Json(serde_json::json!({"net_micro": net, "fee_micro": fee})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_tx_submit(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> axum::response::Response {
    let _ = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };
    match env.tx {
        TxV1::SignerLink { .. } => (StatusCode::BAD_REQUEST, "use /signer/link").into_response(),
        TxV1::FoundingMemberEnroll { .. } => {
            (StatusCode::BAD_REQUEST, "use /founding/enroll").into_response()
        }
        TxV1::Transfer { .. } => post_transfer_enveloped(State(state), headers, Json(env))
            .await
            .into_response(),
        TxV1::GenesisBridge { .. } => {
            post_genesis_bridge_enveloped(State(state), headers, Json(env))
                .await
                .into_response()
        }
        TxV1::EnterpriseInference { .. } => (
            StatusCode::BAD_REQUEST,
            "use /enterprise/inference (envelope required)",
        )
            .into_response(),
    }
}

async fn post_ai_proxy(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(req): Json<AiProxyReq>,
) -> axum::response::Response {
    // Payment envelope must be valid and hardware-attested when required.
    if let Err(e) = verify_envelope_v1(&req.payment) {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }
    crate::ai_proxy::handle_ai_proxy(state.ledger.clone(), state.workers.clone(), req)
        .into_response()
}

#[derive(Debug, Deserialize)]
struct WorkerRegisterReq {
    wallet: String,
    hardware_id_hex: String,
    ed25519_pubkey_hex: String,
    #[serde(default)]
    x25519_pubkey_b64: Option<String>,
    tflops_est: Option<f64>,
}

async fn post_worker_register(
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
    if let Ok(founder) = state.ledger.founder_wallet_public() {
        if !founder.trim().is_empty() && founder.trim().to_ascii_lowercase() == w_lower {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "FOUNDER_WORKER_FORBIDDEN",
                    "message": "founder wallet cannot register as a worker"
                })),
            )
                .into_response();
        }
    }
    // If the wallet has a founding cert (verified hardware attestation), enforce hardware_id match.
    if let Ok(cert) = state.ledger.get_founding_cert(&w_lower) {
        if cert.hardware_id_hex.trim() != req.hardware_id_hex.trim() {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "ATTESTATION_HARDWARE_MISMATCH",
                    "message": "hardware_id_hex does not match founding certificate",
                })),
            )
                .into_response();
        }
    }
    // Genesis Guardians auto-grant: first N workers get a fixed grant from `system:worker_pool`.
    // This runs on first connect/heartbeat attempt so the economy is fully automated.
    let stake = state.ledger.staked_balance_micro(&w_lower).unwrap_or(0);
    if stake < crate::ledger::WORKER_MIN_STAKE_MICRO {
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
                    "grant_tet": (crate::ledger::GENESIS_GUARDIAN_GRANT_MICRO as f64) / (STEVEMON as f64),
                    "min_stake_tet": (crate::ledger::WORKER_MIN_STAKE_MICRO as f64) / (STEVEMON as f64),
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
                "min_stake_tet": (crate::ledger::WORKER_MIN_STAKE_MICRO as f64) / (STEVEMON as f64),
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
        req.tflops_est.unwrap_or(1.0),
    ) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "WORKER_REGISTER_REJECTED", "message": e})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct FounderWithdrawTreasuryReq {
    founder_wallet_id: String,
    amount_tet: f64,
    nonce: u64,
    mldsa_pubkey_b64: String,
    mldsa_signature_b64: String,
}

async fn post_founder_withdraw_treasury(
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
    let amount_micro = ((req.amount_tet * STEVEMON as f64).round() as i128).max(0) as u64;
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
        crate::wallet::verify_mldsa44_b64(&req.mldsa_pubkey_b64, &req.mldsa_signature_b64, &msg)
    {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid founder ml-dsa signature: {e}"),
        )
            .into_response();
    }
    match state.ledger.withdraw_treasury_to_founder(amount_micro, req.nonce) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "amount_micro": amount_micro})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e:?}")).into_response(),
    }
}

async fn get_worker_model_status() -> impl IntoResponse {
    (StatusCode::OK, Json(crate::worker_ai::model_status_v1().await)).into_response()
}

async fn post_worker_model_download() -> impl IntoResponse {
    // Fire-and-forget background download (single-flight is enforced inside worker_ai).
    tokio::spawn(async move {
        let _ = crate::worker_ai::start_model_download().await;
    });
    (StatusCode::ACCEPTED, Json(serde_json::json!({"ok": true}))).into_response()
}

#[derive(Debug, Deserialize)]
struct ComputeE2eeSubmitReq {
    worker_wallet: String,
    client_ephemeral_pub_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
    payment: SignedTxEnvelopeV1,
}

#[derive(Debug, Serialize)]
struct ComputeE2eeSubmitResp {
    job_id: String,
    status: String,
}

async fn enqueue_compute_e2ee_job(state: RestState, req: ComputeE2eeSubmitReq) -> axum::response::Response {
    let worker_wallet = req.worker_wallet.trim().to_string();
    if worker_wallet.is_empty() {
        return (StatusCode::BAD_REQUEST, "worker_wallet required").into_response();
    }

    // Ensure worker exists and has an X25519 pubkey registered (for clients to trust).
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
        client_ephemeral_pub_b64: req.client_ephemeral_pub_b64,
        nonce_b64: req.nonce_b64,
        ciphertext_b64: req.ciphertext_b64,
        created_at_ms: crate::worker_network::now_ms(),
        completed: false,
        result_nonce_b64: None,
        result_ciphertext_b64: None,
    };

    let mut q = std_lock(&state.e2ee_jobs);
    q.jobs.insert(job_id.clone(), job);
    q.pending_by_worker
        .entry(worker_wallet)
        .or_default()
        .push_back(job_id.clone());

    (
        StatusCode::OK,
        Json(ComputeE2eeSubmitResp {
            job_id,
            status: "queued".into(),
        }),
    )
        .into_response()
}

async fn post_v1_compute_e2ee_submit(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(req): Json<ComputeE2eeSubmitReq>,
) -> axum::response::Response {
    if let Err(e) = verify_envelope_v1(&req.payment) {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }
    enqueue_compute_e2ee_job(state, req).await
}

#[derive(Debug, Serialize)]
struct ComputeE2eeResultResp {
    job_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_nonce_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_ciphertext_b64: Option<String>,
}

async fn get_v1_compute_e2ee_result(
    State(state): State<RestState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> axum::response::Response {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
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

#[derive(Debug, Serialize)]
struct WorkerE2eeNextResp {
    job_id: String,
    client_ephemeral_pub_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

async fn get_worker_e2ee_next(
    State(state): State<RestState>,
    headers: HeaderMap,
    Path(wallet): Path<String>,
) -> axum::response::Response {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
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
        if let Some(j) = j_opt {
            if !j.completed {
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
}

#[derive(Debug, Deserialize)]
struct WorkerE2eeCompleteReq {
    wallet: String,
    job_id: String,
    result_nonce_b64: String,
    result_ciphertext_b64: String,
}

async fn post_worker_e2ee_complete(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<WorkerE2eeCompleteReq>,
) -> axum::response::Response {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
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
    (StatusCode::OK, "ok").into_response()
}

fn worker_heartbeat_ttl_ms() -> u128 {
    std::env::var("TET_WORKER_HEARTBEAT_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(60_000)
}

fn tet_presale_usd_floor() -> f64 {
    std::env::var("TET_PRESALE_USD_PER_TET")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|x| x.is_finite() && *x > 0.0)
        .unwrap_or(0.05)
}

/// Ledger-backed TET/USDC index: **presale only** when no workers are online (flat charts for demos);
/// with active workers, scales deterministically from burn + headcount + community mint (vest proxy) — no RNG.
fn tet_algorithmic_index_usd(
    presale: f64,
    total_burned_micro: u64,
    active_workers: u64,
    community_mint_micro: u64,
) -> f64 {
    let active = active_workers as f64;
    if active <= 0.0 {
        return presale;
    }
    let supply_cap_tet = MAX_SUPPLY_MICRO as f64 / STEVEMON as f64;
    let burn_tet = total_burned_micro as f64 / STEVEMON as f64;
    let burn_ratio = if supply_cap_tet > 0.0 {
        burn_tet / supply_cap_tet
    } else {
        0.0
    };
    let burn_term = (burn_ratio * 800.0).tanh() * 0.07;
    let demand_term = (active / 100.0).tanh() * 0.12;
    let comm_tet = community_mint_micro as f64 / STEVEMON as f64;
    let stake_proxy = (comm_tet / 2_000_000_000.0).tanh() * 0.05;
    let mult = 1.0 + burn_term + demand_term + stake_proxy;
    (presale * mult).clamp(presale, presale * 1.40)
}

fn build_network_stats(state: &RestState) -> NetworkStats {
    let ttl = worker_heartbeat_ttl_ms();
    let reg = std_lock(&state.workers);
    let total_compute_tflops = reg.total_tflops(ttl);
    let active_worker_nodes = reg.active_count(ttl) as u64;
    drop(reg);

    let total_burned_micro = state.ledger.total_burned_micro().unwrap_or(0);
    let total_supply_micro = state.ledger.total_supply_micro().unwrap_or(0);
    let community_stevemon_earned_micro = state
        .ledger
        .worker_community_mint_micro_total()
        .unwrap_or(0);
    let genesis_1k_claimed = state.ledger.genesis_1k_filled_count_public().unwrap_or(0);

    // Genesis Guardians counter (derived from worker pool depletion).
    let pool_cur = state
        .ledger
        .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
        .unwrap_or(0);
    let pool_init = crate::ledger::GENESIS_WORKER_POOL_SHARE_MICRO;
    let grant = crate::ledger::GENESIS_GUARDIAN_GRANT_MICRO.max(1);
    let spent = pool_init.saturating_sub(pool_cur);
    let mut filled = spent / grant;
    if filled > crate::ledger::GENESIS_GUARDIANS_TOTAL {
        filled = crate::ledger::GENESIS_GUARDIANS_TOTAL;
    }

    let tet_presale_usd = tet_presale_usd_floor();
    let tet_price_usd = tet_algorithmic_index_usd(
        tet_presale_usd,
        total_burned_micro,
        active_worker_nodes,
        community_stevemon_earned_micro,
    );

    NetworkStats {
        total_compute_tflops,
        active_worker_nodes,
        community_stevemon_earned_micro,
        total_burned_micro,
        genesis_1k_claimed,
        genesis_guardians_filled: filled,
        genesis_guardians_total: crate::ledger::GENESIS_GUARDIANS_TOTAL,
        tet_price_usd,
        tet_presale_usd,
        total_supply_micro,
    }
}

async fn get_network_stats(State(state): State<RestState>) -> impl IntoResponse {
    (StatusCode::OK, Json(build_network_stats(&state))).into_response()
}

async fn get_network_power(State(state): State<RestState>) -> impl IntoResponse {
    let s = build_network_stats(&state);
    let snap = NetworkPowerSnapshot {
        total_compute_tflops: s.total_compute_tflops,
        active_worker_nodes: s.active_worker_nodes,
        community_stevemon_earned_micro: s.community_stevemon_earned_micro,
        total_burned_micro: s.total_burned_micro,
        tet_price_usd: s.tet_price_usd,
        total_supply_micro: s.total_supply_micro,
    };
    (StatusCode::OK, Json(snap)).into_response()
}

async fn get_worker_stats(
    State(state): State<RestState>,
    headers: HeaderMap,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
    #[derive(Serialize)]
    struct R {
        wallet: String,
        online: bool,
        tflops_est: f64,
        last_seen_ms: u128,
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
        (
            StatusCode::OK,
            Json(R {
                wallet: e.wallet,
                online,
                tflops_est: e.tflops_est,
                last_seen_ms: e.last_seen_ms,
            }),
        )
            .into_response()
    } else {
        (StatusCode::NOT_FOUND, "worker not found").into_response()
    }
}

async fn get_worker_pending(headers: HeaderMap, Path(_wallet): Path<String>) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
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

async fn get_system_update(
    headers: HeaderMap,
    State(state): State<RestState>,
) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
    #[derive(Serialize)]
    struct R {
        version_hash: String,
        sig_b64: String,
        signer_pubkey_hex: String,
        note: String,
    }
    let founder = state.ledger.founder_wallet_public().unwrap_or_default();
    let version_hash = std::env::var("TET_UPDATE_VERSION_HASH").unwrap_or_default();
    let sig_b64 = std::env::var("TET_UPDATE_SIG_B64").unwrap_or_default();
    if founder.is_empty() || version_hash.is_empty() || sig_b64.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, "update not configured").into_response();
    }
    let msg = format!("tet-update-v1|{version_hash}");
    if let Err(e) = crate::quantum_shield::verify_ed25519(&founder, &sig_b64, msg.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("bad update signature: {e}"),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(R {
            version_hash,
            sig_b64,
            signer_pubkey_hex: founder,
            note: "Workers should self-update when version_hash changes.".into(),
        }),
    )
        .into_response()
}

async fn get_phase4_tee_status(headers: HeaderMap) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
    (StatusCode::NOT_IMPLEMENTED, "Phase 4: TEE compute stub").into_response()
}

async fn get_phase4_marketplace_status(headers: HeaderMap) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        "Phase 4: marketplace escrow stub",
    )
        .into_response()
}

async fn get_phase4_render_farm_status(headers: HeaderMap) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
    (StatusCode::NOT_IMPLEMENTED, "Phase 4: render farm stub").into_response()
}

async fn post_founding_enroll(
    State(state): State<RestState>,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> axum::response::Response {
    let tx_bytes = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };
    let TxV1::FoundingMemberEnroll { member_wallet } = env.tx.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            "expected founding member enroll tx",
        )
            .into_response();
    };
    // Enforce: the member wallet is the Ed25519 identity of the signer.
    if member_wallet != env.sig.ed25519_pubkey_hex {
        return (
            StatusCode::UNAUTHORIZED,
            "member_wallet must match signer ed25519 pubkey",
        )
            .into_response();
    }
    // Must be hardware-attested (always) to mint a certificate.
    if env.attestation.platform.is_empty() || env.attestation.report_b64.is_empty() {
        return (StatusCode::UNAUTHORIZED, "attestation required").into_response();
    }
    let report = AttestationReport {
        v: 1,
        platform: env.attestation.platform.clone(),
        report_b64: env.attestation.report_b64.clone(),
    };
    let hw = match hardware_id_hex(&report, &tx_bytes) {
        Ok(v) => v,
        Err(e) => return (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
    };
    let cert = FoundingMemberCert {
        v: 1,
        member_wallet: member_wallet.clone(),
        platform: report.platform.clone(),
        hardware_id_hex: hw,
        issued_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    };
    if let Err(e) = state.ledger.put_founding_cert(&cert) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    (StatusCode::OK, Json(cert)).into_response()
}

async fn get_founding_cert(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> axum::response::Response {
    match state.ledger.get_founding_cert(wallet.trim()) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct ProofsQuery {
    limit: Option<usize>,
    before_id: Option<u64>,
}

async fn get_proofs(
    State(state): State<RestState>,
    headers: HeaderMap,
    Query(q): Query<ProofsQuery>,
) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
    let v = state
        .ledger
        .list_proofs(q.limit.unwrap_or(50), q.before_id)
        .unwrap_or_default();
    (StatusCode::OK, Json(v)).into_response()
}

async fn get_proof_by_id(
    State(state): State<RestState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
    match state.ledger.get_proof(id) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

// ---------------- Phase 3: Master Orchestrator ----------------

#[derive(Debug, Deserialize)]
struct ComputeReq {
    plugin: String, // "ai_inference" | "video_render" | "scientific_compute"
    model: Option<String>,
    input: Option<String>,
    // Video plugin:
    frames_total: Option<u64>,
    // Scientific plugin:
    grid_w: Option<u64>,
    grid_h: Option<u64>,
    // Sharding:
    shard_chars: Option<usize>,
    shard_frames: Option<u64>,
    tile_w: Option<u64>,
    tile_h: Option<u64>,
    // Verification:
    redundancy: Option<u32>, // require N matching outputs per shard (stubbed)
    geo: Option<String>,
    // Payment:
    payment: SignedTxEnvelopeV1,
}

async fn post_v1_compute(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(req): Json<ComputeReq>,
) -> axum::response::Response {
    // Verify payment envelope.
    if let Err(e) = verify_envelope_v1(&req.payment) {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }

    let plugin = req.plugin.trim().to_ascii_lowercase();
    let redundancy = req.redundancy.unwrap_or(1).clamp(1, 5);
    let geo = req.geo.unwrap_or_else(|| "CH".into());
    let model = req.model.unwrap_or_else(|| "tet/poc".into());

    // Orchestration: build shards via plugin, then run local deterministic PoC per shard.
    let (plugin_name, shards): (String, Vec<ShardSpec>) = match plugin.as_str() {
        "ai_inference" => {
            let input = req.input.unwrap_or_default();
            let shard_chars = req.shard_chars.unwrap_or(1200);
            (
                "ai_inference".into(),
                shard_ai_inference(&model, &input, shard_chars),
            )
        }
        "video_render" => {
            let frames = req.frames_total.unwrap_or(0);
            let shard_frames = req.shard_frames.unwrap_or(60).max(1);
            (
                "video_render".into(),
                shard_video_rendering(&model, frames, shard_frames),
            )
        }
        "scientific_compute" => {
            let w = req.grid_w.unwrap_or(0);
            let h = req.grid_h.unwrap_or(0);
            let tw = req.tile_w.unwrap_or(64).max(1);
            let th = req.tile_h.unwrap_or(64).max(1);
            (
                "scientific_compute".into(),
                shard_scientific_grid(&model, w, h, tw, th),
            )
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "unsupported plugin (ai_inference|video_render|scientific_compute)",
            )
                .into_response();
        }
    };

    // Cryptographically strong job id (no UUID shortcuts).
    let mut rbytes = [0u8; 16];
    let mut rng = rand_core::OsRng;
    rng.fill_bytes(&mut rbytes);
    let job_id = hex::encode(rbytes);
    let plan = OrchestratePlan {
        job_id: job_id.clone(),
        plugin: plugin_name,
        model: model.clone(),
        task_commitment_root_hex: {
            let mut h = sha2::Sha256::new();
            h.update(b"tet-task-commit:v1");
            for s in &shards {
                h.update(s.task_hash_hex.as_bytes());
                h.update([0u8]);
            }
            hex::encode(h.finalize())
        },
        shards: shards.clone(),
    };
    let outs: Vec<String> = shards
        .iter()
        .map(|s| tet_core::tet_worker::poc_infer(&s.text))
        .collect();
    let merged_output = outs.join("\n---tet-shard---\n");
    let deterministic_recompute_ok = shards
        .iter()
        .zip(outs.iter())
        .all(|(s, o)| tet_core::tet_worker::poc_infer(&s.text) == *o);
    let execution_root_hex = {
        let mut h = sha2::Sha256::new();
        h.update(b"tet-execution-root:v1");
        for (s, out) in shards.iter().zip(outs.iter()) {
            h.update(s.shard_id.to_le_bytes());
            let mut hh = sha2::Sha256::new();
            hh.update(out.as_bytes());
            h.update(hex::encode(hh.finalize()).as_bytes());
            h.update([0u8]);
        }
        hex::encode(h.finalize())
    };
    let run = OrchestrateRunResult {
        job_id,
        shard_outputs: outs,
        merged_output,
        deterministic_recompute_ok,
        execution_root_hex,
    };

    // Verification engine stub: require deterministic recomputation AND redundancy>=1.
    // For production: compare hashes across multiple workers per shard.
    if !run.deterministic_recompute_ok || redundancy < 1 {
        return (
            StatusCode::UNAUTHORIZED,
            "verification failed (determinism check)",
        )
            .into_response();
    }

    // Payment flow: reward minted to a registered worker (if any); otherwise, skip reward.
    // This keeps /v1/compute fully automated even without workers online.
    let att = AttestationReport {
        v: 1,
        platform: req.payment.attestation.platform.clone(),
        report_b64: req.payment.attestation.report_b64.clone(),
    };

    // Charge the user the compute price (already transferred to pool by /ai/proxy pattern).
    // Here we just accept the payment as authorization and mint rewards to workers.
    let imperial_vault = std::env::var("TET_IMPERIAL_VAULT_WALLET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "founder-vault-1".to_string());

    // Energy oracle: estimate CHF cost from shard count (stub).
    let pricing = crate::oracle::energy_pricing_for_geo(&geo);
    let chf_micro_cost = (plan.shards.len() as f64 * pricing.chf_per_kwh * 10_000.0).ceil() as u64; // stub
    let reward_gross =
        crate::oracle::reward_micro_from_energy(chf_micro_cost, pricing.profit_margin);

    let worker_wallet_opt = {
        let reg = std_lock(&state.workers);
        reg.by_wallet
            .values()
            .max_by(|a, b| a.last_seen_ms.cmp(&b.last_seen_ms))
            .map(|e| e.wallet.clone())
    };

    if let Some(worker_wallet) = worker_wallet_opt {
        let payload = serde_json::json!({
            "v": 1,
            "kind": "v1_compute_reward",
            "job_id": plan.job_id,
            "plugin": plugin,
            "shards": plan.shards.len(),
            "geo": geo,
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let _ = state.ledger.mint_worker_network_reward(
            &worker_wallet,
            &imperial_vault,
            reward_gross,
            &payload_bytes,
            Some(&att),
        );
    }

    #[derive(Serialize)]
    struct R {
        plan: crate::conductor::OrchestratePlan,
        run: crate::conductor::OrchestrateRunResult,
        reward_micro_est: u64,
        oracle_chf_per_kwh: f64,
        oracle_profit_margin: f64,
    }
    (
        StatusCode::OK,
        Json(R {
            plan,
            run,
            reward_micro_est: reward_gross,
            oracle_chf_per_kwh: pricing.chf_per_kwh,
            oracle_profit_margin: pricing.profit_margin,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct FounderGenesisReq {
    founder_wallet_id: String,
    mldsa_pubkey_b64: String,
    mldsa_signature_b64: String,
}

async fn post_founder_genesis(
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
    if let Err(e) = crate::wallet::verify_mldsa44_b64(
        &req.mldsa_pubkey_b64,
        &req.mldsa_signature_b64,
        &msg,
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid founder ml-dsa signature: {e}"),
        )
            .into_response();
    }
    match state.ledger.apply_genesis_allocation(&wid) {
        Ok(summary) => {
            let tet = |micro: u64| micro as f64 / STEVEMON as f64;
            eprintln!(
                "\n\
╔══════════════════════════════════════════════════════════════════════════════╗\n\
║  TET GENESIS BLOCK — WHITEPAPER GENESIS (FOUNDER + WORKER POOL)              ║\n\
╠══════════════════════════════════════════════════════════════════════════════╣\n\
║  Tokenomics                                                                  ║\n\
╚══════════════════════════════════════════════════════════════════════════════╝"
            );
            eprintln!(
                "  · Founder genesis → {} TET  wallet={}",
                tet(summary.founder_allocation_micro),
                summary.founder_wallet_id
            );
            eprintln!("  · DEX treasury     → {} TET", tet(summary.dex_treasury_allocation_micro));
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

async fn get_founder_audit_csv(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(r) = require_api_key(&headers) {
        return r;
    }
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
