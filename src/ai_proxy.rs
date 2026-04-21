use crate::attestation::AttestationReport;
use crate::ledger::{LedgerError, MAX_SUPPLY_MICRO, STEVEMON};
use crate::protocol::{SignedTxEnvelopeV1, TxV1};
use crate::worker_network::WorkerRegistry;
use axum::{Json, http::StatusCode, response::IntoResponse};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex as StdMutex};
use tet_core::tet_worker::{
    WorkerProofV1, poc_infer, poe_execution_stub_b64, result_sha256_hex, task_sha256_hex,
    worker_sign_message,
};
use zeroize::Zeroize as _;

#[derive(Debug, Deserialize)]
pub struct AiProxyReq {
    /// A payment envelope (typically Transfer to founder).
    pub payment: SignedTxEnvelopeV1,
    /// OpenAI-compatible-ish shape (skeleton only).
    pub model: String,
    pub input: String,
    /// Hardware-bound PoC proof (required for `tet/...` models when workers are online).
    #[serde(default)]
    pub worker_proof: Option<WorkerProofV1>,
}

#[derive(Debug, Serialize)]
pub struct AiProxyResp {
    pub authorized: bool,
    pub model: String,
    /// `worker_network` | `external_api`
    pub route: String,
    pub note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_output: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PricingQuote {
    pub model: String,
    pub input_chars: usize,
    pub est_input_tokens: u64,
    pub est_output_tokens: u64,
    pub api_cost_usd: f64,
    pub buffer_usd_20pct: f64,
    pub total_usd: f64,
    pub usd_per_tet: f64,
    pub required_net_micro: u64,
    pub required_gross_micro: u64,
    pub fee_bps: u64,
    pub required_fee_micro: u64,
}

fn env_f64(name: &str) -> Option<f64> {
    std::env::var(name).ok().and_then(|v| v.parse::<f64>().ok())
}

fn model_key(model: &str) -> String {
    model
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn openai_rate_usd_per_1k(model: &str, which: &str) -> Option<f64> {
    let mk = model_key(model);
    let k1 = format!("TET_OPENAI_USD_PER_1K_{which}_{mk}");
    let k2 = format!("TET_OPENAI_USD_PER_1K_{which}");
    env_f64(&k1).or_else(|| env_f64(&k2))
}

const PRESALE_USD_PER_TET_FALLBACK: f64 = 0.05;

fn quote_pricing(model: &str, input: &str) -> PricingQuote {
    // Minimal token estimator: ~4 chars per token.
    let input_chars = input.len();
    let est_input_tokens = (input_chars as u64).saturating_add(3) / 4;
    let est_output_tokens = std::env::var("TET_OPENAI_EST_OUTPUT_TOKENS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(256);

    // Playground-friendly: never require external OpenAI price env vars. Fall back to internal stubs.
    const DUMMY_IN_USD_PER_1K: f64 = 0.15;
    const DUMMY_OUT_USD_PER_1K: f64 = 0.60;
    let in_rate = openai_rate_usd_per_1k(model, "IN").unwrap_or(DUMMY_IN_USD_PER_1K);
    let out_rate = openai_rate_usd_per_1k(model, "OUT").unwrap_or(DUMMY_OUT_USD_PER_1K);
    let api_cost_usd =
        (est_input_tokens as f64 * in_rate + est_output_tokens as f64 * out_rate) / 1000.0;

    let buffer_usd_20pct = api_cost_usd * 0.20;
    let total_usd = api_cost_usd + buffer_usd_20pct;

    let usd_per_tet = env_f64("TET_USD_PER_TET")
        .filter(|x| x.is_finite() && *x > 0.0)
        .unwrap_or(PRESALE_USD_PER_TET_FALLBACK);

    let required_net_tet = total_usd / usd_per_tet;
    let required_net_micro = (required_net_tet * STEVEMON as f64).ceil().max(0.0) as u64;

    // AI Proxy fee is fixed at 1% (pure profit, routed to founder by ledger).
    let fee_bps = 100u64;
    // gross such that net == gross * (1 - fee_bps/10_000)
    let required_gross_micro =
        (required_net_micro as u128 * 10_000u128).div_ceil((10_000 - fee_bps) as u128);
    let required_gross_micro = u64::try_from(required_gross_micro).unwrap_or(u64::MAX);
    let required_fee_micro = required_gross_micro.saturating_mul(fee_bps) / 10_000;

    PricingQuote {
        model: model.to_string(),
        input_chars,
        est_input_tokens,
        est_output_tokens,
        api_cost_usd,
        buffer_usd_20pct,
        total_usd,
        usd_per_tet,
        required_net_micro,
        required_gross_micro,
        fee_bps,
        required_fee_micro,
    }
}

fn day_since_epoch() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs / 86_400
}

fn month_yyyymm() -> String {
    // UTC month bucket.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // 1970-01-01 + secs → crude but stable; use chrono-free approximation:
    // We intentionally only need a coarse bucket; for production, replace with a proper date lib.
    // Here: month changes every 30 days (good enough for the guard in beta).
    let month_index = secs / (86_400 * 30);
    format!("m{month_index}")
}

pub fn handle_ai_pricing(model: &str, input: &str) -> PricingQuote {
    if is_worker_network_model(model) {
        return quote_worker_network(model, input);
    }
    quote_pricing(model, input)
}

fn is_worker_network_model(model: &str) -> bool {
    let m = model.trim();
    m.starts_with("tet/") || m.starts_with("tet-internal/")
}

fn quote_worker_network(model: &str, input: &str) -> PricingQuote {
    let input_chars = input.len();
    let gross_micro = std::env::var("TET_WORKER_TASK_MIN_GROSS_MICRO")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10_000_000);
    let fee_bps = 100u64;
    let required_fee_micro = gross_micro.saturating_mul(fee_bps) / 10_000;
    let required_net_micro = gross_micro.saturating_sub(required_fee_micro);
    PricingQuote {
        model: model.to_string(),
        input_chars,
        est_input_tokens: 0,
        est_output_tokens: 0,
        api_cost_usd: 0.0,
        buffer_usd_20pct: 0.0,
        total_usd: 0.0,
        usd_per_tet: env_f64("TET_USD_PER_TET")
            .filter(|x| x.is_finite() && *x > 0.0)
            .unwrap_or(PRESALE_USD_PER_TET_FALLBACK),
        required_net_micro,
        required_gross_micro: gross_micro,
        fee_bps,
        required_fee_micro,
    }
}

fn worker_proof_stub_enabled() -> bool {
    std::env::var("TET_WORKER_PROOF_STUB")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn build_stub_worker_proof(model: &str, input: &str) -> Result<WorkerProofV1, String> {
    let sk_hex = std::env::var("TET_WORKER_STUB_SK_HEX")
        .map_err(|_| "TET_WORKER_STUB_SK_HEX required for stub".to_string())?;
    let mut sk_bytes = hex::decode(sk_hex.trim()).map_err(|_| "bad stub sk hex".to_string())?;
    if sk_bytes.len() != 32 {
        return Err("stub sk must be 32 bytes hex".into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&sk_bytes);
    sk_bytes.zeroize();
    let signing_key = SigningKey::from_bytes(&arr);
    let hw = std::env::var("TET_WORKER_STUB_HW_ID").unwrap_or_else(|_| "stub-hardware-id".into());
    let output = poc_infer(input);
    let t = task_sha256_hex(model, input);
    let r = result_sha256_hex(&output);
    let msg = worker_sign_message(&t, &r, hw.trim());
    let sig = signing_key.sign(&msg);
    let ed25519_sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    let poe_stub_b64 = poe_execution_stub_b64(&t, &r);
    Ok(WorkerProofV1 {
        hardware_id_hex: hw,
        task_sha256_hex: t,
        result_sha256_hex: r,
        output_text: output,
        ed25519_sig_b64,
        poe_stub_b64,
    })
}

pub fn handle_ai_proxy(
    ledger: Arc<crate::ledger::Ledger>,
    workers: Arc<StdMutex<WorkerRegistry>>,
    req: AiProxyReq,
) -> impl IntoResponse {
    let model_trim = req.model.trim().to_string();
    let use_worker_route = {
        let w = workers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ttl = std::env::var("TET_WORKER_HEARTBEAT_TTL_MS")
            .ok()
            .and_then(|v| v.parse::<u128>().ok())
            .unwrap_or(120_000);
        w.active_count(ttl) > 0 && is_worker_network_model(&model_trim)
    };

    // `tet/...` models always use the internal worker-network quote shape (fixed stevemon),
    // even when no workers are online (then we fall back to external_api without OpenAI env).
    let quote = if is_worker_network_model(&model_trim) {
        quote_worker_network(&model_trim, &req.input)
    } else {
        quote_pricing(&req.model, &req.input)
    };

    // $50/month hard guard applies to external API routing only.
    if !use_worker_route {
        let limit_usd = std::env::var("TET_COST_GUARD_USD_LIMIT")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(50.0);
        if !(limit_usd.is_finite() && limit_usd > 0.0) {
            return (StatusCode::BAD_REQUEST, "invalid TET_COST_GUARD_USD_LIMIT").into_response();
        }
        let month = month_yyyymm();
        let used_micro_usd = ledger.ai_cost_month_micro_usd_get(&month).unwrap_or(0);
        let used_usd = used_micro_usd as f64 / 1_000_000.0;
        if used_usd >= limit_usd {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "AI Proxy disabled by monthly cost guard",
            )
                .into_response();
        }
    }
    // Verify envelope (signatures + attestation if required).
    // Note: REST layer should call verify_envelope_v1 before reaching here, but we keep this module
    // decoupled and re-check basic invariants on the payment tx kind.
    let TxV1::Transfer {
        from_wallet,
        to_wallet,
        amount_micro,
        fee_bps: _fee_bps_user,
    } = req.payment.tx.clone()
    else {
        return (StatusCode::BAD_REQUEST, "payment must be a transfer").into_response();
    };
    if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "amount exceeds hard cap").into_response();
    }
    let founder = ledger.founder_wallet_public().unwrap_or_default();
    if founder.is_empty() {
        return (StatusCode::BAD_REQUEST, "founder wallet not configured").into_response();
    }
    let pool = std::env::var("TET_AI_COST_POOL_WALLET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tet-api-pool".to_string());
    if pool == founder {
        return (
            StatusCode::BAD_REQUEST,
            "AI cost pool must not be founder wallet",
        )
            .into_response();
    }
    if to_wallet != pool {
        return (
            StatusCode::UNAUTHORIZED,
            "payment must go to AI cost pool wallet",
        )
            .into_response();
    }
    if amount_micro < quote.required_gross_micro {
        return (
            StatusCode::PAYMENT_REQUIRED,
            "insufficient payment amount for pricing quote",
        )
            .into_response();
    }

    // Quota: Founding members (Genesis 1000) have a daily soft cap during beta.
    let cap = std::env::var("TET_GENESIS_AI_DAILY_SOFT_CAP")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(50);
    if cap > 0 && ledger.has_founding_cert(&from_wallet).unwrap_or(false) {
        let day = day_since_epoch();
        let n = ledger
            .ai_daily_inc(&from_wallet, day)
            .unwrap_or(cap.saturating_add(1));
        if n > cap {
            return (StatusCode::TOO_MANY_REQUESTS, "daily soft cap exceeded").into_response();
        }
    }
    let att = AttestationReport {
        v: 1,
        platform: req.payment.attestation.platform.clone(),
        report_b64: req.payment.attestation.report_b64.clone(),
    };
    // AI proxy fee is always 1% and routed to founder by ledger as pure profit.
    let fee_bps = 100u64;
    eprintln!(
        "[AI_PRICING] model={} net_micro={} gross_micro={} fee_micro={} usd_total={:.6} usd_per_tet={:.6}",
        quote.model,
        quote.required_net_micro,
        quote.required_gross_micro,
        quote.required_fee_micro,
        quote.total_usd,
        quote.usd_per_tet
    );
    let month = month_yyyymm();
    match ledger.transfer_with_fee_attested(
        &from_wallet,
        &to_wallet,
        amount_micro,
        Some(fee_bps),
        Some(&att),
        None,
    ) {
        Ok((_net, _fee)) => {
            if use_worker_route {
                let proof = if let Some(p) = req.worker_proof.clone() {
                    p
                } else if worker_proof_stub_enabled() {
                    match build_stub_worker_proof(&model_trim, &req.input) {
                        Ok(p) => p,
                        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
                    }
                } else {
                    return (
                        StatusCode::BAD_REQUEST,
                        "worker_proof required for tet/ models (or set TET_WORKER_PROOF_STUB=1 for dev)",
                    )
                        .into_response();
                };

                let ttl = std::env::var("TET_WORKER_HEARTBEAT_TTL_MS")
                    .ok()
                    .and_then(|v| v.parse::<u128>().ok())
                    .unwrap_or(120_000);
                let entry = {
                    let reg = workers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    reg.get_by_hardware(proof.hardware_id_hex.trim()).cloned()
                };
                let Some(entry) = entry else {
                    return (
                        StatusCode::UNAUTHORIZED,
                        "worker hardware_id not registered (heartbeat /register first)",
                    )
                        .into_response();
                };
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                if now_ms.saturating_sub(entry.last_seen_ms) > ttl {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "worker offline (heartbeat stale)",
                    )
                        .into_response();
                }
                let worker_wallet = entry.wallet.clone();

                if let Err(e) = tet_core::tet_worker::verify_worker_proof_full(
                    &entry.ed25519_pubkey_hex,
                    &model_trim,
                    &req.input,
                    &proof,
                ) {
                    return (StatusCode::UNAUTHORIZED, e).into_response();
                }

                let imperial_vault = std::env::var("TET_IMPERIAL_VAULT_WALLET")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "founder-vault-1".to_string());

                let reward_gross = std::env::var("TET_WORKER_POC_REWARD_MICRO")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1_000_000);

                let payload = serde_json::json!({
                    "v": 1,
                    "kind": "worker_poc",
                    "model": model_trim,
                    "task_sha256_hex": proof.task_sha256_hex,
                    "worker_wallet": worker_wallet,
                });
                let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();

                if let Err(e) = ledger.mint_worker_network_reward(
                    &worker_wallet,
                    &imperial_vault,
                    reward_gross,
                    &payload_bytes,
                    Some(&att),
                ) {
                    return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
                }

                return (
                    StatusCode::OK,
                    Json(AiProxyResp {
                        authorized: true,
                        model: req.model,
                        route: "worker_network".into(),
                        note: "TET Worker Network: PoC verified (hardware-bound signature + ZK-PoE stub). External API not used."
                            .into(),
                        worker_output: Some(proof.output_text),
                    }),
                )
                    .into_response();
            }

            // External API path: book monthly USD cost guard.
            let add_micro_usd = (quote.total_usd * 1_000_000.0).ceil().max(0.0) as u64;
            let _ = ledger.ai_cost_month_micro_usd_add(&month, add_micro_usd);
            (
                StatusCode::OK,
                Json(AiProxyResp {
                    authorized: true,
                    model: req.model,
                    route: "external_api".into(),
                    note: "TET Authorized: Your AI computation is secured by Hardware Attestation."
                        .into(),
                    worker_output: None,
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

/// Spend exactly **1 TET** from the active ledger wallet (no API key; no signer envelope).
/// Routes funds to `TET_AI_COST_POOL_WALLET` with protocol fee / burn split per ledger rules.
///
/// Requires at least one worker heartbeat within `ttl_ms` (same window as `/network/power` / `/network/stats`);
/// otherwise returns **503** with `error: NO_ACTIVE_WORKERS` for transparent UI messaging.
pub fn utility_playground_response(
    ledger: Arc<crate::ledger::Ledger>,
    active_worker_nodes: usize,
    active_wallet: String,
    prompt: String,
) -> axum::response::Response {
    let prompt = prompt.trim().to_string();
    if prompt.is_empty() {
        return (StatusCode::BAD_REQUEST, "prompt required").into_response();
    }
    if active_worker_nodes == 0 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "NO_ACTIVE_WORKERS",
                "message": "0 Active Worker Nodes found.",
            })),
        )
            .into_response();
    }
    let w = active_wallet.trim();
    if w.is_empty() {
        return (StatusCode::BAD_REQUEST, "no active wallet").into_response();
    }
    let pool = std::env::var("TET_AI_COST_POOL_WALLET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tet-api-pool".into());
    let gross = STEVEMON;
    match ledger.transfer_with_fee(w, &pool, gross, Some(100)) {
        Ok((_net, fee_micro)) => {
            let response_text = poc_infer(&prompt);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "spent_tet_micro": gross,
                    "protocol_fee_micro": fee_micro,
                    "pool_wallet": pool,
                    "note": "Utility loop: 1 TET from your balance is routed to the AI utility pool; protocol fees follow ledger treasury / burn split.",
                    "response": response_text,
                })),
            )
                .into_response()
        }
        Err(LedgerError::InsufficientFunds) => {
            (StatusCode::BAD_REQUEST, "insufficient spendable balance (need 1 TET)").into_response()
        }
        Err(LedgerError::AttestationRequired) => (
            StatusCode::FORBIDDEN,
            "wallet transfers require attestation in this environment",
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}
