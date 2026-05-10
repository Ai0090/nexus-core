use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use sha2::Digest as _;

use crate::{
    ledger::LedgerError,
    protocol::{SignedTxEnvelopeV1, TxV1},
    rest::{
        RestState,
        helpers::{ollama_generate, std_lock, verify_envelope_v1},
    },
};

pub async fn post_enterprise_inference(
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
                .into_response();
        }
    };
    let TxV1::EnterpriseInference {
        enterprise_wallet_id,
        prompt,
        model,
        amount_micro,
        nonce,
        prompt_sha256_hex,
        workload_flag: _,
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
    if let Err(e) = state.ledger.ai_consume_nonce(&w, nonce) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "NONCE_REPLAY_OR_GAP",
                "message": e.to_string(),
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

    // Enforce worker bond (Sybil stake in worker_stakes_v1).
    if !state.ledger.is_active_worker(&worker_wallet) {
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
    let want_model = if requested_model.is_empty() {
        "llama3"
    } else {
        requested_model
    };
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
    let (worker_micro, treasury_micro, burn_micro) =
        match state
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

pub async fn post_enterprise_inference_submit(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> axum::response::Response {
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
                .into_response();
        }
    };

    let TxV1::EnterpriseInference {
        enterprise_wallet_id,
        prompt: _,
        model: _,
        amount_micro,
        nonce,
        prompt_sha256_hex: _,
        workload_flag,
        attestation_required: _,
    } = &env.tx
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

    if let Err(e) = crate::consensus::validate_enterprise_inference_tx(&env.tx) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "INVALID_ENTERPRISE_INFERENCE_TX",
                "message": e,
            })),
        )
            .into_response();
    }
    let workload_flag_value = *workload_flag;
    if !env
        .sig
        .ed25519_pubkey_hex
        .trim()
        .eq_ignore_ascii_case(enterprise_wallet_id.trim())
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "ACTIVE_WALLET_MISMATCH",
                "message": "enterprise_wallet_id must match envelope pubkey",
            })),
        )
            .into_response();
    }
    let spendable = state
        .ledger
        .spendable_balance_micro_now(enterprise_wallet_id)
        .unwrap_or(0);
    if spendable < *amount_micro {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({
                "error": "INSUFFICIENT_FUNDS",
                "message": "insufficient spendable balance for declared AI workload amount",
            })),
        )
            .into_response();
    }
    if let Err(e) = state.ledger.ai_consume_nonce(enterprise_wallet_id, *nonce) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "NONCE_REPLAY_OR_GAP",
                "message": e.to_string(),
            })),
        )
            .into_response();
    }

    if let Err(e) = state.enqueue_mempool_tx(env).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "MEMPOOL_FULL",
                "message": e.to_string(),
            })),
        )
            .into_response();
    }

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ok": true,
            "status": "pending",
            "queued": true,
            "workload_flag": workload_flag_value,
        })),
    )
        .into_response()
}
