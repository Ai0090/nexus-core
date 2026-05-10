use axum::{
    Json, extract::Path, extract::Query, extract::State, http::HeaderMap, response::IntoResponse,
};
use base64::Engine as _;
use solana_sdk::pubkey::Pubkey;

use crate::rest::{
    AiHistoryQuery, AiInferReq, AiInferSignedReq, AiNonceQuery, AiNonceResp, AiPricingQuery,
    AiUtilityReq, RestState,
};

/// Fixed ledger debit per local `POST /ai/infer` settlement (Stevemon micro units).
/// Same baseline as P2P [`crate::p2p_network::AI_INFER_MICROPAYMENT_MICRO`].
const AI_INFER_LOCAL_CHARGE_MICRO: u64 = crate::p2p_network::AI_INFER_MICROPAYMENT_MICRO;

fn is_wallet_id_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn verify_ed25519_prompt_nonce_sig_b64(
    prompt: &str,
    nonce: u64,
    wallet_id_hex: &str,
    sig_b64: &str,
) -> bool {
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::Signature;

    let pk_bytes = match hex::decode(wallet_id_hex.as_bytes()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
        return false;
    };
    let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr);
    let pk = match pk {
        Ok(v) => v,
        Err(_) => return false,
    };

    let sig_bytes = match STANDARD.decode(sig_b64.trim().as_bytes()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);

    // Spec: sign bytes of (prompt + nonce_decimal).
    let msg = format!("{}{}", prompt, nonce);
    pk.verify_strict(msg.as_bytes(), &sig).is_ok()
}

pub async fn get_ai_nonce(
    State(state): State<RestState>,
    Query(q): Query<AiNonceQuery>,
) -> axum::response::Response {
    let wallet = q.wallet_id.trim().to_ascii_lowercase();
    if !is_wallet_id_hex64(&wallet) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "wallet_id must be 64 hex chars",
        )
            .into_response();
    }
    match state.ledger.ai_next_nonce(&wallet) {
        Ok(nonce) => (
            axum::http::StatusCode::OK,
            Json(AiNonceResp {
                wallet_id: wallet,
                nonce,
            }),
        )
            .into_response(),
        Err(e) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}

pub async fn get_ai_pricing(Query(q): Query<AiPricingQuery>) -> axum::response::Response {
    (
        axum::http::StatusCode::OK,
        Json(crate::ai_proxy::handle_ai_pricing(
            q.model.trim(),
            q.input.as_str(),
        )),
    )
        .into_response()
}

pub async fn get_ai_infer_history(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
    Query(q): Query<AiHistoryQuery>,
) -> axum::response::Response {
    let wallet = wallet.trim().to_ascii_lowercase();
    if wallet.len() != 64 || !wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "wallet must be 64 hex chars",
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    match state.ledger.ai_infer_history_for_wallet(&wallet, limit) {
        Ok(v) => (axum::http::StatusCode::OK, Json(v)).into_response(),
        Err(crate::ledger::LedgerError::Invalid(msg)) => {
            (axum::http::StatusCode::BAD_REQUEST, msg).into_response()
        }
        Err(e) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}

pub async fn post_ai_utility(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<AiUtilityReq>,
) -> impl IntoResponse {
    post_ai_utility_impl(State(state), headers, req, None, None).await
}

/// `infer_wallet_if_preverified`: when set (from `POST /ai/infer`), hybrid auth was already enforced
/// for this wallet, prompt, and `flops`; P2P branch requires `x-tet-wallet-id` to match (no header/body split attack).
async fn post_ai_utility_impl(
    State(state): State<RestState>,
    headers: HeaderMap,
    req: AiUtilityReq,
    welcome_airdrop_micro: Option<u64>,
    infer_wallet_if_preverified: Option<String>,
) -> axum::response::Response {
    if req.prompt.len() > 24_576 {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "prompt exceeds maximum length (24KiB)",
        )
            .into_response();
    }

    if let Some(tid) = req
        .target_worker_id
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        let prompt = req.prompt.trim().to_string();
        if prompt.is_empty() {
            return (axum::http::StatusCode::BAD_REQUEST, "prompt required").into_response();
        }

        let sender_id = headers
            .get("x-tet-wallet-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !is_wallet_id_hex64(&sender_id) {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "WALLET_ID_REQUIRED",
                    "message": "Header `x-tet-wallet-id` (64 hex chars) is required for P2P inference; anonymous sender fallback is disabled.",
                })),
            )
                .into_response();
        }

        if let Some(ref w) = infer_wallet_if_preverified {
            let w = w.trim().to_ascii_lowercase();
            if sender_id != w {
                return (
                    axum::http::StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "WALLET_HEADER_MISMATCH",
                        "message": "`x-tet-wallet-id` must match the authenticated `wallet_id` from POST /ai/infer.",
                    })),
                )
                    .into_response();
            }
        }

        let flops_v = match req.flops {
            Some(f) if f > 0 => f,
            _ => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "FLOPS_REQUIRED",
                        "message": "JSON field `flops` (u64, > 0) is required; Ed25519 + ML-DSA must sign the same canonical infer message.",
                    })),
                )
                    .into_response();
            }
        };

        if req.nonce == 0 {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "NONCE_REQUIRED",
                    "message": "JSON field `nonce` (u64, > 0) is required; hybrid signature binds it (replay protection).",
                })),
            )
                .into_response();
        }
        // If this request wasn't already preverified by `/ai/infer`, consume nonce now (Sled, monotonic).
        if infer_wallet_if_preverified.is_none() {
            if let Err(e) = state.ledger.ai_consume_nonce(&sender_id, req.nonce) {
                return (axum::http::StatusCode::UNAUTHORIZED, e.to_string()).into_response();
            }
            let hybrid_msg = crate::wallet::ai_infer_hybrid_auth_message_bytes(
                &sender_id, &prompt, flops_v, req.nonce,
            );
            if let Err(r) =
                crate::rest::helpers::require_hybrid_sig(&headers, &sender_id, &hybrid_msg)
            {
                return r;
            }
        }

        let max_fee_micro = req
            .max_fee_micro
            .unwrap_or(crate::p2p_network::AI_INFER_MICROPAYMENT_MICRO);
        if max_fee_micro == 0 || max_fee_micro > crate::ledger::MAX_SUPPLY_MICRO {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "INVALID_MAX_FEE",
                    "message": "max_fee_micro must be between 1 and MAX_SUPPLY (Stevemon).",
                })),
            )
                .into_response();
        }

        {
            let spendable = state.ledger.balance_micro(&sender_id).unwrap_or(0);
            if spendable < max_fee_micro {
                return (
                    axum::http::StatusCode::PAYMENT_REQUIRED,
                    Json(serde_json::json!({
                        "error": "INSUFFICIENT_LEDGER_BALANCE",
                        "message": "Insufficient Stevemon for this P2P inference (need at least max_fee_micro).",
                        "max_fee_micro": max_fee_micro,
                        "spendable_micro": spendable,
                    })),
                )
                    .into_response();
            }
        }

        let Some(p2p) = state.p2p_client.as_ref() else {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "P2P_DISABLED",
                    "message": "P2P client is not available on this node.",
                })),
            )
                .into_response();
        };

        use rand_core::RngCore as _;
        let mut nonce12 = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce12);

        #[derive(serde::Serialize)]
        struct E2eeBoxV1 {
            client_ephemeral_pub_b64: String,
            client_mlkem_pub_b64: String,
            mlkem_ciphertext_b64: String,
            nonce12_b64: String,
            ciphertext_b64: String,
        }

        let worker_pk = {
            let reg = crate::rest::helpers::std_lock(&state.workers);
            reg.by_wallet
                .get(&tid)
                .and_then(|e| e.x25519_pubkey_b64.as_deref())
                .and_then(|b64| crate::e2ee::decode_x25519_pub_b64(b64.trim()).ok())
        }
        .or_else(|| {
            if let Ok(pk_b64) = std::env::var("TET_WORKER_X25519_PUB_B64")
                && let Ok(pk) = crate::e2ee::decode_x25519_pub_b64(pk_b64.trim())
            {
                return Some(pk);
            }
            None
        });
        let Some(worker_pk) = worker_pk else {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "WORKER_E2EE_KEY_MISSING",
                    "message": "Worker has no x25519 pubkey; cannot encrypt prompt.",
                })),
            )
                .into_response();
        };

        let client_sk_b64 = std::env::var("TET_X25519_STATIC_SK_B64")
            .ok()
            .unwrap_or_default();
        let client_sk = match crate::e2ee::decode_x25519_static_sk_b64(client_sk_b64.trim()) {
            Ok(v) => v,
            Err(_) => {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "CLIENT_E2EE_KEY_MISSING",
                        "message": "Client is missing TET_X25519_STATIC_SK_B64; cannot encrypt prompt.",
                    })),
                )
                    .into_response();
            }
        };
        let client_pk = x25519_dalek::PublicKey::from(&client_sk);

        let worker_mlkem_pub_b64 = std::env::var("TET_WORKER_MLKEM_PUB_B64")
            .ok()
            .unwrap_or_default();
        let worker_mlkem_pk = match crate::e2ee::decode_mlkem_pub_b64(worker_mlkem_pub_b64.trim()) {
            Ok(v) => v,
            Err(_) => {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "WORKER_PQC_KEY_MISSING",
                        "message": "Missing/invalid TET_WORKER_MLKEM_PUB_B64 for testnet route.",
                    })),
                )
                    .into_response();
            }
        };
        let client_mlkem_pub_b64 = std::env::var("TET_MLKEM_STATIC_PUB_B64")
            .ok()
            .unwrap_or_default();
        let client_mlkem_pk = match crate::e2ee::decode_mlkem_pub_b64(client_mlkem_pub_b64.trim()) {
            Ok(v) => v,
            Err(_) => {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "CLIENT_PQC_KEY_MISSING",
                        "message": "Client is missing TET_MLKEM_STATIC_PUB_B64; cannot receive PQ response.",
                    })),
                )
                    .into_response();
            }
        };
        let (ct, mlkem_ct) = match crate::e2ee::encrypt_for_worker(
            &client_sk,
            &worker_pk,
            &worker_mlkem_pk,
            nonce12,
            prompt.as_bytes(),
        ) {
            Ok(v) => v,
            Err(_) => {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "E2EE_ENCRYPT_FAILED",
                        "message": "Failed to encrypt prompt for worker.",
                    })),
                )
                    .into_response();
            }
        };

        let box_v1 = E2eeBoxV1 {
            client_ephemeral_pub_b64: crate::e2ee::encode_x25519_pub_b64(&client_pk),
            client_mlkem_pub_b64: crate::e2ee::encode_mlkem_b64(&client_mlkem_pk),
            mlkem_ciphertext_b64: crate::e2ee::encode_mlkem_b64(&mlkem_ct),
            nonce12_b64: base64::engine::general_purpose::STANDARD.encode(nonce12),
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ct),
        };
        let box_bytes = serde_json::to_vec(&box_v1).unwrap_or_default();
        let req2 = crate::p2p_network::InferenceRequest {
            target_worker_id: tid.clone(),
            sender_id: sender_id.clone(),
            encrypted_prompt_b64: base64::engine::general_purpose::STANDARD.encode(box_bytes),
            max_fee_micro,
        };
        let bytes = match serde_json::to_vec(&req2) {
            Ok(v) => v,
            Err(e) => return (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        };

        use sha2::{Digest as _, Sha256};
        let trace_root: [u8; 32] = Sha256::digest(prompt.as_bytes()).into();
        let trace_root_b64 = base64::engine::general_purpose::STANDARD.encode(trace_root);
        let rx = crate::p2p_network::register_inference_waiter(trace_root_b64.clone());

        let mut published = false;
        for attempt in 0..12u32 {
            match p2p.broadcast_inference_with_ack(bytes.clone()).await {
                Ok(()) => {
                    published = true;
                    break;
                }
                Err(e) => {
                    if attempt == 11 {
                        crate::p2p_network::unregister_inference_waiter(&trace_root_b64);
                        return (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            Json(serde_json::json!({
                                "error": "P2P_PUBLISH_FAILED",
                                "message": format!("Failed to publish inference request: {e}"),
                            })),
                        )
                            .into_response();
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        if !published {
            crate::p2p_network::unregister_inference_waiter(&trace_root_b64);
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "P2P_PUBLISH_FAILED",
                    "message": "Failed to publish inference request.",
                })),
            )
                .into_response();
        }

        let got = tokio::time::timeout(std::time::Duration::from_secs(90), rx).await;
        crate::p2p_network::unregister_inference_waiter(&trace_root_b64);
        match got {
            Ok(Ok(v)) => {
                // Phase 5.1: Economic Loop — pay worker reward if receipt verifies.
                let receipt_ok =
                    crate::zk_verifier::verify_receipt(&v.receipt_b64).unwrap_or(false);
                if receipt_ok {
                    let wid = v.worker_id.trim().to_ascii_lowercase();
                    if wid.len() == 64
                        && wid.chars().all(|c| c.is_ascii_hexdigit())
                        && let Ok(bytes) = hex::decode(wid.as_bytes())
                        && let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice())
                    {
                        let pk = Pubkey::new_from_array(arr);
                        let sol = state.solana.clone();
                        tokio::spawn(async move {
                            let res =
                                tokio::task::spawn_blocking(move || sol.pay_worker_reward(&pk))
                                    .await;
                            match res {
                                Ok(Ok(sig)) => {
                                    log::info!(
                                        "Settlement complete: {} TET paid to Worker {} sig={}",
                                        crate::ledger::solana_client::REWARD_PER_INFERENCE_TET,
                                        wid,
                                        sig
                                    );
                                }
                                Ok(Err(e)) => {
                                    log::error!("[settlement] payout failed worker={} err={e}", wid)
                                }
                                Err(e) => {
                                    log::error!(
                                        "[settlement] payout join failed worker={} err={e}",
                                        wid
                                    )
                                }
                            }
                        });
                    }
                } else {
                    log::warn!(
                        "[settlement] receipt invalid; skipping payout worker={}",
                        v.worker_id
                    );
                }
                let mut body = serde_json::json!({
                        "ok": true,
                        "worker_id": v.worker_id,
                        "response": v.response,
                        "receipt_b64": v.receipt_b64,
                        "max_fee_micro": max_fee_micro,
                });
                if let Some(m) = welcome_airdrop_micro {
                    body["welcome_airdrop_micro"] = serde_json::json!(m);
                }
                return (axum::http::StatusCode::OK, Json(body)).into_response();
            }
            Ok(Err(_closed)) => {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "INFERENCE_CHANNEL_CLOSED",
                        "message": "Inference result channel closed unexpectedly.",
                    })),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    axum::http::StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "error": "INFERENCE_TIMEOUT",
                        "message": "Timed out waiting for inference result.",
                    })),
                )
                    .into_response();
            }
        }
    }

    let prompt_trim = req.prompt.trim();
    if prompt_trim.is_empty() {
        return (axum::http::StatusCode::BAD_REQUEST, "prompt required").into_response();
    }

    let wallet = headers
        .get("x-tet-wallet-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !is_wallet_id_hex64(&wallet) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "WALLET_ID_REQUIRED",
                "message": "Header `x-tet-wallet-id` (64 hex chars) is required for local AI utility; unsigned Ollama fallback is disabled.",
            })),
        )
            .into_response();
    }

    let flops_v = match req.flops {
        Some(f) if f > 0 => f,
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "FLOPS_REQUIRED",
                    "message": "JSON field `flops` (u64, > 0) is required; Ed25519 + ML-DSA hybrid verification is mandatory.",
                })),
            )
                .into_response();
        }
    };
    if req.nonce == 0 {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "NONCE_REQUIRED",
                "message": "JSON field `nonce` (u64, > 0) is required; hybrid signature binds it (replay protection).",
            })),
        )
            .into_response();
    }
    // Consume nonce unless already preverified by `/ai/infer` (which consumed it).
    if infer_wallet_if_preverified.is_none()
        && let Err(e) = state.ledger.ai_consume_nonce(&wallet, req.nonce)
    {
        return (axum::http::StatusCode::UNAUTHORIZED, e.to_string()).into_response();
    }
    let hybrid_msg =
        crate::wallet::ai_infer_hybrid_auth_message_bytes(&wallet, prompt_trim, flops_v, req.nonce);
    if let Err(r) = crate::rest::helpers::require_hybrid_sig(&headers, &wallet, &hybrid_msg) {
        return r;
    }

    let out = match crate::rest::helpers::ollama_generate("llama3", prompt_trim).await {
        Ok(t) => t,
        Err(e) => {
            // Graceful fallback: never crash if Ollama isn't installed/running.
            let msg = e.to_string();
            let is_offline = msg.to_ascii_lowercase().contains("connection")
                || msg.to_ascii_lowercase().contains("refused")
                || msg.to_ascii_lowercase().contains("timed out")
                || msg.to_ascii_lowercase().contains("dns");
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
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
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "response": out,
        })),
    )
        .into_response()
}

pub async fn post_ai_infer(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<AiInferReq>,
) -> axum::response::Response {
    let wallet = req.wallet_id.trim().to_ascii_lowercase();
    if wallet.len() != 64 || !wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "wallet_id must be 64 hex chars",
        )
            .into_response();
    }
    let prompt = req.prompt.trim().to_string();
    if prompt.is_empty() {
        return (axum::http::StatusCode::BAD_REQUEST, "prompt required").into_response();
    }

    let flops_v = match req.flops {
        Some(f) if f > 0 => f,
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "FLOPS_REQUIRED",
                    "message": "JSON field `flops` (u64, > 0) is required; Ed25519 + ML-DSA hybrid verification is mandatory for inference on all nodes.",
                })),
            )
                .into_response();
        }
    };
    if req.nonce == 0 {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "NONCE_REQUIRED",
                "message": "JSON field `nonce` (u64, > 0) is required; hybrid signature binds it (replay protection).",
            })),
        )
            .into_response();
    }
    // Consume nonce in Sled before doing any settlement (prevents replay even if request is retried).
    if let Err(e) = state.ledger.ai_consume_nonce(&wallet, req.nonce) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "INVALID_NONCE",
                "message": e.to_string(),
            })),
        )
            .into_response();
    }
    let msg =
        crate::wallet::ai_infer_hybrid_auth_message_bytes(&wallet, &prompt, flops_v, req.nonce);
    if let Err(r) = crate::rest::helpers::require_hybrid_sig(&headers, &wallet, &msg) {
        return r;
    }

    let welcome_airdrop_micro = match state.ledger.claim_initial_airdrop(&wallet) {
        Ok(crate::ledger::InitialAirdropClaimOutcome::Granted { credited_micro }) => {
            Some(credited_micro)
        }
        Ok(_) => None,
        Err(e) => {
            log::debug!("[faucet] initial airdrop claim skipped: {e}");
            None
        }
    };

    // Phase 5.2 + Phase 1 ledger: minimum Stevemon on Sled (spam gate).
    // Use raw `balances` tree balance — same source as GET /ledger/me — not `spendable_balance_micro_now`
    // (vesting / locks can zero spendable while on-ledger credits exist).
    {
        let min_micro = 10u64.saturating_mul(crate::ledger::STEVEMON);
        let spendable = state.ledger.balance_micro(&wallet).unwrap_or(0);
        if spendable < min_micro {
            return (
                axum::http::StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({
                    "error": "INSUFFICIENT_LEDGER_BALANCE",
                    "message": "Insufficient spendable TET (Stevemon) on ledger for inference.",
                    "min_micro": min_micro,
                    "spendable_micro": spendable,
                })),
            )
                .into_response();
        }
    }

    // Choose a worker (V1): use first registered worker wallet.
    let target_worker_id = {
        let reg = crate::rest::helpers::std_lock(&state.workers);
        reg.by_wallet.keys().next().cloned()
    }
    .or_else(|| {
        std::env::var("TET_DEFAULT_WORKER_ID")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    });

    let Some(tid) = target_worker_id else {
        // Phase 5.2 dev UX: single-node local fallback (no P2P workers available).
        let worker_pk = match state.solana.founder_pubkey() {
            Ok(v) => v,
            Err(e) => {
                log::error!("[ai][local_fallback] failed to load founder pubkey: {e}");
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "NO_WORKERS",
                        "message": "No workers available and local fallback is not configured (missing founder.json).",
                    })),
                )
                    .into_response();
            }
        };
        let worker_id = hex::encode(worker_pk.to_bytes());

        let metrics = match crate::worker_engine::run_local_inference(prompt.trim()).await {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string();
                let status = if msg.contains("TET_ERR_SAFE_MODE") {
                    axum::http::StatusCode::FORBIDDEN
                } else {
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                };
                return (status, msg).into_response();
            }
        };
        let resp = metrics.text.clone();

        let charge_micro = AI_INFER_LOCAL_CHARGE_MICRO;

        let infer_delay_ms = state.ledger.infer_consensus_delay_ms();
        if infer_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(infer_delay_ms)).await;
        }

        let (pool_half, burn_half, audit_hash, audit_seq) = match state
            .ledger
            .settle_ai_inference_dynamic_charge(&wallet, charge_micro)
        {
            Ok(v) => v,
            Err(crate::ledger::LedgerError::InsufficientFunds) => {
                return (
                    axum::http::StatusCode::PAYMENT_REQUIRED,
                    Json(serde_json::json!({
                        "error": "INSUFFICIENT_FUNDS",
                        "message": "Not enough Stevemon to settle this inference (post-compute).",
                        "cost_micro": charge_micro,
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                log::error!("[ai][ledger] settlement failed: {e}");
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "LEDGER_SETTLEMENT_FAILED",
                        "message": format!("{e}"),
                    })),
                )
                    .into_response();
            }
        };
        log::info!(
            "[ai][ledger] inference settled payer={} cost_micro={} pool_credit_micro={} burn_micro={}",
            wallet,
            charge_micro,
            pool_half,
            burn_half
        );

        if let Err(e) = state.ledger.append_ai_infer_session(
            &wallet,
            prompt.trim(),
            resp.trim(),
            charge_micro,
            &audit_hash,
            audit_seq,
        ) {
            log::warn!("[ai][history] append_ai_infer_session failed: {e}");
        }

        let receipt_b64 = match crate::worker_engine::generate_receipt_b64(
            prompt.trim(),
            resp.trim(),
            worker_pk.to_bytes(),
            charge_micro,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("[ai][local_fallback] proof generation failed: {e}");
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "ZK_PROVER_FAILED",
                        "message": format!("{e}"),
                    })),
                )
                    .into_response();
            }
        };

        {
            use sha2::{Digest as _, Sha256};
            let infer_uid = format!("{:x}", Sha256::digest(prompt.trim().as_bytes()));
            crate::vision::zk_court::record_inference_delivered_full(
                state.ledger.as_ref(),
                &infer_uid,
                prompt.trim(),
                resp.trim(),
                metrics.flops,
                &worker_id,
                pool_half,
            );
        }

        let mut body = serde_json::json!({
                "ok": true,
                "worker_id": worker_id,
                "response": resp,
                "receipt_b64": receipt_b64,
                "local_fallback": true,
                "prompt_tokens": metrics.prompt_tokens,
                "completion_tokens": metrics.completion_tokens,
                "flops": format!("{}", metrics.flops),
                "energy_wh": metrics.energy_wh,
                "cost_micro": charge_micro,
                "ncu": metrics.ncu,
        });
        if let Some(m) = welcome_airdrop_micro {
            body["welcome_airdrop_micro"] = serde_json::json!(m);
        }
        return (axum::http::StatusCode::OK, Json(body)).into_response();
    };

    // Reuse the P2P pipeline via existing handler by constructing an AiUtilityReq.
    let req2 = AiUtilityReq {
        prompt,
        target_worker_id: Some(tid),
        nonce: req.nonce,
        max_fee_micro: req.max_fee_micro,
        flops: req.flops,
    };
    post_ai_utility_impl(
        State(state),
        headers,
        req2,
        welcome_airdrop_micro,
        Some(wallet),
    )
    .await
}

pub async fn post_ai_infer_signed(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<AiInferSignedReq>,
) -> axum::response::Response {
    let wallet = req.wallet_id.trim().to_ascii_lowercase();
    if !is_wallet_id_hex64(&wallet) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "wallet_id must be 64 hex chars",
        )
            .into_response();
    }
    let prompt = req.prompt.trim().to_string();
    if prompt.is_empty() {
        return (axum::http::StatusCode::BAD_REQUEST, "prompt required").into_response();
    }

    // Nonce validation (persistent, monotonic): must be next nonce for this wallet.
    if let Err(e) = state.ledger.ai_consume_nonce(&wallet, req.nonce) {
        return (axum::http::StatusCode::UNAUTHORIZED, e.to_string()).into_response();
    }

    // Signature validation over (prompt + nonce).
    if !verify_ed25519_prompt_nonce_sig_b64(&prompt, req.nonce, &wallet, &req.ed25519_sig_b64) {
        return (axum::http::StatusCode::UNAUTHORIZED, "invalid signature").into_response();
    }

    // Forward into the existing pipeline (includes spam-prevention and local fallback).
    let req2 = AiInferReq {
        wallet_id: wallet,
        prompt,
        nonce: req.nonce,
        flops: req.flops,
        max_fee_micro: req.max_fee_micro,
    };
    post_ai_infer(State(state), headers, Json(req2)).await
}

pub async fn post_ai_proxy(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(req): Json<crate::ai_proxy::AiProxyReq>,
) -> impl IntoResponse {
    if let Err(e) = crate::rest::helpers::verify_envelope_v1(&req.payment) {
        return (axum::http::StatusCode::UNAUTHORIZED, e).into_response();
    }
    crate::ai_proxy::handle_ai_proxy(state.ledger.clone(), state.workers.clone(), req)
        .into_response()
}
