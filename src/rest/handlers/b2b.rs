use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine as _;
use rand_core::RngCore as _;

use crate::rest::{
    B2bChatMessage, B2bComputeReq, ComputeE2eeSubmitReq, RestState,
    helpers::{std_lock, verify_envelope_v1},
};

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

pub async fn post_v1_b2b_compute(
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
            .map(|e| {
                (
                    e.wallet.clone(),
                    e.x25519_pubkey_b64.clone().unwrap_or_default(),
                )
            })
    };
    let Some((worker_wallet, worker_pk_b64)) = picked else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no active workers with x25519 keys",
        )
            .into_response();
    };
    if worker_pk_b64.trim().is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no active workers with x25519 keys",
        )
            .into_response();
    }

    let wpk = match crate::e2ee::decode_x25519_pub_b64(worker_pk_b64.trim()) {
        Ok(pk) => pk,
        Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "bad worker x25519 key").into_response();
        }
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
    let worker_mlkem_pub_b64 = {
        let reg = std_lock(&state.workers);
        reg.by_wallet
            .get(&worker_wallet)
            .and_then(|e| e.mlkem_pubkey_b64.clone())
            .unwrap_or_default()
    };
    if worker_mlkem_pub_b64.trim().is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no active workers with mlkem keys",
        )
            .into_response();
    }
    let wmlkem = match crate::e2ee::decode_mlkem_pub_b64(worker_mlkem_pub_b64.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "bad worker mlkem key").into_response(),
    };
    let (ct, _mlkem_ct) =
        match crate::e2ee::encrypt_for_worker(&eph_sk, &wpk, &wmlkem, nonce12, &pt) {
            Ok(c) => c,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed").into_response(),
        };
    let inner = ComputeE2eeSubmitReq {
        worker_wallet,
        client_ephemeral_pub_b64: crate::e2ee::encode_x25519_pub_b64(&eph_pk),
        client_mlkem_pub_b64: String::new(),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce12),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ct),
        mlkem_ciphertext_b64: String::new(),
        payment: req.payment,
    };
    eprintln!(
        "[B2B] compute queued org={org} worker={}",
        inner.worker_wallet
    );
    crate::rest::handlers::worker::enqueue_compute_e2ee_job(state, inner).await
}
