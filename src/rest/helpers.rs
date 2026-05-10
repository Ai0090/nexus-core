use crate::attestation::{AttestationReport, verify_attestation_report};
use crate::protocol::{SignedTxEnvelopeV1, TxV1};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::{Mutex as StdMutex, MutexGuard};
use std::time::Duration;

use super::RestState;

pub fn ollama_url_base() -> String {
    std::env::var("TET_OLLAMA_URL_BASE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11434".into())
}

pub fn ollama_timeout() -> Duration {
    let sec = std::env::var("TET_OLLAMA_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s > 0 && s <= 3600)
        .unwrap_or(120);
    Duration::from_secs(sec)
}

pub async fn ollama_generate(model: &str, prompt: &str) -> Result<String, String> {
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

/// Poisoned mutex recovery: never panic the HTTP server on `lock()` poison.
#[inline]
pub fn std_lock<'a, T>(m: &'a StdMutex<T>) -> MutexGuard<'a, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub async fn global_http_ratelimit(
    State(state): State<RestState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    // CORS preflight must never burn rate limit or hit auth handlers; tower-http CorsLayer
    // usually short-circuits, but if OPTIONS reaches here, pass through.
    if req.method() == axum::http::Method::OPTIONS {
        return next.run(req).await;
    }
    let mut rl = state.http_ratelimit.lock().await;
    if !rl.tick_allow() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    drop(rl);
    next.run(req).await
}

/// Constant-time UTF-8 string equality (for API key comparison).
fn str_ct_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in ab.iter().zip(bb.iter()) {
        d |= x ^ y;
    }
    d == 0
}

/// **Mainnet / operator** routes: require `Authorization: Bearer <TET_ADMIN_API_KEY>`.
/// Missing env, empty key, missing header, or wrong token → `401 Unauthorized` (JSON body).
#[allow(clippy::result_large_err)]
pub fn require_admin_bearer(headers: &HeaderMap) -> Result<(), axum::response::Response> {
    let expected = match std::env::var("TET_ADMIN_API_KEY") {
        Ok(k) => {
            let t = k.trim();
            if t.is_empty() {
                return Err(
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({
                            "error": "ADMIN_API_KEY_NOT_CONFIGURED",
                            "message": "TET_ADMIN_API_KEY is set but empty; administrative routes are disabled.",
                        })),
                    )
                        .into_response(),
                );
            }
            k
        }
        Err(_) => {
            return Err(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "ADMIN_API_KEY_NOT_CONFIGURED",
                        "message": "TET_ADMIN_API_KEY is not set; administrative HTTP routes are disabled.",
                    })),
                )
                    .into_response(),
            );
        }
    };
    let expected_trim = expected.trim();
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    const PREFIX: &str = "Bearer ";
    let token = if auth.len() >= PREFIX.len() && auth[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        auth[PREFIX.len()..].trim()
    } else {
        ""
    };
    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "UNAUTHORIZED",
                "message": "Missing Authorization: Bearer token for administrative route.",
            })),
        )
            .into_response());
    }
    if !str_ct_eq(token, expected_trim) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "UNAUTHORIZED",
                "message": "Invalid administrative API key.",
            })),
        )
            .into_response());
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
pub fn require_hybrid_sig(
    headers: &HeaderMap,
    wallet_id_hex: &str,
    msg: &[u8],
) -> Result<(), axum::response::Response> {
    let ed25519_pk_hex = headers
        .get("x-tet-ed25519-pubkey-hex")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(wallet_id_hex);
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
        crate::quantum_shield::verify_hybrid(ed25519_pk_hex, ed, mldsa_pk, mldsa_sig, msg)
    {
        return Err((StatusCode::UNAUTHORIZED, e.to_string()).into_response());
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
pub fn require_dex_hybrid_sig_strict(
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
    crate::wallet::verify_mldsa_b64(mldsa_pk_b64, mldsa_sig_b64, msg)
        .map_err(|e| (StatusCode::FORBIDDEN, e).into_response())?;
    Ok(())
}

pub fn mainnet_strict() -> bool {
    std::env::var("TET_MAINNET")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn verify_envelope_v1(env: &SignedTxEnvelopeV1) -> Result<Vec<u8>, String> {
    if env.v != 1 {
        return Err("unsupported envelope version".into());
    }
    let tx_bytes = crate::wallet::tx_v1_auth_message_bytes(&env.tx, &env.sig.mldsa_pubkey_b64)?;
    let legacy_tx_bytes = match &env.tx {
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

    if mainnet_strict() {
        let stub = std::env::var("TET_ATTESTATION_ALLOW_STUB")
            .ok()
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if stub {
            return Err("attestation stubs are forbidden on mainnet".into());
        }
    }

    let canonical_ok = crate::quantum_shield::verify_ed25519(
        &env.sig.ed25519_pubkey_hex,
        &env.sig.ed25519_sig_b64,
        &tx_bytes,
    )
    .is_ok()
        && crate::wallet::verify_mldsa_b64(
            &env.sig.mldsa_pubkey_b64,
            &env.sig.mldsa_sig_b64,
            &tx_bytes,
        )
        .is_ok();
    let signed_tx_bytes = if canonical_ok {
        tx_bytes.clone()
    } else {
        if mainnet_strict() {
            return Err("invalid signature or missing chain_id/genesis_hash binding".into());
        }
        crate::quantum_shield::verify_ed25519(
            &env.sig.ed25519_pubkey_hex,
            &env.sig.ed25519_sig_b64,
            &legacy_tx_bytes,
        )
        .map_err(|e| e.to_string())?;
        crate::wallet::verify_mldsa_b64(
            &env.sig.mldsa_pubkey_b64,
            &env.sig.mldsa_sig_b64,
            &legacy_tx_bytes,
        )?;
        legacy_tx_bytes.clone()
    };

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
        verify_attestation_report(&report, &signed_tx_bytes).map_err(|e| e.to_string())?;
    }

    Ok(signed_tx_bytes)
}
