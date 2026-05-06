use axum::{Json, extract::Path, extract::State, http::StatusCode, response::IntoResponse};

use crate::protocol::{SignedTxEnvelopeV1, TxV1};
use crate::rest::RestState;

pub async fn post_founding_enroll(
    State(state): State<RestState>,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> axum::response::Response {
    let tx_bytes = match crate::rest::helpers::verify_envelope_v1(&env) {
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
    if member_wallet != env.sig.ed25519_pubkey_hex {
        return (
            StatusCode::UNAUTHORIZED,
            "member_wallet must match signer ed25519 pubkey",
        )
            .into_response();
    }
    if env.attestation.platform.is_empty() || env.attestation.report_b64.is_empty() {
        return (StatusCode::UNAUTHORIZED, "attestation required").into_response();
    }
    let report = crate::attestation::AttestationReport {
        v: 1,
        platform: env.attestation.platform.clone(),
        report_b64: env.attestation.report_b64.clone(),
    };
    let hw = match crate::attestation::hardware_id_hex(&report, &tx_bytes) {
        Ok(v) => v,
        Err(e) => return (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
    };
    let cert = crate::ledger::FoundingMemberCert {
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

pub async fn get_founding_cert(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> axum::response::Response {
    match state.ledger.get_founding_cert(wallet.trim()) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}
