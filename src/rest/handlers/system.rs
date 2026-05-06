use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;

use crate::rest::RestState;

pub async fn get_system_update(State(state): State<RestState>) -> impl IntoResponse {
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
