use crate::rest::RestState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GossipRequest {
    message: String,
}

pub async fn post_admin_gossip(
    State(state): State<RestState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if crate::rest::helpers::mainnet_strict() {
        return (
            StatusCode::FORBIDDEN,
            "POST /admin/gossip is disabled on mainnet",
        )
            .into_response();
    }
    if let Err(resp) = crate::rest::helpers::require_admin_bearer(&headers) {
        return resp;
    }

    let msg = if let Ok(req) = serde_json::from_str::<GossipRequest>(&body) {
        req.message
    } else {
        body
    };

    let Some(tx) = state.gossip_tx.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "gossip not enabled").into_response();
    };

    if let Err(e) = tx.send(msg).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to queue gossip: {e}"),
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}
