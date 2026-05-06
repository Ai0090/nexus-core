use axum::{http::StatusCode, response::IntoResponse};

pub async fn get_phase4_tee_status() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "Phase 4: TEE compute stub").into_response()
}

pub async fn get_phase4_marketplace_status() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        "Phase 4: marketplace escrow stub",
    )
        .into_response()
}

pub async fn get_phase4_render_farm_status() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "Phase 4: render farm stub").into_response()
}
