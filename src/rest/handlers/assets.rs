use axum::{http::StatusCode, response::IntoResponse};

pub async fn get_ui_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("../../ui.js"),
    )
}

pub async fn get_landing_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("../../landing.js"),
    )
}

pub async fn get_tet_sdk_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("../../tet_sdk.js"),
    )
}

pub async fn get_tet_sdk_node_mjs() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("../../tet_sdk_node.mjs"),
    )
}

pub async fn get_founder_terminal_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("../../founder_terminal.js"),
    )
}

pub async fn get_wallet_client_bundled_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("cache-control", "public, max-age=3600"),
        ],
        include_str!("../../wallet_client_bundled.js"),
    )
}
