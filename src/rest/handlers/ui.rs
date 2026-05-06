use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
};

/// Extracted UI delivery handlers.
///
/// These forward to the original implementations kept in `rest.rs` for now, so behavior stays
/// identical while we de-monolith routing and handler organization.
pub async fn get_ui() -> impl IntoResponse {
    let csp = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; \
script-src 'self'; connect-src 'self' http://127.0.0.1:5791; img-src 'self' data:; style-src 'self' 'unsafe-inline'";
    (
        [
            ("content-security-policy", csp),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
        ],
        Html(include_str!("../../ui.html")),
    )
}

pub async fn get_nexus_wasm_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("cache-control", "no-cache"),
        ],
        include_str!("../../../../nexus-wasm/pkg/nexus_wasm.js"),
    )
}

pub async fn get_nexus_wasm_bg_wasm() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "application/wasm"),
            ("cache-control", "no-cache"),
        ],
        include_bytes!("../../../../nexus-wasm/pkg/nexus_wasm_bg.wasm") as &'static [u8],
    )
}
