use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use sysinfo::System;

pub async fn get_local_telemetry() -> impl IntoResponse {
    #[derive(Serialize)]
    struct T {
        cpu_usage_pct: f32,
        mem_used_bytes: u64,
        mem_total_bytes: u64,
    }
    let mut sys = System::new_all();
    sys.refresh_all();
    let cpu = sys.global_cpu_usage();
    let mem_total = sys.total_memory().saturating_mul(1024);
    let mem_used = sys.used_memory().saturating_mul(1024);
    (
        StatusCode::OK,
        Json(T {
            cpu_usage_pct: cpu,
            mem_used_bytes: mem_used,
            mem_total_bytes: mem_total,
        }),
    )
        .into_response()
}
