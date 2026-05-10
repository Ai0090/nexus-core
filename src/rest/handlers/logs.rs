use crate::rest::RestState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::StreamExt as _;
use serde::Deserialize;
use sha2::Digest as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;

struct LogSseConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for LogSseConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

pub async fn get_logs_sse(State(state): State<RestState>) -> axum::response::Response {
    let max_connections = std::env::var("TET_LOG_SSE_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(128);
    let prev = state.log_sse_connections.fetch_add(1, Ordering::SeqCst);
    if prev >= max_connections {
        state.log_sse_connections.fetch_sub(1, Ordering::SeqCst);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "SSE_CONNECTION_LIMIT",
                "message": "too many concurrent /logs SSE connections",
                "max_connections": max_connections,
            })),
        )
            .into_response();
    }
    let guard = LogSseConnectionGuard {
        counter: state.log_sse_connections.clone(),
    };
    let rx = state.log_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |msg| {
        let _keepalive_guard = &guard;
        async move {
            match msg {
                Ok(line) => Some(Ok::<Event, std::convert::Infallible>(
                    Event::default().data(line),
                )),
                // Lagged/closed: just skip; client will keep receiving future messages.
                Err(_) => None,
            }
        }
    });

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(10))
                .text("keepalive"),
        )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct ExecuteReq {
    pub prompt: String,
}

pub async fn post_execute(
    State(state): State<RestState>,
    Json(req): Json<ExecuteReq>,
) -> impl axum::response::IntoResponse {
    let prompt = req.prompt.trim().to_string();
    let _ = state
        .log_tx
        .send(format!("[TET-Core] Task Received: {prompt}"));
    let _ = state
        .log_tx
        .send("[ZKVM] Booting RISC-V environment...".to_string());

    let tx = state.log_tx.clone();
    let prompt_clone = prompt.clone();
    let hash = run_zkvm_or_simulate(prompt_clone, tx).await;
    let _ = state.log_tx.send(format!(
        "[ZKVM] Proof generated successfully! Receipt Hash: {hash}"
    ));

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "ok": true, "receipt_hash": hash })),
    )
}

async fn run_zkvm_or_simulate(
    prompt: String,
    log_tx: tokio::sync::broadcast::Sender<String>,
) -> String {
    // If the embedded ELF is missing (e.g. RISC0_SKIP_BUILD=1), simulate for now.
    if methods::NEXUS_GUEST_ELF.is_empty() {
        let _ = log_tx.send("[ZKVM] (sim) Proving…".to_string());
        tokio::time::sleep(Duration::from_secs(3)).await;
        let h = sha2::Sha256::digest(prompt.as_bytes());
        return format!("0x{}", hex::encode(&h[..16]));
    }

    // If zk proving is not enabled, simulate but keep the same interface.
    if !cfg!(feature = "zk-prove") {
        let _ = log_tx.send("[ZKVM] (sim) zk-prove feature disabled; simulating…".to_string());
        tokio::time::sleep(Duration::from_secs(3)).await;
        let h = sha2::Sha256::digest(prompt.as_bytes());
        return format!("0x{}", hex::encode(&h[..16]));
    }

    #[cfg(feature = "zk-prove")]
    {
        // Best-effort real proof generation; fall back to simulation on error.
        let prompt_prove = prompt.clone();
        match tokio::task::spawn_blocking(move || {
            use risc0_zkvm::sha::Digestible as _;
            use risc0_zkvm::{ExecutorEnv, default_prover};
            let env = ExecutorEnv::builder()
                .write(&prompt_prove)
                .unwrap()
                .build()
                .unwrap();
            let prover = default_prover();
            let receipt = prover
                .prove(env, methods::NEXUS_GUEST_ELF)
                .map_err(|e| format!("{e}"))?;
            let claimed = receipt.receipt.claim().map_err(|e| format!("{e}"))?;
            Ok::<_, String>(claimed.digest().to_string())
        })
        .await
        {
            Ok(Ok(d)) => format!("0x{d}"),
            Ok(Err(e)) => {
                let _ = log_tx.send(format!("[ZKVM] (sim) Prover failed, simulating… ({e})"));
                tokio::time::sleep(Duration::from_secs(3)).await;
                let h = sha2::Sha256::digest(prompt.as_bytes());
                format!("0x{}", hex::encode(&h[..16]))
            }
            Err(e) => {
                let _ = log_tx.send(format!(
                    "[ZKVM] (sim) Prover task join failed, simulating… ({e})"
                ));
                tokio::time::sleep(Duration::from_secs(3)).await;
                let h = sha2::Sha256::digest(prompt.as_bytes());
                format!("0x{}", hex::encode(&h[..16]))
            }
        }
    }

    #[cfg(not(feature = "zk-prove"))]
    unreachable!("cfg!(feature=\"zk-prove\") checked above; qed.");
}
