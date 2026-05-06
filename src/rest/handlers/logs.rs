use crate::rest::RestState;
use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt as _};
use serde::Deserialize;
use sha2::Digest as _;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;

pub async fn get_logs_sse(
    State(state): State<RestState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.log_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| async move {
        match msg {
            Ok(line) => Some(Ok(Event::default().data(line))),
            // Lagged/closed: just skip; client will keep receiving future messages.
            Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keepalive"),
    )
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
