//! Inference executor abstraction (Phase 3–4).
//!
//! This crate currently focuses on network protocols and B2B boundaries. The executor interface
//! exists so GPU backends (Metal/CUDA) can be integrated without blocking the swarm loop.

use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorTelemetry {
    pub v: u32,
    pub engine: String, // "llama-cpp" | "candle" | "cuda" ...
    pub wall_ms: u64,
    pub joules: u64,
    pub tokens_generated: u32,
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("executor not configured")]
    NotConfigured,
    #[error("model not available")]
    ModelUnavailable,
    #[error("backend error: {0}")]
    Backend(String),
}

#[allow(dead_code)]
pub trait InferenceExecutor: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn run(
        &self,
        prompt: &str,
        max_new_tokens: u32,
    ) -> Result<(String, ExecutorTelemetry), ExecutorError>;
}

/// Stub: used until llama.cpp/candle integration is wired into this slim repo snapshot.
#[allow(dead_code)]
pub struct StubExecutor;

impl InferenceExecutor for StubExecutor {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn run(
        &self,
        _prompt: &str,
        _max_new_tokens: u32,
    ) -> Result<(String, ExecutorTelemetry), ExecutorError> {
        Err(ExecutorError::NotConfigured)
    }
}
