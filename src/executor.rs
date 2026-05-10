//! Inference executor boundary.
//!
//! All real AI execution paths should enter through [`InferenceExecutor`]. Phase 1 wires the
//! production path to a local Ollama runtime; later backends (GGUF/Candle/Metal/CUDA) can implement
//! the same boundary without touching worker routing or settlement code.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

pub type ExecutorFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct InferenceRequest<'a> {
    pub prompt: &'a str,
    pub model: &'a str,
    pub max_new_tokens: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorTelemetry {
    pub v: u32,
    pub engine: String,
    pub model: String,
    pub wall_ms: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

#[derive(Debug, Clone)]
pub struct InferenceOutput {
    pub text: String,
    pub telemetry: ExecutorTelemetry,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("executor not configured")]
    NotConfigured,
    #[error("model not available")]
    ModelUnavailable,
    #[error("backend error: {0}")]
    Backend(String),
}

pub trait InferenceExecutor: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn run<'a>(
        &'a self,
        req: InferenceRequest<'a>,
    ) -> ExecutorFuture<'a, Result<InferenceOutput, ExecutorError>>;
}

pub fn configured_default_model() -> Option<String> {
    ["TET_DEFAULT_MODEL", "TET_OLLAMA_MODEL"]
        .into_iter()
        .find_map(|name| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
}

pub fn resolve_model_name(requested: &str) -> Result<String, ExecutorError> {
    let m = requested.trim();
    if !m.is_empty() {
        return Ok(m.to_string());
    }
    configured_default_model().ok_or(ExecutorError::ModelUnavailable)
}

fn ollama_base_url() -> String {
    std::env::var("TET_OLLAMA_URL_BASE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11434".into())
}

fn ollama_timeout() -> Duration {
    let sec = std::env::var("TET_OLLAMA_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0 && s <= 3600)
        .unwrap_or(120);
    Duration::from_secs(sec)
}

#[derive(Debug, Clone)]
pub struct OllamaExecutor {
    base_url: String,
    timeout: Duration,
}

impl OllamaExecutor {
    pub fn from_env() -> Self {
        Self {
            base_url: ollama_base_url(),
            timeout: ollama_timeout(),
        }
    }

    fn generate_url(&self) -> String {
        format!("{}/api/generate", self.base_url.trim_end_matches('/'))
    }
}

#[derive(Debug, Serialize)]
struct OllamaGenerateReq<'a> {
    model: &'a str,
    prompt: &'a str,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
}

#[derive(Debug, Serialize)]
struct OllamaOptions {
    num_predict: u32,
}

#[derive(Debug, Deserialize)]
struct OllamaGenerateResp {
    response: Option<String>,
    eval_count: Option<u64>,
    prompt_eval_count: Option<u64>,
    eval_duration: Option<u64>,
}

impl InferenceExecutor for OllamaExecutor {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn run<'a>(
        &'a self,
        req: InferenceRequest<'a>,
    ) -> ExecutorFuture<'a, Result<InferenceOutput, ExecutorError>> {
        Box::pin(async move {
            let prompt = req.prompt.trim();
            if prompt.is_empty() {
                return Err(ExecutorError::Backend("prompt required".into()));
            }
            let model = resolve_model_name(req.model)?;
            let client = reqwest::Client::builder()
                .timeout(self.timeout)
                .build()
                .map_err(|e| ExecutorError::Backend(e.to_string()))?;
            let body = OllamaGenerateReq {
                model: &model,
                prompt,
                stream: false,
                options: req.max_new_tokens.map(|num_predict| OllamaOptions { num_predict }),
            };
            let started = Instant::now();
            let resp = client
                .post(self.generate_url())
                .json(&body)
                .send()
                .await
                .map_err(|e| ExecutorError::Backend(format!("ollama POST failed: {e}")))?;
            let status = resp.status();
            let raw = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                return Err(ExecutorError::Backend(format!(
                    "ollama HTTP {}: {}",
                    status.as_u16(),
                    raw.trim()
                )));
            }
            let out: OllamaGenerateResp =
                serde_json::from_str(&raw).context("ollama JSON decode failed")
                    .map_err(|e| ExecutorError::Backend(e.to_string()))?;
            let text = out.response.unwrap_or_default().trim().to_string();
            let prompt_tokens = out.prompt_eval_count.unwrap_or_else(|| {
                let est = (prompt.len().saturating_add(3)) / 4;
                est.max(1) as u64
            });
            let completion_tokens = out.eval_count.unwrap_or(0);
            let wall_ms = out
                .eval_duration
                .map(|ns| ns / 1_000_000)
                .unwrap_or_else(|| started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            Ok(InferenceOutput {
                text,
                telemetry: ExecutorTelemetry {
                    v: 1,
                    engine: self.name().to_string(),
                    model,
                    wall_ms,
                    prompt_tokens,
                    completion_tokens,
                },
            })
        })
    }
}

pub fn default_executor() -> OllamaExecutor {
    OllamaExecutor::from_env()
}

/// Stub: used until llama.cpp/candle integration is wired into this slim repo snapshot.
pub struct StubExecutor;

impl InferenceExecutor for StubExecutor {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn run<'a>(
        &'a self,
        _req: InferenceRequest<'a>,
    ) -> ExecutorFuture<'a, Result<InferenceOutput, ExecutorError>> {
        Box::pin(async { Err(ExecutorError::NotConfigured) })
    }
}
