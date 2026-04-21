//! Local AI inference (text-in / text-out) with Proof-of-Compute metadata.
//!
//! Priority:
//! 1. `TET_AI_CMD` — runs `sh -c "$TET_AI_CMD"` with stdin = UTF-8 input (explicit override; non-empty only).
//! 2. **Heavy local inference** — Candle quantized Llama 3 8B instruct GGUF via `worker_ai::run_local_inference`.
//!    Downloads the model on first run. Prints a severe warning if free RAM < 8GB, but proceeds.
//! 3. **Ollama** fallback — `POST` to `TET_OLLAMA_URL` (default `http://127.0.0.1:11434/api/generate`), model from
//!    `TET_OLLAMA_MODEL` (default `llama3`), timeout `TET_OLLAMA_TIMEOUT_SECS` (default 120).
//! 4. Deterministic `tet_worker::poc_infer` only if everything else fails (last resort).

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::io::Write as _;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
pub struct AiInferProofV1 {
    pub v: u32,
    pub model: String,
    pub output_sha256_hex: String,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiInferResultV1 {
    pub v: u32,
    pub model: String,
    pub output_text: String,
    pub proof: AiInferProofV1,
}

fn output_sha256(model: &str, text: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"tet-ai-out:v1");
    h.update(model.as_bytes());
    h.update([0u8]);
    h.update(text.as_bytes());
    hex::encode(h.finalize())
}

fn run_ai_cmd(cmd: &str, input: &str) -> Result<String, std::io::Error> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn ollama_url() -> String {
    std::env::var("TET_OLLAMA_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11434/api/generate".into())
}

fn ollama_model_name() -> String {
    std::env::var("TET_OLLAMA_MODEL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "llama3".into())
}

fn ollama_timeout() -> Duration {
    let sec = std::env::var("TET_OLLAMA_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s > 0 && s <= 3600)
        .unwrap_or(120);
    Duration::from_secs(sec)
}

/// Returns generated text, or error (connection / HTTP / JSON).
fn try_ollama_generate(prompt: &str) -> Result<String, String> {
    let url = ollama_url();
    let model = ollama_model_name();
    let body = serde_json::json!({
        "model": model,
        "prompt": prompt,
        "stream": false,
    });

    let resp = ureq::post(&url)
        .timeout(ollama_timeout())
        .send_json(body)
        .map_err(|e| e.to_string())?;

    if !(200..300).contains(&resp.status()) {
        return Err(format!("ollama HTTP {}", resp.status()));
    }

    let v: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
    let text = v
        .get("response")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    Ok(text)
}

fn ollama_or_poc(model: &str, input: &str) -> (String, String) {
    match try_ollama_generate(input) {
        Ok(t) => (t, ollama_model_name()),
        Err(_) => {
            eprintln!("[Worker] Ollama not found. Falling back to PoC simulation.");
            (crate::tet_worker::poc_infer(input), model.to_string())
        }
    }
}

pub fn infer_text(model: &str, input: &str) -> AiInferResultV1 {
    let t0 = Instant::now();

    let (output_text, proof_model): (String, String) =
        if let Ok(cmd) = std::env::var("TET_AI_CMD") {
            let cmd = cmd.trim();
            if !cmd.is_empty() {
                (
                    run_ai_cmd(cmd, input).unwrap_or_else(|_| crate::tet_worker::poc_infer(input)),
                    model.to_string(),
                )
            } else {
                // Heavy AI first. If it fails (model download, OOM, etc.), fall back.
                match crate::worker_ai::run_local_inference(input) {
                    Ok(out) => (out, "llama3-8b-instruct-gguf-q4".into()),
                    Err(e) => {
                        eprintln!("[Worker] Heavy AI inference failed: {e}. Falling back to Ollama/PoC.");
                        ollama_or_poc(model, input)
                    }
                }
            }
        } else {
            match crate::worker_ai::run_local_inference(input) {
                Ok(out) => (out, "llama3-8b-instruct-gguf-q4".into()),
                Err(e) => {
                    eprintln!("[Worker] Heavy AI inference failed: {e}. Falling back to Ollama/PoC.");
                    ollama_or_poc(model, input)
                }
            }
        };

    let elapsed_ms = t0.elapsed().as_millis();
    let osh = output_sha256(&proof_model, &output_text);
    AiInferResultV1 {
        v: 1,
        model: proof_model.clone(),
        output_text,
        proof: AiInferProofV1 {
            v: 1,
            model: proof_model,
            output_sha256_hex: osh,
            elapsed_ms,
        },
    }
}
