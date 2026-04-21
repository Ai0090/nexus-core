//! Heavy local AI inference (Llama 3 8B Instruct GGUF) using Candle.
//!
//! This is the "no compromise" brain: quantized 4-bit GGUF (5GB+).
//! Download is **UI-driven** (visual consent) via REST endpoints:
//! - `GET /worker/model/status`
//! - `POST /worker/model/download`
//!
//! WARNING: This can consume multiple GB of RAM. We print a severe warning if free RAM < 8GB.

use anyhow::{Context as _, Result};
use candle_core as candle;
use candle_transformers::generation::{LogitsProcessor, Sampling};
use candle_transformers::models::quantized_llama as qllama;
use once_cell::sync::OnceCell;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;
use tokenizers::Tokenizer;

static MODEL_STATE: OnceCell<Mutex<ModelState>> = OnceCell::new();
static DOWNLOAD_STATE: OnceCell<tokio::sync::Mutex<ModelDownloadState>> = OnceCell::new();

struct ModelState {
    device: candle::Device,
    weights: qllama::ModelWeights,
    tokenizer: Tokenizer,
    eos_token: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelStatusV1 {
    pub v: u32,
    pub ready: bool,
    pub downloading: bool,
    pub model_repo: String,
    pub model_filename: String,
    pub model_path: String,
    pub tokenizer_repo: String,
    pub tokenizer_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    pub downloaded_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct ModelDownloadState {
    downloading: bool,
    total_bytes: Option<u64>,
    downloaded_bytes: u64,
    error: Option<String>,
}

fn warn_if_low_ram() {
    // sysinfo::System::available_memory is in KB.
    let mut sys = sysinfo::System::new_all();
    sys.refresh_memory();
    let avail_bytes = sys.available_memory().saturating_mul(1024);
    if avail_bytes < 8u64 * 1024 * 1024 * 1024 {
        eprintln!("===============================================================");
        eprintln!("INSUFFICIENT RAM FOR HIGH-TIER AI INFERENCE.");
        eprintln!("available_ram_gb≈{:.2}", avail_bytes as f64 / (1024.0 * 1024.0 * 1024.0));
        eprintln!("Proceeding anyway (use at your own risk).");
        eprintln!("===============================================================");
    }
}

fn model_repo() -> String {
    std::env::var("TET_HEAVY_MODEL_REPO")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "QuantFactory/Meta-Llama-3-8B-Instruct-GGUF".into())
}

fn model_filename() -> String {
    std::env::var("TET_HEAVY_MODEL_GGUF")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Meta-Llama-3-8B-Instruct-Q4_K_M.gguf".into())
}

fn tokenizer_repo() -> String {
    std::env::var("TET_HEAVY_TOKENIZER_REPO")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "meta-llama/Meta-Llama-3-8B".into())
}

fn model_dir() -> PathBuf {
    std::env::var("TET_HEAVY_MODEL_DIR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tet_models"))
}

fn model_path_on_disk() -> PathBuf {
    let dir = model_dir();
    dir.join(model_filename())
}

fn tokenizer_path_on_disk() -> PathBuf {
    let dir = model_dir();
    dir.join("tokenizer.json")
}

fn load_tokenizer_from_disk() -> Result<Tokenizer> {
    let tok_path = tokenizer_path_on_disk();
    Tokenizer::from_file(&tok_path)
        .map_err(|e| anyhow::anyhow!("tokenizer load: {e}"))
        .with_context(|| format!("tokenizer missing at {:?}", tok_path))
}

fn load_model_gguf_from_disk() -> Result<(qllama::ModelWeights, PathBuf)> {
    warn_if_low_ram();
    let model_path = model_path_on_disk();
    if !model_path.exists() {
        return Err(anyhow::anyhow!(
            "AI Brain model not downloaded yet (missing file: {:?})",
            model_path
        ));
    }

    let mut file = std::fs::File::open(&model_path).with_context(|| format!("open {model_path:?}"))?;
    let content =
        candle::quantized::gguf_file::Content::read(&mut file).with_context(|| "read gguf")?;

    // Use CPU by default; Candle will use Metal/CUDA if compiled with feature and device is selected.
    let device = candle::Device::Cpu;
    let weights = qllama::ModelWeights::from_gguf(content, &mut file, &device)
        .with_context(|| "build quantized llama weights from gguf")?;
    Ok((weights, model_path))
}

fn init_state() -> Result<ModelState> {
    // Device selection: allow forcing CPU for stability.
    let force_cpu = std::env::var("TET_HEAVY_AI_CPU")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let device = if force_cpu {
        candle::Device::Cpu
    } else {
        // Prefer Metal on macOS when candle-core is built with metal; otherwise CPU.
        // If unavailable, this call will fall back to CPU by returning an error; we stay conservative.
        candle::Device::Cpu
    };

    let tokenizer = load_tokenizer_from_disk()?;
    let (weights, _path) = load_model_gguf_from_disk()?;

    // Llama 3 eos token id.
    let eos = tokenizer
        .get_vocab(true)
        .get("<|end_of_text|>")
        .copied()
        .unwrap_or(128001);

    Ok(ModelState {
        device,
        weights,
        tokenizer,
        eos_token: eos,
    })
}

fn state() -> Result<std::sync::MutexGuard<'static, ModelState>> {
    let m = MODEL_STATE.get_or_try_init(|| -> Result<Mutex<ModelState>> {
        Ok(Mutex::new(init_state()?))
    })?;
    m.lock().map_err(|_| anyhow::anyhow!("AI model mutex poisoned"))
}

fn download_state() -> &'static tokio::sync::Mutex<ModelDownloadState> {
    DOWNLOAD_STATE.get_or_init(|| tokio::sync::Mutex::new(ModelDownloadState::default()))
}

pub async fn model_status_v1() -> ModelStatusV1 {
    let st = download_state().lock().await.clone();
    let model_path = model_path_on_disk();
    let tok_path = tokenizer_path_on_disk();
    let model_ok = model_path.exists();
    let tok_ok = tok_path.exists();
    let ready = model_ok && tok_ok && !st.downloading && st.error.is_none();
    let downloaded_bytes = std::fs::metadata(&model_path).map(|m| m.len()).unwrap_or(0);
    ModelStatusV1 {
        v: 1,
        ready,
        downloading: st.downloading,
        model_repo: model_repo(),
        model_filename: model_filename(),
        model_path: model_path.to_string_lossy().to_string(),
        tokenizer_repo: tokenizer_repo(),
        tokenizer_path: tok_path.to_string_lossy().to_string(),
        total_bytes: st.total_bytes,
        downloaded_bytes: if st.downloading { st.downloaded_bytes } else { downloaded_bytes.max(st.downloaded_bytes) },
        error: st.error,
    }
}

fn hf_resolve_url(repo: &str, filename: &str) -> String {
    // Resolve from main branch by default.
    format!("https://huggingface.co/{repo}/resolve/main/{filename}")
}

async fn head_content_length(url: &str) -> Option<u64> {
    let client = reqwest::Client::new();
    let resp = client.head(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

async fn download_to_path_with_progress(url: &str, dst: &PathBuf) -> Result<()> {
    use futures::StreamExt;
    let client = reqwest::Client::builder()
        .tcp_keepalive(Some(std::time::Duration::from_secs(30)))
        .build()
        .context("reqwest client build")?;
    let resp = client.get(url).send().await.context("download GET")?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("download failed HTTP {}", resp.status()));
    }
    let parent = dst.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    tokio::fs::create_dir_all(&parent).await.ok();
    let tmp = dst.with_extension("partial");
    let mut file = tokio::fs::File::create(&tmp).await.context("create partial file")?;
    let mut stream = resp.bytes_stream();
    while let Some(item) = stream.next().await {
        let bytes = item.context("stream read")?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &bytes)
            .await
            .context("write chunk")?;
        let mut st = download_state().lock().await;
        st.downloaded_bytes = st.downloaded_bytes.saturating_add(bytes.len() as u64);
    }
    tokio::io::AsyncWriteExt::flush(&mut file).await.ok();
    drop(file);
    tokio::fs::rename(&tmp, dst).await.context("rename partial->final")?;
    Ok(())
}

pub async fn start_model_download() -> Result<()> {
    {
        let mut st = download_state().lock().await;
        if st.downloading {
            return Ok(());
        }
        st.downloading = true;
        st.downloaded_bytes = 0;
        st.total_bytes = None;
        st.error = None;
    }

    let repo = model_repo();
    let filename = model_filename();
    let tok_repo = tokenizer_repo();
    let model_url = hf_resolve_url(&repo, &filename);
    let tok_url = hf_resolve_url(&tok_repo, "tokenizer.json");

    let model_dst = model_path_on_disk();
    let tok_dst = tokenizer_path_on_disk();

    // Best-effort total bytes for progress bar (model dominates).
    let total = head_content_length(&model_url).await;
    {
        let mut st = download_state().lock().await;
        st.total_bytes = total;
    }

    // Download tokenizer first (small), then model (huge).
    if let Err(e) = download_to_path_with_progress(&tok_url, &tok_dst).await {
        let mut st = download_state().lock().await;
        st.downloading = false;
        st.error = Some(format!("tokenizer download failed: {e}"));
        return Err(e);
    }
    if let Err(e) = download_to_path_with_progress(&model_url, &model_dst).await {
        let mut st = download_state().lock().await;
        st.downloading = false;
        st.error = Some(format!("model download failed: {e}"));
        return Err(e);
    }

    let mut st = download_state().lock().await;
    st.downloading = false;
    st.error = None;
    Ok(())
}

/// Run heavy local inference (Llama 3 8B Instruct Q4_K_M GGUF).
///
/// This is intentionally synchronous and CPU-safe for MVP. For high throughput, run in a dedicated worker process.
pub fn run_local_inference(prompt: &str) -> Result<String> {
    let prompt = prompt.trim();
    if prompt.is_empty() {
        return Ok(String::new());
    }

    let mut st = state()?;
    let t0 = Instant::now();

    // Chat-style wrapper (minimal).
    let rendered = format!(
        "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n{prompt}\n<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
    );
    let enc = st
        .tokenizer
        .encode(rendered, true)
        .map_err(|e| anyhow::anyhow!("tokenize: {e}"))?;
    let prompt_tokens = enc.get_ids();
    if prompt_tokens.is_empty() {
        return Ok(String::new());
    }

    // Generation parameters (env-overridable).
    let sample_len = std::env::var("TET_HEAVY_SAMPLE_LEN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256)
        .clamp(8, 2048);
    let temperature = std::env::var("TET_HEAVY_TEMPERATURE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.8)
        .clamp(0.0, 2.0);
    let seed = std::env::var("TET_HEAVY_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(299792458);

    let mut logits = LogitsProcessor::from_sampling(
        seed,
        if temperature <= 0.0 {
            Sampling::ArgMax
        } else {
            Sampling::All { temperature }
        },
    );

    // We re-create a token output stream by decoding tokens at the end (fast enough).
    let mut all = Vec::<u32>::new();

    // Prompt pass.
    let input = candle::Tensor::new(prompt_tokens, &st.device)?
        .to_dtype(candle::DType::U32)?
        .unsqueeze(0)?;
    let mut next = {
        let lg = st.weights.forward(&input, 0)?;
        let lg = lg.squeeze(0)?;
        logits.sample(&lg)? as u32
    };
    all.push(next);

    // Autoregressive loop.
    for i in 0..sample_len.saturating_sub(1) {
        if next == st.eos_token {
            break;
        }
        let input = candle::Tensor::new(&[next], &st.device)?
            .to_dtype(candle::DType::U32)?
            .unsqueeze(0)?;
        let lg = st.weights.forward(&input, prompt_tokens.len() + i)?;
        let lg = lg.squeeze(0)?;
        next = logits.sample(&lg)? as u32;
        all.push(next);
    }

    // Decode: tokenizers can decode ids directly.
    let text = st
        .tokenizer
        .decode(&all, true)
        .map_err(|e| anyhow::anyhow!("decode: {e}"))?;

    let dt = t0.elapsed().as_millis();
    eprintln!("[heavy-ai] generated_tokens={} elapsed_ms={dt}", all.len());
    Ok(text)
}

