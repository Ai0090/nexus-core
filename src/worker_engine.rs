//! Local worker execution engine (Phase 1).
//!
//! Real inference via the unified executor boundary and Stevemon / FLOPs accounting.

use crate::ai_filter::{ContentFilter as _, FilterStage};
use crate::executor::InferenceExecutor as _;
use anyhow::anyhow;
use base64::Engine as _;
use nexus_protocol::InferenceJournalV1;
use tokio::task;

/// Metrics returned after a successful local inference run.
#[derive(Debug, Clone)]
pub struct LocalInferenceMetrics {
    pub text: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// `(prompt_tokens + completion_tokens) * difficulty` (floor).
    pub flops: u128,
    /// Rough energy accountability from FLOPs (override via `TET_JOULES_PER_FLOP` × Wh scaling).
    pub energy_wh: f64,
    /// Cost in smallest Stevemon units (Stevemon “micro”).
    pub cost_micro: u64,
    /// Legacy telemetry: ~1000 tokens per NCU (whitepaper reference task).
    pub ncu: f64,
}

fn env_u128(name: &str, default: u128) -> u128 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(default)
        .max(1)
}

/// Run a real local inference via the configured executor.
pub async fn run_local_inference(prompt: &str, model: &str) -> anyhow::Result<LocalInferenceMetrics> {
    let p = prompt.trim();
    if p.is_empty() {
        return Err(anyhow!("prompt required"));
    }
    let model = crate::executor::resolve_model_name(model)
        .map_err(|e| anyhow!("model unavailable: {e}"))?;

    // Phase 4.1: Node Operator Defense (SAFE MODE content filtering).
    if crate::worker_config::safe_mode() {
        let f = crate::ai_filter::default_filter();
        if let Some(d) = f.check(FilterStage::Prompt, p) {
            log::warn!(
                "[safe_mode][block] stage=prompt sha256={} reason={}",
                d.text_sha256_hex,
                d.reason
            );
            return Err(anyhow!(
                "TET_ERR_SAFE_MODE: Prompt blocked by node operator policy."
            ));
        }
    }

    let exec = crate::executor::default_executor();
    let out = exec
        .run(crate::executor::InferenceRequest {
            prompt: p,
            model: &model,
            max_new_tokens: None,
        })
        .await
        .map_err(|e| anyhow!("{} executor failed for model={}: {e}", exec.name(), model))?;
    let text = out.text.trim().to_string();

    if crate::worker_config::safe_mode() {
        let f = crate::ai_filter::default_filter();
        if let Some(d) = f.check(FilterStage::Output, &text) {
            log::warn!(
                "[safe_mode][block] stage=output sha256={} reason={}",
                d.text_sha256_hex,
                d.reason
            );
            return Err(anyhow!(
                "TET_ERR_SAFE_MODE: Output blocked by node operator policy."
            ));
        }
    }

    let completion_tokens = out.telemetry.completion_tokens;
    let prompt_tokens = out.telemetry.prompt_tokens;

    let difficulty = env_u128("TET_MODEL_DIFFICULTY_FLOPS_PER_TOKEN", 1_000_000);
    let tok_sum = (prompt_tokens as u128).saturating_add(completion_tokens as u128);
    let flops = tok_sum.saturating_mul(difficulty);

    // Reference: 3.6e12 J per kWh → Wh = J / 3.6e9.
    let joules_per_flop = crate::vision::thermo_genesis::env_joules_per_flop();
    let energy_wh = (flops as f64 * joules_per_flop) / 3.6e9_f64;

    let gamma = crate::vision::thermo_genesis::NetworkDifficulty::from_env();
    let cost_micro = crate::vision::thermo_genesis::discrete_thermodynamic_reward_stevemon_micro(
        flops,
        joules_per_flop,
        gamma,
    )
    .max(1);

    let ncu = (prompt_tokens.saturating_add(completion_tokens) as f64) / 1000.0;

    Ok(LocalInferenceMetrics {
        text,
        prompt_tokens,
        completion_tokens,
        flops,
        energy_wh,
        cost_micro,
        ncu,
    })
}

fn mock_receipt_b64(
    prompt: &str,
    response: &str,
    worker_pubkey_bytes: [u8; 32],
    cost_micro: u64,
) -> anyhow::Result<String> {
    use sha2::{Digest as _, Sha256};
    let prompt_hash: [u8; 32] = Sha256::digest(prompt.as_bytes()).into();
    let response_hash: [u8; 32] = Sha256::digest(response.as_bytes()).into();
    let j = InferenceJournalV1 {
        worker_pubkey_bytes,
        prompt_hash,
        response_hash,
        cost_micro,
    };
    let bytes = bincode::serialize(&j)?;
    Ok(format!(
        "MOCKJ1:{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

pub async fn generate_receipt_b64(
    prompt: &str,
    response: &str,
    worker_pubkey_bytes: [u8; 32],
    cost_micro: u64,
) -> anyhow::Result<String> {
    // If prover is disabled, run optimistic mode with a mock journal receipt.
    if !crate::worker_config::enable_zk_prover() {
        return mock_receipt_b64(prompt, response, worker_pubkey_bytes, cost_micro);
    }

    // Dev safety: when guest is unavailable (e.g. RISC0_SKIP_BUILD=1), fall back to mock.
    if methods::NEXUS_GUEST_ELF.is_empty() {
        return mock_receipt_b64(prompt, response, worker_pubkey_bytes, cost_micro);
    }

    let p = prompt.to_string();
    let r = response.to_string();
    // Proving is heavy and blocking; never run on the async reactor.
    task::spawn_blocking(move || prove_prompt_response(&p, &r, worker_pubkey_bytes, cost_micro))
        .await
        .map_err(|e| anyhow!("spawn_blocking prover join failed: {e}"))?
}

#[cfg(feature = "zk-prove")]
pub fn prove_prompt_response(
    prompt: &str,
    response: &str,
    worker_pubkey_bytes: [u8; 32],
    _cost_micro: u64,
) -> anyhow::Result<String> {
    use risc0_zkvm::{ExecutorEnv, default_prover};

    if methods::NEXUS_GUEST_ELF.is_empty() {
        return mock_receipt_b64(prompt, response, worker_pubkey_bytes, _cost_micro);
    }
    let env = ExecutorEnv::builder()
        .write(&0u8)?
        .write(&prompt.to_string())?
        .write(&response.to_string())?
        .write(&worker_pubkey_bytes)?
        .build()?;
    let prover = default_prover();
    let receipt = prover.prove(env, methods::NEXUS_GUEST_ELF)?.receipt;
    let bytes = bincode::serialize(&receipt)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

#[cfg(not(feature = "zk-prove"))]
pub fn prove_prompt_response(
    prompt: &str,
    response: &str,
    worker_pubkey_bytes: [u8; 32],
    cost_micro: u64,
) -> anyhow::Result<String> {
    // Lightweight dev path when prover feature isn't compiled in.
    mock_receipt_b64(prompt, response, worker_pubkey_bytes, cost_micro)
}
