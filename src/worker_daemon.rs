//! Autonomous off-chain worker loop for settled `EnterpriseInference` demand.
//!
//! The daemon executes non-deterministic inference off-chain, then returns only a
//! deterministic `VerifyZkProof` claim to the L1 mempool.

use crate::ledger::{AiWorkloadTask, Ledger};
use crate::protocol::{AttestationV1, HybridSigV1, SignedTxEnvelopeV1, TxV1};
use crate::rest::RestState;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use std::time::Duration;

#[derive(Debug, Clone)]
struct InferenceRun {
    response: String,
    flops_u64: u64,
}

pub fn worker_daemon_mnemonic_from_env() -> Option<String> {
    ["TET_WORKER_MNEMONIC", "TET_WALLET_MNEMONIC"]
        .into_iter()
        .find_map(|name| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
}

fn daemon_enabled_from_env() -> bool {
    !matches!(
        std::env::var("TET_WORKER_DAEMON")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("0") | Some("false") | Some("FALSE") | Some("no") | Some("NO")
    )
}

fn poll_interval_from_env() -> Duration {
    let ms = std::env::var("TET_WORKER_DAEMON_POLL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(2_000)
        .max(250);
    Duration::from_millis(ms)
}

pub fn should_start_worker_daemon(ledger: &Ledger, worker_wallet: &str) -> bool {
    if !daemon_enabled_from_env() {
        return false;
    }
    if methods::NEXUS_GUEST_ELF.is_empty() {
        panic!(
            "CRITICAL ERROR: NEXUS_GUEST_ELF is empty! Do not use RISC0_SKIP_BUILD in production."
        );
    }
    if ledger
        .caac_get_worker_record(worker_wallet)
        .map(|rec| rec.role.trim().eq_ignore_ascii_case("POC"))
        .unwrap_or(false)
    {
        return true;
    }
    crate::vision::caac::profile().role == crate::vision::caac::NodeRelayRole::Poc
}

pub fn spawn_worker_daemon(
    state: RestState,
    worker_wallet: String,
    mnemonic: String,
) -> tokio::task::JoinHandle<()> {
    let poll_interval = poll_interval_from_env();
    tokio::spawn(async move {
        log::info!(
            "[worker-daemon] started wallet={} poll_ms={}",
            worker_wallet,
            poll_interval.as_millis()
        );
        loop {
            if let Err(e) = tick_worker_daemon(state.clone(), &worker_wallet, &mnemonic).await {
                log::warn!("[worker-daemon] tick failed: {e}");
            }
            tokio::time::sleep(poll_interval).await;
        }
    })
}

async fn tick_worker_daemon(
    state: RestState,
    worker_wallet: &str,
    mnemonic: &str,
) -> anyhow::Result<()> {
    let tasks = state.ledger.list_unprocessed_ai_workload_tasks(16)?;
    for task in tasks {
        if task.workload_flag != crate::protocol::WorkloadFlag::AiInference.as_u8() {
            continue;
        }
        if task.prompt.trim().is_empty() {
            log::warn!(
                "[worker-daemon] skipping task={} without persisted prompt",
                task.tx_hash
            );
            continue;
        }
        if mempool_has_task_claim(&state, &task.tx_hash).await {
            continue;
        }
        if state.ledger.ai_workload_is_processed(&task.tx_hash)? {
            continue;
        }

        let run = run_inference_for_task(&task).await?;
        let env = build_verify_zk_env_for_task(&task, &run, worker_wallet, mnemonic).await?;
        let should_enqueue = {
            let mp = state.mempool.lock().await;
            !mp.iter()
                .any(|existing| verify_zk_task_id(existing) == Some(task.tx_hash.as_str()))
        };
        if should_enqueue && let Err(e) = state.enqueue_mempool_tx(env).await {
            log::warn!(
                "[worker-daemon] mempool rejected VerifyZkProof task_id={} err={}",
                task.tx_hash,
                e
            );
            continue;
        }
        log::info!(
            "[worker-daemon] submitted VerifyZkProof task_id={} flops_u64={}",
            task.tx_hash,
            run.flops_u64
        );
    }
    Ok(())
}

async fn mempool_has_task_claim(state: &RestState, task_id: &str) -> bool {
    let mp = state.mempool.lock().await;
    mp.iter()
        .any(|env| verify_zk_task_id(env) == Some(task_id.trim()))
}

fn verify_zk_task_id(env: &SignedTxEnvelopeV1) -> Option<&str> {
    match &env.tx {
        TxV1::VerifyZkProof { task_id, .. } if !task_id.trim().is_empty() => Some(task_id.trim()),
        _ => None,
    }
}

async fn run_inference_for_task(task: &AiWorkloadTask) -> anyhow::Result<InferenceRun> {
    let metrics = crate::worker_engine::run_local_inference(&task.prompt)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "real inference failed for task_id={}: {e}; worker daemon does not use mock fallback",
                task.tx_hash
            )
        })?;
    Ok(InferenceRun {
        response: metrics.text,
        flops_u64: u128_to_u64_saturating(metrics.flops).max(1),
    })
}

#[cfg(test)]
fn dynamic_mock_flops(task: &AiWorkloadTask, worker_wallet: &str) -> u64 {
    use sha2::{Digest as _, Sha256};

    let mut h = Sha256::new();
    h.update(task.tx_hash.as_bytes());
    h.update(task.prompt.as_bytes());
    h.update(task.model.as_bytes());
    h.update(worker_wallet.as_bytes());
    let digest: [u8; 32] = h.finalize().into();
    let jitter = u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8])) % 500_000;
    let prompt_units = task.prompt.len().max(1) as u64;
    prompt_units
        .saturating_mul(1_000_000)
        .saturating_add(jitter)
        .max(1)
}

async fn build_verify_zk_env_for_task(
    task: &AiWorkloadTask,
    run: &InferenceRun,
    worker_wallet: &str,
    mnemonic: &str,
) -> anyhow::Result<SignedTxEnvelopeV1> {
    let worker_pubkey_bytes = wallet_hex_to_pk32(worker_wallet)?;
    let prompt = task.prompt.clone();
    let response = run.response.clone();
    let flops_u64 = run.flops_u64;
    let receipt = tokio::task::spawn_blocking(move || {
        prove_zk_court_task_receipt(&prompt, &response, flops_u64, worker_pubkey_bytes)
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking prover join failed: {e}"))??;

    let journal_bytes = receipt.journal.bytes.clone();
    let journal_b64 = base64::engine::general_purpose::STANDARD.encode(&journal_bytes);
    let receipt_bytes = bincode::serialize(&receipt)?;
    let receipt_b64 = base64::engine::general_purpose::STANDARD.encode(receipt_bytes);

    let verified = crate::zk_verifier::verify_tx_receipt_and_journal(
        methods::NEXUS_GUEST_ID,
        &journal_b64,
        &receipt_b64,
    )?;
    match verified {
        crate::zk_verifier::VerifiedZkJournal::ZkCourt(j)
            if j.flops_u64 == run.flops_u64 && j.worker_pubkey_bytes == worker_pubkey_bytes => {}
        crate::zk_verifier::VerifiedZkJournal::ZkCourt(_) => {
            return Err(anyhow::anyhow!(
                "real zk receipt journal mismatch for task_id={}",
                task.tx_hash
            ));
        }
        crate::zk_verifier::VerifiedZkJournal::Inference(_) => {
            return Err(anyhow::anyhow!(
                "worker daemon expected ZkCourtJournalV1 for task_id={}",
                task.tx_hash
            ));
        }
    }

    let tx = TxV1::VerifyZkProof {
        task_id: task.tx_hash.clone(),
        image_id: methods::NEXUS_GUEST_ID,
        journal_b64,
        receipt_b64,
    };
    sign_tx_with_mnemonic(tx, worker_wallet, mnemonic)
}

fn prove_zk_court_task_receipt(
    prompt: &str,
    response: &str,
    flops_u64: u64,
    worker_pubkey_bytes: [u8; 32],
) -> anyhow::Result<risc0_zkvm::Receipt> {
    use nexus_protocol::zk_court_inference_commitment_v1;
    use risc0_zkvm::{ExecutorEnv, default_prover};

    if methods::NEXUS_GUEST_ELF.is_empty() {
        panic!(
            "CRITICAL ERROR: NEXUS_GUEST_ELF is empty! Do not use RISC0_SKIP_BUILD in production."
        );
    }

    let commitment_sha256 =
        zk_court_inference_commitment_v1(prompt, response, flops_u64, &worker_pubkey_bytes);
    let env = ExecutorEnv::builder()
        .write(&1u8)?
        .write(&prompt.to_string())?
        .write(&response.to_string())?
        .write(&flops_u64)?
        .write(&worker_pubkey_bytes)?
        .write(&commitment_sha256)?
        .build()?;

    println!("Real ZK Proof Generation Started... (This may take a while)");
    let started = std::time::Instant::now();
    let receipt = default_prover()
        .prove(env, methods::NEXUS_GUEST_ELF)?
        .receipt;
    crate::metrics::add_zk_prover_millis(
        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    );
    println!("Real ZK Proof Generation Finished.");
    Ok(receipt)
}

fn sign_tx_with_mnemonic(
    tx: TxV1,
    worker_wallet: &str,
    mnemonic: &str,
) -> anyhow::Result<SignedTxEnvelopeV1> {
    let ed_sk = crate::wallet::ed25519_signing_key_from_mnemonic(mnemonic)
        .map_err(|e| anyhow::anyhow!("ed25519 key derivation failed: {e}"))?;
    let derived_wallet = hex::encode(ed_sk.verifying_key().to_bytes());
    let allow_alias = matches!(
        std::env::var("TET_WORKER_DAEMON_ALLOW_WALLET_ALIAS")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    );
    if derived_wallet != worker_wallet.trim().to_ascii_lowercase() && !allow_alias {
        return Err(anyhow::anyhow!(
            "worker mnemonic does not match worker wallet: derived={derived_wallet} configured={worker_wallet}"
        ));
    } else if derived_wallet != worker_wallet.trim().to_ascii_lowercase() {
        log::warn!(
            "[worker-daemon] wallet alias enabled: mnemonic derived wallet={} configured worker wallet={}",
            derived_wallet,
            worker_wallet
        );
    }
    let mldsa_kp = crate::wallet::mldsa_keypair_from_mnemonic(mnemonic)
        .map_err(|e| anyhow::anyhow!("mldsa key derivation failed: {e}"))?;
    let mldsa_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(mldsa_kp.public_key());
    let tx_bytes = crate::wallet::tx_v1_auth_message_bytes(&tx, &mldsa_pubkey_b64)
        .map_err(|e| anyhow::anyhow!("tx auth message failed: {e}"))?;
    let ed_sig = ed_sk.sign(tx_bytes.as_slice());
    let ed25519_sig_b64 =
        base64::engine::general_purpose::STANDARD.encode(ed_sig.to_bytes().as_slice());
    let mldsa_sig_bytes = crate::wallet::mldsa_sign_deterministic(&mldsa_kp, tx_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("mldsa sign failed: {e}"))?;
    let mldsa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&mldsa_sig_bytes);

    Ok(SignedTxEnvelopeV1 {
        v: 1,
        tx,
        sig: HybridSigV1 {
            ed25519_pubkey_hex: worker_wallet.trim().to_ascii_lowercase(),
            ed25519_sig_b64,
            mldsa_pubkey_b64,
            mldsa_sig_b64,
        },
        attestation: AttestationV1 {
            platform: "worker-daemon".to_string(),
            report_b64: String::new(),
        },
    })
}

fn wallet_hex_to_pk32(wallet: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(wallet.trim())?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("worker wallet must be 32-byte hex"))
}

fn u128_to_u64_saturating(v: u128) -> u64 {
    if v > u64::MAX as u128 {
        u64::MAX
    } else {
        v as u64
    }
}

#[allow(dead_code)]
#[cfg(test)]
pub fn dynamic_mock_flops_for_test(task: &AiWorkloadTask, worker_wallet: &str) -> u64 {
    dynamic_mock_flops(task, worker_wallet)
}

#[allow(dead_code)]
#[cfg(test)]
pub async fn build_verify_zk_env_for_task_for_test(
    task: &AiWorkloadTask,
    flops_u64: u64,
    worker_wallet: &str,
    mnemonic: &str,
) -> anyhow::Result<SignedTxEnvelopeV1> {
    let run = InferenceRun {
        response: "test response".to_string(),
        flops_u64,
    };
    build_verify_zk_env_for_task(task, &run, worker_wallet, mnemonic).await
}
