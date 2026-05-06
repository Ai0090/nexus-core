//! ZK-Court: challenge window + RISC Zero commitment proof + liquid slash on fraud verdict.

use crate::ledger::Ledger;
use nexus_protocol::{ZkCourtJournalV1, zk_court_inference_commitment_v1};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengePhase {
    None,
    ChallengeOpen,
    EvidencePending,
    SlashExecuted,
    Dismissed,
}

#[derive(Debug, Clone, Serialize)]
pub struct InferenceDisputeState {
    pub inference_id: String,
    pub worker_wallet_id: String,
    pub phase: ChallengePhase,
    pub challenge_opens_at_ms: u128,
    pub challenge_closes_at_ms: u128,
    pub lazy_eval_suspected: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChallengeSubmitReq {
    pub inference_id: String,
    pub challenger_wallet_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InferenceArtifact {
    pub prompt: String,
    pub response: String,
    pub flops_u64: u64,
    pub worker_wallet_id: String,
    pub commitment_sha256: [u8; 32],
    /// Expected worker-side pool credit from settlement (`pool_half`) — §13.1 **R_expected** for **S = λ × R_expected**.
    pub r_expected_micro: u64,
}

#[derive(Debug, Serialize)]
pub struct ChallengeOutcome {
    pub inference_id: String,
    pub verdict: &'static str,
    pub phase: ChallengePhase,
    pub zk_proof_ok: bool,
    pub host_commitment_match: bool,
    pub slash_micro: Option<u64>,
    pub detail: String,
}

fn challenge_window_ms() -> u128 {
    std::env::var("TET_ZK_COURT_CHALLENGE_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(86_400_000)
}

fn lambda_multiplier() -> u64 {
    std::env::var("TET_SLASH_LAMBDA_MULTIPLIER")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(100)
        .max(1)
}

fn prove_timeout_sec() -> u64 {
    std::env::var("TET_ZK_COURT_PROVE_TIMEOUT_SEC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120)
        .max(5)
}

static DISPUTES: Lazy<Mutex<HashMap<String, InferenceDisputeState>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static ARTIFACTS: Lazy<Mutex<HashMap<String, InferenceArtifact>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Serialize)]
pub struct ZkCourtPunishmentLogV1 {
    pub worker_id: String,
    pub punishment: String,
    pub offense: String,
    pub timestamp: String,
}

static ZK_COURT_LOGS: Lazy<Mutex<VecDeque<ZkCourtPunishmentLogV1>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(32)));

const ZK_COURT_LOG_CAP: usize = 256;

fn wallet_hex_to_pk32(wallet_hex: &str) -> Result<[u8; 32], String> {
    let w = wallet_hex.trim().to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("worker_wallet_id must be 64 hex chars".into());
    }
    let bytes = hex::decode(w.as_bytes()).map_err(|e| e.to_string())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "wallet id must be 32 bytes".into())
}

/// Record inference delivery + artifacts for later ZK-Court challenges.
pub fn record_inference_delivered_full(
    inference_id: &str,
    prompt: &str,
    response: &str,
    flops: u128,
    worker_wallet_id: &str,
    r_expected_micro: u64,
) {
    let flops_u64 = u64::try_from(flops.min(u128::from(u64::MAX))).unwrap_or(u64::MAX);
    let pk = match wallet_hex_to_pk32(worker_wallet_id) {
        Ok(v) => v,
        Err(_) => return,
    };
    let commitment = zk_court_inference_commitment_v1(prompt, response, flops_u64, &pk);
    let art = InferenceArtifact {
        prompt: prompt.to_string(),
        response: response.to_string(),
        flops_u64,
        worker_wallet_id: worker_wallet_id.trim().to_ascii_lowercase(),
        commitment_sha256: commitment,
        r_expected_micro,
    };
    let _ = ARTIFACTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(inference_id.to_string(), art);
    record_inference_delivered(inference_id, worker_wallet_id);
}

/// Opens challenge window (legacy single-arg wrapper calls this via full path from AI handler).
pub fn record_inference_delivered(inference_id: &str, worker_wallet_id: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let win = challenge_window_ms();
    let st = InferenceDisputeState {
        inference_id: inference_id.to_string(),
        worker_wallet_id: worker_wallet_id.trim().to_ascii_lowercase(),
        phase: ChallengePhase::ChallengeOpen,
        challenge_opens_at_ms: now,
        challenge_closes_at_ms: now.saturating_add(win),
        lazy_eval_suspected: false,
    };
    let _ = DISPUTES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(inference_id.to_string(), st);
}

pub fn list_open() -> Vec<InferenceDisputeState> {
    DISPUTES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .filter(|s| s.phase == ChallengePhase::ChallengeOpen)
        .cloned()
        .collect()
}

/// Prepare dispute state for proving (internal); prefer [`run_challenge_pipeline`].
pub fn submit_challenge(req: &ChallengeSubmitReq) -> Result<InferenceDisputeState, String> {
    let mut m = DISPUTES.lock().unwrap_or_else(|e| e.into_inner());
    let ent = m
        .get_mut(&req.inference_id)
        .ok_or_else(|| "unknown inference_id".to_string())?;
    if ent.phase != ChallengePhase::ChallengeOpen {
        return Err("challenge not open for this inference".into());
    }
    ent.phase = ChallengePhase::EvidencePending;
    ent.lazy_eval_suspected = true;
    Ok(ent.clone())
}

fn host_commitment_matches_artifact(art: &InferenceArtifact) -> bool {
    let Ok(pk) = wallet_hex_to_pk32(&art.worker_wallet_id) else {
        return false;
    };
    let h = zk_court_inference_commitment_v1(&art.prompt, &art.response, art.flops_u64, &pk);
    h == art.commitment_sha256
}

fn prove_zk_court_receipt(art: &InferenceArtifact) -> Result<risc0_zkvm::Receipt, anyhow::Error> {
    use risc0_zkvm::{ExecutorEnv, default_prover};

    if methods::NEXUS_GUEST_ELF.is_empty() {
        return Err(anyhow::anyhow!("guest ELF empty (RISC0_SKIP_BUILD?)"));
    }

    let env = ExecutorEnv::builder()
        .write(&1u8)?
        .write(&art.prompt)?
        .write(&art.response)?
        .write(&art.flops_u64)?
        .write(&wallet_hex_to_pk32(&art.worker_wallet_id).map_err(|e| anyhow::anyhow!(e))?)?
        .write(&art.commitment_sha256)?
        .build()?;

    let prover = default_prover();
    let info = prover.prove(env, methods::NEXUS_GUEST_ELF)?;
    Ok(info.receipt)
}

fn verify_zk_court_cryptographic(
    receipt: &risc0_zkvm::Receipt,
) -> anyhow::Result<ZkCourtJournalV1> {
    let image_id = methods::NEXUS_GUEST_ID;
    receipt
        .verify(image_id)
        .map_err(|e| anyhow::anyhow!("receipt.verify: {e:?}"))?;
    receipt
        .journal
        .decode::<ZkCourtJournalV1>()
        .map_err(|e| anyhow::anyhow!("journal decode: {e:?}"))
}

/// Full pipeline: prover + verify + dismissed vs guilty + optional ledger slash.
pub async fn run_challenge_pipeline(
    ledger: &Ledger,
    req: &ChallengeSubmitReq,
) -> Result<ChallengeOutcome, String> {
    submit_challenge(req)?;

    let art = ARTIFACTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&req.inference_id)
        .cloned()
        .ok_or_else(|| "no inference artifact (too old or not recorded)".to_string())?;

    let host_ok = host_commitment_matches_artifact(&art);
    let timeout = Duration::from_secs(prove_timeout_sec());

    let art_for_prove = art.clone();
    let join = tokio::task::spawn_blocking(move || prove_zk_court_receipt(&art_for_prove));
    let prove_res = tokio::time::timeout(timeout, join).await;

    let mut zk_ok = false;
    let mut zk_definitive_invalid = false;

    match prove_res {
        Err(_) => {
            log::warn!("[zk-court] prove timeout inference_id={}", req.inference_id);
        }
        Ok(Err(e)) => {
            log::warn!("[zk-court] join error: {e}");
        }
        Ok(Ok(Err(e))) => {
            log::warn!("[zk-court] prove failed: {e}");
        }
        Ok(Ok(Ok(receipt))) => {
            if let Ok(pk) = wallet_hex_to_pk32(&art.worker_wallet_id) {
                match verify_zk_court_cryptographic(&receipt) {
                    Ok(j) => {
                        zk_ok = j.commitment_sha256 == art.commitment_sha256
                            && j.worker_pubkey_bytes == pk
                            && j.flops_u64 == art.flops_u64;
                        // Definitive cryptographic evidence of fraud: receipt verifies, but journal mismatch.
                        zk_definitive_invalid = !zk_ok;
                    }
                    Err(e) => log::warn!("[zk-court] cryptographic verify failed: {e}"),
                }
            } else {
                log::warn!("[zk-court] bad worker id in artifact");
            }
        }
    }

    // IMPORTANT (mainnet safety): timeouts / prove failures / missing ELF are **never** treated as guilty.
    // We do NOT fall back to host-only acceptance for slashing decisions.

    // Guilty only when fraud is cryptographically proven (receipt verified but journal mismatch).
    let verdict_guilty = zk_definitive_invalid && host_ok;
    let verdict_dismissed = !verdict_guilty;

    let detail;
    let slash_micro;

    if verdict_dismissed {
        detail = if zk_ok && host_ok {
            "cryptographic proof + host transcript consistent — challenge dismissed".into()
        } else if !host_ok {
            "host commitment inconsistent with transcript — dismissed (no cryptographic fraud proof)".into()
        } else {
            "ZK proof unavailable/invalid/timeout — dismissed (no cryptographic fraud proof)".into()
        };
        slash_micro = None;
        let _ = apply_slash_verdict(ledger, &req.inference_id, false);
    } else {
        detail =
            "cryptographic fraud proven (receipt verified but journal mismatch) — guilty".into();
        slash_micro = Some(
            apply_slash_verdict(ledger, &req.inference_id, true).unwrap_or_else(|e| {
                log::error!("[zk-court] slash ledger hook: {e}");
                0
            }),
        );
    }

    let phase = DISPUTES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&req.inference_id)
        .map(|s| s.phase)
        .unwrap_or(ChallengePhase::None);

    Ok(ChallengeOutcome {
        inference_id: req.inference_id.clone(),
        verdict: if verdict_dismissed {
            "dismissed"
        } else {
            "guilty"
        },
        phase,
        zk_proof_ok: zk_ok,
        host_commitment_match: host_ok,
        slash_micro,
        detail,
    })
}

/// After verdict: `verified_fraud == false` → dismissed; `true` → slash worker liquid balance (burn).
pub fn apply_slash_verdict(
    ledger: &Ledger,
    inference_id: &str,
    verified_fraud: bool,
) -> Result<u64, String> {
    let worker = {
        let mut m = DISPUTES.lock().unwrap_or_else(|e| e.into_inner());
        let ent = m
            .get_mut(inference_id)
            .ok_or_else(|| "unknown inference_id".to_string())?;
        if verified_fraud {
            ent.phase = ChallengePhase::SlashExecuted;
        } else {
            ent.phase = ChallengePhase::Dismissed;
        }
        ent.worker_wallet_id.clone()
    };

    if !verified_fraud {
        return Ok(0);
    }

    let r_expected = ARTIFACTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(inference_id)
        .map(|a| a.r_expected_micro)
        .unwrap_or(0);

    let s = r_expected.saturating_mul(lambda_multiplier());
    if s == 0 {
        log::warn!(
            "[zk-court] slash amount S=0 (missing artifact or R_expected=0) inference_id={}",
            inference_id
        );
        return Ok(0);
    }

    match ledger.slash_wallet_liquid_burn_micro(&worker, s) {
        Ok(n) => Ok(n),
        Err(crate::ledger::LedgerError::InsufficientFunds) => {
            log::warn!(
                "[zk-court] slash: zero liquid balance wallet={} inference={}",
                worker,
                inference_id
            );
            Ok(0)
        }
        Err(e) => Err(e.to_string()),
    }
}

pub fn params_json() -> serde_json::Value {
    serde_json::json!({
        "challenge_window_ms": challenge_window_ms(),
        "slash_equation_v1": "S = lambda * R_expected (Stevemon micro); full liquid slash + burn",
        "lambda_multiplier_default": 100,
        "prove_timeout_sec": prove_timeout_sec(),
        "zkvm": "risc0_zkvm guest modes 0=inference journal 1=zk_court commitment",
        "optimistic_execution_v01": "POST /v1/vision/zk-court/verify-optimistic — dummy verify; bond slash uses slash_worker_bond_zk_court_burn_all",
        "env": {
            "TET_SLASH_LAMBDA_MULTIPLIER": "lambda (>=1, default 100) — §13.1 penalty S = lambda * R_expected_micro",
            "TET_ZK_COURT_PROVE_TIMEOUT_SEC": prove_timeout_sec(),
        },
    })
}

/// v0.1 placeholder for zkVM receipt verification (production: bind `commitment` + `proof` bytes).
/// Returns `false` when `proof` is empty or equals **`INVALID`** (simulated fraud for integration tests).
pub fn verify_optimistic_execution(worker_id: &str, commitment: &[u8], proof: &[u8]) -> bool {
    let _ = (worker_id, commitment);
    if proof.is_empty() || proof == b"INVALID" {
        return false;
    }
    true
}

fn now_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn timestamp_string() -> String {
    // v0.1: keep deps minimal. Return unix ms as a string.
    format!("{}", now_unix_ms())
}

pub fn push_zk_court_log(ent: ZkCourtPunishmentLogV1) {
    let mut g = ZK_COURT_LOGS.lock().unwrap_or_else(|e| e.into_inner());
    g.push_front(ent);
    while g.len() > ZK_COURT_LOG_CAP {
        g.pop_back();
    }
}

pub fn list_zk_court_logs() -> Vec<ZkCourtPunishmentLogV1> {
    ZK_COURT_LOGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect()
}

/// On failed optimistic verification: burn **entire** worker bond, remove from [`WorkerRegistry`], Oracle alert.
pub fn execute_optimistic_slash_if_fraud(
    ledger: &Ledger,
    workers: &std::sync::Mutex<crate::worker_network::WorkerRegistry>,
    worker_id: &str,
    commitment: &[u8],
    proof: &[u8],
) -> Result<Option<ZkCourtPunishmentLogV1>, String> {
    if verify_optimistic_execution(worker_id, commitment, proof) {
        return Ok(None);
    }
    let burned = ledger
        .slash_worker_bond_zk_court_burn_all(worker_id)
        .map_err(|e| e.to_string())?;
    {
        let mut w = workers.lock().unwrap_or_else(|e| e.into_inner());
        w.remove_wallet(worker_id);
    }
    let tet_burned = burned / crate::ledger::STEVEMON;
    let punishment = if burned == crate::ledger::MIN_WORKER_STAKE_MICRO {
        "1000 TET".to_string()
    } else {
        format!("{tet_burned} TET")
    };
    let offense = "Invalid Proof Submission".to_string();
    let out = ZkCourtPunishmentLogV1 {
        worker_id: worker_id.trim().to_string(),
        punishment,
        offense,
        timestamp: timestamp_string(),
    };
    log::error!(
        "[ZK-COURT] Worker {} SLASHED! {} Burned. offense={}",
        out.worker_id,
        out.punishment,
        out.offense
    );
    push_zk_court_log(out.clone());
    Ok(Some(out))
}
