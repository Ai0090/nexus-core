use crate::ledger::{BlockRecordV1, BlockRewardRecordV1, CaacWorkerRecord, Ledger, STEVEMON};
use crate::models::NetworkEvent;
use crate::protocol::{SignedTxEnvelopeV1, TxV1, WorkloadFlag};
use crate::rest::RestState;
use crate::rest::helpers::verify_envelope_v1;
use crate::vision::thermo_genesis::{
    NetworkDifficulty, discrete_thermodynamic_reward_stevemon_micro, env_joules_per_flop,
};
use crate::zk_verifier::VerifiedZkJournal;
use sha2::Digest as _;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct MineOutcome {
    pub mined: bool,
    pub block_height: u64,
    pub block_id: String,
    pub producer_id: String,
    pub state_root: String,
    pub tx_hashes: Vec<String>,
    pub tx_count: usize,
    pub reward: BlockRewardBreakdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRewardBreakdown {
    pub base_reward_micro: u64,
    pub compute_reward_micro: u64,
    pub total_reward_micro: u64,
}

#[derive(Debug, Clone)]
pub enum MineError {
    Unauthorized(String),
    BadRequest(String),
}

impl MineError {
    pub fn message(&self) -> &str {
        match self {
            Self::Unauthorized(msg) | Self::BadRequest(msg) => msg,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RemoteBlockApplyOutcome {
    Applied {
        block_height: u64,
        tx_count: usize,
        evicted_count: usize,
        state_root: String,
    },
    ForkLost {
        reason: String,
    },
    Skipped {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub enum RemoteBlockApplyError {
    Rejected(String),
    Ledger(String),
}

#[derive(Debug, Clone)]
pub struct RemoteBlockGossip {
    pub block_height: u64,
    pub block_id: String,
    pub parent_block_id: Option<String>,
    pub producer_id: String,
    pub base_reward_micro: u64,
    pub compute_reward_micro: u64,
    pub total_reward_micro: u64,
    pub state_root: String,
    pub txs: Vec<SignedTxEnvelopeV1>,
}

impl RemoteBlockApplyError {
    pub fn message(&self) -> &str {
        match self {
            Self::Rejected(msg) | Self::Ledger(msg) => msg,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConsensusIdentity(String);

impl ConsensusIdentity {
    pub fn new(id: impl Into<String>) -> Option<Self> {
        let id = id.into().trim().to_ascii_lowercase();
        if id.is_empty() { None } else { Some(Self(id)) }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<ConsensusIdentity>,
}

impl ValidatorSet {
    pub fn new<I, S>(ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut validators: Vec<ConsensusIdentity> =
            ids.into_iter().filter_map(ConsensusIdentity::new).collect();
        validators.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        validators.dedup_by(|a, b| a.as_str() == b.as_str());
        Self { validators }
    }

    pub fn from_env_or_single(local_node_id: &str) -> Self {
        let ids = std::env::var("TET_VALIDATOR_IDS")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|ids| !ids.is_empty())
            .unwrap_or_else(|| vec![local_node_id.to_string()]);
        Self::new(ids)
    }

    pub fn validators(&self) -> &[ConsensusIdentity] {
        &self.validators
    }

    pub fn contains(&self, id: &str) -> bool {
        let Some(id) = ConsensusIdentity::new(id) else {
            return false;
        };
        self.validators.iter().any(|v| v == &id)
    }
}

pub trait LeaderElection {
    fn leader_for_height(
        &self,
        height: u64,
        validators: &ValidatorSet,
    ) -> Option<ConsensusIdentity>;

    fn is_leader(&self, height: u64, local_node_id: &str, validators: &ValidatorSet) -> bool {
        let local = local_node_id.trim().to_ascii_lowercase();
        self.leader_for_height(height, validators)
            .map(|leader| leader.as_str() == local)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HashLeaderElection;

impl LeaderElection for HashLeaderElection {
    fn leader_for_height(
        &self,
        height: u64,
        validators: &ValidatorSet,
    ) -> Option<ConsensusIdentity> {
        validators
            .validators()
            .iter()
            .min_by(|a, b| leader_score(height, a.as_str()).cmp(&leader_score(height, b.as_str())))
            .cloned()
    }
}

pub trait CaacWeightProvider {
    fn consensus_weight(&self, validator_id: &str) -> u64;
}

#[derive(Clone)]
pub struct LedgerCaacWeightProvider {
    ledger: Arc<Ledger>,
}

impl LedgerCaacWeightProvider {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }
}

impl CaacWeightProvider for LedgerCaacWeightProvider {
    fn consensus_weight(&self, validator_id: &str) -> u64 {
        let rec = self.ledger.caac_get_worker_record(validator_id);
        caac_weight_from_record(rec.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct StaticCaacWeightProvider {
    weights: std::collections::HashMap<String, u64>,
}

impl StaticCaacWeightProvider {
    pub fn new<I, S>(weights: I) -> Self
    where
        I: IntoIterator<Item = (S, u64)>,
        S: Into<String>,
    {
        Self {
            weights: weights
                .into_iter()
                .filter_map(|(id, weight)| {
                    ConsensusIdentity::new(id).map(|id| (id.as_str().to_string(), weight.max(1)))
                })
                .collect(),
        }
    }
}

impl CaacWeightProvider for StaticCaacWeightProvider {
    fn consensus_weight(&self, validator_id: &str) -> u64 {
        ConsensusIdentity::new(validator_id)
            .and_then(|id| self.weights.get(id.as_str()).copied())
            .unwrap_or(CAAC_UNREGISTERED_WEIGHT)
    }
}

#[derive(Debug, Clone)]
pub struct CaacLeaderElection<P> {
    weight_provider: P,
}

impl<P> CaacLeaderElection<P> {
    pub fn new(weight_provider: P) -> Self {
        Self { weight_provider }
    }
}

impl<P: CaacWeightProvider> LeaderElection for CaacLeaderElection<P> {
    fn leader_for_height(
        &self,
        height: u64,
        validators: &ValidatorSet,
    ) -> Option<ConsensusIdentity> {
        validators
            .validators()
            .iter()
            .min_by(|a, b| {
                let aw = self.weight_provider.consensus_weight(a.as_str());
                let bw = self.weight_provider.consensus_weight(b.as_str());
                weighted_score(height, a.as_str(), aw)
                    .cmp(&weighted_score(height, b.as_str(), bw))
                    .then_with(|| a.as_str().cmp(b.as_str()))
            })
            .cloned()
    }
}

const CAAC_POC_BASE_WEIGHT: u64 = 100;
const CAAC_POR_BASE_WEIGHT: u64 = 25;
const CAAC_UNREGISTERED_WEIGHT: u64 = 10;

pub fn caac_weight_from_record(rec: Option<&CaacWorkerRecord>) -> u64 {
    let Some(rec) = rec else {
        return CAAC_UNREGISTERED_WEIGHT;
    };
    let base = match rec.role.trim().to_ascii_uppercase().as_str() {
        "POC" => CAAC_POC_BASE_WEIGHT,
        "POR" => CAAC_POR_BASE_WEIGHT,
        _ => CAAC_UNREGISTERED_WEIGHT,
    };
    let latency_score = (1000 / rec.latency_ms.max(1)).clamp(1, 1000);
    let server_penalty = if rec.server_wall_ms > 1000 { 2 } else { 1 };
    base.saturating_add(latency_score / server_penalty).max(1)
}

pub fn weighted_score(height: u64, validator_id: &str, weight: u64) -> u64 {
    let score = leader_score(height, validator_id);
    let mut first = [0u8; 8];
    first.copy_from_slice(&score[..8]);
    u64::from_be_bytes(first) / weight.max(1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderElectionMode {
    Hash,
    Caac,
}

pub fn leader_election_mode_from_env() -> LeaderElectionMode {
    match std::env::var("TET_CONSENSUS_LEADER_MODE") {
        Ok(v) if v.trim().eq_ignore_ascii_case("caac") => LeaderElectionMode::Caac,
        _ => LeaderElectionMode::Hash,
    }
}

pub fn leader_for_height_with_mode(
    height: u64,
    validators: &ValidatorSet,
    mode: LeaderElectionMode,
    ledger: Arc<Ledger>,
) -> Option<ConsensusIdentity> {
    match mode {
        LeaderElectionMode::Hash => HashLeaderElection.leader_for_height(height, validators),
        LeaderElectionMode::Caac => CaacLeaderElection::new(LedgerCaacWeightProvider::new(ledger))
            .leader_for_height(height, validators),
    }
}

pub fn is_leader_with_mode(
    height: u64,
    local_node_id: &str,
    validators: &ValidatorSet,
    mode: LeaderElectionMode,
    ledger: Arc<Ledger>,
) -> bool {
    let local = local_node_id.trim().to_ascii_lowercase();
    leader_for_height_with_mode(height, validators, mode, ledger)
        .map(|leader| leader.as_str() == local)
        .unwrap_or(false)
}

fn leader_score(height: u64, validator_id: &str) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(height.to_be_bytes());
    h.update(validator_id.as_bytes());
    h.finalize().into()
}

pub fn local_node_id_from_env() -> String {
    std::env::var("TET_WALLET_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("TET_PEER_ID")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "local-wallet".to_string())
        .trim()
        .to_ascii_lowercase()
}

pub fn remote_wins_fork(local_block_id: &str, remote_block_id: &str) -> bool {
    remote_block_id < local_block_id
}

pub fn tx_hash_for_env(env: &SignedTxEnvelopeV1) -> Result<String, String> {
    let tx_bytes = verify_envelope_v1(env)?;
    Ok(format!(
        "0x{}",
        hex::encode(sha2::Sha256::digest(&tx_bytes))
    ))
}

pub fn block_id_for_hashes(tx_hashes: &[String]) -> String {
    format!(
        "0x{}",
        hex::encode(sha2::Sha256::digest(tx_hashes.join(",").as_bytes()))
    )
}

pub fn block_id_for_block(block_height: u64, tx_hashes: &[String]) -> String {
    let payload = format!("{block_height}:{}", tx_hashes.join(","));
    format!(
        "0x{}",
        hex::encode(sha2::Sha256::digest(payload.as_bytes()))
    )
}

pub fn block_contains_ai_workload(txs: &[SignedTxEnvelopeV1]) -> bool {
    txs.iter().any(|env| env.tx.is_ai_workload())
}

pub fn producer_can_mine_ai_workload(ledger: &Ledger, producer_id: &str) -> bool {
    ledger
        .caac_get_worker_record(producer_id)
        .map(|rec| rec.role.trim().eq_ignore_ascii_case("POC"))
        .unwrap_or(false)
}

pub fn validate_enterprise_inference_tx(tx: &TxV1) -> Result<(), String> {
    let TxV1::EnterpriseInference {
        enterprise_wallet_id,
        prompt,
        model: _,
        amount_micro,
        nonce,
        prompt_sha256_hex,
        workload_flag,
        attestation_required: _,
    } = tx
    else {
        return Err("expected enterprise_inference tx".to_string());
    };
    let wallet = enterprise_wallet_id.trim().to_ascii_lowercase();
    if wallet.len() != 64 || !wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("enterprise_wallet_id must be 64 hex characters".to_string());
    }
    if prompt.trim().is_empty() {
        return Err("prompt required".to_string());
    }
    if *nonce == 0 {
        return Err("nonce required".to_string());
    }
    if *amount_micro == 0 || *amount_micro > crate::ledger::MAX_SUPPLY_MICRO {
        return Err("invalid amount_micro".to_string());
    }
    if *workload_flag != WorkloadFlag::AiInference.as_u8() {
        return Err("enterprise_inference requires workload_flag=1".to_string());
    }
    let prompt_hash = hex::encode(sha2::Sha256::digest(prompt.trim().as_bytes()));
    if prompt_hash != prompt_sha256_hex.trim().to_ascii_lowercase() {
        return Err("prompt does not match prompt_sha256_hex".to_string());
    }
    Ok(())
}

pub fn base_block_reward_micro_from_env() -> u64 {
    parse_tet_amount_to_micro(
        std::env::var("TET_BASE_BLOCK_REWARD")
            .ok()
            .as_deref()
            .unwrap_or("0.1"),
    )
    .unwrap_or(STEVEMON / 10)
}

fn parse_tet_amount_to_micro(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() || s.starts_with('-') {
        return None;
    }
    let mut parts = s.split('.');
    let whole = parts.next()?.parse::<u64>().ok()?;
    let frac = parts.next().unwrap_or("");
    if parts.next().is_some() || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut frac_padded = frac.chars().take(6).collect::<String>();
    while frac_padded.len() < 6 {
        frac_padded.push('0');
    }
    let frac_micro = if frac_padded.is_empty() {
        0
    } else {
        frac_padded.parse::<u64>().ok()?
    };
    whole
        .checked_mul(STEVEMON)
        .and_then(|v| v.checked_add(frac_micro))
}

pub fn compute_reward_for_block(txs: &[SignedTxEnvelopeV1]) -> Result<u64, String> {
    let mut flops_sum: u128 = 0;
    for env in txs {
        match &env.tx {
            TxV1::Transfer { .. } => {}
            TxV1::VerifyZkProof {
                task_id: _,
                image_id,
                journal_b64,
                receipt_b64,
            } => {
                let journal = crate::zk_verifier::verify_tx_receipt_and_journal(
                    *image_id,
                    journal_b64,
                    receipt_b64,
                )
                .map_err(|e| e.to_string())?;
                if let VerifiedZkJournal::ZkCourt(j) = journal {
                    flops_sum = flops_sum.saturating_add(j.flops_u64 as u128);
                }
            }
            TxV1::EnterpriseInference { .. } => validate_enterprise_inference_tx(&env.tx)?,
            _ => {
                return Err("unsupported tx in block reward calculation".to_string());
            }
        }
    }

    if flops_sum == 0 {
        return Ok(0);
    }
    Ok(discrete_thermodynamic_reward_stevemon_micro(
        flops_sum,
        env_joules_per_flop(),
        NetworkDifficulty::from_env(),
    ))
}

pub fn reward_for_block(txs: &[SignedTxEnvelopeV1]) -> Result<BlockRewardBreakdown, String> {
    let base_reward_micro = base_block_reward_micro_from_env();
    let compute_reward_micro = compute_reward_for_block(txs)?;
    Ok(BlockRewardBreakdown {
        base_reward_micro,
        compute_reward_micro,
        total_reward_micro: base_reward_micro.saturating_add(compute_reward_micro),
    })
}

fn schedule_history_prune(ledger: Arc<Ledger>, block_height: u64) {
    let every = std::env::var("TET_PRUNE_EVERY_BLOCKS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(16);
    if !block_height.is_multiple_of(every) {
        return;
    }
    tokio::spawn(async move {
        match tokio::task::spawn_blocking(move || ledger.prune_history_after_block(block_height))
            .await
        {
            Ok(Ok((undo_removed, audit_removed))) if undo_removed > 0 || audit_removed > 0 => {
                log::info!(
                    "[ledger-prune] height={} block_undo_removed={} audit_removed={}",
                    block_height,
                    undo_removed,
                    audit_removed
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => log::warn!("[ledger-prune] failed at height={block_height}: {e}"),
            Err(e) => log::warn!("[ledger-prune] join failed at height={block_height}: {e}"),
        }
    });
}

fn validate_zk_task_claims(ledger: &Ledger, txs: &[SignedTxEnvelopeV1]) -> Result<(), String> {
    let mut seen_task_ids = HashSet::<String>::new();
    for env in txs {
        let TxV1::VerifyZkProof {
            task_id,
            image_id,
            journal_b64,
            receipt_b64,
        } = &env.tx
        else {
            continue;
        };
        let journal = match crate::zk_verifier::verify_tx_receipt_and_journal(
            *image_id,
            journal_b64,
            receipt_b64,
        ) {
            Ok(j) => j,
            Err(e) => {
                let worker = env.sig.ed25519_pubkey_hex.trim().to_ascii_lowercase();
                let slashed = ledger
                    .slash_worker_bond_to_ecosystem_all(&worker)
                    .unwrap_or(0);
                log::error!(
                    "[zk-slash] invalid receipt in block candidate worker={} slashed_micro={} err={}",
                    worker,
                    slashed,
                    e
                );
                return Err(e.to_string());
            }
        };
        if !matches!(journal, VerifiedZkJournal::ZkCourt(_)) {
            continue;
        }
        let task_id = task_id.trim();
        if task_id.is_empty() {
            return Err("zk court proof requires task_id".to_string());
        }
        if !seen_task_ids.insert(task_id.to_string()) {
            return Err(format!("duplicate zk proof task_id in block: {task_id}"));
        }
        let Some(task) = ledger
            .ai_workload_task(task_id)
            .map_err(|e| e.to_string())?
        else {
            return Err(format!("zk proof references unknown task_id: {task_id}"));
        };
        if task.processed {
            return Err(format!(
                "zk proof references already processed task_id: {task_id}"
            ));
        }
    }
    Ok(())
}

pub fn auto_mine_enabled_from_env() -> bool {
    matches!(
        std::env::var("TET_AUTO_MINE")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

pub fn block_time_from_env() -> Duration {
    let sec = std::env::var("TET_BLOCK_TIME_SEC")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(10)
        .max(1);
    Duration::from_secs(sec)
}

pub fn spawn_auto_miner(
    state: RestState,
    local_node_id: String,
    validator_set: ValidatorSet,
) -> tokio::task::JoinHandle<()> {
    let block_time = block_time_from_env();
    tokio::spawn(async move {
        log::info!(
            "[consensus] auto-mining enabled block_time_sec={} node_id={}",
            block_time.as_secs(),
            local_node_id
        );
        let election = HashLeaderElection;
        let leader_mode = leader_election_mode_from_env();
        loop {
            tokio::time::sleep(block_time).await;
            let next_height = state.ledger.block_height().unwrap_or(0).saturating_add(1);
            let is_leader = match leader_mode {
                LeaderElectionMode::Hash => {
                    election.is_leader(next_height, &local_node_id, &validator_set)
                }
                LeaderElectionMode::Caac => is_leader_with_mode(
                    next_height,
                    &local_node_id,
                    &validator_set,
                    leader_mode,
                    state.ledger.clone(),
                ),
            };
            if !is_leader {
                log::info!(
                    "[consensus] auto-mine skipped: node_id={} is not leader for height={} mode={:?}",
                    local_node_id,
                    next_height,
                    leader_mode
                );
                continue;
            }

            let has_ai_workload = {
                let mp = state.mempool.lock().await;
                block_contains_ai_workload(&mp)
            };
            if has_ai_workload && !producer_can_mine_ai_workload(&state.ledger, &local_node_id) {
                log::info!(
                    "[consensus] auto-mine routing: node_id={} is not POC; preserving AI workload mempool and mining coinbase-only block",
                    local_node_id
                );
                match mine_coinbase_only_block_as(state.clone(), local_node_id.clone()).await {
                    Ok(outcome) if outcome.mined => {
                        log::info!(
                            "[consensus] auto-mined coinbase-only block height={} producer_id={} reward_micro={} state_root={}",
                            outcome.block_height,
                            outcome.producer_id,
                            outcome.reward.total_reward_micro,
                            outcome.state_root
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!(
                            "[consensus] auto-mine coinbase-only failed: {}",
                            e.message()
                        );
                        println!("[CONSENSUS] Auto-mine failed: {}", e.message());
                    }
                }
                continue;
            }

            match mine_pending_block_as(state.clone(), local_node_id.clone()).await {
                Ok(outcome) if outcome.mined => {
                    log::info!(
                        "[consensus] auto-mined block height={} producer_id={} tx_count={} reward_micro={} state_root={}",
                        outcome.block_height,
                        outcome.producer_id,
                        outcome.tx_count,
                        outcome.reward.total_reward_micro,
                        outcome.state_root
                    );
                    println!(
                        "[CONSENSUS] Auto-mined block height={} producer_id={} tx_count={} reward_micro={} state_root={}",
                        outcome.block_height,
                        outcome.producer_id,
                        outcome.tx_count,
                        outcome.reward.total_reward_micro,
                        outcome.state_root
                    );
                }
                Ok(_) => {
                    log::debug!("[consensus] auto-mine tick: mempool empty");
                }
                Err(e) => {
                    log::warn!("[consensus] auto-mine failed: {}", e.message());
                    println!("[CONSENSUS] Auto-mine failed: {}", e.message());
                }
            }
        }
    })
}

pub async fn mine_pending_block(state: RestState) -> Result<MineOutcome, MineError> {
    mine_pending_block_as(state, local_node_id_from_env()).await
}

fn caac_block_weight(ledger: &Ledger, producer_id: &str) -> u64 {
    let rec = ledger.caac_get_worker_record(producer_id);
    caac_weight_from_record(rec.as_ref()).max(1)
}

fn parent_block_id_for_height(ledger: &Ledger, height: u64) -> Result<Option<String>, String> {
    if height <= 1 {
        return Ok(None);
    }
    ledger
        .canonical_block_id_at_height(height.saturating_sub(1))
        .map_err(|e| e.to_string())
}

fn cumulative_weight_for_block(
    ledger: &Ledger,
    parent_block_id: Option<&str>,
    caac_weight: u64,
) -> Result<u128, String> {
    let parent_weight = match parent_block_id {
        Some(parent_id) => ledger
            .block_record_by_id(parent_id)
            .map_err(|e| e.to_string())?
            .map(|b| b.cumulative_weight)
            .unwrap_or(0),
        None => 0,
    };
    Ok(parent_weight.saturating_add(u128::from(caac_weight.max(1))))
}

struct RecordBlockArgs<'a> {
    block_height: u64,
    block_id: &'a str,
    parent_block_id: Option<String>,
    producer_id: &'a str,
    tx_hashes: &'a [String],
    txs: &'a [SignedTxEnvelopeV1],
    state_root: &'a str,
    reward: BlockRewardBreakdown,
    canonical: bool,
}

fn record_block_record(ledger: &Ledger, args: RecordBlockArgs<'_>) -> Result<(), String> {
    let parent_block_id = match args.parent_block_id {
        Some(parent) => Some(parent),
        None => parent_block_id_for_height(ledger, args.block_height)?,
    };
    let caac_weight = caac_block_weight(ledger, args.producer_id);
    let cumulative_weight =
        cumulative_weight_for_block(ledger, parent_block_id.as_deref(), caac_weight)?;
    let row = BlockRecordV1 {
        v: 1,
        height: args.block_height,
        block_id: args.block_id.to_string(),
        parent_block_id,
        producer_id: args.producer_id.to_string(),
        tx_hashes: args.tx_hashes.to_vec(),
        txs: args.txs.to_vec(),
        state_root: args.state_root.to_string(),
        reward: BlockRewardRecordV1 {
            base_reward_micro: args.reward.base_reward_micro,
            compute_reward_micro: args.reward.compute_reward_micro,
            total_reward_micro: args.reward.total_reward_micro,
        },
        caac_weight,
        cumulative_weight,
        canonical: args.canonical,
        ts_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    };
    ledger.record_block_record(&row).map_err(|e| e.to_string())
}

pub fn validate_and_record_backfill_candidate(
    ledger: &Ledger,
    block: RemoteBlockGossip,
) -> Result<BlockRecordV1, RemoteBlockApplyError> {
    let RemoteBlockGossip {
        block_height,
        block_id,
        parent_block_id,
        producer_id,
        base_reward_micro,
        compute_reward_micro,
        total_reward_micro,
        state_root,
        txs,
    } = block;
    let producer_id = ConsensusIdentity::new(producer_id)
        .ok_or_else(|| RemoteBlockApplyError::Rejected("producer_id required".to_string()))?;
    let local_node_id = local_node_id_from_env();
    let validator_set = ValidatorSet::from_env_or_single(&local_node_id);
    if !validator_set.contains(producer_id.as_str()) {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "producer_id is not in validator set: {}",
            producer_id.as_str()
        )));
    }
    let leader_mode = leader_election_mode_from_env();
    let expected_leader = leader_for_height_with_mode(
        block_height,
        &validator_set,
        leader_mode,
        Arc::new(ledger.clone()),
    )
    .ok_or_else(|| RemoteBlockApplyError::Rejected("validator set is empty".to_string()))?;
    if expected_leader != producer_id {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "invalid leader for height={} expected={} received={}",
            block_height,
            expected_leader.as_str(),
            producer_id.as_str()
        )));
    }

    let mut tx_hashes = Vec::with_capacity(txs.len());
    let mut seen = HashSet::with_capacity(txs.len());
    for env in &txs {
        let tx_hash = tx_hash_for_env(env).map_err(RemoteBlockApplyError::Rejected)?;
        if !seen.insert(tx_hash.clone()) {
            return Err(RemoteBlockApplyError::Rejected(format!(
                "duplicate tx in block: {tx_hash}"
            )));
        }
        tx_hashes.push(tx_hash);
    }
    let expected_block_id = block_id_for_block(block_height, &tx_hashes);
    if expected_block_id != block_id {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "block_id mismatch expected={expected_block_id} received={block_id}"
        )));
    }
    if block_contains_ai_workload(&txs)
        && !producer_can_mine_ai_workload(ledger, producer_id.as_str())
    {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "producer_id={} is not POC for AI workload",
            producer_id.as_str()
        )));
    }
    validate_zk_task_claims(ledger, &txs).map_err(RemoteBlockApplyError::Rejected)?;
    let reward = reward_for_block(&txs).map_err(RemoteBlockApplyError::Rejected)?;
    if reward.base_reward_micro != base_reward_micro
        || reward.compute_reward_micro != compute_reward_micro
        || reward.total_reward_micro != total_reward_micro
    {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "block reward mismatch expected=({},{},{}) received=({},{},{})",
            reward.base_reward_micro,
            reward.compute_reward_micro,
            reward.total_reward_micro,
            base_reward_micro,
            compute_reward_micro,
            total_reward_micro
        )));
    }

    record_block_record(
        ledger,
        RecordBlockArgs {
            block_height,
            block_id: &block_id,
            parent_block_id: parent_block_id.clone(),
            producer_id: producer_id.as_str(),
            tx_hashes: &tx_hashes,
            txs: &txs,
            state_root: &state_root,
            reward,
            canonical: false,
        },
    )
    .map_err(RemoteBlockApplyError::Ledger)?;
    ledger
        .block_record_by_id(&block_id)
        .map_err(|e| RemoteBlockApplyError::Ledger(e.to_string()))?
        .ok_or_else(|| RemoteBlockApplyError::Ledger(format!("stored block not found: {block_id}")))
}

fn ancestor_ids_from_tip(ledger: &Ledger, tip_id: &str) -> Result<HashSet<String>, String> {
    let mut out = HashSet::new();
    let mut cur = Some(tip_id.trim().to_string());
    while let Some(id) = cur {
        if !out.insert(id.clone()) {
            break;
        }
        cur = ledger
            .block_record_by_id(&id)
            .map_err(|e| e.to_string())?
            .and_then(|b| b.parent_block_id);
    }
    Ok(out)
}

pub fn find_common_ancestor(ledger: &Ledger, new_tip_id: &str) -> Result<Option<String>, String> {
    let Some(tip) = ledger.chain_tip().map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let current_ancestors = ancestor_ids_from_tip(ledger, &tip.block_id)?;
    let mut cur = Some(new_tip_id.trim().to_string());
    while let Some(id) = cur {
        if current_ancestors.contains(&id) {
            return Ok(Some(id));
        }
        cur = ledger
            .block_record_by_id(&id)
            .map_err(|e| e.to_string())?
            .and_then(|b| b.parent_block_id);
    }
    // Both branches ultimately descend from genesis. Genesis itself is not a stored block record.
    Ok(Some(String::new()))
}

fn branch_from_ancestor_to_tip(
    ledger: &Ledger,
    ancestor_id: &str,
    new_tip_id: &str,
) -> Result<Vec<BlockRecordV1>, String> {
    let mut rev = Vec::new();
    let mut cur = Some(new_tip_id.trim().to_string());
    while let Some(id) = cur {
        if id == ancestor_id {
            break;
        }
        let block = ledger
            .block_record_by_id(&id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("unknown block in branch: {id}"))?;
        cur = block.parent_block_id.clone();
        rev.push(block);
    }
    rev.reverse();
    Ok(rev)
}

fn apply_block_record_forward(ledger: &Ledger, block: &BlockRecordV1) -> Result<(), String> {
    let reward = BlockRewardBreakdown {
        base_reward_micro: block.reward.base_reward_micro,
        compute_reward_micro: block.reward.compute_reward_micro,
        total_reward_micro: block.reward.total_reward_micro,
    };
    validate_zk_task_claims(ledger, &block.txs)?;
    let expected_reward = reward_for_block(&block.txs)?;
    if expected_reward.base_reward_micro != reward.base_reward_micro
        || expected_reward.compute_reward_micro != reward.compute_reward_micro
        || expected_reward.total_reward_micro != reward.total_reward_micro
    {
        return Err(format!("reorg reward mismatch block={}", block.block_id));
    }

    let undo = ledger
        .prepare_block_undo(
            &block.block_id,
            block.height,
            &block.txs,
            &block.tx_hashes,
            &block.producer_id,
            reward.total_reward_micro,
        )
        .map_err(|e| e.to_string())?;
    ledger.store_block_undo(&undo).map_err(|e| e.to_string())?;

    let actual_root = ledger
        .apply_consensus_block_batch(
            block.height,
            &block.txs,
            &block.tx_hashes,
            &block.producer_id,
            reward.total_reward_micro,
        )
        .map_err(|e| e.to_string())?;
    if actual_root != block.state_root {
        return Err(format!(
            "reorg state_root mismatch block={} expected={} actual={}",
            block.block_id, block.state_root, actual_root
        ));
    }
    ledger
        .record_block_summary(
            block.height,
            &block.block_id,
            &block.state_root,
            block.txs.len() as u64,
        )
        .map_err(|e| e.to_string())?;
    let mut canonical = block.clone();
    canonical.canonical = true;
    ledger
        .record_block_record(&canonical)
        .map_err(|e| e.to_string())?;
    ledger
        .record_tx_indexes_batch(block.height, &block.tx_hashes, &block.txs, true)
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn reorg_to_branch(ledger: &Ledger, new_tip_id: &str) -> Result<bool, String> {
    let Some(current_tip) = ledger.chain_tip().map_err(|e| e.to_string())? else {
        return Ok(false);
    };
    let new_tip = ledger
        .block_record_by_id(new_tip_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("unknown new tip: {new_tip_id}"))?;
    if new_tip.cumulative_weight <= current_tip.cumulative_weight {
        return Ok(false);
    }
    let ancestor = find_common_ancestor(ledger, &new_tip.block_id)?
        .ok_or_else(|| "no common ancestor found".to_string())?;
    let branch = branch_from_ancestor_to_tip(ledger, &ancestor, &new_tip.block_id)?;

    let mut cur = Some(current_tip.block_id.clone());
    while let Some(id) = cur {
        if id == ancestor {
            break;
        }
        let block = ledger
            .block_record_by_id(&id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("missing canonical block during unwind: {id}"))?;
        let parent = block.parent_block_id.clone();
        ledger.apply_block_undo(&id).map_err(|e| e.to_string())?;
        ledger
            .set_block_record_canonical(&id, false)
            .map_err(|e| e.to_string())?;
        ledger
            .record_tx_indexes_batch(block.height, &block.tx_hashes, &block.txs, false)
            .map_err(|e| e.to_string())?;
        cur = parent;
    }

    for block in branch {
        apply_block_record_forward(ledger, &block)?;
    }
    Ok(true)
}

pub fn try_reorg_backfilled_branch(ledger: &Ledger, new_tip_id: &str) -> Result<bool, String> {
    let Some(_) = ledger
        .block_record_by_id(new_tip_id)
        .map_err(|e| e.to_string())?
    else {
        return Ok(false);
    };
    if ledger.chain_tip().map_err(|e| e.to_string())?.is_none() {
        return Ok(false);
    }
    let ancestor = match find_common_ancestor(ledger, new_tip_id)? {
        Some(id) => id,
        None => return Ok(false),
    };
    let branch = branch_from_ancestor_to_tip(ledger, &ancestor, new_tip_id)?;
    for block in branch {
        let caac_weight = caac_block_weight(ledger, &block.producer_id);
        let cumulative_weight =
            cumulative_weight_for_block(ledger, block.parent_block_id.as_deref(), caac_weight)?;
        let mut updated = block;
        updated.caac_weight = caac_weight;
        updated.cumulative_weight = cumulative_weight;
        updated.canonical = false;
        ledger
            .record_block_record(&updated)
            .map_err(|e| e.to_string())?;
    }
    reorg_to_branch(ledger, new_tip_id)
}

async fn mine_coinbase_only_block_as(
    state: RestState,
    producer_id: String,
) -> Result<MineOutcome, MineError> {
    let producer_id = ConsensusIdentity::new(producer_id)
        .map(|id| id.as_str().to_string())
        .unwrap_or_else(local_node_id_from_env);
    let txs: Vec<SignedTxEnvelopeV1> = Vec::new();
    let tx_hashes: Vec<String> = Vec::new();
    let next_height = state.ledger.block_height().unwrap_or(0).saturating_add(1);
    let block_id = block_id_for_block(next_height, &tx_hashes);
    let reward = reward_for_block(&txs).map_err(MineError::Unauthorized)?;
    let undo = state
        .ledger
        .prepare_block_undo(
            &block_id,
            next_height,
            &txs,
            &tx_hashes,
            &producer_id,
            reward.total_reward_micro,
        )
        .map_err(|e| MineError::BadRequest(e.to_string()))?;
    state
        .ledger
        .store_block_undo(&undo)
        .map_err(|e| MineError::BadRequest(e.to_string()))?;
    let block_height = next_height;
    let state_root = state
        .ledger
        .apply_consensus_block_batch(
            block_height,
            &txs,
            &tx_hashes,
            &producer_id,
            reward.total_reward_micro,
        )
        .map_err(|e| MineError::BadRequest(e.to_string()))?;
    let _ = state
        .ledger
        .record_block_summary(block_height, &block_id, &state_root, 0);
    let _ = record_block_record(
        &state.ledger,
        RecordBlockArgs {
            block_height,
            block_id: &block_id,
            parent_block_id: None,
            producer_id: &producer_id,
            tx_hashes: &tx_hashes,
            txs: &txs,
            state_root: &state_root,
            reward,
            canonical: true,
        },
    );
    schedule_history_prune(state.ledger.clone(), block_height);

    if let Some(tx) = state.gossip_tx.clone() {
        let ev = NetworkEvent::BlockMined {
            block_height,
            block_id: block_id.clone(),
            parent_block_id: parent_block_id_for_height(&state.ledger, block_height)
                .ok()
                .flatten(),
            producer_id: producer_id.clone(),
            base_reward_micro: reward.base_reward_micro,
            compute_reward_micro: reward.compute_reward_micro,
            total_reward_micro: reward.total_reward_micro,
            state_root: state_root.clone(),
            txs,
        };
        if let Ok(json) = serde_json::to_string(&ev) {
            let _ = tx.send(json).await;
        }
    }

    Ok(MineOutcome {
        mined: true,
        block_height,
        block_id,
        producer_id,
        state_root,
        tx_hashes,
        tx_count: 0,
        reward,
    })
}

pub async fn mine_pending_block_as(
    state: RestState,
    producer_id: String,
) -> Result<MineOutcome, MineError> {
    let producer_id = ConsensusIdentity::new(producer_id)
        .map(|id| id.as_str().to_string())
        .unwrap_or_else(local_node_id_from_env);
    let txs = {
        let mut mp = state.mempool.lock().await;
        if block_contains_ai_workload(&mp)
            && !producer_can_mine_ai_workload(&state.ledger, &producer_id)
        {
            return Err(MineError::Unauthorized(format!(
                "producer_id={} is not POC for AI workload",
                producer_id
            )));
        }
        std::mem::take(&mut *mp)
    };

    let tx_hashes: Vec<String> = txs
        .iter()
        .map(tx_hash_for_env)
        .collect::<Result<Vec<_>, _>>()
        .map_err(MineError::Unauthorized)?;
    let next_height = state.ledger.block_height().unwrap_or(0).saturating_add(1);
    let block_id = block_id_for_block(next_height, &tx_hashes);
    validate_zk_task_claims(&state.ledger, &txs).map_err(MineError::Unauthorized)?;
    let reward = reward_for_block(&txs).map_err(MineError::Unauthorized)?;
    state
        .ledger
        .compute_state_root_after_remote_block(&txs, &producer_id, reward.total_reward_micro)
        .map_err(|e| MineError::BadRequest(e.to_string()))?;
    let undo = state
        .ledger
        .prepare_block_undo(
            &block_id,
            next_height,
            &txs,
            &tx_hashes,
            &producer_id,
            reward.total_reward_micro,
        )
        .map_err(|e| MineError::BadRequest(e.to_string()))?;
    state
        .ledger
        .store_block_undo(&undo)
        .map_err(|e| MineError::BadRequest(e.to_string()))?;

    let block_height = next_height;
    let state_root = state
        .ledger
        .apply_consensus_block_batch(
            block_height,
            &txs,
            &tx_hashes,
            &producer_id,
            reward.total_reward_micro,
        )
        .map_err(|e| MineError::BadRequest(e.to_string()))?;

    let _ =
        state
            .ledger
            .record_block_summary(block_height, &block_id, &state_root, txs.len() as u64);
    let _ = record_block_record(
        &state.ledger,
        RecordBlockArgs {
            block_height,
            block_id: &block_id,
            parent_block_id: None,
            producer_id: &producer_id,
            tx_hashes: &tx_hashes,
            txs: &txs,
            state_root: &state_root,
            reward,
            canonical: true,
        },
    );
    let _ = state
        .ledger
        .record_tx_indexes_batch(block_height, &tx_hashes, &txs, true);
    schedule_history_prune(state.ledger.clone(), block_height);

    if let Some(tx) = state.gossip_tx.clone() {
        let ev = NetworkEvent::BlockMined {
            block_height,
            block_id: block_id.clone(),
            parent_block_id: parent_block_id_for_height(&state.ledger, block_height)
                .ok()
                .flatten(),
            producer_id: producer_id.clone(),
            base_reward_micro: reward.base_reward_micro,
            compute_reward_micro: reward.compute_reward_micro,
            total_reward_micro: reward.total_reward_micro,
            state_root: state_root.clone(),
            txs: txs.clone(),
        };
        if let Ok(json) = serde_json::to_string(&ev) {
            let _ = tx.send(json).await;
        }
    }

    Ok(MineOutcome {
        mined: true,
        block_height,
        block_id,
        producer_id,
        state_root,
        tx_hashes,
        tx_count: txs.len(),
        reward,
    })
}

pub async fn apply_remote_block_from_gossip(
    ledger: Arc<Ledger>,
    mempool: Arc<Mutex<Vec<SignedTxEnvelopeV1>>>,
    block: RemoteBlockGossip,
) -> Result<RemoteBlockApplyOutcome, RemoteBlockApplyError> {
    let RemoteBlockGossip {
        block_height,
        block_id,
        parent_block_id,
        producer_id,
        base_reward_micro,
        compute_reward_micro,
        total_reward_micro,
        state_root,
        txs,
    } = block;
    let local_height = ledger
        .block_height()
        .map_err(|e| RemoteBlockApplyError::Ledger(e.to_string()))?;

    if block_height < local_height {
        return Ok(RemoteBlockApplyOutcome::Skipped {
            reason: format!("stale block height={block_height} local_height={local_height}"),
        });
    }
    if block_height > local_height.saturating_add(1) {
        return Ok(RemoteBlockApplyOutcome::Skipped {
            reason: format!(
                "missing previous blocks height={block_height} local_height={local_height}"
            ),
        });
    }
    let producer_id = ConsensusIdentity::new(producer_id)
        .ok_or_else(|| RemoteBlockApplyError::Rejected("producer_id required".to_string()))?;
    let local_node_id = local_node_id_from_env();
    let validator_set = ValidatorSet::from_env_or_single(&local_node_id);
    if !validator_set.contains(producer_id.as_str()) {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "producer_id is not in validator set: {}",
            producer_id.as_str()
        )));
    }
    let leader_mode = leader_election_mode_from_env();
    let expected_leader =
        leader_for_height_with_mode(block_height, &validator_set, leader_mode, ledger.clone())
            .ok_or_else(|| RemoteBlockApplyError::Rejected("validator set is empty".to_string()))?;
    if expected_leader != producer_id {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "invalid leader for height={} expected={} received={}",
            block_height,
            expected_leader.as_str(),
            producer_id.as_str()
        )));
    }

    let mut tx_hashes = Vec::with_capacity(txs.len());
    let mut seen = HashSet::with_capacity(txs.len());
    for env in &txs {
        let tx_hash = tx_hash_for_env(env).map_err(RemoteBlockApplyError::Rejected)?;
        if !seen.insert(tx_hash.clone()) {
            return Err(RemoteBlockApplyError::Rejected(format!(
                "duplicate tx in block: {tx_hash}"
            )));
        }
        tx_hashes.push(tx_hash);
    }

    let expected_block_id = block_id_for_block(block_height, &tx_hashes);
    if expected_block_id != block_id {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "block_id mismatch expected={expected_block_id} received={block_id}"
        )));
    }

    if block_contains_ai_workload(&txs)
        && !producer_can_mine_ai_workload(&ledger, producer_id.as_str())
    {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "producer_id={} is not POC for AI workload",
            producer_id.as_str()
        )));
    }

    validate_zk_task_claims(&ledger, &txs).map_err(RemoteBlockApplyError::Rejected)?;
    let reward = reward_for_block(&txs).map_err(RemoteBlockApplyError::Rejected)?;
    if reward.base_reward_micro != base_reward_micro
        || reward.compute_reward_micro != compute_reward_micro
        || reward.total_reward_micro != total_reward_micro
    {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "block reward mismatch expected=({},{},{}) received=({},{},{})",
            reward.base_reward_micro,
            reward.compute_reward_micro,
            reward.total_reward_micro,
            base_reward_micro,
            compute_reward_micro,
            total_reward_micro
        )));
    }

    if block_height == local_height {
        let local = ledger
            .block_summary_by_height(block_height)
            .map_err(|e| RemoteBlockApplyError::Ledger(e.to_string()))?;
        if let Some(local) = local {
            if local.block_id != block_id {
                let _ = record_block_record(
                    &ledger,
                    RecordBlockArgs {
                        block_height,
                        block_id: &block_id,
                        parent_block_id: parent_block_id.clone(),
                        producer_id: producer_id.as_str(),
                        tx_hashes: &tx_hashes,
                        txs: &txs,
                        state_root: &state_root,
                        reward,
                        canonical: false,
                    },
                );
                match reorg_to_branch(&ledger, &block_id) {
                    Ok(true) => {
                        return Ok(RemoteBlockApplyOutcome::Applied {
                            block_height,
                            tx_count: txs.len(),
                            evicted_count: 0,
                            state_root,
                        });
                    }
                    Ok(false) => {}
                    Err(e) => return Err(RemoteBlockApplyError::Ledger(e)),
                }
            }
            if remote_wins_fork(&local.block_id, &block_id) {
                return Ok(RemoteBlockApplyOutcome::ForkLost {
                    reason: format!(
                        "remote block wins fork by block_id but reorg is not implemented local={} remote={}",
                        local.block_id, block_id
                    ),
                });
            }
            return Ok(RemoteBlockApplyOutcome::Skipped {
                reason: format!(
                    "remote block lost fork choice local={} remote={}",
                    local.block_id, block_id
                ),
            });
        }
        return Ok(RemoteBlockApplyOutcome::Skipped {
            reason: format!("same height already applied height={block_height}"),
        });
    }

    let expected_state_root = ledger
        .compute_state_root_after_remote_block(
            &txs,
            producer_id.as_str(),
            reward.total_reward_micro,
        )
        .map_err(|e| RemoteBlockApplyError::Rejected(e.to_string()))?;
    if expected_state_root != state_root {
        return Err(RemoteBlockApplyError::Rejected(format!(
            "state_root mismatch expected={expected_state_root} received={state_root}"
        )));
    }
    let undo = ledger
        .prepare_block_undo(
            &block_id,
            block_height,
            &txs,
            &tx_hashes,
            producer_id.as_str(),
            reward.total_reward_micro,
        )
        .map_err(|e| RemoteBlockApplyError::Ledger(e.to_string()))?;
    ledger
        .store_block_undo(&undo)
        .map_err(|e| RemoteBlockApplyError::Ledger(e.to_string()))?;

    let actual_state_root = ledger
        .apply_consensus_block_batch(
            block_height,
            &txs,
            &tx_hashes,
            producer_id.as_str(),
            reward.total_reward_micro,
        )
        .map_err(|e| RemoteBlockApplyError::Ledger(e.to_string()))?;
    if actual_state_root != state_root {
        return Err(RemoteBlockApplyError::Ledger(format!(
            "post-apply state_root mismatch expected={state_root} actual={actual_state_root}"
        )));
    }
    ledger
        .record_block_summary(block_height, &block_id, &state_root, txs.len() as u64)
        .map_err(|e| RemoteBlockApplyError::Ledger(e.to_string()))?;
    record_block_record(
        &ledger,
        RecordBlockArgs {
            block_height,
            block_id: &block_id,
            parent_block_id: parent_block_id.clone(),
            producer_id: producer_id.as_str(),
            tx_hashes: &tx_hashes,
            txs: &txs,
            state_root: &state_root,
            reward,
            canonical: true,
        },
    )
    .map_err(RemoteBlockApplyError::Ledger)?;
    ledger
        .record_tx_indexes_batch(block_height, &tx_hashes, &txs, true)
        .map_err(|e| RemoteBlockApplyError::Ledger(e.to_string()))?;
    schedule_history_prune(ledger.clone(), block_height);

    let block_hashes: HashSet<&str> = tx_hashes.iter().map(String::as_str).collect();
    let evicted_count = {
        let mut mp = mempool.lock().await;
        let before = mp.len();
        mp.retain(|env| match tx_hash_for_env(env) {
            Ok(tx_hash) => !block_hashes.contains(tx_hash.as_str()),
            Err(_) => true,
        });
        before.saturating_sub(mp.len())
    };

    Ok(RemoteBlockApplyOutcome::Applied {
        block_height,
        tx_count: txs.len(),
        evicted_count,
        state_root,
    })
}
