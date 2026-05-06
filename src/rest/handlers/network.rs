use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use rand_core::RngCore as _;
use serde::Serialize;
use sha2::Digest as _;

use crate::ledger::{MAX_SUPPLY_MICRO, STEVEMON};
use crate::{
    attestation::AttestationReport,
    conductor::{
        OrchestratePlan, OrchestrateRunResult, ShardSpec, shard_ai_inference,
        shard_scientific_grid, shard_video_rendering,
    },
    rest::{
        ComputeReq, RestState,
        helpers::{std_lock, verify_envelope_v1},
    },
    worker_network::{NetworkPowerSnapshot, NetworkStats},
};

fn worker_heartbeat_ttl_ms() -> u128 {
    std::env::var("TET_WORKER_HEARTBEAT_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(60_000)
}

fn tet_presale_usd_floor() -> f64 {
    std::env::var("TET_PRESALE_USD_PER_TET")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|x| x.is_finite() && *x > 0.0)
        .unwrap_or(0.05)
}

/// Ledger-backed TET/USDC index: **presale only** when no workers are online (flat charts for demos);
/// with active workers, scales deterministically from burn + headcount + community mint (vest proxy) — no RNG.
fn tet_algorithmic_index_usd(
    presale: f64,
    total_burned_micro: u64,
    active_workers: u64,
    community_mint_micro: u64,
) -> f64 {
    let active = active_workers as f64;
    if active <= 0.0 {
        return presale;
    }
    let supply_cap_tet = MAX_SUPPLY_MICRO as f64 / STEVEMON as f64;
    let burn_tet = total_burned_micro as f64 / STEVEMON as f64;
    let burn_ratio = if supply_cap_tet > 0.0 {
        burn_tet / supply_cap_tet
    } else {
        0.0
    };
    let burn_term = (burn_ratio * 800.0).tanh() * 0.07;
    let demand_term = (active / 100.0).tanh() * 0.12;
    let comm_tet = community_mint_micro as f64 / STEVEMON as f64;
    let stake_proxy = (comm_tet / 2_000_000_000.0).tanh() * 0.05;
    let mult = 1.0 + burn_term + demand_term + stake_proxy;
    (presale * mult).clamp(presale, presale * 1.40)
}

fn build_network_stats(state: &RestState) -> NetworkStats {
    let ttl = worker_heartbeat_ttl_ms();
    let reg = std_lock(&state.workers);
    let total_compute_tflops = reg.total_tflops(ttl);
    let active_worker_nodes = reg.active_count(ttl) as u64;
    drop(reg);

    let total_burned_micro = state.ledger.total_burned_micro().unwrap_or(0);
    let total_supply_micro = state.ledger.total_supply_micro().unwrap_or(0);
    let community_stevemon_earned_micro = state
        .ledger
        .worker_community_mint_micro_total()
        .unwrap_or(0);
    let genesis_1k_claimed = state.ledger.genesis_1k_filled_count_public().unwrap_or(0);

    // Genesis Guardians counter (derived from worker pool depletion).
    let pool_cur = state
        .ledger
        .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
        .unwrap_or(0);
    let pool_init = crate::ledger::GENESIS_WORKER_POOL_SHARE_MICRO;
    let grant = crate::ledger::GENESIS_GUARDIAN_GRANT_MICRO.max(1);
    let spent = pool_init.saturating_sub(pool_cur);
    let mut filled = spent / grant;
    if filled > crate::ledger::GENESIS_GUARDIANS_TOTAL {
        filled = crate::ledger::GENESIS_GUARDIANS_TOTAL;
    }

    let tet_presale_usd = tet_presale_usd_floor();
    let tet_price_usd = tet_algorithmic_index_usd(
        tet_presale_usd,
        total_burned_micro,
        active_worker_nodes,
        community_stevemon_earned_micro,
    );

    let consensus_block_height = state.ledger.inference_block_height();
    let is_genesis_boost = consensus_block_height < crate::ledger::GENESIS_EPOCH_BLOCK_LIMIT;
    let epoch = state.ledger.consensus_display_epoch();

    NetworkStats {
        total_compute_tflops,
        active_worker_nodes,
        community_stevemon_earned_micro,
        total_burned_micro,
        genesis_1k_claimed,
        genesis_guardians_filled: filled,
        genesis_guardians_total: crate::ledger::GENESIS_GUARDIANS_TOTAL,
        tet_price_usd,
        tet_presale_usd,
        total_supply_micro,
        system_worker_pool_balance_micro: pool_cur,
        consensus_block_height,
        epoch,
        is_genesis_boost,
    }
}

pub async fn get_network_stats(State(state): State<RestState>) -> impl IntoResponse {
    (StatusCode::OK, Json(build_network_stats(&state))).into_response()
}

pub async fn get_network_power(State(state): State<RestState>) -> impl IntoResponse {
    let s = build_network_stats(&state);
    let snap = NetworkPowerSnapshot {
        total_compute_tflops: s.total_compute_tflops,
        active_worker_nodes: s.active_worker_nodes,
        community_stevemon_earned_micro: s.community_stevemon_earned_micro,
        total_burned_micro: s.total_burned_micro,
        tet_price_usd: s.tet_price_usd,
        total_supply_micro: s.total_supply_micro,
    };
    (StatusCode::OK, Json(snap)).into_response()
}

pub async fn post_v1_compute(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(req): Json<ComputeReq>,
) -> axum::response::Response {
    // Verify payment envelope.
    if let Err(e) = verify_envelope_v1(&req.payment) {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }

    let plugin = req.plugin.trim().to_ascii_lowercase();
    let redundancy = req.redundancy.unwrap_or(1).clamp(1, 5);
    let geo = req.geo.unwrap_or_else(|| "CH".into());
    let model = req.model.unwrap_or_else(|| "tet/poc".into());

    // Orchestration: build shards via plugin, then run local deterministic PoC per shard.
    let (plugin_name, shards): (String, Vec<ShardSpec>) = match plugin.as_str() {
        "ai_inference" => {
            let input = req.input.unwrap_or_default();
            let shard_chars = req.shard_chars.unwrap_or(1200);
            (
                "ai_inference".into(),
                shard_ai_inference(&model, &input, shard_chars),
            )
        }
        "video_render" => {
            let frames = req.frames_total.unwrap_or(0);
            let shard_frames = req.shard_frames.unwrap_or(60).max(1);
            (
                "video_render".into(),
                shard_video_rendering(&model, frames, shard_frames),
            )
        }
        "scientific_compute" => {
            let w = req.grid_w.unwrap_or(0);
            let h = req.grid_h.unwrap_or(0);
            let tw = req.tile_w.unwrap_or(64).max(1);
            let th = req.tile_h.unwrap_or(64).max(1);
            (
                "scientific_compute".into(),
                shard_scientific_grid(&model, w, h, tw, th),
            )
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "unsupported plugin (ai_inference|video_render|scientific_compute)",
            )
                .into_response();
        }
    };

    // Cryptographically strong job id (no UUID shortcuts).
    let mut rbytes = [0u8; 16];
    let mut rng = rand_core::OsRng;
    rng.fill_bytes(&mut rbytes);
    let job_id = hex::encode(rbytes);
    let plan = OrchestratePlan {
        job_id: job_id.clone(),
        plugin: plugin_name,
        model: model.clone(),
        task_commitment_root_hex: {
            let mut h = sha2::Sha256::new();
            h.update(b"tet-task-commit:v1");
            for s in &shards {
                h.update(s.task_hash_hex.as_bytes());
                h.update([0u8]);
            }
            hex::encode(h.finalize())
        },
        shards: shards.clone(),
    };
    let outs: Vec<String> = shards
        .iter()
        .map(|s| tet_core::tet_worker::poc_infer(&s.text))
        .collect();
    let merged_output = outs.join("\n---tet-shard---\n");
    let deterministic_recompute_ok = shards
        .iter()
        .zip(outs.iter())
        .all(|(s, o)| tet_core::tet_worker::poc_infer(&s.text) == *o);
    let execution_root_hex = {
        let mut h = sha2::Sha256::new();
        h.update(b"tet-execution-root:v1");
        for (s, out) in shards.iter().zip(outs.iter()) {
            h.update(s.shard_id.to_le_bytes());
            let mut hh = sha2::Sha256::new();
            hh.update(out.as_bytes());
            h.update(hex::encode(hh.finalize()).as_bytes());
            h.update([0u8]);
        }
        hex::encode(h.finalize())
    };
    let run = OrchestrateRunResult {
        job_id,
        shard_outputs: outs,
        merged_output,
        deterministic_recompute_ok,
        execution_root_hex,
    };

    // Verification engine stub: require deterministic recomputation AND redundancy>=1.
    // For production: compare hashes across multiple workers per shard.
    if !run.deterministic_recompute_ok || redundancy < 1 {
        return (
            StatusCode::UNAUTHORIZED,
            "verification failed (determinism check)",
        )
            .into_response();
    }

    // Payment flow: reward minted to a registered worker (if any); otherwise, skip reward.
    // This keeps /v1/compute fully automated even without workers online.
    let att = AttestationReport {
        v: 1,
        platform: req.payment.attestation.platform.clone(),
        report_b64: req.payment.attestation.report_b64.clone(),
    };

    // Charge the user the compute price (already transferred to pool by /ai/proxy pattern).
    // Here we just accept the payment as authorization and mint rewards to workers.
    let imperial_vault = std::env::var("TET_IMPERIAL_VAULT_WALLET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "founder-vault-1".to_string());

    // Energy oracle: estimate CHF cost from shard count (stub).
    let pricing = crate::oracle::energy_pricing_for_geo(&geo);
    let chf_micro_cost = (plan.shards.len() as f64 * pricing.chf_per_kwh * 10_000.0).ceil() as u64; // stub
    let reward_gross =
        crate::oracle::reward_micro_from_energy(chf_micro_cost, pricing.profit_margin);

    let worker_wallet_opt = {
        let reg = std_lock(&state.workers);
        reg.by_wallet
            .values()
            .max_by(|a, b| a.last_seen_ms.cmp(&b.last_seen_ms))
            .map(|e| e.wallet.clone())
    };

    if let Some(worker_wallet) = worker_wallet_opt {
        let payload = serde_json::json!({
            "v": 1,
            "kind": "v1_compute_reward",
            "job_id": plan.job_id,
            "plugin": plugin,
            "shards": plan.shards.len(),
            "geo": geo,
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let _ = state.ledger.mint_worker_network_reward(
            &worker_wallet,
            &imperial_vault,
            reward_gross,
            &payload_bytes,
            Some(&att),
        );
    }

    #[derive(Serialize)]
    struct R {
        plan: crate::conductor::OrchestratePlan,
        run: crate::conductor::OrchestrateRunResult,
        reward_micro_est: u64,
        oracle_chf_per_kwh: f64,
        oracle_profit_margin: f64,
    }
    (
        StatusCode::OK,
        Json(R {
            plan,
            run,
            reward_micro_est: reward_gross,
            oracle_chf_per_kwh: pricing.chf_per_kwh,
            oracle_profit_margin: pricing.profit_margin,
        }),
    )
        .into_response()
}
