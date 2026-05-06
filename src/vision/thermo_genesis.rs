//! Thermodynamic economics + genesis targets (whitepaper Phase 1–2).
//! **Ledger** uses `crate::ledger::STEVEMON` (1e6 Stevemon atoms per TET).

use crate::ledger::STEVEMON;
use serde::Serialize;

/// Whitepaper naming: 1 TET = 1_000_000 Stevemon (not yet enforced on-chain).
pub const WHITEPAPER_STEVEMON_PER_TET: u64 = 1_000_000;

pub const MAX_SUPPLY_TET: u64 = 10_000_000_000;

/// Target genesis split per vision doc: 25% founder / 75% system-locked bucket.
pub const GENESIS_FOUNDER_SHARE_BPS: u64 = 2500;
pub const GENESIS_SYSTEM_LOCKED_BPS: u64 = 7500;

/// Network difficulty Γ (whitepaper §4.2). Tunable via [`NetworkDifficulty::from_env`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct NetworkDifficulty(pub f64);

impl NetworkDifficulty {
    pub const GAMMA_V1: NetworkDifficulty = NetworkDifficulty(1.0);

    pub fn from_env() -> Self {
        Self(
            std::env::var("TET_NETWORK_DIFFICULTY_GAMMA")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .filter(|x| x.is_finite() && *x > 0.0)
                .unwrap_or(1.0),
        )
    }
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|x| x.is_finite())
        .unwrap_or(default)
}

/// Node energy proxy **E**: Joules expended **per FLOP** (same symbol as whitepaper §4.2).
pub fn env_joules_per_flop() -> f64 {
    env_f64("TET_JOULES_PER_FLOP", 1e-12).max(f64::MIN_POSITIVE)
}

/// Additional scaling from the dimensionless thermodynamic ratio **R_raw** = (C/E)×Γ into ledger **Stevemon micro**
/// (atomic units). Default aligns with the legacy `TET_FLOPS_PER_STEVEMON_MICRO` order of magnitude when `TET_JOULES_PER_FLOP` is default.
pub fn env_thermo_stevemon_micro_scale() -> f64 {
    env_f64("TET_THERMO_STEVEMON_MICRO_SCALE", 1e-18).max(0.0)
}

/// Whitepaper §4.2 discrete thermodynamic reward:
///
/// **R = (C_flops / E_joules_per_flop) × Γ**
///
/// - `c_flops`: exact inference FLOPs  
/// - `e_joules_per_flop`: **E** = J/FLOP (efficiency proxy, not total joules)  
/// - `gamma`: network difficulty Γ  
///
/// Returns **Stevemon micro** (same atomic units as [`crate::ledger::STEVEMON`]).
pub fn discrete_thermodynamic_reward_stevemon_micro(
    c_flops: u128,
    e_joules_per_flop: f64,
    gamma: NetworkDifficulty,
) -> u64 {
    if c_flops == 0 {
        return 0;
    }
    let e = e_joules_per_flop.max(f64::MIN_POSITIVE);
    let scale = env_thermo_stevemon_micro_scale();
    let ratio = (c_flops as f64 / e) * gamma.0 * scale;
    if !ratio.is_finite() || ratio <= 0.0 {
        return 1;
    }
    let capped = ratio.min(u64::MAX as f64);
    let u = capped as u64;
    u.max(1)
}

#[derive(Debug, Clone, Serialize)]
pub struct InferCostEstimate {
    /// Total fee-like charge in **ledger Stevemon micro** (same units as [`crate::ledger::STEVEMON`]).
    pub total_micro_ledger: u64,
    pub to_worker_reward_micro: u64,
    pub to_protocol_burn_micro: u64,
    /// Raw §4.2 thermodynamic R before the 50/50 settlement split (same units).
    pub thermodynamic_r_micro: u64,
    pub notes: &'static str,
}

/// §4.2 thermodynamic estimate from **declared FLOPs only** (no prompt-length heuristics).
pub fn estimate_ai_infer_cost_micro(c_flops: u128) -> InferCostEstimate {
    let gamma = NetworkDifficulty::from_env();
    let e = env_joules_per_flop();
    let r_micro = discrete_thermodynamic_reward_stevemon_micro(c_flops, e, gamma);
    let half = r_micro / 2;
    let rem = r_micro.saturating_sub(half * 2);
    InferCostEstimate {
        total_micro_ledger: r_micro,
        to_worker_reward_micro: half,
        to_protocol_burn_micro: half.saturating_add(rem),
        thermodynamic_r_micro: r_micro,
        notes: "§4.2 discrete R=(C_flops/E)×Γ → Stevemon micro; 50/50 worker pool / protocol burn on settlement",
    }
}

pub fn genesis_vision_json() -> serde_json::Value {
    serde_json::json!({
        "max_supply_tet": MAX_SUPPLY_TET,
        "whitepaper_stevemon_per_tet": WHITEPAPER_STEVEMON_PER_TET,
        "ledger_stevemon_per_tet": STEVEMON,
        "genesis_split_bps": {
            "founder": GENESIS_FOUNDER_SHARE_BPS,
            "system_locked": GENESIS_SYSTEM_LOCKED_BPS,
        },
        "thermodynamics_v1": {
            "equation": "R = (C_flops / E_joules_per_flop) * Gamma",
            "env": {
                "TET_JOULES_PER_FLOP": "E (J/FLOP)",
                "TET_NETWORK_DIFFICULTY_GAMMA": "Gamma (default 1.0)",
                "TET_THERMO_STEVEMON_MICRO_SCALE": "R to Stevemon micro calibration",
            },
        },
        "burn_policy_infer_fee": "50pct_worker_pool_50pct_burn",
    })
}
