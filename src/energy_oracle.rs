//! Real-time Energy / CHF oracle for worker rewards (local cost + 20% margin, geo-adjusted).

use crate::ledger::STEVEMON;

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(default)
}

/// Geo multiplier: `TET_ORACLE_GEO_<REGION>` e.g. TET_ORACLE_GEO_EU_WEST=1.0
fn geo_multiplier(region: &str) -> f64 {
    let key = format!(
        "TET_ORACLE_GEO_{}",
        region
            .trim()
            .to_ascii_uppercase()
            .replace(['-', ' '], "_")
    );
    env_f64(&key, 1.0).max(0.01)
}

/// CHF micro to credit for `shard_count` shards after energy + 20% profit, adjusted by geo.
/// Base: `TET_ORACLE_CHF_PER_KWH` (default 0.35), `TET_ORACLE_KWH_PER_SHARD` (default 0.002).
pub fn quote_reward_chf_micro(shard_count: usize, geo_region: &str) -> u64 {
    let chf_per_kwh = env_f64("TET_ORACLE_CHF_PER_KWH", 0.35);
    let kwh_per_shard = env_f64("TET_ORACLE_KWH_PER_SHARD", 0.002);
    let profit_bps = std::env::var("TET_ORACLE_PROFIT_BPS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2000);
    let g = geo_multiplier(geo_region);
    let energy_chf = shard_count as f64 * kwh_per_shard * chf_per_kwh * g;
    let with_margin = energy_chf * (1.0 + (profit_bps as f64 / 10_000.0));
    let micro = (with_margin * 1_000_000.0).round().max(1.0);
    micro.min(u64::MAX as f64) as u64
}

/// Stevemon mint amount from CHF micro (1 CHF = 1 TET peg).
pub fn chf_micro_to_stevemon_micro(chf_micro: u64) -> u64 {
    ((chf_micro as u128 * STEVEMON as u128) / 1_000_000u128) as u64
}
