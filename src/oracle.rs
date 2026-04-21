//! Energy/CHF oracle stub (Phase 3+).
//!
//! Production should query a real oracle. This stub uses env vars and a request-provided geo hint.

#[derive(Debug, Clone)]
pub struct EnergyPricing {
    pub chf_per_kwh: f64,
    pub profit_margin: f64, // 0.20 = +20%
}

fn env_f64(name: &str) -> Option<f64> {
    std::env::var(name).ok().and_then(|v| v.parse::<f64>().ok())
}

pub fn energy_pricing_for_geo(geo: &str) -> EnergyPricing {
    let base = env_f64("TET_ORACLE_CHF_PER_KWH").unwrap_or(0.28);
    let margin = env_f64("TET_WORKER_PROFIT_MARGIN").unwrap_or(0.20).max(0.0);
    // Tiny deterministic geo adjustment stub.
    let g = geo.trim().to_ascii_uppercase();
    let mult = match g.as_str() {
        "CH" | "CHE" | "SWITZERLAND" => 1.00,
        "DE" | "GERMANY" => 0.95,
        "US" | "USA" => 0.90,
        _ => 1.05,
    };
    EnergyPricing {
        chf_per_kwh: (base * mult).max(0.01),
        profit_margin: margin,
    }
}

/// Convert a compute-energy estimate into a TET reward (stevemon micro).
///
/// Peg: 1 CHF = 1 TET. `chf_amount_micro` is millionths CHF.
pub fn reward_micro_from_energy(chf_amount_micro: u64, profit_margin: f64) -> u64 {
    let pm = if profit_margin.is_finite() {
        profit_margin.max(0.0)
    } else {
        0.0
    };
    let gross_chf_micro = (chf_amount_micro as f64 * (1.0 + pm)).ceil().max(0.0);
    // 1 CHF == 1 TET; 1 TET == 100_000_000 stevemon.
    let stevemon_per_chf_micro = 100_000_000u128 / 1_000_000u128; // 100
    let micro = gross_chf_micro as u128;
    let out = micro.saturating_mul(stevemon_per_chf_micro);
    u64::try_from(out).unwrap_or(u64::MAX)
}
