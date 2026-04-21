//! In-memory registry of Worker Network nodes (Phase 2).

use serde::Serialize;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct WorkerEntry {
    pub wallet: String,
    pub hardware_id_hex: String,
    pub ed25519_pubkey_hex: String,
    pub x25519_pubkey_b64: Option<String>,
    pub tflops_est: f64,
    pub last_seen_ms: u128,
}

#[derive(Debug, Default)]
pub struct WorkerRegistry {
    pub by_wallet: HashMap<String, WorkerEntry>,
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

impl WorkerRegistry {
    pub fn upsert(&mut self, e: WorkerEntry) {
        self.by_wallet.insert(e.wallet.clone(), e);
    }

    pub fn heartbeat(
        &mut self,
        wallet: &str,
        hardware_id_hex: &str,
        ed25519_pubkey_hex: &str,
        x25519_pubkey_b64: Option<&str>,
        tflops_est: f64,
    ) -> Result<(), &'static str> {
        let w = wallet.trim();
        if w.is_empty() {
            return Err("wallet required");
        }
        let hw = hardware_id_hex.trim();
        if hw.is_empty() {
            return Err("hardware_id_hex required");
        }
        let pk = ed25519_pubkey_hex.trim();
        if pk.is_empty() {
            return Err("ed25519_pubkey_hex required");
        }
        let e = WorkerEntry {
            wallet: w.to_string(),
            hardware_id_hex: hw.to_string(),
            ed25519_pubkey_hex: pk.to_string(),
            x25519_pubkey_b64: x25519_pubkey_b64
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            tflops_est: tflops_est.max(0.0),
            last_seen_ms: now_ms(),
        };
        self.upsert(e);
        Ok(())
    }

    pub fn get_by_hardware(&self, hardware_id_hex: &str) -> Option<&WorkerEntry> {
        let want = hardware_id_hex.trim();
        self.by_wallet.values().find(|e| e.hardware_id_hex == want)
    }

    /// Active if last heartbeat within `ttl_ms`.
    pub fn active_count(&self, ttl_ms: u128) -> usize {
        let t = now_ms();
        self.by_wallet
            .values()
            .filter(|e| t.saturating_sub(e.last_seen_ms) <= ttl_ms)
            .count()
    }

    pub fn total_tflops(&self, ttl_ms: u128) -> f64 {
        let t = now_ms();
        self.by_wallet
            .values()
            .filter(|e| t.saturating_sub(e.last_seen_ms) <= ttl_ms)
            .map(|e| e.tflops_est)
            .sum()
    }

    /// Remove a worker entry by wallet id (used for stake/slash revocation).
    pub fn remove_wallet(&mut self, wallet: &str) {
        let w = wallet.trim().to_string();
        if w.is_empty() {
            return;
        }
        self.by_wallet.remove(&w);
    }
}

#[derive(Serialize)]
pub struct NetworkPowerSnapshot {
    pub total_compute_tflops: f64,
    pub active_worker_nodes: u64,
    pub community_stevemon_earned_micro: u64,
    /// Cumulative protocol fee amount permanently removed from `total_supply_micro` (stevemon micro).
    pub total_burned_micro: u64,
    /// Algorithmic TET / USDC index from ledger + worker registry (see `NetworkStats`).
    pub tet_price_usd: f64,
    pub total_supply_micro: u64,
}

/// Public tokenomics / demand snapshot for dashboards (`GET /network/stats`).
#[derive(Serialize)]
pub struct NetworkStats {
    pub total_compute_tflops: f64,
    pub active_worker_nodes: u64,
    pub community_stevemon_earned_micro: u64,
    pub total_burned_micro: u64,
    /// Genesis 1K airdrop claimed slots (0..=1000).
    pub genesis_1k_claimed: u64,
    /// Genesis Worker grant counter derived from `system:worker_pool` depletion.
    pub genesis_guardians_filled: u64,
    pub genesis_guardians_total: u64,
    pub tet_price_usd: f64,
    /// Pre-sale floor used when pricing the index (env `TET_PRESALE_USD_PER_TET`, default 0.05).
    pub tet_presale_usd: f64,
    pub total_supply_micro: u64,
}
