//! CAAC (環境適応型コンセンサス): hardware probe + **probabilistic fingerprint** + PoC/PoR routing skeleton.

use rand_core::{OsRng, RngCore as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::time::Instant;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

/// Assigned consensus-facing execution lane (whitepaper PoC / PoR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeRelayRole {
    /// Proof of Compute — AI inference capable (high-end).
    Poc,
    /// Proof of Relay — forwarding / DHT / gossip relay (edge).
    Por,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardwareFingerprint {
    pub fingerprint_sha256_hex: String,
    pub cpu_logical_cores: u32,
    pub ram_total_bytes: u64,
    pub gpu_detected: bool,
    pub gpu_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaacProfile {
    pub role: NodeRelayRole,
    pub hw: HardwareFingerprint,
}

fn gpu_hint_detect() -> (bool, String) {
    if std::env::var("CUDA_VISIBLE_DEVICES").is_ok() || std::env::var("GPU_DEVICE_ORDINAL").is_ok()
    {
        return (true, "env_cuda_or_gpu_ordinal".into());
    }
    #[cfg(target_os = "macos")]
    {
        (
            std::process::Command::new("system_profiler")
                .args(["SPDisplaysDataType", "-json"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
            "system_profiler_displays".into(),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        (false, "no_heuristic_match".into())
    }
}

/// Builds a stable-ish fingerprint from host signals (not a security anchor — routing heuristic only).
pub fn probe_hardware_fingerprint() -> HardwareFingerprint {
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );
    sys.refresh_cpu_all();
    sys.refresh_memory();

    let cpu_logical_cores = sys.cpus().len() as u32;
    let ram_total_bytes = sys.total_memory().saturating_mul(1024);
    let (gpu_detected, gpu_hint) = gpu_hint_detect();

    let mut h = Sha256::new();
    h.update(format!("cores={cpu_logical_cores}"));
    h.update(format!("ram={ram_total_bytes}"));
    h.update(format!("gpu={gpu_detected}"));
    h.update(gpu_hint.as_bytes());
    let fingerprint_sha256_hex = hex::encode(h.finalize());

    HardwareFingerprint {
        fingerprint_sha256_hex,
        cpu_logical_cores,
        ram_total_bytes,
        gpu_detected,
        gpu_hint,
    }
}

fn meets_poc_threshold(hw: &HardwareFingerprint) -> bool {
    let min_cores = std::env::var("TET_CAAC_POC_MIN_CORES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(4);
    let min_ram_gib = std::env::var("TET_CAAC_POC_MIN_RAM_GIB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(8);
    let ram_gib = hw.ram_total_bytes / (1024 * 1024 * 1024);
    hw.gpu_detected || (hw.cpu_logical_cores >= min_cores && ram_gib >= min_ram_gib)
}

/// Dynamic PoC vs PoR assignment (routing hook for future scheduler).
pub fn assign_role(hw: &HardwareFingerprint) -> NodeRelayRole {
    if meets_poc_threshold(hw) {
        NodeRelayRole::Poc
    } else {
        NodeRelayRole::Por
    }
}

pub fn profile() -> CaacProfile {
    let hw = probe_hardware_fingerprint();
    let role = assign_role(&hw);
    CaacProfile { role, hw }
}

/// Local, advisory resource weight for CAAC-aware consensus bootstrapping.
///
/// This value is not a consensus proof by itself; network-wide leader verification should use
/// ledger-synced CAAC records so every node sees the same weights.
pub fn local_resource_weight(profile: &CaacProfile) -> u64 {
    let base = match profile.role {
        NodeRelayRole::Poc => 100,
        NodeRelayRole::Por => 25,
    };
    let ram_gib = profile.hw.ram_total_bytes / (1024 * 1024 * 1024);
    let cpu_bonus = u64::from(profile.hw.cpu_logical_cores).saturating_mul(4);
    let ram_bonus = ram_gib.min(128);
    let gpu_bonus = if profile.hw.gpu_detected { 100 } else { 0 };
    base + cpu_bonus + ram_bonus + gpu_bonus
}

/// Issued by [`generate_hardware_challenge`]; worker runs [`compute_challenge_digest`] and submits latency.
#[derive(Debug, Clone, Serialize)]
pub struct HardwareChallengePublic {
    pub variant: &'static str,
    pub seed_hex: String,
    pub rounds: u64,
}

/// Random seed + deterministic SHA256-chain workload parameters (whitepaper §3–4 CAAC lane probe).
pub fn generate_hardware_challenge() -> HardwareChallengePublic {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    HardwareChallengePublic {
        variant: "sha256_chain_v1",
        seed_hex: hex::encode(seed),
        rounds: challenge_rounds_from_seed(&seed),
    }
}

/// Iteration count derived from seed (10_000 … 60_000).
pub fn challenge_rounds_from_seed(seed: &[u8; 32]) -> u64 {
    let base = u64::from_le_bytes(seed[0..8].try_into().unwrap_or([0u8; 8]));
    10_000 + (base % 50_000)
}

/// Deterministic digest after `rounds` SHA256 compositions starting from 32-byte seed.
pub fn compute_challenge_digest(seed_hex: &str) -> Result<String, String> {
    let raw = hex::decode(seed_hex.trim()).map_err(|e| e.to_string())?;
    if raw.len() != 32 {
        return Err("seed must be 32 bytes (64 hex chars)".into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    let rounds = challenge_rounds_from_seed(&arr);
    let mut state = arr;
    for _ in 0..rounds {
        let mut h = Sha256::new();
        h.update(state);
        state.copy_from_slice(&h.finalize());
    }
    Ok(hex::encode(state))
}

/// Server-side wall time to run the same workload (audit; not used for PoC/PoR decision).
pub fn measure_challenge_wall_ms(seed_hex: &str) -> Result<u64, String> {
    let t0 = Instant::now();
    let _ = compute_challenge_digest(seed_hex)?;
    Ok(t0.elapsed().as_millis() as u64)
}

/// Max client-reported latency (ms) to classify as **PoC**; over → **PoR** (edge). Override: `TET_CAAC_POC_MAX_LATENCY_MS`.
pub fn caac_poc_max_latency_ms() -> u64 {
    std::env::var("TET_CAAC_POC_MAX_LATENCY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50)
        .max(1)
}

/// Classify by measured wall-clock during the challenge (client reports; server checks digest).
pub fn role_from_latency_ms(latency_ms: u64) -> NodeRelayRole {
    if latency_ms <= caac_poc_max_latency_ms() {
        NodeRelayRole::Poc
    } else {
        NodeRelayRole::Por
    }
}

/// `POC` / `POR` for [`crate::ledger::CaacWorkerRecord::role`].
pub fn role_to_tag(role: NodeRelayRole) -> &'static str {
    match role {
        NodeRelayRole::Poc => "POC",
        NodeRelayRole::Por => "POR",
    }
}
