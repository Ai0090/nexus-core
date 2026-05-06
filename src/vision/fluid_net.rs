//! Fluid P2P: bootnode discovery env parsing (`BOOTNODES` alias + `TET_BOOTNODES`).

/// Comma-separated bootstrap multiaddrs (libp2p). Checks `TET_BOOTNODES` then `BOOTNODES`.
pub fn bootnode_addrs_from_env() -> Vec<String> {
    let raw = std::env::var("TET_BOOTNODES")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("BOOTNODES")
                .ok()
                .filter(|s| !s.trim().is_empty())
        });
    raw.map(|s| {
        s.split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

pub fn log_startup_summary() {
    let nodes = bootnode_addrs_from_env();
    log::info!(
        "[vision][fluid_net] bootnodes_loaded={} (TET_BOOTNODES | BOOTNODES)",
        nodes.len()
    );
    for (i, n) in nodes.iter().enumerate().take(8) {
        log::info!("[vision][fluid_net] bootnode[{i}] {n}");
    }
}
