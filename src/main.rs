mod ai_proxy;
mod attestation;
mod chaos;
mod conductor;
mod e2ee;
mod executor;
mod invariant_tests;
mod ledger;
mod marketplace;
mod network;
mod oracle;
mod p2p_dex;
mod protocol;
mod quantum_shield;
mod replication;
mod render_farm;
mod rest;
mod tee_compute;
mod updater;
mod wallet;
mod worker_network;
mod worker_ai;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod test_env;

use crate::ledger::Ledger;
use crate::network::NetworkManager;
use crate::rest::{HttpRateLimit, RestState, serve};
use crate::worker_network::WorkerRegistry;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Chaos tester mode (anti-fragility).
    // Usage: `TET-Core chaos-sim` (no server).
    if std::env::args().any(|a| a == "chaos-sim") {
        let r = crate::chaos::simulate_reroute(20_000, 1_000, 500);
        if !r.ok_no_loss {
            return Err("chaos-sim failed: shard loss detected".into());
        }
        println!(
            "CHAOS_SIM_OK workers_total={} workers_online_after={} shards_total={} rerouted_shards={}",
            r.workers_total, r.workers_online_after, r.shards_total, r.rerouted_shards
        );
        return Ok(());
    }
    let db_dir = std::env::var("TET_DB_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tet.db".to_string());
    let initial_wallet = std::env::var("TET_WALLET_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::env::var("TET_PEER_ID")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "local-wallet".to_string())
        });

    // CRITICAL: production mode must never boot with an unencrypted ledger.
    // If `TET_PROD` / `TET_MAINNET` is set, require a DB key and reject `TET_DB_ENCRYPT=off`.
    let is_prod = std::env::var("TET_PROD")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || std::env::var("TET_MAINNET")
            .ok()
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    if is_prod {
        let encrypt_mode = std::env::var("TET_DB_ENCRYPT")
            .ok()
            .unwrap_or_else(|| "strict".to_string())
            .to_ascii_lowercase();
        if encrypt_mode == "off" || encrypt_mode == "false" || encrypt_mode == "0" {
            eprintln!("[FATAL] Production mode forbids TET_DB_ENCRYPT=off.");
            std::process::exit(2);
        }
        let has_key = std::env::var("TET_DB_KEY_B64")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some()
            || std::env::var("TET_DB_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .is_some();
        if !has_key {
            eprintln!("[FATAL] Production mode requires an encryption key: set TET_DB_KEY_B64 (preferred) or TET_DB_KEY.");
            std::process::exit(2);
        }
    }

    let ledger = Arc::new(Ledger::open(&db_dir)?);
    ledger.init_genesis_founder_premine_from_env()?;

    // Optional P2P mesh (can be disabled for local demos).
    let enable_p2p = std::env::var("TET_ENABLE_P2P")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let p2p = if enable_p2p {
        let mut nm = NetworkManager::new(initial_wallet.clone()).await?;
        let tx = nm.tx();
        crate::replication::set_p2p_sender(Some(tx.clone()));
        tokio::spawn(async move {
            let _ = nm.run().await;
        });
        Some(tx)
    } else {
        crate::replication::set_p2p_sender(None);
        None
    };

    let bind = std::env::var("TET_REST_BIND")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "127.0.0.1:5010".to_string());
    let addr: SocketAddr = bind.parse()?;

    let http_rps = std::env::var("TET_HTTP_RPS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(25)
        .max(1);

    let state = RestState {
        ledger,
        p2p_tx: p2p,
        http_ratelimit: Arc::new(tokio::sync::Mutex::new(HttpRateLimit::new(http_rps))),
        workers: Arc::new(StdMutex::new(WorkerRegistry::default())),
        e2ee_jobs: Arc::new(StdMutex::new(crate::rest::E2eeJobQueue::default())),
        dex: Arc::new(StdMutex::new(crate::p2p_dex::DexEngine::default())),
        genesis_1k_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    serve(state, addr).await?;
    Ok(())
}
