#![allow(dead_code)]

mod ai_filter;
mod ai_proxy;
mod attestation;
mod chaos;
mod conductor;
mod consensus;
mod e2ee;
mod executor;
mod invariant_tests;
mod ledger;
mod marketplace;
mod metrics;
mod models;
mod network;
mod onchain;
mod oracle;
mod p2p;
mod p2p_dex;
mod p2p_network;
mod protocol;
mod quantum_shield;
mod render_farm;
mod replication;
mod rest;
mod tee_compute;
mod updater;
mod vision;
mod wallet;
mod worker_ai;
mod worker_config;
mod worker_daemon;
mod worker_engine;
mod worker_network;
mod zk_verifier;

#[cfg(test)]
mod test_env;
#[cfg(test)]
mod tests;

use crate::ledger::{GENESIS_FOUNDER_DEV_PUBLIC_HEX, Ledger};
use crate::network::NetworkManager;
use crate::rest::{HttpRateLimit, RestState, serve};
use crate::worker_network::WorkerRegistry;
use base64::Engine as _;
use methods::NEXUS_GUEST_ID;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::broadcast;

type AnyErr = Box<dyn std::error::Error + Send + Sync>;

fn init_tracing() {
    let _ = tracing_log::LogTracer::init();
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json_logs = std::env::var("TET_JSON_LOG")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let fmt = tracing_subscriber::fmt().with_env_filter(env_filter);
    if json_logs {
        let _ = fmt.json().try_init();
    } else {
        let _ = fmt.try_init();
    }
}

fn fatal_db_lock_help(db_dir: &str, port: u16, e: &dyn std::error::Error) -> ! {
    eprintln!();
    eprintln!("[FATAL] Could not open ledger DB at `{db_dir}`.");
    eprintln!("[FATAL] {e}");
    eprintln!();
    eprintln!(
        "Most common cause: another TET-Core process is already running and holding the sled lock."
    );
    eprintln!();
    eprintln!("Fix options:");
    eprintln!("  1) Stop the existing process (recommended). On macOS:");
    eprintln!("     lsof -nP -iTCP:{port} -sTCP:LISTEN");
    eprintln!("     kill <PID>");
    eprintln!();
    eprintln!("  2) Run a separate sandbox DB (keeps your main ledger intact):");
    eprintln!("     TET_DB_DIR=tet_sandbox.db cargo run --bin TET-Core");
    eprintln!();
    std::process::exit(2);
}

#[tokio::main]
async fn main() -> Result<(), AnyErr> {
    init_tracing();

    // Phase 2.5: Node Operator Defense (default SAFE MODE).
    let safe_mode = crate::worker_config::configure_from_args();
    if safe_mode {
        log::info!(
            "Node started in SAFE MODE. Content filtering is ENABLED to protect the operator."
        );
    } else {
        log::warn!(
            "Node started in UNSAFE MODE. Content filtering is DISABLED (--unsafe-no-filter)."
        );
    }
    if crate::worker_config::enable_zk_prover() {
        log::info!("ZK PROVER: ENABLED (Strict Mode Active)");
    } else {
        log::info!("ZK PROVER: DISABLED (Optimistic Mode Active)");
    }

    crate::vision::fluid_net::log_startup_summary();
    let _caac = crate::vision::caac::profile();
    log::info!(
        "[vision][caac] role={:?} fingerprint_prefix={}…",
        _caac.role,
        _caac
            .hw
            .fingerprint_sha256_hex
            .chars()
            .take(12)
            .collect::<String>()
    );

    // Phase 1.3.1: Keygen CLI for E2E scripts.
    // Usage: `RISC0_SKIP_BUILD=1 cargo run --quiet --bin TET-Core -- --keygen`
    if std::env::args().any(|a| a == "--keygen") {
        use pqcrypto_kyber::kyber768;
        use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
        use x25519_dalek::{PublicKey, StaticSecret};

        let x_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let x_pk = PublicKey::from(&x_sk);
        let (k_pk, k_sk) = kyber768::keypair();

        println!(
            "export GEN_X25519_SK=\"{}\"",
            base64::engine::general_purpose::STANDARD.encode(x_sk.to_bytes())
        );
        println!(
            "export GEN_X25519_PK=\"{}\"",
            base64::engine::general_purpose::STANDARD.encode(x_pk.as_bytes())
        );
        println!(
            "export GEN_MLKEM_SK=\"{}\"",
            base64::engine::general_purpose::STANDARD.encode(k_sk.as_bytes())
        );
        println!(
            "export GEN_MLKEM_PK=\"{}\"",
            base64::engine::general_purpose::STANDARD.encode(k_pk.as_bytes())
        );
        return Ok(());
    }

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(5010);
    // Chaos tester mode (anti-fragility).
    // Usage: `TET-Core chaos-sim` (no server).
    if std::env::args().any(|a| a == "chaos-sim") {
        let r = crate::chaos::simulate_reroute(20_000, 1_000, 500);
        if !r.ok_no_loss {
            let err: AnyErr = Box::new(std::io::Error::other(
                "chaos-sim failed: shard loss detected",
            ));
            return Err(err);
        }
        println!(
            "CHAOS_SIM_OK workers_total={} workers_online_after={} shards_total={} rerouted_shards={}",
            r.workers_total, r.workers_online_after, r.shards_total, r.rerouted_shards
        );
        return Ok(());
    }
    let db_dir_base = std::env::var("TET_DB_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tet.db".to_string());
    // Local testnet: avoid sled lock collisions on a single host.
    // If the operator didn't specify a DB dir explicitly, namespace it by PORT.
    let db_dir = if std::env::var("TET_DB_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some()
    {
        db_dir_base.clone()
    } else {
        format!("{db_dir_base}_{port}")
    };
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

    // CRITICAL: never boot "prod" with a zero guest ID (happens when RISC0_SKIP_BUILD=1 stubs methods).
    if is_prod && NEXUS_GUEST_ID == [0u32; 8] {
        panic!("CRITICAL: ZK Guest ID is zero. Refusing to boot in production mode.");
    }
    let is_mainnet = std::env::var("TET_MAINNET")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if is_mainnet {
        let allow_mock_zk = std::env::var("TET_ALLOW_MOCK_ZK")
            .ok()
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if allow_mock_zk {
            panic!("CRITICAL: TET_MAINNET=1 forbids TET_ALLOW_MOCK_ZK=1.");
        }
        let has_founder = std::env::var("TET_GENESIS_FOUNDER_WALLET_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some();
        if !has_founder {
            panic!("CRITICAL: TET_MAINNET=1 requires TET_GENESIS_FOUNDER_WALLET_ID.");
        }
    }
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
            eprintln!(
                "[FATAL] Production mode requires an encryption key: set TET_DB_KEY_B64 (preferred) or TET_DB_KEY."
            );
            std::process::exit(2);
        }
    }

    if let Err(e) =
        tet_core::pqc_keystore::ensure_node_mldsa_keystore(std::path::Path::new(&db_dir))
    {
        log::warn!("ML-DSA node keystore: {e}");
    } else {
        log::info!("ML-DSA node keystore ready under `{db_dir}`");
    }

    let ledger = match Ledger::open(&db_dir) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("could not acquire lock on")
                || msg.contains("Resource temporarily unavailable")
                || msg.contains("WouldBlock")
            {
                fatal_db_lock_help(&db_dir, port, &e);
            }
            // LedgerError may not be Send+Sync; return a portable error type.
            let err: AnyErr = Box::new(std::io::Error::other(msg));
            return Err(err);
        }
    };
    ledger.init_genesis_founder_premine_from_env()?;

    // MVP tokenomics bootstrap: if ledger is empty, apply genesis to the Sovereign OS founder wallet
    // (`//Ferdie` pubkey hex). Must stay in sync with tet-network OsClient `FOUNDER_SIGNING_URI`.
    {
        let founder_wallet_id = std::env::var("TET_GENESIS_FOUNDER_WALLET_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_else(|| GENESIS_FOUNDER_DEV_PUBLIC_HEX.to_string());
        let supply0 = ledger.total_supply_micro().unwrap_or(0);
        if supply0 == 0 {
            let s = ledger
                .apply_genesis_allocation(&founder_wallet_id)
                .unwrap_or_else(|e| {
                    panic!(
                        "[ledger] FATAL: auto genesis (big bang) failed with supply unset/0: {e}"
                    )
                });
            log::info!(
                "[ledger] auto genesis OK founder={} total_supply_micro={}",
                s.founder_wallet_id,
                s.total_supply_micro
            );
        }
    }

    // Phase 1.1: Dev/test faucet for E2E loops (avoids "insufficient funds").
    // Guardrails:
    // - Disabled in prod/mainnet mode.
    // - Amount is explicit via env.
    if !is_prod
        && let Ok(v) = std::env::var("TET_DEV_FAUCET_MICRO")
        && let Ok(micro) = v.trim().parse::<u64>()
        && micro > 0
    {
        let payload = format!("dev_faucet|wallet={initial_wallet}|micro={micro}").into_bytes();
        match ledger.mint_reward_with_proof(&initial_wallet, micro, &payload, None, false) {
            Ok((_gross, net, _fee, _proof_id)) => {
                eprintln!(
                    "[dev] faucet credited micro={} (net={}) wallet={}",
                    micro, net, initial_wallet
                );
            }
            Err(e) => {
                eprintln!(
                    "[dev] faucet failed micro={} wallet={} err={}",
                    micro, initial_wallet, e
                );
            }
        }
    }

    if !is_prod
        && matches!(
            std::env::var("TET_DEV_FORCE_POC")
                .ok()
                .as_deref()
                .map(str::trim),
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
        )
    {
        let rec = crate::ledger::CaacWorkerRecord {
            role: "POC".to_string(),
            latency_ms: 1,
            seed_hex: "dev-force-poc".to_string(),
            server_wall_ms: 1,
        };
        if let Err(e) = ledger.caac_put_worker_record(&initial_wallet, &rec) {
            log::warn!("[dev] force POC CAAC record failed wallet={initial_wallet}: {e}");
        } else {
            log::info!("[dev] force POC CAAC record enabled wallet={initial_wallet}");
        }
    }

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

    // Phase 1/2 TET P2P engine (Gossipsub + Kademlia) — additive wiring.
    // Phase 3.3: On-chain worker registration/stake (localnet).
    if let Err(e) = crate::onchain::maybe_register_worker_before_p2p() {
        eprintln!("[onchain][warn] worker register/stake skipped or failed: {e}");
    }

    let nexus_p2p_client = match crate::p2p_network::start_p2p_node(ledger.clone()) {
        Ok((c, _jh)) => Some(c),
        Err(e) => {
            eprintln!("[p2p][warn] TET P2P engine failed to start: {e}");
            None
        }
    };

    let mempool = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    // Phase 0: libp2p local discovery mesh (mDNS + Ping).
    // Runs behind the HTTP server, listens on tcp/0 (ephemeral), logs PeerId + listen addr.
    let gossip_tx = if enable_p2p {
        match crate::p2p::start_mdns_ping_swarm(ledger.clone(), mempool.clone()) {
            Ok(tx) => Some(tx),
            Err(e) => {
                eprintln!("[p2p][warn] failed to start mdns/ping/gossip swarm: {e}");
                None
            }
        }
    } else {
        None
    };

    let bind = std::env::var("TET_REST_BIND")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("0.0.0.0:{port}"));
    let addr: SocketAddr = bind.parse()?;

    let http_rps = std::env::var("TET_HTTP_RPS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(25)
        .max(1);

    let (log_tx, _log_rx) = broadcast::channel::<String>(100);

    let state = RestState {
        ledger,
        solana: Arc::new(crate::ledger::solana_client::NexusSolanaClient::devnet()),
        p2p_tx: p2p,
        p2p_client: nexus_p2p_client,
        gossip_tx,
        mempool,
        http_ratelimit: Arc::new(tokio::sync::Mutex::new(HttpRateLimit::new(http_rps))),
        workers: Arc::new(StdMutex::new(WorkerRegistry::default())),
        e2ee_jobs: Arc::new(StdMutex::new(crate::rest::E2eeJobQueue::default())),
        dex: Arc::new(StdMutex::new(crate::p2p_dex::DexEngine::default())),
        genesis_1k_lock: Arc::new(tokio::sync::Mutex::new(())),
        log_tx,
        log_sse_connections: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };

    if crate::consensus::auto_mine_enabled_from_env() {
        let consensus_node_id = initial_wallet.trim().to_ascii_lowercase();
        let validator_set = crate::consensus::ValidatorSet::from_env_or_single(&consensus_node_id);
        let _auto_miner =
            crate::consensus::spawn_auto_miner(state.clone(), consensus_node_id, validator_set);
    }

    if crate::worker_daemon::should_start_worker_daemon(&state.ledger, &initial_wallet) {
        if let Some(mnemonic) = crate::worker_daemon::worker_daemon_mnemonic_from_env() {
            let _worker_daemon = crate::worker_daemon::spawn_worker_daemon(
                state.clone(),
                initial_wallet.trim().to_ascii_lowercase(),
                mnemonic,
            );
        } else {
            log::warn!(
                "[worker-daemon] POC role detected but no TET_WORKER_MNEMONIC/TET_WALLET_MNEMONIC is configured; daemon not started"
            );
        }
    } else {
        log::info!("[worker-daemon] not started: node is not POC or daemon disabled");
    }

    serve(state, addr).await?;
    Ok(())
}
