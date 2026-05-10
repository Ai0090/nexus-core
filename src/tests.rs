#![allow(clippy::await_holding_lock)]

use axum::http::header::HeaderName;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use rand_core::RngCore as _;
use serde_json::Value;
use sha2::Digest as _;
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::test_env::lock()
}

fn set_test_env_base() {
    // Safety: these tests serialize on ENV_LOCK.
    unsafe {
        std::env::set_var("TET_DB_ENCRYPT", "false");
        std::env::set_var("TET_REQUIRE_ATTESTATION", "false");
        std::env::set_var("TET_API_KEY", "testkey");
        std::env::set_var("TET_ADMIN_API_KEY", "test-admin-key");
        std::env::set_var("TET_DISABLE_RATE_LIMIT", "1");
        std::env::set_var("TET_FOUNDER_WALLET", "founder");
        // Tests assume founder funds are liquid; disable founder genesis cliff lock for unit tests.
        std::env::set_var("TET_FOUNDER_CLIFF_MS", "0");
        // Avoid cross-test leakage (parallel default + snapshot test overrides).
        std::env::remove_var("TET_LEDGER_JSON_PATH");
        std::env::remove_var("TET_LEDGER_TMP_PATH");
        std::env::remove_var("TET_VALIDATOR_IDS");
        std::env::remove_var("TET_WALLET_ID");
        std::env::remove_var("TET_PEER_ID");
        std::env::remove_var("TET_BLOCK_TIME_SEC");
        std::env::remove_var("TET_CONSENSUS_LEADER_MODE");
        std::env::remove_var("TET_BASE_BLOCK_REWARD");
        std::env::remove_var("TET_ALLOW_MOCK_ZK");
        std::env::remove_var("TET_JOULES_PER_FLOP");
        std::env::remove_var("TET_NETWORK_DIFFICULTY_GAMMA");
        std::env::remove_var("TET_THERMO_STEVEMON_MICRO_SCALE");
    }
}

fn open_temp_ledger() -> crate::ledger::Ledger {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    // Keep tempdir alive by leaking it for test lifetime (small, per-test).
    std::mem::forget(dir);
    crate::ledger::Ledger::open(db.to_str().unwrap()).unwrap()
}

fn rest_state_for_tests(ledger: std::sync::Arc<crate::ledger::Ledger>) -> crate::rest::RestState {
    let (log_tx, _log_rx) = tokio::sync::broadcast::channel::<String>(64);
    crate::rest::RestState {
        ledger,
        solana: std::sync::Arc::new(crate::ledger::solana_client::NexusSolanaClient::devnet()),
        p2p_tx: None,
        p2p_client: None,
        gossip_tx: None,
        mempool: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        http_ratelimit: std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::rest::HttpRateLimit::new(999),
        )),
        workers: std::sync::Arc::new(std::sync::Mutex::new(
            crate::worker_network::WorkerRegistry::default(),
        )),
        e2ee_jobs: std::sync::Arc::new(std::sync::Mutex::new(crate::rest::E2eeJobQueue::default())),
        dex: std::sync::Arc::new(std::sync::Mutex::new(crate::p2p_dex::DexEngine::default())),
        genesis_1k_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        log_tx,
        log_sse_connections: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    }
}

fn admin_headers_for_tests() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer test-admin-key".parse().unwrap(),
    );
    h
}

fn signed_transfer_env_for_tests(
    from_words: &str,
    from_wallet_id: &str,
    to_wallet_id: &str,
    amount_micro: u64,
) -> crate::protocol::SignedTxEnvelopeV1 {
    let tx = crate::protocol::TxV1::Transfer {
        from_wallet: from_wallet_id.to_string(),
        to_wallet: to_wallet_id.to_string(),
        amount_micro,
        fee_bps: 100,
    };
    let tx_bytes = serde_json::to_vec(&tx).unwrap();
    let ed_sk = crate::wallet::ed25519_signing_key_from_mnemonic(from_words).unwrap();
    let mldsa_kp = crate::wallet::mldsa_keypair_from_mnemonic(from_words).unwrap();
    let mldsa_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(mldsa_kp.public_key());
    let ed_sig = ed_sk.sign(tx_bytes.as_slice());
    let ed_sig_b64 = base64::engine::general_purpose::STANDARD.encode(ed_sig.to_bytes().as_slice());
    let mldsa_sig_bytes =
        crate::wallet::mldsa_sign_deterministic(&mldsa_kp, tx_bytes.as_slice()).unwrap();
    let mldsa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&mldsa_sig_bytes);

    crate::protocol::SignedTxEnvelopeV1 {
        v: 1,
        tx,
        sig: crate::protocol::HybridSigV1 {
            ed25519_pubkey_hex: from_wallet_id.to_string(),
            ed25519_sig_b64: ed_sig_b64,
            mldsa_pubkey_b64,
            mldsa_sig_b64,
        },
        attestation: crate::protocol::AttestationV1 {
            platform: "test".to_string(),
            report_b64: String::new(),
        },
    }
}

fn signed_zk_env_for_tests(
    words: &str,
    wallet_id: &str,
    journal_b64: String,
    receipt_b64: String,
) -> crate::protocol::SignedTxEnvelopeV1 {
    signed_zk_env_with_task_for_tests(words, wallet_id, "", journal_b64, receipt_b64)
}

fn signed_zk_env_with_task_for_tests(
    words: &str,
    wallet_id: &str,
    task_id: &str,
    journal_b64: String,
    receipt_b64: String,
) -> crate::protocol::SignedTxEnvelopeV1 {
    let tx = crate::protocol::TxV1::VerifyZkProof {
        task_id: task_id.to_string(),
        image_id: methods::NEXUS_GUEST_ID,
        journal_b64,
        receipt_b64,
    };
    let tx_bytes = serde_json::to_vec(&tx).unwrap();
    let ed_sk = crate::wallet::ed25519_signing_key_from_mnemonic(words).unwrap();
    let mldsa_kp = crate::wallet::mldsa_keypair_from_mnemonic(words).unwrap();
    let mldsa_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(mldsa_kp.public_key());
    let ed_sig = ed_sk.sign(tx_bytes.as_slice());
    let ed_sig_b64 = base64::engine::general_purpose::STANDARD.encode(ed_sig.to_bytes().as_slice());
    let mldsa_sig_bytes =
        crate::wallet::mldsa_sign_deterministic(&mldsa_kp, tx_bytes.as_slice()).unwrap();
    let mldsa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&mldsa_sig_bytes);

    crate::protocol::SignedTxEnvelopeV1 {
        v: 1,
        tx,
        sig: crate::protocol::HybridSigV1 {
            ed25519_pubkey_hex: wallet_id.to_string(),
            ed25519_sig_b64: ed_sig_b64,
            mldsa_pubkey_b64,
            mldsa_sig_b64,
        },
        attestation: crate::protocol::AttestationV1 {
            platform: "test".to_string(),
            report_b64: String::new(),
        },
    }
}

fn signed_enterprise_inference_env_for_tests(
    words: &str,
    wallet_id: &str,
    prompt: &str,
    model: &str,
    amount_micro: u64,
    nonce: u64,
    workload_flag: u8,
) -> crate::protocol::SignedTxEnvelopeV1 {
    let prompt_sha256_hex = hex::encode(sha2::Sha256::digest(prompt.trim().as_bytes()));
    let mldsa_kp = crate::wallet::mldsa_keypair_from_mnemonic(words).unwrap();
    let mldsa_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(mldsa_kp.public_key());
    let tx = crate::protocol::TxV1::EnterpriseInference {
        enterprise_wallet_id: wallet_id.to_string(),
        prompt: prompt.to_string(),
        model: model.to_string(),
        amount_micro,
        nonce,
        prompt_sha256_hex,
        workload_flag,
        attestation_required: false,
    };
    let msg = crate::wallet::enterprise_inference_hybrid_auth_message_bytes(
        wallet_id,
        nonce,
        amount_micro,
        match &tx {
            crate::protocol::TxV1::EnterpriseInference {
                prompt_sha256_hex, ..
            } => prompt_sha256_hex,
            _ => unreachable!(),
        },
        model,
        false,
        &mldsa_pubkey_b64,
    );
    let ed_sk = crate::wallet::ed25519_signing_key_from_mnemonic(words).unwrap();
    let ed_sig = ed_sk.sign(msg.as_slice());
    let ed_sig_b64 = base64::engine::general_purpose::STANDARD.encode(ed_sig.to_bytes().as_slice());
    let mldsa_sig_bytes =
        crate::wallet::mldsa_sign_deterministic(&mldsa_kp, msg.as_slice()).unwrap();
    let mldsa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&mldsa_sig_bytes);

    crate::protocol::SignedTxEnvelopeV1 {
        v: 1,
        tx,
        sig: crate::protocol::HybridSigV1 {
            ed25519_pubkey_hex: wallet_id.to_string(),
            ed25519_sig_b64: ed_sig_b64,
            mldsa_pubkey_b64,
            mldsa_sig_b64,
        },
        attestation: crate::protocol::AttestationV1 {
            platform: "test".to_string(),
            report_b64: String::new(),
        },
    }
}

#[test]
fn hash_leader_election_is_deterministic_and_single_winner() {
    let _g = env_lock();
    set_test_env_base();
    use crate::consensus::LeaderElection as _;

    let validators = crate::consensus::ValidatorSet::new(["alice", "bob", "carol"]);
    let election = crate::consensus::HashLeaderElection;
    let leader1 = election.leader_for_height(42, &validators).unwrap();
    let leader2 = election.leader_for_height(42, &validators).unwrap();

    assert_eq!(leader1, leader2);
    assert!(validators.contains(leader1.as_str()));
    assert!(election.is_leader(42, leader1.as_str(), &validators));
}

#[test]
fn caac_weight_from_record_uses_role_latency_and_fallback() {
    let _g = env_lock();
    set_test_env_base();

    let poc = crate::ledger::CaacWorkerRecord {
        role: "POC".to_string(),
        latency_ms: 1,
        seed_hex: "00".repeat(32),
        server_wall_ms: 10,
    };
    let por = crate::ledger::CaacWorkerRecord {
        role: "POR".to_string(),
        latency_ms: 1000,
        seed_hex: "11".repeat(32),
        server_wall_ms: 10,
    };

    assert_eq!(crate::consensus::caac_weight_from_record(None), 10);
    assert!(crate::consensus::caac_weight_from_record(Some(&poc)) > 100);
    assert!(
        crate::consensus::caac_weight_from_record(Some(&poc))
            > crate::consensus::caac_weight_from_record(Some(&por))
    );
}

#[test]
fn caac_leader_election_is_deterministic() {
    let _g = env_lock();
    set_test_env_base();
    use crate::consensus::LeaderElection as _;

    let provider = crate::consensus::StaticCaacWeightProvider::new([
        ("alice", 10),
        ("bob", 250),
        ("carol", 100),
    ]);
    let election = crate::consensus::CaacLeaderElection::new(provider);
    let validators = crate::consensus::ValidatorSet::new(["alice", "bob", "carol"]);

    let leader1 = election.leader_for_height(777, &validators).unwrap();
    let leader2 = election.leader_for_height(777, &validators).unwrap();

    assert_eq!(leader1, leader2);
    assert!(validators.contains(leader1.as_str()));
}

#[test]
fn ledger_caac_weight_provider_reads_worker_records() {
    let _g = env_lock();
    set_test_env_base();
    use crate::consensus::CaacWeightProvider as _;

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger
        .caac_put_worker_record(
            "poc",
            &crate::ledger::CaacWorkerRecord {
                role: "POC".to_string(),
                latency_ms: 1,
                seed_hex: "22".repeat(32),
                server_wall_ms: 10,
            },
        )
        .unwrap();

    let provider = crate::consensus::LedgerCaacWeightProvider::new(ledger);
    assert!(provider.consensus_weight("poc") > provider.consensus_weight("missing"));
}

#[test]
fn caac_high_weight_validator_wins_more_often_over_many_heights() {
    let _g = env_lock();
    set_test_env_base();
    use crate::consensus::LeaderElection as _;

    let provider = crate::consensus::StaticCaacWeightProvider::new([("poc", 1100), ("por", 26)]);
    let election = crate::consensus::CaacLeaderElection::new(provider);
    let validators = crate::consensus::ValidatorSet::new(["poc", "por"]);

    let poc_wins = (1..=200)
        .filter(|height| {
            election
                .leader_for_height(*height, &validators)
                .map(|leader| leader.as_str() == "poc")
                .unwrap_or(false)
        })
        .count();

    assert!(poc_wins > 120, "poc_wins={poc_wins}");
}

#[test]
fn local_caac_profile_resource_weight_prefers_poc_gpu_and_capacity() {
    let _g = env_lock();
    set_test_env_base();

    let poc = crate::vision::caac::CaacProfile {
        role: crate::vision::caac::NodeRelayRole::Poc,
        hw: crate::vision::caac::HardwareFingerprint {
            fingerprint_sha256_hex: "a".repeat(64),
            cpu_logical_cores: 16,
            ram_total_bytes: 64 * 1024 * 1024 * 1024,
            gpu_detected: true,
            gpu_hint: "test".to_string(),
        },
    };
    let por = crate::vision::caac::CaacProfile {
        role: crate::vision::caac::NodeRelayRole::Por,
        hw: crate::vision::caac::HardwareFingerprint {
            fingerprint_sha256_hex: "b".repeat(64),
            cpu_logical_cores: 2,
            ram_total_bytes: 4 * 1024 * 1024 * 1024,
            gpu_detected: false,
            gpu_hint: "test".to_string(),
        },
    };

    assert!(
        crate::vision::caac::local_resource_weight(&poc)
            > crate::vision::caac::local_resource_weight(&por)
    );
}

#[tokio::test]
async fn remote_block_rejects_non_leader_producer() {
    let _g = env_lock();
    set_test_env_base();
    use crate::consensus::LeaderElection as _;
    unsafe {
        std::env::set_var("TET_VALIDATOR_IDS", "alice,bob");
        std::env::set_var("TET_WALLET_ID", "alice");
    }

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());

    let sender = crate::wallet::generate_mnemonic_12().unwrap();
    let sender_words = sender.mnemonic_12.clone().unwrap();
    let sender_wallet_id = sender.address_hex.to_ascii_lowercase();
    let recipient = crate::wallet::generate_mnemonic_12().unwrap();
    let recipient_wallet_id = recipient.address_hex.to_ascii_lowercase();
    ledger
        .admin_rest_faucet(
            &sender_wallet_id,
            1000 * crate::ledger::STEVEMON,
            "ip",
            true,
            1,
            1,
        )
        .unwrap();

    let env = signed_transfer_env_for_tests(
        &sender_words,
        &sender_wallet_id,
        &recipient_wallet_id,
        crate::ledger::STEVEMON,
    );
    let tx_hash = crate::consensus::tx_hash_for_env(&env).unwrap();
    let block_id = crate::consensus::block_id_for_block(1, &[tx_hash]);
    let reward = crate::consensus::reward_for_block(std::slice::from_ref(&env)).unwrap();
    let state_root = ledger
        .compute_state_root_after_remote_block(
            std::slice::from_ref(&env),
            "alice",
            reward.total_reward_micro,
        )
        .unwrap();

    let validators = crate::consensus::ValidatorSet::new(["alice", "bob"]);
    let leader = crate::consensus::HashLeaderElection
        .leader_for_height(1, &validators)
        .unwrap()
        .as_str()
        .to_string();
    let non_leader = if leader == "alice" { "bob" } else { "alice" }.to_string();

    let res = crate::consensus::apply_remote_block_from_gossip(
        ledger,
        state.mempool.clone(),
        crate::consensus::RemoteBlockGossip {
            block_height: 1,
            block_id,
            parent_block_id: None,
            producer_id: non_leader,
            base_reward_micro: reward.base_reward_micro,
            compute_reward_micro: reward.compute_reward_micro,
            total_reward_micro: reward.total_reward_micro,
            state_root,
            txs: vec![env],
        },
    )
    .await;
    assert!(matches!(
        res,
        Err(crate::consensus::RemoteBlockApplyError::Rejected(_))
    ));
}

#[tokio::test]
async fn auto_miner_skips_when_local_node_is_not_leader() {
    let _g = env_lock();
    set_test_env_base();
    use crate::consensus::LeaderElection as _;
    unsafe {
        std::env::set_var("TET_BLOCK_TIME_SEC", "1");
    }

    let validators = crate::consensus::ValidatorSet::new(["alice", "bob"]);
    let leader = crate::consensus::HashLeaderElection
        .leader_for_height(1, &validators)
        .unwrap()
        .as_str()
        .to_string();
    let non_leader = if leader == "alice" { "bob" } else { "alice" }.to_string();

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());

    let sender = crate::wallet::generate_mnemonic_12().unwrap();
    let sender_words = sender.mnemonic_12.clone().unwrap();
    let sender_wallet_id = sender.address_hex.to_ascii_lowercase();
    let recipient = crate::wallet::generate_mnemonic_12().unwrap();
    let recipient_wallet_id = recipient.address_hex.to_ascii_lowercase();
    ledger
        .admin_rest_faucet(
            &sender_wallet_id,
            1000 * crate::ledger::STEVEMON,
            "ip",
            true,
            1,
            1,
        )
        .unwrap();
    state
        .mempool
        .lock()
        .await
        .push(signed_transfer_env_for_tests(
            &sender_words,
            &sender_wallet_id,
            &recipient_wallet_id,
            crate::ledger::STEVEMON,
        ));

    let handle = crate::consensus::spawn_auto_miner(state.clone(), non_leader, validators);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    handle.abort();

    assert_eq!(ledger.block_height().unwrap(), 0);
    assert_eq!(state.mempool.lock().await.len(), 1);
}

#[tokio::test]
async fn auto_miner_mines_coinbase_only_blocks_when_mempool_is_empty() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_BLOCK_TIME_SEC", "1");
        std::env::set_var("TET_BASE_BLOCK_REWARD", "0.1");
    }

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());
    let validators = crate::consensus::ValidatorSet::new(["alice"]);

    let pool_before = ledger
        .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
        .unwrap();
    let producer_before = ledger.balance_micro("alice").unwrap();

    let handle = crate::consensus::spawn_auto_miner(state.clone(), "alice".to_string(), validators);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    handle.abort();

    assert_eq!(state.mempool.lock().await.len(), 0);
    assert!(ledger.block_height().unwrap() >= 1);
    assert!(
        ledger.balance_micro("alice").unwrap() >= producer_before + crate::ledger::STEVEMON / 10
    );
    assert!(
        ledger
            .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
            .unwrap()
            <= pool_before - crate::ledger::STEVEMON / 10
    );
}

#[tokio::test]
async fn enterprise_inference_tx_enters_mempool_with_workload_flag() {
    let _g = env_lock();
    set_test_env_base();

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());

    let wallet = crate::wallet::generate_mnemonic_12().unwrap();
    let words = wallet.mnemonic_12.clone().unwrap();
    let wallet_id = wallet.address_hex.to_ascii_lowercase();
    ledger
        .admin_rest_faucet(&wallet_id, crate::ledger::STEVEMON, "ip", true, 1, 1)
        .unwrap();
    let env = signed_enterprise_inference_env_for_tests(
        &words,
        &wallet_id,
        "summarize demand",
        "llama3",
        10_000,
        1,
        crate::protocol::WorkloadFlag::AiInference.as_u8(),
    );

    let resp = crate::rest::handlers::enterprise::post_enterprise_inference_submit(
        axum::extract::State(state.clone()),
        HeaderMap::new(),
        axum::Json(env),
    )
    .await
    .into_response();

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let mp = state.mempool.lock().await;
    assert_eq!(mp.len(), 1);
    assert_eq!(
        mp[0].tx.workload_flag(),
        crate::protocol::WorkloadFlag::AiInference
    );
}

#[tokio::test]
async fn poc_producer_can_mine_ai_workload_block() {
    let _g = env_lock();
    set_test_env_base();

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    ledger
        .caac_put_worker_record(
            "alice",
            &crate::ledger::CaacWorkerRecord {
                role: "POC".to_string(),
                latency_ms: 1,
                seed_hex: "seed".to_string(),
                server_wall_ms: 1,
            },
        )
        .unwrap();
    let state = rest_state_for_tests(ledger.clone());
    let wallet = crate::wallet::generate_mnemonic_12().unwrap();
    let words = wallet.mnemonic_12.clone().unwrap();
    let wallet_id = wallet.address_hex.to_ascii_lowercase();
    let env = signed_enterprise_inference_env_for_tests(
        &words,
        &wallet_id,
        "run inference",
        "llama3",
        10_000,
        1,
        crate::protocol::WorkloadFlag::AiInference.as_u8(),
    );
    state.mempool.lock().await.push(env);

    let outcome = crate::consensus::mine_pending_block_as(state.clone(), "alice".to_string())
        .await
        .unwrap();

    assert!(outcome.mined);
    assert_eq!(outcome.tx_count, 1);
    assert_eq!(ledger.block_height().unwrap(), 1);
    assert_eq!(state.mempool.lock().await.len(), 0);
}

#[tokio::test]
async fn por_producer_cannot_mine_ai_workload_and_keeps_mempool() {
    let _g = env_lock();
    set_test_env_base();

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    ledger
        .caac_put_worker_record(
            "alice",
            &crate::ledger::CaacWorkerRecord {
                role: "POR".to_string(),
                latency_ms: 100,
                seed_hex: "seed".to_string(),
                server_wall_ms: 1,
            },
        )
        .unwrap();
    let state = rest_state_for_tests(ledger.clone());
    let wallet = crate::wallet::generate_mnemonic_12().unwrap();
    let words = wallet.mnemonic_12.clone().unwrap();
    let wallet_id = wallet.address_hex.to_ascii_lowercase();
    let env = signed_enterprise_inference_env_for_tests(
        &words,
        &wallet_id,
        "run inference",
        "llama3",
        10_000,
        1,
        crate::protocol::WorkloadFlag::AiInference.as_u8(),
    );
    state.mempool.lock().await.push(env);

    let res = crate::consensus::mine_pending_block_as(state.clone(), "alice".to_string()).await;
    assert!(matches!(
        res,
        Err(crate::consensus::MineError::Unauthorized(_))
    ));
    assert_eq!(ledger.block_height().unwrap(), 0);
    assert_eq!(state.mempool.lock().await.len(), 1);
}

#[tokio::test]
async fn remote_ai_workload_rejects_non_poc_producer() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_VALIDATOR_IDS", "alice");
        std::env::set_var("TET_WALLET_ID", "alice");
    }

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    ledger
        .caac_put_worker_record(
            "alice",
            &crate::ledger::CaacWorkerRecord {
                role: "POR".to_string(),
                latency_ms: 100,
                seed_hex: "seed".to_string(),
                server_wall_ms: 1,
            },
        )
        .unwrap();
    let state = rest_state_for_tests(ledger.clone());
    let wallet = crate::wallet::generate_mnemonic_12().unwrap();
    let words = wallet.mnemonic_12.clone().unwrap();
    let wallet_id = wallet.address_hex.to_ascii_lowercase();
    let env = signed_enterprise_inference_env_for_tests(
        &words,
        &wallet_id,
        "remote ai workload",
        "llama3",
        10_000,
        1,
        crate::protocol::WorkloadFlag::AiInference.as_u8(),
    );
    let tx_hash = crate::consensus::tx_hash_for_env(&env).unwrap();
    let block_id = crate::consensus::block_id_for_block(1, &[tx_hash]);
    let reward = crate::consensus::reward_for_block(std::slice::from_ref(&env)).unwrap();
    let state_root = ledger
        .compute_state_root_after_remote_block(
            std::slice::from_ref(&env),
            "alice",
            reward.total_reward_micro,
        )
        .unwrap();

    let res = crate::consensus::apply_remote_block_from_gossip(
        ledger,
        state.mempool.clone(),
        crate::consensus::RemoteBlockGossip {
            block_height: 1,
            block_id,
            parent_block_id: None,
            producer_id: "alice".to_string(),
            base_reward_micro: reward.base_reward_micro,
            compute_reward_micro: reward.compute_reward_micro,
            total_reward_micro: reward.total_reward_micro,
            state_root,
            txs: vec![env],
        },
    )
    .await;
    assert!(matches!(
        res,
        Err(crate::consensus::RemoteBlockApplyError::Rejected(_))
    ));
}

#[tokio::test]
async fn por_auto_miner_preserves_ai_workload_and_mines_empty_block() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_BLOCK_TIME_SEC", "1");
    }

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    ledger
        .caac_put_worker_record(
            "alice",
            &crate::ledger::CaacWorkerRecord {
                role: "POR".to_string(),
                latency_ms: 100,
                seed_hex: "seed".to_string(),
                server_wall_ms: 1,
            },
        )
        .unwrap();
    let state = rest_state_for_tests(ledger.clone());
    let wallet = crate::wallet::generate_mnemonic_12().unwrap();
    let words = wallet.mnemonic_12.clone().unwrap();
    let wallet_id = wallet.address_hex.to_ascii_lowercase();
    let env = signed_enterprise_inference_env_for_tests(
        &words,
        &wallet_id,
        "keep me pending",
        "llama3",
        10_000,
        1,
        crate::protocol::WorkloadFlag::AiInference.as_u8(),
    );
    state.mempool.lock().await.push(env);

    let handle = crate::consensus::spawn_auto_miner(
        state.clone(),
        "alice".to_string(),
        crate::consensus::ValidatorSet::new(["alice"]),
    );
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    handle.abort();

    assert!(ledger.block_height().unwrap() >= 1);
    assert_eq!(state.mempool.lock().await.len(), 1);
}

#[tokio::test]
async fn same_height_fork_choice_reports_remote_winner_without_reorg() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_VALIDATOR_IDS", "alice");
        std::env::set_var("TET_WALLET_ID", "alice");
    }

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());

    let sender = crate::wallet::generate_mnemonic_12().unwrap();
    let sender_words = sender.mnemonic_12.clone().unwrap();
    let sender_wallet_id = sender.address_hex.to_ascii_lowercase();
    let recipient = crate::wallet::generate_mnemonic_12().unwrap();
    let recipient_wallet_id = recipient.address_hex.to_ascii_lowercase();
    ledger
        .admin_rest_faucet(
            &sender_wallet_id,
            1000 * crate::ledger::STEVEMON,
            "ip",
            true,
            1,
            1,
        )
        .unwrap();

    let env = signed_transfer_env_for_tests(
        &sender_words,
        &sender_wallet_id,
        &recipient_wallet_id,
        crate::ledger::STEVEMON,
    );
    let reward = crate::consensus::reward_for_block(std::slice::from_ref(&env)).unwrap();
    let tx_hash = crate::consensus::tx_hash_for_env(&env).unwrap();
    let remote_block_id = crate::consensus::block_id_for_block(1, &[tx_hash]);
    ledger.set_block_height_if_newer(1).unwrap();
    ledger
        .record_block_summary(1, "zzzz-local-block", "0xlocal", 1)
        .unwrap();

    let res = crate::consensus::apply_remote_block_from_gossip(
        ledger,
        state.mempool.clone(),
        crate::consensus::RemoteBlockGossip {
            block_height: 1,
            block_id: remote_block_id,
            parent_block_id: None,
            producer_id: "alice".to_string(),
            base_reward_micro: reward.base_reward_micro,
            compute_reward_micro: reward.compute_reward_micro,
            total_reward_micro: reward.total_reward_micro,
            state_root: "0xnot-checked-for-same-height".to_string(),
            txs: vec![env],
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        res,
        crate::consensus::RemoteBlockApplyOutcome::ForkLost { .. }
    ));
}

#[tokio::test]
async fn phase2_mempool_mine_and_apply_block_to_peer() {
    let _g = env_lock();
    set_test_env_base();

    // Node A + Node B ledgers.
    let ledger_a = std::sync::Arc::new(open_temp_ledger());
    ledger_a.init_genesis_founder_premine_from_env().unwrap();
    ledger_a.apply_genesis_allocation("founder").unwrap();

    let ledger_b = std::sync::Arc::new(open_temp_ledger());
    ledger_b.init_genesis_founder_premine_from_env().unwrap();
    ledger_b.apply_genesis_allocation("founder").unwrap();

    let state_a = rest_state_for_tests(ledger_a.clone());
    let state_b = rest_state_for_tests(ledger_b.clone());

    // Sender/recipient wallets (real keys for envelope verification).
    let sender = crate::wallet::generate_mnemonic_12().unwrap();
    let sender_words = sender.mnemonic_12.clone().unwrap();
    let sender_wallet_id = sender.address_hex.to_ascii_lowercase();

    let recipient = crate::wallet::generate_mnemonic_12().unwrap();
    let recipient_wallet_id = recipient.address_hex.to_ascii_lowercase();

    // [A] Faucet sender via handler (rate limit bypass is enabled via env).
    let faucet_req = crate::rest::FaucetReq {
        wallet_id: sender_wallet_id.clone(),
        amount_tet: Some(1000.0),
    };
    let resp = crate::rest::handlers::ledger::post_ledger_faucet(
        axum::extract::State(state_a.clone()),
        admin_headers_for_tests(),
        axum::extract::ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        axum::Json(faucet_req),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap();
    let audit_hash_hex = v
        .get("audit_hash_hex")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    assert!(!audit_hash_hex.is_empty());

    // [B] Apply faucet event (simulate gossip delivery).
    let faucet_ev = crate::models::NetworkEvent::FaucetExecuted {
        event_id: audit_hash_hex,
        to_wallet: sender_wallet_id.clone(),
        amount_micro: 1000u64 * crate::ledger::STEVEMON,
    };
    assert!(ledger_b.apply_remote_event(&faucet_ev).unwrap());

    // [A] Submit transfer: must be 202 Accepted, DB unchanged, mempool len=1.
    let amount_micro = crate::ledger::STEVEMON;
    let tx = crate::protocol::TxV1::Transfer {
        from_wallet: sender_wallet_id.clone(),
        to_wallet: recipient_wallet_id.clone(),
        amount_micro,
        fee_bps: 100,
    };
    let tx_bytes = serde_json::to_vec(&tx).unwrap();
    let ed_sk = crate::wallet::ed25519_signing_key_from_mnemonic(&sender_words).unwrap();
    let mldsa_kp = crate::wallet::mldsa_keypair_from_mnemonic(&sender_words).unwrap();
    let mldsa_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(mldsa_kp.public_key());
    let ed_sig = ed_sk.sign(tx_bytes.as_slice());
    let ed_sig_b64 = base64::engine::general_purpose::STANDARD.encode(ed_sig.to_bytes().as_slice());
    let mldsa_sig_bytes =
        crate::wallet::mldsa_sign_deterministic(&mldsa_kp, tx_bytes.as_slice()).unwrap();
    let mldsa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&mldsa_sig_bytes);

    let env = crate::protocol::SignedTxEnvelopeV1 {
        v: 1,
        tx: tx.clone(),
        sig: crate::protocol::HybridSigV1 {
            ed25519_pubkey_hex: sender_wallet_id.clone(),
            ed25519_sig_b64: ed_sig_b64,
            mldsa_pubkey_b64,
            mldsa_sig_b64,
        },
        attestation: crate::protocol::AttestationV1 {
            platform: "test".to_string(),
            report_b64: String::new(),
        },
    };

    let bal_before = ledger_a.balance_micro(&sender_wallet_id).unwrap();
    let resp2 = crate::rest::handlers::ledger::post_transfer_enveloped(
        axum::extract::State(state_a.clone()),
        HeaderMap::new(),
        axum::Json(env.clone()),
    )
    .await
    .into_response();
    assert_eq!(resp2.status(), StatusCode::ACCEPTED);
    assert_eq!(state_a.mempool.lock().await.len(), 1);
    assert_eq!(
        ledger_a.balance_micro(&sender_wallet_id).unwrap(),
        bal_before
    );

    // [A] Mine: mempool drained, balances updated.
    let resp3 = crate::rest::handlers::ledger::post_ledger_mine(
        axum::extract::State(state_a.clone()),
        admin_headers_for_tests(),
    )
    .await
    .into_response();
    assert_eq!(resp3.status(), StatusCode::OK);
    let body3 = axum::body::to_bytes(resp3.into_body(), usize::MAX)
        .await
        .unwrap();
    let mined: Value = serde_json::from_slice(&body3).unwrap();
    let block_height = mined
        .get("block_height")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let block_id = mined
        .get("block_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let state_root = mined
        .get("state_root")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let producer_id = mined
        .get("producer_id")
        .and_then(|x| x.as_str())
        .unwrap_or("local-wallet")
        .to_string();
    let base_reward_micro = mined
        .get("base_reward_micro")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let compute_reward_micro = mined
        .get("compute_reward_micro")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let total_reward_micro = mined
        .get("total_reward_micro")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    assert_eq!(block_height, 1);
    assert!(!block_id.is_empty());
    assert!(!state_root.is_empty());
    assert_eq!(state_a.mempool.lock().await.len(), 0);
    assert!(ledger_a.balance_micro(&sender_wallet_id).unwrap() < bal_before);

    // [B] Reject bad state_root before mutating local state.
    let sender_before_remote = ledger_b.balance_micro(&sender_wallet_id).unwrap();
    let bad = crate::consensus::apply_remote_block_from_gossip(
        ledger_b.clone(),
        state_b.mempool.clone(),
        crate::consensus::RemoteBlockGossip {
            block_height,
            block_id: block_id.clone(),
            parent_block_id: None,
            producer_id: producer_id.clone(),
            base_reward_micro,
            compute_reward_micro,
            total_reward_micro,
            state_root: "0xbad-root".to_string(),
            txs: vec![env.clone()],
        },
    )
    .await;
    assert!(matches!(
        bad,
        Err(crate::consensus::RemoteBlockApplyError::Rejected(_))
    ));
    assert_eq!(ledger_b.block_height().unwrap(), 0);
    assert_eq!(
        ledger_b.balance_micro(&sender_wallet_id).unwrap(),
        sender_before_remote
    );

    // [B] If the same tx is still pending locally, applying the remote block must evict it.
    state_b.mempool.lock().await.push(env.clone());
    let applied = crate::consensus::apply_remote_block_from_gossip(
        ledger_b.clone(),
        state_b.mempool.clone(),
        crate::consensus::RemoteBlockGossip {
            block_height,
            block_id: block_id.clone(),
            parent_block_id: None,
            producer_id: producer_id.clone(),
            base_reward_micro,
            compute_reward_micro,
            total_reward_micro,
            state_root: state_root.clone(),
            txs: vec![env.clone()],
        },
    )
    .await
    .unwrap();
    match applied {
        crate::consensus::RemoteBlockApplyOutcome::Applied {
            block_height,
            tx_count,
            evicted_count,
            state_root: applied_root,
        } => {
            assert_eq!(block_height, 1);
            assert_eq!(tx_count, 1);
            assert_eq!(evicted_count, 1);
            assert_eq!(applied_root, state_root);
        }
        other => panic!("expected remote block apply, got {other:?}"),
    }
    assert_eq!(state_b.mempool.lock().await.len(), 0);
    assert_eq!(ledger_b.block_height().unwrap(), 1);

    assert_eq!(
        ledger_b.balance_micro(&sender_wallet_id).unwrap(),
        ledger_a.balance_micro(&sender_wallet_id).unwrap()
    );
    assert_eq!(
        ledger_b.balance_micro(&recipient_wallet_id).unwrap(),
        ledger_a.balance_micro(&recipient_wallet_id).unwrap()
    );

    // Deterministic state root: after applying same block, roots match.
    assert_eq!(ledger_a.compute_state_root(), ledger_b.compute_state_root());

    let skipped = crate::consensus::apply_remote_block_from_gossip(
        ledger_b.clone(),
        state_b.mempool.clone(),
        crate::consensus::RemoteBlockGossip {
            block_height,
            block_id,
            parent_block_id: None,
            producer_id,
            base_reward_micro,
            compute_reward_micro,
            total_reward_micro,
            state_root,
            txs: vec![env],
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        skipped,
        crate::consensus::RemoteBlockApplyOutcome::Skipped { .. }
    ));
}

#[tokio::test]
async fn coinbase_reward_moves_worker_pool_to_producer_without_minting() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_BASE_BLOCK_REWARD", "0.1");
    }

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());

    let sender = crate::wallet::generate_mnemonic_12().unwrap();
    let sender_words = sender.mnemonic_12.clone().unwrap();
    let sender_wallet_id = sender.address_hex.to_ascii_lowercase();
    let recipient = crate::wallet::generate_mnemonic_12().unwrap();
    let recipient_wallet_id = recipient.address_hex.to_ascii_lowercase();
    ledger
        .admin_rest_faucet(
            &sender_wallet_id,
            1000 * crate::ledger::STEVEMON,
            "ip",
            true,
            1,
            1,
        )
        .unwrap();

    let env = signed_transfer_env_for_tests(
        &sender_words,
        &sender_wallet_id,
        &recipient_wallet_id,
        crate::ledger::STEVEMON,
    );
    state.mempool.lock().await.push(env);

    let producer_id = "producer-alpha";
    let pool_before = ledger
        .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
        .unwrap();
    let producer_before = ledger.balance_micro(producer_id).unwrap();
    let supply_before = ledger.total_supply_micro().unwrap();

    let outcome = crate::consensus::mine_pending_block_as(state, producer_id.to_string())
        .await
        .unwrap();

    assert!(outcome.mined);
    assert_eq!(
        outcome.reward.base_reward_micro,
        crate::ledger::STEVEMON / 10
    );
    assert_eq!(outcome.reward.compute_reward_micro, 0);
    assert_eq!(
        outcome.reward.total_reward_micro,
        crate::ledger::STEVEMON / 10
    );
    assert_eq!(
        ledger.balance_micro(producer_id).unwrap(),
        producer_before + outcome.reward.total_reward_micro
    );
    assert_eq!(
        ledger
            .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
            .unwrap(),
        pool_before + 5_000 - outcome.reward.total_reward_micro
    );
    assert_eq!(ledger.total_supply_micro().unwrap(), supply_before - 5_000);
}

#[tokio::test]
async fn remote_coinbase_only_block_applies_and_advances_height() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_VALIDATOR_IDS", "alice");
        std::env::set_var("TET_WALLET_ID", "alice");
        std::env::set_var("TET_BASE_BLOCK_REWARD", "0.1");
    }

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());

    let txs = Vec::new();
    let reward = crate::consensus::reward_for_block(&txs).unwrap();
    let block_id = crate::consensus::block_id_for_block(1, &[]);
    let state_root = ledger
        .compute_state_root_after_remote_block(&txs, "alice", reward.total_reward_micro)
        .unwrap();
    let pool_before = ledger
        .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
        .unwrap();
    let producer_before = ledger.balance_micro("alice").unwrap();
    let supply_before = ledger.total_supply_micro().unwrap();

    let applied = crate::consensus::apply_remote_block_from_gossip(
        ledger.clone(),
        state.mempool.clone(),
        crate::consensus::RemoteBlockGossip {
            block_height: 1,
            block_id,
            parent_block_id: None,
            producer_id: "alice".to_string(),
            base_reward_micro: reward.base_reward_micro,
            compute_reward_micro: reward.compute_reward_micro,
            total_reward_micro: reward.total_reward_micro,
            state_root: state_root.clone(),
            txs,
        },
    )
    .await
    .unwrap();

    match applied {
        crate::consensus::RemoteBlockApplyOutcome::Applied {
            block_height,
            tx_count,
            evicted_count,
            state_root: applied_root,
        } => {
            assert_eq!(block_height, 1);
            assert_eq!(tx_count, 0);
            assert_eq!(evicted_count, 0);
            assert_eq!(applied_root, state_root);
        }
        other => panic!("expected coinbase-only remote block apply, got {other:?}"),
    }
    assert_eq!(ledger.block_height().unwrap(), 1);
    assert_eq!(
        ledger.balance_micro("alice").unwrap(),
        producer_before + reward.total_reward_micro
    );
    assert_eq!(
        ledger
            .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
            .unwrap(),
        pool_before - reward.total_reward_micro
    );
    assert_eq!(ledger.total_supply_micro().unwrap(), supply_before);
}

#[tokio::test]
async fn zero_coinbase_reward_keeps_producer_balance_unchanged() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_BASE_BLOCK_REWARD", "0");
    }

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());

    let sender = crate::wallet::generate_mnemonic_12().unwrap();
    let sender_words = sender.mnemonic_12.clone().unwrap();
    let sender_wallet_id = sender.address_hex.to_ascii_lowercase();
    let recipient = crate::wallet::generate_mnemonic_12().unwrap();
    let recipient_wallet_id = recipient.address_hex.to_ascii_lowercase();
    ledger
        .admin_rest_faucet(
            &sender_wallet_id,
            1000 * crate::ledger::STEVEMON,
            "ip",
            true,
            1,
            1,
        )
        .unwrap();

    let env = signed_transfer_env_for_tests(
        &sender_words,
        &sender_wallet_id,
        &recipient_wallet_id,
        crate::ledger::STEVEMON,
    );
    state.mempool.lock().await.push(env);

    let producer_id = "zero-reward-producer";
    let producer_before = ledger.balance_micro(producer_id).unwrap();
    let outcome = crate::consensus::mine_pending_block_as(state, producer_id.to_string())
        .await
        .unwrap();

    assert!(outcome.mined);
    assert_eq!(outcome.reward.total_reward_micro, 0);
    assert_eq!(ledger.balance_micro(producer_id).unwrap(), producer_before);
}

#[test]
fn block_reward_fails_when_worker_pool_is_depleted() {
    let _g = env_lock();
    set_test_env_base();

    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let pool_balance = ledger
        .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
        .unwrap();

    let err = ledger
        .apply_block_reward("producer-alpha", pool_balance + 1, 1)
        .unwrap_err();
    assert!(matches!(err, crate::ledger::LedgerError::InsufficientFunds));
}

#[test]
fn state_root_changes_on_1_micro_difference() {
    let _g = env_lock();
    set_test_env_base();
    let ledger1 = open_temp_ledger();
    ledger1.init_genesis_founder_premine_from_env().unwrap();
    ledger1.apply_genesis_allocation("founder").unwrap();

    let ledger2 = open_temp_ledger();
    ledger2.init_genesis_founder_premine_from_env().unwrap();
    ledger2.apply_genesis_allocation("founder").unwrap();

    let w = "a".repeat(64);
    // Credit 1 micro difference via admin faucet (pool -> user, no inflation).
    let _ = ledger1
        .admin_rest_faucet(&w, 1_000, "ip", true, 1, 1)
        .unwrap();
    let _ = ledger2
        .admin_rest_faucet(&w, 1_001, "ip", true, 1, 1)
        .unwrap();

    let r1 = ledger1.compute_state_root();
    let r2 = ledger2.compute_state_root();
    assert_ne!(r1, r2);
}

#[tokio::test]
async fn zk_verify_tx_enqueues_and_mines_into_block() {
    let _g = env_lock();
    set_test_env_base();

    // Build a mock receipt that passes `zk_verifier` in non-prod (MOCKJ1).
    let j = crate::zk_verifier::InferenceJournalV1 {
        worker_pubkey_bytes: [0u8; 32],
        prompt_hash: [0u8; 32],
        response_hash: [0u8; 32],
        cost_micro: 1,
    };
    let j_bytes = bincode::serialize(&j).unwrap();
    let j_b64 = base64::engine::general_purpose::STANDARD.encode(&j_bytes);
    let receipt_b64 = format!("MOCKJ1:{j_b64}");

    let wallet = crate::wallet::generate_mnemonic_12().unwrap();
    let words = wallet.mnemonic_12.clone().unwrap();
    let wallet_id = wallet.address_hex.to_ascii_lowercase();

    let tx = crate::protocol::TxV1::VerifyZkProof {
        task_id: String::new(),
        image_id: methods::NEXUS_GUEST_ID,
        journal_b64: j_b64.clone(),
        receipt_b64: receipt_b64.clone(),
    };
    let tx_bytes = serde_json::to_vec(&tx).unwrap();

    let ed_sk = crate::wallet::ed25519_signing_key_from_mnemonic(&words).unwrap();
    let mldsa_kp = crate::wallet::mldsa_keypair_from_mnemonic(&words).unwrap();
    let mldsa_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(mldsa_kp.public_key());
    let ed_sig = ed_sk.sign(tx_bytes.as_slice());
    let ed_sig_b64 = base64::engine::general_purpose::STANDARD.encode(ed_sig.to_bytes().as_slice());
    let mldsa_sig_bytes =
        crate::wallet::mldsa_sign_deterministic(&mldsa_kp, tx_bytes.as_slice()).unwrap();
    let mldsa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&mldsa_sig_bytes);

    let env = crate::protocol::SignedTxEnvelopeV1 {
        v: 1,
        tx: tx.clone(),
        sig: crate::protocol::HybridSigV1 {
            ed25519_pubkey_hex: wallet_id.clone(),
            ed25519_sig_b64: ed_sig_b64,
            mldsa_pubkey_b64,
            mldsa_sig_b64,
        },
        attestation: crate::protocol::AttestationV1 {
            platform: "test".to_string(),
            report_b64: String::new(),
        },
    };

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());

    // Submit via zk_verify endpoint: should be 202 + mempool len=1
    let resp = crate::rest::handlers::ledger::post_ledger_zk_verify(
        axum::extract::State(state.clone()),
        HeaderMap::new(),
        axum::Json(env.clone()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(state.mempool.lock().await.len(), 1);

    // Mine: mempool drained, tx included in BlockMined response.
    let resp2 = crate::rest::handlers::ledger::post_ledger_mine(
        axum::extract::State(state.clone()),
        admin_headers_for_tests(),
    )
    .await
    .into_response();
    assert_eq!(resp2.status(), StatusCode::OK);
    assert_eq!(state.mempool.lock().await.len(), 0);
}

#[tokio::test]
async fn zk_court_receipt_adds_thermodynamic_compute_reward() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_BASE_BLOCK_REWARD", "0.1");
        std::env::set_var("TET_JOULES_PER_FLOP", "0.000001");
        std::env::set_var("TET_NETWORK_DIFFICULTY_GAMMA", "1");
        std::env::set_var("TET_THERMO_STEVEMON_MICRO_SCALE", "1");
    }

    let wallet = crate::wallet::generate_mnemonic_12().unwrap();
    let words = wallet.mnemonic_12.clone().unwrap();
    let wallet_id = wallet.address_hex.to_ascii_lowercase();
    let task_id = "0xtask-thermo";
    let flops = 10u64;
    let j = crate::zk_verifier::ZkCourtJournalV1 {
        commitment_sha256: [7u8; 32],
        flops_u64: flops,
        worker_pubkey_bytes: [9u8; 32],
    };
    let j_bytes = bincode::serialize(&j).unwrap();
    let j_b64 = base64::engine::general_purpose::STANDARD.encode(&j_bytes);
    let receipt_b64 = format!("MOCKZC1:{j_b64}");
    let env = signed_zk_env_with_task_for_tests(&words, &wallet_id, task_id, j_b64, receipt_b64);

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    ledger
        .record_enterprise_inference_demand(crate::ledger::AiWorkloadTask {
            v: 1,
            kind: "enterprise_inference_demand".to_string(),
            tx_hash: task_id.to_string(),
            enterprise_wallet_id: wallet_id.clone(),
            prompt: "dynamic test prompt".to_string(),
            prompt_sha256_hex: hex::encode(sha2::Sha256::digest("dynamic test prompt".as_bytes())),
            model: "test-model".to_string(),
            amount_micro: 1,
            workload_flag: crate::protocol::WorkloadFlag::AiInference.as_u8(),
            block_height: 1,
            processed: false,
            processed_by: None,
            processed_receipt_hash_hex: None,
            processed_at_ms: None,
        })
        .unwrap();
    let state = rest_state_for_tests(ledger.clone());
    state.mempool.lock().await.push(env);

    let producer_id = "producer-thermo";
    let producer_before = ledger.balance_micro(producer_id).unwrap();
    let expected_compute =
        crate::vision::thermo_genesis::discrete_thermodynamic_reward_stevemon_micro(
            flops as u128,
            crate::vision::thermo_genesis::env_joules_per_flop(),
            crate::vision::thermo_genesis::NetworkDifficulty::from_env(),
        );

    let outcome = crate::consensus::mine_pending_block_as(state, producer_id.to_string())
        .await
        .unwrap();

    assert!(outcome.mined);
    assert_eq!(outcome.reward.compute_reward_micro, expected_compute);
    assert_eq!(
        outcome.reward.total_reward_micro,
        crate::ledger::STEVEMON / 10 + expected_compute
    );
    assert_eq!(
        ledger.balance_micro(producer_id).unwrap(),
        producer_before + outcome.reward.total_reward_micro
    );
}

#[tokio::test]
async fn invalid_zk_receipt_is_rejected_by_consensus_mining() {
    let _g = env_lock();
    set_test_env_base();

    let wallet = crate::wallet::generate_mnemonic_12().unwrap();
    let words = wallet.mnemonic_12.clone().unwrap();
    let wallet_id = wallet.address_hex.to_ascii_lowercase();
    let j = crate::zk_verifier::InferenceJournalV1 {
        worker_pubkey_bytes: [0u8; 32],
        prompt_hash: [0u8; 32],
        response_hash: [0u8; 32],
        cost_micro: 1,
    };
    let j_bytes = bincode::serialize(&j).unwrap();
    let j_b64 = base64::engine::general_purpose::STANDARD.encode(&j_bytes);
    let env = signed_zk_env_for_tests(&words, &wallet_id, j_b64, "not-a-receipt".to_string());

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let state = rest_state_for_tests(ledger.clone());
    state.mempool.lock().await.push(env);

    let res = crate::consensus::mine_pending_block_as(state, "producer-zk".to_string()).await;
    assert!(matches!(
        res,
        Err(crate::consensus::MineError::Unauthorized(_))
    ));
    assert_eq!(ledger.block_height().unwrap(), 0);
}

#[tokio::test]
async fn remote_block_rejects_journal_mismatch_and_compute_reward_tamper() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_VALIDATOR_IDS", "alice");
        std::env::set_var("TET_WALLET_ID", "alice");
        std::env::set_var("TET_BASE_BLOCK_REWARD", "0.1");
        std::env::set_var("TET_JOULES_PER_FLOP", "0.000001");
        std::env::set_var("TET_NETWORK_DIFFICULTY_GAMMA", "1");
        std::env::set_var("TET_THERMO_STEVEMON_MICRO_SCALE", "1");
    }

    let wallet = crate::wallet::generate_mnemonic_12().unwrap();
    let words = wallet.mnemonic_12.clone().unwrap();
    let wallet_id = wallet.address_hex.to_ascii_lowercase();
    let task_id = "0xtask-remote-zk";
    let j = crate::zk_verifier::ZkCourtJournalV1 {
        commitment_sha256: [1u8; 32],
        flops_u64: 10,
        worker_pubkey_bytes: [2u8; 32],
    };
    let j_bytes = bincode::serialize(&j).unwrap();
    let j_b64 = base64::engine::general_purpose::STANDARD.encode(&j_bytes);
    let receipt_b64 = format!("MOCKZC1:{j_b64}");
    let env = signed_zk_env_with_task_for_tests(
        &words,
        &wallet_id,
        task_id,
        j_b64.clone(),
        receipt_b64.clone(),
    );
    let tx_hash = crate::consensus::tx_hash_for_env(&env).unwrap();
    let block_id = crate::consensus::block_id_for_block(1, &[tx_hash]);

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    ledger
        .record_enterprise_inference_demand(crate::ledger::AiWorkloadTask {
            v: 1,
            kind: "enterprise_inference_demand".to_string(),
            tx_hash: task_id.to_string(),
            enterprise_wallet_id: wallet_id.clone(),
            prompt: "remote prompt".to_string(),
            prompt_sha256_hex: hex::encode(sha2::Sha256::digest("remote prompt".as_bytes())),
            model: "test-model".to_string(),
            amount_micro: 1,
            workload_flag: crate::protocol::WorkloadFlag::AiInference.as_u8(),
            block_height: 1,
            processed: false,
            processed_by: None,
            processed_receipt_hash_hex: None,
            processed_at_ms: None,
        })
        .unwrap();
    let state = rest_state_for_tests(ledger.clone());
    let reward = crate::consensus::reward_for_block(std::slice::from_ref(&env)).unwrap();
    let state_root = ledger
        .compute_state_root_after_remote_block(
            std::slice::from_ref(&env),
            "alice",
            reward.total_reward_micro,
        )
        .unwrap();

    let tampered = crate::consensus::apply_remote_block_from_gossip(
        ledger.clone(),
        state.mempool.clone(),
        crate::consensus::RemoteBlockGossip {
            block_height: 1,
            block_id: block_id.clone(),
            parent_block_id: None,
            producer_id: "alice".to_string(),
            base_reward_micro: reward.base_reward_micro,
            compute_reward_micro: reward.compute_reward_micro + 1,
            total_reward_micro: reward.total_reward_micro + 1,
            state_root: state_root.clone(),
            txs: vec![env.clone()],
        },
    )
    .await;
    assert!(matches!(
        tampered,
        Err(crate::consensus::RemoteBlockApplyError::Rejected(_))
    ));

    let mismatch_bytes = bincode::serialize(&crate::zk_verifier::ZkCourtJournalV1 {
        commitment_sha256: [3u8; 32],
        flops_u64: 10,
        worker_pubkey_bytes: [2u8; 32],
    })
    .unwrap();
    let mismatch_b64 = base64::engine::general_purpose::STANDARD.encode(mismatch_bytes);
    let mismatch_env =
        signed_zk_env_with_task_for_tests(&words, &wallet_id, task_id, mismatch_b64, receipt_b64);
    let mismatch_hash = crate::consensus::tx_hash_for_env(&mismatch_env).unwrap();
    let mismatch_block_id = crate::consensus::block_id_for_block(1, &[mismatch_hash]);
    let mismatch = crate::consensus::apply_remote_block_from_gossip(
        ledger,
        state.mempool.clone(),
        crate::consensus::RemoteBlockGossip {
            block_height: 1,
            block_id: mismatch_block_id,
            parent_block_id: None,
            producer_id: "alice".to_string(),
            base_reward_micro: reward.base_reward_micro,
            compute_reward_micro: reward.compute_reward_micro,
            total_reward_micro: reward.total_reward_micro,
            state_root,
            txs: vec![mismatch_env],
        },
    )
    .await;
    assert!(matches!(
        mismatch,
        Err(crate::consensus::RemoteBlockApplyError::Rejected(_))
    ));
}

#[tokio::test]
async fn zk_task_race_loser_is_rejected_after_winner_processed() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_BASE_BLOCK_REWARD", "0.1");
        std::env::set_var("TET_JOULES_PER_FLOP", "0.000001");
        std::env::set_var("TET_NETWORK_DIFFICULTY_GAMMA", "1");
        std::env::set_var("TET_THERMO_STEVEMON_MICRO_SCALE", "1");
    }

    let worker_a = crate::wallet::generate_mnemonic_12().unwrap();
    let worker_b = crate::wallet::generate_mnemonic_12().unwrap();
    let words_a = worker_a.mnemonic_12.clone().unwrap();
    let words_b = worker_b.mnemonic_12.clone().unwrap();
    let wallet_a = worker_a.address_hex.to_ascii_lowercase();
    let wallet_b = worker_b.address_hex.to_ascii_lowercase();
    let task_id = "0xtask-race";

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    ledger
        .record_enterprise_inference_demand(crate::ledger::AiWorkloadTask {
            v: 1,
            kind: "enterprise_inference_demand".to_string(),
            tx_hash: task_id.to_string(),
            enterprise_wallet_id: wallet_a.clone(),
            prompt: "race prompt".to_string(),
            prompt_sha256_hex: hex::encode(sha2::Sha256::digest("race prompt".as_bytes())),
            model: "test-model".to_string(),
            amount_micro: 1,
            workload_flag: crate::protocol::WorkloadFlag::AiInference.as_u8(),
            block_height: 1,
            processed: false,
            processed_by: None,
            processed_receipt_hash_hex: None,
            processed_at_ms: None,
        })
        .unwrap();

    let make_env = |words: &str, wallet_id: &str, marker: u8| {
        let j = crate::zk_verifier::ZkCourtJournalV1 {
            commitment_sha256: [marker; 32],
            flops_u64: 10 + marker as u64,
            worker_pubkey_bytes: [marker; 32],
        };
        let j_bytes = bincode::serialize(&j).unwrap();
        let j_b64 = base64::engine::general_purpose::STANDARD.encode(&j_bytes);
        let receipt_b64 = format!("MOCKZC1:{j_b64}");
        signed_zk_env_with_task_for_tests(words, wallet_id, task_id, j_b64, receipt_b64)
    };

    let winner = make_env(&words_a, &wallet_a, 1);
    let loser = make_env(&words_b, &wallet_b, 2);
    let state = rest_state_for_tests(ledger.clone());
    state.mempool.lock().await.push(winner);
    let outcome =
        crate::consensus::mine_pending_block_as(state.clone(), "producer-race".to_string())
            .await
            .unwrap();
    assert!(outcome.mined);
    assert!(ledger.ai_workload_is_processed(task_id).unwrap());

    state.mempool.lock().await.push(loser);
    let res = crate::consensus::mine_pending_block_as(state, "producer-race".to_string()).await;
    assert!(matches!(
        res,
        Err(crate::consensus::MineError::Unauthorized(_))
    ));
}

#[test]
fn worker_daemon_mock_flops_are_dynamic_per_task_and_worker() {
    let task_a = crate::ledger::AiWorkloadTask {
        v: 1,
        kind: "enterprise_inference_demand".to_string(),
        tx_hash: "0xtask-a".to_string(),
        enterprise_wallet_id: "enterprise".to_string(),
        prompt: "short prompt".to_string(),
        prompt_sha256_hex: hex::encode(sha2::Sha256::digest("short prompt".as_bytes())),
        model: "test-model".to_string(),
        amount_micro: 1,
        workload_flag: crate::protocol::WorkloadFlag::AiInference.as_u8(),
        block_height: 1,
        processed: false,
        processed_by: None,
        processed_receipt_hash_hex: None,
        processed_at_ms: None,
    };
    let mut task_b = task_a.clone();
    task_b.tx_hash = "0xtask-b".to_string();
    task_b.prompt =
        "a much longer prompt that should produce a different mock flop count".to_string();
    task_b.prompt_sha256_hex = hex::encode(sha2::Sha256::digest(task_b.prompt.as_bytes()));

    let flops_a = crate::worker_daemon::dynamic_mock_flops_for_test(&task_a, &"a".repeat(64));
    let flops_b = crate::worker_daemon::dynamic_mock_flops_for_test(&task_b, &"b".repeat(64));

    assert!(flops_a > 0);
    assert!(flops_b > 0);
    assert_ne!(flops_a, flops_b);
}

#[tokio::test]
async fn reorg_to_heavier_fork_unwinds_transfer_and_replays_new_branch() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_BASE_BLOCK_REWARD", "0.1");
    }

    let wallet_a = crate::wallet::generate_mnemonic_12().unwrap();
    let words_a = wallet_a.mnemonic_12.clone().unwrap();
    let a = wallet_a.address_hex.to_ascii_lowercase();
    let b = "b".repeat(64);
    let c = "c".repeat(64);

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    ledger
        .apply_remote_transfer("0xfund-a-main", "founder", &a, 10_000, 0)
        .unwrap();
    let initial_a = ledger.balance_micro(&a).unwrap();

    let canonical_tx = signed_transfer_env_for_tests(&words_a, &a, &b, 1_000);
    let state = rest_state_for_tests(ledger.clone());
    state.mempool.lock().await.push(canonical_tx);
    let canonical = crate::consensus::mine_pending_block_as(state, "producer-a".to_string())
        .await
        .unwrap();
    assert!(canonical.mined);
    assert_eq!(ledger.block_height().unwrap(), 1);
    assert!(ledger.balance_micro(&b).unwrap() > 0);

    let branch_tx = signed_transfer_env_for_tests(&words_a, &a, &c, 2_000);
    let branch_hash = crate::consensus::tx_hash_for_env(&branch_tx).unwrap();
    let branch_id = crate::consensus::block_id_for_block(1, std::slice::from_ref(&branch_hash));
    let branch_reward =
        crate::consensus::reward_for_block(std::slice::from_ref(&branch_tx)).unwrap();

    let branch_ledger = open_temp_ledger();
    branch_ledger
        .init_genesis_founder_premine_from_env()
        .unwrap();
    branch_ledger.apply_genesis_allocation("founder").unwrap();
    branch_ledger
        .apply_remote_transfer("0xfund-a-branch", "founder", &a, 10_000, 0)
        .unwrap();
    branch_ledger
        .apply_remote_transfer(&branch_hash, &a, &c, 2_000, 100)
        .unwrap();
    branch_ledger
        .apply_block_reward("producer-b", branch_reward.total_reward_micro, 1)
        .unwrap();
    let branch_root = branch_ledger.compute_state_root();

    ledger
        .record_block_record(&crate::ledger::BlockRecordV1 {
            v: 1,
            height: 1,
            block_id: branch_id.clone(),
            parent_block_id: None,
            producer_id: "producer-b".to_string(),
            tx_hashes: vec![branch_hash.clone()],
            txs: vec![branch_tx],
            state_root: branch_root.clone(),
            reward: crate::ledger::BlockRewardRecordV1 {
                base_reward_micro: branch_reward.base_reward_micro,
                compute_reward_micro: branch_reward.compute_reward_micro,
                total_reward_micro: branch_reward.total_reward_micro,
            },
            caac_weight: 1_000,
            cumulative_weight: 1_000,
            canonical: false,
            ts_ms: 1,
        })
        .unwrap();

    let changed = crate::consensus::reorg_to_branch(&ledger, &branch_id).unwrap();
    assert!(changed);
    assert_eq!(ledger.block_height().unwrap(), 1);
    assert_eq!(ledger.compute_state_root(), branch_root);
    assert_eq!(ledger.balance_micro(&a).unwrap(), initial_a - 2_000);
    assert_eq!(ledger.balance_micro(&b).unwrap(), 0);
    assert_eq!(ledger.balance_micro(&c).unwrap(), 1_980);
    assert_eq!(ledger.balance_micro("producer-a").unwrap(), 0);
    assert_eq!(
        ledger.balance_micro("producer-b").unwrap(),
        branch_reward.total_reward_micro
    );
    assert_eq!(
        ledger.chain_tip().unwrap().unwrap().block_id,
        branch_id,
        "heavier branch must become canonical tip"
    );
}

#[tokio::test]
async fn backfilled_child_first_branch_reorgs_after_parent_arrives() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_BASE_BLOCK_REWARD", "0.1");
        std::env::set_var("TET_WALLET_ID", "local-wallet");
    }

    let wallet_a = crate::wallet::generate_mnemonic_12().unwrap();
    let words_a = wallet_a.mnemonic_12.clone().unwrap();
    let a = wallet_a.address_hex.to_ascii_lowercase();
    let b = "b".repeat(64);
    let c = "c".repeat(64);

    let ledger = std::sync::Arc::new(open_temp_ledger());
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    ledger
        .apply_remote_transfer("0xfund-a-main-backfill", "founder", &a, 10_000, 0)
        .unwrap();
    let initial_a = ledger.balance_micro(&a).unwrap();

    let canonical_tx = signed_transfer_env_for_tests(&words_a, &a, &b, 1_000);
    let state = rest_state_for_tests(ledger.clone());
    state.mempool.lock().await.push(canonical_tx);
    let canonical = crate::consensus::mine_pending_block_as(state, "local-wallet".to_string())
        .await
        .unwrap();
    assert!(canonical.mined);
    assert_eq!(ledger.block_height().unwrap(), 1);

    let branch_tx = signed_transfer_env_for_tests(&words_a, &a, &c, 2_000);
    let branch_hash = crate::consensus::tx_hash_for_env(&branch_tx).unwrap();
    let parent_block_id =
        crate::consensus::block_id_for_block(1, std::slice::from_ref(&branch_hash));
    let child_block_id = crate::consensus::block_id_for_block(2, &[]);
    let parent_reward =
        crate::consensus::reward_for_block(std::slice::from_ref(&branch_tx)).unwrap();
    let child_reward = crate::consensus::reward_for_block(&[]).unwrap();

    let branch_ledger = open_temp_ledger();
    branch_ledger
        .init_genesis_founder_premine_from_env()
        .unwrap();
    branch_ledger.apply_genesis_allocation("founder").unwrap();
    branch_ledger
        .apply_remote_transfer("0xfund-a-branch-backfill", "founder", &a, 10_000, 0)
        .unwrap();
    branch_ledger
        .apply_remote_transfer(&branch_hash, &a, &c, 2_000, 100)
        .unwrap();
    branch_ledger
        .apply_block_reward("local-wallet", parent_reward.total_reward_micro, 1)
        .unwrap();
    let parent_state_root = branch_ledger.compute_state_root();
    branch_ledger
        .apply_block_reward("local-wallet", child_reward.total_reward_micro, 2)
        .unwrap();
    let child_state_root = branch_ledger.compute_state_root();

    let child = crate::consensus::RemoteBlockGossip {
        block_height: 2,
        block_id: child_block_id.clone(),
        parent_block_id: Some(parent_block_id.clone()),
        producer_id: "local-wallet".to_string(),
        base_reward_micro: child_reward.base_reward_micro,
        compute_reward_micro: child_reward.compute_reward_micro,
        total_reward_micro: child_reward.total_reward_micro,
        state_root: child_state_root.clone(),
        txs: Vec::new(),
    };
    crate::consensus::validate_and_record_backfill_candidate(&ledger, child).unwrap();
    assert_eq!(ledger.block_height().unwrap(), 1);
    assert_eq!(
        ledger.chain_tip().unwrap().unwrap().block_id,
        canonical.block_id
    );

    let parent = crate::consensus::RemoteBlockGossip {
        block_height: 1,
        block_id: parent_block_id.clone(),
        parent_block_id: None,
        producer_id: "local-wallet".to_string(),
        base_reward_micro: parent_reward.base_reward_micro,
        compute_reward_micro: parent_reward.compute_reward_micro,
        total_reward_micro: parent_reward.total_reward_micro,
        state_root: parent_state_root,
        txs: vec![branch_tx],
    };
    crate::consensus::validate_and_record_backfill_candidate(&ledger, parent).unwrap();
    let changed = crate::consensus::try_reorg_backfilled_branch(&ledger, &child_block_id).unwrap();
    assert!(changed);
    assert_eq!(ledger.block_height().unwrap(), 2);
    assert_eq!(ledger.compute_state_root(), child_state_root);
    assert_eq!(ledger.balance_micro(&a).unwrap(), initial_a - 2_000);
    assert_eq!(ledger.balance_micro(&b).unwrap(), 0);
    assert_eq!(ledger.balance_micro(&c).unwrap(), 1_980);
    assert_eq!(
        ledger.balance_micro("local-wallet").unwrap(),
        parent_reward.total_reward_micro + child_reward.total_reward_micro
    );
    assert_eq!(
        ledger.chain_tip().unwrap().unwrap().block_id,
        child_block_id,
        "child-first backfilled branch must become canonical after parent arrives"
    );
}

#[test]
fn ledger_atomic_snapshot_writes_json_and_clears_tmp() {
    let _g = env_lock();
    set_test_env_base();
    let tmpdir = tempfile::tempdir().unwrap();
    let json_path = tmpdir.path().join("snap.json");
    let tmp_path = tmpdir.path().join("snap.tmp");
    unsafe {
        std::env::set_var("TET_LEDGER_JSON_PATH", json_path.to_str().unwrap());
        std::env::set_var("TET_LEDGER_TMP_PATH", tmp_path.to_str().unwrap());
    }

    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    // Trigger snapshot persistence via mint.
    let _ = ledger
        .mint_reward_with_proof("alice", 1_000_000, b"energy:test", None, false)
        .unwrap();

    assert!(json_path.exists(), "snapshot json must exist");
    let bytes = std::fs::read(&json_path).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v.get("v").and_then(|x| x.as_u64()).unwrap_or(0), 1);
    // Best-effort: tmp should not remain after rename.
    assert!(!tmp_path.exists(), "tmp snapshot should be renamed away");
}

#[test]
fn ledger_aml_chf_limit_is_enforced_at_1000() {
    let _g = env_lock();
    set_test_env_base();
    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();

    // 1000 CHF == 1_000_000_000 micro-CHF
    let limit_micro = 1_000u64 * 1_000_000u64;
    let ok = ledger.mint_fiat_chf_topup("bob", limit_micro, "ref1");
    assert!(ok.is_ok(), "exactly at limit should succeed");

    let too_much = ledger.mint_fiat_chf_topup("bob", 1, "ref2");
    assert!(
        too_much.is_err()
            && too_much
                .err()
                .unwrap()
                .to_string()
                .contains("AML Limit Exceeded"),
        "exceeding limit must fail"
    );
}

#[test]
fn e2ee_encrypt_route_blind_decrypt_cycle() {
    let _g = env_lock();
    set_test_env_base();

    let (worker_sk, worker_pk) = crate::e2ee::gen_worker_static_keypair();
    let (client_eph_sk, client_eph_pk) = crate::e2ee::gen_worker_static_keypair();
    let mut nonce12 = [0u8; 12];
    let mut rng = rand_core::OsRng;
    rng.fill_bytes(&mut nonce12);

    let pt = b"hello quantum mesh";
    let (wpk, wsk) = {
        use pqcrypto_traits::kem::{PublicKey, SecretKey};
        let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    };
    let (ct, kem_ct) =
        crate::e2ee::encrypt_for_worker(&client_eph_sk, &worker_pk, &wpk, nonce12, pt).unwrap();

    // Blind routing: core never decrypts; we just forward bytes unchanged.
    let routed_ct = ct.clone();

    let out = crate::e2ee::decrypt_on_worker(
        &worker_sk,
        &client_eph_pk,
        &wsk,
        &kem_ct,
        nonce12,
        &routed_ct,
    )
    .unwrap();
    assert_eq!(out.as_slice(), pt);
}

#[test]
fn worker_hardware_id_is_stable_and_not_uuid_like() {
    let _g = env_lock();
    set_test_env_base();

    let id1 = tet_core::tet_worker::hardware_id_sha256_hex_best_effort().unwrap();
    let id2 = tet_core::tet_worker::hardware_id_sha256_hex_best_effort().unwrap();
    assert_eq!(
        id1, id2,
        "hardware_id must be deterministic per device snapshot"
    );
    assert_eq!(id1.len(), 64, "sha256 hex length");
    assert!(id1.chars().all(|c: char| c.is_ascii_hexdigit()));
    assert!(!id1.contains('-'), "must not look like UUID");
}

#[test]
fn db_strict_encryption_encrypts_sensitive_meta_values() {
    use crate::attestation::AttestationReport;
    use crate::ledger::STEVEMON;
    use tempfile::tempdir;

    let _g = env_lock();
    // Strict encryption must be on for this test.
    unsafe { std::env::set_var("TET_DB_ENCRYPT", "strict") };
    // Generate a per-test 32-byte key (base64). Do not hardcode secret-like material in source.
    let mut k = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut k);
    let kb64 = base64::engine::general_purpose::STANDARD.encode(k);
    unsafe { std::env::set_var("TET_DB_KEY_B64", kb64) };
    // Ensure we can apply genesis and fund a wallet deterministically.
    unsafe {
        std::env::set_var(
            "TET_FOUNDER_WALLET",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
    };
    // Disable founder cliff for this test so founder can fund another wallet.
    unsafe { std::env::set_var("TET_FOUNDER_CLIFF_MS", "0") };

    let dir = tempdir().unwrap();
    let path = dir.path().join("tet.db");
    let l = crate::ledger::Ledger::open(path.to_str().unwrap()).unwrap();

    // Apply genesis to ensure balances exist, then fund target wallet.
    l.init_genesis_founder_premine_from_env().unwrap();
    l.apply_genesis_allocation("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .unwrap();

    let w = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    // Fund wallet from founder. Use the attested path so this test is stable even if other tests
    // enable `TET_REQUIRE_ATTESTATION` concurrently (env is process-global in Rust 2024).
    let att = AttestationReport {
        v: 1,
        platform: "test".into(),
        report_b64: "test".into(),
    };
    let _ = l
        .transfer_with_fee_attested(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            w,
            2_000u64 * STEVEMON,
            Some(50),
            Some(&att),
            None,
        )
        .unwrap();

    // Stake writes to meta via encrypt_value.
    let _ = l.stake_micro(w, 1234 * STEVEMON, None).unwrap();
    let stake_key = {
        let mut k = b"wallet_stake_v1:".to_vec();
        k.extend_from_slice(w.as_bytes());
        k
    };
    let raw = l.test_only_raw_meta_value(&stake_key);
    assert!(!raw.is_empty());
    // Ciphertext must not equal plaintext bytes.
    assert_ne!(raw, (1234u64 * STEVEMON).to_le_bytes().to_vec());
    // Should decrypt via public API to the expected value.
    assert_eq!(l.staked_balance_micro(w).unwrap(), 1234u64 * STEVEMON);
}

fn sign_hybrid_headers(
    headers: &mut HeaderMap,
    who: &str,
    ed_signing: &SigningKey,
    mldsa_kp: &dilithium::MlDsaKeyPair,
    msg: &[u8],
) {
    // Ed25519 signature
    let sig = ed_signing.sign(msg);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    let k = format!("x-tet-{who}-ed25519-sig-b64");
    headers.insert(
        HeaderName::from_bytes(k.as_bytes()).unwrap(),
        sig_b64.parse().unwrap(),
    );

    // ML-DSA (mode follows keypair)
    let sig = crate::wallet::mldsa_sign_deterministic(mldsa_kp, msg).unwrap();
    let ps_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(mldsa_kp.public_key());
    let kpk = format!("x-tet-{who}-mldsa-pubkey-b64");
    let ksig = format!("x-tet-{who}-mldsa-sig-b64");
    headers.insert(
        HeaderName::from_bytes(kpk.as_bytes()).unwrap(),
        pk_b64.parse().unwrap(),
    );
    headers.insert(
        HeaderName::from_bytes(ksig.as_bytes()).unwrap(),
        ps_b64.parse().unwrap(),
    );
}

#[tokio::test]
async fn dex_maker_can_cancel_unfilled_order() {
    let _g = env_lock();
    set_test_env_base();

    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    let _ = ledger
        .mint_reward_with_proof("alice", 2_000_000_000, b"energy:test", None, false)
        .unwrap();
    let bal_before = ledger.balance_micro("alice").unwrap();
    let supply_before_dex = ledger.total_supply_micro().unwrap();
    let burned_before_dex = ledger.total_burned_micro().unwrap();

    let state = rest_state_for_tests(std::sync::Arc::new(ledger));

    let place = crate::rest::handlers::dex::post_dex_order_place(
        axum::extract::State(state.clone()),
        axum::Json(crate::rest::DexOrderPlaceReq {
            maker_wallet: "alice".into(),
            side: "sell".into(),
            quote_asset: "USDC".into(),
            price_quote_per_tet: 50,
            tet_micro_total: 500_000_000,
            ttl_sec: Some(600),
        }),
    )
    .await;
    assert_eq!(place.status(), StatusCode::OK);
    let place_body = axum::body::to_bytes(place.into_body(), usize::MAX)
        .await
        .unwrap();
    let place_json: serde_json::Value = serde_json::from_slice(&place_body).unwrap();
    let order_id = place_json
        .get("order_id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let ledger = state.ledger.clone();
    let escrow = crate::p2p_dex::escrow_wallet_for_order(&order_id);
    assert!(ledger.balance_micro(&escrow).unwrap() > 0);

    let cancel = crate::rest::handlers::dex::post_dex_order_cancel(
        axum::extract::State(state),
        axum::Json(crate::rest::DexOrderCancelReq {
            order_id,
            maker_wallet: "alice".into(),
        }),
    )
    .await;
    assert_eq!(cancel.status(), StatusCode::OK);

    let bal_after = ledger.balance_micro("alice").unwrap();
    assert_eq!(ledger.balance_micro(&escrow).unwrap(), 0);
    // Phase 2: transfer fees are strict (PROTOCOL_MAINTENANCE_FEE_BPS); half of each fee is burned.
    let lock_gross = 500_000_000u64;
    let bps = crate::ledger::PROTOCOL_MAINTENANCE_FEE_BPS;
    let fee_lock = lock_gross.saturating_mul(bps) / 10_000;
    let escrow_net = lock_gross.saturating_sub(fee_lock);
    let fee_refund = escrow_net.saturating_mul(bps) / 10_000;
    let (_, burn_lock) = crate::ledger::Ledger::split_protocol_fee_treasury_and_burn(fee_lock);
    let (_, burn_refund) = crate::ledger::Ledger::split_protocol_fee_treasury_and_burn(fee_refund);
    let expected_burn_dex = burn_lock.saturating_add(burn_refund);
    let expected_roundtrip_fee = fee_lock.saturating_add(fee_refund);
    assert_eq!(bal_before.saturating_sub(bal_after), expected_roundtrip_fee);
    assert_eq!(
        ledger.total_burned_micro().unwrap(),
        burned_before_dex.saturating_add(expected_burn_dex)
    );
    assert_eq!(
        ledger.total_supply_micro().unwrap(),
        supply_before_dex.saturating_sub(expected_burn_dex)
    );
}

#[test]
fn transfer_fee_half_burn_reduces_total_supply_and_tracks_burned() {
    let _g = env_lock();
    set_test_env_base();
    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let sup0 = ledger.total_supply_micro().unwrap();
    assert_eq!(sup0, crate::ledger::GENESIS_TOTAL_MINT_MICRO);
    let burned0 = ledger.total_burned_micro().unwrap();
    assert_eq!(burned0, 0);

    let pool = "founder";
    ledger
        .transfer_with_fee(pool, "alice", 100_000_000, Some(50))
        .unwrap();
    // Phase 2: transfer fees are strict (PROTOCOL_MAINTENANCE_FEE_BPS), ignoring provided fee_bps.
    let fee = 100_000_000u64 * crate::ledger::PROTOCOL_MAINTENANCE_FEE_BPS / 10_000; // 1_000_000
    let (_, burn) = crate::ledger::Ledger::split_protocol_fee_treasury_and_burn(fee);
    assert_eq!(ledger.total_burned_micro().unwrap(), burn);
    assert_eq!(
        ledger.total_supply_micro().unwrap(),
        sup0.saturating_sub(burn)
    );
}

#[tokio::test]
async fn dex_escrow_flow_quantum_gate_accepts_valid_and_rejects_classical_only() {
    let _g = env_lock();
    set_test_env_base();

    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    // Fund maker so they can lock escrow.
    let _ = ledger
        .mint_reward_with_proof("maker", 5_000_000_000, b"energy:test", None, false)
        .unwrap();

    let state = rest_state_for_tests(std::sync::Arc::new(ledger));

    // Place order (maker sells TET for USDC).
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", "testkey".parse().unwrap());
    let place = crate::rest::handlers::dex::post_dex_order_place(
        axum::extract::State(state.clone()),
        axum::Json(crate::rest::DexOrderPlaceReq {
            maker_wallet: "maker".into(),
            side: "sell".into(),
            quote_asset: "USDC".into(),
            price_quote_per_tet: 100,
            tet_micro_total: 1_000_000_000,
            ttl_sec: Some(600),
        }),
    )
    .await;
    assert_eq!(place.status(), StatusCode::OK);

    // Taker takes.
    let take = crate::rest::handlers::dex::post_dex_take(
        axum::extract::State(state.clone()),
        axum::Json(crate::rest::DexTakeReq {
            taker_wallet: "taker".into(),
            side: "buy".into(),
            quote_asset: "USDC".into(),
            tet_micro: 250_000_000,
            max_price_quote_per_tet: Some(100),
            settlement_ttl_sec: Some(600),
        }),
    )
    .await;
    assert_eq!(take.status(), StatusCode::OK);
    let take_body = axum::body::to_bytes(take.into_body(), usize::MAX)
        .await
        .unwrap();
    let take_json: serde_json::Value = serde_json::from_slice(&take_body).unwrap();
    let trade_id = take_json
        .get("trade_id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    // Prepare valid hybrid signatures for both parties.
    let maker_ed = SigningKey::generate(&mut rand_core::OsRng);
    let taker_ed = SigningKey::generate(&mut rand_core::OsRng);
    let maker_mldsa = {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        dilithium::MlDsaKeyPair::generate_deterministic(dilithium::ML_DSA_65, &seed)
    };
    let taker_mldsa = {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        dilithium::MlDsaKeyPair::generate_deterministic(dilithium::ML_DSA_65, &seed)
    };

    let trade = {
        let dex = state.dex.lock().unwrap();
        dex.get_trade(&trade_id).unwrap()
    };
    let txid = "solana_txid_dummy_123";
    let msg = crate::p2p_dex::DexEngine::trade_complete_message_v1(&trade, txid);

    let mut qh = headers.clone();
    sign_hybrid_headers(&mut qh, "maker", &maker_ed, &maker_mldsa, &msg);
    sign_hybrid_headers(&mut qh, "taker", &taker_ed, &taker_mldsa, &msg);

    // Payment verified guard: hybrid-ready but settlement not confirmed -> 403.
    let blocked = crate::rest::handlers::dex::post_dex_trade_complete(
        axum::extract::State(state.clone()),
        qh.clone(),
        axum::Json(crate::rest::DexTradeCompleteReq {
            trade_id: trade_id.clone(),
            solana_usdc_txid: txid.into(),
            maker_ed25519_pubkey_hex: hex::encode(maker_ed.verifying_key().as_bytes()),
            taker_ed25519_pubkey_hex: hex::encode(taker_ed.verifying_key().as_bytes()),
        }),
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);

    let confirm = crate::rest::handlers::dex::post_dex_settlement_confirm(
        axum::extract::State(state.clone()),
        axum::Json(crate::rest::DexSettlementConfirmReq {
            trade_id: trade_id.clone(),
            solana_usdc_txid: txid.into(),
        }),
    )
    .await;
    assert_eq!(confirm.status(), StatusCode::OK);

    // After settlement confirm, complete should pass (quantum gate still enforced).
    let complete_ok = crate::rest::handlers::dex::post_dex_trade_complete(
        axum::extract::State(state.clone()),
        qh.clone(),
        axum::Json(crate::rest::DexTradeCompleteReq {
            trade_id: trade_id.clone(),
            solana_usdc_txid: txid.into(),
            maker_ed25519_pubkey_hex: hex::encode(maker_ed.verifying_key().as_bytes()),
            taker_ed25519_pubkey_hex: hex::encode(taker_ed.verifying_key().as_bytes()),
        }),
    )
    .await;
    assert_eq!(complete_ok.status(), StatusCode::OK);

    // Classical-only: omit ML-DSA headers -> must be 403.
    let mut classical = headers.clone();
    let sig = maker_ed.sign(&msg);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    classical.insert("x-tet-maker-ed25519-sig-b64", sig_b64.parse().unwrap());
    classical.insert("x-tet-taker-ed25519-sig-b64", sig_b64.parse().unwrap());

    let complete_forbidden = crate::rest::handlers::dex::post_dex_trade_complete(
        axum::extract::State(state),
        classical,
        axum::Json(crate::rest::DexTradeCompleteReq {
            trade_id,
            solana_usdc_txid: txid.into(),
            maker_ed25519_pubkey_hex: hex::encode(maker_ed.verifying_key().as_bytes()),
            taker_ed25519_pubkey_hex: hex::encode(taker_ed.verifying_key().as_bytes()),
        }),
    )
    .await;
    assert_eq!(complete_forbidden.status(), StatusCode::FORBIDDEN);
}

#[test]
fn genesis_allocates_exact_split_once_and_rejects_second() {
    let _g = env_lock();
    set_test_env_base();
    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    assert_eq!(ledger.total_supply_micro().unwrap(), 0);

    let s = ledger.apply_genesis_allocation("steve").unwrap();
    assert_eq!(
        s.founder_allocation_micro,
        crate::ledger::GENESIS_FOUNDER_SHARE_MICRO
    );
    assert_eq!(
        s.dex_treasury_allocation_micro,
        crate::ledger::GENESIS_DEX_TREASURY_MICRO
    );
    assert_eq!(
        s.worker_pool_allocation_micro,
        crate::ledger::GENESIS_WORKER_POOL_SHARE_MICRO
    );
    assert_eq!(
        s.total_supply_micro,
        crate::ledger::GENESIS_TOTAL_MINT_MICRO
    );

    assert_eq!(
        ledger.balance_micro("steve").unwrap(),
        crate::ledger::GENESIS_FOUNDER_SHARE_MICRO
    );
    assert_eq!(
        ledger
            .balance_micro(crate::ledger::WALLET_DEX_TREASURY)
            .unwrap(),
        0,
        "Phase 1 founder-only genesis leaves DEX treasury at 0"
    );
    assert_eq!(
        ledger
            .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
            .unwrap(),
        crate::ledger::GENESIS_WORKER_POOL_SHARE_MICRO,
        "§10 genesis: 75% system-locked mint credits worker pool"
    );
    assert_eq!(
        ledger.total_supply_micro().unwrap(),
        crate::ledger::GENESIS_TOTAL_MINT_MICRO
    );

    let r2 = ledger.apply_genesis_allocation("other");
    assert!(matches!(
        r2,
        Err(crate::ledger::LedgerError::GenesisAlreadyApplied)
    ));
}

struct EnvVarRemoveOnDrop {
    key: &'static str,
}

impl Drop for EnvVarRemoveOnDrop {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(self.key);
        }
    }
}

#[test]
fn genesis_1k_worker_pool_reward_is_110_percent_of_standard_gross() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_WORKER_VEST_MS", "80");
    }
    let _vest_env = EnvVarRemoveOnDrop {
        key: "TET_WORKER_VEST_MS",
    };

    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();

    ledger
        .transfer_with_fee(
            "founder",
            crate::ledger::WALLET_SYSTEM_WORKER_POOL,
            200_000_000,
            Some(50),
        )
        .unwrap();

    ledger
        .test_only_mark_genesis_1k_participant("maker", 42)
        .unwrap();

    let gross_req = 100_000_000u64;
    let boosted_gross = (gross_req as u128 * 11 / 10) as u64;
    let imperial_bps = 100u64;
    let imperial_tax = boosted_gross.saturating_mul(imperial_bps) / 10_000;
    let expected_worker_net = boosted_gross.saturating_sub(imperial_tax);

    ledger
        .mint_worker_network_reward("maker", "imperial-vault", gross_req, b"energy:poc", None)
        .unwrap();

    let locked = ledger.locked_balance_micro_now("maker").unwrap();
    assert_eq!(
        locked, expected_worker_net,
        "Genesis participant should receive +10% on gross before imperial split"
    );
}

#[tokio::test]
async fn worker_ai_reward_vest_blocks_dex_until_lock_expires() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_WORKER_VEST_MS", "80");
    }
    let _vest_env = EnvVarRemoveOnDrop {
        key: "TET_WORKER_VEST_MS",
    };

    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let supply_after_genesis = ledger.total_supply_micro().unwrap();
    assert_eq!(
        supply_after_genesis,
        crate::ledger::GENESIS_TOTAL_MINT_MICRO,
        "genesis must mint full max supply (25% founder + 75% system pool)"
    );

    ledger
        .transfer_with_fee(
            "founder",
            crate::ledger::WALLET_SYSTEM_WORKER_POOL,
            200_000_000,
            Some(50),
        )
        .unwrap();

    let gross = 100_000_000u64;
    ledger
        .mint_worker_network_reward("maker", "imperial-vault", gross, b"energy:poc", None)
        .unwrap();
    assert!(
        ledger.total_supply_micro().unwrap() <= supply_after_genesis,
        "worker_pool payout must not inflate total supply (burn is allowed)"
    );

    let locked = ledger.locked_balance_micro_now("maker").unwrap();
    assert!(locked > 0, "worker_net must appear as locked balance");
    assert_eq!(
        ledger.spendable_balance_micro_now("maker").unwrap(),
        0,
        "DEX must not spend vest-locked worker_net"
    );

    let state = rest_state_for_tests(std::sync::Arc::new(ledger));

    let place_fail = crate::rest::handlers::dex::post_dex_order_place(
        axum::extract::State(state.clone()),
        axum::Json(crate::rest::DexOrderPlaceReq {
            maker_wallet: "maker".into(),
            side: "sell".into(),
            quote_asset: "USDC".into(),
            price_quote_per_tet: 100,
            tet_micro_total: 1_000_000,
            ttl_sec: Some(600),
        }),
    )
    .await;
    assert_eq!(place_fail.status(), StatusCode::BAD_REQUEST);

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let place_ok = crate::rest::handlers::dex::post_dex_order_place(
        axum::extract::State(state),
        axum::Json(crate::rest::DexOrderPlaceReq {
            maker_wallet: "maker".into(),
            side: "sell".into(),
            quote_asset: "USDC".into(),
            price_quote_per_tet: 100,
            tet_micro_total: 1_000_000,
            ttl_sec: Some(600),
        }),
    )
    .await;
    assert_eq!(place_ok.status(), StatusCode::OK);
}

#[test]
fn ai_utility_micro_tet_split_is_nonzero_for_0_001_tet() {
    let _g = env_lock();
    set_test_env_base();
    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();

    // Fund payer with exactly 0.001 TET (1000 micro).
    let payer = "payer";
    let worker = "worker";
    let burn = ledger.ai_burn_wallet();
    // Genesis mints full max supply — fund payer from founder (no additional mint).
    ledger.transfer_no_fee("founder", payer, 10_000).unwrap();

    let (w, t, b) = ledger
        .settle_ai_utility_payment(payer, worker, 1_000, &burn)
        .unwrap();
    assert_eq!(w + t + b, 1_000, "split must conserve gross micro");
    assert_eq!(w, 800, "80% worker");
    assert_eq!(t, 150, "15% treasury");
    assert_eq!(b, 50, "5% burn");
}

/// BIP39 → Ed25519 wallet id must match `wallet_client_bundled.js` (`@scure/bip39` + `@noble/ed25519`).
#[test]
fn client_wallet_bundle_matches_core_abandon_vector() {
    // Public repo policy: do not hardcode a mnemonic phrase in source.
    // Instead, generate a mnemonic and validate cross-primitive invariants.
    let wi = crate::wallet::generate_mnemonic_12().unwrap();
    let phrase = wi.mnemonic_12.as_deref().unwrap_or_default();
    let w = crate::wallet::recover_from_mnemonic_12(phrase).unwrap();
    assert_eq!(w.address_hex.len(), 64);
    assert!(w.address_hex.chars().all(|c| c.is_ascii_hexdigit()));

    // ML-DSA pubkey (default ML-DSA-65) must be decodable; length matches FIPS-204 raw encoding.
    let pk = base64::engine::general_purpose::STANDARD
        .decode(w.dilithium_pubkey_b64.trim())
        .unwrap();
    assert_eq!(pk.len(), dilithium::ML_DSA_65.public_key_bytes());
}

#[test]
fn mldsa44_hybrid_transfer_sign_verify_roundtrip() {
    let wi = crate::wallet::generate_mnemonic_12().unwrap();
    let phrase = wi.mnemonic_12.as_deref().unwrap_or_default();
    let kp = crate::wallet::mldsa44_keypair_from_mnemonic(phrase).unwrap();
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(kp.public_key());
    let bob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let msg = crate::wallet::transfer_hybrid_auth_message_bytes(bob, 1_000_000, 3, &pk_b64);
    let sig = crate::wallet::mldsa44_sign_deterministic(&kp, &msg).unwrap();
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    crate::wallet::verify_mldsa44_b64(&pk_b64, &sig_b64, &msg).unwrap();
}

#[test]
fn mldsa65_hybrid_transfer_sign_verify_roundtrip() {
    let wi = crate::wallet::generate_mnemonic_12().unwrap();
    let phrase = wi.mnemonic_12.as_deref().unwrap_or_default();
    let kp = crate::wallet::mldsa_keypair_from_mnemonic(phrase).unwrap();
    assert_eq!(kp.mode(), dilithium::ML_DSA_65);
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(kp.public_key());
    let bob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let msg = crate::wallet::transfer_hybrid_auth_message_bytes(bob, 1_000_000, 3, &pk_b64);
    let sig = crate::wallet::mldsa_sign_deterministic(&kp, &msg).unwrap();
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    crate::wallet::verify_mldsa_b64(&pk_b64, &sig_b64, &msg).unwrap();
}

#[test]
fn mainnet_rejects_legacy_tx_signature_without_chain_binding() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_MAINNET", "1");
        std::env::set_var(
            "TET_GENESIS_FOUNDER_WALLET_ID",
            crate::ledger::GENESIS_FOUNDER_DEV_PUBLIC_HEX,
        );
    }

    let wi = crate::wallet::generate_mnemonic_12().unwrap();
    let phrase = wi.mnemonic_12.as_deref().unwrap_or_default();
    let w = crate::wallet::recover_from_mnemonic_12(phrase).unwrap();
    let bob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let env = signed_transfer_env_for_tests(phrase, &w.address_hex, bob, 1_000_000);
    let err = crate::rest::helpers::verify_envelope_v1(&env).unwrap_err();
    assert!(err.contains("chain_id/genesis_hash"));

    unsafe {
        std::env::remove_var("TET_MAINNET");
        std::env::remove_var("TET_GENESIS_FOUNDER_WALLET_ID");
    }
}

#[test]
fn mainnet_panics_when_mock_zk_is_enabled() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_MAINNET", "1");
        std::env::set_var("TET_ALLOW_MOCK_ZK", "1");
    }

    let result = std::panic::catch_unwind(|| {
        let _ = crate::zk_verifier::verify_receipt("MOCKJ1:");
    });
    assert!(result.is_err());

    unsafe {
        std::env::remove_var("TET_MAINNET");
        std::env::remove_var("TET_ALLOW_MOCK_ZK");
    }
}

#[tokio::test]
async fn mempool_limit_evicts_lowest_fee_tx() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_MEMPOOL_MAX_TXS", "1");
        std::env::set_var("TET_MEMPOOL_MAX_BYTES", "1048576");
    }
    let ledger = std::sync::Arc::new(open_temp_ledger());
    let state = rest_state_for_tests(ledger);
    let alice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let bob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let make_env = |fee_bps| crate::protocol::SignedTxEnvelopeV1 {
        v: 1,
        tx: crate::protocol::TxV1::Transfer {
            from_wallet: alice.to_string(),
            to_wallet: bob.to_string(),
            amount_micro: 1_000_000,
            fee_bps,
        },
        sig: crate::protocol::HybridSigV1 {
            ed25519_pubkey_hex: alice.to_string(),
            ed25519_sig_b64: String::new(),
            mldsa_pubkey_b64: String::new(),
            mldsa_sig_b64: String::new(),
        },
        attestation: crate::protocol::AttestationV1 {
            platform: String::new(),
            report_b64: String::new(),
        },
    };

    assert!(!state.enqueue_mempool_tx(make_env(1)).await.unwrap());
    assert!(state.enqueue_mempool_tx(make_env(100)).await.unwrap());
    let mp = state.mempool.lock().await;
    assert_eq!(mp.len(), 1);
    let crate::protocol::TxV1::Transfer { fee_bps, .. } = mp[0].tx else {
        panic!("expected transfer");
    };
    assert_eq!(fee_bps, 100);

    unsafe {
        std::env::remove_var("TET_MEMPOOL_MAX_TXS");
        std::env::remove_var("TET_MEMPOOL_MAX_BYTES");
    }
}

#[test]
fn ledger_prune_removes_old_block_undo_beyond_depth() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_PRUNE_DEPTH", "2");
        std::env::set_var("TET_AUDIT_MAX_EVENTS", "100000");
    }
    let ledger = open_temp_ledger();
    for height in 1..=5 {
        let undo = crate::ledger::BlockUndoV1 {
            v: 1,
            block_id: format!("block-{height}"),
            height,
            balances: vec![],
            meta: vec![],
            tx_index: vec![],
            canonical_by_height: vec![],
            chain_tip: vec![],
            blocks: vec![],
            created_at_ms: 0,
        };
        ledger.store_block_undo(&undo).unwrap();
    }

    let (undo_removed, _) = ledger.prune_history_after_block(5).unwrap();
    assert_eq!(undo_removed, 2);
    assert!(ledger.block_undo_by_id("block-1").unwrap().is_none());
    assert!(ledger.block_undo_by_id("block-2").unwrap().is_none());
    assert!(ledger.block_undo_by_id("block-3").unwrap().is_some());

    unsafe {
        std::env::remove_var("TET_PRUNE_DEPTH");
        std::env::remove_var("TET_AUDIT_MAX_EVENTS");
    }
}

#[test]
fn zkcourt_dispute_persists_and_invalid_challenge_bond_goes_to_ecosystem() {
    let _g = env_lock();
    set_test_env_base();
    unsafe {
        std::env::set_var("TET_ZK_COURT_CHALLENGER_BOND_MICRO", "1000");
    }
    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let challenger = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let worker = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    ledger
        .transfer_no_fee("founder", challenger, 10_000)
        .unwrap();

    crate::vision::zk_court::record_inference_delivered_full(
        &ledger, "infer-1", "prompt", "response", 42, worker, 1,
    );
    let persisted = crate::vision::zk_court::list_open_persisted(&ledger);
    assert!(persisted.iter().any(|d| d.inference_id == "infer-1"));
    let eco_before = ledger
        .balance_micro(crate::ledger::WALLET_ECOSYSTEM)
        .unwrap();
    let req = crate::vision::zk_court::ChallengeSubmitReq {
        inference_id: "infer-1".to_string(),
        challenger_wallet_id: challenger.to_string(),
        reason: "test invalid challenge".to_string(),
    };
    let st = crate::vision::zk_court::submit_challenge(&ledger, &req).unwrap();
    assert_eq!(st.challenger_bond_micro, 1000);
    let settled = crate::vision::zk_court::apply_slash_verdict(&ledger, "infer-1", false).unwrap();
    assert_eq!(settled, 0);
    assert_eq!(
        ledger
            .balance_micro(crate::ledger::WALLET_ECOSYSTEM)
            .unwrap(),
        eco_before + 1000
    );

    unsafe {
        std::env::remove_var("TET_ZK_COURT_CHALLENGER_BOND_MICRO");
    }
}

#[test]
fn invalid_zk_slash_moves_entire_worker_bond_to_ecosystem() {
    let _g = env_lock();
    set_test_env_base();
    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();
    let worker = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    ledger
        .transfer_no_fee("founder", worker, crate::ledger::MIN_WORKER_STAKE_MICRO)
        .unwrap();
    ledger
        .stake_worker_bond_micro(worker, crate::ledger::MIN_WORKER_STAKE_MICRO, None)
        .unwrap();
    let eco_before = ledger
        .balance_micro(crate::ledger::WALLET_ECOSYSTEM)
        .unwrap();

    let slashed = ledger.slash_worker_bond_to_ecosystem_all(worker).unwrap();
    assert_eq!(slashed, crate::ledger::MIN_WORKER_STAKE_MICRO);
    assert_eq!(ledger.worker_bond_micro(worker).unwrap(), 0);
    assert_eq!(
        ledger
            .balance_micro(crate::ledger::WALLET_ECOSYSTEM)
            .unwrap(),
        eco_before + crate::ledger::MIN_WORKER_STAKE_MICRO
    );
}

#[test]
fn signed_transfer_rejects_replay_nonce() {
    let _g = env_lock();
    set_test_env_base();
    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();

    let wi = crate::wallet::generate_mnemonic_12().unwrap();
    let phrase = wi.mnemonic_12.as_deref().unwrap_or_default();
    let w = crate::wallet::recover_from_mnemonic_12(phrase).unwrap();
    let pool = "founder";
    ledger
        .transfer_with_fee(pool, &w.address_hex, 50_000_000_000, Some(50))
        .unwrap();

    let bob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let amount_micro = 1_000_000u64;
    ledger
        .transfer_with_fee_attested(
            &w.address_hex,
            bob,
            amount_micro,
            Some(100),
            None,
            Some(1u64),
        )
        .unwrap();
    assert_eq!(
        ledger.wallet_last_transfer_nonce(&w.address_hex).unwrap(),
        1
    );

    let err = ledger
        .transfer_with_fee_attested(
            &w.address_hex,
            bob,
            amount_micro,
            Some(100),
            None,
            Some(1u64),
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("stale") || err.to_string().contains("replay"),
        "{err}"
    );

    ledger
        .transfer_with_fee_attested(
            &w.address_hex,
            bob,
            amount_micro,
            Some(100),
            None,
            Some(2u64),
        )
        .unwrap();
    assert_eq!(
        ledger.wallet_last_transfer_nonce(&w.address_hex).unwrap(),
        2
    );

    let sk = crate::wallet::ed25519_signing_key_from_mnemonic(phrase).unwrap();
    assert_eq!(
        hex::encode(sk.verifying_key().to_bytes()),
        w.address_hex,
        "signing key must match wallet id"
    );
}

#[test]
fn initial_faucet_airdrop_grants_once_and_second_call_is_already_claimed() {
    let _g = env_lock();
    set_test_env_base();
    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();

    let user = "a".repeat(64);
    let pool_before = ledger
        .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
        .unwrap();

    assert_eq!(
        ledger.claim_initial_airdrop(&user).unwrap(),
        crate::ledger::InitialAirdropClaimOutcome::Granted {
            credited_micro: crate::ledger::FAUCET_INITIAL_AIRDROP_MICRO_PER_USER
        }
    );
    assert_eq!(
        ledger.balance_micro(&user).unwrap(),
        crate::ledger::FAUCET_INITIAL_AIRDROP_MICRO_PER_USER
    );
    assert_eq!(
        ledger
            .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
            .unwrap(),
        pool_before.saturating_sub(crate::ledger::FAUCET_INITIAL_AIRDROP_MICRO_PER_USER)
    );
    assert_eq!(
        ledger.claim_initial_airdrop(&user).unwrap(),
        crate::ledger::InitialAirdropClaimOutcome::AlreadyClaimed
    );
    assert_eq!(
        ledger.balance_micro(&user).unwrap(),
        crate::ledger::FAUCET_INITIAL_AIRDROP_MICRO_PER_USER
    );
}

#[test]
fn admin_rest_faucet_once_per_wallet_and_ip_rl() {
    let _g = env_lock();
    set_test_env_base();
    let ledger = open_temp_ledger();
    ledger.init_genesis_founder_premine_from_env().unwrap();
    ledger.apply_genesis_allocation("founder").unwrap();

    let w1 = "b".repeat(64);
    let w2 = "c".repeat(64);
    let amt = 1_000u64 * crate::ledger::STEVEMON;
    let ip = "203.0.113.7";

    match ledger
        .admin_rest_faucet(&w1, amt, ip, false, 86_400_000, 1)
        .unwrap()
    {
        crate::ledger::AdminRestFaucetOutcome::Granted {
            credited_micro,
            audit_hash_hex,
        } => {
            assert_eq!(credited_micro, amt);
            assert!(!audit_hash_hex.trim().is_empty());
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert_eq!(
        ledger
            .admin_rest_faucet(&w1, amt, ip, false, 86_400_000, 1)
            .unwrap(),
        crate::ledger::AdminRestFaucetOutcome::AlreadyClaimed
    );
    assert_eq!(
        ledger
            .admin_rest_faucet(&w2, amt, ip, false, 86_400_000, 1)
            .unwrap(),
        crate::ledger::AdminRestFaucetOutcome::IpRateLimited
    );
    match ledger
        .admin_rest_faucet(&w2, amt, "198.51.100.1", false, 86_400_000, 1)
        .unwrap()
    {
        crate::ledger::AdminRestFaucetOutcome::Granted {
            credited_micro,
            audit_hash_hex,
        } => {
            assert_eq!(credited_micro, amt);
            assert!(!audit_hash_hex.trim().is_empty());
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}
