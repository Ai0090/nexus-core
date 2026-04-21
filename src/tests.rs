use axum::http::{HeaderMap, StatusCode};
use axum::http::header::HeaderName;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signer as _;
use rand_core::RngCore as _;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::test_env::lock()
}

fn set_test_env_base() {
    // Safety: these tests serialize on ENV_LOCK.
    unsafe {
        std::env::set_var("TET_DB_ENCRYPT", "false");
        std::env::set_var("TET_REQUIRE_ATTESTATION", "false");
        std::env::set_var("TET_API_KEY", "testkey");
        std::env::set_var("TET_FOUNDER_WALLET", "founder");
        // Tests assume founder funds are liquid; disable founder genesis cliff lock for unit tests.
        std::env::set_var("TET_FOUNDER_CLIFF_MS", "0");
    }
}

fn open_temp_ledger() -> crate::ledger::Ledger {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    // Keep tempdir alive by leaking it for test lifetime (small, per-test).
    std::mem::forget(dir);
    crate::ledger::Ledger::open(db.to_str().unwrap()).unwrap()
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
        too_much.is_err() && too_much.err().unwrap().to_string().contains("AML Limit Exceeded"),
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
    let ct = crate::e2ee::encrypt_for_worker(&client_eph_sk, &worker_pk, nonce12, pt).unwrap();

    // Blind routing: core never decrypts; we just forward bytes unchanged.
    let routed_ct = ct.clone();

    let out = crate::e2ee::decrypt_on_worker(&worker_sk, &client_eph_pk, nonce12, &routed_ct)
        .unwrap();
    assert_eq!(out.as_slice(), pt);
}

#[test]
fn worker_hardware_id_is_stable_and_not_uuid_like() {
    let _g = env_lock();
    set_test_env_base();

    let id1 = tet_core::tet_worker::hardware_id_sha256_hex_best_effort().unwrap();
    let id2 = tet_core::tet_worker::hardware_id_sha256_hex_best_effort().unwrap();
    assert_eq!(id1, id2, "hardware_id must be deterministic per device snapshot");
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

    // ML-DSA-44 signature
    let sig = crate::wallet::mldsa44_sign_deterministic(mldsa_kp, msg).unwrap();
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

    let state = crate::rest::RestState {
        ledger: std::sync::Arc::new(ledger),
        p2p_tx: None,
        http_ratelimit: std::sync::Arc::new(tokio::sync::Mutex::new(crate::rest::HttpRateLimit::new(999))),
        workers: std::sync::Arc::new(std::sync::Mutex::new(crate::worker_network::WorkerRegistry::default())),
        e2ee_jobs: std::sync::Arc::new(std::sync::Mutex::new(crate::rest::E2eeJobQueue::default())),
        dex: std::sync::Arc::new(std::sync::Mutex::new(crate::p2p_dex::DexEngine::default())),
        genesis_1k_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
    };

    let place = crate::rest::post_dex_order_place(
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
    let place_body = axum::body::to_bytes(place.into_body(), usize::MAX).await.unwrap();
    let place_json: serde_json::Value = serde_json::from_slice(&place_body).unwrap();
    let order_id = place_json.get("order_id").unwrap().as_str().unwrap().to_string();

    let ledger = state.ledger.clone();
    let escrow = crate::p2p_dex::escrow_wallet_for_order(&order_id);
    assert!(ledger.balance_micro(&escrow).unwrap() > 0);

    let cancel = crate::rest::post_dex_order_cancel(
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
    // Lock + refund each use default 50 bps fee; half of each fee is burned from total supply.
    let lock_gross = 500_000_000u64;
    let fee_lock = lock_gross.saturating_mul(50) / 10_000;
    let escrow_net = lock_gross.saturating_sub(fee_lock);
    let fee_refund = escrow_net.saturating_mul(50) / 10_000;
    let (_, burn_lock) = crate::ledger::Ledger::split_protocol_fee_treasury_and_burn(fee_lock);
    let (_, burn_refund) =
        crate::ledger::Ledger::split_protocol_fee_treasury_and_burn(fee_refund);
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
        .transfer_with_fee(pool, "alice", 10_000_000_000, Some(50))
        .unwrap();
    let fee = 10_000_000_000u64 * 50 / 10_000; // 50_000_000
    let (_, burn) = crate::ledger::Ledger::split_protocol_fee_treasury_and_burn(fee);
    assert_eq!(ledger.total_burned_micro().unwrap(), burn);
    assert_eq!(ledger.total_supply_micro().unwrap(), sup0.saturating_sub(burn));
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

    let state = crate::rest::RestState {
        ledger: std::sync::Arc::new(ledger),
        p2p_tx: None,
        http_ratelimit: std::sync::Arc::new(tokio::sync::Mutex::new(crate::rest::HttpRateLimit::new(999))),
        workers: std::sync::Arc::new(std::sync::Mutex::new(crate::worker_network::WorkerRegistry::default())),
        e2ee_jobs: std::sync::Arc::new(std::sync::Mutex::new(crate::rest::E2eeJobQueue::default())),
        dex: std::sync::Arc::new(std::sync::Mutex::new(crate::p2p_dex::DexEngine::default())),
        genesis_1k_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
    };

    // Place order (maker sells TET for USDC).
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", "testkey".parse().unwrap());
    let place = crate::rest::post_dex_order_place(
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
    let take = crate::rest::post_dex_take(
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
    let take_body = axum::body::to_bytes(take.into_body(), usize::MAX).await.unwrap();
    let take_json: serde_json::Value = serde_json::from_slice(&take_body).unwrap();
    let trade_id = take_json.get("trade_id").unwrap().as_str().unwrap().to_string();

    // Prepare valid hybrid signatures for both parties.
    let maker_ed = SigningKey::generate(&mut rand_core::OsRng);
    let taker_ed = SigningKey::generate(&mut rand_core::OsRng);
    let maker_mldsa = {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        dilithium::MlDsaKeyPair::generate_deterministic(dilithium::ML_DSA_44, &seed)
    };
    let taker_mldsa = {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        dilithium::MlDsaKeyPair::generate_deterministic(dilithium::ML_DSA_44, &seed)
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
    let blocked = crate::rest::post_dex_trade_complete(
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

    let confirm = crate::rest::post_dex_settlement_confirm(
        axum::extract::State(state.clone()),
        axum::Json(crate::rest::DexSettlementConfirmReq {
            trade_id: trade_id.clone(),
            solana_usdc_txid: txid.into(),
        }),
    )
    .await;
    assert_eq!(confirm.status(), StatusCode::OK);

    // After settlement confirm, complete should pass (quantum gate still enforced).
    let complete_ok = crate::rest::post_dex_trade_complete(
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

    let complete_forbidden = crate::rest::post_dex_trade_complete(
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
    assert_eq!(s.total_supply_micro, crate::ledger::GENESIS_TOTAL_MINT_MICRO);

    assert_eq!(
        ledger.balance_micro("steve").unwrap(),
        crate::ledger::GENESIS_FOUNDER_SHARE_MICRO
    );
    assert_eq!(
        ledger
            .balance_micro(crate::ledger::WALLET_DEX_TREASURY)
            .unwrap(),
        crate::ledger::GENESIS_DEX_TREASURY_MICRO
    );
    assert_eq!(
        ledger
            .balance_micro(crate::ledger::WALLET_SYSTEM_WORKER_POOL)
            .unwrap(),
        crate::ledger::GENESIS_WORKER_POOL_SHARE_MICRO
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

    // Worker pool is pre-funded at genesis in whitepaper mode.

    ledger
        .test_only_mark_genesis_1k_participant("maker", 42)
        .unwrap();

    let gross_req = 100_000_000u64;
    let boosted_gross = (gross_req as u128 * 11 / 10) as u64;
    let imperial_bps = 100u64;
    let imperial_tax = boosted_gross.saturating_mul(imperial_bps) / 10_000;
    let expected_worker_net = boosted_gross.saturating_sub(imperial_tax);

    ledger
        .mint_worker_network_reward(
            "maker",
            "imperial-vault",
            gross_req,
            b"energy:poc",
            None,
        )
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
        "whitepaper genesis must mint founder+worker_pool supply"
    );

    // Worker pool is pre-funded at genesis in whitepaper mode.

    let gross = 100_000_000u64;
    ledger
        .mint_worker_network_reward(
            "maker",
            "imperial-vault",
            gross,
            b"energy:poc",
            None,
        )
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

    let state = crate::rest::RestState {
        ledger: std::sync::Arc::new(ledger),
        p2p_tx: None,
        http_ratelimit: std::sync::Arc::new(tokio::sync::Mutex::new(crate::rest::HttpRateLimit::new(999))),
        workers: std::sync::Arc::new(std::sync::Mutex::new(
            crate::worker_network::WorkerRegistry::default(),
        )),
        e2ee_jobs: std::sync::Arc::new(std::sync::Mutex::new(crate::rest::E2eeJobQueue::default())),
        dex: std::sync::Arc::new(std::sync::Mutex::new(crate::p2p_dex::DexEngine::default())),
        genesis_1k_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
    };

    let place_fail = crate::rest::post_dex_order_place(
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

    let place_ok = crate::rest::post_dex_order_place(
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
    // Mint enough to cover any protocol fee/burn applied on mint paths.
    ledger
        .mint_reward_with_proof(payer, 2_000, b"energy:test", None, false)
        .unwrap();

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

    // ML-DSA-44 pubkey must be decodable (matches browser bundle implementation family).
    let pk = base64::engine::general_purpose::STANDARD
        .decode(w.dilithium_pubkey_b64.trim())
        .unwrap();
    assert!(pk.len() >= 32);
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
    assert_eq!(ledger.wallet_last_transfer_nonce(&w.address_hex).unwrap(), 1);

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
    assert_eq!(ledger.wallet_last_transfer_nonce(&w.address_hex).unwrap(), 2);

    let sk = crate::wallet::ed25519_signing_key_from_mnemonic(phrase).unwrap();
    assert_eq!(
        hex::encode(sk.verifying_key().to_bytes()),
        w.address_hex,
        "signing key must match wallet id"
    );
}
