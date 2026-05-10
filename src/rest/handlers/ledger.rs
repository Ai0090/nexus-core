use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine as _;
use serde::Serialize;
use std::net::SocketAddr;

use crate::{
    attestation::AttestationReport,
    ledger::{
        ADMIN_REST_FAUCET_MAX_AMOUNT_MICRO, AdminRestFaucetOutcome, BlockSummary,
        InitialAirdropClaimOutcome, MAX_SUPPLY_MICRO, MIN_WORKER_STAKE_MICRO, STEVEMON,
        TxIndexRecordV1,
    },
    protocol::{SignedTxEnvelopeV1, TxV1},
    rest::{
        ExplorerEventsQuery, FaucetReq, GuardianRecoverReq, LedgerMeQuery,
        LedgerWorkerBondStakeReq, LedgerWorkerBondUnstakeReq, MarketIndexResp, MintDemoReq,
        ProofsQuery, RestState, VaultHistoryQuery, WalletIdQuery,
        helpers::{require_admin_bearer, require_hybrid_sig, verify_envelope_v1},
    },
};

use sha2::Digest as _;
use solana_sdk::pubkey::Pubkey;

use crate::models::NetworkEvent;

fn faucet_bypass_limits() -> bool {
    matches!(
        std::env::var("TET_FAUCET_BYPASS_LIMITS").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("Yes")
    )
}

fn faucet_ip_window_ms() -> u64 {
    std::env::var("TET_FAUCET_IP_WINDOW_MS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(86_400_000)
}

fn faucet_max_per_ip_per_window() -> u32 {
    std::env::var("TET_FAUCET_MAX_PER_IP_PER_WINDOW")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(1)
        .max(1)
}

fn disable_rate_limit() -> bool {
    matches!(
        std::env::var("TET_DISABLE_RATE_LIMIT").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

fn faucet_also_mint_solana() -> bool {
    matches!(
        std::env::var("TET_FAUCET_ALSO_MINT_SOLANA").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

/// Prefer proxy headers when present; otherwise use the TCP peer IP.
fn extract_client_ip(headers: &HeaderMap, sock: SocketAddr) -> String {
    if let Some(ff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first) = ff.split(',').next()
    {
        let s = first.trim();
        if !s.is_empty() && s.len() <= 128 {
            return s.to_string();
        }
    }
    if let Some(r) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let s = r.trim();
        if !s.is_empty() && s.len() <= 128 {
            return s.to_string();
        }
    }
    sock.ip().to_string()
}

pub async fn get_explorer_events(
    State(state): State<RestState>,
    Query(q): Query<ExplorerEventsQuery>,
) -> axum::response::Response {
    let limit = q.limit.unwrap_or(200).clamp(1, 1_000);
    match state.ledger.audit_events_recent(limit) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}

pub async fn get_vault_history(
    State(state): State<RestState>,
    Query(q): Query<VaultHistoryQuery>,
) -> axum::response::Response {
    let wallet = q.wallet_id.trim().to_ascii_lowercase();
    if wallet.len() != 64 || !wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
    }
    let limit = q.limit.unwrap_or(200).clamp(1, 1_000);
    let ev = match state.ledger.audit_events_recent(2_000) {
        Ok(v) => v,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    };
    let mut out = Vec::new();
    for e in ev {
        let action = e
            .record
            .get("action")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let from = e
            .record
            .get("from_wallet")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let to = e
            .record
            .get("to_wallet")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let w = e
            .record
            .get("wallet")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let founder_wallet_id = e
            .record
            .get("founder_wallet_id")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let touched = from == wallet
            || to == wallet
            || w == wallet
            || founder_wallet_id == wallet
            || e.record
                .get("worker_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                == wallet;
        if !touched {
            continue;
        }
        // For now, include all actions; UI will group by action.
        if !action.is_empty() {
            out.push(e);
        }
        if out.len() >= limit {
            break;
        }
    }
    (StatusCode::OK, Json(out)).into_response()
}

pub async fn get_market_index(State(state): State<RestState>) -> axum::response::Response {
    let total_supply_micro = state.ledger.total_supply_micro().unwrap_or(0);
    let total_supply_tet = total_supply_micro as f64 / STEVEMON as f64;
    let r = MarketIndexResp {
        // UI-only reference peg (non-fiat wording). Do not treat as financial price feed.
        tet_usd_peg: 0.0,
        total_supply_cap_tet: 10_000_000_000u64,
        total_supply_tet,
        total_supply_micro,
        genesis_airdrop_tet: crate::ledger::GENESIS_1K_BONUS_TET,
    };
    (StatusCode::OK, Json(r)).into_response()
}

async fn post_ledger_recover_from_guardian_impl(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(req): Json<GuardianRecoverReq>,
) -> axum::response::Response {
    match crate::replication::verify_state_snapshot_signed(
        req.sha256_hex.trim(),
        req.snapshot_b64.trim(),
        req.ed25519_pubkey_hex.trim(),
        req.ed25519_sig_b64.trim(),
    ) {
        Ok(bytes) => match state.ledger.import_snapshot_json_v1(&bytes) {
            Ok(()) => {
                eprintln!(
                    "[REPL] Ledger restored from guardian sha256={}",
                    req.sha256_hex.trim()
                );
                (StatusCode::OK, "restored").into_response()
            }
            Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::UNAUTHORIZED, e).into_response(),
    }
}

async fn get_ledger_me_impl(
    State(state): State<RestState>,
    Query(q): Query<LedgerMeQuery>,
) -> impl IntoResponse {
    #[derive(Serialize)]
    struct R {
        wallet_id: String,
        // Canonical integer units for UIs (1 TET = 100,000,000 micro).
        balance_micro_tet: u64,
        locked_balance_micro_tet: u64,
        staked_micro_tet: u64,
        fee_total_micro_tet: u64,
        total_supply_micro_tet: u64,
        total_burned_micro_tet: u64,
        balance_tet: f64,
        locked_balance_tet: f64,
        staked_balance_tet: f64,
        fee_total_tet: f64,
        total_supply_tet: f64,
        total_burned_tet: f64,
        /// AI inference burn share attributed to this wallet (Stevemon micro).
        wallet_inference_burn_micro: u64,
        is_founder: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        founder_genesis_balance_tet: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        founder_genesis_locked_tet: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        founder_genesis_unlocked_tet: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        founder_genesis_unlocks_at_ms: Option<u128>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dex_treasury_earnings_tet: Option<f64>,
    }
    let wallet = q.wallet_id.trim().to_ascii_lowercase();
    if wallet.len() != 64 || !wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
    }
    let bal_micro = state.ledger.balance_micro(&wallet).unwrap_or(0);
    let locked = state.ledger.locked_balance_micro_now(&wallet).unwrap_or(0);
    let staked = state.ledger.staked_balance_micro(&wallet).unwrap_or(0);
    let fee = state.ledger.fee_total_micro().unwrap_or(0);
    let sup = state.ledger.total_supply_micro().unwrap_or(0);
    let burned = state.ledger.total_burned_micro().unwrap_or(0);
    let wallet_infer_burn = state
        .ledger
        .wallet_inference_burn_contribution_micro(&wallet);
    let founder = state.ledger.founder_wallet_public().unwrap_or_default();
    let is_founder = !founder.is_empty() && founder == wallet;

    let (fg_bal, fg_locked, fg_unlocked, fg_unlocks_at, dex_earn) = if is_founder {
        let unlock_at = state.ledger.founder_genesis_unlock_at_ms().ok();
        let locked_micro = state.ledger.founder_genesis_locked_micro().unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let locked_now = match unlock_at {
            Some(t) if t > now => locked_micro,
            _ => 0,
        };
        let unlocked_now = crate::ledger::GENESIS_FOUNDER_SHARE_MICRO.saturating_sub(locked_now);
        let dex_bal = state
            .ledger
            .balance_micro(crate::ledger::WALLET_DEX_TREASURY)
            .unwrap_or(0);
        (
            Some(crate::ledger::GENESIS_FOUNDER_SHARE_MICRO as f64 / STEVEMON as f64),
            Some(locked_now as f64 / STEVEMON as f64),
            Some(unlocked_now as f64 / STEVEMON as f64),
            unlock_at,
            Some(dex_bal as f64 / STEVEMON as f64),
        )
    } else {
        (None, None, None, None, None)
    };
    (
        StatusCode::OK,
        Json(R {
            wallet_id: wallet,
            balance_micro_tet: bal_micro,
            locked_balance_micro_tet: locked,
            staked_micro_tet: staked,
            fee_total_micro_tet: fee,
            total_supply_micro_tet: sup,
            total_burned_micro_tet: burned,
            wallet_inference_burn_micro: wallet_infer_burn,
            balance_tet: bal_micro as f64 / STEVEMON as f64,
            locked_balance_tet: locked as f64 / STEVEMON as f64,
            staked_balance_tet: staked as f64 / STEVEMON as f64,
            fee_total_tet: fee as f64 / STEVEMON as f64,
            total_supply_tet: sup as f64 / STEVEMON as f64,
            total_burned_tet: burned as f64 / STEVEMON as f64,
            is_founder,
            founder_genesis_balance_tet: fg_bal,
            founder_genesis_locked_tet: fg_locked,
            founder_genesis_unlocked_tet: fg_unlocked,
            founder_genesis_unlocks_at_ms: fg_unlocks_at,
            dex_treasury_earnings_tet: dex_earn,
        }),
    )
        .into_response()
}

async fn get_genesis_1k_status_impl(
    State(state): State<RestState>,
    Query(q): Query<WalletIdQuery>,
) -> impl IntoResponse {
    let w = q.wallet_id.trim().to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
    }
    match state.ledger.genesis_1k_status(&w) {
        Ok(s) => (StatusCode::OK, Json(s)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_initial_airdrop_claim_impl(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let _guard = state.genesis_1k_lock.lock().await;
    let w = headers
        .get("x-tet-wallet-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "missing/invalid x-tet-wallet-id").into_response();
    }
    let mldsa_pk_b64 = headers
        .get("x-tet-mldsa-pubkey-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let sig_b64 = headers
        .get("x-tet-ed25519-sig-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let mldsa_sig_b64 = headers
        .get("x-tet-mldsa-sig-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if sig_b64.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            "missing x-tet-ed25519-sig-b64 (hybrid initial airdrop claim)",
        )
            .into_response();
    }
    if mldsa_pk_b64.is_empty() || mldsa_sig_b64.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            "missing x-tet-mldsa-pubkey-b64 or x-tet-mldsa-sig-b64 (hybrid initial airdrop claim)",
        )
            .into_response();
    }
    let msg = crate::wallet::initial_airdrop_claim_hybrid_auth_message_bytes(&w, mldsa_pk_b64);
    if let Err(e) = crate::quantum_shield::verify_ed25519(&w, sig_b64, &msg) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid initial airdrop claim ed25519 signature: {e}"),
        )
            .into_response();
    }
    if let Err(e) = crate::wallet::verify_mldsa_b64(mldsa_pk_b64, mldsa_sig_b64, &msg) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid initial airdrop claim ml-dsa signature: {e}"),
        )
            .into_response();
    }
    match state.ledger.claim_initial_airdrop(&w) {
        Ok(InitialAirdropClaimOutcome::Granted { credited_micro }) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "outcome": "granted",
                "welcome_airdrop_micro": credited_micro,
                "welcome_airdrop_tet": crate::ledger::FAUCET_INITIAL_AIRDROP_TET_PER_USER,
            })),
        )
            .into_response(),
        Ok(InitialAirdropClaimOutcome::AlreadyClaimed) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "outcome": "already_claimed",
            })),
        )
            .into_response(),
        Ok(InitialAirdropClaimOutcome::CapReached) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "outcome": "cap_reached",
            })),
        )
            .into_response(),
        Ok(InitialAirdropClaimOutcome::PoolInsufficient) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "outcome": "pool_insufficient",
                "message": "Worker pool balance too low for welcome airdrop.",
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_genesis_1k_claim_impl(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let _guard = state.genesis_1k_lock.lock().await;
    let w = headers
        .get("x-tet-wallet-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "missing/invalid x-tet-wallet-id").into_response();
    }
    let sig_b64 = headers
        .get("x-tet-ed25519-sig-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let mldsa_pk_b64 = headers
        .get("x-tet-mldsa-pubkey-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let mldsa_sig_b64 = headers
        .get("x-tet-mldsa-sig-b64")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if sig_b64.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            "missing x-tet-ed25519-sig-b64 (hybrid genesis1k claim)",
        )
            .into_response();
    }
    if mldsa_pk_b64.is_empty() || mldsa_sig_b64.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            "missing x-tet-mldsa-pubkey-b64 or x-tet-mldsa-sig-b64 (hybrid genesis1k claim)",
        )
            .into_response();
    }
    let msg = crate::wallet::genesis_1k_claim_hybrid_auth_message_bytes(&w, mldsa_pk_b64);
    if let Err(e) = crate::quantum_shield::verify_ed25519(&w, sig_b64, &msg) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid genesis 1k claim ed25519 signature: {e}"),
        )
            .into_response();
    }
    if let Err(e) = crate::wallet::verify_mldsa_b64(mldsa_pk_b64, mldsa_sig_b64, &msg) {
        return (
            StatusCode::UNAUTHORIZED,
            format!("invalid genesis 1k claim ml-dsa signature: {e}"),
        )
            .into_response();
    }
    match state.ledger.genesis_1k_claim(&w) {
        Ok(slot) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "slot": slot,
                "bonus_tet": crate::ledger::GENESIS_1K_BONUS_TET,
                "bonus_micro": crate::ledger::GENESIS_1K_BONUS_TET.saturating_mul(crate::ledger::STEVEMON),
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn get_ledger_balance_impl(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    #[derive(Serialize)]
    struct R {
        wallet_id: String,
        balance_tet: f64,
        locked_balance_tet: f64,
    }
    let w = wallet.trim();
    let bal = state.ledger.balance_micro(w).unwrap_or(0);
    let locked = state.ledger.locked_balance_micro_now(w).unwrap_or(0);
    (
        StatusCode::OK,
        Json(R {
            wallet_id: wallet,
            balance_tet: bal as f64 / STEVEMON as f64,
            locked_balance_tet: locked as f64 / STEVEMON as f64,
        }),
    )
        .into_response()
}

async fn post_transfer_enveloped_impl(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> impl IntoResponse {
    let _tx_bytes = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };
    let TxV1::Transfer {
        from_wallet,
        to_wallet: _,
        amount_micro,
        fee_bps: _,
    } = env.tx.clone()
    else {
        return (StatusCode::BAD_REQUEST, "expected transfer tx").into_response();
    };
    if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "amount exceeds hard cap").into_response();
    }
    // Phase 2: precheck only (no DB mutation); enqueue into mempool and return 202 Accepted.
    let spendable = state
        .ledger
        .spendable_balance_micro_now(&from_wallet)
        .unwrap_or(0);
    if spendable < amount_micro {
        return (StatusCode::BAD_REQUEST, "insufficient funds").into_response();
    }

    if let Err(e) = state.enqueue_mempool_tx(env).await {
        return (StatusCode::TOO_MANY_REQUESTS, e.to_string()).into_response();
    }

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ok": true,
            "status": "pending",
            "queued": true
        })),
    )
        .into_response()
}

async fn post_mint_demo_impl(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<MintDemoReq>,
) -> impl IntoResponse {
    if let Err(r) = require_admin_bearer(&headers) {
        return r;
    }
    if !req.amount_tet.is_finite() || req.amount_tet <= 0.0 {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    if req.amount_tet > 10_000_000_000.0 {
        return (StatusCode::BAD_REQUEST, "amount exceeds hard cap").into_response();
    }
    let gross_micro = (req.amount_tet * STEVEMON as f64).round().max(0.0) as u64;
    if gross_micro == 0 || gross_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "amount exceeds hard cap").into_response();
    }
    let note = req.energy_note.unwrap_or_default();
    let payload = format!("energy_note:{note}").into_bytes();
    let wallet = headers
        .get("x-tet-wallet-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if wallet.len() != 64 || !wallet.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "missing/invalid x-tet-wallet-id").into_response();
    }
    let msg = format!(
        "tet-tx-v1|mint_demo|to={}|gross_micro={}|payload_sha256={}",
        wallet,
        gross_micro,
        hex::encode(sha2::Sha256::digest(&payload))
    );
    if let Err(r) = require_hybrid_sig(&headers, &wallet, msg.as_bytes()) {
        return r;
    }
    let ed_sig = headers
        .get("x-tet-ed25519-sig-b64")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mldsa_pk = headers
        .get("x-tet-mldsa-pubkey-b64")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mldsa_sig = headers
        .get("x-tet-mldsa-sig-b64")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    match state
        .ledger
        .mint_reward_with_proof(&wallet, gross_micro, &payload, None, false)
    {
        Ok((_gross, _net, _fee, proof_id)) => {
            if let Ok(p) = state.ledger.get_proof(proof_id) {
                if let Some(tx) = state.p2p_tx.as_ref()
                    && let Ok(bytes) =
                        serde_json::to_vec(&crate::network::LedgerGossip::ProofAnnounce {
                            signer_wallet_id: wallet.clone(),
                            id: p.id,
                            hash_sha256_hex: p.hash_sha256_hex.clone(),
                            ed25519_sig_b64: ed_sig.clone(),
                            mldsa_pubkey_b64: mldsa_pk.clone(),
                            mldsa_sig_b64: mldsa_sig.clone(),
                        })
                {
                    let _ = tx.send(bytes);
                }

                // NOTE: mint_demo is a local-only mint helper; do not sync as a transfer event.
                (StatusCode::OK, Json(p)).into_response()
            } else {
                (StatusCode::OK, "ok").into_response()
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_ledger_faucet_impl(
    State(state): State<RestState>,
    headers: HeaderMap,
    ConnectInfo(sock): ConnectInfo<SocketAddr>,
    Json(req): Json<FaucetReq>,
) -> impl IntoResponse {
    if let Err(r) = require_admin_bearer(&headers) {
        return r;
    }
    let w = req.wallet_id.trim().to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
    }
    let bytes = match hex::decode(w.as_bytes()) {
        Ok(v) => v,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
        }
    };
    let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 32 bytes").into_response();
    };
    let pk = Pubkey::new_from_array(arr);
    let amount_tet = req
        .amount_tet
        .unwrap_or(100.0)
        .clamp(0.00000001, 1_000_000.0);
    let amount_micro = (amount_tet * STEVEMON as f64).round() as u64;
    if amount_micro == 0 {
        return (StatusCode::BAD_REQUEST, "amount_tet too small").into_response();
    }
    if amount_micro > ADMIN_REST_FAUCET_MAX_AMOUNT_MICRO {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "amount_micro exceeds single-grant cap ({})",
                ADMIN_REST_FAUCET_MAX_AMOUNT_MICRO
            ),
        )
            .into_response();
    }

    let bypass = faucet_bypass_limits();
    let ip_label = extract_client_ip(&headers, sock);
    let (window_ms, max_ip) = if disable_rate_limit() {
        // Local/dev bypass: keep one-time-per-wallet rule, only skip IP-based RL.
        // Setting max_ip very high prevents `admin_faucet_ip_rl` while still recording the row.
        (faucet_ip_window_ms(), u32::MAX)
    } else {
        (faucet_ip_window_ms(), faucet_max_per_ip_per_window())
    };

    match state
        .ledger
        .admin_rest_faucet(&w, amount_micro, &ip_label, bypass, window_ms, max_ip)
    {
        Ok(AdminRestFaucetOutcome::Granted {
            credited_micro,
            audit_hash_hex,
        }) => {
            let mut solana_sig: Option<String> = None;
            if faucet_also_mint_solana() {
                match state.solana.faucet_tet(&pk, credited_micro) {
                    Ok(sig) => solana_sig = Some(sig),
                    Err(e) => {
                        log::error!(
                            "[solana][faucet] ledger credited but SPL mint failed wallet_id={} err={e:?}",
                            w
                        );
                    }
                }
            }

            if let Some(tx) = state.gossip_tx.clone() {
                let event = NetworkEvent::FaucetExecuted {
                    event_id: audit_hash_hex.clone(),
                    to_wallet: w.clone(),
                    amount_micro: credited_micro,
                };
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = tx.send(json).await;
                }
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "to_wallet_id": w,
                    "amount_micro_tet": credited_micro,
                    "audit_hash_hex": audit_hash_hex,
                    "ledger": "credited",
                    "solana_sig": solana_sig,
                })),
            )
                .into_response()
        }
        Ok(AdminRestFaucetOutcome::AlreadyClaimed) => {
            (
                StatusCode::FORBIDDEN,
                "faucet: this wallet already received its admin faucet grant",
            )
                .into_response()
        }
        Ok(AdminRestFaucetOutcome::IpRateLimited) => (
            StatusCode::TOO_MANY_REQUESTS,
            "faucet: IP rate limit (see TET_FAUCET_IP_WINDOW_MS / TET_FAUCET_MAX_PER_IP_PER_WINDOW)",
        )
            .into_response(),
        Ok(AdminRestFaucetOutcome::PoolInsufficient) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "faucet: worker pool balance insufficient for this grant",
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_genesis_bridge_enveloped_impl(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> impl IntoResponse {
    let _tx_bytes = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };
    let founder = state.ledger.founder_wallet_public().unwrap_or_default();
    let TxV1::GenesisBridge {
        founder_wallet,
        to_wallet,
        amount_micro,
    } = env.tx.clone()
    else {
        return (StatusCode::BAD_REQUEST, "expected genesis_bridge tx").into_response();
    };
    if founder_wallet != founder {
        return (StatusCode::UNAUTHORIZED, "founder wallet required").into_response();
    }
    if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "amount exceeds hard cap").into_response();
    }
    let att = AttestationReport {
        v: 1,
        platform: env.attestation.platform.clone(),
        report_b64: env.attestation.report_b64.clone(),
    };
    match state.ledger.transfer_with_fee_attested(
        &founder_wallet,
        &to_wallet,
        amount_micro,
        Some(50),
        Some(&att),
        None,
    ) {
        Ok((net, fee)) => {
            if let Some(tx) = state.gossip_tx.clone() {
                let tx_hash = format!("0x{}", hex::encode(sha2::Sha256::digest(&_tx_bytes)));
                let event = NetworkEvent::TransferExecuted {
                    tx_hash,
                    from_wallet: founder_wallet.clone(),
                    to_wallet: to_wallet.clone(),
                    amount_micro,
                    fee_bps: 50,
                };
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = tx.send(json).await;
                }
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({"net_micro": net, "fee_micro": fee})),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_tx_submit_impl(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> axum::response::Response {
    let _ = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };
    match env.tx {
        TxV1::SignerLink { .. } => (StatusCode::BAD_REQUEST, "use /signer/link").into_response(),
        TxV1::FoundingMemberEnroll { .. } => {
            (StatusCode::BAD_REQUEST, "use /founding/enroll").into_response()
        }
        TxV1::Transfer { .. } => post_transfer_enveloped_impl(State(state), headers, Json(env))
            .await
            .into_response(),
        TxV1::GenesisBridge { .. } => {
            post_genesis_bridge_enveloped_impl(State(state), headers, Json(env))
                .await
                .into_response()
        }
        TxV1::EnterpriseInference { .. } => {
            crate::rest::handlers::enterprise::post_enterprise_inference_submit(
                State(state),
                headers,
                Json(env),
            )
            .await
            .into_response()
        }
        TxV1::VerifyZkProof { .. } => post_ledger_zk_verify(State(state), headers, Json(env))
            .await
            .into_response(),
    }
}

async fn get_proofs_impl(
    State(state): State<RestState>,
    Query(q): Query<ProofsQuery>,
) -> impl IntoResponse {
    let v = state
        .ledger
        .list_proofs(q.limit.unwrap_or(50), q.before_id)
        .unwrap_or_default();
    (StatusCode::OK, Json(v)).into_response()
}

async fn get_proof_by_id_impl(
    State(state): State<RestState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.ledger.get_proof(id) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

pub async fn get_ledger_me(
    State(state): State<RestState>,
    Query(q): Query<LedgerMeQuery>,
) -> impl IntoResponse {
    get_ledger_me_impl(State(state), Query(q)).await
}

pub async fn get_ledger_state(State(state): State<RestState>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct R {
        block_height: u64,
        mempool_len: usize,
        state_root: String,
    }
    let mempool_len = {
        let mp = state.mempool.lock().await;
        mp.len()
    };
    let block_height = state.ledger.block_height().unwrap_or(0);
    let state_root = state.ledger.compute_state_root();
    (
        StatusCode::OK,
        Json(R {
            block_height,
            mempool_len,
            state_root,
        }),
    )
        .into_response()
}

pub async fn get_ledger_blocks(State(state): State<RestState>) -> impl IntoResponse {
    let v: Vec<BlockSummary> = state.ledger.recent_blocks(20);
    (StatusCode::OK, Json(v)).into_response()
}

#[derive(Serialize)]
struct LedgerBlockDetailResp {
    block: BlockSummary,
    txs: Vec<TxIndexRecordV1>,
}

pub async fn get_ledger_block(
    State(state): State<RestState>,
    Path(height): Path<u64>,
) -> impl IntoResponse {
    let block = match state.ledger.block_summary_by_height(height) {
        Ok(Some(block)) => block,
        Ok(None) => return (StatusCode::NOT_FOUND, "block not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let txs = match state.ledger.txs_by_block_height(height, 500) {
        Ok(txs) => txs,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    (StatusCode::OK, Json(LedgerBlockDetailResp { block, txs })).into_response()
}

fn decoded_zk_journal_json(journal_b64: &str) -> Option<serde_json::Value> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(journal_b64.as_bytes())
        .ok()?;
    if let Ok(j) = bincode::deserialize::<crate::zk_verifier::ZkCourtJournalV1>(&bytes) {
        return Some(serde_json::json!({
            "type": "ZkCourtJournalV1",
            "commitment_sha256_hex": hex::encode(j.commitment_sha256),
            "flops_u64": j.flops_u64,
            "worker_pubkey_hex": hex::encode(j.worker_pubkey_bytes),
        }));
    }
    if let Ok(j) = bincode::deserialize::<crate::zk_verifier::InferenceJournalV1>(&bytes) {
        return Some(serde_json::json!({
            "type": "InferenceJournalV1",
            "prompt_hash_hex": hex::encode(j.prompt_hash),
            "response_hash_hex": hex::encode(j.response_hash),
            "cost_micro": j.cost_micro,
            "worker_pubkey_hex": hex::encode(j.worker_pubkey_bytes),
        }));
    }
    None
}

pub async fn get_explorer_tx(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let Some(row) = (match state.ledger.tx_by_hash(&hash) {
        Ok(row) => row,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }) else {
        return (StatusCode::NOT_FOUND, "tx not found").into_response();
    };

    let (zk_journal, task) = match &row.tx.tx {
        TxV1::VerifyZkProof {
            task_id,
            journal_b64,
            ..
        } => {
            let task = if task_id.trim().is_empty() {
                None
            } else {
                state.ledger.ai_workload_task(task_id).ok().flatten()
            };
            (decoded_zk_journal_json(journal_b64), task)
        }
        TxV1::EnterpriseInference { .. } => (
            None,
            state.ledger.ai_workload_task(&row.hash).ok().flatten(),
        ),
        _ => (None, None),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "found": true,
            "source": "tx_index_v1",
            "hash": row.hash,
            "block_height": row.block_height,
            "tx_index": row.tx_index,
            "tx_kind": row.tx_kind,
            "workload_flag": row.workload_flag,
            "signer_wallet": row.signer_wallet,
            "indexed_at_ms": row.indexed_at_ms,
            "tx": row.tx,
            "zk_journal": zk_journal,
            "task": task,
        })),
    )
        .into_response()
}

pub async fn get_ledger_balance(
    State(state): State<RestState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    get_ledger_balance_impl(State(state), Path(wallet)).await
}

pub async fn post_transfer_enveloped(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> impl IntoResponse {
    post_transfer_enveloped_impl(State(state), headers, Json(env)).await
}

pub async fn post_mint_demo(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<MintDemoReq>,
) -> impl IntoResponse {
    post_mint_demo_impl(State(state), headers, Json(req)).await
}

pub async fn post_ledger_faucet(
    State(state): State<RestState>,
    headers: HeaderMap,
    ConnectInfo(sock): ConnectInfo<SocketAddr>,
    Json(req): Json<FaucetReq>,
) -> impl IntoResponse {
    post_ledger_faucet_impl(State(state), headers, ConnectInfo(sock), Json(req)).await
}

pub async fn post_ledger_mine(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(r) = require_admin_bearer(&headers) {
        return r;
    }

    match crate::consensus::mine_pending_block(state).await {
        Ok(outcome) if !outcome.mined => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "mined": false, "tx_count": 0 })),
        )
            .into_response(),
        Ok(outcome) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "mined": true,
                "block_height": outcome.block_height,
                "block_id": outcome.block_id,
                "producer_id": outcome.producer_id,
                "state_root": outcome.state_root,
                "tx_hashes": outcome.tx_hashes,
                "tx_count": outcome.tx_count,
                "base_reward_micro": outcome.reward.base_reward_micro,
                "compute_reward_micro": outcome.reward.compute_reward_micro,
                "total_reward_micro": outcome.reward.total_reward_micro,
            })),
        )
            .into_response(),
        Err(crate::consensus::MineError::Unauthorized(e)) => {
            (StatusCode::UNAUTHORIZED, e).into_response()
        }
        Err(crate::consensus::MineError::BadRequest(e)) => {
            (StatusCode::BAD_REQUEST, e).into_response()
        }
    }
}

pub async fn post_ledger_zk_verify(
    State(state): State<RestState>,
    _headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> impl IntoResponse {
    let _tx_bytes = match verify_envelope_v1(&env) {
        Ok(b) => b,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };

    let TxV1::VerifyZkProof {
        task_id,
        image_id,
        journal_b64,
        receipt_b64,
    } = env.tx.clone()
    else {
        return (StatusCode::BAD_REQUEST, "expected verify_zk_proof tx").into_response();
    };

    // Ensure the submitted image_id matches what this chain is configured to accept.
    if image_id != methods::NEXUS_GUEST_ID {
        return (StatusCode::BAD_REQUEST, "image_id mismatch").into_response();
    }

    if !task_id.trim().is_empty() {
        match state.ledger.ai_workload_task(&task_id) {
            Ok(Some(task)) if task.processed => {
                return (
                    StatusCode::CONFLICT,
                    format!("task already processed: {}", task_id.trim()),
                )
                    .into_response();
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("unknown task_id: {}", task_id.trim()),
                )
                    .into_response();
            }
            Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
        }
    }

    if let Err(e) =
        crate::zk_verifier::verify_tx_receipt_and_journal(image_id, &journal_b64, &receipt_b64)
    {
        let worker = env.sig.ed25519_pubkey_hex.trim().to_ascii_lowercase();
        let slashed = state
            .ledger
            .slash_worker_bond_to_ecosystem_all(&worker)
            .unwrap_or(0);
        log::error!(
            "[zk-slash] invalid receipt submission worker={} slashed_micro={} err={}",
            worker,
            slashed,
            e
        );
        return (
            StatusCode::BAD_REQUEST,
            format!("receipt verify error: {e}; worker bond slashed_micro={slashed}"),
        )
            .into_response();
    }

    // Enqueue into mempool (Phase 2: pending until mined).
    if let Err(e) = state.enqueue_mempool_tx(env).await {
        return (StatusCode::TOO_MANY_REQUESTS, e.to_string()).into_response();
    }

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "ok": true, "status": "pending", "queued": true })),
    )
        .into_response()
}

pub async fn get_proofs(
    State(state): State<RestState>,
    Query(q): Query<ProofsQuery>,
) -> impl IntoResponse {
    get_proofs_impl(State(state), Query(q)).await
}

pub async fn get_proof_by_id(
    State(state): State<RestState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    get_proof_by_id_impl(State(state), Path(id)).await
}

pub async fn post_genesis_bridge_enveloped(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> impl IntoResponse {
    post_genesis_bridge_enveloped_impl(State(state), headers, Json(env)).await
}

pub async fn post_tx_submit(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(env): Json<SignedTxEnvelopeV1>,
) -> axum::response::Response {
    post_tx_submit_impl(State(state), headers, Json(env)).await
}

pub async fn post_ledger_recover_from_guardian(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<GuardianRecoverReq>,
) -> axum::response::Response {
    post_ledger_recover_from_guardian_impl(State(state), headers, Json(req)).await
}

pub async fn get_genesis_1k_status(
    State(state): State<RestState>,
    Query(q): Query<WalletIdQuery>,
) -> impl IntoResponse {
    get_genesis_1k_status_impl(State(state), Query(q)).await
}

pub async fn post_genesis_1k_claim(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    post_genesis_1k_claim_impl(State(state), headers).await
}

pub async fn post_initial_airdrop_claim(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    post_initial_airdrop_claim_impl(State(state), headers).await
}

async fn post_ledger_worker_bond_stake_impl(
    State(state): State<RestState>,
    Json(req): Json<LedgerWorkerBondStakeReq>,
) -> axum::response::Response {
    const MAX_B64_FIELD: usize = 32_768;
    if req.wallet_id.len() > 256
        || req.ed25519_sig_hex.len() > 200
        || req.mldsa_pubkey_b64.len() > MAX_B64_FIELD
        || req.mldsa_sig_b64.len() > MAX_B64_FIELD
    {
        return (StatusCode::BAD_REQUEST, "fields exceed maximum length").into_response();
    }
    let w = req.wallet_id.trim().to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
    }
    if req.nonce == 0 {
        return (StatusCode::BAD_REQUEST, "nonce must be > 0").into_response();
    }
    if !req.amount_tet.is_finite() || req.amount_tet <= 0.0 {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    let amount_micro = (req.amount_tet * STEVEMON as f64).round().max(0.0) as u64;
    if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    let msg = crate::wallet::worker_bond_stake_hybrid_auth_message_bytes(
        &w,
        amount_micro,
        req.nonce,
        &req.mldsa_pubkey_b64,
    );
    if let Err(e) = crate::wallet::verify_ed25519_hex_message(&w, &msg, req.ed25519_sig_hex.trim())
    {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }
    if let Err(e) = crate::wallet::verify_mldsa_b64(&req.mldsa_pubkey_b64, &req.mldsa_sig_b64, &msg)
    {
        return (StatusCode::UNAUTHORIZED, e.to_string()).into_response();
    }
    match state
        .ledger
        .stake_worker_bond_micro(&w, amount_micro, Some(req.nonce))
    {
        Ok((moved_micro, new_bond_micro)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "wallet_id": w,
                "moved_micro": moved_micro,
                "worker_bond_micro": new_bond_micro,
                "min_active_worker_bond_micro": MIN_WORKER_STAKE_MICRO,
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn post_ledger_worker_bond_unstake_impl(
    State(state): State<RestState>,
    Json(req): Json<LedgerWorkerBondUnstakeReq>,
) -> axum::response::Response {
    const MAX_B64_FIELD: usize = 32_768;
    if req.wallet_id.len() > 256
        || req.ed25519_sig_hex.len() > 200
        || req.mldsa_pubkey_b64.len() > MAX_B64_FIELD
        || req.mldsa_sig_b64.len() > MAX_B64_FIELD
    {
        return (StatusCode::BAD_REQUEST, "fields exceed maximum length").into_response();
    }
    let w = req.wallet_id.trim().to_ascii_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "wallet_id must be 64 hex chars").into_response();
    }
    if req.nonce == 0 {
        return (StatusCode::BAD_REQUEST, "nonce must be > 0").into_response();
    }
    if !req.amount_tet.is_finite() || req.amount_tet <= 0.0 {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    let amount_micro = (req.amount_tet * STEVEMON as f64).round().max(0.0) as u64;
    if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    }
    let msg = crate::wallet::worker_bond_unstake_hybrid_auth_message_bytes(
        &w,
        amount_micro,
        req.nonce,
        &req.mldsa_pubkey_b64,
    );
    if let Err(e) = crate::wallet::verify_ed25519_hex_message(&w, &msg, req.ed25519_sig_hex.trim())
    {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }
    if let Err(e) = crate::wallet::verify_mldsa_b64(&req.mldsa_pubkey_b64, &req.mldsa_sig_b64, &msg)
    {
        return (StatusCode::UNAUTHORIZED, e.to_string()).into_response();
    }
    match state
        .ledger
        .unstake_worker_bond_micro(&w, amount_micro, Some(req.nonce))
    {
        Ok((moved_micro, new_bond_micro)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "wallet_id": w,
                "moved_micro": moved_micro,
                "worker_bond_micro": new_bond_micro,
                "min_active_worker_bond_micro": MIN_WORKER_STAKE_MICRO,
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn post_ledger_stake(
    State(state): State<RestState>,
    Json(req): Json<LedgerWorkerBondStakeReq>,
) -> axum::response::Response {
    post_ledger_worker_bond_stake_impl(State(state), Json(req)).await
}

pub async fn post_ledger_unstake(
    State(state): State<RestState>,
    Json(req): Json<LedgerWorkerBondUnstakeReq>,
) -> axum::response::Response {
    post_ledger_worker_bond_unstake_impl(State(state), Json(req)).await
}
