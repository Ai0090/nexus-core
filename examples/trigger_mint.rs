//! Local P2P / ledger smoke: fund a test wallet via **admin faucet** (pool → user, **no new mint**),
//! then submit a **signed `Transfer`** envelope to `POST /ledger/transfer`.
//!
//! Why not `mint_demo`? Genesis already credits [`MAX_SUPPLY_MICRO`]; additional mints hit the hard cap by design.
//!
//! ## One-shot run
//!
//! ```text
//! export TET_ADMIN_API_KEY=dev
//! export TET_SENDER_MNEMONIC="twelve words ..."
//! cargo run --example trigger_mint
//! ```
//!
//! Optional:
//! - `TET_BASE_URL` (default `http://localhost:5010`)
//! - `TET_RECIPIENT_MNEMONIC` (default: generate a fresh recipient)
//! - `TET_TRANSFER_AMOUNT_MICRO` (default `1000000` = 1 TET)
//! - `TET_SKIP_FAUCET=1` if the sender is already funded (skips `/ledger/faucet`)
//! - `TET_FAUCET_AMOUNT_TET` (default `10000.0`) — per-grant cap is enforced server-side

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use tet_core::protocol::{AttestationV1, HybridSigV1, SignedTxEnvelopeV1, TxV1};

const STEVEMON: u64 = 1_000_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let admin_key = std::env::var("TET_ADMIN_API_KEY")
        .unwrap_or_default()
        .trim()
        .to_string();
    if admin_key.is_empty() {
        eprintln!(
            "Missing env: TET_ADMIN_API_KEY (required for /ledger/faucet unless TET_SKIP_FAUCET=1)"
        );
        std::process::exit(2);
    }

    let sender_words = std::env::var("TET_SENDER_MNEMONIC")
        .unwrap_or_default()
        .trim()
        .to_string();
    if sender_words.is_empty() {
        eprintln!(
            "Missing env: TET_SENDER_MNEMONIC (12-word BIP39 mnemonic for the spending wallet)"
        );
        std::process::exit(2);
    }

    let base_url = std::env::var("TET_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://localhost:5010".to_string());

    let skip_faucet = matches!(
        std::env::var("TET_SKIP_FAUCET").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    );

    let faucet_amount_tet: f64 = std::env::var("TET_FAUCET_AMOUNT_TET")
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .unwrap_or(10_000.0);

    let amount_micro: u64 = std::env::var("TET_TRANSFER_AMOUNT_MICRO")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(STEVEMON);

    let client = reqwest::Client::new();
    let base = base_url.trim_end_matches('/').to_string();

    // ── Sender / recipient keys ─────────────────────────────────────────────────────────────
    let sender_info = tet_core::wallet::recover_from_mnemonic_12(&sender_words)?;
    let from_wallet = sender_info.address_hex.to_ascii_lowercase();

    let recipient_words = if let Ok(w) = std::env::var("TET_RECIPIENT_MNEMONIC") {
        let t = w.trim().to_string();
        if t.is_empty() {
            tet_core::wallet::generate_mnemonic_12()?
                .mnemonic_12
                .ok_or("internal: generated mnemonic missing")?
        } else {
            t
        }
    } else {
        tet_core::wallet::generate_mnemonic_12()?
            .mnemonic_12
            .ok_or("internal: generated mnemonic missing")?
    };
    let recipient_info = tet_core::wallet::recover_from_mnemonic_12(&recipient_words)?;
    let to_wallet = recipient_info.address_hex.to_ascii_lowercase();

    if from_wallet == to_wallet {
        return Err("sender and recipient wallet_id must differ".into());
    }

    println!("[trigger_mint] from_wallet={}", from_wallet);
    println!("[trigger_mint] to_wallet={}", to_wallet);
    println!("[trigger_mint] transfer_amount_micro={}", amount_micro);

    // ── Fund sender from system pool (no supply inflation) ──────────────────────────────────
    if !skip_faucet {
        let faucet_url = format!("{}/ledger/faucet", base);
        let body = serde_json::json!({
            "wallet_id": from_wallet,
            "amount_tet": faucet_amount_tet,
        });
        println!("[trigger_mint] POST {} (admin faucet)", faucet_url);
        let r = client
            .post(&faucet_url)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", admin_key))
            .json(&body)
            .send()
            .await?;
        let st = r.status();
        let txt = r.text().await.unwrap_or_default();
        println!("[trigger_mint] faucet status={}", st);
        println!("[trigger_mint] faucet body={}", txt);
        if !st.is_success() {
            return Err(format!("faucet HTTP error: {}", st).into());
        }
        // Give gossipsub time to reach peer nodes and `apply_remote_event` to commit before transfer.
        std::thread::sleep(std::time::Duration::from_secs(2));
        println!("[trigger_mint] waited 2s after faucet (gossip / DB sync grace)");
    } else {
        println!("[trigger_mint] skipping faucet (TET_SKIP_FAUCET=1)");
    }

    // ── Build + sign transfer envelope (must match `verify_envelope_v1` in rest/helpers.rs) ─
    let tx = TxV1::Transfer {
        from_wallet: from_wallet.clone(),
        to_wallet: to_wallet.clone(),
        amount_micro,
        fee_bps: 100,
    };
    let tx_bytes = serde_json::to_vec(&tx)?;

    let ed_sk = tet_core::wallet::ed25519_signing_key_from_mnemonic(&sender_words)?;
    let mldsa_kp = tet_core::wallet::mldsa_keypair_from_mnemonic(&sender_words)?;
    let mldsa_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(mldsa_kp.public_key());

    let ed_sig = ed_sk.sign(tx_bytes.as_slice());
    let ed_sig_b64 = base64::engine::general_purpose::STANDARD.encode(ed_sig.to_bytes().as_slice());
    let mldsa_sig_bytes =
        tet_core::wallet::mldsa_sign_deterministic(&mldsa_kp, tx_bytes.as_slice())?;
    let mldsa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&mldsa_sig_bytes);

    let envelope = SignedTxEnvelopeV1 {
        v: 1,
        tx,
        sig: HybridSigV1 {
            ed25519_pubkey_hex: from_wallet.clone(),
            ed25519_sig_b64: ed_sig_b64,
            mldsa_pubkey_b64,
            mldsa_sig_b64,
        },
        attestation: AttestationV1 {
            platform: "local-example".to_string(),
            report_b64: String::new(),
        },
    };

    let transfer_url = format!("{}/ledger/transfer", base);
    println!("[trigger_mint] POST {}", transfer_url);
    let r2 = client
        .post(&transfer_url)
        .header("content-type", "application/json")
        .json(&envelope)
        .send()
        .await?;
    let st2 = r2.status();
    let txt2 = r2.text().await.unwrap_or_default();
    println!("[trigger_mint] transfer status={}", st2);
    println!("[trigger_mint] transfer body={}", txt2);

    Ok(())
}
