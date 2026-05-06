//! REST DTOs and query/response models.
//!
//! This module exists to prevent handler code from depending on private structs in `rest.rs`.
//! Keep these types as stable as possible; prefer adding new versions rather than mutating.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AiPricingQuery {
    pub model: String,
    pub input: String,
}

#[derive(Debug, Serialize)]
pub struct DexOrderbookEntry {
    pub order_id: String,
    pub maker_wallet: String,
    pub side: String,
    pub quote_asset: String,
    pub price_quote_per_tet: u64,
    pub tet_micro_remaining: u64,
    pub expires_at_ms: u128,
}

#[derive(Debug, Deserialize)]
pub struct GuardianRecoverReq {
    pub sha256_hex: String,
    pub snapshot_b64: String,
    pub ed25519_pubkey_hex: String,
    pub ed25519_sig_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct B2bComputeReq {
    pub model: String,
    #[serde(default)]
    pub input: Option<String>,
    #[serde(default)]
    pub messages: Option<Vec<B2bChatMessage>>,
    pub payment: crate::protocol::SignedTxEnvelopeV1,
}

#[derive(Debug, Deserialize)]
pub struct B2bChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct MintDemoReq {
    pub amount_tet: f64,
    /// Any bytes to bind in the proof hash preimage (demo input).
    pub energy_note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WalletRecoverReq {
    #[allow(dead_code)]
    pub mnemonic_12: String,
}

#[derive(Debug, Deserialize)]
pub struct WalletTransferSignedReq {
    pub from_address: String,
    pub to_address: String,
    pub amount_tet: f64,
    pub nonce: u64,
    pub signature: String,
    /// ML-DSA public key (raw, STANDARD base64; typically ML-DSA-65). Length implies security level.
    pub mldsa_pubkey_b64: String,
    /// ML-DSA signature (raw, STANDARD base64) over `transfer_hybrid_auth_message_bytes`.
    pub mldsa_signature_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct WalletStakeSignedReq {
    pub wallet_id: String,
    pub amount_tet: f64,
    pub nonce: u64,
    /// Ed25519 signature (128 hex chars) over `tet stake hybrid v1|...`
    pub ed25519_sig_hex: String,
    /// ML-DSA public key (STANDARD base64)
    pub mldsa_pubkey_b64: String,
    /// ML-DSA signature (STANDARD base64) over the same stake message
    pub mldsa_sig_b64: String,
}

/// `POST /ledger/stake`: same JSON shape as [`WalletStakeSignedReq`]; preimage is [`crate::wallet::worker_bond_stake_hybrid_auth_message_bytes`].
pub type LedgerWorkerBondStakeReq = WalletStakeSignedReq;
/// `POST /ledger/unstake`: preimage is [`crate::wallet::worker_bond_unstake_hybrid_auth_message_bytes`].
pub type LedgerWorkerBondUnstakeReq = WalletStakeSignedReq;

#[derive(Debug, Deserialize)]
pub struct WalletSlashReq {
    pub wallet_id: String,
    pub amount_tet: f64,
}

#[derive(Debug, Deserialize)]
pub struct LedgerMeQuery {
    pub wallet_id: String,
}

#[derive(Debug, Deserialize)]
pub struct WalletIdQuery {
    pub wallet_id: String,
}

#[derive(Debug, Deserialize)]
pub struct FaucetReq {
    pub wallet_id: String,
    /// Amount in TET (human units). Defaults to 100 if omitted.
    pub amount_tet: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct AiUtilityReq {
    pub prompt: String,
    pub target_worker_id: Option<String>,
    /// Required (>0): monotonic per-wallet nonce (replay protection); must be included in hybrid signature preimage.
    pub nonce: u64,
    /// Max Stevemon the payer authorizes for this P2P job (default 10 = 0.00001 TET, same as local infer).
    #[serde(default)]
    pub max_fee_micro: Option<u64>,
    /// Required (>0): must match hybrid signing payload (same as `POST /ai/infer`).
    #[serde(default)]
    pub flops: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AiInferReq {
    pub wallet_id: String,
    pub prompt: String,
    /// Required (>0): monotonic per-wallet nonce (replay protection); must be included in hybrid signature preimage.
    pub nonce: u64,
    /// Declared client-side FLOPs (§4.2); **always required** (>0) — hybrid signature binds this value.
    #[serde(default)]
    pub flops: Option<u64>,
    /// When routing to a P2P worker, max Stevemon authorized (default: 10).
    #[serde(default)]
    pub max_fee_micro: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AiNonceQuery {
    pub wallet_id: String,
}

#[derive(Debug, Serialize)]
pub struct AiNonceResp {
    pub wallet_id: String,
    pub nonce: u64,
}

#[derive(Debug, Deserialize)]
pub struct AiInferSignedReq {
    pub wallet_id: String,
    pub prompt: String,
    pub nonce: u64,
    /// STANDARD base64 Ed25519 signature over bytes of: `(prompt + nonce)` where nonce is decimal string.
    pub ed25519_sig_b64: String,
    #[serde(default)]
    pub flops: Option<u64>,
    #[serde(default)]
    pub max_fee_micro: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ExplorerEventsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct VaultHistoryQuery {
    pub wallet_id: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct AiHistoryQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct MarketIndexResp {
    pub tet_usd_peg: f64,
    pub total_supply_cap_tet: u64,
    pub total_supply_tet: f64,
    pub total_supply_micro: u64,
    pub genesis_airdrop_tet: u64,
}

#[derive(Debug, Deserialize)]
pub struct WorkerRegisterReq {
    pub wallet: String,
    pub hardware_id_hex: String,
    pub ed25519_pubkey_hex: String,
    #[serde(default)]
    pub x25519_pubkey_b64: Option<String>,
    #[serde(default)]
    pub mlkem_pubkey_b64: Option<String>,
    pub tflops_est: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct FounderWithdrawTreasuryReq {
    pub founder_wallet_id: String,
    pub amount_tet: f64,
    pub nonce: u64,
    pub mldsa_pubkey_b64: String,
    pub mldsa_signature_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct ComputeE2eeSubmitReq {
    pub worker_wallet: String,
    pub client_ephemeral_pub_b64: String,
    #[serde(default)]
    pub client_mlkem_pub_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    #[serde(default)]
    pub mlkem_ciphertext_b64: String,
    pub payment: crate::protocol::SignedTxEnvelopeV1,
}

#[derive(Debug, Serialize)]
pub struct ComputeE2eeSubmitResp {
    pub job_id: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct ComputeE2eeResultResp {
    pub job_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_nonce_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_ciphertext_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorkerE2eeNextResp {
    pub job_id: String,
    pub client_ephemeral_pub_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct WorkerE2eeCompleteReq {
    pub wallet: String,
    pub job_id: String,
    pub result_nonce_b64: String,
    pub result_ciphertext_b64: String,
    #[serde(default)]
    pub result_mlkem_ciphertext_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct ProofsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub before_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ComputeReq {
    pub plugin: String, // "ai_inference" | "video_render" | "scientific_compute"
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub input: Option<String>,
    // Video plugin:
    #[serde(default)]
    pub frames_total: Option<u64>,
    // Scientific plugin:
    #[serde(default)]
    pub grid_w: Option<u64>,
    #[serde(default)]
    pub grid_h: Option<u64>,
    // Sharding:
    #[serde(default)]
    pub shard_chars: Option<usize>,
    #[serde(default)]
    pub shard_frames: Option<u64>,
    #[serde(default)]
    pub tile_w: Option<u64>,
    #[serde(default)]
    pub tile_h: Option<u64>,
    // Verification:
    #[serde(default)]
    pub redundancy: Option<u32>, // require N matching outputs per shard (stubbed)
    #[serde(default)]
    pub geo: Option<String>,
    // Payment:
    pub payment: crate::protocol::SignedTxEnvelopeV1,
}

#[derive(Debug, Deserialize)]
pub struct FounderGenesisReq {
    pub founder_wallet_id: String,
    pub mldsa_pubkey_b64: String,
    pub mldsa_signature_b64: String,
}

// --- DEX DTOs ---

#[derive(Debug, Deserialize)]
pub struct DexOrderPlaceReq {
    pub maker_wallet: String,
    /// "buy" | "sell"
    pub side: String,
    pub quote_asset: String,
    pub price_quote_per_tet: u64,
    pub tet_micro_total: u64,
    #[serde(default)]
    pub ttl_sec: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct DexOrderPlaceResp {
    pub order_id: String,
    pub escrow_wallet: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct DexOrderCancelReq {
    pub order_id: String,
    pub maker_wallet: String,
}

#[derive(Debug, Serialize)]
pub struct DexOrderCancelResp {
    pub order_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct DexTakeReq {
    pub taker_wallet: String,
    /// taker intent: "buy" | "sell"
    pub side: String,
    pub quote_asset: String,
    pub tet_micro: u64,
    #[serde(default)]
    pub max_price_quote_per_tet: Option<u64>,
    #[serde(default)]
    pub settlement_ttl_sec: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct DexTakeResp {
    pub trade_id: String,
    pub order_id: String,
    pub status: String,
    pub deadline_at_ms: u128,
}

#[derive(Debug, Deserialize)]
pub struct DexTradeCompleteReq {
    pub trade_id: String,
    pub solana_usdc_txid: String,
    pub maker_ed25519_pubkey_hex: String,
    pub taker_ed25519_pubkey_hex: String,
}

#[derive(Debug, Serialize)]
pub struct DexTradeCompleteResp {
    pub trade_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct DexSettlementConfirmReq {
    pub trade_id: String,
    pub solana_usdc_txid: String,
}

#[derive(Debug, Serialize)]
pub struct DexSettlementConfirmResp {
    pub trade_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct DexSweepRefundsReq {
    #[serde(default)]
    pub now_ms: Option<u128>,
}

#[derive(Debug, Serialize)]
pub struct DexSweepRefundsResp {
    pub refunded_trade_ids: Vec<String>,
}
