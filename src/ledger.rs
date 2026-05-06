use crate::attestation::{AttestationReport, attestation_required};
use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};
use sled::transaction::{
    ConflictableTransactionError, TransactionError, Transactional, TransactionalTree,
};
use zeroize::{Zeroize as _, ZeroizeOnDrop};

mod crypto;
mod peers;
pub mod solana_client;

/// Smallest unit: 1 TET = 1,000,000 Stevemon (6 decimals; whitepaper).
pub const STEVEMON: u64 = 1_000_000;

/// Mainnet Genesis Epoch length (inference settlements ≈ nominal 4s spacing → ~60 days).
pub const GENESIS_EPOCH_BLOCK_LIMIT: u64 = 1_300_000;
/// Worker-pool credit multiplier during Genesis Epoch (burn remainder absorbs reduced burn share).
pub const GENESIS_REWARD_MULTIPLIER: u64 = 5;
/// Minimum wall-clock spacing between inference settlements (consensus stabilizer).
pub const TARGET_BLOCK_TIME_MS: u64 = 4_000;

/// Default **Founder** ledger `wallet_id`: Ed25519 verifying key as 64 lowercase hex (no `0x`).
/// Aligned with Sovereign OS normalized in-app wallet genesis; `apply_genesis_allocation` credits
/// [`GENESIS_FOUNDER_SHARE_MICRO`] (25億 TET) to this address on first boot.
/// Override at runtime with `TET_GENESIS_FOUNDER_WALLET_ID`.
pub const GENESIS_FOUNDER_DEV_PUBLIC_HEX: &str =
    "57e0b29d233917a619d0f335dfc1135add3359c49590720cfb0f9f70d71f36a0";
/// Legacy denomination before Stevemon scale alignment (8 decimals per TET).
pub const LEGACY_STEVEMON_PER_TET: u64 = 100_000_000;
pub const MAX_SUPPLY_MICRO: u64 = 10_000_000_000u64 * STEVEMON;

/// Worker Pool wallet (locked, unspendable by humans; no private key exists).
pub const WALLET_WORKER_POOL: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
/// Ecosystem wallet (locked, unspendable by humans; no private key exists).
pub const WALLET_ECOSYSTEM: &str =
    "0000000000000000000000000000000000000000000000000000000000000002";

/// Founder genesis premine (Whitepaper §10): **25%** of max supply → 2.5B TET.
pub const GENESIS_FOUNDER_PREMINE_TET: u64 = 2_500_000_000;
pub const GENESIS_FOUNDER_SHARE_MICRO: u64 = GENESIS_FOUNDER_PREMINE_TET * STEVEMON;
/// DEX liquidity treasury at genesis (optional tranche; MVP stays 0).
pub const GENESIS_DEX_TREASURY_MICRO: u64 = 0;
/// **75%** system-locked tranche minted to [`WALLET_SYSTEM_WORKER_POOL`] at genesis (7.5B TET).
pub const GENESIS_SYSTEM_LOCKED_TET: u64 = 7_500_000_000;
pub const GENESIS_WORKER_POOL_SHARE_MICRO: u64 = GENESIS_SYSTEM_LOCKED_TET * STEVEMON;
pub const GENESIS_ECOSYSTEM_SHARE_MICRO: u64 = 0;
pub const WALLET_PROTOCOL_RESERVE: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";
pub const GENESIS_PROTOCOL_RESERVE_SHARE_MICRO: u64 = 0;

/// Total circulating mint at genesis: 25% founder + 75% system pool = **100亿 TET** ([`MAX_SUPPLY_MICRO`]).
pub const GENESIS_TOTAL_MINT_MICRO: u64 =
    GENESIS_FOUNDER_SHARE_MICRO + GENESIS_WORKER_POOL_SHARE_MICRO;

const _: () = assert!(GENESIS_TOTAL_MINT_MICRO == MAX_SUPPLY_MICRO);

/// Genesis Worker grant: 100,000 TET × 1,000 nodes = 100,000,000 TET (funded from `system:worker_pool` at genesis).
pub const GENESIS_GUARDIANS_TOTAL: u64 = 10_000;
pub const GENESIS_GUARDIAN_GRANT_MICRO: u64 = 10_000u64 * STEVEMON;

pub const WALLET_DEX_TREASURY: &str = "dex:treasury";
pub const WALLET_SYSTEM_WORKER_POOL: &str = WALLET_WORKER_POOL;
/// AI compute sink wallet. When pre-sale lock is active, transfers are only allowed to this destination.
pub const WALLET_AI_BURN_DEFAULT: &str = "tet-api-pool";
/// Legacy registration threshold (meta-tree stake via `/wallet/stake`). Prefer [`MIN_WORKER_STAKE_MICRO`] + [`worker_stakes_v1`] bond for Sybil resistance.
pub const WORKER_MIN_STAKE_MICRO: u64 = 5_000u64 * STEVEMON;

/// Minimum **worker bond** (Sybil resistance): collateral locked in [`worker_stakes_v1`] tree (**1,000 TET** Stevemon).
pub const MIN_WORKER_STAKE_MICRO: u64 = 1_000u64 * STEVEMON;

/// Protocol maintenance fee on transfers: **1%** of gross amount (bps); fee split **50%** worker pool / **50%** burn (§10).
pub const PROTOCOL_MAINTENANCE_FEE_BPS: u64 = 100;

/// --- DePIN economics (AI utility) ---
/// Worker must have at least this much **bond** in [`worker_stakes_v1`] to count as an active worker ([`is_active_worker`]).
pub const MIN_STAKE_AMOUNT_MICRO: u64 = MIN_WORKER_STAKE_MICRO;
/// Network fee percent (20%) charged on AI task payments.
pub const NETWORK_FEE_BPS: u64 = 2_000; // 20.00%
/// Burn percent of the network fee (25% of 20% = 5% of total).
pub const BURN_FRACTION_OF_NETWORK_FEE_BPS: u64 = 2_500; // 25.00% of the network fee
/// Slashing penalty (5%) applied to staked balance on worker failure.
pub const SLASHING_PENALTY_BPS: u64 = 500; // 5.00%

/// Default lock duration for AI worker rewards (anti-dump).
const WORKER_REWARD_VEST_MS_DEFAULT: u128 = 90u128 * 86_400_000;
const META_NEXT_VEST_SEQ: &[u8] = b"next_global_vest_seq";

const META_TOTAL_SUPPLY: &[u8] = b"total_supply_micro";
const META_TOTAL_BURNED: &[u8] = b"total_burned_micro";
const META_FOUNDER_WALLET: &[u8] = b"founder_wallet";
/// Founder genesis vesting: 1-year cliff → 100% unlock.
const META_FOUNDER_GENESIS_UNLOCK_AT_MS: &[u8] = b"founder_genesis_unlock_at_ms_v1";
/// Amount of founder genesis allocation that is locked until `META_FOUNDER_GENESIS_UNLOCK_AT_MS`.
const META_FOUNDER_GENESIS_LOCKED_MICRO: &[u8] = b"founder_genesis_locked_micro_v1";
const META_FEE_TOTAL: &[u8] = b"fee_total_micro";
const META_GENESIS_GUARDIANS_FILLED: &[u8] = b"genesis_guardians_filled_v1";
const META_GENESIS_GUARDIAN_GRANTED_PREFIX: &[u8] = b"genesis_guardian_grant_v1:";
const META_TREASURY_WITHDRAW_NONCE: &[u8] = b"treasury_withdraw_nonce_v1";
const META_PROOF_SEQ: &[u8] = b"energy:proof_seq";
const META_AUDIT_SEQ: &[u8] = b"audit_seq_v1";
/// Completed inference settlements (logical chain height for Genesis Epoch economics).
const META_INFERENCE_BLOCK_HEIGHT: &[u8] = b"inference_block_height_u64_v1";
/// Phase 2: mined block height for transfer batching.
const META_LEDGER_BLOCK_HEIGHT: &[u8] = b"ledger_block_height_u64_v1";
/// Wall-clock ms after last inference settlement commit (consensus spacing).
const META_INFER_CONSENSUS_LAST_MS: &[u8] = b"infer_consensus_last_wall_ms_v1";
const META_DB_MAGIC: &[u8] = b"db_magic_v1";
/// Persisted Stevemon atoms per 1 TET (detects legacy 1e8 DB vs current 1e6).
const META_STEVEMON_PER_TET: &[u8] = b"stevemon_per_tet_v1";
/// Persistent per-wallet AI inference nonce (replay protection for `/ai/infer` hybrid).
const META_AI_NONCE_PREFIX: &[u8] = b"ai_nonce_v1:";
/// Idempotency marker for remotely-applied gossipsub transfers: `remote_tx_applied_v1:{tx_hash}`.
const META_REMOTE_TX_APPLIED_PREFIX: &[u8] = b"remote_tx_applied_v1:";
const DB_MAGIC: &[u8] = b"tet-db-v1";
// Legacy magic bytes from earlier snapshots (kept for seamless migration).
// Stored as raw bytes to avoid brand leakage in source strings.
const DB_MAGIC_LEGACY: &[u8] = &[
    0x6e, 0x65, 0x78, 0x75, 0x73, 0x2d, 0x64, 0x62, 0x2d, 0x76, 0x31,
];
const META_AI_COST_MONTH_MICROUSD_PREFIX: &[u8] = b"ai_cost_usd_micro:";
const META_WORKER_COMMUNITY_MICRO: &[u8] = b"worker_community_mint_micro";
const META_CHF_DEPOSITS_MICRO: &[u8] = b"fiat_chf_deposits_micro";
const META_FIAT_MINT_STEVEMON_MICRO: &[u8] = b"fiat_mint_stevemon_micro";
const META_AML_CHF_PREFIX: &[u8] = b"aml_chf_micro:";
const META_GENESIS_1K_FILLED: &[u8] = b"genesis_1k_filled";
/// Per-wallet CAAC attestation (JSON) — `caac_worker_v1:{wallet_id_hex}`.
const META_CAAC_WALLET_PREFIX: &str = "caac_worker_v1:";

/// Persisted CAAC lane assignment after hardware challenge (JSON blob in meta tree).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaacWorkerRecord {
    pub role: String,
    pub latency_ms: u64,
    pub seed_hex: String,
    pub server_wall_ms: u64,
}
/// Last committed transfer nonce per wallet (replay protection for signed HTTP transfers).
const META_WALLET_NONCE_PREFIX: &[u8] = b"wallet_nonce_v1:";
/// Per-wallet staked balance (micro-units) — economic security layer.
const META_WALLET_STAKE_PREFIX: &[u8] = b"wallet_stake_v1:";
/// Per-wallet pre-sale lock expiry (ms since epoch). If now < locked_until, wallet is transfer-locked except burn sink.
const META_WALLET_PRESALE_LOCK_UNTIL_PREFIX: &[u8] = b"wallet_presale_lock_until_ms_v1:";
const GENESIS_1K_MAX: u64 = 10_000;
/// Gross bonus amount (mint) for Genesis 1,000 claims — 10,000 TET airdrop (display-only UX must match).
pub const GENESIS_1K_BONUS_TET: u64 = 10_000;
/// Worker-pool gross uplift for Genesis 1,000 participants: standard reward × 1.10 (floor, integer math).
const GENESIS_1K_WORKER_GROSS_NUM: u128 = 11;
const GENESIS_1K_WORKER_GROSS_DEN: u128 = 10;

/// Welcome initial airdrop: **1,000 TET** per wallet, first **10,000** distinct wallets (10M TET total), debited from [`WALLET_SYSTEM_WORKER_POOL`].
pub const FAUCET_INITIAL_AIRDROP_TET_PER_USER: u64 = 1_000;
pub const FAUCET_INITIAL_AIRDROP_MICRO_PER_USER: u64 =
    FAUCET_INITIAL_AIRDROP_TET_PER_USER * STEVEMON;
pub const FAUCET_INITIAL_AIRDROP_MAX_RECIPIENTS: u64 = 10_000;

/// Hard cap for one admin [`Ledger::admin_rest_faucet`] grant (Stevemon micro): **1M TET** (matches REST clamp).
pub const ADMIN_REST_FAUCET_MAX_AMOUNT_MICRO: u64 = 1_000_000u64 * STEVEMON;

const META_FAUCET_INITIAL_RECIPIENTS_COUNT: &[u8] = b"faucet_initial_recipients_count_v1";
// On-chain ZK verify markers (meta keys).
const META_ZK_VERIFIED_PREFIX: &[u8] = b"zk_verified_v1:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminRestFaucetOutcome {
    Granted {
        credited_micro: u64,
        audit_hash_hex: String,
    },
    AlreadyClaimed,
    IpRateLimited,
    PoolInsufficient,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct FaucetIpRlV1 {
    v: u32,
    /// Unix ms timestamps of successful admin faucet grants from this IP (rolling window).
    grant_ts_ms: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialAirdropClaimOutcome {
    /// Credited this call (pool → user).
    Granted { credited_micro: u64 },
    /// This `wallet_id` already has a row in `faucet_recipients_v1`.
    AlreadyClaimed,
    /// Program counter reached [`FAUCET_INITIAL_AIRDROP_MAX_RECIPIENTS`] (no further grants ever).
    CapReached,
    /// Worker pool balance below [`FAUCET_INITIAL_AIRDROP_MICRO_PER_USER`].
    PoolInsufficient,
}

fn day_since_epoch() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs / 86_400
}

#[derive(Clone)]
pub struct Ledger {
    #[allow(dead_code)]
    db: sled::Db,
    balances: sled::Tree,
    meta: sled::Tree,
    proofs: sled::Tree,
    audit: sled::Tree,
    audit_seq: sled::Tree,
    founding: sled::Tree,
    ai_quota: sled::Tree,
    /// Worker AI reward vesting rows (90-day lock by default).
    vest_locks: sled::Tree,
    /// Persistent P2P peer memory (kademlia routing hints).
    p2p_peers: sled::Tree,
    /// Keys `wallet64hex:seq020` → encrypted [`AiInferHistoryRowV1`] JSON.
    ai_infer_sessions: sled::Tree,
    /// One-time welcome airdrop recipients (`wallet_id` utf8 → encrypted marker).
    faucet_recipients: sled::Tree,
    /// Admin `POST /ledger/faucet`: each `wallet_id` may claim at most once (encrypted marker).
    faucet_claims: sled::Tree,
    /// Rolling-window IP rate baseline for admin faucet (encrypted JSON).
    faucet_ip_rl: sled::Tree,
    /// Worker Sybil bond: `wallet_id` utf8 → encrypted `u64` micro (locked; not spendable until unstake).
    worker_stakes: sled::Tree,
    enc_key: Option<EncKey>,
    snapshot_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FoundingMemberCert {
    pub v: u32,
    pub member_wallet: String,
    pub platform: String,
    pub hardware_id_hex: String,
    pub issued_at_ms: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnergyProofRecord {
    pub id: u64,
    pub hash_sha256_hex: String,
    pub payload_b64: String,
    pub verified: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEventV1 {
    pub seq: u64,
    pub hash_hex: String,
    pub ts_ms: u128,
    pub record: serde_json::Value,
}

/// Persisted row for `GET /ai/history/:wallet` — local `POST /ai/infer` sessions linked to ledger audit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AiInferHistoryRowV1 {
    pub v: u32,
    pub payer_wallet: String,
    pub prompt: String,
    pub response: String,
    pub cost_micro: u64,
    pub ledger_audit_hash_hex: String,
    pub ledger_audit_seq: u64,
    pub ts_ms: u64,
}

/// Max UTF-8 bytes stored per prompt/response in [`Ledger::append_ai_infer_session`].
const AI_INFER_HISTORY_TEXT_MAX_BYTES: usize = 256 * 1024;

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Genesis1kStatus {
    pub slots_total: u64,
    pub slots_filled: u64,
    pub claimed: bool,
    pub your_slot: Option<u64>,
    pub can_claim: bool,
    pub bonus_tet: u32,
}

fn genesis_1k_wallet_slot_meta_key(wallet: &str) -> Vec<u8> {
    format!("genesis_1k_slot:{wallet}").into_bytes()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisAllocationSummary {
    pub founder_wallet_id: String,
    pub founder_allocation_micro: u64,
    pub dex_treasury_allocation_micro: u64,
    pub worker_pool_allocation_micro: u64,
    pub total_supply_micro: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("hard cap exceeded")]
    HardCapExceeded,
    #[error("founder wallet not configured")]
    FounderWalletMissing,
    #[error("genesis already applied (total supply > 0)")]
    GenesisAlreadyApplied,
    #[error("attestation required")]
    AttestationRequired,
    #[error("hybrid signature verification failed: {0}")]
    HybridSigRejected(String),
    #[error("sled: {0}")]
    Sled(#[from] sled::Error),
    #[error("invalid: {0}")]
    Invalid(String),
}

#[derive(Clone, ZeroizeOnDrop)]
struct EncKey([u8; 32]);

impl EncKey {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn u64_to_bytes(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}
fn bytes_to_u64(b: &[u8]) -> u64 {
    b.try_into().ok().map(u64::from_le_bytes).unwrap_or(0)
}

/// True only when `pt` is a canonical ledger balance plaintext: **8 bytes** little-endian `u64` (Stevemon micro) with amount ≥ 1.
/// Other modules may store unrelated ciphertext under unrelated keys; decrypt errors or non-8-byte plaintext are **not** balances.
fn plaintext_is_material_balance_amount_micro(pt: &[u8]) -> bool {
    if pt.len() != 8 {
        return false;
    }
    let Ok(arr) = <[u8; 8]>::try_from(pt) else {
        return false;
    };
    let amt = u64::from_le_bytes(arr);
    amt >= 1
}

fn ledger_now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn founder_genesis_cliff_ms() -> u128 {
    std::env::var("TET_FOUNDER_CLIFF_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(365u128 * 86_400_000u128)
}

/// Lock duration for worker AI rewards; override with `TET_WORKER_VEST_MS` (milliseconds) for tests.
pub fn worker_reward_vest_duration_ms() -> u128 {
    std::env::var("TET_WORKER_VEST_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(WORKER_REWARD_VEST_MS_DEFAULT)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct VestLockV1 {
    v: u32,
    pub wallet: String,
    pub amount_micro: u64,
    pub unlock_at_ms: u128,
}

impl Ledger {
    fn zk_verified_meta_key(receipt_hash_hex: &str) -> Vec<u8> {
        let mut k = META_ZK_VERIFIED_PREFIX.to_vec();
        k.extend_from_slice(receipt_hash_hex.trim().as_bytes());
        k
    }

    /// Record a verified zk receipt in the ledger (idempotent).
    pub fn record_verified_zk_receipt(
        &self,
        image_id: [u32; 8],
        receipt_hash: &[u8; 32],
        journal_hash: &[u8; 32],
    ) -> Result<bool, LedgerError> {
        if image_id != methods::NEXUS_GUEST_ID {
            return Err(LedgerError::Invalid("image_id mismatch".into()));
        }
        let receipt_hash_hex = hex::encode(receipt_hash);
        let k = Self::zk_verified_meta_key(&receipt_hash_hex);
        let res: Result<bool, TransactionError<sled::Error>> = self.meta.transaction(|m| {
            if m.get(&k)?.is_some() {
                return Ok(false);
            }
            let v = serde_json::to_vec(&serde_json::json!({
                "v": 1,
                "kind": "zk_verified",
                "image_id": image_id,
                "receipt_hash_hex": receipt_hash_hex,
                "journal_hash_hex": hex::encode(journal_hash),
                "ts_ms": ledger_now_ms(),
            }))
            .map_err(|e| {
                ConflictableTransactionError::Abort(sled::Error::Unsupported(format!(
                    "zk_verified_json:{e}"
                )))
            })?;
            m.insert(k.clone(), self.encrypt_value(&v)?)?;
            Ok(true)
        });
        let applied = res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => LedgerError::Sled(e),
        })?;
        if applied {
            let audit = serde_json::json!({
                "v": 1,
                "ts_ms": ledger_now_ms(),
                "action": "zk_verify_record_v1",
                "receipt_hash_hex": receipt_hash_hex,
                "journal_hash_hex": hex::encode(journal_hash),
            });
            let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
            std::mem::drop(self.db.flush_async());
        }
        Ok(applied)
    }
    /// Compute a deterministic state root over all wallet balances.
    ///
    /// - Reads every key/value in the `balances` sled tree.
    /// - Decrypts values and uses canonical 8-byte LE `u64` amounts.
    /// - Sorts by wallet key bytes lexicographically.
    /// - Hashes the concatenation to produce a stable root.
    pub fn compute_state_root(&self) -> String {
        let mut rows: Vec<(Vec<u8>, u64)> = Vec::new();
        for it in self.balances.iter() {
            let Ok((k, v)) = it else {
                continue;
            };
            let Ok(pt) = self.decrypt_value(v.as_ref()) else {
                continue;
            };
            if pt.len() != 8 {
                continue;
            }
            let Ok(arr) = <[u8; 8]>::try_from(pt.as_slice()) else {
                continue;
            };
            let amt = u64::from_le_bytes(arr);
            rows.push((k.to_vec(), amt));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));

        let mut h = Sha256::new();
        for (k, amt) in rows {
            h.update(&k);
            h.update(u64_to_bytes(amt));
        }
        format!("0x{}", hex::encode(h.finalize()))
    }
    /// Read current mined block height (0 if unset).
    pub fn block_height(&self) -> Result<u64, LedgerError> {
        Ok(self
            .meta
            .get(META_LEDGER_BLOCK_HEIGHT)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    /// Bump block height by 1 and persist. Returns the new height.
    pub fn bump_block_height(&self) -> Result<u64, LedgerError> {
        let res: Result<u64, TransactionError<sled::Error>> = self.meta.transaction(|m| {
            let cur = m
                .get(META_LEDGER_BLOCK_HEIGHT)?
                .as_deref()
                .map(|v| self.decrypt_value(v))
                .transpose()?
                .as_deref()
                .map(bytes_to_u64)
                .unwrap_or(0);
            let next = cur.saturating_add(1);
            m.insert(
                META_LEDGER_BLOCK_HEIGHT,
                self.encrypt_value(&u64_to_bytes(next))?,
            )?;
            Ok(next)
        });
        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => LedgerError::Sled(e),
        })
    }
    fn remote_tx_applied_meta_key(tx_hash: &str) -> Vec<u8> {
        let mut k = META_REMOTE_TX_APPLIED_PREFIX.to_vec();
        k.extend_from_slice(tx_hash.trim().as_bytes());
        k
    }

    /// Apply a network-synced event from libp2p gossipsub to the local ledger.
    ///
    /// CRITICAL: This must **not** re-broadcast the event. It only mutates the DB.
    pub fn apply_remote_event(
        &self,
        event: &crate::models::NetworkEvent,
    ) -> Result<bool, LedgerError> {
        match event {
            crate::models::NetworkEvent::BlockMined {
                block_height: _,
                block_id: _,
                state_root: _,
                txs,
            } => {
                let mut any = false;
                for env in txs {
                    match &env.tx {
                        crate::protocol::TxV1::Transfer {
                            from_wallet,
                            to_wallet,
                            amount_micro,
                            fee_bps,
                        } => {
                            let tx_bytes = serde_json::to_vec(&env.tx)
                                .map_err(|e| LedgerError::Invalid(e.to_string()))?;
                            let tx_hash =
                                format!("0x{}", hex::encode(sha2::Sha256::digest(&tx_bytes)));
                            if self.apply_remote_transfer(
                                &tx_hash,
                                from_wallet,
                                to_wallet,
                                *amount_micro,
                                *fee_bps,
                            )? {
                                any = true;
                            }
                        }
                        _ => continue,
                    }
                }
                Ok(any)
            }
            crate::models::NetworkEvent::TransferExecuted {
                tx_hash,
                from_wallet,
                to_wallet,
                amount_micro,
                fee_bps,
            } => {
                self.apply_remote_transfer(tx_hash, from_wallet, to_wallet, *amount_micro, *fee_bps)
            }
            crate::models::NetworkEvent::FaucetExecuted {
                event_id,
                to_wallet,
                amount_micro,
            } => self.apply_remote_faucet(event_id, to_wallet, *amount_micro),
        }
    }

    fn apply_remote_transfer(
        &self,
        tx_hash: &str,
        from: &str,
        to: &str,
        amount_micro: u64,
        fee_bps: u64,
    ) -> Result<bool, LedgerError> {
        if from.trim().is_empty() || to.trim().is_empty() {
            return Err(LedgerError::Invalid("from/to required".into()));
        }
        if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
            return Err(LedgerError::Invalid("amount exceeds hard cap".into()));
        }

        let from = from.trim().to_ascii_lowercase();
        let to = to.trim().to_ascii_lowercase();
        let from_k = from.as_bytes().to_vec();
        let to_k = to.as_bytes().to_vec();

        let bps = fee_bps;
        let fee_micro = amount_micro.saturating_mul(bps) / 10_000;
        let net_micro = amount_micro.saturating_sub(fee_micro);
        let fee_pool_half = fee_micro / 2;
        let fee_burn_half = fee_micro.saturating_sub(fee_pool_half);

        let pool_k = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();
        let burn_wallet = self.ai_burn_wallet();
        let burn_k = burn_wallet.as_bytes().to_vec();

        let applied_k = Self::remote_tx_applied_meta_key(tx_hash);

        let now_ms = ledger_now_ms();
        let locked_sum = self.locked_balance_micro(&from, now_ms)?;
        let res: Result<bool, TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                if m.get(&applied_k)?.is_some() {
                    return Ok(false);
                }
                let fb = b
                    .get(&from_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                let spendable = fb.saturating_sub(locked_sum);
                if spendable < amount_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("remote_insufficient_funds".into()),
                    ));
                }
                let tb = b
                    .get(&to_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);

                b.insert(
                    from_k.clone(),
                    self.encrypt_value(&u64_to_bytes(fb - amount_micro))?,
                )?;
                b.insert(
                    to_k.clone(),
                    self.encrypt_value(&u64_to_bytes(tb.saturating_add(net_micro)))?,
                )?;

                if fee_micro > 0 {
                    let pool_cur = b
                        .get(&pool_k)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    b.insert(
                        pool_k.clone(),
                        self.encrypt_value(&u64_to_bytes(pool_cur.saturating_add(fee_pool_half)))?,
                    )?;
                    let burn_cur = b
                        .get(&burn_k)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    b.insert(
                        burn_k.clone(),
                        self.encrypt_value(&u64_to_bytes(burn_cur.saturating_add(fee_burn_half)))?,
                    )?;

                    let supply = m
                        .get(META_TOTAL_SUPPLY)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_TOTAL_SUPPLY,
                        self.encrypt_value(&u64_to_bytes(supply.saturating_sub(fee_burn_half)))?,
                    )?;

                    let burned = m
                        .get(META_TOTAL_BURNED)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_TOTAL_BURNED,
                        self.encrypt_value(&u64_to_bytes(burned.saturating_add(fee_burn_half)))?,
                    )?;

                    let fee_total = m
                        .get(META_FEE_TOTAL)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_FEE_TOTAL,
                        self.encrypt_value(&u64_to_bytes(fee_total.saturating_add(fee_micro)))?,
                    )?;
                }

                m.insert(applied_k.clone(), self.encrypt_value(b"1")?)?;
                Ok(true)
            });

        let applied = res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("remote_insufficient_funds") {
                    LedgerError::InsufficientFunds
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;

        if applied {
            let audit = serde_json::json!({
                "v": 1,
                "ts_ms": ledger_now_ms(),
                "action": "remote_transfer_apply_v1",
                "tx_hash": tx_hash,
                "from_wallet": from,
                "to_wallet": to,
                "amount_micro": amount_micro,
                "net_micro": net_micro,
                "fee_micro": fee_micro,
                "fee_bps": bps,
            });
            let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
            self.persist_snapshot_best_effort();
            std::mem::drop(self.db.flush_async());
        }
        Ok(applied)
    }

    fn apply_remote_faucet(
        &self,
        event_id: &str,
        to_wallet: &str,
        amount_micro: u64,
    ) -> Result<bool, LedgerError> {
        let event_id = event_id.trim();
        if event_id.is_empty() {
            return Err(LedgerError::Invalid("event_id required".into()));
        }
        if to_wallet.trim().is_empty() {
            return Err(LedgerError::Invalid("to_wallet required".into()));
        }
        if amount_micro == 0 || amount_micro > ADMIN_REST_FAUCET_MAX_AMOUNT_MICRO {
            return Err(LedgerError::Invalid(
                "amount_micro out of allowed faucet range".into(),
            ));
        }

        let w = to_wallet.trim().to_ascii_lowercase();
        if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(LedgerError::Invalid("wallet must be 64 hex chars".into()));
        }
        if w == WALLET_SYSTEM_WORKER_POOL
            || w == WALLET_DEX_TREASURY
            || w == WALLET_PROTOCOL_RESERVE
            || w == WALLET_ECOSYSTEM
            || w == self.ai_burn_wallet()
        {
            return Err(LedgerError::Invalid(
                "reserved wallet cannot receive remote faucet".into(),
            ));
        }

        let w_k = w.as_bytes().to_vec();
        let pool_k = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();
        let applied_k = Self::remote_tx_applied_meta_key(event_id);

        let res: Result<bool, TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                if m.get(&applied_k)?.is_some() {
                    return Ok(false);
                }

                let pool_cur = b
                    .get(&pool_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if pool_cur < amount_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("remote_faucet_pool_insufficient".into()),
                    ));
                }

                let user_cur = b
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);

                b.insert(
                    pool_k.clone(),
                    self.encrypt_value(&u64_to_bytes(pool_cur.saturating_sub(amount_micro)))?,
                )?;
                b.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(user_cur.saturating_add(amount_micro)))?,
                )?;

                m.insert(applied_k.clone(), self.encrypt_value(b"1")?)?;
                Ok(true)
            });

        let applied = res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("remote_faucet_pool_insufficient") {
                    LedgerError::InsufficientFunds
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;

        if applied {
            let audit = serde_json::json!({
                "v": 1,
                "ts_ms": ledger_now_ms(),
                "action": "remote_faucet_apply_v1",
                "event_id": event_id,
                "to_wallet": w,
                "amount_micro": amount_micro,
                "pool_wallet": WALLET_SYSTEM_WORKER_POOL,
            });
            let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
            self.persist_snapshot_best_effort();
            std::mem::drop(self.db.flush_async());
        }

        Ok(applied)
    }

    fn ai_nonce_meta_key(wallet: &str) -> Vec<u8> {
        let w = wallet.trim().to_ascii_lowercase();
        let mut k = Vec::with_capacity(META_AI_NONCE_PREFIX.len() + w.len());
        k.extend_from_slice(META_AI_NONCE_PREFIX);
        k.extend_from_slice(w.as_bytes());
        k
    }

    /// Read last committed AI nonce (0 if unset). Next valid nonce is `last + 1`.
    pub fn ai_last_nonce(&self, wallet: &str) -> Result<u64, LedgerError> {
        let k = Self::ai_nonce_meta_key(wallet);
        Ok(self
            .meta
            .get(k)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    pub fn ai_next_nonce(&self, wallet: &str) -> Result<u64, LedgerError> {
        Ok(self.ai_last_nonce(wallet)?.saturating_add(1).max(1))
    }

    /// Atomically consume AI nonce: require `nonce == last + 1`, then persist `last = nonce`.
    pub fn ai_consume_nonce(&self, wallet: &str, nonce: u64) -> Result<(), LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if nonce == 0 {
            return Err(LedgerError::Invalid("nonce must be > 0".into()));
        }
        let k = Self::ai_nonce_meta_key(&w);
        let res: Result<(), TransactionError<sled::Error>> = self.meta.transaction(|m| {
            let cur = m
                .get(&k)?
                .as_deref()
                .map(|v| self.decrypt_value(v))
                .transpose()?
                .as_deref()
                .map(bytes_to_u64)
                .unwrap_or(0);
            let want = cur.saturating_add(1).max(1);
            if nonce != want {
                return Err(ConflictableTransactionError::Abort(
                    sled::Error::Unsupported("invalid_ai_nonce".into()),
                ));
            }
            m.insert(k.clone(), self.encrypt_value(&u64_to_bytes(nonce))?)?;
            Ok(())
        });
        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("invalid_ai_nonce") {
                    LedgerError::Invalid("invalid nonce".into())
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;
        Ok(())
    }
    fn genesis_guardian_grant_meta_key(wallet: &str) -> Vec<u8> {
        let mut k = META_GENESIS_GUARDIAN_GRANTED_PREFIX.to_vec();
        k.extend_from_slice(wallet.trim().as_bytes());
        k
    }

    /// Auto-grant 100,000 TET to the first 1,000 workers (one-time per wallet).
    /// Debits `system:worker_pool` and credits the worker wallet (no fees).
    pub fn grant_genesis_guardian_if_eligible(&self, wallet: &str) -> Result<bool, LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(LedgerError::Invalid("wallet must be 64-hex id".into()));
        }
        // Never grant reserved/system wallets, and never grant the founder.
        if w == WALLET_SYSTEM_WORKER_POOL
            || w == WALLET_DEX_TREASURY
            || w == self.ai_burn_wallet()
            || self
                .founder_wallet_public()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                == w
        {
            return Ok(false);
        }
        let grant_k = Self::genesis_guardian_grant_meta_key(&w);
        let w_k = w.as_bytes().to_vec();
        let pool_k = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();
        let res: Result<bool, TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                if m.get(&grant_k)?.is_some() {
                    return Ok(false);
                }
                let filled = m
                    .get(META_GENESIS_GUARDIANS_FILLED)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if filled >= GENESIS_GUARDIANS_TOTAL {
                    return Ok(false);
                }
                let pool_cur = b
                    .get(&pool_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if pool_cur < GENESIS_GUARDIAN_GRANT_MICRO {
                    return Ok(false);
                }
                let w_cur = b
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    pool_k.clone(),
                    self.encrypt_value(&u64_to_bytes(
                        pool_cur.saturating_sub(GENESIS_GUARDIAN_GRANT_MICRO),
                    ))?,
                )?;
                b.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(
                        w_cur.saturating_add(GENESIS_GUARDIAN_GRANT_MICRO),
                    ))?,
                )?;
                m.insert(grant_k.clone(), self.encrypt_value(b"1")?)?;
                m.insert(
                    META_GENESIS_GUARDIANS_FILLED,
                    self.encrypt_value(&u64_to_bytes(filled.saturating_add(1)))?,
                )?;
                Ok(true)
            });
        let granted = res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => LedgerError::Sled(e),
        })?;
        if granted {
            let audit = serde_json::json!({
                "v": 1,
                "ts_ms": ledger_now_ms(),
                "action": "genesis_guardian_grant_v1",
                "wallet": w,
                "amount_micro": GENESIS_GUARDIAN_GRANT_MICRO,
                "pool_wallet": WALLET_SYSTEM_WORKER_POOL,
            });
            let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
            self.persist_snapshot_best_effort();
        }
        Ok(granted)
    }

    /// Founder-only withdrawal of liquid earnings from `dex:treasury` into founder wallet (no fees).
    pub fn withdraw_treasury_to_founder(
        &self,
        amount_micro: u64,
        nonce: u64,
    ) -> Result<(), LedgerError> {
        if amount_micro == 0 || amount_micro > MAX_SUPPLY_MICRO {
            return Err(LedgerError::Invalid("invalid amount".into()));
        }
        if nonce == 0 {
            return Err(LedgerError::Invalid("nonce must be > 0".into()));
        }
        let founder = self.founder_wallet()?;
        let founder_k = founder.as_bytes().to_vec();
        let treasury_k = WALLET_DEX_TREASURY.as_bytes().to_vec();
        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                let cur_nonce = m
                    .get(META_TREASURY_WITHDRAW_NONCE)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if nonce <= cur_nonce {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("stale_nonce".into()),
                    ));
                }
                let t_cur = b
                    .get(&treasury_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if t_cur < amount_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("insufficient_treasury".into()),
                    ));
                }
                let f_cur = b
                    .get(&founder_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    treasury_k.clone(),
                    self.encrypt_value(&u64_to_bytes(t_cur.saturating_sub(amount_micro)))?,
                )?;
                b.insert(
                    founder_k.clone(),
                    self.encrypt_value(&u64_to_bytes(f_cur.saturating_add(amount_micro)))?,
                )?;
                m.insert(
                    META_TREASURY_WITHDRAW_NONCE,
                    self.encrypt_value(&u64_to_bytes(nonce))?,
                )?;
                Ok(())
            });
        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                let s = e.to_string();
                if s.contains("stale_nonce") {
                    LedgerError::Invalid("stale nonce".into())
                } else if s.contains("insufficient_treasury") {
                    LedgerError::InsufficientFunds
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;
        let audit = serde_json::json!({
            "v": 1,
            "action": "treasury_withdraw_v1",
            "to_founder_wallet": founder,
            "from_wallet": WALLET_DEX_TREASURY,
            "amount_micro": amount_micro,
            "nonce": nonce,
        });
        let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
        self.persist_snapshot_best_effort();
        Ok(())
    }
    fn wallet_nonce_meta_key(wallet: &str) -> Vec<u8> {
        let mut k = META_WALLET_NONCE_PREFIX.to_vec();
        k.extend_from_slice(wallet.trim().to_ascii_lowercase().as_bytes());
        k
    }

    fn wallet_stake_meta_key(wallet: &str) -> Vec<u8> {
        let mut k = META_WALLET_STAKE_PREFIX.to_vec();
        k.extend_from_slice(wallet.trim().to_ascii_lowercase().as_bytes());
        k
    }

    fn wallet_presale_lock_until_meta_key(wallet: &str) -> Vec<u8> {
        let mut k = META_WALLET_PRESALE_LOCK_UNTIL_PREFIX.to_vec();
        k.extend_from_slice(wallet.trim().to_ascii_lowercase().as_bytes());
        k
    }

    /// AI burn / compute sink wallet used for pre-sale lock gating (override with `TET_AI_BURN_WALLET`).
    pub fn ai_burn_wallet(&self) -> String {
        std::env::var("TET_AI_BURN_WALLET")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| WALLET_AI_BURN_DEFAULT.to_string())
    }

    /// Pre-sale lock duration applied to inbound allocations from `dex:treasury` (override with `TET_PRESALE_LOCK_MS`).
    pub fn presale_lock_duration_ms(&self) -> u128 {
        std::env::var("TET_PRESALE_LOCK_MS")
            .ok()
            .and_then(|v| v.parse::<u128>().ok())
            .unwrap_or(0)
    }

    /// Read the staked balance (micro) for a wallet.
    pub fn staked_balance_micro(&self, wallet: &str) -> Result<u64, LedgerError> {
        let k = Self::wallet_stake_meta_key(wallet);
        Ok(self
            .meta
            .get(k)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    /// Read pre-sale lock expiry for a wallet (ms since epoch). 0 means unlocked.
    pub fn presale_locked_until_ms(&self, wallet: &str) -> Result<u128, LedgerError> {
        let k = Self::wallet_presale_lock_until_meta_key(wallet);
        let raw = self
            .meta
            .get(k)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?;
        let v = raw.as_deref().map(bytes_to_u64).unwrap_or(0);
        Ok(v as u128)
    }

    fn set_presale_locked_until_ms_txn(
        &self,
        m: &TransactionalTree,
        wallet: &str,
        locked_until_ms: u128,
    ) -> Result<(), ConflictableTransactionError<sled::Error>> {
        let k = Self::wallet_presale_lock_until_meta_key(wallet);
        let v = locked_until_ms.min(u64::MAX as u128) as u64;
        m.insert(k, self.encrypt_value(&u64_to_bytes(v))?)?;
        Ok(())
    }

    /// Stake: move micro-units from liquid balance into staked balance.
    /// If `signed_nonce` is provided, it is committed to the standard wallet nonce log (replay-safe).
    pub fn stake_micro(
        &self,
        wallet: &str,
        amount_micro: u64,
        signed_nonce: Option<u64>,
    ) -> Result<(u64, u64), LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if amount_micro == 0 {
            return Err(LedgerError::Invalid("amount must be > 0".into()));
        }
        let w_k = w.as_bytes().to_vec();
        let stake_k = Self::wallet_stake_meta_key(&w);
        let now_ms = ledger_now_ms();
        // Existing vest locks still apply to the liquid balance.
        let locked_sum = self.locked_balance_micro(&w, now_ms)?;
        let nonce_key = Self::wallet_nonce_meta_key(&w);
        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                if let Some(req_n) = signed_nonce {
                    let cur = m
                        .get(&nonce_key)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    if req_n <= cur {
                        return Err(ConflictableTransactionError::Abort(
                            sled::Error::Unsupported("stale_nonce".into()),
                        ));
                    }
                }
                let fb = b
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                let spendable = fb.saturating_sub(locked_sum);
                if spendable < amount_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("insufficient funds".into()),
                    ));
                }
                let cur_stake = m
                    .get(&stake_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(fb.saturating_sub(amount_micro)))?,
                )?;
                m.insert(
                    stake_k.clone(),
                    self.encrypt_value(&u64_to_bytes(cur_stake.saturating_add(amount_micro)))?,
                )?;
                if let Some(req_n) = signed_nonce {
                    m.insert(nonce_key.clone(), self.encrypt_value(&u64_to_bytes(req_n))?)?;
                }
                Ok(())
            });
        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient") {
                    LedgerError::InsufficientFunds
                } else if e.to_string().contains("stale_nonce") {
                    LedgerError::Invalid("stale nonce".into())
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;
        let new_stake = self.staked_balance_micro(&w)?;
        self.persist_snapshot_best_effort();
        Ok((amount_micro, new_stake))
    }

    /// Read worker bond (Stevemon micro) locked in the `worker_stakes_v1` tree.
    pub fn worker_bond_micro(&self, wallet: &str) -> Result<u64, LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        let k = w.as_bytes();
        Ok(self
            .worker_stakes
            .get(k)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    /// Whether `wallet_id` holds at least [`MIN_WORKER_STAKE_MICRO`] as worker bond (Sybil gate for P2P/worker layer).
    pub fn is_active_worker(&self, wallet_id: &str) -> bool {
        self.worker_bond_micro(wallet_id).unwrap_or(0) >= MIN_WORKER_STAKE_MICRO
    }

    /// Stake worker bond: atomically move Stevemon from liquid [`balances`] into [`worker_stakes_v1`].
    pub fn stake_worker_bond_micro(
        &self,
        wallet: &str,
        amount_micro: u64,
        signed_nonce: Option<u64>,
    ) -> Result<(u64, u64), LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if amount_micro == 0 {
            return Err(LedgerError::Invalid("amount must be > 0".into()));
        }
        let w_k = w.as_bytes().to_vec();
        let now_ms = ledger_now_ms();
        let locked_sum = self.locked_balance_micro(&w, now_ms)?;
        let nonce_key = Self::wallet_nonce_meta_key(&w);
        let res: Result<(), TransactionError<sled::Error>> =
            (&self.balances, &self.worker_stakes, &self.meta).transaction(|(b, ws, m)| {
                if let Some(req_n) = signed_nonce {
                    let cur = m
                        .get(&nonce_key)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    if req_n <= cur {
                        return Err(ConflictableTransactionError::Abort(
                            sled::Error::Unsupported("stale_nonce".into()),
                        ));
                    }
                }
                let fb = b
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                let spendable = fb.saturating_sub(locked_sum);
                if spendable < amount_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("insufficient funds".into()),
                    ));
                }
                let cur_bond = ws
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(fb.saturating_sub(amount_micro)))?,
                )?;
                ws.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(cur_bond.saturating_add(amount_micro)))?,
                )?;
                if let Some(req_n) = signed_nonce {
                    m.insert(nonce_key.clone(), self.encrypt_value(&u64_to_bytes(req_n))?)?;
                }
                Ok(())
            });
        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient") {
                    LedgerError::InsufficientFunds
                } else if e.to_string().contains("stale_nonce") {
                    LedgerError::Invalid("stale nonce".into())
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;
        let new_bond = self.worker_bond_micro(&w)?;
        self.persist_snapshot_best_effort();
        Ok((amount_micro, new_bond))
    }

    /// Unstake worker bond: atomically move Stevemon from [`worker_stakes_v1`] back to [`balances`].
    pub fn unstake_worker_bond_micro(
        &self,
        wallet: &str,
        amount_micro: u64,
        signed_nonce: Option<u64>,
    ) -> Result<(u64, u64), LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if amount_micro == 0 {
            return Err(LedgerError::Invalid("amount must be > 0".into()));
        }
        let w_k = w.as_bytes().to_vec();
        let nonce_key = Self::wallet_nonce_meta_key(&w);
        let res: Result<(), TransactionError<sled::Error>> =
            (&self.balances, &self.worker_stakes, &self.meta).transaction(|(b, ws, m)| {
                if let Some(req_n) = signed_nonce {
                    let cur = m
                        .get(&nonce_key)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    if req_n <= cur {
                        return Err(ConflictableTransactionError::Abort(
                            sled::Error::Unsupported("stale_nonce".into()),
                        ));
                    }
                }
                let cur_bond = ws
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if cur_bond < amount_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("insufficient_worker_bond".into()),
                    ));
                }
                let fb = b
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                ws.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(cur_bond.saturating_sub(amount_micro)))?,
                )?;
                b.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(fb.saturating_add(amount_micro)))?,
                )?;
                if let Some(req_n) = signed_nonce {
                    m.insert(nonce_key.clone(), self.encrypt_value(&u64_to_bytes(req_n))?)?;
                }
                Ok(())
            });
        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient_worker_bond") {
                    LedgerError::Invalid("insufficient worker bond".into())
                } else if e.to_string().contains("stale_nonce") {
                    LedgerError::Invalid("stale nonce".into())
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;
        let new_bond = self.worker_bond_micro(&w)?;
        self.persist_snapshot_best_effort();
        Ok((amount_micro, new_bond))
    }

    fn caac_wallet_meta_key(wallet: &str) -> Vec<u8> {
        format!(
            "{}{}",
            META_CAAC_WALLET_PREFIX,
            wallet.trim().to_ascii_lowercase()
        )
        .into_bytes()
    }

    pub fn caac_put_worker_record(
        &self,
        wallet: &str,
        rec: &CaacWorkerRecord,
    ) -> Result<(), LedgerError> {
        let k = Self::caac_wallet_meta_key(wallet);
        let bytes = serde_json::to_vec(rec).map_err(|e| LedgerError::Invalid(e.to_string()))?;
        let enc = self.encrypt_value(&bytes)?;
        self.meta.insert(k, enc)?;
        std::mem::drop(self.db.flush_async());
        Ok(())
    }

    pub fn caac_get_worker_record(&self, wallet: &str) -> Option<CaacWorkerRecord> {
        let k = Self::caac_wallet_meta_key(wallet);
        let v = self.meta.get(&k).ok()??;
        let pt = self.decrypt_value(v.as_ref()).ok()?;
        serde_json::from_slice(&pt).ok()
    }

    /// ZK-Court: forfeit **entire** worker bond, burn from total supply, clear bond row.
    pub fn slash_worker_bond_zk_court_burn_all(&self, wallet: &str) -> Result<u64, LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        let w_k = w.as_bytes().to_vec();
        let res: Result<u64, TransactionError<sled::Error>> = (&self.meta, &self.worker_stakes)
            .transaction(|(m, ws)| {
                let cur_bond = ws
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if cur_bond == 0 {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("zero_worker_bond".into()),
                    ));
                }
                ws.remove(w_k.clone())?;
                let burned_prev = m
                    .get(META_TOTAL_BURNED)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    META_TOTAL_BURNED,
                    self.encrypt_value(&u64_to_bytes(burned_prev.saturating_add(cur_bond)))?,
                )?;
                let supply = m
                    .get(META_TOTAL_SUPPLY)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    META_TOTAL_SUPPLY,
                    self.encrypt_value(&u64_to_bytes(supply.saturating_sub(cur_bond)))?,
                )?;
                Ok(cur_bond)
            });
        match res {
            Ok(bond) => {
                let audit = serde_json::json!({
                    "v": 1,
                    "action": "zk_court_worker_bond_slash_burn_v1",
                    "wallet": w,
                    "bond_burned_micro": bond,
                });
                let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
                self.persist_snapshot_best_effort();
                Ok(bond)
            }
            Err(TransactionError::Abort(e) | TransactionError::Storage(e)) => {
                if e.to_string().contains("zero_worker_bond") {
                    Err(LedgerError::Invalid("no worker bond to slash".into()))
                } else {
                    Err(LedgerError::Sled(e))
                }
            }
        }
    }

    /// Slash: remove micro-units from staked balance and burn them from total supply.
    pub fn slash_stake_micro(
        &self,
        wallet: &str,
        amount_micro: u64,
    ) -> Result<(u64, u64), LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if amount_micro == 0 {
            return Err(LedgerError::Invalid("amount must be > 0".into()));
        }
        let stake_k = Self::wallet_stake_meta_key(&w);
        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, _b)| {
                let cur_stake = m
                    .get(&stake_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if cur_stake < amount_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("insufficient_stake".into()),
                    ));
                }
                m.insert(
                    stake_k.clone(),
                    self.encrypt_value(&u64_to_bytes(cur_stake.saturating_sub(amount_micro)))?,
                )?;
                // Burn slashed stake from supply (scarcity) and track total burned.
                let burned_prev = m
                    .get(META_TOTAL_BURNED)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    META_TOTAL_BURNED,
                    self.encrypt_value(&u64_to_bytes(burned_prev.saturating_add(amount_micro)))?,
                )?;
                let supply = m
                    .get(META_TOTAL_SUPPLY)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    META_TOTAL_SUPPLY,
                    self.encrypt_value(&u64_to_bytes(supply.saturating_sub(amount_micro)))?,
                )?;
                Ok(())
            });
        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient_stake") {
                    LedgerError::Invalid("insufficient staked balance".into())
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;
        let new_stake = self.staked_balance_micro(&w)?;
        self.persist_snapshot_best_effort();
        Ok((amount_micro, new_stake))
    }

    /// ZK-Court / fraud slash: debit liquid balance up to `penalty_micro`, burn entirely from total supply.
    ///
    /// Matches burn accounting used elsewhere: credit burn sink, bump [`META_TOTAL_BURNED`], reduce [`META_TOTAL_SUPPLY`].
    pub fn slash_wallet_liquid_burn_micro(
        &self,
        wallet: &str,
        penalty_micro: u64,
    ) -> Result<u64, LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if penalty_micro == 0 {
            return Err(LedgerError::Invalid("penalty must be > 0".into()));
        }

        let burn_wallet = self.ai_burn_wallet();
        let burn_k = burn_wallet.as_bytes().to_vec();
        let wallet_k = w.as_bytes().to_vec();

        let res: Result<u64, TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                let bal = b
                    .get(&wallet_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                let take = bal.min(penalty_micro);
                if take == 0 {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("zero_slashable_balance".into()),
                    ));
                }

                b.insert(
                    wallet_k.clone(),
                    self.encrypt_value(&u64_to_bytes(bal.saturating_sub(take)))?,
                )?;

                let total = m
                    .get(META_TOTAL_SUPPLY)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);

                let b_cur = b
                    .get(&burn_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    burn_k.clone(),
                    self.encrypt_value(&u64_to_bytes(b_cur.saturating_add(take)))?,
                )?;

                let burned_prev = m
                    .get(META_TOTAL_BURNED)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    META_TOTAL_BURNED,
                    self.encrypt_value(&u64_to_bytes(burned_prev.saturating_add(take)))?,
                )?;

                m.insert(
                    META_TOTAL_SUPPLY,
                    self.encrypt_value(&u64_to_bytes(total.saturating_sub(take)))?,
                )?;

                Ok(take)
            });

        let taken = res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("zero_slashable_balance") {
                    LedgerError::InsufficientFunds
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;

        let audit = serde_json::json!({
            "v": 1,
            "action": "zk_court_slash_liquid_burn_v1",
            "wallet": w,
            "burn_wallet": burn_wallet,
            "slash_micro": taken,
            "penalty_micro_requested": penalty_micro,
        });
        let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
        self.persist_snapshot_best_effort();
        Ok(taken)
    }

    /// Last committed nonce for [`Ledger::transfer_with_fee_attested`] when `signed_transfer_nonce` is set.
    /// Missing entry is treated as **0** (first valid client nonce is **1**).
    pub fn wallet_last_transfer_nonce(&self, wallet: &str) -> Result<u64, LedgerError> {
        let k = Self::wallet_nonce_meta_key(wallet);
        Ok(self
            .meta
            .get(k)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    /// Half of each protocol-style fee → worker pool credit; half → burn from [`META_TOTAL_SUPPLY`].
    pub fn split_protocol_fee_treasury_and_burn(fee_micro: u64) -> (u64, u64) {
        let pool_micro = fee_micro / 2;
        let burn_micro = fee_micro.saturating_sub(pool_micro);
        (pool_micro, burn_micro)
    }

    pub fn open(path: &str) -> Result<Self, LedgerError> {
        let db = sled::open(path)?;
        let snapshot_dir = std::path::Path::new(path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));

        // Default posture: if an encryption key is provided, we treat encryption as strict unless explicitly disabled.
        let has_key = std::env::var("TET_DB_KEY_B64")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some()
            || std::env::var("TET_DB_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .is_some();
        let encrypt_mode = std::env::var("TET_DB_ENCRYPT")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if has_key {
                    "strict".to_string()
                } else {
                    "off".to_string()
                }
            });
        let mode = encrypt_mode.trim().to_ascii_lowercase();
        let disable_encrypt = mode == "0" || mode == "false";
        let strict = mode == "strict";

        let enc_key = if disable_encrypt {
            None
        } else {
            let b64 = std::env::var("TET_DB_KEY_B64")
                .ok()
                .or_else(|| std::env::var("TET_DB_KEY").ok());
            if strict && b64.is_none() {
                return Err(LedgerError::Invalid(
                    "TET_DB_ENCRYPT=strict requires TET_DB_KEY_B64 (or TET_DB_KEY)".into(),
                ));
            }
            b64.and_then(|b64| {
                let mut bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .ok()?;
                if bytes.len() != 32 {
                    bytes.zeroize();
                    return None;
                }
                let mut km = [0u8; 32];
                km.copy_from_slice(&bytes);
                bytes.zeroize();
                Some(EncKey(km))
            })
        };
        if strict && enc_key.is_none() {
            return Err(LedgerError::Invalid(
                "TET_DB_ENCRYPT=strict requires a valid 32-byte base64 key".into(),
            ));
        }

        let ledger = Self {
            balances: db.open_tree("balances")?,
            meta: db.open_tree("meta")?,
            proofs: db.open_tree("energy_proofs")?,
            audit: db.open_tree("audit")?,
            audit_seq: db.open_tree("audit_seq_v1")?,
            founding: db.open_tree("founding_certs")?,
            ai_quota: db.open_tree("ai_quota")?,
            vest_locks: db.open_tree("vest_locks")?,
            p2p_peers: db.open_tree("p2p_peers")?,
            ai_infer_sessions: db.open_tree("ai_infer_sessions_v1")?,
            faucet_recipients: db.open_tree("faucet_recipients_v1")?,
            faucet_claims: db.open_tree("faucet_claims_v1")?,
            faucet_ip_rl: db.open_tree("faucet_ip_rl_v1")?,
            worker_stakes: db.open_tree("worker_stakes_v1")?,
            db,
            enc_key,
            snapshot_dir,
        };
        ledger.ensure_db_magic(strict)?;
        ledger.maybe_migrate_stevemon_scale()?;
        // Load persisted snapshot if present (crash-safe external snapshot).
        ledger.load_snapshot_if_present();
        Ok(ledger)
    }

    fn load_snapshot_if_present(&self) {
        let (json_path, _tmp_path) = self.snapshot_path();
        let Ok(bytes) = std::fs::read(&json_path) else {
            return;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return;
        };
        if v.get("v").and_then(|x| x.as_u64()).unwrap_or(0) != 1 {
            return;
        }
        // Restore founder wallet + balances only if there is no material on-ledger balance state.
        if self.has_balance_rows().unwrap_or(true) {
            return;
        }
        if let Some(fw) = v
            .get("founder_wallet")
            .and_then(|x| x.as_str())
            .filter(|fw| !fw.trim().is_empty())
        {
            let _ = self.meta.insert(
                META_FOUNDER_WALLET,
                self.encrypt_value(fw.as_bytes()).unwrap_or_default(),
            );
        }
        if let Some(arr) = v.get("balances").and_then(|x| x.as_array()) {
            for row in arr {
                let Some(w) = row.get(0).and_then(|x| x.as_str()) else {
                    continue;
                };
                let amt = row.get(1).and_then(|x| x.as_u64()).unwrap_or(0);
                let _ = self.balances.insert(
                    w.as_bytes(),
                    self.encrypt_value(&u64_to_bytes(amt)).unwrap_or_default(),
                );
            }
        }
        let _ = self.db.flush();
    }

    fn ensure_db_magic(&self, strict: bool) -> Result<(), LedgerError> {
        if strict && self.enc_key.is_none() {
            return Err(LedgerError::Invalid(
                "strict mode requires encryption key".into(),
            ));
        }
        let Some(v) = self.meta.get(META_DB_MAGIC)? else {
            // First boot: initialize sentinel.
            let enc = self.encrypt_value(DB_MAGIC)?;
            self.meta.insert(META_DB_MAGIC, enc)?;
            std::mem::drop(self.db.flush_async());
            return Ok(());
        };
        let pt = self
            .decrypt_value(v.as_ref())
            .map_err(|_| LedgerError::Invalid("database decryption failed (wrong key?)".into()))?;
        if pt.as_slice() == DB_MAGIC_LEGACY {
            let enc = self.encrypt_value(DB_MAGIC)?;
            self.meta.insert(META_DB_MAGIC, enc)?;
            std::mem::drop(self.db.flush_async());
            return Ok(());
        }
        if pt.as_slice() != DB_MAGIC {
            return Err(LedgerError::Invalid(
                "database magic mismatch (wrong key?)".into(),
            ));
        }
        Ok(())
    }

    fn read_stevemon_per_tet_meta(&self) -> Result<Option<u64>, LedgerError> {
        let Some(enc) = self.meta.get(META_STEVEMON_PER_TET)? else {
            return Ok(None);
        };
        let pt = self.decrypt_value(enc.as_ref())?;
        Ok(Some(bytes_to_u64(&pt)))
    }

    fn write_stevemon_per_tet_meta(&self, v: u64) -> Result<(), LedgerError> {
        self.meta
            .insert(META_STEVEMON_PER_TET, self.encrypt_value(&u64_to_bytes(v))?)?;
        Ok(())
    }

    fn ledger_has_any_monetary_state(&self) -> Result<bool, LedgerError> {
        if self.has_balance_rows()? {
            return Ok(true);
        }
        if self.total_supply_micro().unwrap_or(0) > 0 {
            return Ok(true);
        }
        if self.vest_locks.iter().next().transpose()?.is_some() {
            return Ok(true);
        }
        Ok(false)
    }

    /// Align stored amounts with [`STEVEMON`] when upgrading from legacy 1e8 atoms/TET (divide by 100).
    fn maybe_migrate_stevemon_scale(&self) -> Result<(), LedgerError> {
        if self.read_stevemon_per_tet_meta()? == Some(STEVEMON) {
            return Ok(());
        }
        if !self.ledger_has_any_monetary_state()? {
            self.write_stevemon_per_tet_meta(STEVEMON)?;
            std::mem::drop(self.db.flush_async());
            return Ok(());
        }

        eprintln!(
            "[ledger] Stevemon migration: {} atoms/TET → {} atoms/TET (amounts ÷ 100)",
            LEGACY_STEVEMON_PER_TET, STEVEMON
        );
        self.migrate_legacy_e8_micro_state_div100()?;
        self.write_stevemon_per_tet_meta(STEVEMON)?;
        std::mem::drop(self.db.flush_async());
        Ok(())
    }

    fn scale_encrypted_u64_in_tree_div100(
        &self,
        tree: &sled::Tree,
        key: &[u8],
    ) -> Result<(), LedgerError> {
        let Some(enc) = tree.get(key)? else {
            return Ok(());
        };
        let pt = self.decrypt_value(enc.as_ref())?;
        let old = bytes_to_u64(&pt);
        let new_v = old / 100;
        tree.insert(key, self.encrypt_value(&u64_to_bytes(new_v))?)?;
        Ok(())
    }

    fn migrate_legacy_e8_micro_state_div100(&self) -> Result<(), LedgerError> {
        for item in self.balances.iter() {
            let (k, v) = item?;
            let pt = self.decrypt_value(v.as_ref())?;
            let old = bytes_to_u64(&pt);
            let new_v = old / 100;
            self.balances
                .insert(k.as_ref(), self.encrypt_value(&u64_to_bytes(new_v))?)?;
        }

        for k in [
            META_TOTAL_SUPPLY,
            META_TOTAL_BURNED,
            META_FEE_TOTAL,
            META_FOUNDER_GENESIS_LOCKED_MICRO,
            META_WORKER_COMMUNITY_MICRO,
            META_CHF_DEPOSITS_MICRO,
            META_FIAT_MINT_STEVEMON_MICRO,
        ] {
            self.scale_encrypted_u64_in_tree_div100(&self.meta, k)?;
        }

        for item in self.meta.iter() {
            let (k, v) = item?;
            if !k.starts_with(META_WALLET_STAKE_PREFIX) {
                continue;
            }
            let pt = match self.decrypt_value(v.as_ref()) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let old = bytes_to_u64(&pt);
            let new_v = old / 100;
            self.meta
                .insert(k.as_ref(), self.encrypt_value(&u64_to_bytes(new_v))?)?;
        }

        for item in self.vest_locks.iter() {
            let (k, v) = item?;
            let pt = self.decrypt_value(v.as_ref())?;
            let mut row: VestLockV1 =
                serde_json::from_slice(&pt).map_err(|e| LedgerError::Invalid(e.to_string()))?;
            row.amount_micro /= 100;
            let enc = self.encrypt_value(
                &serde_json::to_vec(&row).map_err(|e| LedgerError::Invalid(e.to_string()))?,
            )?;
            self.vest_locks.insert(k.as_ref(), enc)?;
        }

        Ok(())
    }

    // `cipher/encrypt_value/decrypt_value` moved to `ledger/crypto.rs`

    #[cfg(test)]
    pub fn test_only_raw_meta_value(&self, key: &[u8]) -> Vec<u8> {
        self.meta
            .get(key)
            .ok()
            .flatten()
            .map(|v| v.to_vec())
            .unwrap_or_default()
    }

    fn audit_write(&self, record_json: &[u8]) -> Result<(String, u64), LedgerError> {
        // Encrypted, append-only audit record with a stable hash.
        let mut h = Sha256::new();
        h.update(record_json);
        let hash_hex = hex::encode(h.finalize());
        let key = hash_hex.as_bytes();
        let enc = self.encrypt_value(record_json)?;
        self.audit.insert(key, enc)?;
        // Maintain a monotonic sequence for ordered reads (Explorer / history feeds).
        let seq = self.next_audit_seq()?;
        let _ = self
            .audit_seq
            .insert(u64_to_bytes(seq), hash_hex.as_bytes());
        std::mem::drop(self.db.flush_async());
        eprintln!("[AUDIT] Transaction Executed - Hash: {hash_hex}");
        Ok((hash_hex, seq))
    }

    fn next_audit_seq(&self) -> Result<u64, LedgerError> {
        let cur = self
            .meta
            .get(META_AUDIT_SEQ)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0);
        let next = cur.saturating_add(1);
        self.meta
            .insert(META_AUDIT_SEQ, self.encrypt_value(&u64_to_bytes(next))?)?;
        Ok(next)
    }

    fn snapshot_path(&self) -> (std::path::PathBuf, std::path::PathBuf) {
        let json = std::env::var("TET_LEDGER_JSON_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "tet_ledger.json".to_string());
        let tmp = std::env::var("TET_LEDGER_TMP_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "tet_ledger.tmp".to_string());
        let jp = std::path::PathBuf::from(&json);
        let tp = std::path::PathBuf::from(&tmp);
        let jp = if jp.is_absolute() {
            jp
        } else {
            self.snapshot_dir.join(jp)
        };
        let tp = if tp.is_absolute() {
            tp
        } else {
            self.snapshot_dir.join(tp)
        };
        (jp, tp)
    }

    pub fn snapshot_json_path_public(&self) -> String {
        let (p, _) = self.snapshot_path();
        if let Ok(c) = std::fs::canonicalize(&p) {
            return c.to_string_lossy().into_owned();
        }
        p.to_string_lossy().into_owned()
    }

    pub fn audit_events_recent(&self, limit: usize) -> Result<Vec<AuditEventV1>, LedgerError> {
        let mut out = Vec::new();
        let it = self.audit_seq.iter().rev();
        for res in it {
            let (k, v) = res?;
            let seq = bytes_to_u64(k.as_ref());
            let hash_hex = String::from_utf8_lossy(v.as_ref()).to_string();
            if hash_hex.is_empty() {
                continue;
            }
            let Some(enc) = self.audit.get(hash_hex.as_bytes())? else {
                continue;
            };
            let pt = self.decrypt_value(enc.as_ref())?;
            let mut record: serde_json::Value =
                serde_json::from_slice(&pt).unwrap_or_else(|_| serde_json::json!({ "raw_b64": base64::engine::general_purpose::STANDARD.encode(pt) }));
            let ts_ms = record
                .get("ts_ms")
                .and_then(|x| x.as_u64())
                .map(|v| v as u128)
                .unwrap_or(0);
            // Ensure we always have ts_ms for UI sorting/labeling (even legacy events).
            if ts_ms == 0 {
                let now = ledger_now_ms();
                if let Some(obj) = record.as_object_mut() {
                    obj.insert("ts_ms".to_string(), serde_json::json!(now));
                }
            }
            let ts_ms = record
                .get("ts_ms")
                .and_then(|x| x.as_u64())
                .map(|v| v as u128)
                .unwrap_or(0);
            out.push(AuditEventV1 {
                seq,
                hash_hex,
                ts_ms,
                record,
            });
            if out.len() >= limit.max(1) {
                break;
            }
        }
        Ok(out)
    }

    fn fsync_parent_dir(path: &std::path::Path) {
        if let Some(parent) = path.parent().and_then(|p| std::fs::File::open(p).ok()) {
            let _ = parent.sync_all();
        }
    }

    fn atomic_write_snapshot(&self, bytes: &[u8]) -> Result<(), LedgerError> {
        let (json_path, tmp_path) = self.snapshot_path();
        if let Some(parent) = tmp_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LedgerError::Invalid(format!("snapshot parent mkdir failed: {e}")))?;
        }
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp_path)
                .map_err(|e| LedgerError::Invalid(format!("snapshot tmp open failed: {e}")))?;
            use std::io::Write as _;
            f.write_all(bytes)
                .map_err(|e| LedgerError::Invalid(format!("snapshot tmp write failed: {e}")))?;
            f.sync_all()
                .map_err(|e| LedgerError::Invalid(format!("snapshot tmp fsync failed: {e}")))?;
        }
        std::fs::rename(&tmp_path, &json_path)
            .map_err(|e| LedgerError::Invalid(format!("snapshot rename failed: {e}")))?;
        Self::fsync_parent_dir(&json_path);
        Ok(())
    }

    fn build_snapshot_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        #[derive(serde::Serialize)]
        struct Snap {
            v: u32,
            total_supply_micro: u64,
            total_burned_micro: u64,
            fee_total_micro: u64,
            founder_wallet: String,
            worker_community_mint_micro: u64,
            chf_deposits_micro: u64,
            fiat_mint_stevemon_micro: u64,
            balances: Vec<(String, u64)>,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            worker_stakes: Vec<(String, u64)>,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            vest_locks: Vec<VestLockV1>,
        }
        let mut balances = Vec::new();
        for it in self.balances.iter() {
            let (k, v) = it?;
            let w = String::from_utf8_lossy(k.as_ref()).to_string();
            let amt = self.decrypt_value(v.as_ref())?;
            balances.push((w, bytes_to_u64(&amt)));
        }
        let mut worker_stakes = Vec::new();
        for it in self.worker_stakes.iter() {
            let (k, v) = it?;
            let w = String::from_utf8_lossy(k.as_ref()).to_string();
            let amt = self.decrypt_value(v.as_ref())?;
            worker_stakes.push((w, bytes_to_u64(&amt)));
        }
        let mut vest_locks = Vec::new();
        for it in self.vest_locks.iter() {
            let (k, v) = it?;
            if k.len() < 4 || &k.as_ref()[0..4] != b"vl1\x00" {
                continue;
            }
            let pt = self.decrypt_value(v.as_ref())?;
            let row: VestLockV1 =
                serde_json::from_slice(&pt).map_err(|e| LedgerError::Invalid(e.to_string()))?;
            vest_locks.push(row);
        }
        let founder_wallet = self.founder_wallet_public().unwrap_or_default();
        let snap = Snap {
            v: 1,
            total_supply_micro: self.total_supply_micro().unwrap_or(0),
            total_burned_micro: self.total_burned_micro().unwrap_or(0),
            fee_total_micro: self.fee_total_micro().unwrap_or(0),
            founder_wallet,
            worker_community_mint_micro: self.worker_community_mint_micro_total().unwrap_or(0),
            chf_deposits_micro: self.chf_deposits_micro_total().unwrap_or(0),
            fiat_mint_stevemon_micro: self.fiat_mint_stevemon_micro_total().unwrap_or(0),
            balances,
            worker_stakes,
            vest_locks,
        };
        serde_json::to_vec(&snap).map_err(|e| LedgerError::Invalid(e.to_string()))
    }

    fn persist_snapshot_best_effort(&self) {
        if let Ok(bytes) = self.build_snapshot_bytes()
            && self.atomic_write_snapshot(&bytes).is_ok()
        {
            crate::replication::emit_signed_state_update(&bytes);
        }
    }

    /// Flush DB and write an external JSON snapshot (best effort).
    ///
    /// Used for production shutdown safety (SIGTERM/SIGINT).
    pub fn flush_and_snapshot_best_effort(&self) {
        // Ensure sled's internal state is flushed to disk.
        let _ = self.db.flush();
        // Also emit the external snapshot (crash-safe restore path if DB directory is moved/empty).
        self.persist_snapshot_best_effort();
    }

    /// Restore balances + core meta fields from a v1 snapshot JSON (e.g. from a Guardian).
    /// Clears existing balances and replaces them with snapshot contents.
    pub fn import_snapshot_json_v1(&self, json_bytes: &[u8]) -> Result<(), LedgerError> {
        let v: serde_json::Value =
            serde_json::from_slice(json_bytes).map_err(|e| LedgerError::Invalid(e.to_string()))?;
        if v.get("v").and_then(|x| x.as_u64()).unwrap_or(0) != 1 {
            return Err(LedgerError::Invalid("unsupported snapshot v".into()));
        }

        for it in self.balances.iter() {
            let (k, _) = it?;
            self.balances.remove(k)?;
        }

        for it in self.vest_locks.iter() {
            let (k, _) = it?;
            self.vest_locks.remove(k)?;
        }

        for it in self.worker_stakes.iter() {
            let (k, _) = it?;
            self.worker_stakes.remove(k)?;
        }

        if let Some(fw) = v
            .get("founder_wallet")
            .and_then(|x| x.as_str())
            .filter(|fw| !fw.trim().is_empty())
        {
            self.meta
                .insert(META_FOUNDER_WALLET, self.encrypt_value(fw.as_bytes())?)?;
        }

        let total = v
            .get("total_supply_micro")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        self.meta
            .insert(META_TOTAL_SUPPLY, self.encrypt_value(&u64_to_bytes(total))?)?;

        let fee_total = v
            .get("fee_total_micro")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        self.meta.insert(
            META_FEE_TOTAL,
            self.encrypt_value(&u64_to_bytes(fee_total))?,
        )?;

        let burned = v
            .get("total_burned_micro")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        self.meta.insert(
            META_TOTAL_BURNED,
            self.encrypt_value(&u64_to_bytes(burned))?,
        )?;

        let wcomm = v
            .get("worker_community_mint_micro")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        self.meta.insert(
            META_WORKER_COMMUNITY_MICRO,
            self.encrypt_value(&u64_to_bytes(wcomm))?,
        )?;

        let chf = v
            .get("chf_deposits_micro")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        self.meta.insert(
            META_CHF_DEPOSITS_MICRO,
            self.encrypt_value(&u64_to_bytes(chf))?,
        )?;

        let fiat = v
            .get("fiat_mint_stevemon_micro")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        self.meta.insert(
            META_FIAT_MINT_STEVEMON_MICRO,
            self.encrypt_value(&u64_to_bytes(fiat))?,
        )?;

        if let Some(arr) = v.get("balances").and_then(|x| x.as_array()) {
            for row in arr {
                let Some(w) = row.get(0).and_then(|x| x.as_str()) else {
                    continue;
                };
                let amt = row.get(1).and_then(|x| x.as_u64()).unwrap_or(0);
                self.balances
                    .insert(w.as_bytes(), self.encrypt_value(&u64_to_bytes(amt))?)?;
            }
        }

        if let Some(arr) = v.get("worker_stakes").and_then(|x| x.as_array()) {
            for row in arr {
                let Some(w) = row.get(0).and_then(|x| x.as_str()) else {
                    continue;
                };
                let amt = row.get(1).and_then(|x| x.as_u64()).unwrap_or(0);
                self.worker_stakes
                    .insert(w.as_bytes(), self.encrypt_value(&u64_to_bytes(amt))?)?;
            }
        }

        if let Some(arr) = v.get("vest_locks").and_then(|x| x.as_array()) {
            for (i, row_val) in arr.iter().enumerate() {
                let row: VestLockV1 = serde_json::from_value(row_val.clone())
                    .map_err(|e| LedgerError::Invalid(e.to_string()))?;
                let vest_id = (i as u64).saturating_add(1);
                let mut vk = Vec::with_capacity(4 + 8);
                vk.extend_from_slice(b"vl1\x00");
                vk.extend_from_slice(&vest_id.to_le_bytes());
                let vest_bytes =
                    serde_json::to_vec(&row).map_err(|e| LedgerError::Invalid(e.to_string()))?;
                self.vest_locks
                    .insert(vk, self.encrypt_value(&vest_bytes)?)?;
            }
            let n = arr.len() as u64;
            self.meta
                .insert(META_NEXT_VEST_SEQ, self.encrypt_value(&u64_to_bytes(n))?)?;
        } else {
            self.meta
                .insert(META_NEXT_VEST_SEQ, self.encrypt_value(&u64_to_bytes(0))?)?;
        }

        std::mem::drop(self.db.flush_async());
        self.persist_snapshot_best_effort();
        Ok(())
    }

    pub fn audit_csv_export(&self, limit: usize) -> Result<String, LedgerError> {
        let cap = limit.clamp(1, 100_000);
        let mut out = String::new();
        out.push_str("hash_sha256_hex,record_json\n");
        for (i, it) in self.audit.iter().enumerate() {
            if i >= cap {
                break;
            }
            let (k, v) = it?;
            let hash = String::from_utf8_lossy(k.as_ref()).to_string();
            let pt = self.decrypt_value(v.as_ref())?;
            let rec = String::from_utf8_lossy(&pt)
                .replace(['\n', '\r'], " ")
                .replace('"', "\"\"");
            out.push('"');
            out.push_str(&hash);
            out.push_str("\",\"");
            out.push_str(&rec);
            out.push_str("\"\n");
        }
        Ok(out)
    }

    /// Records `TET_FOUNDER_WALLET` in meta for fee routing / audits. Does **not** mint TET.
    /// Full fixed-supply genesis mint is `apply_genesis_allocation` (typically via `POST /founder/genesis`).
    pub fn init_genesis_founder_premine_from_env(&self) -> Result<(), LedgerError> {
        let founder = std::env::var("TET_FOUNDER_WALLET")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_default();
        let founder = founder.trim().to_string();
        if founder.is_empty() {
            return Ok(());
        }
        self.meta
            .insert(META_FOUNDER_WALLET, self.encrypt_value(founder.as_bytes())?)?;
        self.db.flush()?;
        Ok(())
    }

    /// One-time genesis mint: **25%** founder + **75%** [`WALLET_SYSTEM_WORKER_POOL`] (= full [`MAX_SUPPLY_MICRO`]).
    /// Fails with [`LedgerError::GenesisAlreadyApplied`] if total supply is already non-zero.
    ///
    /// **Big bang:** when `META_TOTAL_SUPPLY` is unset or 0, the `balances` tree is **cleared** first so async
    /// racing writes cannot block genesis; then allocation runs. (Does not clear `meta` / other trees.)
    pub fn apply_genesis_allocation(
        &self,
        founder_wallet_id: &str,
    ) -> Result<GenesisAllocationSummary, LedgerError> {
        let founder = founder_wallet_id.trim().to_string();
        if founder.is_empty() {
            return Err(LedgerError::Invalid("founder_wallet_id required".into()));
        }

        if self.total_supply_micro()? > 0 {
            return Err(LedgerError::GenesisAlreadyApplied);
        }

        self.balances.clear()?;
        self.worker_stakes.clear()?;
        self.db.flush()?;

        let founder_key = founder.as_bytes().to_vec();
        let pool_key = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();
        let ecosystem_key = WALLET_ECOSYSTEM.as_bytes().to_vec();
        let reserve_key = WALLET_PROTOCOL_RESERVE.as_bytes().to_vec();
        let now_ms = ledger_now_ms();
        let unlock_at_ms = now_ms.saturating_add(founder_genesis_cliff_ms());

        let res: Result<GenesisAllocationSummary, TransactionError<sled::Error>> =
            (&self.meta, &self.balances).transaction(|(m, b)| {
                let total = m
                    .get(META_TOTAL_SUPPLY)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if total > 0 {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("genesis_already_applied".into()),
                    ));
                }

                if GENESIS_FOUNDER_SHARE_MICRO == 0 {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("genesis founder allocation must be > 0".into()),
                    ));
                }
                if GENESIS_TOTAL_MINT_MICRO > MAX_SUPPLY_MICRO {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("genesis allocation exceeds max supply".into()),
                    ));
                }

                let credit =
                    |tree: &TransactionalTree,
                     key: &[u8],
                     add: u64|
                     -> Result<(), ConflictableTransactionError<sled::Error>> {
                        let cur = tree
                            .get(key)?
                            .as_deref()
                            .map(|v| self.decrypt_value(v))
                            .transpose()?
                            .as_deref()
                            .map(bytes_to_u64)
                            .unwrap_or(0);
                        tree.insert(
                            key.to_vec(),
                            self.encrypt_value(&u64_to_bytes(cur.saturating_add(add)))?,
                        )?;
                        Ok(())
                    };

                credit(b, &founder_key, GENESIS_FOUNDER_SHARE_MICRO)?;
                credit(b, &pool_key, GENESIS_WORKER_POOL_SHARE_MICRO)?;
                credit(b, &ecosystem_key, GENESIS_ECOSYSTEM_SHARE_MICRO)?;
                credit(b, &reserve_key, GENESIS_PROTOCOL_RESERVE_SHARE_MICRO)?;

                m.insert(
                    META_TOTAL_SUPPLY,
                    self.encrypt_value(&u64_to_bytes(GENESIS_TOTAL_MINT_MICRO))?,
                )?;
                m.insert(META_FOUNDER_WALLET, self.encrypt_value(founder.as_bytes())?)?;
                // Founder vesting: lock the genesis allocation for exactly 365 days.
                m.insert(
                    META_FOUNDER_GENESIS_UNLOCK_AT_MS,
                    self.encrypt_value(&u64_to_bytes((unlock_at_ms.min(u64::MAX as u128)) as u64))?,
                )?;
                m.insert(
                    META_FOUNDER_GENESIS_LOCKED_MICRO,
                    self.encrypt_value(&u64_to_bytes(GENESIS_FOUNDER_SHARE_MICRO))?,
                )?;

                Ok(GenesisAllocationSummary {
                    founder_wallet_id: founder.clone(),
                    founder_allocation_micro: GENESIS_FOUNDER_SHARE_MICRO,
                    dex_treasury_allocation_micro: GENESIS_DEX_TREASURY_MICRO,
                    worker_pool_allocation_micro: GENESIS_WORKER_POOL_SHARE_MICRO,
                    total_supply_micro: GENESIS_TOTAL_MINT_MICRO,
                })
            });

        let summary = res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("genesis_already_applied") {
                    LedgerError::GenesisAlreadyApplied
                } else if e.to_string().contains("genesis ") {
                    LedgerError::Invalid(e.to_string())
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;

        let audit = serde_json::json!({
            "v": 1,
            "ts_ms": ledger_now_ms(),
            "action": "genesis_allocation",
            "founder_wallet_id": summary.founder_wallet_id,
            "founder_allocation_micro": summary.founder_allocation_micro,
            "worker_pool_wallet_id": WALLET_WORKER_POOL,
            "worker_pool_allocation_micro": GENESIS_WORKER_POOL_SHARE_MICRO,
            "ecosystem_wallet_id": WALLET_ECOSYSTEM,
            "ecosystem_allocation_micro": GENESIS_ECOSYSTEM_SHARE_MICRO,
            "protocol_reserve_wallet_id": WALLET_PROTOCOL_RESERVE,
            "protocol_reserve_allocation_micro": GENESIS_PROTOCOL_RESERVE_SHARE_MICRO,
            "dex_treasury_wallet": WALLET_DEX_TREASURY,
            "dex_treasury_allocation_micro": summary.dex_treasury_allocation_micro,
            "worker_pool_wallet": WALLET_SYSTEM_WORKER_POOL,
            "worker_pool_allocation_micro": summary.worker_pool_allocation_micro,
            "total_supply_micro": summary.total_supply_micro,
        });
        let audit_vec = serde_json::to_vec(&audit).expect("genesis audit JSON serialize");
        self.audit_write(&audit_vec)
            .unwrap_or_else(|e| panic!("FATAL: genesis audit_write failed: {e}"));
        // Synchronous flush so `META_TOTAL_SUPPLY` and balances are visible to REST immediately after boot.
        self.db
            .flush()
            .unwrap_or_else(|e| panic!("FATAL: genesis sled flush failed after mint: {e}"));

        let ts = self.total_supply_micro().unwrap_or_else(|e| {
            panic!("FATAL: could not read META_TOTAL_SUPPLY after genesis flush: {e}")
        });
        assert_eq!(
            ts, GENESIS_TOTAL_MINT_MICRO,
            "FATAL: META_TOTAL_SUPPLY mismatch after genesis (expected GENESIS_TOTAL_MINT_MICRO)"
        );
        let founder_bal = self
            .balance_micro(&founder)
            .unwrap_or_else(|e| panic!("FATAL: could not read founder balance after genesis: {e}"));
        assert_eq!(
            founder_bal, GENESIS_FOUNDER_SHARE_MICRO,
            "FATAL: founder credited balance mismatch after genesis"
        );
        let pool_bal = self
            .balance_micro(WALLET_SYSTEM_WORKER_POOL)
            .unwrap_or_else(|e| {
                panic!("FATAL: could not read system worker pool balance after genesis: {e}")
            });
        assert_eq!(
            pool_bal, GENESIS_WORKER_POOL_SHARE_MICRO,
            "FATAL: system-locked pool balance mismatch after genesis"
        );

        let snap_bytes = self
            .build_snapshot_bytes()
            .unwrap_or_else(|e| panic!("FATAL: genesis build_snapshot_bytes: {e}"));
        self.atomic_write_snapshot(&snap_bytes)
            .unwrap_or_else(|e| panic!("FATAL: genesis atomic_write_snapshot: {e}"));
        crate::replication::emit_signed_state_update(&snap_bytes);

        Ok(summary)
    }

    /// True only if the **`balances` sled tree** (never `meta` / other trees) has at least one leaf that is a **valid ledger balance**:
    /// decrypt succeeds, plaintext is exactly **8 bytes** LE `u64`, and amount ≥ 1 micro-unit.
    /// Decrypt failures (e.g. foreign ciphertext) and non-canonical plaintext lengths are skipped — they are **not** treated as balances.
    pub fn has_balance_rows(&self) -> Result<bool, LedgerError> {
        for item in self.balances.iter() {
            let (_k, v) = item?;
            let Ok(pt) = self.decrypt_value(v.as_ref()) else {
                continue;
            };
            if plaintext_is_material_balance_amount_micro(&pt) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn balance_micro(&self, peer: &str) -> Result<u64, LedgerError> {
        Ok(self
            .balances
            .get(peer.as_bytes())?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    /// Sum of worker AI reward tranches still inside the 90-day lock window (DEX cannot spend this portion).
    pub fn locked_balance_micro(&self, peer: &str, now_ms: u128) -> Result<u64, LedgerError> {
        let mut sum = 0u64;
        let peer = peer.trim();
        for it in self.vest_locks.iter() {
            let (_k, v) = it?;
            let pt = self.decrypt_value(v.as_ref())?;
            let row: VestLockV1 =
                serde_json::from_slice(&pt).map_err(|e| LedgerError::Invalid(e.to_string()))?;
            if row.wallet == peer && row.unlock_at_ms > now_ms {
                sum = sum.saturating_add(row.amount_micro);
            }
        }

        // Founder genesis vesting lock (1-year cliff). Only locks the genesis allocation, not later earnings.
        // This is enforced by reducing the spendable balance of the founder wallet until unlock time.
        if !peer.is_empty()
            && let Ok(founder) = self.founder_wallet()
            && !founder.is_empty()
            && founder == peer
        {
            let unlock_at = self.founder_genesis_unlock_at_ms().unwrap_or(0);
            if unlock_at > 0 && now_ms < unlock_at {
                let locked = self.founder_genesis_locked_micro().unwrap_or(0);
                sum = sum.saturating_add(locked);
            }
        }
        Ok(sum)
    }

    /// Founder genesis unlock timestamp (ms since epoch). 0 means unset/unlocked.
    pub fn founder_genesis_unlock_at_ms(&self) -> Result<u128, LedgerError> {
        let raw = self
            .meta
            .get(META_FOUNDER_GENESIS_UNLOCK_AT_MS)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?;
        let v = raw.as_deref().map(bytes_to_u64).unwrap_or(0);
        Ok(v as u128)
    }

    /// Locked founder genesis amount (micro). This remains constant until unlock time.
    pub fn founder_genesis_locked_micro(&self) -> Result<u64, LedgerError> {
        Ok(self
            .meta
            .get(META_FOUNDER_GENESIS_LOCKED_MICRO)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    pub fn locked_balance_micro_now(&self, peer: &str) -> Result<u64, LedgerError> {
        self.locked_balance_micro(peer, ledger_now_ms())
    }

    /// Balance that may be debited by transfers (including DEX escrow locks).
    pub fn spendable_balance_micro(&self, peer: &str, now_ms: u128) -> Result<u64, LedgerError> {
        let bal = self.balance_micro(peer)?;
        let locked = self.locked_balance_micro(peer, now_ms)?;
        Ok(bal.saturating_sub(locked))
    }

    pub fn spendable_balance_micro_now(&self, peer: &str) -> Result<u64, LedgerError> {
        self.spendable_balance_micro(peer, ledger_now_ms())
    }

    pub fn fee_total_micro(&self) -> Result<u64, LedgerError> {
        Ok(self
            .meta
            .get(META_FEE_TOTAL)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    pub fn ai_cost_month_micro_usd_get(&self, month: &str) -> Result<u64, LedgerError> {
        let mut k = META_AI_COST_MONTH_MICROUSD_PREFIX.to_vec();
        k.extend_from_slice(month.as_bytes());
        Ok(self.meta.get(k)?.as_deref().map(bytes_to_u64).unwrap_or(0))
    }

    pub fn ai_cost_month_micro_usd_add(
        &self,
        month: &str,
        add_micro_usd: u64,
    ) -> Result<u64, LedgerError> {
        let mut k = META_AI_COST_MONTH_MICROUSD_PREFIX.to_vec();
        k.extend_from_slice(month.as_bytes());
        let cur = self.meta.get(&k)?.as_deref().map(bytes_to_u64).unwrap_or(0);
        let next = cur.saturating_add(add_micro_usd);
        self.meta
            .insert(k, self.encrypt_value(&u64_to_bytes(next))?)?;
        std::mem::drop(self.db.flush_async());
        Ok(next)
    }

    pub fn total_supply_micro(&self) -> Result<u64, LedgerError> {
        Ok(self
            .meta
            .get(META_TOTAL_SUPPLY)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    pub fn total_burned_micro(&self) -> Result<u64, LedgerError> {
        Ok(self
            .meta
            .get(META_TOTAL_BURNED)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    /// Logical inference "block" height: number of completed `settle_ai_inference_dynamic_charge` commits.
    pub fn inference_block_height(&self) -> u64 {
        match self.meta.get(META_INFERENCE_BLOCK_HEIGHT) {
            Ok(Some(v)) => self
                .decrypt_value(v.as_ref())
                .ok()
                .map(|b| bytes_to_u64(b.as_ref()))
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// Wall ms when the last inference settlement completed (0 = never).
    fn inference_last_block_wall_ms(&self) -> u64 {
        match self.meta.get(META_INFER_CONSENSUS_LAST_MS) {
            Ok(Some(v)) => self
                .decrypt_value(v.as_ref())
                .ok()
                .map(|b| bytes_to_u64(b.as_ref()))
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// Milliseconds to wait before the next inference settlement (0 = no wait).
    pub fn infer_consensus_delay_ms(&self) -> u64 {
        let last = self.inference_last_block_wall_ms();
        if last == 0 {
            return 0;
        }
        let now = ledger_now_ms() as u64;
        let elapsed = now.saturating_sub(last);
        TARGET_BLOCK_TIME_MS.saturating_sub(elapsed)
    }

    fn wallet_infer_burn_meta_key(wallet: &str) -> Vec<u8> {
        format!(
            "wallet_infer_burn_micro_v1:{}",
            wallet.trim().to_ascii_lowercase()
        )
        .into_bytes()
    }

    /// Cumulative burn share (Stevemon micro) attributed to this wallet from AI inference settlements.
    pub fn wallet_inference_burn_contribution_micro(&self, wallet: &str) -> u64 {
        let k = Self::wallet_infer_burn_meta_key(wallet);
        match self.meta.get(&k) {
            Ok(Some(v)) => self
                .decrypt_value(v.as_ref())
                .ok()
                .map(|b| bytes_to_u64(b.as_ref()))
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// Display epoch (1 = first epoch including Genesis window).
    pub fn consensus_display_epoch(&self) -> u64 {
        let h = self.inference_block_height();
        1u64.saturating_add(h / GENESIS_EPOCH_BLOCK_LIMIT)
    }

    fn founder_wallet(&self) -> Result<String, LedgerError> {
        let Some(v) = self.meta.get(META_FOUNDER_WALLET)? else {
            return Err(LedgerError::FounderWalletMissing);
        };
        let pt = self.decrypt_value(v.as_ref())?;
        Ok(String::from_utf8_lossy(&pt).to_string())
    }

    pub fn founder_wallet_public(&self) -> Result<String, LedgerError> {
        self.founder_wallet()
    }

    pub fn put_founding_cert(&self, cert: &FoundingMemberCert) -> Result<(), LedgerError> {
        let key = cert.member_wallet.as_bytes();
        let bytes = serde_json::to_vec(cert).map_err(|e| LedgerError::Invalid(e.to_string()))?;
        let enc = self.encrypt_value(&bytes)?;
        self.founding.insert(key, enc)?;
        std::mem::drop(self.db.flush_async());
        Ok(())
    }

    pub fn get_founding_cert(&self, wallet: &str) -> Result<FoundingMemberCert, LedgerError> {
        let Some(v) = self.founding.get(wallet.as_bytes())? else {
            return Err(LedgerError::Invalid("founding cert not found".into()));
        };
        let pt = self.decrypt_value(v.as_ref())?;
        let c: FoundingMemberCert =
            serde_json::from_slice(&pt).map_err(|e| LedgerError::Invalid(e.to_string()))?;
        Ok(c)
    }

    #[allow(dead_code)]
    pub fn founding_guardian_count(&self) -> Result<u64, LedgerError> {
        Ok(self.founding.iter().count() as u64)
    }

    pub fn has_founding_cert(&self, wallet: &str) -> Result<bool, LedgerError> {
        Ok(self.founding.get(wallet.as_bytes())?.is_some())
    }

    /// Public Genesis 1,000 program status for `wallet` (first 1,000 claimers get a bonus mint).
    pub fn genesis_1k_status(&self, wallet: &str) -> Result<Genesis1kStatus, LedgerError> {
        let w = wallet.trim();
        let filled = self.genesis_1k_filled_count()?;
        let slot = if w.is_empty() {
            None
        } else {
            let k = genesis_1k_wallet_slot_meta_key(w);
            self.meta
                .get(&k)?
                .as_deref()
                .map(|v| self.decrypt_value(v))
                .transpose()?
                .as_deref()
                .map(bytes_to_u64)
        };
        let claimed = slot.is_some();
        let can_claim = !w.is_empty() && !claimed && filled < GENESIS_1K_MAX;
        Ok(Genesis1kStatus {
            slots_total: GENESIS_1K_MAX,
            slots_filled: filled,
            claimed,
            your_slot: slot,
            can_claim,
            bonus_tet: GENESIS_1K_BONUS_TET as u32,
        })
    }

    fn genesis_1k_filled_count(&self) -> Result<u64, LedgerError> {
        Ok(self
            .meta
            .get(META_GENESIS_1K_FILLED)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    /// Public view for dashboards (`/network/stats`) and UI FOMO counters.
    pub fn genesis_1k_filled_count_public(&self) -> Result<u64, LedgerError> {
        self.genesis_1k_filled_count()
    }

    /// Claim Genesis 1,000 bonus once per wallet while slots remain. Caller must serialize claims (e.g. HTTP mutex).
    /// Mint + genesis bookkeeping occur in **one** sled transaction (see `mint_reward_with_proof`).
    pub fn genesis_1k_claim(&self, wallet: &str) -> Result<u64, LedgerError> {
        let wallet = wallet.trim();
        if wallet.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        let gross_micro = GENESIS_1K_BONUS_TET.saturating_mul(STEVEMON);
        let payload = format!("genesis1000:{wallet}:v1");
        self.mint_reward_with_proof(wallet, gross_micro, payload.as_bytes(), None, true)?;
        let k_slot = genesis_1k_wallet_slot_meta_key(wallet);
        let slot = self
            .meta
            .get(&k_slot)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .ok_or_else(|| LedgerError::Invalid("genesis 1k slot read failed".into()))?;
        std::mem::drop(self.db.flush_async());
        Ok(slot)
    }

    /// One-time **1,000 TET** transfer from [`WALLET_SYSTEM_WORKER_POOL`] to `wallet_id`, for the first
    /// [`FAUCET_INITIAL_AIRDROP_MAX_RECIPIENTS`] distinct wallets. All checks and updates run in **one** sled transaction
    /// (counter + recipient marker + balances) so double-claim and cap races are impossible.
    pub fn claim_initial_airdrop(
        &self,
        wallet_id: &str,
    ) -> Result<InitialAirdropClaimOutcome, LedgerError> {
        let w = wallet_id.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(LedgerError::Invalid("wallet must be 64 hex chars".into()));
        }
        if w == WALLET_SYSTEM_WORKER_POOL
            || w == WALLET_DEX_TREASURY
            || w == WALLET_PROTOCOL_RESERVE
            || w == WALLET_ECOSYSTEM
            || w == self.ai_burn_wallet()
        {
            return Err(LedgerError::Invalid(
                "reserved wallet cannot claim initial airdrop".into(),
            ));
        }

        let w_k = w.as_bytes().to_vec();
        let pool_k = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();
        let amt = FAUCET_INITIAL_AIRDROP_MICRO_PER_USER;

        let res: Result<InitialAirdropClaimOutcome, TransactionError<sled::Error>> =
            (&self.meta, &self.balances, &self.faucet_recipients).transaction(|(m, b, f)| {
                if f.get(&w_k)?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("faucet_initial_already_claimed".into()),
                    ));
                }
                let count = m
                    .get(META_FAUCET_INITIAL_RECIPIENTS_COUNT)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if count >= FAUCET_INITIAL_AIRDROP_MAX_RECIPIENTS {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("faucet_initial_cap_reached".into()),
                    ));
                }
                let pool_cur = b
                    .get(&pool_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if pool_cur < amt {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("faucet_initial_pool_insufficient".into()),
                    ));
                }
                let user_cur = b
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    pool_k.clone(),
                    self.encrypt_value(&u64_to_bytes(pool_cur.saturating_sub(amt)))?,
                )?;
                b.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(user_cur.saturating_add(amt)))?,
                )?;
                f.insert(w_k.clone(), self.encrypt_value(b"{\"v\":1}")?)?;
                m.insert(
                    META_FAUCET_INITIAL_RECIPIENTS_COUNT,
                    self.encrypt_value(&u64_to_bytes(count.saturating_add(1)))?,
                )?;
                Ok(InitialAirdropClaimOutcome::Granted {
                    credited_micro: amt,
                })
            });

        match res {
            Ok(out) => {
                let audit = serde_json::json!({
                    "v": 1,
                    "ts_ms": ledger_now_ms(),
                    "action": "initial_faucet_airdrop_v1",
                    "wallet": w,
                    "credited_micro": amt,
                    "pool_wallet": WALLET_SYSTEM_WORKER_POOL,
                });
                let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
                self.persist_snapshot_best_effort();
                std::mem::drop(self.db.flush_async());
                Ok(out)
            }
            Err(TransactionError::Abort(e)) | Err(TransactionError::Storage(e)) => {
                let es = e.to_string();
                if es.contains("faucet_initial_already_claimed") {
                    Ok(InitialAirdropClaimOutcome::AlreadyClaimed)
                } else if es.contains("faucet_initial_cap_reached") {
                    Ok(InitialAirdropClaimOutcome::CapReached)
                } else if es.contains("faucet_initial_pool_insufficient") {
                    Ok(InitialAirdropClaimOutcome::PoolInsufficient)
                } else {
                    Err(LedgerError::Sled(e))
                }
            }
        }
    }

    /// Admin HTTP faucet: move `amount_micro` from [`WALLET_SYSTEM_WORKER_POOL`] → `wallet_id` exactly once per wallet,
    /// with per-IP rolling-window limits enforced in the **same** sled transaction as the balance updates when
    /// `bypass_limits` is false.
    pub fn admin_rest_faucet(
        &self,
        wallet_id: &str,
        amount_micro: u64,
        ip_key: &str,
        bypass_limits: bool,
        ip_window_ms: u64,
        max_grants_per_ip_per_window: u32,
    ) -> Result<AdminRestFaucetOutcome, LedgerError> {
        let w = wallet_id.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(LedgerError::Invalid("wallet must be 64 hex chars".into()));
        }
        if amount_micro == 0 || amount_micro > ADMIN_REST_FAUCET_MAX_AMOUNT_MICRO {
            return Err(LedgerError::Invalid(
                "amount_micro out of allowed faucet range".into(),
            ));
        }
        if w == WALLET_SYSTEM_WORKER_POOL
            || w == WALLET_DEX_TREASURY
            || w == WALLET_PROTOCOL_RESERVE
            || w == WALLET_ECOSYSTEM
            || w == self.ai_burn_wallet()
        {
            return Err(LedgerError::Invalid(
                "reserved wallet cannot use admin faucet".into(),
            ));
        }

        let w_k = w.as_bytes().to_vec();
        let pool_k = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();

        let mut ip_norm = ip_key.trim().to_string();
        if ip_norm.is_empty() {
            ip_norm = "unknown".to_string();
        }
        if ip_norm.len() > 128 {
            ip_norm.truncate(128);
        }
        let ip_k = format!("iprl:{ip_norm}").into_bytes();

        let pool_insufficient_abort = || {
            ConflictableTransactionError::Abort(sled::Error::Unsupported(
                "admin_faucet_pool_insufficient".into(),
            ))
        };

        if bypass_limits {
            let res: Result<(), TransactionError<sled::Error>> = self.balances.transaction(|b| {
                let pool_cur = b
                    .get(&pool_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if pool_cur < amount_micro {
                    return Err(pool_insufficient_abort());
                }
                let user_cur = b
                    .get(&w_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    pool_k.clone(),
                    self.encrypt_value(&u64_to_bytes(pool_cur.saturating_sub(amount_micro)))?,
                )?;
                b.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(user_cur.saturating_add(amount_micro)))?,
                )?;
                Ok(())
            });
            return match res {
                Ok(()) => {
                    let audit = serde_json::json!({
                        "v": 1,
                        "ts_ms": ledger_now_ms(),
                        "action": "admin_rest_faucet_v1",
                        "wallet": w,
                        "credited_micro": amount_micro,
                        "pool_wallet": WALLET_SYSTEM_WORKER_POOL,
                        "bypass_limits": true,
                    });
                    let audit_vec = serde_json::to_vec(&audit).unwrap_or_default();
                    let (audit_hash_hex, _audit_seq) = self.audit_write(&audit_vec)?;
                    self.persist_snapshot_best_effort();
                    std::mem::drop(self.db.flush_async());
                    Ok(AdminRestFaucetOutcome::Granted {
                        credited_micro: amount_micro,
                        audit_hash_hex,
                    })
                }
                Err(TransactionError::Abort(e)) | Err(TransactionError::Storage(e)) => {
                    let es = e.to_string();
                    if es.contains("admin_faucet_pool_insufficient") {
                        Ok(AdminRestFaucetOutcome::PoolInsufficient)
                    } else {
                        Err(LedgerError::Sled(e))
                    }
                }
            };
        }

        let max_ip = max_grants_per_ip_per_window.max(1);
        let window_ms = ip_window_ms.max(1);

        let res: Result<(), TransactionError<sled::Error>> =
            (&self.balances, &self.faucet_claims, &self.faucet_ip_rl).transaction(
                |(b, fc, ipr)| {
                    if fc.get(&w_k)?.is_some() {
                        return Err(ConflictableTransactionError::Abort(
                            sled::Error::Unsupported("admin_faucet_wallet_already_claimed".into()),
                        ));
                    }

                    let now_ms = ledger_now_ms() as u64;
                    let mut ip_row = FaucetIpRlV1 {
                        v: 1,
                        grant_ts_ms: vec![],
                    };
                    if let Some(enc) = ipr.get(&ip_k)?
                        && let Ok(pt) = self.decrypt_value(&enc)
                        && let Ok(parsed) = serde_json::from_slice::<FaucetIpRlV1>(&pt)
                    {
                        ip_row = parsed;
                    }
                    ip_row
                        .grant_ts_ms
                        .retain(|t| now_ms.saturating_sub(*t) < window_ms);
                    if ip_row.grant_ts_ms.len() >= max_ip as usize {
                        return Err(ConflictableTransactionError::Abort(
                            sled::Error::Unsupported("admin_faucet_ip_rl".into()),
                        ));
                    }

                    let pool_cur = b
                        .get(&pool_k)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    if pool_cur < amount_micro {
                        return Err(pool_insufficient_abort());
                    }
                    let user_cur = b
                        .get(&w_k)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);

                    b.insert(
                        pool_k.clone(),
                        self.encrypt_value(&u64_to_bytes(pool_cur.saturating_sub(amount_micro)))?,
                    )?;
                    b.insert(
                        w_k.clone(),
                        self.encrypt_value(&u64_to_bytes(user_cur.saturating_add(amount_micro)))?,
                    )?;
                    fc.insert(
                        w_k.clone(),
                        self.encrypt_value(br#"{"v":1,"kind":"admin_rest_faucet"}"#)?,
                    )?;

                    ip_row.grant_ts_ms.push(now_ms);
                    let ip_json = serde_json::to_vec(&ip_row).map_err(|e| {
                        ConflictableTransactionError::Abort(sled::Error::Unsupported(format!(
                            "admin_faucet_ip_json:{e}"
                        )))
                    })?;
                    ipr.insert(ip_k.clone(), self.encrypt_value(&ip_json)?)?;

                    Ok(())
                },
            );

        match res {
            Ok(()) => {
                let credited_micro = amount_micro;
                let audit = serde_json::json!({
                    "v": 1,
                    "ts_ms": ledger_now_ms(),
                    "action": "admin_rest_faucet_v1",
                    "wallet": w,
                    "credited_micro": credited_micro,
                    "pool_wallet": WALLET_SYSTEM_WORKER_POOL,
                    "ip_key": ip_norm,
                    "bypass_limits": false,
                });
                let audit_vec = serde_json::to_vec(&audit).unwrap_or_default();
                let (audit_hash_hex, _audit_seq) = self.audit_write(&audit_vec)?;
                self.persist_snapshot_best_effort();
                std::mem::drop(self.db.flush_async());
                Ok(AdminRestFaucetOutcome::Granted {
                    credited_micro,
                    audit_hash_hex,
                })
            }
            Err(TransactionError::Abort(e)) | Err(TransactionError::Storage(e)) => {
                let es = e.to_string();
                if es.contains("admin_faucet_wallet_already_claimed") {
                    Ok(AdminRestFaucetOutcome::AlreadyClaimed)
                } else if es.contains("admin_faucet_ip_rl") {
                    Ok(AdminRestFaucetOutcome::IpRateLimited)
                } else if es.contains("admin_faucet_pool_insufficient") {
                    Ok(AdminRestFaucetOutcome::PoolInsufficient)
                } else {
                    Err(LedgerError::Sled(e))
                }
            }
        }
    }

    /// Whether `wallet` holds a Genesis 1,000 slot (claimed program bonus — same meta key as claim).
    fn genesis_1k_participant(&self, wallet: &str) -> bool {
        let w = wallet.trim();
        if w.is_empty() {
            return false;
        }
        self.meta
            .get(genesis_1k_wallet_slot_meta_key(w))
            .ok()
            .flatten()
            .is_some()
    }

    #[cfg(test)]
    /// Marks a wallet as Genesis 1,000 for tests (meta key only; does not mint or bump filled count).
    pub fn test_only_mark_genesis_1k_participant(
        &self,
        wallet: &str,
        slot: u64,
    ) -> Result<(), LedgerError> {
        let w = wallet.trim();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        self.meta.insert(
            genesis_1k_wallet_slot_meta_key(w),
            self.encrypt_value(&u64_to_bytes(slot))?,
        )?;
        std::mem::drop(self.db.flush_async());
        Ok(())
    }

    #[allow(dead_code)]
    pub fn ai_daily_count(&self, wallet: &str, day: u64) -> Result<u64, LedgerError> {
        let k = format!("{wallet}:{day}");
        Ok(self
            .ai_quota
            .get(k.as_bytes())?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    pub fn ai_daily_inc(&self, wallet: &str, day: u64) -> Result<u64, LedgerError> {
        let k = format!("{wallet}:{day}");
        let cur = self
            .ai_quota
            .get(k.as_bytes())?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0);
        let next = cur.saturating_add(1);
        self.ai_quota
            .insert(k.as_bytes(), u64_to_bytes(next).to_vec())?;
        std::mem::drop(self.db.flush_async());
        Ok(next)
    }

    fn fee_bps_mint(&self) -> u64 {
        std::env::var("TET_PROTOCOL_FEE_BPS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(100)
            .min(10_000)
    }

    pub fn mint_reward_with_proof(
        &self,
        peer: &str,
        gross_micro: u64,
        energy_payload_bytes: &[u8],
        attestation: Option<&AttestationReport>,
        commit_genesis_1k_slot: bool,
    ) -> Result<(u64, u64, u64, u64), LedgerError> {
        if gross_micro == 0 {
            return Ok((0, 0, 0, 0));
        }
        if attestation_required() && attestation.is_none() {
            return Err(LedgerError::AttestationRequired);
        }
        let peer_trim = peer.trim();
        if commit_genesis_1k_slot && peer_trim.is_empty() {
            return Err(LedgerError::Invalid(
                "genesis 1k commit requires peer wallet".into(),
            ));
        }
        let fee_bps = self.fee_bps_mint();
        let fee_micro = gross_micro.saturating_mul(fee_bps) / 10_000;
        let net_micro = gross_micro.saturating_sub(fee_micro);
        let founder = self.founder_wallet()?;

        // Hash preimage is the payload bytes (includes energy/joules info upstream).
        let mut h = Sha256::new();
        h.update(energy_payload_bytes);
        if let Some(a) = attestation {
            h.update(a.platform.as_bytes());
            h.update(a.report_b64.as_bytes());
        }
        let hash = hex::encode(h.finalize());
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(energy_payload_bytes);

        let peer_key = peer_trim.as_bytes().to_vec();
        let founder_key = founder.as_bytes().to_vec();
        let genesis_1k_slot_key: Option<Vec<u8>> = if commit_genesis_1k_slot {
            Some(genesis_1k_wallet_slot_meta_key(peer_trim))
        } else {
            None
        };

        let res: Result<u64, TransactionError<sled::Error>> =
            (&self.meta, &self.balances, &self.proofs).transaction(|(m, b, p)| {
                if let Some(ref g1k_key) = genesis_1k_slot_key {
                    if m.get(g1k_key)?.is_some() {
                        return Err(ConflictableTransactionError::Abort(
                            sled::Error::Unsupported("genesis_1k_already_claimed".into()),
                        ));
                    }
                    let cur = m
                        .get(META_GENESIS_1K_FILLED)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    if cur >= GENESIS_1K_MAX {
                        return Err(ConflictableTransactionError::Abort(
                            sled::Error::Unsupported("genesis_1k_full".into()),
                        ));
                    }
                    let next_slot = cur.saturating_add(1);
                    m.insert(
                        META_GENESIS_1K_FILLED,
                        self.encrypt_value(&u64_to_bytes(next_slot))?,
                    )?;
                    m.insert(
                        g1k_key.clone(),
                        self.encrypt_value(&u64_to_bytes(next_slot))?,
                    )?;
                }

                let total = m
                    .get(META_TOTAL_SUPPLY)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                let (treasury_micro, burn_micro) =
                    Self::split_protocol_fee_treasury_and_burn(fee_micro);
                let new_total = total.saturating_add(gross_micro).saturating_sub(burn_micro);
                if new_total > MAX_SUPPLY_MICRO {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("MAX_SUPPLY exceeded".into()),
                    ));
                }

                let seq = m
                    .get(META_PROOF_SEQ)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                let proof_id = seq.saturating_add(1);
                m.insert(META_PROOF_SEQ, self.encrypt_value(&u64_to_bytes(proof_id))?)?;

                let record = serde_json::json!({
                    "id": proof_id,
                    "hash_sha256_hex": hash,
                    "payload_b64": payload_b64,
                });
                let rec_bytes = serde_json::to_vec(&record).map_err(|e| {
                    ConflictableTransactionError::Abort(sled::Error::Unsupported(e.to_string()))
                })?;
                p.insert(
                    u64_to_bytes(proof_id).to_vec(),
                    self.encrypt_value(&rec_bytes)?,
                )?;

                let cur_peer = b
                    .get(&peer_key)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    peer_key.clone(),
                    self.encrypt_value(&u64_to_bytes(cur_peer.saturating_add(net_micro)))?,
                )?;

                if fee_micro > 0 {
                    let cur_f = b
                        .get(&founder_key)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    b.insert(
                        founder_key.clone(),
                        self.encrypt_value(&u64_to_bytes(cur_f.saturating_add(treasury_micro)))?,
                    )?;
                    let fee_total = m
                        .get(META_FEE_TOTAL)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_FEE_TOTAL,
                        self.encrypt_value(&u64_to_bytes(
                            fee_total.saturating_add(treasury_micro),
                        ))?,
                    )?;
                    let burned_prev = m
                        .get(META_TOTAL_BURNED)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_TOTAL_BURNED,
                        self.encrypt_value(&u64_to_bytes(burned_prev.saturating_add(burn_micro)))?,
                    )?;
                }

                m.insert(
                    META_TOTAL_SUPPLY,
                    self.encrypt_value(&u64_to_bytes(new_total))?,
                )?;
                Ok(proof_id)
            });

        let proof_id = res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                let es = e.to_string();
                if es.contains("MAX_SUPPLY") {
                    LedgerError::HardCapExceeded
                } else if es.contains("genesis_1k_already_claimed") {
                    LedgerError::Invalid("genesis 1,000 bonus already claimed".into())
                } else if es.contains("genesis_1k_full") {
                    LedgerError::Invalid("genesis 1,000 program is full".into())
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;
        let (treasury_micro, burn_micro) = Self::split_protocol_fee_treasury_and_burn(fee_micro);
        let audit = serde_json::json!({
            "v": 1,
            "action": "mint",
            "to_wallet": peer_trim,
            "gross_micro": gross_micro,
            "net_micro": net_micro,
            "fee_micro": fee_micro,
            "treasury_fee_micro": treasury_micro,
            "burned_fee_micro": burn_micro,
            "proof_id": proof_id,
            "payload_sha256_hex": hash,
        });
        let bytes = serde_json::to_vec(&audit).unwrap_or_default();
        let _ = self.audit_write(&bytes);
        // Ensure dev faucet / mint is durable before subsequent transfers in the same run.
        // Sled writes can be async; a flush here prevents confusing "insufficient funds" in tight E2E loops.
        self.db.flush().map_err(LedgerError::Sled)?;
        self.persist_snapshot_best_effort();
        Ok((gross_micro, net_micro, fee_micro, proof_id))
    }

    /// Worker AI reward payout: debits **`system:worker_pool`** only (no supply inflation).
    /// Split: 99% `worker_net` (90-day vest to worker) / 1% imperial tax (unlocked to vault).
    pub fn mint_worker_network_reward(
        &self,
        worker_wallet: &str,
        imperial_vault_wallet: &str,
        gross_micro: u64,
        energy_payload_bytes: &[u8],
        attestation: Option<&AttestationReport>,
    ) -> Result<(u64, u64, u64, u64), LedgerError> {
        if gross_micro == 0 {
            return Ok((0, 0, 0, 0));
        }
        let gross_requested_micro = gross_micro;
        let genesis_1k_uplift_applied = self.genesis_1k_participant(worker_wallet);
        let gross_micro = if genesis_1k_uplift_applied {
            ((gross_micro as u128).saturating_mul(GENESIS_1K_WORKER_GROSS_NUM)
                / GENESIS_1K_WORKER_GROSS_DEN) as u64
        } else {
            gross_micro
        };
        if worker_wallet == imperial_vault_wallet {
            return Err(LedgerError::Invalid(
                "worker wallet must differ from imperial vault".into(),
            ));
        }
        if attestation_required() && attestation.is_none() {
            return Err(LedgerError::AttestationRequired);
        }
        let imperial_bps = 100u64;
        let imperial_tax = gross_micro.saturating_mul(imperial_bps) / 10_000;
        let worker_net = gross_micro.saturating_sub(imperial_tax);

        let mut h = Sha256::new();
        h.update(b"tet-worker-poc:v1");
        h.update(energy_payload_bytes);
        if let Some(a) = attestation {
            h.update(a.platform.as_bytes());
            h.update(a.report_b64.as_bytes());
        }
        let hash = hex::encode(h.finalize());
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(energy_payload_bytes);

        let w_key = worker_wallet.trim().as_bytes().to_vec();
        let i_key = imperial_vault_wallet.trim().as_bytes().to_vec();
        let pool_k = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();

        let now_ms = ledger_now_ms();
        let unlock_at_ms = now_ms.saturating_add(worker_reward_vest_duration_ms());

        let res: Result<u64, TransactionError<sled::Error>> =
            (&self.meta, &self.balances, &self.proofs, &self.vest_locks).transaction(
                |(m, b, p, vl)| {
                    let pool_bal = b
                        .get(&pool_k)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    if pool_bal < gross_micro {
                        return Err(ConflictableTransactionError::Abort(
                            sled::Error::Unsupported("insufficient_worker_pool".into()),
                        ));
                    }

                    let seq = m
                        .get(META_PROOF_SEQ)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    let proof_id = seq.saturating_add(1);
                    m.insert(META_PROOF_SEQ, self.encrypt_value(&u64_to_bytes(proof_id))?)?;

                    let record = serde_json::json!({
                        "id": proof_id,
                        "kind": "worker_poc",
                        "hash_sha256_hex": hash,
                        "payload_b64": payload_b64,
                    });
                    let rec_bytes = serde_json::to_vec(&record).map_err(|e| {
                        ConflictableTransactionError::Abort(sled::Error::Unsupported(e.to_string()))
                    })?;
                    p.insert(
                        u64_to_bytes(proof_id).to_vec(),
                        self.encrypt_value(&rec_bytes)?,
                    )?;

                    b.insert(
                        pool_k.clone(),
                        self.encrypt_value(&u64_to_bytes(pool_bal.saturating_sub(gross_micro)))?,
                    )?;

                    let cur_w = b
                        .get(&w_key)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    b.insert(
                        w_key.clone(),
                        self.encrypt_value(&u64_to_bytes(cur_w.saturating_add(worker_net)))?,
                    )?;

                    if imperial_tax > 0 {
                        let cur_i = b
                            .get(&i_key)?
                            .as_deref()
                            .map(|v| self.decrypt_value(v))
                            .transpose()?
                            .as_deref()
                            .map(bytes_to_u64)
                            .unwrap_or(0);
                        b.insert(
                            i_key.clone(),
                            self.encrypt_value(&u64_to_bytes(cur_i.saturating_add(imperial_tax)))?,
                        )?;
                    }

                    let comm = m
                        .get(META_WORKER_COMMUNITY_MICRO)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_WORKER_COMMUNITY_MICRO,
                        self.encrypt_value(&u64_to_bytes(comm.saturating_add(worker_net)))?,
                    )?;

                    let vest_id = m
                        .get(META_NEXT_VEST_SEQ)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0)
                        .saturating_add(1);
                    m.insert(
                        META_NEXT_VEST_SEQ,
                        self.encrypt_value(&u64_to_bytes(vest_id))?,
                    )?;

                    let mut vk = Vec::with_capacity(4 + 8);
                    vk.extend_from_slice(b"vl1\x00");
                    vk.extend_from_slice(&vest_id.to_le_bytes());
                    let vest = VestLockV1 {
                        v: 1,
                        wallet: worker_wallet.trim().to_string(),
                        amount_micro: worker_net,
                        unlock_at_ms,
                    };
                    let vest_bytes = serde_json::to_vec(&vest).map_err(|e| {
                        ConflictableTransactionError::Abort(sled::Error::Unsupported(e.to_string()))
                    })?;
                    vl.insert(vk, self.encrypt_value(&vest_bytes)?)?;

                    Ok(proof_id)
                },
            );

        let proof_id = res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient_worker_pool") {
                    LedgerError::InsufficientFunds
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;
        let audit = serde_json::json!({
            "v": 1,
            "action": "worker_pool_payout_vest",
            "worker_wallet": worker_wallet,
            "imperial_vault": imperial_vault_wallet,
            "pool_wallet": WALLET_SYSTEM_WORKER_POOL,
            "gross_micro_requested": gross_requested_micro,
            "genesis_1k_worker_uplift_10pct": genesis_1k_uplift_applied,
            "gross_micro": gross_micro,
            "worker_net_micro": worker_net,
            "imperial_tax_micro": imperial_tax,
            "vest_unlock_at_ms": unlock_at_ms,
            "proof_id": proof_id,
            "payload_sha256_hex": hash,
        });
        let bytes = serde_json::to_vec(&audit).unwrap_or_default();
        let _ = self.audit_write(&bytes);
        self.persist_snapshot_best_effort();
        Ok((gross_micro, worker_net, imperial_tax, proof_id))
    }

    /// AI utility settlement: user pays `gross_micro` and the protocol routes value deterministically.
    ///
    /// - **80%** → `worker_wallet`
    /// - **20%** → network fee
    ///   - burn **25% of network fee** (i.e. **5% of total**) → reduces total supply + increases burned
    ///   - remaining **75% of network fee** (i.e. **15% of total**) → `dex:treasury`
    ///
    /// This path is atomic and does **not** use `transfer_with_fee_*` to avoid stacking protocol fees
    /// on top of the explicit DePIN split.
    pub fn settle_ai_utility_payment(
        &self,
        payer_wallet: &str,
        worker_wallet: &str,
        gross_micro: u64,
        burn_wallet: &str,
    ) -> Result<(u64, u64, u64), LedgerError> {
        let payer = payer_wallet.trim();
        let worker = worker_wallet.trim();
        let burn = burn_wallet.trim();
        if payer.is_empty() || worker.is_empty() || burn.is_empty() {
            return Err(LedgerError::Invalid("wallet ids required".into()));
        }
        if gross_micro == 0 || gross_micro > MAX_SUPPLY_MICRO {
            return Err(LedgerError::Invalid("invalid gross amount".into()));
        }
        if payer == worker {
            return Err(LedgerError::Invalid("payer and worker must differ".into()));
        }

        let fee_bps = NETWORK_FEE_BPS;
        let fee_micro = gross_micro.saturating_mul(fee_bps) / 10_000;
        let worker_micro = gross_micro.saturating_sub(fee_micro);
        // Burn 25% of network fee (5% of total).
        let burn_micro = fee_micro.saturating_mul(BURN_FRACTION_OF_NETWORK_FEE_BPS) / 10_000;
        let treasury_micro = fee_micro.saturating_sub(burn_micro);

        let payer_k = payer.as_bytes().to_vec();
        let worker_k = worker.as_bytes().to_vec();
        let burn_k = burn.as_bytes().to_vec();
        let treasury_k = WALLET_DEX_TREASURY.as_bytes().to_vec();

        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                let total = m
                    .get(META_TOTAL_SUPPLY)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);

                // Ensure payer has enough (spendable checks happen at a higher layer; this is the raw ledger balance).
                let payer_cur = b
                    .get(&payer_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if payer_cur < gross_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("insufficient_funds".into()),
                    ));
                }

                // Debit payer.
                b.insert(
                    payer_k.clone(),
                    self.encrypt_value(&u64_to_bytes(payer_cur.saturating_sub(gross_micro)))?,
                )?;

                // Credit worker (80%).
                let w_cur = b
                    .get(&worker_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    worker_k.clone(),
                    self.encrypt_value(&u64_to_bytes(w_cur.saturating_add(worker_micro)))?,
                )?;

                // Credit treasury (15%).
                if treasury_micro > 0 {
                    let t_cur = b
                        .get(&treasury_k)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    b.insert(
                        treasury_k.clone(),
                        self.encrypt_value(&u64_to_bytes(t_cur.saturating_add(treasury_micro)))?,
                    )?;

                    // Track founder revenue into fee_total as well (useful aggregate).
                    let fee_total = m
                        .get(META_FEE_TOTAL)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_FEE_TOTAL,
                        self.encrypt_value(&u64_to_bytes(
                            fee_total.saturating_add(treasury_micro),
                        ))?,
                    )?;
                }

                // Burn (5%): credit burn wallet (optional sink accounting) and reduce total supply.
                if burn_micro > 0 {
                    let b_cur = b
                        .get(&burn_k)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    b.insert(
                        burn_k.clone(),
                        self.encrypt_value(&u64_to_bytes(b_cur.saturating_add(burn_micro)))?,
                    )?;

                    let burned_prev = m
                        .get(META_TOTAL_BURNED)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_TOTAL_BURNED,
                        self.encrypt_value(&u64_to_bytes(burned_prev.saturating_add(burn_micro)))?,
                    )?;

                    m.insert(
                        META_TOTAL_SUPPLY,
                        self.encrypt_value(&u64_to_bytes(total.saturating_sub(burn_micro)))?,
                    )?;
                }
                Ok(())
            });

        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient_funds") {
                    LedgerError::InsufficientFunds
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;

        let audit = serde_json::json!({
            "v": 1,
            "action": "ai_utility_settlement_v1",
            "payer_wallet": payer,
            "worker_wallet": worker,
            "treasury_wallet": WALLET_DEX_TREASURY,
            "burn_wallet": burn,
            "gross_micro": gross_micro,
            "worker_micro": worker_micro,
            "network_fee_micro": fee_micro,
            "treasury_micro": treasury_micro,
            "burn_micro": burn_micro,
            "network_fee_bps": fee_bps,
            "burn_fraction_of_network_fee_bps": BURN_FRACTION_OF_NETWORK_FEE_BPS,
        });
        let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
        self.persist_snapshot_best_effort();
        Ok((worker_micro, treasury_micro, burn_micro))
    }

    /// Phase 1 AI inference settlement: debit `payer_wallet`; route **50%** to the worker reward pool and **50%** to burn.
    ///
    /// Burn path mirrors [`Ledger::settle_ai_utility_payment`]: credit burn sink for accounting, bump [`META_TOTAL_BURNED`],
    /// reduce [`META_TOTAL_SUPPLY`].
    pub fn settle_ai_inference_dynamic_charge(
        &self,
        payer_wallet: &str,
        cost_micro: u64,
    ) -> Result<(u64, u64, String, u64), LedgerError> {
        let payer = payer_wallet.trim();
        if payer.is_empty() {
            return Err(LedgerError::Invalid("payer wallet required".into()));
        }
        if cost_micro == 0 || cost_micro > MAX_SUPPLY_MICRO {
            return Err(LedgerError::Invalid("invalid inference cost".into()));
        }

        let height_at = self.inference_block_height();
        let base_pool = cost_micro / 2;
        let pool_half = if height_at < GENESIS_EPOCH_BLOCK_LIMIT {
            base_pool
                .saturating_mul(GENESIS_REWARD_MULTIPLIER)
                .min(cost_micro)
        } else {
            base_pool
        };
        let burn_half = cost_micro.saturating_sub(pool_half);
        let pool_k = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();
        let burn_wallet = self.ai_burn_wallet();
        let burn_k = burn_wallet.as_bytes().to_vec();
        let payer_k = payer.as_bytes().to_vec();

        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                let payer_cur = b
                    .get(&payer_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                if payer_cur < cost_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("insufficient_funds".into()),
                    ));
                }

                b.insert(
                    payer_k.clone(),
                    self.encrypt_value(&u64_to_bytes(payer_cur.saturating_sub(cost_micro)))?,
                )?;

                let pool_cur = b
                    .get(&pool_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    pool_k.clone(),
                    self.encrypt_value(&u64_to_bytes(pool_cur.saturating_add(pool_half)))?,
                )?;

                let total = m
                    .get(META_TOTAL_SUPPLY)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);

                if burn_half > 0 {
                    let b_cur = b
                        .get(&burn_k)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    b.insert(
                        burn_k.clone(),
                        self.encrypt_value(&u64_to_bytes(b_cur.saturating_add(burn_half)))?,
                    )?;

                    let burned_prev = m
                        .get(META_TOTAL_BURNED)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_TOTAL_BURNED,
                        self.encrypt_value(&u64_to_bytes(burned_prev.saturating_add(burn_half)))?,
                    )?;

                    m.insert(
                        META_TOTAL_SUPPLY,
                        self.encrypt_value(&u64_to_bytes(total.saturating_sub(burn_half)))?,
                    )?;
                }

                let wb_k = Self::wallet_infer_burn_meta_key(payer);
                let prev_infer_burn = m
                    .get(&wb_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    wb_k,
                    self.encrypt_value(&u64_to_bytes(prev_infer_burn.saturating_add(burn_half)))?,
                )?;

                let next_infer_h = height_at.saturating_add(1);
                m.insert(
                    META_INFERENCE_BLOCK_HEIGHT,
                    self.encrypt_value(&u64_to_bytes(next_infer_h))?,
                )?;
                let wall_now = u64::try_from(ledger_now_ms()).unwrap_or(u64::MAX);
                m.insert(
                    META_INFER_CONSENSUS_LAST_MS,
                    self.encrypt_value(&u64_to_bytes(wall_now))?,
                )?;

                Ok(())
            });

        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient_funds") {
                    LedgerError::InsufficientFunds
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;

        let audit = serde_json::json!({
            "v": 1,
            "action": "ai_inference_dynamic_charge_v1",
            "payer_wallet": payer,
            "cost_micro": cost_micro,
            "worker_pool_wallet": WALLET_SYSTEM_WORKER_POOL,
            "pool_credit_micro": pool_half,
            "burn_wallet": burn_wallet,
            "burn_micro": burn_half,
            "inference_block_height_before": height_at,
            "genesis_boost_active": height_at < GENESIS_EPOCH_BLOCK_LIMIT,
        });
        let (audit_hash, audit_seq) =
            self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default())?;
        self.persist_snapshot_best_effort();
        Ok((pool_half, burn_half, audit_hash, audit_seq))
    }

    /// Append one local inference session after settlement (same `audit_seq` as the charge row).
    pub fn append_ai_infer_session(
        &self,
        payer_wallet: &str,
        prompt: &str,
        response: &str,
        cost_micro: u64,
        ledger_audit_hash_hex: &str,
        ledger_audit_seq: u64,
    ) -> Result<(), LedgerError> {
        let w = payer_wallet.trim().to_ascii_lowercase();
        if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(LedgerError::Invalid(
                "payer wallet must be 64 hex chars".into(),
            ));
        }
        let ts_ms = u64::try_from(ledger_now_ms()).unwrap_or(u64::MAX);
        let row = AiInferHistoryRowV1 {
            v: 1,
            payer_wallet: w.clone(),
            prompt: truncate_utf8_bytes(prompt, AI_INFER_HISTORY_TEXT_MAX_BYTES),
            response: truncate_utf8_bytes(response, AI_INFER_HISTORY_TEXT_MAX_BYTES),
            cost_micro,
            ledger_audit_hash_hex: ledger_audit_hash_hex.trim().to_string(),
            ledger_audit_seq,
            ts_ms,
        };
        let key = format!("{w}:{ledger_audit_seq:020}").into_bytes();
        let bytes = serde_json::to_vec(&row).map_err(|e| LedgerError::Invalid(e.to_string()))?;
        let enc = self.encrypt_value(&bytes)?;
        self.ai_infer_sessions.insert(key, enc)?;
        std::mem::drop(self.db.flush_async());
        Ok(())
    }

    /// Recent local AI inference sessions for a wallet (newest `ledger_audit_seq` first).
    pub fn ai_infer_history_for_wallet(
        &self,
        wallet: &str,
        limit: usize,
    ) -> Result<Vec<AiInferHistoryRowV1>, LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(LedgerError::Invalid("wallet must be 64 hex chars".into()));
        }
        let prefix = format!("{w}:");
        let mut rows: Vec<AiInferHistoryRowV1> = Vec::new();
        for item in self.ai_infer_sessions.scan_prefix(prefix.as_bytes()) {
            let (_k, enc_v) = item.map_err(LedgerError::Sled)?;
            let pt = self.decrypt_value(enc_v.as_ref())?;
            if let Ok(row) = serde_json::from_slice::<AiInferHistoryRowV1>(&pt) {
                rows.push(row);
            }
        }
        rows.sort_by(|a, b| b.ledger_audit_seq.cmp(&a.ledger_audit_seq));
        rows.truncate(limit);
        Ok(rows)
    }

    pub fn worker_community_mint_micro_total(&self) -> Result<u64, LedgerError> {
        Ok(self
            .meta
            .get(META_WORKER_COMMUNITY_MICRO)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    pub fn chf_deposits_micro_total(&self) -> Result<u64, LedgerError> {
        Ok(self
            .meta
            .get(META_CHF_DEPOSITS_MICRO)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    pub fn fiat_mint_stevemon_micro_total(&self) -> Result<u64, LedgerError> {
        Ok(self
            .meta
            .get(META_FIAT_MINT_STEVEMON_MICRO)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0))
    }

    /// Swiss CHF top-up (Stripe placeholder): `chf_amount_micro` = millionths CHF; 1 CHF = 1 TET peg.
    pub fn mint_fiat_chf_topup(
        &self,
        wallet: &str,
        chf_amount_micro: u64,
        payment_ref: &str,
    ) -> Result<u64, LedgerError> {
        if chf_amount_micro == 0 {
            return Err(LedgerError::Invalid("zero CHF amount".into()));
        }
        // AML circuit breaker: max 1,000 CHF per wallet per 24h.
        let day = day_since_epoch();
        let mut aml_k = META_AML_CHF_PREFIX.to_vec();
        aml_k.extend_from_slice(wallet.trim().as_bytes());
        aml_k.extend_from_slice(b":");
        aml_k.extend_from_slice(day.to_string().as_bytes());
        let cur_aml = self
            .meta
            .get(&aml_k)?
            .as_deref()
            .map(bytes_to_u64)
            .unwrap_or(0);
        let next_aml = cur_aml.saturating_add(chf_amount_micro);
        let limit = 1_000u64 * 1_000_000u64;
        if next_aml > limit {
            return Err(LedgerError::Invalid("AML Limit Exceeded".into()));
        }
        let stevemon_micro_u128 =
            (chf_amount_micro as u128).saturating_mul(STEVEMON as u128) / 1_000_000u128;
        let stevemon_micro = u64::try_from(stevemon_micro_u128)
            .map_err(|_| LedgerError::Invalid("mint overflow".into()))?;
        if stevemon_micro == 0 {
            return Err(LedgerError::Invalid("mint too small".into()));
        }
        let payload = format!("fiat_chf|{payment_ref}|{chf_amount_micro}");
        let mut h = Sha256::new();
        h.update(payload.as_bytes());
        let hash = hex::encode(h.finalize());

        let peer_key = wallet.as_bytes().to_vec();

        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                let total = m
                    .get(META_TOTAL_SUPPLY)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                let new_total = total.saturating_add(stevemon_micro);
                if new_total > MAX_SUPPLY_MICRO {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("MAX_SUPPLY exceeded".into()),
                    ));
                }

                let cur = b
                    .get(&peer_key)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    peer_key.clone(),
                    self.encrypt_value(&u64_to_bytes(cur.saturating_add(stevemon_micro)))?,
                )?;

                let chf_prev = m
                    .get(META_CHF_DEPOSITS_MICRO)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    META_CHF_DEPOSITS_MICRO,
                    self.encrypt_value(&u64_to_bytes(chf_prev.saturating_add(chf_amount_micro)))?,
                )?;

                let fiat_prev = m
                    .get(META_FIAT_MINT_STEVEMON_MICRO)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    META_FIAT_MINT_STEVEMON_MICRO,
                    self.encrypt_value(&u64_to_bytes(fiat_prev.saturating_add(stevemon_micro)))?,
                )?;
                m.insert(aml_k.clone(), self.encrypt_value(&u64_to_bytes(next_aml))?)?;

                m.insert(
                    META_TOTAL_SUPPLY,
                    self.encrypt_value(&u64_to_bytes(new_total))?,
                )?;
                Ok(())
            });

        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("MAX_SUPPLY") {
                    LedgerError::HardCapExceeded
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;

        let audit = serde_json::json!({
            "v": 1,
            "action": "fiat_chf_topup",
            "wallet": wallet,
            "chf_amount_micro": chf_amount_micro,
            "stevemon_micro": stevemon_micro,
            "payment_ref": payment_ref,
            "payload_sha256_hex": hash,
        });
        let bytes = serde_json::to_vec(&audit).unwrap_or_default();
        let _ = self.audit_write(&bytes);
        self.persist_snapshot_best_effort();
        Ok(stevemon_micro)
    }

    #[allow(dead_code)]
    pub fn transfer_with_fee(
        &self,
        from: &str,
        to: &str,
        amount_micro: u64,
        fee_bps: Option<u64>,
    ) -> Result<(u64, u64), LedgerError> {
        // Military-grade SEND gating: if attestation is required, this path is not allowed.
        if attestation_required() {
            return Err(LedgerError::AttestationRequired);
        }
        self.transfer_with_fee_attested(from, to, amount_micro, fee_bps, None, None)
    }

    /// Fee-less transfer (Phase 1.1.1): move `amount_micro` from `from` to `to` with **no founder fee**.
    ///
    /// This is intentionally narrow: it preserves spendable/locked and pre-sale lock checks,
    /// but does not require a founder wallet to be configured.
    pub fn transfer_no_fee(
        &self,
        from: &str,
        to: &str,
        amount_micro: u64,
    ) -> Result<u64, LedgerError> {
        if from == to || amount_micro == 0 {
            return Ok(0);
        }
        if amount_micro > MAX_SUPPLY_MICRO {
            return Err(LedgerError::Invalid("amount exceeds hard cap".into()));
        }
        if attestation_required() {
            return Err(LedgerError::AttestationRequired);
        }

        let from_k = from.as_bytes().to_vec();
        let to_k = to.as_bytes().to_vec();

        let now_ms = ledger_now_ms();
        let locked_sum = self.locked_balance_micro(from, now_ms)?;
        let locked_until = self.presale_locked_until_ms(from).unwrap_or(0);
        if locked_until > 0 && now_ms < locked_until {
            let burn = self.ai_burn_wallet();
            if to.trim().to_ascii_lowercase() != burn {
                return Err(LedgerError::Invalid(
                    "wallet is locked (pre-sale vest). Transfers are restricted until unlock; burn-only is allowed."
                        .into(),
                ));
            }
        }

        let presale_lock_ms = self.presale_lock_duration_ms();
        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances).transaction(|(m, b)| {
            let fb = b
                .get(&from_k)?
                .as_deref()
                .map(|v| self.decrypt_value(v))
                .transpose()?
                .as_deref()
                .map(bytes_to_u64)
                .unwrap_or(0);
            let spendable = fb.saturating_sub(locked_sum);
            log::debug!(
                "[ledger] Attempting transfer: {} micro-TET from={} to={} sender_balance={} locked_sum={} spendable={}",
                amount_micro,
                from,
                to,
                fb,
                locked_sum,
                spendable
            );
            if spendable < amount_micro {
                return Err(ConflictableTransactionError::Abort(
                    sled::Error::Unsupported("insufficient funds".into()),
                ));
            }
            let tb = b
                .get(&to_k)?
                .as_deref()
                .map(|v| self.decrypt_value(v))
                .transpose()?
                .as_deref()
                .map(bytes_to_u64)
                .unwrap_or(0);

            b.insert(
                from_k.clone(),
                self.encrypt_value(&u64_to_bytes(fb - amount_micro))?,
            )?;
            b.insert(
                to_k.clone(),
                self.encrypt_value(&u64_to_bytes(tb.saturating_add(amount_micro)))?,
            )?;

            // If this is a pre-sale allocation from the DEX treasury, mark recipient as locked.
            if presale_lock_ms > 0 && from.trim().to_ascii_lowercase() == WALLET_DEX_TREASURY {
                let unlock_at = now_ms.saturating_add(presale_lock_ms);
                self.set_presale_locked_until_ms_txn(m, to, unlock_at)?;
            }
            Ok(())
        });

        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient") {
                    LedgerError::InsufficientFunds
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;

        // Make the transfer durable immediately for E2E determinism.
        self.db.flush().map_err(LedgerError::Sled)?;
        self.persist_snapshot_best_effort();
        Ok(amount_micro)
    }

    /// Ed25519 + ML-DSA over the canonical hybrid transfer string — both must pass (AND).
    pub fn verify_dual_transfer_auth(
        from_wallet_hex: &str,
        to_wallet: &str,
        amount_micro: u64,
        nonce: u64,
        ed25519_sig_hex: &str,
        mldsa_pubkey_b64: &str,
        mldsa_sig_b64: &str,
    ) -> Result<(), LedgerError> {
        crate::wallet::verify_dual_signed_transfer(
            from_wallet_hex,
            to_wallet,
            amount_micro,
            nonce,
            ed25519_sig_hex,
            mldsa_pubkey_b64,
            mldsa_sig_b64,
        )
        .map_err(LedgerError::HybridSigRejected)
    }

    /// [`Self::transfer_with_fee_attested`] after mandatory hybrid verification (wallet HTTP path).
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_with_fee_attested_dual_verified(
        &self,
        from: &str,
        to: &str,
        amount_micro: u64,
        fee_bps: Option<u64>,
        attestation: Option<&AttestationReport>,
        signed_transfer_nonce: Option<u64>,
        ed25519_sig_hex: &str,
        mldsa_pubkey_b64: &str,
        mldsa_sig_b64: &str,
    ) -> Result<(u64, u64), LedgerError> {
        let nonce = signed_transfer_nonce
            .ok_or_else(|| LedgerError::Invalid("signed transfer requires nonce".into()))?;
        if nonce == 0 {
            return Err(LedgerError::Invalid(
                "nonce must be greater than last committed nonce".into(),
            ));
        }
        Self::verify_dual_transfer_auth(
            from,
            to,
            amount_micro,
            nonce,
            ed25519_sig_hex,
            mldsa_pubkey_b64,
            mldsa_sig_b64,
        )?;
        self.transfer_with_fee_attested(
            from,
            to,
            amount_micro,
            fee_bps,
            attestation,
            signed_transfer_nonce,
        )
    }

    pub fn transfer_with_fee_attested(
        &self,
        from: &str,
        to: &str,
        amount_micro: u64,
        fee_bps: Option<u64>,
        attestation: Option<&AttestationReport>,
        signed_transfer_nonce: Option<u64>,
    ) -> Result<(u64, u64), LedgerError> {
        if from == to || amount_micro == 0 {
            return Ok((0, 0));
        }
        if amount_micro > MAX_SUPPLY_MICRO {
            return Err(LedgerError::Invalid("amount exceeds hard cap".into()));
        }
        if attestation_required() && attestation.is_none() {
            return Err(LedgerError::AttestationRequired);
        }
        let _ = fee_bps;
        let bps = PROTOCOL_MAINTENANCE_FEE_BPS; // strict: 1% on all transfers
        let fee_micro = amount_micro.saturating_mul(bps) / 10_000;
        let net_micro = amount_micro.saturating_sub(fee_micro);
        let fee_pool_half = fee_micro / 2;
        let fee_burn_half = fee_micro.saturating_sub(fee_pool_half);

        let from_k = from.as_bytes().to_vec();
        let to_k = to.as_bytes().to_vec();
        let pool_k = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();
        let burn_wallet = self.ai_burn_wallet();
        let burn_k = burn_wallet.as_bytes().to_vec();

        let now_ms = ledger_now_ms();
        // `TransactionalTree` has no `.iter()` — read vest locks on the real tree before txn.
        let locked_sum = self.locked_balance_micro(from, now_ms)?;
        // Pre-sale transfer lock: allow burn-only while locked (spend but not sell).
        let locked_until = self.presale_locked_until_ms(from).unwrap_or(0);
        if locked_until > 0 && now_ms < locked_until {
            let burn = self.ai_burn_wallet();
            if to.trim().to_ascii_lowercase() != burn {
                return Err(LedgerError::Invalid(
                    "wallet is locked (pre-sale vest). Transfers are restricted until unlock; burn-only is allowed."
                        .into(),
                ));
            }
        }

        let nonce_key = Self::wallet_nonce_meta_key(from);
        let presale_lock_ms = self.presale_lock_duration_ms();
        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances)
            .transaction(|(m, b)| {
                if let Some(req_n) = signed_transfer_nonce {
                    let cur = m
                        .get(&nonce_key)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    if req_n <= cur {
                        return Err(ConflictableTransactionError::Abort(
                            sled::Error::Unsupported("stale_nonce".into()),
                        ));
                    }
                }
                let fb = b
                    .get(&from_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                let spendable = fb.saturating_sub(locked_sum);
                if spendable < amount_micro {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("insufficient funds".into()),
                    ));
                }
                let tb = b
                    .get(&to_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    from_k.clone(),
                    self.encrypt_value(&u64_to_bytes(fb - amount_micro))?,
                )?;
                b.insert(
                    to_k.clone(),
                    self.encrypt_value(&u64_to_bytes(tb.saturating_add(net_micro)))?,
                )?;
                // If this is a pre-sale allocation from the DEX treasury, mark recipient as locked.
                if presale_lock_ms > 0 && from.trim().to_ascii_lowercase() == WALLET_DEX_TREASURY {
                    let unlock_at = now_ms.saturating_add(presale_lock_ms);
                    self.set_presale_locked_until_ms_txn(m, to, unlock_at)?;
                }
                if fee_micro > 0 {
                    let pool_cur = b
                        .get(&pool_k)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    b.insert(
                        pool_k.clone(),
                        self.encrypt_value(&u64_to_bytes(pool_cur.saturating_add(fee_pool_half)))?,
                    )?;

                    if fee_burn_half > 0 {
                        let sink_cur = b
                            .get(&burn_k)?
                            .as_deref()
                            .map(|v| self.decrypt_value(v))
                            .transpose()?
                            .as_deref()
                            .map(bytes_to_u64)
                            .unwrap_or(0);
                        b.insert(
                            burn_k.clone(),
                            self.encrypt_value(&u64_to_bytes(
                                sink_cur.saturating_add(fee_burn_half),
                            ))?,
                        )?;

                        let burned_prev = m
                            .get(META_TOTAL_BURNED)?
                            .as_deref()
                            .map(|v| self.decrypt_value(v))
                            .transpose()?
                            .as_deref()
                            .map(bytes_to_u64)
                            .unwrap_or(0);
                        m.insert(
                            META_TOTAL_BURNED,
                            self.encrypt_value(&u64_to_bytes(
                                burned_prev.saturating_add(fee_burn_half),
                            ))?,
                        )?;

                        let supply = m
                            .get(META_TOTAL_SUPPLY)?
                            .as_deref()
                            .map(|v| self.decrypt_value(v))
                            .transpose()?
                            .as_deref()
                            .map(bytes_to_u64)
                            .unwrap_or(0);
                        m.insert(
                            META_TOTAL_SUPPLY,
                            self.encrypt_value(&u64_to_bytes(
                                supply.saturating_sub(fee_burn_half),
                            ))?,
                        )?;
                    }

                    let fee_total = m
                        .get(META_FEE_TOTAL)?
                        .as_deref()
                        .map(|v| self.decrypt_value(v))
                        .transpose()?
                        .as_deref()
                        .map(bytes_to_u64)
                        .unwrap_or(0);
                    m.insert(
                        META_FEE_TOTAL,
                        self.encrypt_value(&u64_to_bytes(fee_total.saturating_add(fee_micro)))?,
                    )?;
                }
                if let Some(req_n) = signed_transfer_nonce {
                    m.insert(nonce_key.clone(), self.encrypt_value(&u64_to_bytes(req_n))?)?;
                }
                Ok(())
            });
        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient") {
                    LedgerError::InsufficientFunds
                } else if e.to_string().contains("stale_nonce") {
                    LedgerError::Invalid("stale or replay nonce".into())
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;
        let audit = serde_json::json!({
            "v": 1,
            "ts_ms": ledger_now_ms(),
            "action": "transfer",
            "from_wallet": from,
            "to_wallet": to,
            "amount_micro": amount_micro,
            "net_micro": net_micro,
            "fee_micro": fee_micro,
            "fee_to_worker_pool_micro": fee_pool_half,
            "fee_burned_micro": fee_burn_half,
            "fee_bps": bps,
        });
        let bytes = serde_json::to_vec(&audit).unwrap_or_default();
        let _ = self.audit_write(&bytes);
        self.persist_snapshot_best_effort();
        Ok((net_micro, fee_micro))
    }

    pub fn get_proof(&self, id: u64) -> Result<EnergyProofRecord, LedgerError> {
        let Some(v) = self.proofs.get(u64_to_bytes(id))? else {
            return Err(LedgerError::Invalid("proof not found".into()));
        };
        let pt = self.decrypt_value(v.as_ref())?;
        let val: serde_json::Value =
            serde_json::from_slice(&pt).map_err(|e| LedgerError::Invalid(e.to_string()))?;
        let hash = val
            .get("hash_sha256_hex")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let payload_b64 = val
            .get("payload_b64")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let payload = base64::engine::general_purpose::STANDARD
            .decode(payload_b64.as_bytes())
            .unwrap_or_default();
        let mut h = Sha256::new();
        h.update(&payload);
        let ok = !hash.is_empty() && hex::encode(h.finalize()) == hash;
        Ok(EnergyProofRecord {
            id,
            hash_sha256_hex: hash,
            payload_b64,
            verified: ok,
        })
    }

    pub fn list_proofs(
        &self,
        limit: usize,
        before: Option<u64>,
    ) -> Result<Vec<EnergyProofRecord>, LedgerError> {
        let cap = limit.clamp(1, 1000);
        let mut out = Vec::new();
        let mut cur = before.unwrap_or(u64::MAX).saturating_sub(1);
        while out.len() < cap && cur > 0 {
            if let Ok(p) = self.get_proof(cur) {
                out.push(p);
            }
            cur = cur.saturating_sub(1);
        }
        Ok(out)
    }
}
