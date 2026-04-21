use crate::attestation::{AttestationReport, attestation_required};
use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};
use sled::transaction::{ConflictableTransactionError, TransactionError, Transactional, TransactionalTree};
use zeroize::{Zeroize as _, ZeroizeOnDrop};

/// Smallest unit: 1 TET = 100,000,000 stevemon (8 decimals).
pub const STEVEMON: u64 = 100_000_000;
pub const MAX_SUPPLY_MICRO: u64 = 10_000_000_000u64 * STEVEMON;

/// Whitepaper-aligned genesis mint to Founder (Strategic Treasury custody): 2,000,000,000 TET (20% of 10B cap).
pub const GENESIS_FOUNDER_SHARE_MICRO: u64 = 2_000_000_000u64 * STEVEMON;
/// DEX liquidity treasury at genesis (disabled in founder-only genesis mode).
pub const GENESIS_DEX_TREASURY_MICRO: u64 = 0;
/// Worker compute incentive pool at genesis for 1,000 Genesis Workers × 100,000 TET = 100,000,000 TET.
pub const GENESIS_WORKER_POOL_SHARE_MICRO: u64 = 100_000_000u64 * STEVEMON;

/// Total minted supply at genesis (subset of the hard cap).
pub const GENESIS_TOTAL_MINT_MICRO: u64 =
    GENESIS_FOUNDER_SHARE_MICRO + GENESIS_DEX_TREASURY_MICRO + GENESIS_WORKER_POOL_SHARE_MICRO;

/// Genesis Worker grant: 100,000 TET × 1,000 nodes = 100,000,000 TET (funded from `system:worker_pool` at genesis).
pub const GENESIS_GUARDIANS_TOTAL: u64 = 10_000;
pub const GENESIS_GUARDIAN_GRANT_MICRO: u64 = 10_000u64 * STEVEMON;

pub const WALLET_DEX_TREASURY: &str = "dex:treasury";
pub const WALLET_SYSTEM_WORKER_POOL: &str = "system:worker_pool";
/// AI compute sink wallet. When pre-sale lock is active, transfers are only allowed to this destination.
pub const WALLET_AI_BURN_DEFAULT: &str = "tet-api-pool";
/// Worker minimum stake (5,000 TET) in micro-units.
pub const WORKER_MIN_STAKE_MICRO: u64 = 5_000u64 * STEVEMON;

/// --- DePIN economics (AI utility) ---
/// Worker must have at least this much stake to process AI tasks.
pub const MIN_STAKE_AMOUNT_MICRO: u64 = WORKER_MIN_STAKE_MICRO;
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
const META_DB_MAGIC: &[u8] = b"db_magic_v1";
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
/// Last committed transfer nonce per wallet (replay protection for signed HTTP transfers).
const META_WALLET_NONCE_PREFIX: &[u8] = b"wallet_nonce_v1:";
/// Per-wallet staked balance (micro-units) — economic security layer.
const META_WALLET_STAKE_PREFIX: &[u8] = b"wallet_stake_v1:";
/// Per-wallet pre-sale lock expiry (ms since epoch). If now < locked_until, wallet is transfer-locked except burn sink.
const META_WALLET_PRESALE_LOCK_UNTIL_PREFIX: &[u8] = b"wallet_presale_lock_until_ms_v1:";
const GENESIS_1K_MAX: u64 = 1_000;
/// Gross bonus amount (mint) for Genesis 1,000 claims — 10,000 TET airdrop (display-only UX must match).
pub const GENESIS_1K_BONUS_TET: u64 = 10_000;
/// Worker-pool gross uplift for Genesis 1,000 participants: standard reward × 1.10 (floor, integer math).
const GENESIS_1K_WORKER_GROSS_NUM: u128 = 11;
const GENESIS_1K_WORKER_GROSS_DEN: u128 = 10;

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
    founding: sled::Tree,
    ai_quota: sled::Tree,
    /// Worker AI reward vesting rows (90-day lock by default).
    vest_locks: sled::Tree,
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
            || self.founder_wallet_public().unwrap_or_default().trim().to_ascii_lowercase() == w
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
                    self.encrypt_value(&u64_to_bytes(pool_cur.saturating_sub(GENESIS_GUARDIAN_GRANT_MICRO)))?,
                )?;
                b.insert(
                    w_k.clone(),
                    self.encrypt_value(&u64_to_bytes(w_cur.saturating_add(GENESIS_GUARDIAN_GRANT_MICRO)))?,
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
    pub fn withdraw_treasury_to_founder(&self, amount_micro: u64, nonce: u64) -> Result<(), LedgerError> {
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
        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances).transaction(|(m, b)| {
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
                m.insert(
                    nonce_key.clone(),
                    self.encrypt_value(&u64_to_bytes(req_n))?,
                )?;
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

    /// Slash: remove micro-units from staked balance and burn them from total supply.
    pub fn slash_stake_micro(&self, wallet: &str, amount_micro: u64) -> Result<(u64, u64), LedgerError> {
        let w = wallet.trim().to_ascii_lowercase();
        if w.is_empty() {
            return Err(LedgerError::Invalid("wallet required".into()));
        }
        if amount_micro == 0 {
            return Err(LedgerError::Invalid("amount must be > 0".into()));
        }
        let stake_k = Self::wallet_stake_meta_key(&w);
        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances).transaction(|(m, _b)| {
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

    /// Half of each protocol fee is retained (credited to the founder vault); the other half is burned from total supply.
    pub fn split_protocol_fee_treasury_and_burn(fee_micro: u64) -> (u64, u64) {
        let treasury_micro = fee_micro / 2;
        let burn_micro = fee_micro.saturating_sub(treasury_micro);
        (treasury_micro, burn_micro)
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
            .unwrap_or_else(|| if has_key { "strict".to_string() } else { "off".to_string() });
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
            founding: db.open_tree("founding_certs")?,
            ai_quota: db.open_tree("ai_quota")?,
            vest_locks: db.open_tree("vest_locks")?,
            db,
            enc_key,
            snapshot_dir,
        };
        ledger.ensure_db_magic(strict)?;
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
        // Restore founder wallet + balances if sled appears empty.
        if self.balances.iter().next().is_some() {
            return;
        }
        if let Some(fw) = v.get("founder_wallet").and_then(|x| x.as_str()) {
            if !fw.trim().is_empty() {
                let _ = self.meta.insert(
                    META_FOUNDER_WALLET,
                    self.encrypt_value(fw.as_bytes()).unwrap_or_default(),
                );
            }
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

    fn cipher(&self) -> Option<Aes256Gcm> {
        self.enc_key.as_ref().map(|k| {
            let key = Key::<Aes256Gcm>::from_slice(k.as_bytes());
            Aes256Gcm::new(key)
        })
    }

    fn encrypt_value(&self, plaintext: &[u8]) -> Result<Vec<u8>, sled::Error> {
        let Some(cipher) = self.cipher() else {
            return Ok(plaintext.to_vec());
        };
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| sled::Error::Unsupported(format!("encrypt failed: {e}")))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn decrypt_value(&self, bytes: &[u8]) -> Result<Vec<u8>, sled::Error> {
        let Some(cipher) = self.cipher() else {
            return Ok(bytes.to_vec());
        };
        if bytes.len() < 12 {
            return Err(sled::Error::Unsupported("ciphertext too short".into()));
        }
        let (nonce_b, ct) = bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_b);
        cipher
            .decrypt(nonce, ct)
            .map_err(|e| sled::Error::Unsupported(format!("decrypt failed: {e}")))
    }

    #[cfg(test)]
    pub fn test_only_raw_meta_value(&self, key: &[u8]) -> Vec<u8> {
        self.meta.get(key).ok().flatten().map(|v| v.to_vec()).unwrap_or_default()
    }

    fn audit_write(&self, record_json: &[u8]) -> Result<String, LedgerError> {
        // Encrypted, append-only audit record with a stable hash.
        let mut h = Sha256::new();
        h.update(record_json);
        let hash_hex = hex::encode(h.finalize());
        let key = hash_hex.as_bytes();
        let enc = self.encrypt_value(record_json)?;
        self.audit.insert(key, enc)?;
        std::mem::drop(self.db.flush_async());
        eprintln!("[AUDIT] Transaction Executed - Hash: {hash_hex}");
        Ok(hash_hex)
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

    fn fsync_parent_dir(path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            if let Ok(f) = std::fs::File::open(parent) {
                let _ = f.sync_all();
            }
        }
    }

    fn atomic_write_snapshot(&self, bytes: &[u8]) -> Result<(), LedgerError> {
        let (json_path, tmp_path) = self.snapshot_path();
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
            vest_locks: Vec<VestLockV1>,
        }
        let mut balances = Vec::new();
        for it in self.balances.iter() {
            let (k, v) = it?;
            let w = String::from_utf8_lossy(k.as_ref()).to_string();
            let amt = self.decrypt_value(v.as_ref())?;
            balances.push((w, bytes_to_u64(&amt)));
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
            vest_locks,
        };
        serde_json::to_vec(&snap).map_err(|e| LedgerError::Invalid(e.to_string()))
    }

    fn persist_snapshot_best_effort(&self) {
        if let Ok(bytes) = self.build_snapshot_bytes() {
            if self.atomic_write_snapshot(&bytes).is_ok() {
                crate::replication::emit_signed_state_update(&bytes);
            }
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

        if let Some(fw) = v.get("founder_wallet").and_then(|x| x.as_str()) {
            if !fw.trim().is_empty() {
                self.meta.insert(
                    META_FOUNDER_WALLET,
                    self.encrypt_value(fw.as_bytes())?,
                )?;
            }
        }

        let total = v
            .get("total_supply_micro")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        self.meta.insert(
            META_TOTAL_SUPPLY,
            self.encrypt_value(&u64_to_bytes(total))?,
        )?;

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
                self.balances.insert(
                    w.as_bytes(),
                    self.encrypt_value(&u64_to_bytes(amt))?,
                )?;
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
                let vest_bytes = serde_json::to_vec(&row)
                    .map_err(|e| LedgerError::Invalid(e.to_string()))?;
                self.vest_locks
                    .insert(vk, self.encrypt_value(&vest_bytes)?)?;
            }
            let n = arr.len() as u64;
            self.meta.insert(
                META_NEXT_VEST_SEQ,
                self.encrypt_value(&u64_to_bytes(n))?,
            )?;
        } else {
            self.meta.insert(
                META_NEXT_VEST_SEQ,
                self.encrypt_value(&u64_to_bytes(0))?,
            )?;
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
        std::mem::drop(self.db.flush_async());
        Ok(())
    }

    /// One-time genesis mint (clean launch default is founder-only).
    /// Fails with [`LedgerError::GenesisAlreadyApplied`] if total supply is already non-zero.
    pub fn apply_genesis_allocation(
        &self,
        founder_wallet_id: &str,
    ) -> Result<GenesisAllocationSummary, LedgerError> {
        let founder = founder_wallet_id.trim().to_string();
        if founder.is_empty() {
            return Err(LedgerError::Invalid("founder_wallet_id required".into()));
        }

        // Hard anti-footgun: genesis must run on a *truly empty* balances tree.
        // If operators "wipe" only meta keys or partially delete sled files, stale balances could remain
        // and a second genesis would incorrectly top-up supply. Refuse in that case.
        if self.balances.iter().next().transpose()?.is_some() {
            return Err(LedgerError::GenesisAlreadyApplied);
        }

        let founder_key = founder.as_bytes().to_vec();
        let treasury_key = WALLET_DEX_TREASURY.as_bytes().to_vec();
        let pool_key = WALLET_SYSTEM_WORKER_POOL.as_bytes().to_vec();
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
                    return Err(ConflictableTransactionError::Abort(sled::Error::Unsupported(
                        "genesis founder allocation must be > 0".into(),
                    )));
                }
                if GENESIS_TOTAL_MINT_MICRO > MAX_SUPPLY_MICRO {
                    return Err(ConflictableTransactionError::Abort(sled::Error::Unsupported(
                        "genesis allocation exceeds max supply".into(),
                    )));
                }

                let credit = |tree: &TransactionalTree,
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
                if GENESIS_DEX_TREASURY_MICRO > 0 {
                    credit(b, &treasury_key, GENESIS_DEX_TREASURY_MICRO)?;
                }
                if GENESIS_WORKER_POOL_SHARE_MICRO > 0 {
                    credit(b, &pool_key, GENESIS_WORKER_POOL_SHARE_MICRO)?;
                }

                m.insert(
                    META_TOTAL_SUPPLY,
                    self.encrypt_value(&u64_to_bytes(GENESIS_TOTAL_MINT_MICRO))?,
                )?;
                m.insert(
                    META_FOUNDER_WALLET,
                    self.encrypt_value(founder.as_bytes())?,
                )?;
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
            "action": "genesis_allocation",
            "founder_wallet_id": summary.founder_wallet_id,
            "founder_allocation_micro": summary.founder_allocation_micro,
            "dex_treasury_wallet": WALLET_DEX_TREASURY,
            "dex_treasury_allocation_micro": summary.dex_treasury_allocation_micro,
            "worker_pool_wallet": WALLET_SYSTEM_WORKER_POOL,
            "worker_pool_allocation_micro": summary.worker_pool_allocation_micro,
            "total_supply_micro": summary.total_supply_micro,
        });
        let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
        // Ensure durability for the founder demo flow — balances must persist immediately after genesis.
        std::mem::drop(self.db.flush_async());
        self.persist_snapshot_best_effort();
        Ok(summary)
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
        if !peer.is_empty() {
            if let Ok(founder) = self.founder_wallet() {
                if !founder.is_empty() && founder == peer {
                    let unlock_at = self.founder_genesis_unlock_at_ms().unwrap_or(0);
                    if unlock_at > 0 && (now_ms as u128) < unlock_at {
                        let locked = self.founder_genesis_locked_micro().unwrap_or(0);
                        sum = sum.saturating_add(locked);
                    }
                }
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
        let can_claim =
            !w.is_empty() && !claimed && filled < GENESIS_1K_MAX;
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
        self.mint_reward_with_proof(
            wallet,
            gross_micro,
            payload.as_bytes(),
            None,
            true,
        )?;
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
    pub fn test_only_mark_genesis_1k_participant(&self, wallet: &str, slot: u64) -> Result<(), LedgerError> {
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
                let new_total = total
                    .saturating_add(gross_micro)
                    .saturating_sub(burn_micro);
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
                        self.encrypt_value(&u64_to_bytes(
                            burned_prev.saturating_add(burn_micro),
                        ))?,
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
            ((gross_micro as u128)
                .saturating_mul(GENESIS_1K_WORKER_GROSS_NUM)
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
                    return Err(ConflictableTransactionError::Abort(sled::Error::Unsupported(
                        "insufficient_funds".into(),
                    )));
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
                        self.encrypt_value(&u64_to_bytes(fee_total.saturating_add(treasury_micro)))?,
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
        let founder = self.founder_wallet()?;
        let bps = fee_bps.unwrap_or(50).clamp(50, 100);
        let fee_micro = amount_micro.saturating_mul(bps) / 10_000;
        let net_micro = amount_micro.saturating_sub(fee_micro);

        let from_k = from.as_bytes().to_vec();
        let to_k = to.as_bytes().to_vec();
        let founder_k = founder.as_bytes().to_vec();

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
                let ob = b
                    .get(&founder_k)?
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
                    let (treasury_micro, burn_micro) =
                        Self::split_protocol_fee_treasury_and_burn(fee_micro);
                    b.insert(
                        founder_k.clone(),
                        self.encrypt_value(&u64_to_bytes(ob.saturating_add(treasury_micro)))?,
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
                        self.encrypt_value(&u64_to_bytes(
                            burned_prev.saturating_add(burn_micro),
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
                            supply.saturating_sub(burn_micro),
                        ))?,
                    )?;
                }
                if let Some(req_n) = signed_transfer_nonce {
                    m.insert(
                        nonce_key.clone(),
                        self.encrypt_value(&u64_to_bytes(req_n))?,
                    )?;
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
        let (treasury_micro, burn_micro) = Self::split_protocol_fee_treasury_and_burn(fee_micro);
        let audit = serde_json::json!({
            "v": 1,
            "action": "transfer",
            "from_wallet": from,
            "to_wallet": to,
            "amount_micro": amount_micro,
            "net_micro": net_micro,
            "fee_micro": fee_micro,
            "treasury_fee_micro": treasury_micro,
            "burned_fee_micro": burn_micro,
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
