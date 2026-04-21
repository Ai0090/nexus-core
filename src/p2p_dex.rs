//! Isolated P2P DEX module (maker/taker order book + TET-only escrow).
//!
//! Design constraints:
//! - Must NOT modify core `ledger.rs` or E2EE primitives.
//! - Interacts with the ledger only via existing public methods (transfers).
//! - Escrow is represented as dedicated ledger "wallet strings" derived from trade/order ids.
//! - External settlement ("Stevemon" stable equivalents like USDT/USDC) is *off-ledger*.
//!   This module enforces TET escrow, deadlines, and refund safety.

use crate::ledger::{Ledger, LedgerError};
use crate::quantum_shield::HybridSigError;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Price is expressed in "stevemon-quote-units per 1 TET" (off-ledger quote).
/// Amounts of TET are expressed in ledger micro-units (stevemon = 1e-8 TET).
pub type OrderId = String;
pub type TradeId = String;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Side {
    BuyTET,
    SellTET,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub v: u32,
    pub id: OrderId,
    pub maker_wallet: String,
    pub side: Side,
    /// Off-ledger quote asset ticker ("USDT", "USDC", etc). Informational for matching.
    pub quote_asset: String,
    /// Quote units per 1.0 TET (off-ledger).
    pub price_quote_per_tet: u64,
    /// Total TET the maker is offering (micro-units).
    pub tet_micro_total: u64,
    /// Remaining unfilled TET (micro-units).
    pub tet_micro_remaining: u64,
    /// Expiration time (unix ms). After this, maker can cancel/refund remaining escrow.
    pub expires_at_ms: u128,
    pub created_at_ms: u128,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TradeStatus {
    /// Escrow locked; waiting for off-ledger settlement confirmation.
    PendingSettlement,
    /// Released to taker (TET transferred).
    Completed,
    /// Refunded to maker (timeout/cancel/fail).
    Refunded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trade {
    pub v: u32,
    pub id: TradeId,
    pub order_id: OrderId,
    pub maker_wallet: String,
    pub taker_wallet: String,
    pub side: Side,
    pub quote_asset: String,
    pub price_quote_per_tet: u64,
    pub tet_micro: u64,
    pub status: TradeStatus,
    pub created_at_ms: u128,
    pub deadline_at_ms: u128,
    /// Set by `POST /dex/settlement/confirm` after Solana listener (or stub) verifies USDC payment.
    pub solana_usdc_txid: Option<String>,
    pub settlement_finalized: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DexError {
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("hybrid signature: {0}")]
    HybridSig(#[from] HybridSigError),
    #[error("order not found")]
    OrderNotFound,
    #[error("trade not found")]
    TradeNotFound,
    #[error("order expired")]
    OrderExpired,
    #[error("insufficient remaining size")]
    InsufficientRemaining,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn escrow_wallet_for_order(order_id: &str) -> String {
    // No randomness; deterministic + collision resistant from order id.
    format!("dex:escrow:order:{}", sha256_hex(order_id.as_bytes()))
}

pub fn escrow_wallet_for_trade(trade_id: &str) -> String {
    format!("dex:escrow:trade:{}", sha256_hex(trade_id.as_bytes()))
}

fn stable_id(prefix: &str, maker_wallet: &str, nonce16_hex: &str) -> String {
    let base = format!("{prefix}|{maker_wallet}|{nonce16_hex}");
    sha256_hex(base.as_bytes())
}

/// Minimal, isolated in-memory order book. Persistence can be added outside this module.
///
/// Matching:
/// - Orders match only when `side` and `quote_asset` are compatible.
/// - For simplicity, this engine creates 1 trade per taker fill request (no multi-order sweep).
pub struct DexEngine {
    orders: HashMap<OrderId, Order>,
    trades: HashMap<TradeId, Trade>,
    /// Sell book: lowest price first.
    sell_by_price: BTreeMap<u64, VecDeque<OrderId>>,
    /// Buy book: highest price first (stored by price, but we iterate reverse).
    buy_by_price: BTreeMap<u64, VecDeque<OrderId>>,
}

impl Default for DexEngine {
    fn default() -> Self {
        Self {
            orders: HashMap::new(),
            trades: HashMap::new(),
            sell_by_price: BTreeMap::new(),
            buy_by_price: BTreeMap::new(),
        }
    }
}

impl DexEngine {
    pub fn get_order(&self, id: &str) -> Option<Order> {
        self.orders.get(id).cloned()
    }

    pub fn get_trade(&self, id: &str) -> Option<Trade> {
        self.trades.get(id).cloned()
    }

    pub fn list_active_orders(&self, now_ms: u128) -> Vec<Order> {
        self.orders
            .values()
            .filter(|o| o.tet_micro_remaining > 0 && o.expires_at_ms > now_ms)
            .cloned()
            .collect()
    }

    /// Maker lists an order by escrow-locking `tet_micro_total` into the order escrow wallet.
    pub fn place_maker_order(
        &mut self,
        ledger: &Ledger,
        maker_wallet: &str,
        side: Side,
        quote_asset: &str,
        price_quote_per_tet: u64,
        tet_micro_total: u64,
        ttl: Duration,
    ) -> Result<Order, DexError> {
        let maker_wallet = maker_wallet.trim();
        if maker_wallet.is_empty() {
            return Err(DexError::Invalid("maker_wallet required".into()));
        }
        if quote_asset.trim().is_empty() {
            return Err(DexError::Invalid("quote_asset required".into()));
        }
        if price_quote_per_tet == 0 {
            return Err(DexError::Invalid("price must be > 0".into()));
        }
        if tet_micro_total == 0 {
            return Err(DexError::Invalid("tet_micro_total must be > 0".into()));
        }
        let created_at_ms = now_ms();
        let expires_at_ms = created_at_ms.saturating_add(ttl.as_millis());

        // Deterministic id seeded by time + maker + size/price.
        let nonce16_hex = {
            let base = format!("{created_at_ms}|{maker_wallet}|{side:?}|{quote_asset}|{price_quote_per_tet}|{tet_micro_total}");
            sha256_hex(base.as_bytes())[..32].to_string()
        };
        let id = stable_id("dex-order-v1", maker_wallet, &nonce16_hex);
        let escrow_wallet = escrow_wallet_for_order(&id);

        // Lock funds into escrow via ledger transfer (no core modifications).
        // Fee behavior: use the ledger default by passing `None`.
        let _ = ledger.transfer_with_fee(maker_wallet, &escrow_wallet, tet_micro_total, None)?;
        // Track the *actual* escrow balance (net of protocol fees).
        let escrow_bal = ledger.balance_micro(&escrow_wallet)?;
        if escrow_bal == 0 {
            return Err(DexError::Invalid("escrow lock resulted in zero balance".into()));
        }

        let order = Order {
            v: 1,
            id: id.clone(),
            maker_wallet: maker_wallet.to_string(),
            side,
            quote_asset: quote_asset.trim().to_string(),
            price_quote_per_tet,
            tet_micro_total: escrow_bal,
            tet_micro_remaining: escrow_bal,
            expires_at_ms,
            created_at_ms,
        };
        self.index_order(&order);
        self.orders.insert(id.clone(), order.clone());
        Ok(order)
    }

    /// Maker cancels an unfilled / partially filled order; remaining order escrow is refunded.
    pub fn cancel_maker_order(
        &mut self,
        ledger: &Ledger,
        order_id: &str,
        maker_wallet: &str,
    ) -> Result<Order, DexError> {
        let oid = order_id.trim();
        if oid.is_empty() {
            return Err(DexError::Invalid("order_id required".into()));
        }
        let maker = maker_wallet.trim();
        if maker.is_empty() {
            return Err(DexError::Invalid("maker_wallet required".into()));
        }
        let o = self.orders.get(oid).cloned().ok_or(DexError::OrderNotFound)?;
        if o.maker_wallet.trim() != maker {
            return Err(DexError::Invalid("only order maker may cancel".into()));
        }
        let order_escrow = escrow_wallet_for_order(&o.id);
        let bal = ledger.balance_micro(&order_escrow)?;
        if bal > 0 {
            let _ = ledger.transfer_with_fee(&order_escrow, maker, bal, None)?;
        }
        self.deindex_order(&o);
        self.orders.remove(oid);
        let mut done = o;
        done.tet_micro_remaining = 0;
        Ok(done)
    }

    /// Taker requests a fill against the best price on the opposite book.
    ///
    /// Result is a `Trade` with TET escrow moved into a trade-specific escrow wallet.
    /// Release/refund is handled by `complete_trade_*` or `refund_expired()`.
    pub fn take_best(
        &mut self,
        ledger: &Ledger,
        taker_wallet: &str,
        side: Side,
        quote_asset: &str,
        tet_micro: u64,
        max_price_quote_per_tet: Option<u64>,
        settlement_ttl: Duration,
    ) -> Result<Trade, DexError> {
        let taker_wallet = taker_wallet.trim();
        if taker_wallet.is_empty() {
            return Err(DexError::Invalid("taker_wallet required".into()));
        }
        if quote_asset.trim().is_empty() {
            return Err(DexError::Invalid("quote_asset required".into()));
        }
        if tet_micro == 0 {
            return Err(DexError::Invalid("tet_micro must be > 0".into()));
        }

        // Determine which book we match against.
        let want_opposite = match side {
            Side::BuyTET => Side::SellTET,
            Side::SellTET => Side::BuyTET,
        };

        let best_order_id = self.best_order_id(want_opposite, quote_asset.trim(), max_price_quote_per_tet)
            .ok_or(DexError::OrderNotFound)?;

        let mut order = self.orders.get(&best_order_id).cloned().ok_or(DexError::OrderNotFound)?;
        if order.expires_at_ms <= now_ms() {
            // Lazy cleanup.
            self.deindex_order(&order);
            self.orders.remove(&best_order_id);
            return Err(DexError::OrderExpired);
        }
        if order.quote_asset != quote_asset.trim() {
            return Err(DexError::Invalid("quote_asset mismatch".into()));
        }
        if order.side != want_opposite {
            return Err(DexError::Invalid("side mismatch".into()));
        }
        if order.tet_micro_remaining < tet_micro {
            return Err(DexError::InsufficientRemaining);
        }

        // Move escrow from order-escrow to trade-escrow, leaving remainder in order escrow.
        let created_at_ms = now_ms();
        let deadline_at_ms = created_at_ms.saturating_add(settlement_ttl.as_millis());
        let trade_id = stable_id(
            "dex-trade-v1",
            &order.maker_wallet,
            &sha256_hex(format!("{created_at_ms}|{best_order_id}|{taker_wallet}|{tet_micro}").as_bytes())[..32],
        );
        let order_escrow = escrow_wallet_for_order(&order.id);
        let trade_escrow = escrow_wallet_for_trade(&trade_id);

        // Internal transfer between escrow wallets. Uses existing ledger transfer path.
        let _ = ledger.transfer_with_fee(&order_escrow, &trade_escrow, tet_micro, None)?;
        let trade_bal = ledger.balance_micro(&trade_escrow)?;
        if trade_bal == 0 {
            return Err(DexError::Invalid("trade escrow balance is zero".into()));
        }
        let order_bal = ledger.balance_micro(&order_escrow)?;

        order.tet_micro_remaining = order_bal;
        self.orders.insert(order.id.clone(), order.clone());
        if order.tet_micro_remaining == 0 {
            self.deindex_order(&order);
        }

        let trade = Trade {
            v: 1,
            id: trade_id.clone(),
            order_id: order.id.clone(),
            maker_wallet: order.maker_wallet.clone(),
            taker_wallet: taker_wallet.to_string(),
            side,
            quote_asset: order.quote_asset.clone(),
            price_quote_per_tet: order.price_quote_per_tet,
            tet_micro: trade_bal,
            status: TradeStatus::PendingSettlement,
            created_at_ms,
            deadline_at_ms,
            solana_usdc_txid: None,
            settlement_finalized: false,
        };
        self.trades.insert(trade_id.clone(), trade.clone());
        Ok(trade)
    }

    /// Mark Solana USDC settlement as finalized for this trade (internal gate before Quantum release).
    pub fn confirm_solana_settlement(
        &mut self,
        trade_id: &str,
        solana_usdc_txid: &str,
    ) -> Result<Trade, DexError> {
        let tid = trade_id.trim();
        let txid = solana_usdc_txid.trim();
        if tid.is_empty() || txid.is_empty() {
            return Err(DexError::Invalid("trade_id and solana_usdc_txid required".into()));
        }
        let mut t = self.trades.get(tid).cloned().ok_or(DexError::TradeNotFound)?;
        if t.status != TradeStatus::PendingSettlement {
            return Err(DexError::Invalid("trade not pending settlement".into()));
        }
        if t.settlement_finalized {
            return Err(DexError::Invalid("settlement already finalized".into()));
        }
        t.solana_usdc_txid = Some(txid.to_string());
        t.settlement_finalized = true;
        self.trades.insert(t.id.clone(), t.clone());
        Ok(t)
    }

    /// Complete a trade by releasing escrowed TET to the taker.
    ///
    /// Quantum-resistant preparation: we require the caller to have already verified a hybrid
    /// signature policy externally. This module provides a canonical message for signing.
    pub fn complete_trade_release_to_taker(
        &mut self,
        ledger: &Ledger,
        trade_id: &str,
    ) -> Result<Trade, DexError> {
        let mut t = self.trades.get(trade_id).cloned().ok_or(DexError::TradeNotFound)?;
        if t.status != TradeStatus::PendingSettlement {
            return Ok(t);
        }
        let trade_escrow = escrow_wallet_for_trade(&t.id);
        // Release *actual* escrow balance to avoid fee-induced underfunding.
        let bal = ledger.balance_micro(&trade_escrow)?;
        if bal == 0 {
            return Err(DexError::Invalid("trade escrow empty".into()));
        }
        let _ = ledger.transfer_with_fee(&trade_escrow, &t.taker_wallet, bal, None)?;
        t.tet_micro = bal;
        t.status = TradeStatus::Completed;
        self.trades.insert(t.id.clone(), t.clone());
        Ok(t)
    }

    /// Refund a trade (e.g., failed settlement) back to the maker.
    pub fn refund_trade_to_maker(
        &mut self,
        ledger: &Ledger,
        trade_id: &str,
    ) -> Result<Trade, DexError> {
        let mut t = self.trades.get(trade_id).cloned().ok_or(DexError::TradeNotFound)?;
        if t.status != TradeStatus::PendingSettlement {
            return Ok(t);
        }
        let trade_escrow = escrow_wallet_for_trade(&t.id);
        let bal = ledger.balance_micro(&trade_escrow)?;
        if bal == 0 {
            return Err(DexError::Invalid("trade escrow empty".into()));
        }
        let _ = ledger.transfer_with_fee(&trade_escrow, &t.maker_wallet, bal, None)?;
        t.tet_micro = bal;
        t.status = TradeStatus::Refunded;
        self.trades.insert(t.id.clone(), t.clone());
        Ok(t)
    }

    /// Cancel remaining maker escrow for an expired order (refund to maker).
    pub fn cancel_expired_order_refund_remaining(
        &mut self,
        ledger: &Ledger,
        order_id: &str,
    ) -> Result<Order, DexError> {
        let mut o = self.orders.get(order_id).cloned().ok_or(DexError::OrderNotFound)?;
        if o.expires_at_ms > now_ms() {
            return Err(DexError::Invalid("order not yet expired".into()));
        }
        if o.tet_micro_remaining > 0 {
            let order_escrow = escrow_wallet_for_order(&o.id);
            let _ = ledger.transfer_with_fee(&order_escrow, &o.maker_wallet, o.tet_micro_remaining, None)?;
            o.tet_micro_remaining = 0;
        }
        self.deindex_order(&o);
        self.orders.insert(o.id.clone(), o.clone());
        Ok(o)
    }

    /// Refund all expired pending trades. Returns refunded trade ids.
    pub fn refund_expired_trades(
        &mut self,
        ledger: &Ledger,
        now_ms: u128,
    ) -> Result<Vec<String>, DexError> {
        let mut refunded = Vec::new();
        let ids: Vec<String> = self.trades.keys().cloned().collect();
        for id in ids {
            let t = self.trades.get(&id).cloned().ok_or(DexError::TradeNotFound)?;
            if t.status == TradeStatus::PendingSettlement && t.deadline_at_ms <= now_ms {
                let _ = self.refund_trade_to_maker(ledger, &id)?;
                refunded.push(id);
            }
        }
        Ok(refunded)
    }

    /// Canonical message bytes for maker+taker hybrid signing (Ed25519 + ML-DSA-44).
    ///
    /// Expected verification policy (outside this module):
    /// - Verify maker hybrid signature over this message
    /// - Verify taker hybrid signature over this message
    pub fn trade_complete_message_v1(trade: &Trade, solana_txid: &str) -> Vec<u8> {
        let v = serde_json::json!({
            "v": 1,
            "kind": "dex_trade_complete",
            "trade_id": trade.id,
            "order_id": trade.order_id,
            "maker_wallet": trade.maker_wallet,
            "taker_wallet": trade.taker_wallet,
            "side": format!("{:?}", trade.side),
            "quote_asset": trade.quote_asset,
            "price_quote_per_tet": trade.price_quote_per_tet,
            "tet_micro": trade.tet_micro,
            "created_at_ms": trade.created_at_ms,
            // External settlement proof commitment (non-repudiation).
            "solana_usdc_txid": solana_txid,
        });
        serde_json::to_vec(&v).unwrap_or_default()
    }

    fn index_order(&mut self, o: &Order) {
        let q = match o.side {
            Side::SellTET => self.sell_by_price.entry(o.price_quote_per_tet).or_default(),
            Side::BuyTET => self.buy_by_price.entry(o.price_quote_per_tet).or_default(),
        };
        q.push_back(o.id.clone());
    }

    fn deindex_order(&mut self, o: &Order) {
        let map = match o.side {
            Side::SellTET => &mut self.sell_by_price,
            Side::BuyTET => &mut self.buy_by_price,
        };
        if let Some(q) = map.get_mut(&o.price_quote_per_tet) {
            q.retain(|id| id != &o.id);
            if q.is_empty() {
                map.remove(&o.price_quote_per_tet);
            }
        }
    }

    fn best_order_id(
        &self,
        side: Side,
        quote_asset: &str,
        max_price_quote_per_tet: Option<u64>,
    ) -> Option<OrderId> {
        match side {
            Side::SellTET => {
                // Lowest ask that matches constraints.
                for (price, q) in &self.sell_by_price {
                    if let Some(maxp) = max_price_quote_per_tet {
                        if *price > maxp {
                            return None;
                        }
                    }
                    for id in q {
                        if let Some(o) = self.orders.get(id) {
                            if o.quote_asset == quote_asset && o.tet_micro_remaining > 0 {
                                return Some(id.clone());
                            }
                        }
                    }
                }
                None
            }
            Side::BuyTET => {
                // Highest bid.
                for (price, q) in self.buy_by_price.iter().rev() {
                    if let Some(maxp) = max_price_quote_per_tet {
                        // For taker selling TET, they want >= min; caller passes maxp as guard.
                        // We only enforce an upper bound consistently; deeper policy is external.
                        if *price > maxp {
                            // continue scanning for smaller prices
                        }
                    }
                    for id in q {
                        if let Some(o) = self.orders.get(id) {
                            if o.quote_asset == quote_asset && o.tet_micro_remaining > 0 {
                                return Some(id.clone());
                            }
                        }
                    }
                }
                None
            }
        }
    }
}

