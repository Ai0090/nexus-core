use axum::{Json, extract::State, http::HeaderMap, response::IntoResponse};
use std::time::Duration;

use crate::rest::{
    DexOrderCancelReq, DexOrderCancelResp, DexOrderPlaceReq, DexOrderPlaceResp, DexOrderbookEntry,
    DexSettlementConfirmReq, DexSettlementConfirmResp, DexSweepRefundsReq, DexSweepRefundsResp,
    DexTakeReq, DexTakeResp, DexTradeCompleteReq, DexTradeCompleteResp, RestState,
};

pub async fn post_dex_order_place(
    State(state): State<RestState>,
    Json(req): Json<DexOrderPlaceReq>,
) -> axum::response::Response {
    let side = match req.side.trim().to_ascii_lowercase().as_str() {
        "buy" => crate::p2p_dex::Side::BuyTET,
        "sell" => crate::p2p_dex::Side::SellTET,
        _ => return (axum::http::StatusCode::BAD_REQUEST, "side must be buy|sell").into_response(),
    };
    let ttl = Duration::from_secs(req.ttl_sec.unwrap_or(15 * 60).clamp(30, 86_400));

    let mut dex = crate::rest::helpers::std_lock(&state.dex);
    match dex.place_maker_order(
        &state.ledger,
        req.maker_wallet.trim(),
        side,
        req.quote_asset.trim(),
        req.price_quote_per_tet,
        req.tet_micro_total,
        ttl,
    ) {
        Ok(o) => {
            let escrow_wallet = crate::p2p_dex::escrow_wallet_for_order(&o.id);
            eprintln!("[DEX] Order Placed: {}", o.id);
            (
                axum::http::StatusCode::OK,
                Json(DexOrderPlaceResp {
                    order_id: o.id,
                    escrow_wallet,
                    status: "placed".into(),
                }),
            )
                .into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn post_dex_order_cancel(
    State(state): State<RestState>,
    Json(req): Json<DexOrderCancelReq>,
) -> axum::response::Response {
    let mut dex = crate::rest::helpers::std_lock(&state.dex);
    match dex.cancel_maker_order(&state.ledger, req.order_id.trim(), req.maker_wallet.trim()) {
        Ok(o) => (
            axum::http::StatusCode::OK,
            Json(DexOrderCancelResp {
                order_id: o.id,
                status: "cancelled".into(),
            }),
        )
            .into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn post_dex_take(
    State(state): State<RestState>,
    Json(req): Json<DexTakeReq>,
) -> axum::response::Response {
    let side = match req.side.trim().to_ascii_lowercase().as_str() {
        "buy" => crate::p2p_dex::Side::BuyTET,
        "sell" => crate::p2p_dex::Side::SellTET,
        _ => return (axum::http::StatusCode::BAD_REQUEST, "side must be buy|sell").into_response(),
    };
    let ttl = Duration::from_secs(req.settlement_ttl_sec.unwrap_or(20 * 60).clamp(30, 86_400));

    let mut dex = crate::rest::helpers::std_lock(&state.dex);
    match dex.take_best(
        &state.ledger,
        req.taker_wallet.trim(),
        side,
        req.quote_asset.trim(),
        req.tet_micro,
        req.max_price_quote_per_tet,
        ttl,
    ) {
        Ok(t) => {
            eprintln!("[DEX] Trade Created: {} order={}", t.id, t.order_id);
            (
                axum::http::StatusCode::OK,
                Json(DexTakeResp {
                    trade_id: t.id,
                    order_id: t.order_id,
                    status: "pending_settlement".into(),
                    deadline_at_ms: t.deadline_at_ms,
                }),
            )
                .into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn post_dex_trade_complete(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(req): Json<DexTradeCompleteReq>,
) -> axum::response::Response {
    let trade = {
        let dex = crate::rest::helpers::std_lock(&state.dex);
        dex.get_trade(req.trade_id.trim())
    };
    let Some(trade) = trade else {
        return (axum::http::StatusCode::NOT_FOUND, "trade not found").into_response();
    };

    if !trade.settlement_finalized {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "payment settlement not finalized; call POST /dex/settlement/confirm first",
        )
            .into_response();
    }
    let txid = req.solana_usdc_txid.trim();
    if txid.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "solana_usdc_txid required",
        )
            .into_response();
    }
    if trade.solana_usdc_txid.as_deref() != Some(txid) {
        return (
            axum::http::StatusCode::CONFLICT,
            "solana_usdc_txid does not match finalized settlement",
        )
            .into_response();
    }

    let msg = crate::p2p_dex::DexEngine::trade_complete_message_v1(&trade, txid);
    if let Err(r) = crate::rest::helpers::require_dex_hybrid_sig_strict(
        &headers,
        req.maker_ed25519_pubkey_hex.trim(),
        &msg,
        "maker",
    ) {
        return r;
    }
    if let Err(r) = crate::rest::helpers::require_dex_hybrid_sig_strict(
        &headers,
        req.taker_ed25519_pubkey_hex.trim(),
        &msg,
        "taker",
    ) {
        return r;
    }

    let mut dex = crate::rest::helpers::std_lock(&state.dex);
    match dex.complete_trade_release_to_taker(&state.ledger, req.trade_id.trim()) {
        Ok(t) => {
            eprintln!("[DEX] Quantum Sig Verified for Trade: {}", t.id);
            eprintln!("[DEX] Trade Completed: {}", t.id);
            (
                axum::http::StatusCode::OK,
                Json(DexTradeCompleteResp {
                    trade_id: t.id,
                    status: "completed".into(),
                }),
            )
                .into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn post_dex_settlement_confirm(
    State(state): State<RestState>,
    Json(req): Json<DexSettlementConfirmReq>,
) -> axum::response::Response {
    let mut dex = crate::rest::helpers::std_lock(&state.dex);
    match dex.confirm_solana_settlement(req.trade_id.trim(), req.solana_usdc_txid.trim()) {
        Ok(t) => {
            eprintln!(
                "[DEX] Settlement Finalized: trade={} txid={}",
                t.id,
                req.solana_usdc_txid.trim()
            );
            (
                axum::http::StatusCode::OK,
                Json(DexSettlementConfirmResp {
                    trade_id: t.id,
                    status: "settlement_finalized".into(),
                }),
            )
                .into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn post_dex_sweep_refunds(
    State(state): State<RestState>,
    Json(req): Json<DexSweepRefundsReq>,
) -> axum::response::Response {
    let now = req.now_ms.unwrap_or_else(crate::worker_network::now_ms);
    let mut dex = crate::rest::helpers::std_lock(&state.dex);
    match dex.refund_expired_trades(&state.ledger, now) {
        Ok(ids) => {
            for id in &ids {
                eprintln!("[DEX] Trade Refunded (timeout): {id}");
            }
            (
                axum::http::StatusCode::OK,
                Json(DexSweepRefundsResp {
                    refunded_trade_ids: ids,
                }),
            )
                .into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn get_dex_orderbook(State(state): State<RestState>) -> axum::response::Response {
    let now = crate::worker_network::now_ms();
    let mut out = Vec::new();
    let dex = crate::rest::helpers::std_lock(&state.dex);
    for o in dex.list_active_orders(now) {
        out.push(DexOrderbookEntry {
            order_id: o.id.clone(),
            maker_wallet: o.maker_wallet.clone(),
            side: match o.side {
                crate::p2p_dex::Side::BuyTET => "buy".into(),
                crate::p2p_dex::Side::SellTET => "sell".into(),
            },
            quote_asset: o.quote_asset.clone(),
            price_quote_per_tet: o.price_quote_per_tet,
            tet_micro_remaining: o.tet_micro_remaining,
            expires_at_ms: o.expires_at_ms,
        });
    }
    (axum::http::StatusCode::OK, Json(out)).into_response()
}
