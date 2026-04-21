//! Phase 4 stub: P2P stevemon trading + smart escrow (future).

#[derive(Debug, Clone)]
pub struct EscrowOfferV1 {
    pub offer_id: String,
    pub maker_wallet: String,
    pub amount_stevemon_micro: u64,
}

#[derive(Debug, Clone)]
pub struct EscrowStateV1 {
    pub offer_id: String,
    pub status: String, // "open" | "filled" | "cancelled"
}

pub fn stub_offer() -> EscrowOfferV1 {
    EscrowOfferV1 {
        offer_id: "escrow_stub".into(),
        maker_wallet: "unknown".into(),
        amount_stevemon_micro: 0,
    }
}
