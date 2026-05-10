use crate::protocol::SignedTxEnvelopeV1;
use serde::{Deserialize, Serialize};

/// Network-wide state sync events carried over libp2p gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEvent {
    /// A mined block containing zero or more signed transactions.
    ///
    /// Receiver nodes should apply it idempotently (per-tx) without re-broadcast.
    BlockMined {
        block_height: u64,
        block_id: String,
        #[serde(default)]
        parent_block_id: Option<String>,
        producer_id: String,
        base_reward_micro: u64,
        compute_reward_micro: u64,
        total_reward_micro: u64,
        state_root: String,
        txs: Vec<SignedTxEnvelopeV1>,
    },

    /// A ledger transfer that has been executed on a remote node.
    ///
    /// Receiver nodes should apply it **idempotently** (keyed by `tx_hash`) without re-broadcast.
    TransferExecuted {
        tx_hash: String,
        from_wallet: String,
        to_wallet: String,
        amount_micro: u64,
        fee_bps: u64,
    },

    /// Admin faucet credit observed on another node (pool → user).
    ///
    /// Remote receivers debit [`crate::ledger::WALLET_SYSTEM_WORKER_POOL`] and credit `to_wallet`,
    /// keyed by `event_id` for idempotency (typically the originating node's audit hash hex).
    FaucetExecuted {
        event_id: String,
        to_wallet: String,
        amount_micro: u64,
    },
}
