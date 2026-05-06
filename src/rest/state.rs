use crate::ledger::Ledger;
use crate::p2p_dex::DexEngine;
use crate::worker_network::WorkerRegistry;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use tokio::sync::mpsc;

use crate::protocol::SignedTxEnvelopeV1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct E2eeJobV1 {
    pub(crate) v: u32,
    pub(crate) job_id: String,
    pub(crate) worker_wallet: String,
    pub(crate) client_ephemeral_pub_b64: String,
    #[serde(default)]
    pub(crate) client_mlkem_pub_b64: String,
    pub(crate) nonce_b64: String,
    pub(crate) ciphertext_b64: String,
    #[serde(default)]
    pub(crate) mlkem_ciphertext_b64: String,
    pub(crate) created_at_ms: u128,
    pub(crate) completed: bool,
    pub(crate) result_nonce_b64: Option<String>,
    pub(crate) result_ciphertext_b64: Option<String>,
    pub(crate) result_mlkem_ciphertext_b64: Option<String>,
}

#[derive(Default)]
pub struct E2eeJobQueue {
    pub(crate) jobs: std::collections::HashMap<String, E2eeJobV1>,
    pub(crate) pending_by_worker:
        std::collections::HashMap<String, std::collections::VecDeque<String>>,
}

#[derive(Clone)]
pub struct RestState {
    pub ledger: Arc<Ledger>,
    pub solana: Arc<crate::ledger::solana_client::NexusSolanaClient>,
    pub p2p_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    pub p2p_client: Option<crate::p2p_network::P2pClient>,
    pub gossip_tx: Option<mpsc::Sender<String>>,
    /// In-memory pending transactions (Phase 2 mempool).
    pub mempool: Arc<Mutex<Vec<SignedTxEnvelopeV1>>>,
    pub http_ratelimit: Arc<Mutex<HttpRateLimit>>,
    pub workers: Arc<StdMutex<WorkerRegistry>>,
    pub e2ee_jobs: Arc<StdMutex<E2eeJobQueue>>,
    pub dex: Arc<StdMutex<DexEngine>>,
    pub genesis_1k_lock: Arc<tokio::sync::Mutex<()>>,
    pub log_tx: broadcast::Sender<String>,
}

#[derive(Debug)]
pub struct HttpRateLimit {
    window_start: std::time::Instant,
    count: u64,
    max_per_sec: u64,
}

impl HttpRateLimit {
    pub fn new(max_per_sec: u64) -> Self {
        Self {
            window_start: std::time::Instant::now(),
            count: 0,
            max_per_sec: max_per_sec.max(1),
        }
    }

    pub(crate) fn tick_allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        if now.duration_since(self.window_start) >= std::time::Duration::from_secs(1) {
            self.window_start = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= self.max_per_sec
    }
}
