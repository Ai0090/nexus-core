use crate::ledger::Ledger;
use crate::p2p_dex::DexEngine;
use crate::worker_network::WorkerRegistry;
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicUsize;
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
    pub log_sse_connections: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
pub enum MempoolEnqueueError {
    TxTooLarge { bytes: usize, max_bytes: usize },
    Full { txs: usize, bytes: usize },
}

impl std::fmt::Display for MempoolEnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TxTooLarge { bytes, max_bytes } => {
                write!(
                    f,
                    "transaction is too large for mempool: {bytes} > {max_bytes} bytes"
                )
            }
            Self::Full { txs, bytes } => write!(
                f,
                "mempool is full and incoming tx fee is not high enough to evict: txs={txs} bytes={bytes}"
            ),
        }
    }
}

impl RestState {
    pub fn mempool_max_txs() -> usize {
        std::env::var("TET_MEMPOOL_MAX_TXS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(10_000)
    }

    pub fn mempool_max_bytes() -> usize {
        std::env::var("TET_MEMPOOL_MAX_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(64 * 1024 * 1024)
    }

    pub fn tx_estimated_bytes(env: &SignedTxEnvelopeV1) -> usize {
        serde_json::to_vec(env)
            .map(|v| v.len())
            .unwrap_or(usize::MAX)
    }

    pub fn tx_fee_score(env: &SignedTxEnvelopeV1) -> u128 {
        match &env.tx {
            crate::protocol::TxV1::Transfer {
                amount_micro,
                fee_bps,
                ..
            } => (*amount_micro as u128).saturating_mul(*fee_bps as u128) / 10_000,
            crate::protocol::TxV1::EnterpriseInference { amount_micro, .. } => {
                *amount_micro as u128
            }
            _ => 0,
        }
    }

    pub async fn enqueue_mempool_tx(
        &self,
        env: SignedTxEnvelopeV1,
    ) -> Result<bool, MempoolEnqueueError> {
        let max_txs = Self::mempool_max_txs();
        let max_bytes = Self::mempool_max_bytes();
        let incoming_bytes = Self::tx_estimated_bytes(&env);
        if incoming_bytes > max_bytes {
            return Err(MempoolEnqueueError::TxTooLarge {
                bytes: incoming_bytes,
                max_bytes,
            });
        }

        let incoming_fee = Self::tx_fee_score(&env);
        let mut mp = self.mempool.lock().await;
        let mut total_bytes = mp.iter().map(Self::tx_estimated_bytes).sum::<usize>();
        let mut evicted = false;

        while (mp.len() >= max_txs || total_bytes.saturating_add(incoming_bytes) > max_bytes)
            && !mp.is_empty()
        {
            let Some((idx, lowest_fee)) = mp
                .iter()
                .enumerate()
                .map(|(idx, existing)| (idx, Self::tx_fee_score(existing)))
                .min_by_key(|(_, fee)| *fee)
            else {
                break;
            };
            if incoming_fee <= lowest_fee {
                return Err(MempoolEnqueueError::Full {
                    txs: mp.len(),
                    bytes: total_bytes,
                });
            }
            let removed = mp.remove(idx);
            total_bytes = total_bytes.saturating_sub(Self::tx_estimated_bytes(&removed));
            evicted = true;
        }

        if mp.len() >= max_txs || total_bytes.saturating_add(incoming_bytes) > max_bytes {
            return Err(MempoolEnqueueError::Full {
                txs: mp.len(),
                bytes: total_bytes,
            });
        }
        mp.push(env);
        Ok(evicted)
    }
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
