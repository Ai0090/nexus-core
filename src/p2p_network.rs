//! Phase 1 foundation: basic libp2p Swarm builder.
//!
//! This module is **additive** and intentionally not wired into `main.rs`'s runtime yet
//! to avoid breaking Phase 0 server behavior.

use base64::Engine as _;
use clone_solana_sdk::signature::Signer as _;
use futures::future::Either;
use libp2p::autonat;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::OrTransport;
use libp2p::core::transport::Transport as _;
use libp2p::core::upgrade;
use libp2p::dcutr;
use libp2p::gossipsub::{self, IdentTopic as Topic, MessageAuthenticity, ValidationMode};
use libp2p::identify;
use libp2p::identity;
use libp2p::kad::{self, store::MemoryStore};
use libp2p::multiaddr::Protocol;
use libp2p::noise;
use libp2p::relay;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::tcp;
use libp2p::yamux;
use libp2p::{Multiaddr, PeerId};
use libp2p_webrtc as webrtc;
use once_cell::sync::Lazy;
use rand_core::RngCore as _;
use serde_json::Value;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use x25519_dalek::{PublicKey, StaticSecret};

type AnyErr = Box<dyn Error + Send + Sync + 'static>;

pub const INFERENCE_TOPIC: &str = "nexus-inference-v1";

/// Hard cap for gossip payloads (libp2p `max_transmit_size` + local validation).
/// Default **96 KiB**: fits E2EE-wrapped inference (~24KiB prompt ceiling) + ML-KEM/X25519 boxes + ZK receipt headroom.
/// Override with `TET_P2P_GOSSIP_MAX_MSG_BYTES` (allowed range **48 KiB … 128 KiB**).
pub const DEFAULT_GOSSIP_MAX_MSG_BYTES: usize = 96 * 1024;

fn gossip_max_msg_bytes() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        std::env::var("TET_P2P_GOSSIP_MAX_MSG_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map(|n| n.clamp(48 * 1024, 128 * 1024))
            .unwrap_or(DEFAULT_GOSSIP_MAX_MSG_BYTES)
    })
}

fn max_b64_field_bytes(total_cap: usize) -> usize {
    total_cap.saturating_sub(4096).max(1024)
}

fn is_wallet_id_hex64(s: &str) -> bool {
    let s = s.trim();
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Normalize wallet id for [`crate::ledger::Ledger`] lookups (matches `worker_bond_micro` / `is_active_worker`).
fn normalize_ledger_wallet_id(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// Structural validation on [`serde_json::Value`] **before** spawning decrypt / ZK / AI work.
fn validate_inference_request_json(v: &Value, total_cap: usize) -> bool {
    let Some(o) = v.as_object() else {
        return false;
    };
    let max_field = max_b64_field_bytes(total_cap);
    let tw = o
        .get("target_worker_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim();
    let sid = o
        .get("sender_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim();
    let ep = o
        .get("encrypted_prompt_b64")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if tw.is_empty() || tw.len() > 256 {
        return false;
    }
    if !is_wallet_id_hex64(sid) {
        return false;
    }
    if ep.is_empty() || ep.len() > max_field {
        return false;
    }
    match o.get("max_fee_micro") {
        None => {}
        Some(Value::Number(n)) => {
            let Some(u) = n.as_u64() else {
                return false;
            };
            if u == 0 || u > crate::ledger::MAX_SUPPLY_MICRO {
                return false;
            }
        }
        Some(_) => return false,
    }
    true
}

fn validate_inference_result_json(v: &Value, total_cap: usize) -> bool {
    let Some(o) = v.as_object() else {
        return false;
    };
    let max_field = max_b64_field_bytes(total_cap);
    let ts = o
        .get("target_sender_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim();
    let wid = o
        .get("worker_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim();
    let er = o
        .get("encrypted_response_b64")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let rcpt = o.get("receipt_b64").and_then(|x| x.as_str()).unwrap_or("");
    let tr = o
        .get("trace_root_b64")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if !is_wallet_id_hex64(ts) {
        return false;
    }
    if wid.is_empty() || wid.len() > 256 {
        return false;
    }
    if er.is_empty() || er.len() > max_field {
        return false;
    }
    if rcpt.is_empty() || rcpt.len() > max_field {
        return false;
    }
    if tr.is_empty() || tr.len() > max_field {
        return false;
    }
    true
}

#[derive(Debug)]
enum ParsedGossip {
    Request(InferenceRequest),
    Result(InferenceResult),
}

/// Single JSON parse + shape filter; returns classified payload or error (caller reports `Reject` to gossipsub).
fn classify_gossip_payload(data: &[u8]) -> Result<ParsedGossip, ()> {
    let cap = gossip_max_msg_bytes();
    if data.is_empty() || data.len() > cap {
        return Err(());
    }
    let v: Value = serde_json::from_slice(data).map_err(|_| ())?;
    let Some(o) = v.as_object() else {
        return Err(());
    };
    let looks_req = o.contains_key("encrypted_prompt_b64") && o.contains_key("target_worker_id");
    let looks_res = o.contains_key("receipt_b64") && o.contains_key("encrypted_response_b64");

    if looks_req {
        if !validate_inference_request_json(&v, cap) {
            return Err(());
        }
        let req = serde_json::from_value(v).map_err(|_| ())?;
        return Ok(ParsedGossip::Request(req));
    }
    if looks_res {
        if !validate_inference_result_json(&v, cap) {
            return Err(());
        }
        let res = serde_json::from_value(v).map_err(|_| ())?;
        return Ok(ParsedGossip::Result(res));
    }
    Err(())
}

fn is_bootnode() -> bool {
    std::env::var("TET_IS_BOOTNODE")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn split_p2p_peer(mut addr: Multiaddr) -> Option<(Multiaddr, PeerId)> {
    match addr.pop() {
        Some(Protocol::P2p(peer)) => Some((addr, peer)),
        Some(p) => {
            addr.push(p);
            None
        }
        None => None,
    }
}

fn decode_nonce12(b64: &str) -> Option<[u8; 12]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()?;
    raw.try_into().ok()
}

fn encode_nonce12(n: [u8; 12]) -> String {
    base64::engine::general_purpose::STANDARD.encode(n)
}

fn decode_32(b64: &str) -> Option<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()?;
    raw.try_into().ok()
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct E2eeBoxV1 {
    client_ephemeral_pub_b64: String,
    client_mlkem_pub_b64: String,
    mlkem_ciphertext_b64: String,
    nonce12_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct E2eeRespBoxV1 {
    worker_static_pub_b64: String,
    mlkem_ciphertext_b64: String,
    nonce12_b64: String,
    ciphertext_b64: String,
}

static PENDING_CLIENT_EPH_SK_BY_TRACE_ROOT: Lazy<
    Mutex<std::collections::HashMap<String, [u8; 32]>>,
> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

static WORKER_INFERENCE_SEMAPHORE: Lazy<Arc<Semaphore>> = Lazy::new(|| {
    let n = std::env::var("TET_WORKER_MAX_INFLIGHT_INFERENCES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(1, 64);
    Arc::new(Semaphore::new(n))
});

pub fn remember_client_eph_sk_for_trace_root(trace_root_b64: &str, client_eph_sk: &StaticSecret) {
    let mut m = PENDING_CLIENT_EPH_SK_BY_TRACE_ROOT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    m.insert(trace_root_b64.to_string(), client_eph_sk.to_bytes());
}

fn take_client_eph_sk_for_trace_root(trace_root_b64: &str) -> Option<StaticSecret> {
    let mut m = PENDING_CLIENT_EPH_SK_BY_TRACE_ROOT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let raw = m.remove(trace_root_b64)?;
    Some(StaticSecret::from(raw))
}

fn load_local_worker_x25519_static_secret() -> Option<StaticSecret> {
    let b64 = std::env::var("TET_X25519_STATIC_SK_B64").ok()?;
    let raw: [u8; 32] = decode_32(b64.trim())?;
    Some(StaticSecret::from(raw))
}

fn load_local_worker_mlkem_static_secret_bytes() -> Option<Vec<u8>> {
    let b64 = std::env::var("TET_MLKEM_STATIC_SK_B64").ok()?;
    crate::e2ee::decode_mlkem_sk_b64(b64.trim()).ok()
}

/// Baseline P2P inference settlement (Stevemon micro): **10** = **0.00001 TET**, aligned with local `POST /ai/infer`.
/// Worker binds ZK receipts to `min(thermodynamic_estimate, max_fee_micro)` so gossip settlement stays micropayment-sized.
pub const AI_INFER_MICROPAYMENT_MICRO: u64 = 10;

fn default_inference_max_fee_micro() -> u64 {
    AI_INFER_MICROPAYMENT_MICRO
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InferenceRequest {
    pub target_worker_id: String,
    pub sender_id: String,
    pub encrypted_prompt_b64: String,
    /// Client-authorized upper bound for this job (Stevemon). Older payloads omit this → deserialize default [`AI_INFER_MICROPAYMENT_MICRO`].
    #[serde(default = "default_inference_max_fee_micro")]
    pub max_fee_micro: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InferenceResult {
    pub target_sender_id: String,
    pub worker_id: String,
    pub encrypted_response_b64: String,
    pub ncu: f64,
    pub cost_micro_tet: u64,
    pub receipt_b64: String,
    pub trace_root_b64: String,
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub flops: u64,
    #[serde(default)]
    pub energy_wh: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UiLastInference {
    pub worker_id: String,
    pub response: String,
    pub receipt_b64: String,
    pub trace_root_b64: String,
}

static LAST_INFERENCE_FOR_UI: Lazy<Mutex<Option<UiLastInference>>> = Lazy::new(|| Mutex::new(None));

static PENDING_INFERENCE_WAITERS_BY_TRACE_ROOT: Lazy<
    Mutex<std::collections::HashMap<String, oneshot::Sender<UiLastInference>>>,
> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

pub fn set_last_inference_for_ui(v: UiLastInference) {
    let mut g = LAST_INFERENCE_FOR_UI
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *g = Some(v);
}

pub fn get_last_inference_for_ui() -> Option<UiLastInference> {
    let g = LAST_INFERENCE_FOR_UI
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    g.clone()
}

pub fn register_inference_waiter(trace_root_b64: String) -> oneshot::Receiver<UiLastInference> {
    let (tx, rx) = oneshot::channel();
    let mut g = PENDING_INFERENCE_WAITERS_BY_TRACE_ROOT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    g.insert(trace_root_b64, tx);
    rx
}

pub fn unregister_inference_waiter(trace_root_b64: &str) {
    let mut g = PENDING_INFERENCE_WAITERS_BY_TRACE_ROOT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    g.remove(trace_root_b64);
}

fn fulfill_inference_waiter(trace_root_b64: &str, v: UiLastInference) {
    let tx = {
        let mut g = PENDING_INFERENCE_WAITERS_BY_TRACE_ROOT
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        g.remove(trace_root_b64)
    };
    if let Some(tx) = tx {
        let _ = tx.send(v);
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NexusEvent")]
pub struct NexusBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub autonat: autonat::Behaviour,
    pub relay_server: relay::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
}

#[derive(Debug)]
pub enum NexusEvent {
    #[allow(dead_code)]
    Kademlia(kad::Event),
    #[allow(dead_code)]
    Gossipsub(gossipsub::Event),
    #[allow(dead_code)]
    Identify(identify::Event),
    #[allow(dead_code)]
    Autonat(autonat::Event),
    #[allow(dead_code)]
    RelayServer(relay::Event),
    #[allow(dead_code)]
    RelayClient(relay::client::Event),
    #[allow(dead_code)]
    Dcutr(dcutr::Event),
}

impl From<kad::Event> for NexusEvent {
    fn from(e: kad::Event) -> Self {
        Self::Kademlia(e)
    }
}
impl From<gossipsub::Event> for NexusEvent {
    fn from(e: gossipsub::Event) -> Self {
        Self::Gossipsub(e)
    }
}
impl From<identify::Event> for NexusEvent {
    fn from(e: identify::Event) -> Self {
        Self::Identify(e)
    }
}
impl From<autonat::Event> for NexusEvent {
    fn from(e: autonat::Event) -> Self {
        Self::Autonat(e)
    }
}
impl From<relay::Event> for NexusEvent {
    fn from(e: relay::Event) -> Self {
        Self::RelayServer(e)
    }
}
impl From<relay::client::Event> for NexusEvent {
    fn from(e: relay::client::Event) -> Self {
        Self::RelayClient(e)
    }
}
impl From<dcutr::Event> for NexusEvent {
    fn from(e: dcutr::Event) -> Self {
        Self::Dcutr(e)
    }
}

pub enum P2pCommand {
    BroadcastInference {
        payload: Vec<u8>,
        ack: Option<oneshot::Sender<anyhow::Result<()>>>,
    },
    /// Return libp2p swarm connected peer count (for REST `/v1/vision/network/config`).
    ConnectedPeersCount { reply: oneshot::Sender<usize> },
}

#[derive(Clone)]
pub struct P2pClient {
    sender: mpsc::Sender<P2pCommand>,
}

impl P2pClient {
    /// Active libp2p connections (swarm connected peers). Returns 0 if P2P stack is disabled.
    pub async fn connected_peers_count(&self) -> anyhow::Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(P2pCommand::ConnectedPeersCount { reply: tx })
            .await
            .map_err(|e| anyhow::anyhow!("p2p command channel closed: {e}"))?;
        rx.await
            .map_err(|e| anyhow::anyhow!("connected_peers reply closed: {e}"))
    }

    pub async fn broadcast_inference(&self, payload: Vec<u8>) -> anyhow::Result<()> {
        self.sender
            .send(P2pCommand::BroadcastInference { payload, ack: None })
            .await
            .map_err(|e| anyhow::anyhow!("p2p command channel closed: {e}"))?;
        Ok(())
    }

    pub async fn broadcast_inference_with_ack(&self, payload: Vec<u8>) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(P2pCommand::BroadcastInference {
                payload,
                ack: Some(tx),
            })
            .await
            .map_err(|e| anyhow::anyhow!("p2p command channel closed: {e}"))?;
        rx.await
            .map_err(|e| anyhow::anyhow!("p2p publish ack channel closed: {e}"))?
    }
}

/// Build a minimal, encrypted, multiplexed libp2p swarm.
///
/// - Identity: ephemeral Ed25519 keypair generated locally at boot (Phase 1).
/// - Transport: TCP (tokio) + Noise (XX) + Yamux.
/// - Behaviour: NexusBehaviour = Kademlia + Gossipsub (discovery + broadcast).
pub fn build_basic_swarm() -> Result<(Swarm<NexusBehaviour>, PeerId), AnyErr> {
    let keypair = identity::Keypair::generate_ed25519();
    let public = keypair.public();
    let peer_id = PeerId::from(keypair.public());

    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));

    // Relay client: required for NAT traversal (relay fallback + DCUtR).
    let (relay_transport, relay_client) = relay::client::new(peer_id);

    let tcp_relay_transport = OrTransport::new(tcp_transport, relay_transport)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&keypair)?)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();

    // WebRTC-direct transport (UDP + DTLS + SCTP). This enables browser/mobile connectivity.
    let webrtc_transport = webrtc::tokio::Transport::new(
        keypair.clone(),
        webrtc::tokio::Certificate::generate(&mut rand::thread_rng())
            .map_err(|e| format!("webrtc certificate generate failed: {e:?}"))?,
    )
    .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
    .boxed();

    // OrTransport yields `Either<L, R>`; flatten since both sides now yield the same output type.
    let transport = OrTransport::new(tcp_relay_transport, webrtc_transport)
        .map(|either, _| match either {
            Either::Left(v) => v,
            Either::Right(v) => v,
        })
        .boxed();

    // Kademlia DHT for peer discovery (no central servers).
    //
    // NOTE: We still use MemoryStore in this snapshot, but we harden config so swapping in a
    // persistent store later doesn't require behavioural changes.
    let store = MemoryStore::new(peer_id);
    let mut kcfg = kad::Config::default();
    // Larger-scale posture (Phase 1.2): longer timeouts and provider TTL.
    kcfg.set_query_timeout(Duration::from_secs(120));
    kcfg.set_provider_record_ttl(Some(Duration::from_secs(24 * 60 * 60)));
    // Keep provider records refreshed before TTL.
    kcfg.set_provider_publication_interval(Some(Duration::from_secs(60 * 60)));
    // Conservative routing table sizing (helps stability under churn).
    kcfg.set_kbucket_inserts(kad::BucketInserts::OnConnected);
    let kademlia = kad::Behaviour::with_config(peer_id, store, kcfg);

    // Gossipsub for inference requests & micro-proof broadcasts.
    let max_tx = gossip_max_msg_bytes();
    let gcfg = gossipsub::ConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .validate_messages()
        // Drop oversize frames at the protocol layer (strictly <= app cap).
        .max_transmit_size(max_tx)
        .heartbeat_interval(Duration::from_millis(800))
        // Limit fan-out work per RPC (anti-spam; pairs with small max_transmit_size).
        .max_messages_per_rpc(Some(32))
        .build()?;
    let mut gossipsub =
        gossipsub::Behaviour::new(MessageAuthenticity::Signed(keypair.clone()), gcfg)?;
    // Peer scoring: invalid `MessageAcceptance::Reject` paths hit P4 (invalid message deliveries) on the topic.
    // Heavy weight so unstaked "worker" result spam + malformed gossip hits graylist quickly.
    let topic_scoring = gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        invalid_message_deliveries_weight: -22.0,
        invalid_message_deliveries_decay: 0.88,
        ..Default::default()
    };
    let topic_h = Topic::new(INFERENCE_TOPIC).hash();
    let mut score_params = gossipsub::PeerScoreParams::default();
    score_params.topics.insert(topic_h, topic_scoring);
    // P5: amplify [`Behaviour::set_application_score`] for stake-violation penalties (Worker-only spam).
    score_params.app_specific_weight = 14.0;
    score_params.behaviour_penalty_weight = -12.0;
    score_params.behaviour_penalty_threshold = 1.0;
    let score_thresholds = gossipsub::PeerScoreThresholds {
        gossip_threshold: -6.0,
        publish_threshold: -45.0,
        // Somewhat stricter than default (-75): spammy / unstaked-result relays exit mesh sooner.
        graylist_threshold: -62.0,
        ..Default::default()
    };
    score_params
        .validate()
        .map_err(|e| format!("gossipsub peer score params: {e}"))?;
    score_thresholds
        .validate()
        .map_err(|e| format!("gossipsub peer score thresholds: {e}"))?;
    gossipsub
        .with_peer_score(score_params, score_thresholds)
        .map_err(|e| format!("gossipsub peer score init failed: {e:?}"))?;

    let topic = Topic::new(INFERENCE_TOPIC);
    gossipsub.subscribe(&topic)?;

    let identify_config = identify::Config::new("/nexus/1.0.0".to_string(), public);
    let identify = identify::Behaviour::new(identify_config);

    let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());
    let relay_server = relay::Behaviour::new(peer_id, Default::default());
    let dcutr = dcutr::Behaviour::new(peer_id);

    let behaviour = NexusBehaviour {
        kademlia,
        gossipsub,
        identify,
        autonat,
        relay_server,
        relay_client,
        dcutr,
    };
    let swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    Ok((swarm, peer_id))
}

/// Listen on a multiaddr (e.g. `/ip4/0.0.0.0/tcp/0`) and return the chosen PeerId.
///
/// This is a convenience helper for Phase 1 bring-up and local smoke testing.
pub fn listen_on(swarm: &mut Swarm<NexusBehaviour>, addr: Multiaddr) -> Result<PeerId, AnyErr> {
    let peer_id = *swarm.local_peer_id();
    swarm.listen_on(addr)?;
    Ok(peer_id)
}

/// Poll a single swarm event (non-blocking) for wiring later.
///
/// This function contains real logic and is safe to call from a tokio task once Phase 1
/// is integrated.
pub async fn next_event(swarm: &mut Swarm<NexusBehaviour>) -> SwarmEvent<NexusEvent> {
    use futures::StreamExt;
    swarm.select_next_some().await
}

pub async fn run_swarm_loop(
    mut swarm: Swarm<NexusBehaviour>,
    ledger: Arc<crate::ledger::Ledger>,
    local_worker_id: String,
    command_tx: mpsc::Sender<P2pCommand>,
    mut command_rx: mpsc::Receiver<P2pCommand>,
) {
    use futures::StreamExt;
    // Host verifier (RISC Zero receipt verification).
    let topic = Topic::new(INFERENCE_TOPIC);

    // Phase 2.3: restore known peers into Kademlia on boot.
    {
        let peers = ledger.load_peers();
        if !peers.is_empty() {
            log::info!("[p2p][peers] restoring {} known peer addrs", peers.len());
        }
        for (peer_id, addr) in peers {
            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
        }
    }

    loop {
        tokio::select! {
            cmd = command_rx.recv() => {
                match cmd {
                    Some(P2pCommand::ConnectedPeersCount { reply }) => {
                        let n = swarm.connected_peers().count();
                        let _ = reply.send(n);
                    }
                    Some(P2pCommand::BroadcastInference { payload, ack }) => {
                        let cap = gossip_max_msg_bytes();
                        let res = if payload.len() > cap {
                            Err(anyhow::anyhow!(
                                "gossip payload {} bytes exceeds {} byte cap (set TET_P2P_GOSSIP_MAX_MSG_BYTES or raise default)",
                                payload.len(),
                                cap
                            ))
                        } else {
                            swarm
                                .behaviour_mut()
                                .gossipsub
                                .publish(topic.clone(), payload)
                                .map(|msg_id| {
                                    log::info!("🚀 [p2p][gossip] PUBLISH SUCCESS: msg_id={}", msg_id);
                                })
                                .map_err(|e| anyhow::anyhow!("{e:?}"))
                        };
                        if let Err(e) = &res {
                            log::error!("❌ [p2p][gossip] PUBLISH FAILED: {:?}", e);
                        }
                        if let Some(ack) = ack {
                            let _ = ack.send(res.map(|_| ()));
                        }
                    }
                    None => {
                        // Control plane dropped: keep the swarm alive (still receiving).
                    }
                }
            }
            ev = swarm.select_next_some() => {
                match ev {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        log::info!("[p2p] listening {address}");
                    }
                    SwarmEvent::Behaviour(NexusEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message_id,
                        message,
                        ..
                    })) => {
                            // Phase 1.3: autonomous request->compute->result loop.
                            // Pre-validate JSON shape + size **before** decrypt / ZK / AI (Week 2 spam hardening).
                            let parsed = match classify_gossip_payload(&message.data) {
                                Ok(p) => p,
                                Err(()) => {
                                    let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id,
                                        &propagation_source,
                                        libp2p::gossipsub::MessageAcceptance::Reject,
                                    );
                                    continue;
                                }
                            };

                            // Strict-mode gossip validation: clients may broadcast [`InferenceRequest`] without worker stake.
                            // Only [`InferenceResult`] senders must prove ledger worker bond (Sybil / spam gate).
                            match &parsed {
                                ParsedGossip::Request(_) => {
                                    let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id,
                                        &propagation_source,
                                        libp2p::gossipsub::MessageAcceptance::Accept,
                                    );
                                }
                                ParsedGossip::Result(res) => {
                                    let wid = normalize_ledger_wallet_id(&res.worker_id);
                                    if !ledger.is_active_worker(&wid) {
                                        log::warn!(
                                            "[p2p][stake] reject InferenceResult: worker_id={} is not staked (need >= {} micro bond); peer={}",
                                            wid,
                                            crate::ledger::MIN_WORKER_STAKE_MICRO,
                                            propagation_source
                                        );
                                        let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                            &message_id,
                                            &propagation_source,
                                            libp2p::gossipsub::MessageAcceptance::Reject,
                                        );
                                        // Application score (P5) + Reject (P4) → rapid graylist for relaying fake workers.
                                        let _set = swarm
                                            .behaviour_mut()
                                            .gossipsub
                                            .set_application_score(&propagation_source, -9.0);
                                        if !_set {
                                            log::debug!(
                                                "[p2p][stake] set_application_score no-op (peer not in score table): {}",
                                                propagation_source
                                            );
                                        }
                                        continue;
                                    }
                                    let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id,
                                        &propagation_source,
                                        libp2p::gossipsub::MessageAcceptance::Accept,
                                    );
                                }
                            }

                            match parsed {
                            ParsedGossip::Request(req) => {
                                log::info!("[p2p][trace] Checking target_worker_id...");
                                if req.target_worker_id != local_worker_id {
                                    log::warn!(
                                        "[p2p][trace] Mismatch! msg_target={}, my_id={}",
                                        req.target_worker_id,
                                        local_worker_id
                                    );
                                    continue;
                                }
                                let worker_sk = match load_local_worker_x25519_static_secret() {
                                    Some(sk) => sk,
                                    None => {
                                        log::error!("[p2p][e2ee] missing TET_X25519_STATIC_SK_B64; cannot decrypt prompt");
                                        continue;
                                    }
                                };
                                let worker_mlkem_sk = match load_local_worker_mlkem_static_secret_bytes() {
                                    Some(v) => v,
                                    None => {
                                        log::error!("[p2p][e2ee] missing TET_MLKEM_STATIC_SK_B64; cannot PQ-decrypt prompt");
                                        continue;
                                    }
                                };
                                let tx2 = command_tx.clone();
                                let worker_id = local_worker_id.clone();
                                let permit = match WORKER_INFERENCE_SEMAPHORE.clone().try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        // Drop silently: bounded concurrency to prevent OOM / CPU exhaustion.
                                        continue;
                                    }
                                };
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    log::info!("[p2p][trace] Entering decryption phase...");
                                    // Decode + decrypt prompt
                                    let boxed_bytes = match base64::engine::general_purpose::STANDARD
                                        .decode(req.encrypted_prompt_b64.as_bytes())
                                    {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][e2ee] bad encrypted_prompt_b64 (base64): {e}");
                                            return;
                                        }
                                    };
                                    let bx: E2eeBoxV1 = match serde_json::from_slice(&boxed_bytes) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][e2ee] bad prompt box json: {e}");
                                            return;
                                        }
                                    };
                                    let client_mlkem_pk = match crate::e2ee::decode_mlkem_pub_b64(bx.client_mlkem_pub_b64.trim()) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][e2ee] bad client mlkem pubkey: {:?}", e);
                                            return;
                                        }
                                    };
                                    log::debug!(
                                        "[p2p][e2ee] Raw CT B64 to decode (first 20 chars): {:.20}",
                                        bx.mlkem_ciphertext_b64.trim()
                                    );
                                    let mlkem_ct = match crate::e2ee::decode_mlkem_ct_b64(bx.mlkem_ciphertext_b64.trim()) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][e2ee] decode_mlkem_ct_b64 failed: {:?}", e);
                                            return;
                                        }
                                    };
                                    let nonce12 = match decode_nonce12(bx.nonce12_b64.trim()) {
                                        Some(v) => v,
                                        None => {
                                            log::error!("[p2p][e2ee] bad nonce12");
                                            return;
                                        }
                                    };
                                    let ct = match base64::engine::general_purpose::STANDARD.decode(bx.ciphertext_b64.as_bytes()) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][e2ee] bad ciphertext b64: {e}");
                                            return;
                                        }
                                    };
                                    log::info!("[p2p][trace] Normal decrypt path selected");
                                    let client_eph_pk = match crate::e2ee::decode_x25519_pub_b64(bx.client_ephemeral_pub_b64.trim()) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][e2ee] bad client ephemeral pubkey: {e}");
                                            return;
                                        }
                                    };
                                    let pt = match crate::e2ee::decrypt_on_worker(&worker_sk, &client_eph_pk, &worker_mlkem_sk, &mlkem_ct, nonce12, &ct) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][e2ee] decrypt failed (not for this worker?): {e}");
                                            return;
                                        }
                                    };
                                    let prompt = match String::from_utf8(pt) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            log::error!("[p2p][e2ee] decrypted prompt not utf8: {e}");
                                            return;
                                        }
                                    };
                                    log::info!("[p2p][e2ee] True X25519 decryption successful!");
                                    log::info!("[p2p][trace] Spawned task, calling Ollama...");

                                    let metrics = match crate::worker_engine::run_local_inference(prompt.trim()).await {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][worker] inference failed sender={} err={e}", req.sender_id);
                                            return;
                                        }
                                    };
                                    let resp = metrics.text.clone();
                                    let ncu = metrics.ncu;
                                    // Auction-style cap: ledger gross never exceeds `max_fee_micro`; thermodynamic estimate is informational above that.
                                    let max_fee = req.max_fee_micro.max(1);
                                    let receipt_cost_micro = metrics.cost_micro.min(max_fee).max(1);
                                    let cost_micro_tet = receipt_cost_micro;
                                    if metrics.cost_micro > receipt_cost_micro {
                                        log::info!(
                                            "[p2p][economics] thermo_estimate_micro={} settled_micro={} (max_fee_micro={})",
                                            metrics.cost_micro,
                                            receipt_cost_micro,
                                            max_fee
                                        );
                                    }
                                    let flops_u64 =
                                        u64::try_from(metrics.flops.min(u128::from(u64::MAX))).unwrap_or(u64::MAX);
                                    let worker_pubkey_bytes = {
                                        // PoC: bind the "worker id" to 32 bytes deterministically.
                                        // In production, this should be the real worker pubkey bytes.
                                        use sha2::{Digest as _, Sha256};
                                        let h: [u8; 32] = Sha256::digest(worker_id.as_bytes()).into();
                                        h
                                    };
                                    let receipt_b64 = match crate::worker_engine::generate_receipt_b64(
                                        prompt.trim(),
                                        resp.trim(),
                                        worker_pubkey_bytes,
                                        receipt_cost_micro,
                                    ).await {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][zk] proof generation failed: {e}");
                                            return;
                                        }
                                    };
                                    // Trace root is a deterministic commitment tied to the prompt (placeholder for real trace merkle root).
                                    use sha2::{Digest as _, Sha256};
                                    let trace_root: [u8; 32] = Sha256::digest(prompt.as_bytes()).into();

                                    log::info!("========================================");
                                    log::info!("[p2p][ai] Llama3 Response: {}", resp);
                                    log::info!("========================================");

                                    // Encrypt response for the original requester (client ephemeral key).
                                    let mut resp_nonce12 = [0u8; 12];
                                    rand_core::OsRng.fill_bytes(&mut resp_nonce12);
                                    let (resp_ct, resp_mlkem_ct) = match crate::e2ee::encrypt_on_worker(&worker_sk, &client_eph_pk, &client_mlkem_pk, resp_nonce12, resp.as_bytes()) {
                                        Ok(v) => v,
                                        Err(_) => {
                                            log::error!("[p2p][e2ee] encrypt response failed");
                                            return;
                                        }
                                    };
                                    let worker_pk_b64 = crate::e2ee::encode_x25519_pub_b64(&PublicKey::from(&worker_sk));
                                    let resp_box = E2eeRespBoxV1 {
                                        worker_static_pub_b64: worker_pk_b64,
                                        mlkem_ciphertext_b64: crate::e2ee::encode_mlkem_b64(&resp_mlkem_ct),
                                        nonce12_b64: encode_nonce12(resp_nonce12),
                                        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(resp_ct),
                                    };
                                    let resp_box_bytes = match serde_json::to_vec(&resp_box) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            log::error!("[p2p][e2ee] response box json encode failed: {e}");
                                            return;
                                        }
                                    };
                                    let result = InferenceResult {
                                        target_sender_id: req.sender_id.clone(),
                                        ncu,
                                        cost_micro_tet,
                                        worker_id,
                                        encrypted_response_b64: base64::engine::general_purpose::STANDARD.encode(resp_box_bytes),
                                        receipt_b64,
                                        trace_root_b64: base64::engine::general_purpose::STANDARD.encode(trace_root),
                                        prompt_tokens: metrics.prompt_tokens,
                                        completion_tokens: metrics.completion_tokens,
                                        flops: flops_u64,
                                        energy_wh: metrics.energy_wh,
                                    };
                                    match serde_json::to_vec(&result) {
                                        Ok(bytes) => {
                                            if let Err(e) = tx2.send(P2pCommand::BroadcastInference { payload: bytes, ack: None }).await {
                                                log::error!("[p2p][worker] failed to broadcast result: {e}");
                                            }
                                        }
                                        Err(e) => log::error!("[p2p][worker] result json encode failed: {e}"),
                                    }
                                });
                                log::info!("[p2p][gossip] inference request from={propagation_source} bytes={}", message.data.len());
                                continue;
                            }

                            ParsedGossip::Result(res) => {
                                // Phase 1.6: E2EE routing guard — ignore results not meant for us.
                                if res.target_sender_id != local_worker_id {
                                    continue;
                                }
                                if res.receipt_b64.trim().is_empty() {
                                    log::error!(
                                        "[p2p][zk] missing receipt_b64 (no receipt = no payment). worker_id={}",
                                        res.worker_id
                                    );
                                    continue;
                                }
                                let (journal, proof_size) = match crate::zk_verifier::verify_and_extract_inference_journal_with_size(&res.receipt_b64) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        log::error!("[p2p][zk] verify/decode failed: {e}");
                                        (nexus_protocol::InferenceJournalV1 {
                                            worker_pubkey_bytes: [0u8; 32],
                                            prompt_hash: [0u8; 32],
                                            response_hash: [0u8; 32],
                                            cost_micro: 0,
                                        }, 0)
                                    }
                                };
                                if proof_size == 0 {
                                    log::error!(
                                        "[p2p][zk] Receipt verification FAILED. proof_size={} bytes worker_id={}",
                                        proof_size,
                                        res.worker_id
                                    );

                                    let do_slash = std::env::var("TET_ONCHAIN_SLASH")
                                        .ok()
                                        .as_deref()
                                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                                        .unwrap_or(false);
                                    if do_slash {
                                        let program_id = match crate::onchain::default_program_id() {
                                            Ok(v) => v,
                                            Err(e) => {
                                                log::error!("[onchain] default_program_id failed: {e}");
                                                continue;
                                            }
                                        };
                                        let admin_kp = match crate::onchain::load_worker_keypair_from_env() {
                                            Ok(v) => v,
                                            Err(e) => {
                                                log::error!("[onchain] load admin keypair failed: {e}");
                                                continue;
                                            }
                                        };

                                        let worker_pk: clone_solana_sdk::pubkey::Pubkey =
                                            match std::env::var("TET_ONCHAIN_SLASH_WORKER_PUBKEY")
                                                .ok()
                                                .filter(|s| !s.trim().is_empty())
                                                .unwrap_or_else(|| admin_kp.pubkey().to_string())
                                                .parse()
                                            {
                                                Ok(v) => v,
                                                Err(e) => {
                                                    log::error!("[onchain] bad TET_ONCHAIN_SLASH_WORKER_PUBKEY: {e}");
                                                    continue;
                                                }
                                            };

                                        let treasury: clone_solana_sdk::pubkey::Pubkey =
                                            match std::env::var("TET_ONCHAIN_TREASURY")
                                                .ok()
                                                .filter(|s| !s.trim().is_empty())
                                                .unwrap_or_else(|| admin_kp.pubkey().to_string())
                                                .parse()
                                            {
                                                Ok(v) => v,
                                                Err(e) => {
                                                    log::error!("[onchain] bad TET_ONCHAIN_TREASURY: {e}");
                                                    continue;
                                                }
                                            };

                                        if let Err(e) = crate::onchain::slash_bad_worker(
                                            &admin_kp,
                                            &worker_pk,
                                            &program_id,
                                            &treasury,
                                        ) {
                                            log::error!("[onchain] slash_bad_worker failed: {e}");
                                        }
                                    }
                                    continue;
                                }
                                log::info!("🛡️ [p2p][zk] ZK Receipt Verified! IMAGE_ID matched. Proof size: {} bytes", proof_size);

                                // STRICT: journal binds the worker identity.
                                {
                                    use sha2::{Digest as _, Sha256};
                                    let expected: [u8; 32] = Sha256::digest(res.worker_id.as_bytes()).into();
                                    if journal.worker_pubkey_bytes != expected {
                                        log::error!(
                                            "[p2p][zk] worker binding mismatch (journal != sha256(worker_id)) worker_id={}",
                                            res.worker_id
                                        );
                                        continue;
                                    }
                                }

                                // Decrypt response (only the original requester can).
                                        let boxed_bytes = match base64::engine::general_purpose::STANDARD
                                            .decode(res.encrypted_response_b64.as_bytes())
                                        {
                                            Ok(v) => v,
                                            Err(_) => {
                                                log::error!("[p2p][e2ee] bad encrypted_response_b64 (base64)");
                                                continue;
                                            }
                                        };
                                        let bx: E2eeRespBoxV1 = match serde_json::from_slice(&boxed_bytes) {
                                            Ok(v) => v,
                                            Err(e) => {
                                                log::error!("[p2p][e2ee] bad response box json: {e}");
                                                continue;
                                            }
                                        };
                                        log::debug!(
                                            "[p2p][e2ee] Raw CT B64 to decode (first 20 chars): {:.20}",
                                            bx.mlkem_ciphertext_b64.trim()
                                        );
                                        let mlkem_ct = match crate::e2ee::decode_mlkem_ct_b64(bx.mlkem_ciphertext_b64.trim()) {
                                            Ok(v) => v,
                                            Err(e) => {
                                                log::error!("[p2p][e2ee] decode_mlkem_ct_b64 failed: {:?}", e);
                                                continue;
                                            }
                                        };
                                        let nonce12 = match decode_nonce12(bx.nonce12_b64.trim()) {
                                            Some(v) => v,
                                            None => {
                                                log::error!("[p2p][e2ee] bad response nonce12");
                                                continue;
                                            }
                                        };
                                        let ct = match base64::engine::general_purpose::STANDARD.decode(bx.ciphertext_b64.as_bytes()) {
                                            Ok(v) => v,
                                            Err(_) => {
                                                log::error!("[p2p][e2ee] bad response ciphertext b64");
                                                continue;
                                            }
                                        };
                                        let worker_pk = match crate::e2ee::decode_x25519_pub_b64(bx.worker_static_pub_b64.trim()) {
                                            Ok(v) => v,
                                            Err(_) => {
                                                log::error!("[p2p][e2ee] bad worker static pubkey");
                                                continue;
                                            }
                                        };
                                        let client_sk_b64 = std::env::var("TET_X25519_STATIC_SK_B64").ok().unwrap_or_default();
                                        let client_sk = match crate::e2ee::decode_x25519_static_sk_b64(client_sk_b64.trim()) {
                                            Ok(v) => v,
                                            Err(_) => {
                                                log::error!("[p2p][e2ee] missing/invalid TET_X25519_STATIC_SK_B64 on client; cannot decrypt");
                                                continue;
                                            }
                                        };
                                        let client_mlkem_sk_b64 = std::env::var("TET_MLKEM_STATIC_SK_B64").ok().unwrap_or_default();
                                        let client_mlkem_sk = match crate::e2ee::decode_mlkem_sk_b64(client_mlkem_sk_b64.trim()) {
                                            Ok(v) => v,
                                            Err(_) => {
                                                log::error!("[p2p][e2ee] missing/invalid TET_MLKEM_STATIC_SK_B64 on client; cannot PQ-decrypt");
                                                continue;
                                            }
                                        };
                                        let pt = match crate::e2ee::decrypt_on_client(&client_sk, &worker_pk, &client_mlkem_sk, &mlkem_ct, nonce12, &ct) {
                                            Ok(v) => v,
                                            Err(e) => {
                                                log::error!("[p2p][e2ee] decrypt response failed: {e}");
                                                continue;
                                            }
                                        };
                                        let resp = String::from_utf8(pt).unwrap_or_else(|_| "<non-utf8>".to_string());

                                        // STRICT: journal binds the exact response contents.
                                        {
                                            use sha2::{Digest as _, Sha256};
                                            let actual: [u8; 32] = Sha256::digest(resp.as_bytes()).into();
                                            if journal.response_hash != actual {
                                                log::error!(
                                                    "[p2p][zk] Response hash mismatch! Rejecting payment. worker_id={}",
                                                    res.worker_id
                                                );
                                                continue;
                                            }
                                        }

                                        // Settle using ZK-bound cost; clamp by gossip envelope as defense-in-depth (matches worker receipt cap).
                                        let client = local_worker_id.trim();
                                        let worker = res.worker_id.trim();
                                        let cost = journal
                                            .cost_micro
                                            .max(1)
                                            .min(res.cost_micro_tet.max(1));
                                        if !client.is_empty() && !worker.is_empty() && client != worker {
                                            let burn_wallet = ledger.ai_burn_wallet();
                                            match ledger.settle_ai_utility_payment(client, worker, cost, &burn_wallet) {
                                                Ok((_w, _t, _b)) => {
                                                    log::info!("💸 [p2p][settlement] SETTLED gross={} Stevemon from {} to {} (ZK journal, micropayment cap)!", cost, client, worker);
                                                }
                                                Err(e) => {
                                                    log::error!("[p2p][settlement] settlement failed gross_micro={} from={} to={} err={e}", cost, client, worker);
                                                }
                                            }
                                        }

                                        // Phase 4.7: Store last verified inference for browser UI (trustless verification demo).
                                        let ui = UiLastInference {
                                            worker_id: res.worker_id.clone(),
                                            response: resp.clone(),
                                            receipt_b64: res.receipt_b64.clone(),
                                            trace_root_b64: res.trace_root_b64.clone(),
                                        };
                                        let tr = ui.trace_root_b64.clone();
                                        set_last_inference_for_ui(ui.clone());
                                        fulfill_inference_waiter(&tr, ui);

                                        log::info!("⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐");
                                        log::info!("[p2p][client] MISSION ACCOMPLISHED! AI Response: {}", resp);
                                        log::info!("⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐");
                                log::info!("[p2p][gossip] inference result from={propagation_source} bytes={}", message.data.len());
                                continue;
                            }
                            }
                    }
                    SwarmEvent::Behaviour(NexusEvent::Identify(ev)) => {
                        log::info!("Identify event: {:?}", ev);
                        if let identify::Event::Received { peer_id, info, .. } = ev {
                            for addr in info.listen_addrs {
                                swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .add_address(&peer_id, addr.clone());
                                let _ = ledger.save_peer(&peer_id, &addr);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NexusEvent::Autonat(autonat::Event::StatusChanged {
                        new: autonat::NatStatus::Public(addr),
                        ..
                    })) => {
                        log::info!("🌍 [p2p][autonat] PUBLIC IP DISCOVERED: {}", addr);
                    }
                    SwarmEvent::Behaviour(NexusEvent::Kademlia(e)) => {
                        log::info!("[p2p][kad] event={:?}", e);
                        if let kad::Event::RoutingUpdated { peer, addresses, .. } = &e {
                            for addr in addresses.iter() {
                                let _ = ledger.save_peer(peer, addr);
                            }
                        }
                        if let kad::Event::OutboundQueryProgressed { id, result, .. } = e {
                            log::info!("[p2p][kad] query={id:?} result={result:?}");
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

pub fn start_p2p_node(
    ledger: Arc<crate::ledger::Ledger>,
) -> anyhow::Result<(P2pClient, tokio::task::JoinHandle<()>)> {
    let (mut swarm, _peer_id) =
        build_basic_swarm().map_err(|e| anyhow::anyhow!("build_basic_swarm failed: {e}"))?;
    let listen: Multiaddr = std::env::var("TET_P2P_LISTEN")
        .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/0".to_string())
        .parse()
        .map_err(|e| anyhow::anyhow!("listen multiaddr parse failed: {e}"))?;
    // Start listening immediately (real networking side-effect).
    let _ = listen_on(&mut swarm, listen.clone())
        .map_err(|e| anyhow::anyhow!("listen_on failed: {e}"))?;

    // Phase 4.3: Also listen on WebRTC-direct (UDP) using the same port as TCP, when specified.
    // Example: /ip4/0.0.0.0/tcp/8002 -> /ip4/0.0.0.0/udp/8002/webrtc-direct
    if let Some(tcp_port) = listen.iter().find_map(|p| match p {
        Protocol::Tcp(port) if port != 0 => Some(port),
        _ => None,
    }) {
        let candidate_ports = [tcp_port, tcp_port.saturating_add(10_000)];
        let mut ok = false;
        for udp_port in candidate_ports {
            let webrtc_listen: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/webrtc-direct", udp_port)
                .parse()
                .map_err(|e| anyhow::anyhow!("webrtc listen multiaddr parse failed: {e}"))?;
            match swarm.listen_on(webrtc_listen.clone()) {
                Ok(_) => {
                    log::info!("[p2p][webrtc] listening addr={webrtc_listen}");
                    ok = true;
                    break;
                }
                Err(e) => {
                    log::warn!("[p2p][webrtc] listen_on failed addr={webrtc_listen} err={e:?}");
                }
            }
        }
        if !ok {
            log::error!("[p2p][webrtc] failed to bind any UDP port for webrtc-direct");
        }
    }

    // Phase 1.2: Multi-bootnode bootstrap strategy (`TET_BOOTNODES` | `BOOTNODES`).
    let bootnodes = {
        let v = crate::vision::fluid_net::bootnode_addrs_from_env();
        if v.is_empty() { None } else { Some(v) }
    };

    if let Some(nodes) = bootnodes {
        for (i, s) in nodes.into_iter().enumerate() {
            let addr: Multiaddr = s
                .parse()
                .map_err(|e| anyhow::anyhow!("TET_BOOTNODES multiaddr parse failed: {e}"))?;
            log::info!("[p2p] Dialing bootnode: {}", addr);
            if let Err(e) = swarm.dial(addr.clone()) {
                log::error!("[p2p] bootnode dial failed addr={addr} err={e}");
            }

            // Phase 4.1: For Workers/Clients behind NAT, reserve a slot on the first bootnode
            // and start listening on the relayed /p2p-circuit address so others can reach us.
            if i == 0 && !is_bootnode() {
                if let Some((base, bootnode_peer_id)) = split_p2p_peer(addr.clone()) {
                    // Ensure pubsub has at least one peer to graft to quickly.
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&bootnode_peer_id);

                    let mut relay_listen = base;
                    relay_listen.push(Protocol::P2p(bootnode_peer_id));
                    relay_listen.push(Protocol::P2pCircuit);
                    if let Err(e) = swarm.listen_on(relay_listen.clone()) {
                        log::error!(
                            "[p2p][relay] listen_on p2p-circuit failed addr={relay_listen} err={e}"
                        );
                    } else {
                        log::info!("[p2p][relay] listening via relay addr={relay_listen}");
                    }
                } else {
                    log::warn!(
                        "[p2p][relay] bootnode addr missing trailing /p2p/<peer_id>; cannot reserve/listen"
                    );
                }
            }
        }
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            log::error!("[p2p][kad] bootstrap failed: {e:?}");
        } else {
            log::info!("[p2p][kad] bootstrap started");
        }
    } else if let Ok(addr_str) = std::env::var("TET_DIAL_PEER") {
        // Back-compat single dial.
        let s = addr_str.trim();
        if !s.is_empty() {
            let addr: Multiaddr = s
                .parse()
                .map_err(|e| anyhow::anyhow!("TET_DIAL_PEER multiaddr parse failed: {e}"))?;
            log::info!("[p2p] Dialing explicit peer: {}", addr);
            if let Err(e) = swarm.dial(addr.clone()) {
                log::error!("[p2p] explicit dial failed addr={addr} err={e}");
            }

            // Phase 4.1: If the explicit dial includes a /p2p/<peer_id>, treat it as a relay
            // and listen on /p2p-circuit through it.
            if !is_bootnode() {
                if let Some((base, relay_peer_id)) = split_p2p_peer(addr.clone()) {
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&relay_peer_id);

                    let mut relay_listen = base;
                    relay_listen.push(Protocol::P2p(relay_peer_id));
                    relay_listen.push(Protocol::P2pCircuit);
                    if let Err(e) = swarm.listen_on(relay_listen.clone()) {
                        log::error!(
                            "[p2p][relay] listen_on p2p-circuit failed addr={relay_listen} err={e}"
                        );
                    } else {
                        log::info!("[p2p][relay] listening via relay addr={relay_listen}");
                    }
                } else {
                    log::warn!(
                        "[p2p][relay] TET_DIAL_PEER missing trailing /p2p/<peer_id>; skipping relay listen"
                    );
                }
            }
        }
    }

    // Semantic routing: advertise model capability in the DHT.
    let k: &[u8] = b"model:llama3-8b";
    let key = libp2p::kad::RecordKey::new(&k);
    if let Err(e) = swarm.behaviour_mut().kademlia.start_providing(key) {
        log::error!("[p2p][kad] start_providing failed: {e}");
    }

    let local_worker_id = std::env::var("TET_WALLET_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| swarm.local_peer_id().to_string());

    let (tx, rx) = mpsc::channel::<P2pCommand>(256);
    let loop_tx = tx.clone();
    let client = P2pClient { sender: tx };
    let h = tokio::spawn(async move {
        run_swarm_loop(swarm, ledger, local_worker_id, loop_tx, rx).await;
    });
    Ok((client, h))
}
