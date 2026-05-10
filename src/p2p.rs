//! Minimal local P2P "nervous system" (mDNS discovery + Ping liveness).
//!
//! Scope: establish that multiple nodes on the same LAN can discover and connect to each other.
//! No consensus, no application protocol.

use futures::StreamExt;
use libp2p::core::transport::Transport as _;
use libp2p::core::upgrade;
use libp2p::gossipsub;
use libp2p::identify;
use libp2p::identity;
use libp2p::kad;
use libp2p::mdns;
use libp2p::multiaddr::Protocol;
use libp2p::noise;
use libp2p::ping;
use libp2p::request_response;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::tcp;
use libp2p::yamux;
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};

use crate::models::NetworkEvent;
use crate::protocol::SignedTxEnvelopeV1;
use std::sync::Arc;

type AnyErr = Box<dyn Error + Send + Sync + 'static>;

pub const BLOCK_SYNC_PROTOCOL: &str = "/tet/v1/block-sync/json";
pub const DEFAULT_MAX_ORPHANS: usize = 256;
pub const DEFAULT_ORPHAN_TTL_MS: u64 = 10 * 60 * 1000;
pub const DEFAULT_MAX_BACKFILL_DEPTH: usize = 64;
const DEFAULT_BLACKLIST_MAX_PEERS: usize = 4096;
const DEFAULT_BLACKLIST_TTL_MS: u64 = 30 * 60 * 1000;
const DEFAULT_PENDING_BACKFILL_MAX: usize = 2048;
const DEFAULT_PENDING_BACKFILL_TTL_MS: u64 = 2 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockRequest {
    pub block_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub block_id: String,
    pub block: Option<crate::ledger::BlockRecordV1>,
}

#[derive(Debug, Clone)]
struct OrphanEntry {
    block: crate::ledger::BlockRecordV1,
    received_from: Option<PeerId>,
    depth: usize,
    inserted_at_ms: u64,
}

#[derive(Debug)]
pub struct OrphanBuffer {
    max_orphans: usize,
    ttl_ms: u64,
    entries: HashMap<String, OrphanEntry>,
    order: VecDeque<String>,
}

impl OrphanBuffer {
    pub fn new(max_orphans: usize, ttl_ms: u64) -> Self {
        Self {
            max_orphans: max_orphans.max(1),
            ttl_ms,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn insert(
        &mut self,
        block: crate::ledger::BlockRecordV1,
        received_from: Option<PeerId>,
        depth: usize,
        now_ms: u64,
    ) {
        self.prune_expired(now_ms);
        if self.entries.contains_key(&block.block_id) {
            self.entries.insert(
                block.block_id.clone(),
                OrphanEntry {
                    block,
                    received_from,
                    depth,
                    inserted_at_ms: now_ms,
                },
            );
            return;
        }
        self.order.push_back(block.block_id.clone());
        self.entries.insert(
            block.block_id.clone(),
            OrphanEntry {
                block,
                received_from,
                depth,
                inserted_at_ms: now_ms,
            },
        );
        while self.entries.len() > self.max_orphans {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }

    pub fn remove(&mut self, block_id: &str) -> Option<crate::ledger::BlockRecordV1> {
        self.entries.remove(block_id).map(|e| e.block)
    }

    pub fn children_of(
        &mut self,
        parent_id: &str,
        now_ms: u64,
    ) -> Vec<crate::ledger::BlockRecordV1> {
        self.prune_expired(now_ms);
        self.entries
            .values()
            .filter(|e| e.block.parent_block_id.as_deref() == Some(parent_id))
            .map(|e| e.block.clone())
            .collect()
    }

    pub fn depth_for(&self, block_id: &str) -> usize {
        self.entries.get(block_id).map(|e| e.depth).unwrap_or(0)
    }

    pub fn received_from(&self, block_id: &str) -> Option<PeerId> {
        self.entries.get(block_id).and_then(|e| e.received_from)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn prune_expired(&mut self, now_ms: u64) {
        if self.ttl_ms == 0 {
            return;
        }
        self.entries
            .retain(|_, e| now_ms.saturating_sub(e.inserted_at_ms) <= self.ttl_ms);
        self.order.retain(|id| self.entries.contains_key(id));
    }
}

#[derive(Debug)]
struct BoundedPeerBlacklist {
    max_peers: usize,
    ttl_ms: u64,
    entries: HashMap<PeerId, u64>,
    order: VecDeque<PeerId>,
}

impl BoundedPeerBlacklist {
    fn from_env() -> Self {
        let max_peers = std::env::var("TET_P2P_BLACKLIST_MAX_PEERS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(DEFAULT_BLACKLIST_MAX_PEERS)
            .max(1);
        let ttl_ms = std::env::var("TET_P2P_BLACKLIST_TTL_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_BLACKLIST_TTL_MS);
        Self {
            max_peers,
            ttl_ms,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn insert(&mut self, peer: PeerId, now_ms: u64) {
        self.prune(now_ms);
        if !self.entries.contains_key(&peer) {
            self.order.push_back(peer);
        }
        self.entries.insert(peer, now_ms);
        while self.entries.len() > self.max_peers {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn contains(&mut self, peer: &PeerId, now_ms: u64) -> bool {
        self.prune(now_ms);
        self.entries.contains_key(peer)
    }

    fn prune(&mut self, now_ms: u64) {
        if self.ttl_ms > 0 {
            self.entries
                .retain(|_, inserted| now_ms.saturating_sub(*inserted) <= self.ttl_ms);
        }
        self.order.retain(|peer| self.entries.contains_key(peer));
    }
}

#[derive(Debug, Clone)]
struct PendingBackfillEntry {
    block_id: String,
    depth: usize,
    inserted_at_ms: u64,
}

fn pending_backfill_max_from_env() -> usize {
    std::env::var("TET_PENDING_BACKFILL_MAX")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_PENDING_BACKFILL_MAX)
        .max(1)
}

fn pending_backfill_ttl_ms_from_env() -> u64 {
    std::env::var("TET_PENDING_BACKFILL_TTL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_PENDING_BACKFILL_TTL_MS)
}

fn prune_pending_backfill(
    pending: &mut HashMap<request_response::OutboundRequestId, PendingBackfillEntry>,
    now_ms: u64,
    max_entries: usize,
    ttl_ms: u64,
) {
    if ttl_ms > 0 {
        pending.retain(|_, e| now_ms.saturating_sub(e.inserted_at_ms) <= ttl_ms);
    }
    if pending.len() <= max_entries {
        return;
    }
    let mut by_age = pending
        .iter()
        .map(|(id, e)| (*id, e.inserted_at_ms))
        .collect::<Vec<_>>();
    by_age.sort_by_key(|(_, ts)| *ts);
    for (id, _) in by_age.into_iter().take(pending.len() - max_entries) {
        pending.remove(&id);
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
struct TetBehaviour {
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    block_sync: request_response::json::Behaviour<BlockRequest, BlockResponse>,
}

#[derive(Debug)]
enum Event {
    Mdns(mdns::Event),
    Ping(ping::Event),
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Kademlia(kad::Event),
    BlockSync(request_response::Event<BlockRequest, BlockResponse>),
}

impl From<mdns::Event> for Event {
    fn from(e: mdns::Event) -> Self {
        Self::Mdns(e)
    }
}
impl From<ping::Event> for Event {
    fn from(e: ping::Event) -> Self {
        Self::Ping(e)
    }
}
impl From<gossipsub::Event> for Event {
    fn from(e: gossipsub::Event) -> Self {
        Self::Gossipsub(e)
    }
}
impl From<identify::Event> for Event {
    fn from(e: identify::Event) -> Self {
        Self::Identify(e)
    }
}
impl From<kad::Event> for Event {
    fn from(e: kad::Event) -> Self {
        Self::Kademlia(e)
    }
}
impl From<request_response::Event<BlockRequest, BlockResponse>> for Event {
    fn from(e: request_response::Event<BlockRequest, BlockResponse>) -> Self {
        Self::BlockSync(e)
    }
}

pub const BLOCKS_TOPIC: &str = "/tet/v1/blocks";
pub const TXS_TOPIC: &str = "/tet/v1/txs";
pub const AI_WORKLOAD_TOPIC: &str = "/tet/v1/ai-workload";
#[deprecated(note = "Use sharded /tet/v1/* topics")]
pub const GLOBAL_STATE_TOPIC: &str = "tet-global-state";
pub const DEFAULT_GLOBAL_GOSSIP_MAX_MSG_BYTES: usize = 128 * 1024;

fn global_gossip_max_msg_bytes() -> usize {
    std::env::var("TET_P2P_GOSSIP_MAX_MSG_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|n| n.clamp(48 * 1024, 512 * 1024))
        .unwrap_or(DEFAULT_GLOBAL_GOSSIP_MAX_MSG_BYTES)
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn block_sync_behaviour() -> request_response::json::Behaviour<BlockRequest, BlockResponse> {
    request_response::json::Behaviour::new(
        [(
            StreamProtocol::new(BLOCK_SYNC_PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(20)),
    )
}

fn orphan_buffer_from_env() -> OrphanBuffer {
    let max_orphans = std::env::var("TET_P2P_MAX_ORPHANS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_ORPHANS);
    let ttl_ms = std::env::var("TET_P2P_ORPHAN_TTL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_ORPHAN_TTL_MS);
    OrphanBuffer::new(max_orphans, ttl_ms)
}

fn max_backfill_depth_from_env() -> usize {
    std::env::var("TET_P2P_MAX_BACKFILL_DEPTH")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_BACKFILL_DEPTH)
        .max(1)
}

fn local_node_wants_ai_workload() -> bool {
    crate::vision::caac::profile().role == crate::vision::caac::NodeRelayRole::Poc
}

fn network_event_topics(
    msg: &str,
    blocks_topic: &gossipsub::IdentTopic,
    txs_topic: &gossipsub::IdentTopic,
    ai_topic: &gossipsub::IdentTopic,
) -> Vec<gossipsub::IdentTopic> {
    match serde_json::from_str::<NetworkEvent>(msg) {
        Ok(NetworkEvent::BlockMined { txs, .. }) => {
            let mut topics = vec![blocks_topic.clone()];
            if txs
                .iter()
                .any(|env| matches!(env.tx, crate::protocol::TxV1::EnterpriseInference { .. }))
            {
                topics.push(ai_topic.clone());
            }
            topics
        }
        Ok(NetworkEvent::TransferExecuted { .. }) | Ok(NetworkEvent::FaucetExecuted { .. }) => {
            vec![txs_topic.clone()]
        }
        Err(_) => vec![txs_topic.clone()],
    }
}

/// Start a libp2p swarm task and return a Sender you can use to publish gossip messages.
pub fn start_mdns_ping_swarm(
    ledger: Arc<crate::ledger::Ledger>,
    mempool: Arc<Mutex<Vec<SignedTxEnvelopeV1>>>,
) -> Result<mpsc::Sender<String>, AnyErr> {
    let (tx, rx) = mpsc::channel::<String>(256);
    tokio::spawn(async move {
        if let Err(e) = run_mdns_ping_swarm(ledger, mempool, rx).await {
            println!("[P2P] Swarm task exited: {e}");
            log::warn!("[p2p][mdns] swarm exited: {e}");
        }
    });
    Ok(tx)
}

/// Run a libp2p swarm that:
/// - listens on `/ip4/0.0.0.0/tcp/0` (port auto-assigned)
/// - discovers peers via mDNS
/// - dials discovered peers automatically
/// - sends ping keepalives and logs RTT / failures
async fn run_mdns_ping_swarm(
    ledger: Arc<crate::ledger::Ledger>,
    mempool: Arc<Mutex<Vec<SignedTxEnvelopeV1>>>,
    mut publish_rx: mpsc::Receiver<String>,
) -> Result<(), AnyErr> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    log::info!("[P2P] My Peer ID: {peer_id}");

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&keypair)?)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed();

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;
    let ping = ping::Behaviour::new(
        ping::Config::new()
            .with_interval(Duration::from_secs(10))
            .with_timeout(Duration::from_secs(20)),
    );

    let max_gossip_bytes = global_gossip_max_msg_bytes();
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .validate_messages()
        .max_transmit_size(max_gossip_bytes)
        .mesh_n(6)
        .mesh_n_low(4)
        .mesh_n_high(12)
        .heartbeat_interval(Duration::from_millis(800))
        .max_messages_per_rpc(Some(32))
        .build()
        .map_err(|e| -> AnyErr { format!("gossipsub config: {e}").into() })?;
    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| -> AnyErr { format!("gossipsub init: {e}").into() })?;
    let mut score_params = gossipsub::PeerScoreParams::default();
    let topic_scoring = gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        invalid_message_deliveries_weight: -22.0,
        invalid_message_deliveries_decay: 0.88,
        ..Default::default()
    };
    for topic in [BLOCKS_TOPIC, TXS_TOPIC, AI_WORKLOAD_TOPIC] {
        score_params.topics.insert(
            gossipsub::IdentTopic::new(topic).hash(),
            topic_scoring.clone(),
        );
    }
    score_params.app_specific_weight = 12.0;
    score_params.behaviour_penalty_weight = -10.0;
    score_params.behaviour_penalty_threshold = 1.0;
    let score_thresholds = gossipsub::PeerScoreThresholds {
        gossip_threshold: -6.0,
        publish_threshold: -45.0,
        graylist_threshold: -62.0,
        ..Default::default()
    };
    score_params
        .validate()
        .map_err(|e| -> AnyErr { format!("gossipsub peer score params: {e}").into() })?;
    score_thresholds
        .validate()
        .map_err(|e| -> AnyErr { format!("gossipsub peer score thresholds: {e}").into() })?;
    gossipsub
        .with_peer_score(score_params, score_thresholds)
        .map_err(|e| -> AnyErr { format!("gossipsub peer score init failed: {e:?}").into() })?;

    let identify = identify::Behaviour::new(
        identify::Config::new("/tet/identify/1.0.0".to_string(), keypair.public())
            .with_agent_version(format!("tet-core/{}", env!("CARGO_PKG_VERSION"))),
    );

    let store = kad::store::MemoryStore::new(peer_id);
    let mut kademlia = kad::Behaviour::new(peer_id, store);
    kademlia.set_mode(Some(kad::Mode::Server));

    let behaviour = TetBehaviour {
        mdns,
        ping,
        gossipsub,
        identify,
        kademlia,
        block_sync: block_sync_behaviour(),
    };
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    println!("[P2P] My Peer ID: {}", swarm.local_peer_id());
    log::info!("[P2P] My Peer ID: {}", swarm.local_peer_id());

    let blocks_topic = gossipsub::IdentTopic::new(BLOCKS_TOPIC);
    let txs_topic = gossipsub::IdentTopic::new(TXS_TOPIC);
    let ai_workload_topic = gossipsub::IdentTopic::new(AI_WORKLOAD_TOPIC);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&blocks_topic)
        .expect("Failed to subscribe to blocks topic");
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&txs_topic)
        .expect("Failed to subscribe to txs topic");
    let wants_ai_workload = local_node_wants_ai_workload();
    let ai_workload_topic_hash = ai_workload_topic.hash();
    if wants_ai_workload {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&ai_workload_topic)
            .expect("Failed to subscribe to ai-workload topic");
        println!("[P2P] Subscribed to AI workload topic as PoC");
    } else {
        println!("[P2P] PoR mode: not subscribing to AI workload topic");
    }
    println!("[P2P] Subscribed to sharded topics: {BLOCKS_TOPIC}, {TXS_TOPIC}");

    if let Ok(external) = std::env::var("TET_EXTERNAL_ADDR")
        && !external.trim().is_empty()
    {
        match external.trim().parse::<Multiaddr>() {
            Ok(addr) => {
                swarm.add_external_address(addr.clone());
                println!("[P2P] Advertising external address: {addr}");
            }
            Err(e) => println!("[P2P] Invalid TET_EXTERNAL_ADDR ignored: {external} ({e})"),
        }
    }

    let bootnodes = crate::vision::fluid_net::bootnode_addrs_from_env();
    if !bootnodes.is_empty() {
        println!(
            "[P2P] Found TET_BOOTNODES/BOOTNODES: {} entries",
            bootnodes.len()
        );
        for raw in bootnodes {
            match raw.parse::<Multiaddr>() {
                Ok(addr) => {
                    if let Some((dial_addr, pid)) = split_p2p_peer(addr.clone()) {
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&pid, dial_addr.clone());
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                        println!("[P2P] Bootnode added to Kademlia: peer={pid} addr={dial_addr}");
                    }
                    match swarm.dial(addr.clone()) {
                        Ok(()) => println!("[P2P] Dialing bootnode: {addr}"),
                        Err(e) => println!("[P2P] Bootnode dial failed: {addr} ({e})"),
                    }
                }
                Err(e) => println!("[P2P] Invalid bootnode ignored: {raw} ({e})"),
            }
        }
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            println!("[P2P] ❌ Kademlia bootstrap failed: {:?}", e);
        } else {
            println!("[P2P] ✅ Kademlia bootstrap started");
        }
    } else {
        println!("[P2P] No TET_BOOTNODES provided. Running as an isolated node.");
    }

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>()?)?;

    let mut dialing: HashSet<PeerId> = HashSet::new();
    let mut orphan_buffer = orphan_buffer_from_env();
    let max_backfill_depth = max_backfill_depth_from_env();
    let pending_backfill_max = pending_backfill_max_from_env();
    let pending_backfill_ttl_ms = pending_backfill_ttl_ms_from_env();
    let mut pending_backfill: HashMap<request_response::OutboundRequestId, PendingBackfillEntry> =
        HashMap::new();
    let mut blacklisted_peers = BoundedPeerBlacklist::from_env();
    loop {
        tokio::select! {
            maybe_msg = publish_rx.recv() => {
                let now = now_ms();
                blacklisted_peers.prune(now);
                prune_pending_backfill(&mut pending_backfill, now, pending_backfill_max, pending_backfill_ttl_ms);
                if let Some(msg) = maybe_msg {
                    if msg.len() > max_gossip_bytes {
                        crate::metrics::inc_gossip_rejected();
                        println!(
                            "[P2P] ❌ GOSSIP PUBLISH REJECTED: message too large bytes={} cap={}",
                            msg.len(),
                            max_gossip_bytes
                        );
                        continue;
                    }
                    let topics = network_event_topics(&msg, &blocks_topic, &txs_topic, &ai_workload_topic);
                    for topic in topics {
                        match swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), msg.as_bytes())
                        {
                            Ok(_msg_id) => {
                                println!("[P2P] 📣 GOSSIP PUBLISHED topic={} msg={}", topic.hash(), msg);
                            }
                            Err(e) => {
                                println!("[P2P] ❌ GOSSIP PUBLISH ERROR topic={} err={:?}", topic.hash(), e);
                            }
                        }
                    }
                } else {
                    println!("[P2P] publish channel closed; stopping swarm.");
                    break;
                }
            }
            ev = swarm.select_next_some() => match ev {
            SwarmEvent::NewListenAddr { address, .. } => {
                log::info!("[p2p][mdns] listen_addr={address}");
            }
            SwarmEvent::Behaviour(Event::Mdns(mdns::Event::Discovered(peers))) => {
                for (pid, addr) in peers {
                    if pid == *swarm.local_peer_id() {
                        continue;
                    }
                    if dialing.contains(&pid) {
                        continue;
                    }
                    dialing.insert(pid);
                    log::info!("[p2p][mdns] discovered peer_id={pid} addr={addr}");
                    swarm.behaviour_mut().kademlia.add_address(&pid, addr.clone());
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                    let _ = swarm.dial(addr);
                }
            }
            SwarmEvent::Behaviour(Event::Mdns(mdns::Event::Expired(peers))) => {
                for (pid, addr) in peers {
                    log::debug!("[p2p][mdns] expired peer_id={pid} addr={addr}");
                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&pid);
                    dialing.remove(&pid);
                }
            }
            SwarmEvent::Behaviour(Event::Identify(identify::Event::Received { peer_id, info, .. })) => {
                for a in info.listen_addrs {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, a.clone());
                }
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                println!("[P2P] 🪪 IDENTIFY RECEIVED from {}", peer_id);
            }
            SwarmEvent::Behaviour(Event::Kademlia(ev)) => {
                // Keep it noisy for debugging while stabilizing Phase 2 network discovery.
                log::debug!("[p2p][kad] event={ev:?}");
            }
            SwarmEvent::Behaviour(Event::BlockSync(ev)) => {
                match ev {
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    } => {
                        let block = ledger
                            .block_record_by_id(&request.block_id)
                            .ok()
                            .flatten();
                        let _ = swarm.behaviour_mut().block_sync.send_response(
                            channel,
                            BlockResponse {
                                block_id: request.block_id,
                                block,
                            },
                        );
                        println!("[P2P] ↩️ BLOCK RESPONSE SENT to {}", peer);
                    }
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    } => {
                        let Some(pending_req) = pending_backfill.remove(&request_id) else {
                            continue;
                        };
                        let requested_id = pending_req.block_id;
                        let depth = pending_req.depth;
                        if requested_id != response.block_id {
                            blacklisted_peers.insert(peer, now_ms());
                            println!(
                                "[P2P] ❌ BLOCK RESPONSE REJECTED peer={} requested={} got={}",
                                peer, requested_id, response.block_id
                            );
                            continue;
                        }
                        let Some(block) = response.block else {
                            blacklisted_peers.insert(peer, now_ms());
                            println!(
                                "[P2P] ❌ BLOCK RESPONSE EMPTY peer={} block={}",
                                peer, response.block_id
                            );
                            continue;
                        };
                        let gossip = crate::consensus::RemoteBlockGossip {
                            block_height: block.height,
                            block_id: block.block_id.clone(),
                            parent_block_id: block.parent_block_id.clone(),
                            producer_id: block.producer_id.clone(),
                            base_reward_micro: block.reward.base_reward_micro,
                            compute_reward_micro: block.reward.compute_reward_micro,
                            total_reward_micro: block.reward.total_reward_micro,
                            state_root: block.state_root.clone(),
                            txs: block.txs.clone(),
                        };
                        let stored = match crate::consensus::validate_and_record_backfill_candidate(
                            ledger.as_ref(),
                            gossip,
                        ) {
                            Ok(stored) => stored,
                            Err(e) => {
                                blacklisted_peers.insert(peer, now_ms());
                                println!(
                                    "[P2P] ❌ BACKFILLED BLOCK REJECTED peer={} err={}",
                                    peer,
                                    e.message()
                                );
                                continue;
                            }
                        };
                        if let Some(parent_id) = stored.parent_block_id.as_deref()
                            && ledger
                                .block_record_by_id(parent_id)
                                .map(|b| b.is_none())
                                .unwrap_or(true)
                        {
                            if depth >= max_backfill_depth {
                                blacklisted_peers.insert(peer, now_ms());
                                println!(
                                    "[P2P] ❌ BACKFILL DEPTH LIMIT peer={} block={} depth={} max={}",
                                    peer, stored.block_id, depth, max_backfill_depth
                                );
                                continue;
                            }
                            let rid = swarm
                                .behaviour_mut()
                                .block_sync
                                .send_request(&peer, BlockRequest { block_id: parent_id.to_string() });
                            prune_pending_backfill(&mut pending_backfill, now_ms(), pending_backfill_max, pending_backfill_ttl_ms);
                            pending_backfill.insert(
                                rid,
                                PendingBackfillEntry {
                                    block_id: parent_id.to_string(),
                                    depth: depth + 1,
                                    inserted_at_ms: now_ms(),
                                },
                            );
                            println!(
                                "[P2P] 🧩 BACKFILL RECURSE block={} missing_parent={} depth={}",
                                stored.block_id,
                                parent_id,
                                depth + 1
                            );
                            continue;
                        }

                        let mut candidates = orphan_buffer.children_of(&stored.block_id, now_ms());
                        candidates.push(stored.clone());
                        for candidate in candidates {
                            match crate::consensus::try_reorg_backfilled_branch(
                                ledger.as_ref(),
                                &candidate.block_id,
                            ) {
                                Ok(true) => {
                                    orphan_buffer.remove(&candidate.block_id);
                                    println!(
                                        "[P2P] ✅ BACKFILLED BRANCH REORG APPLIED tip={}",
                                        candidate.block_id
                                    );
                                }
                                Ok(false) => {
                                    println!(
                                        "[P2P] ⏭️ BACKFILLED BRANCH DID NOT WIN tip={}",
                                        candidate.block_id
                                    );
                                }
                                Err(e) => {
                                    blacklisted_peers.insert(peer, now_ms());
                                    println!(
                                        "[P2P] ❌ BACKFILLED REORG FAILED tip={} err={}",
                                        candidate.block_id, e
                                    );
                                }
                            }
                        }
                    }
                    request_response::Event::OutboundFailure {
                        peer,
                        request_id,
                        error,
                        ..
                    } => {
                        pending_backfill.remove(&request_id);
                        println!(
                            "[P2P] ❌ BLOCK REQUEST FAILED peer={} err={:?}",
                            peer, error
                        );
                    }
                    request_response::Event::InboundFailure { peer, error, .. } => {
                        println!(
                            "[P2P] ❌ BLOCK REQUEST INBOUND FAILURE peer={} err={:?}",
                            peer, error
                        );
                    }
                    request_response::Event::ResponseSent { peer, .. } => {
                        log::debug!("[p2p][block-sync] response_sent peer={peer}");
                    }
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                println!("[P2P] CONNECTION ESTABLISHED with {}", peer_id);
                log::info!(
                    "[p2p][mdns] connected peer_id={} endpoint={:?}",
                    peer_id,
                    endpoint.get_remote_address()
                );
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                log::warn!("[p2p][mdns] disconnected peer_id={peer_id} cause={cause:?}");
                dialing.remove(&peer_id);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                println!("[P2P] DIAL ERROR to {:?}: {:?}", peer_id, error);
                log::warn!("[p2p][mdns] outgoing error peer_id={peer_id:?} err={error}");
                if let Some(pid) = peer_id {
                    dialing.remove(&pid);
                }
            }
            SwarmEvent::IncomingConnectionError { send_back_addr, error, .. } => {
                log::warn!(
                    "[p2p][mdns] incoming error from_addr={send_back_addr} err={error}"
                );
            }
            SwarmEvent::Behaviour(Event::Gossipsub(gossipsub::Event::Message { message_id, message, .. })) => {
                let source_peer = message.source;
                if message.data.len() > max_gossip_bytes {
                    if let Some(source) = source_peer.as_ref() {
                        let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                            &message_id,
                            source,
                            gossipsub::MessageAcceptance::Reject,
                        );
                    }
                    println!(
                        "[P2P] ❌ GOSSIP REJECTED: oversize bytes={} cap={}",
                        message.data.len(),
                        max_gossip_bytes
                    );
                    continue;
                }
                let message_data = String::from_utf8_lossy(&message.data);
                if message.topic == ai_workload_topic_hash && !wants_ai_workload {
                    let parsed = serde_json::from_str::<NetworkEvent>(&message_data).is_ok();
                    if let Some(source) = source_peer.as_ref() {
                        let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                            &message_id,
                            source,
                            if parsed {
                                gossipsub::MessageAcceptance::Accept
                            } else {
                                gossipsub::MessageAcceptance::Reject
                            },
                        );
                    }
                    println!("[P2P] PoR bandwidth guard: validated AI workload gossip without applying");
                    continue;
                }
                match serde_json::from_str::<NetworkEvent>(&message_data) {
                    Ok(event) => {
                        if let Some(source) = source_peer.as_ref() {
                            let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                &message_id,
                                source,
                                gossipsub::MessageAcceptance::Accept,
                            );
                        }
                        match &event {
                            NetworkEvent::FaucetExecuted {
                                event_id,
                                to_wallet,
                                amount_micro,
                            } => {
                                println!(
                                    "[P2P] 🔄 STATE SYNC DETECTED: FaucetExecuted {{ event_id: {:?}, to_wallet: {:?}, amount_micro: {:?} }}",
                                    event_id, to_wallet, amount_micro
                                );
                            }
                            other => {
                                println!("[P2P] 🔄 STATE SYNC DETECTED: {:?}", other);
                            }
                        }
                        match event {
                            NetworkEvent::BlockMined {
                                block_height,
                                block_id,
                                parent_block_id,
                                producer_id,
                                base_reward_micro,
                                compute_reward_micro,
                                total_reward_micro,
                                state_root,
                                txs,
                            } => {
                                let gossip = crate::consensus::RemoteBlockGossip {
                                    block_height,
                                    block_id: block_id.clone(),
                                    parent_block_id: parent_block_id.clone(),
                                    producer_id: producer_id.clone(),
                                    base_reward_micro,
                                    compute_reward_micro,
                                    total_reward_micro,
                                    state_root: state_root.clone(),
                                    txs: txs.clone(),
                                };
                                if let Some(parent_id) = parent_block_id.as_deref()
                                    && ledger
                                        .block_record_by_id(parent_id)
                                        .map(|b| b.is_none())
                                        .unwrap_or(true)
                                {
                                    match crate::consensus::validate_and_record_backfill_candidate(
                                        ledger.as_ref(),
                                        gossip,
                                    ) {
                                        Ok(candidate) => {
                                            let now = now_ms();
                                            orphan_buffer.insert(
                                                candidate.clone(),
                                                source_peer,
                                                0,
                                                now,
                                            );
                                            if let Some(peer) = source_peer
                                                && !blacklisted_peers.contains(&peer, now)
                                                && max_backfill_depth > 0
                                            {
                                                let req = BlockRequest {
                                                    block_id: parent_id.to_string(),
                                                };
                                                let rid = swarm
                                                    .behaviour_mut()
                                                    .block_sync
                                                    .send_request(&peer, req);
                                                prune_pending_backfill(&mut pending_backfill, now, pending_backfill_max, pending_backfill_ttl_ms);
                                                pending_backfill.insert(
                                                    rid,
                                                    PendingBackfillEntry {
                                                        block_id: parent_id.to_string(),
                                                        depth: 1,
                                                        inserted_at_ms: now,
                                                    },
                                                );
                                                println!(
                                                    "[P2P] 🕳️ ORPHAN BLOCK BUFFERED block={} missing_parent={} request_peer={}",
                                                    candidate.block_id, parent_id, peer
                                                );
                                            } else {
                                                println!(
                                                    "[P2P] 🕳️ ORPHAN BLOCK BUFFERED block={} missing_parent={} no_source_peer",
                                                    candidate.block_id, parent_id
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            if let Some(peer) = source_peer {
                                                blacklisted_peers.insert(peer, now_ms());
                                            }
                                            println!(
                                                "[P2P] ❌ ORPHAN CANDIDATE REJECTED: {}",
                                                e.message()
                                            );
                                        }
                                    }
                                    continue;
                                }
                                match crate::consensus::apply_remote_block_from_gossip(
                                    ledger.clone(),
                                    mempool.clone(),
                                    gossip,
                                )
                                .await
                                {
                                    Ok(crate::consensus::RemoteBlockApplyOutcome::Applied {
                                        block_height,
                                        tx_count,
                                        evicted_count,
                                        state_root,
                                    }) => {
                                        println!(
                                            "[P2P] ✅ REMOTE BLOCK APPLIED height={} tx_count={} evicted_mempool={} state_root={}",
                                            block_height, tx_count, evicted_count, state_root
                                        );
                                    }
                                    Ok(crate::consensus::RemoteBlockApplyOutcome::ForkLost {
                                        reason,
                                    }) => {
                                        println!("[P2P] ⚠️ REMOTE FORK WINS BUT REORG UNSUPPORTED: {}", reason);
                                    }
                                    Ok(crate::consensus::RemoteBlockApplyOutcome::Skipped {
                                        reason,
                                    }) => {
                                        println!("[P2P] ⏭️ REMOTE BLOCK SKIPPED: {}", reason);
                                    }
                                    Err(e) => {
                                        println!(
                                            "[P2P] ❌ REMOTE BLOCK REJECTED: {}",
                                            e.message()
                                        );
                                    }
                                }
                            }
                            other => match ledger.apply_remote_event(&other) {
                                Ok(true) => {
                                    println!("[P2P] ✅ REMOTE EVENT APPLIED to local ledger");
                                }
                                Ok(false) => {
                                    println!("[P2P] ⏭️ REMOTE EVENT ALREADY APPLIED (idempotent)");
                                }
                                Err(e) => {
                                    println!("[P2P] ❌ REMOTE EVENT APPLY FAILED: {}", e);
                                }
                            },
                        }
                    }
                    Err(e) => {
                        if let Some(source) = source_peer.as_ref() {
                            let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                &message_id,
                                source,
                                gossipsub::MessageAcceptance::Reject,
                            );
                        }
                        println!(
                            "[P2P] 📢 GOSSIP RECEIVED (unparsed): {} (err={})",
                            message_data, e
                        );
                    }
                }
            }
            SwarmEvent::Behaviour(Event::Ping(ev)) => {
                let ping::Event { peer, result, .. } = ev;
                match result {
                    Ok(rtt) => {
                        println!(
                            "[P2P] PING OK peer_id={} rtt_ms={}",
                            peer,
                            rtt.as_millis()
                        );
                        log::debug!(
                            "[p2p][mdns] ping_ok peer_id={peer} rtt_ms={}",
                            rtt.as_millis()
                        );
                    }
                    Err(e) => {
                        println!("[P2P] PING FAIL peer_id={} err={}", peer, e);
                        log::warn!("[p2p][mdns] ping_fail peer_id={peer} err={e}");
                    }
                }
            }
            _ => {}
        }}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::transport::MemoryTransport;
    use libp2p::swarm::SwarmEvent;
    use tokio::time::{Duration as TokioDuration, timeout};

    fn build_memory_swarm() -> Swarm<TetBehaviour> {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let transport = MemoryTransport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair).expect("noise config"))
            .multiplex(yamux::Config::default())
            .timeout(Duration::from_secs(20))
            .boxed();

        let mdns =
            mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id).expect("mdns behaviour");
        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(Duration::from_secs(10))
                .with_timeout(Duration::from_secs(20)),
        );
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .validation_mode(gossipsub::ValidationMode::Strict)
            .validate_messages()
            .max_transmit_size(DEFAULT_GLOBAL_GOSSIP_MAX_MSG_BYTES)
            // Tests should not depend on heartbeat/mesh timing.
            .flood_publish(true)
            .build()
            .expect("gossipsub config");
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .expect("gossipsub behaviour");

        let identify = identify::Behaviour::new(
            identify::Config::new("/tet/identify/1.0.0".to_string(), keypair.public())
                .with_agent_version(format!("tet-core/{}", env!("CARGO_PKG_VERSION"))),
        );

        let store = kad::store::MemoryStore::new(peer_id);
        let mut kademlia = kad::Behaviour::new(peer_id, store);
        kademlia.set_mode(Some(kad::Mode::Server));

        let behaviour = TetBehaviour {
            mdns,
            ping,
            gossipsub,
            identify,
            kademlia,
            block_sync: block_sync_behaviour(),
        };

        Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        )
    }

    #[tokio::test]
    async fn tetbehaviour_gossipsub_message_propagates_between_two_swarms() {
        let mut a = build_memory_swarm();
        let mut b = build_memory_swarm();

        let ident_topic = gossipsub::IdentTopic::new(BLOCKS_TOPIC);
        let topic_hash = ident_topic.hash();
        a.behaviour_mut()
            .gossipsub
            .subscribe(&ident_topic)
            .expect("sub A");
        b.behaviour_mut()
            .gossipsub
            .subscribe(&ident_topic)
            .expect("sub B");

        // Listen on deterministic memory addrs and dial.
        let a_addr: Multiaddr = "/memory/10001".parse().unwrap();
        a.listen_on(a_addr.clone()).unwrap();
        b.listen_on("/memory/10002".parse().unwrap()).unwrap();
        b.dial(a_addr).unwrap();

        // Drive both swarms until connected and message received.
        let a_peer = *a.local_peer_id();
        let b_peer = *b.local_peer_id();
        let payload = br#"{"kind":"block_mined","block_height":1,"block_id":"t","txs":[]}"#;

        let fut = async {
            let mut a_connected = false;
            let mut b_connected = false;
            let mut a_saw_b_sub = false;
            let mut published = false;
            loop {
                tokio::select! {
                    ev = a.select_next_some() => {
                        match ev {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                if peer_id == b_peer {
                                    a_connected = true;
                                    a.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                }
                            }
                            SwarmEvent::Behaviour(Event::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                                if peer_id == b_peer && topic == topic_hash {
                                    a_saw_b_sub = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    ev = b.select_next_some() => {
                        match ev {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                if peer_id == a_peer {
                                    b_connected = true;
                                    b.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                }
                            }
                            SwarmEvent::Behaviour(Event::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                                assert_eq!(message.data, payload);
                                return;
                            }
                            _ => {}
                        }
                    }
                }

                if a_connected && b_connected && a_saw_b_sub && !published {
                    // Publish only after B's subscription is observed to avoid `InsufficientPeers`.
                    a.behaviour_mut()
                        .gossipsub
                        .publish(ident_topic.clone(), payload)
                        .expect("publish");
                    published = true;
                }
            }
        };

        timeout(TokioDuration::from_secs(6), fut)
            .await
            .expect("timeout waiting for gossipsub message");
    }

    #[tokio::test]
    async fn memory_transport_block_request_response_round_trips() {
        let mut a = build_memory_swarm();
        let mut b = build_memory_swarm();

        let a_addr: Multiaddr = "/memory/10011".parse().unwrap();
        a.listen_on(a_addr.clone()).unwrap();
        b.listen_on("/memory/10012".parse().unwrap()).unwrap();
        b.dial(a_addr).unwrap();

        let a_peer = *a.local_peer_id();
        let b_peer = *b.local_peer_id();
        let wanted = "0xmissing-parent".to_string();

        let fut = async {
            let mut request_sent = false;
            loop {
                tokio::select! {
                    ev = a.select_next_some() => match ev {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == b_peer && !request_sent => {
                            a.behaviour_mut().block_sync.send_request(
                                &b_peer,
                                BlockRequest {
                                    block_id: wanted.clone(),
                                },
                            );
                            request_sent = true;
                        }
                        SwarmEvent::Behaviour(Event::BlockSync(request_response::Event::Message {
                            message: request_response::Message::Response { response, .. },
                            ..
                        })) => {
                            assert_eq!(response.block_id, wanted);
                            assert!(response.block.is_none());
                            return;
                        }
                        _ => {}
                    },
                    ev = b.select_next_some() => match ev {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == a_peer => {}
                        SwarmEvent::Behaviour(Event::BlockSync(request_response::Event::Message {
                            message: request_response::Message::Request { request, channel, .. },
                            ..
                        })) => {
                            assert_eq!(request.block_id, wanted);
                            b.behaviour_mut().block_sync.send_response(
                                channel,
                                BlockResponse {
                                    block_id: request.block_id,
                                    block: None,
                                },
                            ).expect("send response");
                        }
                        _ => {}
                    },
                }
            }
        };

        timeout(TokioDuration::from_secs(6), fut)
            .await
            .expect("timeout waiting for block sync response");
    }

    #[test]
    fn orphan_buffer_enforces_capacity_and_ttl() {
        let mut buffer = OrphanBuffer::new(2, 10);
        let mk = |id: &str, parent: &str| crate::ledger::BlockRecordV1 {
            v: 1,
            height: 1,
            block_id: id.to_string(),
            parent_block_id: Some(parent.to_string()),
            producer_id: "producer".to_string(),
            tx_hashes: Vec::new(),
            txs: Vec::new(),
            state_root: "root".to_string(),
            reward: crate::ledger::BlockRewardRecordV1 {
                base_reward_micro: 0,
                compute_reward_micro: 0,
                total_reward_micro: 0,
            },
            caac_weight: 1,
            cumulative_weight: 1,
            canonical: false,
            ts_ms: 1,
        };

        buffer.insert(mk("a", "p"), None, 0, 1);
        buffer.insert(mk("b", "p"), None, 0, 2);
        buffer.insert(mk("c", "p"), None, 0, 3);
        assert_eq!(buffer.len(), 2);
        assert!(buffer.remove("a").is_none());
        assert_eq!(buffer.children_of("p", 20).len(), 0);
    }
}
