//! Minimal P2P mesh (Phase 3) for this rebuilt snapshot.
//!
//! Goals:
//! - discovery: Kademlia (bootstrap via env later)
//! - gossip: ledger announcements (`/tet/v1/ledger`)
//! - invariants: swarm loop must never be blocked by heavy IO/inference

#![allow(clippy::collapsible_match)]
#![allow(clippy::collapsible_if)]

use futures::StreamExt;
use libp2p::core::transport::Transport as _;
use libp2p::core::upgrade;
use libp2p::gossipsub::{self, IdentTopic as Topic, MessageAuthenticity, ValidationMode};
use libp2p::identity;
use libp2p::kad::{self, store::MemoryStore};
use libp2p::noise;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::tcp;
use libp2p::yamux;
use libp2p::{Multiaddr, PeerId};
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub const TET_LEDGER_TOPIC: &str = "/tet/v1/ledger";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum LedgerGossip {
    ProofAnnounce {
        signer_wallet_id: String,
        id: u64,
        hash_sha256_hex: String,
        ed25519_sig_b64: Option<String>,
        mldsa_pubkey_b64: Option<String>,
        mldsa_sig_b64: Option<String>,
    },
    TransferAnnounce {
        signer_wallet_id: String,
        from_peer_id: String,
        to_peer_id: String,
        amount_micro: u64,
        fee_micro: u64,
        ed25519_sig_b64: Option<String>,
        mldsa_pubkey_b64: Option<String>,
        mldsa_sig_b64: Option<String>,
    },
    /// Signed full `tet_ledger.json` snapshot (v1 JSON bytes), for Passive Guardians.
    StateSnapshotSigned {
        sha256_hex: String,
        snapshot_b64: String,
        ed25519_pubkey_hex: String,
        ed25519_sig_b64: String,
    },
}

fn verify_p2p_hybrid(m: &LedgerGossip) -> bool {
    match m {
        LedgerGossip::StateSnapshotSigned {
            sha256_hex,
            snapshot_b64,
            ed25519_pubkey_hex,
            ed25519_sig_b64,
        } => crate::replication::verify_state_snapshot_signed(
            sha256_hex,
            snapshot_b64,
            ed25519_pubkey_hex,
            ed25519_sig_b64,
        )
        .is_ok(),
        LedgerGossip::TransferAnnounce { .. } | LedgerGossip::ProofAnnounce { .. } => {
            if !crate::quantum_shield::pqc_active() {
                return true;
            }
            let (signer, preimage, ed, pk, ps) = match m {
                LedgerGossip::TransferAnnounce {
                    signer_wallet_id,
                    from_peer_id,
                    to_peer_id,
                    amount_micro,
                    fee_micro: _,
                    ed25519_sig_b64,
                    mldsa_pubkey_b64,
                    mldsa_sig_b64,
                } => {
                    let msg = format!(
                        "tet-p2p-v1|transfer_announce|signer={}|from={}|to={}|amount_micro={}",
                        signer_wallet_id, from_peer_id, to_peer_id, amount_micro
                    );
                    (
                        signer_wallet_id.as_str(),
                        msg,
                        ed25519_sig_b64.as_deref(),
                        mldsa_pubkey_b64.as_deref(),
                        mldsa_sig_b64.as_deref(),
                    )
                }
                LedgerGossip::ProofAnnounce {
                    signer_wallet_id,
                    id,
                    hash_sha256_hex,
                    ed25519_sig_b64,
                    mldsa_pubkey_b64,
                    mldsa_sig_b64,
                } => {
                    let msg = format!(
                        "tet-p2p-v1|proof_announce|signer={}|id={}|hash={}",
                        signer_wallet_id, id, hash_sha256_hex
                    );
                    (
                        signer_wallet_id.as_str(),
                        msg,
                        ed25519_sig_b64.as_deref(),
                        mldsa_pubkey_b64.as_deref(),
                        mldsa_sig_b64.as_deref(),
                    )
                }
                LedgerGossip::StateSnapshotSigned { .. } => unreachable!(),
            };
            // Enforce PQC signatures (ML-DSA-44) for all gossip when PQC is active.
            // Any missing or invalid signature is rejected.
            if pk.is_none() || ps.is_none() {
                return false;
            }
            crate::quantum_shield::verify_hybrid(signer, ed, pk, ps, preimage.as_bytes()).is_ok()
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
struct Behaviour {
    kademlia: kad::Behaviour<MemoryStore>,
    gossipsub: gossipsub::Behaviour,
}

#[derive(Debug)]
enum Event {
    #[allow(dead_code)]
    Kademlia(kad::Event),
    Gossipsub(gossipsub::Event),
}

impl From<kad::Event> for Event {
    fn from(e: kad::Event) -> Self {
        Self::Kademlia(e)
    }
}
impl From<gossipsub::Event> for Event {
    fn from(e: gossipsub::Event) -> Self {
        Self::Gossipsub(e)
    }
}

type NetResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

pub struct NetworkManager {
    swarm: Swarm<Behaviour>,
    ledger_topic: Topic,
    seen: HashSet<[u8; 32]>,
    peer_ratelimit: HashMap<PeerId, PeerBudget>,
    banned_peers: HashMap<PeerId, Instant>,
    peer_bad_sigs: HashMap<PeerId, (Instant, u32)>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct PeerBudget {
    window_start: Instant,
    count: u32,
    quarantine_until: Option<Instant>,
}

impl NetworkManager {
    pub async fn new(_namespace: String) -> NetResult<Self> {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair)?)
            .multiplex(yamux::Config::default())
            .timeout(Duration::from_secs(20))
            .boxed();

        let store = MemoryStore::new(peer_id);
        let kademlia = kad::Behaviour::with_config(peer_id, store, kad::Config::default());

        let ledger_topic = Topic::new(TET_LEDGER_TOPIC);
        let gcfg = gossipsub::ConfigBuilder::default()
            .validation_mode(ValidationMode::Strict)
            .validate_messages()
            .heartbeat_interval(Duration::from_millis(800))
            .build()?;
        let mut gossipsub = gossipsub::Behaviour::new(MessageAuthenticity::Signed(keypair), gcfg)?;
        gossipsub.subscribe(&ledger_topic)?;

        let behaviour = Behaviour {
            kademlia,
            gossipsub,
        };
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );

        let listen: Multiaddr = std::env::var("TET_P2P_LISTEN")
            .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/0".to_string())
            .parse()
            .map_err(|e| format!("listen multiaddr parse failed: {e}"))?;
        swarm.listen_on(listen)?;

        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        Ok(Self {
            swarm,
            ledger_topic,
            seen: HashSet::new(),
            peer_ratelimit: HashMap::new(),
            banned_peers: HashMap::new(),
            peer_bad_sigs: HashMap::new(),
            tx,
            rx,
        })
    }

    pub fn tx(&self) -> mpsc::UnboundedSender<Vec<u8>> {
        self.tx.clone()
    }

    pub async fn run(&mut self) -> NetResult<()> {
        let max_per_sec = std::env::var("TET_P2P_MSG_RPS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(60)
            .max(1);
        let quarantine_secs = std::env::var("TET_P2P_QUARANTINE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30)
            .max(1);
        let ban_secs = std::env::var("TET_P2P_BAN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300)
            .max(5);
        let bad_sig_limit_per_sec = std::env::var("TET_P2P_BADSIG_LIMIT_PER_SEC")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(30)
            .max(1);
        loop {
            tokio::select! {
                Some(bytes) = async { self.rx.recv().await } => {
                    let _ = self.swarm.behaviour_mut().gossipsub.publish(self.ledger_topic.clone(), bytes);
                }
                ev = self.swarm.select_next_some() => {
                    match ev {
                    SwarmEvent::NewListenAddr { address, .. } => {
                            eprintln!("[p2p] listening {address}");
                        }
                        SwarmEvent::Behaviour(Event::Gossipsub(e)) => {
                            if let gossipsub::Event::Message { propagation_source, message, .. } = e {
                                let now = Instant::now();
                                // Ban enforcement (peer-id level; IP banning is transport-specific).
                                if let Some(until) = self.banned_peers.get(&propagation_source).copied() {
                                    if now < until {
                                        let _ = self.swarm.disconnect_peer_id(propagation_source);
                                        continue;
                                    }
                                    self.banned_peers.remove(&propagation_source);
                                }
                                // Lightweight, best-effort quarantine for abusive peers.
                                let entry = self.peer_ratelimit.entry(propagation_source).or_insert(PeerBudget{
                                    window_start: now,
                                    count: 0,
                                    quarantine_until: None,
                                });
                                if let Some(until) = entry.quarantine_until {
                                    if now < until {
                                continue;
                            }
                                    entry.quarantine_until = None;
                                    entry.window_start = now;
                                    entry.count = 0;
                                }
                                if now.duration_since(entry.window_start) >= Duration::from_secs(1) {
                                    entry.window_start = now;
                                    entry.count = 0;
                                }
                                entry.count = entry.count.saturating_add(1);
                                if entry.count > max_per_sec {
                                    entry.quarantine_until = Some(now + Duration::from_secs(quarantine_secs));
                                continue;
                            }
                                let mut h = Sha256::new();
                                h.update(&message.data);
                                let out = h.finalize();
                                let mut key = [0u8; 32];
                                key.copy_from_slice(out.as_slice());
                                    if self.seen.insert(key) {
                                    if let Ok(m) = serde_json::from_slice::<LedgerGossip>(&message.data) {
                                        if !verify_p2p_hybrid(&m) {
                                            // Military-grade: invalid signatures -> disconnect + ban.
                                            let slot = self.peer_bad_sigs.entry(propagation_source).or_insert((now, 0));
                                            if now.duration_since(slot.0) >= Duration::from_secs(1) {
                                                slot.0 = now;
                                                slot.1 = 0;
                                            }
                                            slot.1 = slot.1.saturating_add(1);
                                            if slot.1 >= bad_sig_limit_per_sec {
                                                self.banned_peers.insert(propagation_source, now + Duration::from_secs(ban_secs));
                                            }
                                            let _ = self.swarm.disconnect_peer_id(propagation_source);
                                            continue;
                                        }
                                        match m {
                                            LedgerGossip::ProofAnnounce { signer_wallet_id, id, hash_sha256_hex, .. } => {
                                                eprintln!("[p2p][ledger] proof id={id} hash={}", &hash_sha256_hex[..hash_sha256_hex.len().min(12)]);
                                                let _ = signer_wallet_id;
                                            }
                                            LedgerGossip::TransferAnnounce { from_peer_id, to_peer_id, amount_micro, fee_micro, signer_wallet_id, .. } => {
                                                eprintln!("[p2p][ledger] xfer {from_peer_id}->{to_peer_id} amt={amount_micro} fee={fee_micro}");
                                                let _ = signer_wallet_id;
                                            }
                                            LedgerGossip::StateSnapshotSigned {
                                                sha256_hex,
                                                snapshot_b64,
                                                ed25519_pubkey_hex,
                                                ed25519_sig_b64,
                                            } => {
                                                if let Ok(bytes) = crate::replication::verify_state_snapshot_signed(
                                                    &sha256_hex,
                                                    &snapshot_b64,
                                                    &ed25519_pubkey_hex,
                                                    &ed25519_sig_b64,
                                                ) {
                                                    crate::replication::guardian_store_verified_snapshot(
                                                        &bytes,
                                                        &sha256_hex,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
