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
use libp2p::noise;
use libp2p::ping;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::tcp;
use libp2p::yamux;
use libp2p::{Multiaddr, PeerId};
use std::collections::HashSet;
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::models::NetworkEvent;
use std::sync::Arc;

type AnyErr = Box<dyn Error + Send + Sync + 'static>;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
struct TetBehaviour {
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

#[derive(Debug)]
enum Event {
    Mdns(mdns::Event),
    Ping(ping::Event),
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Kademlia(kad::Event),
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

pub const GLOBAL_STATE_TOPIC: &str = "tet-global-state";

/// Start a libp2p swarm task and return a Sender you can use to publish gossip messages.
pub fn start_mdns_ping_swarm(
    ledger: Arc<crate::ledger::Ledger>,
) -> Result<mpsc::Sender<String>, AnyErr> {
    let (tx, rx) = mpsc::channel::<String>(256);
    tokio::spawn(async move {
        if let Err(e) = run_mdns_ping_swarm(ledger, rx).await {
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

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Permissive)
        .build()
        .map_err(|e| -> AnyErr { format!("gossipsub config: {e}").into() })?;
    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| -> AnyErr { format!("gossipsub init: {e}").into() })?;

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
    };
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    println!("[P2P] My Peer ID: {}", swarm.local_peer_id());
    log::info!("[P2P] My Peer ID: {}", swarm.local_peer_id());

    let global_topic = gossipsub::IdentTopic::new(GLOBAL_STATE_TOPIC);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&global_topic)
        .expect("Failed to subscribe to tet-global-state");
    println!(
        "[P2P] Subscribed to gossipsub topic: {}",
        GLOBAL_STATE_TOPIC
    );

    if let Ok(bootstrap_str) = std::env::var("TET_BOOTSTRAP_PEER") {
        println!("[P2P] Found TET_BOOTSTRAP_PEER: {}", bootstrap_str);
        let addr: libp2p::Multiaddr = bootstrap_str.parse().expect("Invalid bootstrap address");
        swarm.dial(addr).expect("Failed to dial bootstrap peer");
        println!("[P2P] Dialing bootstrap peer...");
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            println!("[P2P] ❌ Kademlia bootstrap failed: {:?}", e);
        } else {
            println!("[P2P] ✅ Kademlia bootstrap started");
        }
    } else {
        println!("[P2P] No TET_BOOTSTRAP_PEER provided. Running as an isolated node.");
    }

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>()?)?;

    let mut dialing: HashSet<PeerId> = HashSet::new();
    loop {
        tokio::select! {
            maybe_msg = publish_rx.recv() => {
                if let Some(msg) = maybe_msg {
                    match swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(global_topic.clone(), msg.as_bytes())
                    {
                        Ok(_msg_id) => {
                            println!("[P2P] 📣 GOSSIP PUBLISHED: {}", msg);
                        }
                        Err(e) => {
                            println!("[P2P] ❌ GOSSIP PUBLISH ERROR: {:?}", e);
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
            SwarmEvent::Behaviour(Event::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                let message_data = String::from_utf8_lossy(&message.data);
                match serde_json::from_str::<NetworkEvent>(&message_data) {
                    Ok(event) => {
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
                        match ledger.apply_remote_event(&event) {
                            Ok(true) => {
                                println!("[P2P] ✅ REMOTE EVENT APPLIED to local ledger");
                            }
                            Ok(false) => {
                                println!("[P2P] ⏭️ REMOTE EVENT ALREADY APPLIED (idempotent)");
                            }
                            Err(e) => {
                                println!("[P2P] ❌ REMOTE EVENT APPLY FAILED: {}", e);
                            }
                        }
                    }
                    Err(e) => {
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
            .validation_mode(gossipsub::ValidationMode::Permissive)
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

        let ident_topic = gossipsub::IdentTopic::new(GLOBAL_STATE_TOPIC);
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
}
