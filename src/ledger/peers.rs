use super::*;

use libp2p::{Multiaddr, PeerId};

impl Ledger {
    pub fn save_peer(&self, peer_id: &PeerId, address: &Multiaddr) -> Result<(), LedgerError> {
        let key = peer_id.to_bytes();
        let addr_s = address.to_string();

        let cur = self
            .p2p_peers
            .get(&key)?
            .as_deref()
            .map(|v| self.decrypt_value(v))
            .transpose()?
            .unwrap_or_default();

        let mut addrs: Vec<String> = if cur.is_empty() {
            Vec::new()
        } else {
            serde_json::from_slice(&cur).unwrap_or_default()
        };

        if !addrs.iter().any(|a| a == &addr_s) {
            addrs.push(addr_s);
            // Keep it bounded.
            if addrs.len() > 16 {
                addrs.drain(0..(addrs.len() - 16));
            }
            let bytes = serde_json::to_vec(&addrs).unwrap_or_default();
            self.p2p_peers.insert(key, self.encrypt_value(&bytes)?)?;
            std::mem::drop(self.db.flush_async());
        }
        Ok(())
    }

    pub fn load_peers(&self) -> Vec<(PeerId, Multiaddr)> {
        let mut out = Vec::new();
        for it in self.p2p_peers.iter().flatten() {
            let (k, v) = it;
            let peer = PeerId::from_bytes(k.as_ref()).ok();
            let bytes = self.decrypt_value(v.as_ref()).ok().unwrap_or_default();
            let addrs: Vec<String> = serde_json::from_slice(&bytes).unwrap_or_default();
            let Some(peer_id) = peer else { continue };
            for s in addrs {
                if let Ok(addr) = s.parse::<Multiaddr>() {
                    out.push((peer_id, addr));
                }
            }
        }
        out
    }
}
