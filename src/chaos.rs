//! Chaos tester (anti-fragility): simulate mass worker joins/offlines and ensure shard rerouting.

use rand_core::{RngCore as _, SeedableRng as _};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct WorkerSim {
    pub id: String,
    pub online: bool,
}

#[derive(Debug)]
pub struct ChaosReport {
    pub workers_total: usize,
    pub workers_online_after: usize,
    pub shards_total: usize,
    pub rerouted_shards: usize,
    pub ok_no_loss: bool,
}

fn worker_id(i: usize) -> String {
    format!("worker-{i:04}")
}

pub fn simulate_reroute(shards_total: usize, join: usize, offline: usize) -> ChaosReport {
    let mut workers: Vec<WorkerSim> = (0..join)
        .map(|i| WorkerSim {
            id: worker_id(i),
            online: true,
        })
        .collect();

    // Assign shards round-robin.
    let mut assignment: BTreeMap<usize, String> = BTreeMap::new();
    for shard_id in 0..shards_total {
        let w = &workers[shard_id % workers.len()];
        assignment.insert(shard_id, w.id.clone());
    }

    // Take workers offline deterministically.
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0x544554_u64); // "TET"
    let mut idxs: Vec<usize> = (0..workers.len()).collect();
    // Fisher-Yates shuffle.
    for i in (1..idxs.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        idxs.swap(i, j);
    }
    let off = offline.min(workers.len().saturating_sub(1));
    let offline_set: BTreeSet<String> = idxs
        .into_iter()
        .take(off)
        .map(|i| {
            workers[i].online = false;
            workers[i].id.clone()
        })
        .collect();

    let online: Vec<String> = workers
        .iter()
        .filter(|w| w.online)
        .map(|w| w.id.clone())
        .collect();

    // Reroute shards whose worker is offline.
    let mut rerouted = 0usize;
    for (sid, wid) in assignment.iter_mut() {
        if offline_set.contains(wid) {
            let pick = online[*sid % online.len()].clone();
            *wid = pick;
            rerouted += 1;
        }
    }

    // Verify: every shard has exactly one assignment, and all assigned workers are online.
    let ok_no_loss = assignment.len() == shards_total
        && assignment.values().all(|wid| !offline_set.contains(wid));

    ChaosReport {
        workers_total: join,
        workers_online_after: online.len(),
        shards_total,
        rerouted_shards: rerouted,
        ok_no_loss,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaos_reroute_never_loses_shards() {
        let r = simulate_reroute(20_000, 1_000, 500);
        assert!(r.ok_no_loss);
        assert!(r.rerouted_shards > 0);
        assert_eq!(r.workers_total, 1_000);
        assert_eq!(r.workers_online_after, 500);
    }
}
