//! Verification Engine: require identical result hashes across redundant workers before merge.

use sha2::{Digest as _, Sha256};
use tet_core::tet_worker::result_sha256_hex;

/// For each shard index, `candidates` lists outputs from different workers.
/// Returns one canonical output per shard only if **all** result hashes match (100% accuracy gate).
pub fn verify_redundant_and_pick(
    shard_count: usize,
    candidates: &[Vec<String>],
) -> Result<Vec<String>, String> {
    if candidates.is_empty() {
        return Err("no worker result sets".into());
    }
    let workers = candidates.len();
    for w in candidates {
        if w.len() != shard_count {
            return Err(format!(
                "worker output len {} != shard_count {}",
                w.len(),
                shard_count
            ));
        }
    }

    let mut canonical = Vec::with_capacity(shard_count);
    for i in 0..shard_count {
        let mut hashes: Vec<String> = Vec::with_capacity(workers);
        for w in candidates {
            hashes.push(result_sha256_hex(&w[i]));
        }
        let first = &hashes[0];
        if !hashes.iter().all(|h| h == first) {
            return Err(format!(
                "shard {i}: worker result hash mismatch (verification failed)"
            ));
        }
        canonical.push(candidates[0][i].clone());
    }
    Ok(canonical)
}

/// Single-worker path: pass one vec as the only candidate.
pub fn verify_single_worker(outputs: Vec<String>) -> Result<Vec<String>, String> {
    Ok(outputs)
}

pub fn hash_set_idempotency(job_id: &str, execution_root_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"tet-job-seal:v1");
    h.update(job_id.as_bytes());
    h.update(execution_root_hex.as_bytes());
    hex::encode(h.finalize())
}
