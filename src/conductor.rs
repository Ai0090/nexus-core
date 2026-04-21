//! High-precision orchestration (Phase 3+): shard tasks, verify, and aggregate.
//!
//! This is a deterministic scaffold. Production should distribute shards to remote workers and use
//! the verification engine to compare redundant results across devices.

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tet_core::tet_worker::poc_infer;
use rand_core::RngCore as _;

#[derive(Debug, Clone, Serialize)]
pub struct ShardSpec {
    pub shard_id: usize,
    pub text: String,
    pub task_hash_hex: String,
}

#[derive(Debug, Serialize)]
pub struct OrchestratePlan {
    pub job_id: String,
    pub plugin: String,
    pub model: String,
    pub shards: Vec<ShardSpec>,
    /// Pre-execution commitment: SHA256 over ordered shard task hashes.
    pub task_commitment_root_hex: String,
}

#[derive(Debug, Serialize)]
pub struct OrchestrateRunResult {
    pub job_id: String,
    pub shard_outputs: Vec<String>,
    pub merged_output: String,
    /// True iff every output matches deterministic `poc_infer(shard.text)` (stub).
    pub deterministic_recompute_ok: bool,
    /// Post-execution root over ordered `(shard_id || sha256(output))`.
    pub execution_root_hex: String,
}

#[derive(Debug, Serialize)]
pub struct OrchestrateFullResponse {
    pub plan: OrchestratePlan,
    pub run: OrchestrateRunResult,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn strong_id_hex16() -> String {
    let mut rbytes = [0u8; 16];
    let mut rng = rand_core::OsRng;
    rng.fill_bytes(&mut rbytes);
    hex::encode(rbytes)
}

fn task_hash(model: &str, shard_id: usize, payload: &str) -> String {
    let pre = format!("tet-task:v1|model={model}|shard={shard_id}|{payload}");
    sha256_hex(pre.as_bytes())
}

fn commitment_root(shards: &[ShardSpec]) -> String {
    let mut h = Sha256::new();
    h.update(b"tet-task-commit:v1");
    for s in shards {
        h.update(s.task_hash_hex.as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

fn execution_root(shards: &[ShardSpec], outs: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(b"tet-execution-root:v1");
    for (s, out) in shards.iter().zip(outs.iter()) {
        h.update(s.shard_id.to_le_bytes());
        h.update(sha256_hex(out.as_bytes()).as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

fn split_text(input: &str, shard_chars: usize) -> Vec<String> {
    let maxc = shard_chars.max(64);
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let j = (i + maxc).min(chars.len());
        out.push(chars[i..j].iter().collect());
        i = j;
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// AI INFERENCE plugin: split a large context window into text chunks.
pub fn shard_ai_inference(model: &str, input: &str, shard_chars: usize) -> Vec<ShardSpec> {
    split_text(input, shard_chars)
        .into_iter()
        .enumerate()
        .map(|(i, t)| ShardSpec {
            shard_id: i,
            task_hash_hex: task_hash(model, i, &t),
            text: t,
        })
        .collect()
}

/// VIDEO RENDERING plugin: split frames into individual shard tasks (stub).
pub fn shard_video_rendering(model: &str, frames_total: u64, shard_frames: u64) -> Vec<ShardSpec> {
    let sf = shard_frames.max(1);
    let mut shards = Vec::new();
    let mut start = 0u64;
    let mut id = 0usize;
    while start < frames_total {
        let end = (start + sf).min(frames_total);
        let payload = format!("frames:{start}..{end}");
        shards.push(ShardSpec {
            shard_id: id,
            task_hash_hex: task_hash(model, id, &payload),
            text: payload,
        });
        id += 1;
        start = end;
    }
    if shards.is_empty() {
        shards.push(ShardSpec {
            shard_id: 0,
            task_hash_hex: task_hash(model, 0, "frames:0..0"),
            text: "frames:0..0".into(),
        });
    }
    shards
}

/// SCIENTIFIC COMPUTE plugin: grid-based splitting into tiles (stub).
pub fn shard_scientific_grid(
    model: &str,
    grid_w: u64,
    grid_h: u64,
    tile_w: u64,
    tile_h: u64,
) -> Vec<ShardSpec> {
    let tw = tile_w.max(1);
    let th = tile_h.max(1);
    let mut shards = Vec::new();
    let mut id = 0usize;
    let mut y = 0u64;
    while y < grid_h {
        let mut x = 0u64;
        while x < grid_w {
            let xe = (x + tw).min(grid_w);
            let ye = (y + th).min(grid_h);
            let payload = format!("tile:{x},{y}-{xe},{ye}");
            shards.push(ShardSpec {
                shard_id: id,
                task_hash_hex: task_hash(model, id, &payload),
                text: payload,
            });
            id += 1;
            x = xe;
        }
        y = (y + th).min(grid_h);
    }
    if shards.is_empty() {
        shards.push(ShardSpec {
            shard_id: 0,
            task_hash_hex: task_hash(model, 0, "tile:0,0-0,0"),
            text: "tile:0,0-0,0".into(),
        });
    }
    shards
}

pub fn orchestrate_and_run(
    model: &str,
    input: &str,
    shard_chars: usize,
) -> OrchestrateFullResponse {
    // Default plugin: AI inference shard.
    let shards = shard_ai_inference(model, input, shard_chars);
    let job_id = strong_id_hex16();
    let plan = OrchestratePlan {
        job_id: job_id.clone(),
        plugin: "ai_inference".into(),
        model: model.to_string(),
        task_commitment_root_hex: commitment_root(&shards),
        shards: shards.clone(),
    };
    let outs: Vec<String> = shards.iter().map(|s| poc_infer(&s.text)).collect();
    let merged_output = outs.join("\n---tet-shard---\n");
    let deterministic_recompute_ok = shards
        .iter()
        .zip(outs.iter())
        .all(|(s, o)| poc_infer(&s.text) == *o);
    let run = OrchestrateRunResult {
        job_id,
        shard_outputs: outs.clone(),
        merged_output,
        deterministic_recompute_ok,
        execution_root_hex: execution_root(&shards, &outs),
    };
    OrchestrateFullResponse { plan, run }
}
