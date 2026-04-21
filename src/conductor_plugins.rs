//! Task sharding plugins (Conductor): AI inference, video frames, scientific grid.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tet_core::tet_worker::task_sha256_hex;

use rand_core::RngCore as _;

use crate::conductor::{ShardSpec, aggregate_outputs, split_into_shards};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskPluginKind {
    /// Parallel context chunks (UTF-8 character windows).
    AiInference,
    /// One task per frame index (payload: newline-separated frame indices or raw frame count).
    VideoRendering,
    /// Grid / row blocks (CSV or line-based scientific arrays).
    ScientificCompute,
}

#[derive(Debug, Serialize)]
pub struct PluginPlan {
    pub job_id: String,
    pub kind: TaskPluginKind,
    pub shards: Vec<ShardSpec>,
    pub task_commitment_root_hex: String,
}

fn strong_id_hex16() -> String {
    let mut rbytes = [0u8; 16];
    let mut rng = rand_core::OsRng;
    rng.fill_bytes(&mut rbytes);
    hex::encode(rbytes)
}

fn task_commitment_root(shards: &[ShardSpec]) -> String {
    let mut h = Sha256::new();
    h.update(b"tet-task-commit:v1");
    for s in shards {
        h.update(s.task_hash_hex.as_bytes());
        h.update(&[0u8]);
    }
    hex::encode(h.finalize())
}

/// AI: same as generic char sharding; `model` scopes task hashes.
pub fn shard_ai_inference(model: &str, input: &str, shard_chars: usize) -> PluginPlan {
    let job_id = strong_id_hex16();
    let shards = split_into_shards(model, input, shard_chars);
    let task_commitment_root_hex = task_commitment_root(&shards);
    PluginPlan {
        job_id,
        kind: TaskPluginKind::AiInference,
        shards,
        task_commitment_root_hex,
    }
}

/// Video: each line in `input` is a frame id; one shard per frame (or batch lines into groups of `frames_per_shard`).
pub fn shard_video_frames(model: &str, input: &str, frames_per_shard: usize) -> PluginPlan {
    let job_id = strong_id_hex16();
    let fps = frames_per_shard.max(1);
    let lines: Vec<&str> = input.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut shards = Vec::new();
    let mut shard_id = 0usize;
    let mut chunk = Vec::new();
    for line in lines {
        chunk.push(line.to_string());
        if chunk.len() >= fps {
            let text = chunk.join("\n");
            let task_hash_hex = task_sha256_hex(model, &format!("video:{shard_id}|{text}"));
            shards.push(ShardSpec {
                shard_id,
                slice_start: shard_id,
                slice_end: shard_id + 1,
                text,
                task_hash_hex,
            });
            shard_id += 1;
            chunk.clear();
        }
    }
    if !chunk.is_empty() {
        let text = chunk.join("\n");
        let task_hash_hex = task_sha256_hex(model, &format!("video:{shard_id}|{text}"));
        shards.push(ShardSpec {
            shard_id,
            slice_start: shard_id,
            slice_end: shard_id + 1,
            text,
            task_hash_hex,
        });
    }
    if shards.is_empty() {
        let task_hash_hex = task_sha256_hex(model, "video:empty");
        shards.push(ShardSpec {
            shard_id: 0,
            slice_start: 0,
            slice_end: 0,
            text: String::new(),
            task_hash_hex,
        });
    }
    let task_commitment_root_hex = task_commitment_root(&shards);
    PluginPlan {
        job_id,
        kind: TaskPluginKind::VideoRendering,
        shards,
        task_commitment_root_hex,
    }
}

/// Scientific: split CSV/line data into row blocks of `rows_per_shard`.
pub fn shard_scientific_grid(model: &str, input: &str, rows_per_shard: usize) -> PluginPlan {
    let job_id = strong_id_hex16();
    let rps = rows_per_shard.max(1);
    let rows: Vec<&str> = input.lines().collect();
    let mut shards = Vec::new();
    let mut shard_id = 0usize;
    let mut i = 0usize;
    while i < rows.len() {
        let end = (i + rps).min(rows.len());
        let text = rows[i..end].join("\n");
        let task_hash_hex = task_sha256_hex(model, &format!("sci:{shard_id}|{text}"));
        shards.push(ShardSpec {
            shard_id,
            slice_start: i,
            slice_end: end,
            text,
            task_hash_hex,
        });
        shard_id += 1;
        i = end;
    }
    if shards.is_empty() {
        let task_hash_hex = task_sha256_hex(model, "sci:empty");
        shards.push(ShardSpec {
            shard_id: 0,
            slice_start: 0,
            slice_end: 0,
            text: String::new(),
            task_hash_hex,
        });
    }
    let task_commitment_root_hex = task_commitment_root(&shards);
    PluginPlan {
        job_id,
        kind: TaskPluginKind::ScientificCompute,
        shards,
        task_commitment_root_hex,
    }
}

pub fn merge_shard_outputs(kind: TaskPluginKind, outputs: &[String]) -> String {
    match kind {
        TaskPluginKind::AiInference | TaskPluginKind::ScientificCompute => {
            aggregate_outputs(outputs)
        }
        TaskPluginKind::VideoRendering => {
            // Re-assemble frames in shard order (each shard may contain multiple frame lines).
            outputs.join("\n---tet-frame-batch---\n")
        }
    }
}
