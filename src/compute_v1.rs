//! `POST /v1/compute` pipeline: plugins → execute → verify → oracle quote.

use serde::Serialize;
use tet_core::tet_worker::poc_infer;

use crate::conductor::execution_root;
use crate::conductor_plugins::{
    TaskPluginKind, merge_shard_outputs, shard_ai_inference, shard_scientific_grid,
    shard_video_frames,
};
use crate::energy_oracle::{chf_micro_to_stevemon_micro, quote_reward_chf_micro};
use crate::verification_engine::{verify_redundant_and_pick, verify_single_worker};

#[derive(Debug, Serialize)]
pub struct V1ComputeInnerResult {
    pub job_id: String,
    pub kind: TaskPluginKind,
    pub task_commitment_root_hex: String,
    pub merged_output: String,
    pub execution_root_hex: String,
    pub verification_passed: bool,
    pub redundant_worker_check_passed: bool,
    pub shard_count: usize,
    pub reward_chf_micro: u64,
    pub reward_stevemon_micro: u64,
}

pub fn execute_compute_job(
    kind: TaskPluginKind,
    model: &str,
    input: &str,
    shard_param: usize,
    geo_region: &str,
) -> Result<V1ComputeInnerResult, String> {
    let plan = match kind {
        TaskPluginKind::AiInference => shard_ai_inference(model, input, shard_param),
        TaskPluginKind::VideoRendering => shard_video_frames(model, input, shard_param),
        TaskPluginKind::ScientificCompute => shard_scientific_grid(model, input, shard_param),
    };
    let job_id = plan.job_id.clone();
    let task_commitment_root_hex = plan.task_commitment_root_hex.clone();

    let mut outs: Vec<String> = Vec::with_capacity(plan.shards.len());
    for s in &plan.shards {
        outs.push(poc_infer(&s.text));
    }

    let merged_output = merge_shard_outputs(plan.kind, &outs);
    let execution_root_hex = execution_root(&plan.shards, &outs).map_err(|e| e.to_string())?;
    verify_single_worker(outs.clone()).map_err(|e| e.to_string())?;

    let redundant_worker_check_passed = verify_redundant_and_pick(plan.shards.len(), &[outs.clone()])
        .is_ok();

    let reward_chf_micro = quote_reward_chf_micro(plan.shards.len(), geo_region);
    let reward_stevemon_micro = chf_micro_to_stevemon_micro(reward_chf_micro);

    Ok(V1ComputeInnerResult {
        job_id,
        kind: plan.kind,
        task_commitment_root_hex,
        merged_output,
        execution_root_hex,
        verification_passed: true,
        redundant_worker_check_passed,
        shard_count: plan.shards.len(),
        reward_chf_micro,
        reward_stevemon_micro,
    })
}
