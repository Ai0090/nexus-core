//! Phase 4 stub: video/3D render farm sharding logic (future).

#[derive(Debug, Clone)]
pub struct RenderShardV1 {
    pub shard_id: u64,
    pub frame_start: u64,
    pub frame_end: u64,
}

#[derive(Debug, Clone)]
pub struct RenderJobV1 {
    pub job_id: String,
    pub total_frames: u64,
}

pub fn split_frames_stub(total_frames: u64, shard_frames: u64) -> Vec<RenderShardV1> {
    let sf = shard_frames.max(1);
    let mut shards = Vec::new();
    let mut start = 0u64;
    let mut id = 0u64;
    while start < total_frames {
        let end = (start + sf).min(total_frames);
        shards.push(RenderShardV1 {
            shard_id: id,
            frame_start: start,
            frame_end: end,
        });
        id += 1;
        start = end;
    }
    if shards.is_empty() {
        shards.push(RenderShardV1 {
            shard_id: 0,
            frame_start: 0,
            frame_end: 0,
        });
    }
    shards
}
