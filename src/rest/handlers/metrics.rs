use crate::rest::RestState;
use axum::{extract::State, http::header, response::IntoResponse};

fn prom_line(
    out: &mut String,
    name: &str,
    help: &str,
    metric_type: &str,
    value: impl std::fmt::Display,
) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(metric_type);
    out.push('\n');
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

pub async fn get_metrics(State(state): State<RestState>) -> impl IntoResponse {
    let block_height = state.ledger.block_height().unwrap_or(0);
    let (mempool_len, mempool_bytes) = {
        let mp = state.mempool.lock().await;
        (
            mp.len(),
            mp.iter()
                .map(crate::rest::RestState::tx_estimated_bytes)
                .sum::<usize>(),
        )
    };
    let p2p_peers = match &state.p2p_client {
        Some(client) => client.connected_peers_count().await.unwrap_or(0),
        None => 0,
    };
    let total_supply = state.ledger.total_supply_micro().unwrap_or(0);
    let total_burned = state.ledger.total_burned_micro().unwrap_or(0);
    let sse_logs = state
        .log_sse_connections
        .load(std::sync::atomic::Ordering::Relaxed);

    let mut out = String::with_capacity(2048);
    prom_line(
        &mut out,
        "tet_block_height",
        "Current canonical block height.",
        "gauge",
        block_height,
    );
    prom_line(
        &mut out,
        "tet_mempool_len",
        "Pending mempool transaction count.",
        "gauge",
        mempool_len,
    );
    prom_line(
        &mut out,
        "tet_mempool_bytes",
        "Estimated serialized mempool bytes.",
        "gauge",
        mempool_bytes,
    );
    prom_line(
        &mut out,
        "tet_mempool_max_txs",
        "Configured mempool transaction cap.",
        "gauge",
        crate::rest::RestState::mempool_max_txs(),
    );
    prom_line(
        &mut out,
        "tet_mempool_max_bytes",
        "Configured mempool byte cap.",
        "gauge",
        crate::rest::RestState::mempool_max_bytes(),
    );
    prom_line(
        &mut out,
        "tet_p2p_peers",
        "Connected libp2p peers.",
        "gauge",
        p2p_peers,
    );
    prom_line(
        &mut out,
        "tet_gossip_rejected_total",
        "Rejected gossip messages.",
        "counter",
        crate::metrics::gossip_rejected_total(),
    );
    prom_line(
        &mut out,
        "tet_zk_prover_seconds",
        "Total local ZK prover wall-clock seconds.",
        "counter",
        format!("{:.3}", crate::metrics::zk_prover_seconds_total()),
    );
    prom_line(
        &mut out,
        "tet_total_supply_micro",
        "Current total supply in micro TET.",
        "gauge",
        total_supply,
    );
    prom_line(
        &mut out,
        "tet_total_burned_micro",
        "Total burned micro TET.",
        "counter",
        total_burned,
    );
    prom_line(
        &mut out,
        "tet_log_sse_connections",
        "Current /logs SSE connections.",
        "gauge",
        sse_logs,
    );
    prom_line(
        &mut out,
        "tet_zkcourt_open_disputes",
        "Open ZK-Court disputes.",
        "gauge",
        crate::vision::zk_court::list_open_persisted(state.ledger.as_ref()).len(),
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}
