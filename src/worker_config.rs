use std::sync::atomic::{AtomicBool, Ordering};

static SAFE_MODE: AtomicBool = AtomicBool::new(true);
static ENABLE_ZK_PROVER: AtomicBool = AtomicBool::new(false);

/// Configure worker/operator safety posture.
///
/// Default: SAFE MODE enabled.
/// Opt-out: pass `--unsafe-no-filter` to disable content filtering placeholders.
pub fn configure_from_args() -> bool {
    let unsafe_no_filter = std::env::args().any(|a| a == "--unsafe-no-filter");
    let safe_mode = !unsafe_no_filter;
    SAFE_MODE.store(safe_mode, Ordering::SeqCst);

    let enable_zk = std::env::args().any(|a| a == "--enable-zk-prover");
    ENABLE_ZK_PROVER.store(enable_zk, Ordering::SeqCst);
    safe_mode
}

pub fn safe_mode() -> bool {
    SAFE_MODE.load(Ordering::Relaxed)
}

pub fn enable_zk_prover() -> bool {
    ENABLE_ZK_PROVER.load(Ordering::Relaxed)
}
