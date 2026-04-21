//! Phase 4 stub: TEE-private compute + hardware attestation (future).

#[derive(Debug, Clone)]
pub struct TeeSessionV1 {
    pub session_id: String,
    pub attestation_kind: String,
}

#[derive(Debug, Clone)]
pub struct TeeComputeRequestV1 {
    pub session_id: String,
    pub encrypted_input_b64: String,
}

#[derive(Debug, Clone)]
pub struct TeeComputeResultV1 {
    pub session_id: String,
    pub encrypted_output_b64: String,
}

pub fn open_session_stub() -> TeeSessionV1 {
    TeeSessionV1 {
        session_id: "tee_stub".into(),
        attestation_kind: "stub".into(),
    }
}
