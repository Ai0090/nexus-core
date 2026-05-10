//! Phase 2.3 foundation: Host-side "ZK-Supreme Court" verifier (RISC Zero API shape).
//!
//! Guest compilation may be bypassed via `RISC0_SKIP_BUILD=1`.

use base64::Engine as _;
pub use nexus_protocol::{InferenceJournalV1, ZkCourtJournalV1};
use risc0_zkvm::Receipt;

#[derive(Debug, Clone)]
pub enum VerifiedZkJournal {
    Inference(InferenceJournalV1),
    ZkCourt(ZkCourtJournalV1),
}

fn mock_zk_allowed() -> bool {
    let mainnet = std::env::var("TET_MAINNET")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if mainnet {
        let allow_mock = std::env::var("TET_ALLOW_MOCK_ZK")
            .ok()
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if allow_mock {
            panic!("CRITICAL: TET_MAINNET=1 forbids TET_ALLOW_MOCK_ZK=1.");
        }
        return false;
    }
    cfg!(test)
        || matches!(
            std::env::var("TET_ALLOW_MOCK_ZK")
                .ok()
                .as_deref()
                .map(str::trim),
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
        )
}

fn decode_journal_bytes(bytes: &[u8]) -> anyhow::Result<VerifiedZkJournal> {
    if let Ok(j) = bincode::deserialize::<InferenceJournalV1>(bytes) {
        return Ok(VerifiedZkJournal::Inference(j));
    }
    if let Ok(j) = bincode::deserialize::<ZkCourtJournalV1>(bytes) {
        return Ok(VerifiedZkJournal::ZkCourt(j));
    }
    Err(anyhow::anyhow!(
        "journal is neither InferenceJournalV1 nor ZkCourtJournalV1"
    ))
}

pub fn verify_tx_receipt_and_journal(
    image_id: [u32; 8],
    journal_b64: &str,
    receipt_b64: &str,
) -> anyhow::Result<VerifiedZkJournal> {
    let supplied_journal = base64::engine::general_purpose::STANDARD
        .decode(journal_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to decode journal b64: {e}"))?;

    if let Some(rest) = receipt_b64.strip_prefix("MOCKJ1:") {
        if !mock_zk_allowed() {
            return Err(anyhow::anyhow!(
                "mock zk receipt rejected; set TET_ALLOW_MOCK_ZK=1 for dev/test"
            ));
        }
        if image_id != methods::NEXUS_GUEST_ID {
            return Err(anyhow::anyhow!("image_id mismatch"));
        }
        let receipt_journal = base64::engine::general_purpose::STANDARD
            .decode(rest.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to decode MOCKJ1 b64: {e}"))?;
        if supplied_journal != receipt_journal {
            return Err(anyhow::anyhow!(
                "journal_b64 does not match receipt journal"
            ));
        }
        let j = bincode::deserialize::<InferenceJournalV1>(&receipt_journal)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize MOCKJ1 journal: {e}"))?;
        return Ok(VerifiedZkJournal::Inference(j));
    }

    if let Some(rest) = receipt_b64.strip_prefix("MOCKZC1:") {
        if !mock_zk_allowed() {
            return Err(anyhow::anyhow!(
                "mock zk receipt rejected; set TET_ALLOW_MOCK_ZK=1 for dev/test"
            ));
        }
        if image_id != methods::NEXUS_GUEST_ID {
            return Err(anyhow::anyhow!("image_id mismatch"));
        }
        let receipt_journal = base64::engine::general_purpose::STANDARD
            .decode(rest.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to decode MOCKZC1 b64: {e}"))?;
        if supplied_journal != receipt_journal {
            return Err(anyhow::anyhow!(
                "journal_b64 does not match receipt journal"
            ));
        }
        let j = bincode::deserialize::<ZkCourtJournalV1>(&receipt_journal)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize MOCKZC1 journal: {e}"))?;
        return Ok(VerifiedZkJournal::ZkCourt(j));
    }

    let receipt_bytes = base64::engine::general_purpose::STANDARD
        .decode(receipt_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to decode receipt b64: {e}"))?;
    let receipt: Receipt = bincode::deserialize(&receipt_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize receipt: {e}"))?;
    receipt
        .verify(image_id)
        .map_err(|e| anyhow::anyhow!("ZK Verification Math Failed: {e:?}"))?;

    if supplied_journal.as_slice() != receipt.journal.bytes.as_slice() {
        return Err(anyhow::anyhow!(
            "journal_b64 does not match receipt journal"
        ));
    }

    decode_journal_bytes(&supplied_journal)
}

pub fn verify_receipt(receipt_b64: &str) -> anyhow::Result<bool> {
    Ok(verify_receipt_with_size(receipt_b64)?.0)
}

pub fn verify_receipt_with_size(receipt_b64: &str) -> anyhow::Result<(bool, usize)> {
    // Dev-mode mock receipt: encoded `InferenceJournalV1` (no cryptographic proof).
    if let Some(rest) = receipt_b64.strip_prefix("MOCKJ1:") {
        if !mock_zk_allowed() {
            return Err(anyhow::anyhow!(
                "mock zk receipt rejected; set TET_ALLOW_MOCK_ZK=1 for dev/test"
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(rest.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to decode MOCKJ1 b64: {e}"))?;
        // Validate it at least deserializes.
        let _j: InferenceJournalV1 = bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize MOCKJ1 journal: {e}"))?;
        return Ok((true, bytes.len()));
    }

    // 1. Decode base64
    let receipt_bytes = base64::engine::general_purpose::STANDARD
        .decode(receipt_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to decode receipt b64: {e}"))?;
    let proof_size = receipt_bytes.len();

    // 2. Deserialize into RISC Zero Receipt
    let receipt: Receipt = bincode::deserialize(&receipt_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize receipt: {}", e))?;

    // 3. Verify against the Image ID (generated by `methods` crate).
    let image_id = methods::NEXUS_GUEST_ID;
    match receipt.verify(image_id) {
        Ok(_) => Ok((true, proof_size)),
        Err(e) => {
            log::error!("ZK Verification Math Failed: {:?}", e);
            Ok((false, proof_size))
        }
    }
}

#[allow(dead_code)]
pub fn verify_and_extract_inference_journal(
    receipt_b64: &str,
) -> anyhow::Result<InferenceJournalV1> {
    if let Some(rest) = receipt_b64.strip_prefix("MOCKJ1:") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(rest.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to decode MOCKJ1 b64: {e}"))?;
        let j: InferenceJournalV1 = bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize MOCKJ1 journal: {e}"))?;
        return Ok(j);
    }
    let receipt_bytes = base64::engine::general_purpose::STANDARD
        .decode(receipt_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to decode receipt b64: {e}"))?;
    let receipt: Receipt = bincode::deserialize(&receipt_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize receipt: {}", e))?;

    // Verify first: do not decode untrusted journal before cryptographic verification.
    let image_id = methods::NEXUS_GUEST_ID;
    receipt
        .verify(image_id)
        .map_err(|e| anyhow::anyhow!("ZK Verification Math Failed: {e:?}"))?;

    receipt
        .journal
        .decode()
        .map_err(|e| anyhow::anyhow!("Failed to decode inference journal: {e:?}"))
}

pub fn verify_and_extract_inference_journal_with_size(
    receipt_b64: &str,
) -> anyhow::Result<(InferenceJournalV1, usize)> {
    if let Some(rest) = receipt_b64.strip_prefix("MOCKJ1:") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(rest.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to decode MOCKJ1 b64: {e}"))?;
        let proof_size = bytes.len();
        let j: InferenceJournalV1 = bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize MOCKJ1 journal: {e}"))?;
        return Ok((j, proof_size));
    }
    let receipt_bytes = base64::engine::general_purpose::STANDARD
        .decode(receipt_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to decode receipt b64: {e}"))?;
    let proof_size = receipt_bytes.len();
    let receipt: Receipt = bincode::deserialize(&receipt_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize receipt: {}", e))?;

    let image_id = methods::NEXUS_GUEST_ID;
    receipt
        .verify(image_id)
        .map_err(|e| anyhow::anyhow!("ZK Verification Math Failed: {e:?}"))?;

    let journal: InferenceJournalV1 = receipt
        .journal
        .decode()
        .map_err(|e| anyhow::anyhow!("Failed to decode inference journal: {e:?}"))?;
    Ok((journal, proof_size))
}
