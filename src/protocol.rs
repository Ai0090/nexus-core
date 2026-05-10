use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WorkloadFlag {
    Standard = 0,
    AiInference = 1,
}

impl WorkloadFlag {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

pub fn default_ai_workload_flag() -> u8 {
    WorkloadFlag::AiInference.as_u8()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTxEnvelopeV1 {
    pub v: u32,
    pub tx: TxV1,
    pub sig: HybridSigV1,
    pub attestation: AttestationV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TxV1 {
    /// Links a native signer to the running tet-core instance.
    ///
    /// This is a control-plane message only (no ledger mutation).
    SignerLink {
        /// Wallet identifier to display/use on this node.
        wallet_id: String,
    },
    /// Registers a Founding Member certificate bound to the caller's hardware attestation.
    ///
    /// This is a control-plane message only (no ledger mutation). The server persists the binding
    /// of `member_wallet` -> `hardware_id` derived from the attestation payload.
    FoundingMemberEnroll { member_wallet: String },
    Transfer {
        from_wallet: String,
        to_wallet: String,
        amount_micro: u64,
        fee_bps: u64,
    },
    GenesisBridge {
        founder_wallet: String,
        to_wallet: String,
        amount_micro: u64,
    },
    /// Enterprise demand-side inference request (B2B).
    ///
    /// The canonical signature message binds authorization to:
    /// `enterprise_wallet_id`, `nonce`, `amount_micro`, `prompt_sha256_hex`, and `model`.
    EnterpriseInference {
        enterprise_wallet_id: String,
        /// Plain prompt payload (server re-hashes and enforces `prompt_sha256_hex` match).
        prompt: String,
        /// Optional model selector (client-visible; server may map/ignore).
        model: String,
        amount_micro: u64,
        nonce: u64,
        prompt_sha256_hex: String,
        /// Whitepaper §5 Workload Flag: `1` = AI inference request.
        #[serde(default = "default_ai_workload_flag")]
        workload_flag: u8,
        /// If true, only route to workers with a verified hardware attestation (Founding cert).
        #[serde(default)]
        attestation_required: bool,
    },

    /// Verify a RISC Zero ZK-VM receipt on-chain (Phase 3).
    ///
    /// `receipt_b64` uses STANDARD base64 over `bincode`-serialized `risc0_zkvm::Receipt`.
    /// For local/dev tests, a mock receipt may be supplied with prefix `MOCKJ1:` (see `zk_verifier`).
    VerifyZkProof {
        /// Original `EnterpriseInference` transaction hash. Used by consensus to settle exactly one
        /// winning proof per AI task.
        #[serde(default)]
        task_id: String,
        image_id: [u32; 8],
        /// Public journal bytes (STANDARD base64). For RISC Zero receipts this should match `receipt.journal`.
        journal_b64: String,
        /// Receipt bytes (STANDARD base64), or dev-mode mock prefix `MOCKJ1:...`.
        receipt_b64: String,
    },
}

impl TxV1 {
    pub fn workload_flag(&self) -> WorkloadFlag {
        match self {
            Self::EnterpriseInference { workload_flag, .. }
                if *workload_flag == WorkloadFlag::AiInference.as_u8() =>
            {
                WorkloadFlag::AiInference
            }
            _ => WorkloadFlag::Standard,
        }
    }

    pub fn is_ai_workload(&self) -> bool {
        self.workload_flag() == WorkloadFlag::AiInference
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSigV1 {
    pub ed25519_pubkey_hex: String,
    pub ed25519_sig_b64: String,
    /// In production mode this should be base64 public key bytes (Dilithium2/ML-DSA family).
    pub mldsa_pubkey_b64: String,
    pub mldsa_sig_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationV1 {
    /// "macos-se" | "windows-tpm" | "android-strongbox" | ...
    pub platform: String,
    /// Base64 of provider-specific attestation payload.
    pub report_b64: String,
}
