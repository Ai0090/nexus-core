## External Chain Compatibility (Bridge Interfaces)

Goal: keep TET interoperable by enabling future management via MetaMask / Phantom, without locking it inside a single ecosystem.

### 1) ERC-20 Wrapper (Ethereum)
- **`deposit(bytes32 tetRecipient, uint256 amount, bytes proof)`**
  - external chain → TET Core (mint wrapped representation)
- **`withdraw(address erc20Recipient, uint256 amount, bytes tetProof)`**
  - TET Core → external chain (burn wrapped representation)
- **Events**
  - `Deposited(tetRecipient, amount, txHash)`
  - `Withdrawn(erc20Recipient, amount, tetProofHash)`

### 2) SPL Wrapper (Solana)
- same shape as ERC-20 (deposit/withdraw + events/logs)
- SPL Token Program compatible interfaces for Phantom integration

### 3) Security Boundary (Phase 4)
- run bridges as a dedicated **edge service** (gateway/bridge boundary)
- require audit logs + correlation IDs, similar to Proof-of-Energy / Attestation flows
- keep the approach: “stub first → incremental production hardening”

