## TET-Network / tet-core

TET-Network is an experimental Rust codebase for a minimal L1-style ledger + P2P mesh, designed to evolve toward a trustless, verifiable compute network.

### Features

- **Hybrid cryptography**: Ed25519 + ML-DSA (Dilithium-style) paths for sensitive flows
- **Ledger + state root**: deterministic state root computed from all balances
- **Mempool + mining**: transactions are queued then applied as a block (`/ledger/mine`)
- **P2P autonomous mesh**: libp2p (Gossipsub/Kademlia/Identify/mDNS) for state sync
- **ZK-VM integration (RISC Zero)**: `VerifyZkProof` transaction type and `/ledger/zk_verify`

### Quick start (English)

#### Prerequisites

- Rust toolchain (stable)
- (Optional) Node.js for web assets if you use the UI pieces
- (Optional) RISC Zero toolchain for guest builds (CI skips guest build by default)

#### Build / lint / test

```bash
cargo fmt
RISC0_SKIP_BUILD=1 cargo clippy -- -D warnings
RISC0_SKIP_BUILD=1 cargo test
```

#### Run a local node

```bash
cp .env.example .env
# edit .env
cargo run
```

### クイックスタート（日本語）

TET-Network は、Rust で書かれた最小構成の L1 風 Ledger と P2P メッシュを統合し、検証可能な計算ネットワークへ進化させるための実験的コードベースです。

#### 主な特徴

- **ハイブリッド暗号**: Ed25519 + ML-DSA（Dilithium系）を重要フローで併用
- **Ledger + State Root**: 全残高から決定論的に State Root を計算
- **Mempool + マイニング**: tx をプールし、`/ledger/mine` でブロックとして適用
- **P2P 自律メッシュ**: libp2p（Gossipsub/Kademlia/Identify/mDNS）で状態同期
- **ZK-VM（RISC Zero）統合**: `VerifyZkProof` と `/ledger/zk_verify`

#### ビルド / 静的解析 / テスト

```bash
cargo fmt
RISC0_SKIP_BUILD=1 cargo clippy -- -D warnings
RISC0_SKIP_BUILD=1 cargo test
```

#### ローカル起動

```bash
cp .env.example .env
# .env を編集
cargo run
```

### License

Dual-licensed under **Apache-2.0** (`LICENSE-APACHE`) OR **MIT** (`LICENSE-MIT`).

