## Contributing

Thanks for helping build TET-Network.

### Ground rules

- **No secrets**: never commit `.env`, private keys, local databases, or credentials.
- **Keep CI green**: PRs must pass formatting, clippy (no warnings), and tests.
- **Small, reviewable changes**: prefer focused PRs with clear commit messages.

### Development workflow

```bash
cargo fmt
RISC0_SKIP_BUILD=1 cargo clippy -- -D warnings
RISC0_SKIP_BUILD=1 cargo test
```

### CI notes (RISC0)

CI sets `RISC0_SKIP_BUILD=1` by default to avoid requiring the guest toolchain on every runner.
If your change touches guest code, run the full guest build locally in your environment.

## コントリビュート（日本語）

TET-Network への貢献ありがとうございます。

### ルール

- **シークレット禁止**: `.env`、秘密鍵、ローカルDB、認証情報はコミットしない。
- **CI を常に緑に**: フォーマット、Clippy（警告ゼロ）、テストがすべて通ること。
- **小さくレビューしやすく**: 目的が明確な差分・コミットを優先する。

### 開発フロー

```bash
cargo fmt
RISC0_SKIP_BUILD=1 cargo clippy -- -D warnings
RISC0_SKIP_BUILD=1 cargo test
```

### CI 補足（RISC0）

CI は `RISC0_SKIP_BUILD=1` をデフォルトで設定し、ゲスト用ツールチェーン無しでも検証できるようにしています。
ゲスト側の変更を含む場合は、各自の環境でフルビルドも実施してください。

