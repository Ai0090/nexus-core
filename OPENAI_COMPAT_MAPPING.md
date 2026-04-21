## OpenAI Compatibility Mapping (Prototype)

The TET Network B2B API Gateway treats **OpenAI compatibility** as a first-class requirement.

### Implemented (prototype)
- **`POST /v1/chat/completions`**
  - minimal request/response compatibility with OpenAI Chat Completions
  - accepts `model`, `messages`, `max_tokens` and routes inference tasks into the TET network

### Developer Telemetry / Ledger
- **`GET /economics/snapshot`**: energy & economics snapshot, including ESR (Energy Standard Ratio)
- **`GET /ledger/proof`**, **`GET /ledger/proof/{id}`**: Proof-of-Energy (third-party verifiable)
- **`POST /ledger/transfer`**: TET transfer (Protocol Fee 0.5–1.0% → Network Operations)

### Compatibility Roadmap (Phase 4)
- `GET /v1/models`
- `POST /v1/embeddings`
- `POST /v1/responses` (new Responses API family)
- org/project-scoped API keys, billing, and rate controls

