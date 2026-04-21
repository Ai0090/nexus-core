// TET Enterprise SDK (Node.js ESM)
// Requires Node 18+ (global fetch) and a build that can import `scripts/wallet_client_entry.mjs`.

import { webcrypto as nodeWebCrypto } from "node:crypto";
import {
  tetWalletIdFromMnemonic,
  tetMldsa44PubkeyB64FromMnemonic,
  tetSignEnterpriseInferenceHybrid,
  validateMnemonicPhrase,
} from "../scripts/wallet_client_entry.mjs";

const subtle = (globalThis.crypto && globalThis.crypto.subtle) ? globalThis.crypto.subtle : nodeWebCrypto.subtle;

function cleanMnemonic(rawInput) {
  return String(rawInput ?? "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

async function sha256HexUtf8(s) {
  const bytes = new TextEncoder().encode(String(s || ""));
  const dig = await subtle.digest("SHA-256", bytes);
  const u8 = new Uint8Array(dig);
  let hex = "";
  for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, "0");
  return hex;
}

function amountToMicro(amount) {
  const raw = typeof amount === "number" ? String(amount) : String(amount || "").trim();
  const m = raw.match(/^(\d+)(?:\.(\d+))?$/);
  if (!m) throw new Error("invalid amount");
  const whole = BigInt(m[1] || "0");
  const fracRaw = String(m[2] || "");
  const frac = (fracRaw + "00000000").slice(0, 8);
  const fracN = BigInt(frac || "0");
  const micro = whole * 100000000n + fracN;
  if (micro <= 0n) throw new Error("amount too small");
  if (micro > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("amount too large");
  return Number(micro);
}

function coreBaseFromEnv() {
  const raw = String(process.env.TET_CORE_BASE || "").trim().replace(/\/$/, "");
  if (!raw) {
    throw new Error("TET_CORE_BASE is required (e.g. https://your-node.example.com)");
  }
  return raw;
}
function coreApi(path) {
  const p = String(path || "").startsWith("/") ? String(path || "") : `/${path}`;
  return `${coreBaseFromEnv()}${p}`;
}

async function fetchJsonLoose(url, opts) {
  const r = await fetch(url, opts || {});
  const raw = await r.text();
  const trimmed = raw.trim();
  let data = {};
  if (trimmed) {
    try {
      data = JSON.parse(trimmed);
    } catch {
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${trimmed.slice(0, 400)}`);
      return { _plain: trimmed };
    }
  }
  if (!r.ok) {
    const msg =
      data && typeof data === "object" ? String(data.message || data.error || trimmed || r.status) : String(r.status);
    const e = new Error(msg);
    e.status = r.status;
    if (data && typeof data === "object" && (data.error || data.code)) e.code = String(data.error || data.code);
    throw e;
  }
  return data;
}

function rethrowEnterpriseFriendly(e) {
  const code = e && e.code ? String(e.code) : "";
  if (code === "AI_ENGINE_NOT_RUNNING") {
    const err = new Error(
      "TET Network Error: No active worker nodes currently have the AI engine (Ollama) installed and running. Please try again later or increase your compute bounty."
    );
    err.code = code;
    if (e && e.status) err.status = e.status;
    err.cause = e;
    throw err;
  }
  throw e;
}

export class TetEnterpriseSDK {
  constructor(mnemonic12, opts = {}) {
    this.mnemonic = cleanMnemonic(mnemonic12);
    if (!this.mnemonic) throw new Error("mnemonic required");
    this.coreBase = String(opts.coreBase || coreBaseFromEnv()).trim().replace(/\/$/, "");
    this._wid = null;
  }

  async walletId() {
    if (this._wid) return this._wid;
    if (!validateMnemonicPhrase(this.mnemonic)) throw new Error("invalid mnemonic phrase");
    this._wid = tetWalletIdFromMnemonic(this.mnemonic);
    return this._wid;
  }

  async inference({ prompt, amount, model, attestationRequired } = {}) {
    const p = String(prompt || "").trim();
    const m = String(model || "").trim();
    if (!p) throw new Error("prompt required");
    if (!m) throw new Error("model required");
    const amountMicro = amountToMicro(amount);
    const attReq = !!attestationRequired;

    const wid = await this.walletId();

    // Zero-trust server uses active wallet; set it explicitly.
    await fetchJsonLoose(`${this.coreBase}/wallet/active_public`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ wallet_id: wid }),
    });

    const promptHash = await sha256HexUtf8(p);
    const nonceData = await fetchJsonLoose(`${this.coreBase}/wallet/nonce/${encodeURIComponent(wid)}`);
    const nonce = Number(nonceData.next_nonce || 0);
    if (!Number.isFinite(nonce) || nonce <= 0) throw new Error("could not obtain next_nonce");

    // Hybrid signature binds to exact payload.
    const sig = await tetSignEnterpriseInferenceHybrid(
      this.mnemonic,
      wid,
      nonce,
      amountMicro,
      promptHash,
      m,
      attReq
    );

    const env = {
      v: 1,
      tx: {
        kind: "enterprise_inference",
        enterprise_wallet_id: wid,
        prompt: p,
        model: m,
        amount_micro: amountMicro,
        nonce,
        prompt_sha256_hex: promptHash,
        attestation_required: attReq,
      },
      sig: {
        ed25519_pubkey_hex: wid,
        ed25519_sig_b64: sig.ed25519_sig_b64,
        mldsa_pubkey_b64: sig.mldsa_pubkey_b64 || tetMldsa44PubkeyB64FromMnemonic(this.mnemonic),
        mldsa_sig_b64: sig.mldsa_signature_b64,
      },
      attestation: { platform: "", report_b64: "" },
    };

    try {
      return await fetchJsonLoose(`${this.coreBase}/enterprise/inference`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(env),
      });
    } catch (e) {
      rethrowEnterpriseFriendly(e);
    }
  }
}

