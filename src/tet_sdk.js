// TET Enterprise SDK (browser-first foundation)
// Usage:
//   const tet = new TetEnterpriseSDK("twelve words ...");
//   const res = await tet.inference({ prompt: "Draw a futuristic city", amount: 10, model: "TET-Vision-v1" });
//   console.log(res);

(function () {
  const STEVEMON = 100_000_000;

  function coreBase() {
    const raw = String(localStorage.getItem("tet-core-base") || "")
      .trim()
      .replace(/\/$/, "");
    try {
      if (raw) return new URL(raw).origin;
    } catch (_) {}
    try {
      const here = new URL(window.location.href);
      if (here.protocol === "http:" || here.protocol === "https:") return here.origin;
    } catch (_) {}
    return "";
  }
  function coreApi(path) {
    const p = String(path || "").startsWith("/") ? String(path || "") : `/${path}`;
    return `${coreBase()}${p}`;
  }

  function cleanMnemonic(rawInput) {
    return String(rawInput ?? "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, " ");
  }

  async function sha256HexUtf8(s) {
    const bytes = new TextEncoder().encode(String(s || ""));
    const dig = await crypto.subtle.digest("SHA-256", bytes);
    const u8 = new Uint8Array(dig);
    let hex = "";
    for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, "0");
    return hex;
  }

  function amountToMicro(amount) {
    // Accept number or string; convert to micro-TET (STEVEMON = 1e8) without float precision loss.
    const raw = typeof amount === "number" ? String(amount) : String(amount || "").trim();
    const m = raw.match(/^(\d+)(?:\.(\d+))?$/);
    if (!m) throw new Error("invalid amount");
    const whole = BigInt(m[1] || "0");
    const fracRaw = String(m[2] || "");
    const frac = (fracRaw + "00000000").slice(0, 8); // pad/truncate to 8 decimals
    const fracN = BigInt(frac || "0");
    const micro = whole * 100000000n + fracN;
    if (micro <= 0n) throw new Error("amount too small");
    if (micro > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("amount too large");
    }
    return Number(micro);
  }

  async function ensureWalletClient() {
    if (window.tetWalletClient) return;
    await new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = coreApi("/assets/wallet_client_bundled.js");
      s.onload = () => resolve();
      s.onerror = () => reject(new Error("failed to load /assets/wallet_client_bundled.js"));
      document.head.appendChild(s);
    });
    if (!window.tetWalletClient) throw new Error("tetWalletClient not available");
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

  class TetEnterpriseSDK {
    constructor(mnemonic12) {
      this.mnemonic = cleanMnemonic(mnemonic12);
      if (!this.mnemonic) throw new Error("mnemonic required");
      this._wid = null;
    }

    async walletId() {
      if (this._wid) return this._wid;
      await ensureWalletClient();
      if (!window.tetWalletClient.validateMnemonicPhrase(this.mnemonic)) {
        throw new Error("invalid mnemonic phrase");
      }
      this._wid = window.tetWalletClient.tetWalletIdFromMnemonic(this.mnemonic);
      return this._wid;
    }

    async inference({ prompt, amount, model, attestationRequired }) {
      const p = String(prompt || "").trim();
      const m = String(model || "").trim();
      if (!p) throw new Error("prompt required");
      if (!m) throw new Error("model required");
      const amountMicro = amountToMicro(amount);

      await ensureWalletClient();
      const wid = await this.walletId();

      // Zero-trust server uses active wallet; set it explicitly.
      await fetchJsonLoose(coreApi("/wallet/active_public"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ wallet_id: wid }),
      });

      const promptHash = await sha256HexUtf8(p);
      const attReq = !!attestationRequired;

      // Use the server nonce source for monotonicity across processes.
      const nonceData = await fetchJsonLoose(coreApi("/wallet/nonce/" + encodeURIComponent(wid)));
      const nonce = Number(nonceData.next_nonce || 0);
      if (!Number.isFinite(nonce) || nonce <= 0) throw new Error("could not obtain next_nonce");

      const sig = await window.tetWalletClient.tetSignEnterpriseInferenceHybrid(
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
          mldsa_pubkey_b64: sig.mldsa_pubkey_b64,
          mldsa_sig_b64: sig.mldsa_signature_b64,
        },
        attestation: { platform: "", report_b64: "" },
      };

      try {
        return await fetchJsonLoose(coreApi("/enterprise/inference"), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(env),
        });
      } catch (e) {
        rethrowEnterpriseFriendly(e);
      }
    }
  }

  window.TetEnterpriseSDK = TetEnterpriseSDK;
})();

