const key = (localStorage.getItem("x-api-key") || "");
const SIGNER = (localStorage.getItem("tet-signer-base") || "http://localhost:5791")
  .trim()
  .replace(/\/$/, "");
const STEVEMON = 100_000_000;
const LS_WALLET_ID_KEY = "tet-wallet-id";

function getCoreBase() {
  const raw = (localStorage.getItem("tet-core-base") || "").trim().replace(/\/$/, "");
  try {
    if (raw) {
      const u = new URL(raw);
      if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("protocol");
      return u.origin;
    }
    const here = new URL(window.location.href);
    if (here.protocol === "http:" || here.protocol === "https:") {
      return here.origin;
    }
    return "";
  } catch {
    return "";
  }
}
/** TET core HTTP API (Rust). Invalid `tet-core-base` values are ignored to avoid fetch URL SyntaxError (WebKit). */
function coreApi(path) {
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${getCoreBase()}${p}`;
}

function setCurrentWalletId(wid) {
  const w = String(wid || "").trim().toLowerCase();
  if (w && w.length === 64) {
    try {
      localStorage.setItem(LS_WALLET_ID_KEY, w);
    } catch (_) {}
  }
}

function getCurrentWalletId() {
  return String(localStorage.getItem(LS_WALLET_ID_KEY) || "").trim().toLowerCase();
}

/** Read body as text, parse JSON safely; avoids `response.json()` / `JSON.parse` surprising SyntaxError. */
async function fetchJsonLoose(url, opts) {
  const r = await fetch(url, opts || {});
  const raw = await r.text();
  let data = {};
  const trimmed = raw.trim();
  if (trimmed) {
    try {
      data = JSON.parse(trimmed);
    } catch {
      if (!r.ok) {
        throw new Error(`HTTP ${r.status}: ${trimmed.slice(0, 400)}`);
      }
      return { _plain: trimmed };
    }
  }
  if (typeof data !== "object" || data === null) {
    if (!r.ok) {
      throw new Error(String(trimmed || r.status));
    }
    return { _plain: String(data) };
  }
  if (!r.ok) {
    const msg =
      (data.error !== undefined || data.message !== undefined)
        ? String(data.error ?? data.message)
        : trimmed.slice(0, 400) || String(r.status);
    const e = new Error(msg);
    if (data && typeof data === "object") {
      const c = data.error || data.code;
      if (c != null && String(c).trim()) e.code = String(c).trim();
    }
    e.status = r.status;
    throw e;
  }
  return data;
}

/** Normalize `/ai/utility` (and similar) payloads whether JSON object or plain text wrapper. */
function textFromUtilityResponse(j) {
  let body = "";
  let note = "";
  if (j != null && typeof j === "object") {
    note = j.note != null ? String(j.note) : "";
    if (j._plain != null) body = String(j._plain);
    else if (j.response != null) body = String(j.response);
    else if (j.output != null) body = String(j.output);
    else if (j.text != null) body = String(j.text);
    else body = JSON.stringify(j);
  } else if (typeof j === "string") {
    body = j;
  } else {
    body = String(j ?? "");
  }
  return { body, note };
}

async function typewriterAppend(chatEl, chunk, msPerChar = 3) {
  if (!chatEl || chunk == null || chunk === "") return;
  const s = String(chunk);
  for (let i = 0; i < s.length; i++) {
    chatEl.value += s[i];
    chatEl.scrollTop = chatEl.scrollHeight;
    await new Promise((res) => setTimeout(res, msPerChar));
  }
}

function chatAppendInstant(chatEl, chunk) {
  if (!chatEl || chunk == null || chunk === "") return;
  chatEl.value += String(chunk);
  chatEl.scrollTop = chatEl.scrollHeight;
}

const UTILITY_NETWORK_UNAVAILABLE_MSG =
  "[NETWORK STATUS: UNAVAILABLE]\n" +
  "Reason: 0 Active Worker Nodes found.\n" +
  "Action Required: The TET Network relies on decentralized compute. Please connect a worker node (Miner) to the P2P network to process this AI request.";

let __toastCssInjected = false;
function showToast(msg) {
  try {
    if (!__toastCssInjected) {
      const st = document.createElement("style");
      st.textContent =
        ".tet-toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);z-index:9999;" +
        "background:rgba(0,0,0,.92);border:1px solid rgba(212,196,168,.35);color:#fafafa;" +
        "padding:12px 14px;border-radius:12px;min-width:280px;max-width:min(560px,92vw);" +
        "font-family:ui-monospace, 'Roboto Mono', monospace;font-size:12px;letter-spacing:.02em;" +
        "box-shadow:0 18px 60px rgba(0,0,0,.55)}";
      document.head.appendChild(st);
      __toastCssInjected = true;
    }
    const d = document.createElement("div");
    d.className = "tet-toast";
    d.textContent = String(msg);
    document.body.appendChild(d);
    setTimeout(() => d.remove(), 2600);
  } catch (_) {}
}

async function withTimeout(promise, ms) {
  let t;
  const timeout = new Promise((_, rej) => {
    t = setTimeout(() => rej(new Error("timeout")), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(t);
  }
}

// Local AI verification (Ollama): ping localhost every 5s.
async function pingLocalOllamaUi() {
  const st = document.getElementById("uiAiEngineStatus");
  const hint = document.getElementById("uiAiEngineHint");
  if (!st || !hint) return false;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 900);
  try {
    // CORS note: `no-cors` returns opaque responses (status not readable),
    // but a successful TCP connection resolves. Connection refused rejects.
    await fetch("http://127.0.0.1:11434/api/tags", {
      method: "GET",
      mode: "no-cors",
      cache: "no-store",
      signal: ctrl.signal,
    });
    st.textContent = "🟢 AI_ENGINE: ONLINE & READY";
    st.style.color = "#00ff00";
    hint.textContent = "Local Ollama detected on 127.0.0.1:11434.";
    return true;
  } catch (_) {
    st.textContent = "🔴 AI_ENGINE: OFFLINE";
    st.style.color = "#ff0000";
    hint.textContent = "No local Ollama detected. Install and run Ollama, then re-check.";
    return false;
  } finally {
    clearTimeout(t);
  }
}

const TET_ENC_STORAGE_KEY = "tet-enc-wallet-v1";
const PBKDF_ITERATIONS = 250000;

function cleanMnemonic(rawInput) {
  return String(rawInput ?? "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

function shortWid(wid) {
  const w = String(wid || "").trim();
  if (w.length <= 18) return w || "—";
  return w.slice(0, 10) + "…" + w.slice(-8);
}

function bufToB64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64ToBuf(b64) {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

async function deriveAesKeyFromPin(pin, saltBuf) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBuf,
      iterations: PBKDF_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMnemonicLocal(mnemonic, pin) {
  await ensureTetWalletClient();
  mnemonic = cleanMnemonic(mnemonic);
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const rawKey = window.tetWalletClient.tetArgon2idKey32(pin, salt);
  const key = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(mnemonic)
  );
  return {
    v: 2,
    kdf: "argon2id",
    c: bufToB64(ct),
    salt: bufToB64(salt),
    iv: bufToB64(iv),
  };
}

async function decryptMnemonicLocal(bundle, pin) {
  const salt = b64ToBuf(bundle.salt);
  const iv = b64ToBuf(bundle.iv);
  const rawCt = b64ToBuf(bundle.c);
  const useArgon2 = bundle.v === 2 || bundle.kdf === "argon2id";
  let key;
  if (useArgon2) {
    await ensureTetWalletClient();
    const rawKey = window.tetWalletClient.tetArgon2idKey32(pin, salt);
    key = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  } else {
    key = await deriveAesKeyFromPin(pin, salt);
  }
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    rawCt
  );
  return cleanMnemonic(new TextDecoder().decode(pt));
}

/** PIN を一度だけ聞き、localStorage の暗号化ニーモニックを復号（サーバーには送らない）。 */
async function promptPinAndDecryptStoredMnemonic() {
  const raw = localStorage.getItem(TET_ENC_STORAGE_KEY);
  if (!raw) {
    throw new Error("No encrypted wallet in this browser. Unlock or complete onboarding first.");
  }
  const pin = window.prompt(
    "Enter your PIN to sign this transfer (stays in this tab only; not sent to the server):"
  );
  if (pin == null || pin === "") {
    throw new Error("Cancelled.");
  }
  try {
    const bundle = JSON.parse(raw);
    return cleanMnemonic(await decryptMnemonicLocal(bundle, pin));
  } catch (e) {
    const name = e && e.name;
    if (name === "OperationError") {
      throw new Error("Wrong PIN.");
    }
    throw e;
  }
}

/** Load bundled non-custodial wallet crypto from the core if the static tag failed (wrong base URL, etc.). */
async function loadWalletClientScript() {
  if (window.tetWalletClient) return;
  await new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = coreApi("/assets/wallet_client_bundled.js?v=genesis_v3");
    s.async = true;
    s.onload = () => res();
    s.onerror = () =>
      rej(new Error("Could not load wallet_client_bundled.js from core (check tet-core-base)."));
    document.head.appendChild(s);
  });
}

async function ensureTetWalletClient() {
  await loadWalletClientScript();
  if (!window.tetWalletClient) {
    throw new Error("Wallet crypto bundle not loaded (expected /assets/wallet_client_bundled.js).");
  }
}

let __obPendingMnemonic = "";
let __tetAppStarted = false;

function setUxApp() {
  document.documentElement.setAttribute("data-ux", "app");
}

function showObStep(stepId) {
  for (const id of [
    "obStepWelcome",
    "obStepPhrase",
    "obStepRestore",
    "obStepPin",
  ]) {
    const el = document.getElementById(id);
    if (el) el.hidden = id !== stepId;
  }
}

function startMainAppLoop() {
  if (__tetAppStarted) return;
  __tetAppStarted = true;
  const modelEl = document.getElementById("model");
  if (modelEl && !modelEl.value) modelEl.value = "llama3";
  if (modelEl) {
    modelEl.addEventListener("change", () => refreshQuote().catch(() => {}));
  }
  // Local Ollama ping (UI only; best-effort)
  const chk = document.getElementById("btnUiCheckAiEngine");
  if (chk) chk.onclick = () => pingLocalOllamaUi().catch(() => {});
  pingLocalOllamaUi().catch(() => {});
  setInterval(() => pingLocalOllamaUi().catch(() => {}), 5000);
  const promptEl = document.getElementById("prompt");
  let quoteTimer = null;
  if (promptEl) {
    promptEl.addEventListener("input", () => {
      clearTimeout(quoteTimer);
      quoteTimer = setTimeout(() => refreshQuote().catch(() => {}), 450);
    });
  }
  (async () => {
    await refreshTop();
    queueMicrotask(() =>
      drawTradingChart("chartTflops", liveChartHist.tf, liveChartHist.px)
    );
    setInterval(refreshTop, 4000);
    try {
      await refreshQuote();
    } catch (_) {}
  })();
}

async function doLogoutHard() {
  const ok = window.confirm(
    "WARNING: If you haven't backed up your 12-word recovery phrase, your funds will be lost forever. Proceed?"
  );
  if (!ok) return;
  // Best-effort: tell core to flush/snapshot immediately.
  try {
    await withTimeout(
      fetchJsonLoose(coreApi("/logout"), { method: "POST", keepalive: true }),
      1200
    );
  } catch (_) {}
  try {
    // Clear sensitive frontend session material.
    localStorage.removeItem(TET_ENC_STORAGE_KEY);
    localStorage.removeItem("x-api-key");
    sessionStorage.clear();
  } catch (_) {}
  window.location.reload();
}

// Highly visible logout (clears local encrypted wallet).
(function wireLogoutTop() {
  const btn = document.getElementById("btnLogoutTop");
  if (!btn) return;
  const show = () => {
    try {
      btn.style.display = localStorage.getItem(TET_ENC_STORAGE_KEY) ? "block" : "none";
    } catch (_) {
      btn.style.display = "none";
    }
  };
  show();
  btn.onclick = () => doLogoutHard();
  window.addEventListener("storage", () => show());
})();

function wireLockAndOnboarding() {
  const tos = document.getElementById("chkTosAgree");
  const btnGen = document.getElementById("btnObGenerate");
  if (tos && btnGen) {
    const sync = () => {
      btnGen.disabled = !tos.checked;
    };
    tos.onchange = sync;
    sync();
  }

  const btnUnlock = document.getElementById("btnUnlock");
  const btnForgot = document.getElementById("btnForgotPin");
  if (btnUnlock) {
    btnUnlock.onclick = async () => {
      const pin =
        (document.getElementById("unlockPin") &&
          document.getElementById("unlockPin").value) ||
        "";
      const msg = document.getElementById("unlockMsg");
      if (msg) msg.textContent = "";
      if (!pin) {
        if (msg) msg.textContent = "Enter your PIN.";
        return;
      }
      try {
        const raw = localStorage.getItem(TET_ENC_STORAGE_KEY);
        if (!raw) throw new Error("No wallet data");
        const bundle = JSON.parse(raw);
        const phrase = cleanMnemonic(await decryptMnemonicLocal(bundle, pin));
        await ensureTetWalletClient();
        if (!window.tetWalletClient.validateMnemonicPhrase(phrase)) {
          throw new Error("Invalid recovery phrase after decrypt.");
        }
        const wid = window.tetWalletClient.tetWalletIdFromMnemonic(phrase);
        setCurrentWalletId(wid);
        const up = document.getElementById("unlockPin");
        if (up) up.value = "";
        setUxApp();
        startMainAppLoop();
      } catch (e) {
        if (msg) {
          const name = e && e.name;
          msg.textContent =
            name === "OperationError" ? "Wrong PIN." : String(e);
        }
      }
    };
  }
  if (btnForgot) {
    btnForgot.onclick = () => {
      localStorage.removeItem(TET_ENC_STORAGE_KEY);
      document.documentElement.setAttribute("data-ux", "onboard");
      showObStep("obStepRestore");
      const um = document.getElementById("unlockMsg");
      if (um) um.textContent = "";
      const up = document.getElementById("unlockPin");
      if (up) up.value = "";
    };
  }

  const chkSaved = document.getElementById("chkObSaved");
  const btnAckHide = document.getElementById("btnObAckHide");
  if (chkSaved && btnAckHide) {
    chkSaved.onchange = () => {
      btnAckHide.disabled = !chkSaved.checked;
    };
    btnAckHide.disabled = true;
  }
  if (btnAckHide) {
    btnAckHide.onclick = () => {
      const chk = document.getElementById("chkObSaved");
      if (!chk || !chk.checked) return;
      const ta = document.getElementById("obPhraseTa");
      if (ta) ta.value = "";
      const widEl = document.getElementById("obPhraseWid");
      if (widEl) widEl.textContent = "—";
      const om = document.getElementById("obPhraseMsg");
      if (om) om.textContent = "Recovery phrase hidden on this screen.";
      showObStep("obStepPin");
    };
  }

  if (btnGen) {
    btnGen.onclick = async () => {
      const wm = document.getElementById("obWelcomeMsg");
      if (wm) wm.textContent = "";
      try {
        await ensureTetWalletClient();
        const phrase = cleanMnemonic(window.tetWalletClient.tetGenerateMnemonic12());
        __obPendingMnemonic = phrase;
        const wid = window.tetWalletClient.tetWalletIdFromMnemonic(phrase);
        const ta = document.getElementById("obPhraseTa");
        if (ta) ta.value = phrase;
        const widEl = document.getElementById("obPhraseWid");
        if (widEl) widEl.textContent = wid;
        const btnCopyWords = document.getElementById("btnCopyObPhrase");
        const btnCopyWid = document.getElementById("btnCopyObWid");
        if (btnCopyWords) {
          btnCopyWords.onclick = async () => {
            try {
              await navigator.clipboard.writeText(phrase);
              const om = document.getElementById("obPhraseMsg");
              if (om) om.textContent = "Copied 12 words to clipboard.";
            } catch (_) {}
          };
        }
        if (btnCopyWid) {
          btnCopyWid.onclick = async () => {
            try {
              await navigator.clipboard.writeText(wid);
              const om = document.getElementById("obPhraseMsg");
              if (om) om.textContent = "Copied Wallet ID to clipboard.";
            } catch (_) {}
          };
        }
        const chk = document.getElementById("chkObSaved");
        if (chk) chk.checked = false;
        if (btnAckHide) btnAckHide.disabled = true;
        const om = document.getElementById("obPhraseMsg");
        if (om) om.textContent = "";
        showObStep("obStepPhrase");
      } catch (e) {
        if (wm) wm.textContent = String(e);
      }
    };
  }
  const btnRestore = document.getElementById("btnObRestore");
  if (btnRestore) {
    btnRestore.onclick = () => showObStep("obStepRestore");
  }
  const btnRestoreNext = document.getElementById("btnObRestoreNext");
  const restoreTa = document.getElementById("obRestoreTa");
  const restoreDerived = document.getElementById("obRestoreDerived");
  const restoreDerivedMsg = document.getElementById("obRestoreDerivedMsg");
  let restoreTimer = null;
  async function updateRestoreDerived() {
    if (!restoreTa) return;
    const phrase = cleanMnemonic(restoreTa.value || "");
    if (!restoreDerived) return;
    if (!phrase) {
      restoreDerived.textContent = "—";
      if (restoreDerivedMsg) restoreDerivedMsg.textContent = "";
      return;
    }
    const words = phrase.split(" ").filter(Boolean);
    if (words.length !== 12) {
      restoreDerived.textContent = "—";
      if (restoreDerivedMsg) {
        restoreDerivedMsg.textContent = `Enter exactly 12 words. (${words.length}/12)`;
      }
      return;
    }
    try {
      await ensureTetWalletClient();
      if (!window.tetWalletClient.validateMnemonicPhrase(phrase)) {
        restoreDerived.textContent = "—";
        if (restoreDerivedMsg) restoreDerivedMsg.textContent = "Invalid BIP39 phrase.";
        return;
      }
      const wid = window.tetWalletClient.tetWalletIdFromMnemonic(phrase);
      restoreDerived.textContent = shortWid(wid);
      if (restoreDerivedMsg) restoreDerivedMsg.textContent = "Phrase looks valid. Wallet ID derived deterministically.";
    } catch (e) {
      restoreDerived.textContent = "—";
      if (restoreDerivedMsg) restoreDerivedMsg.textContent = String(e && e.message ? e.message : e);
    }
  }
  if (restoreTa) {
    restoreTa.addEventListener("input", () => {
      clearTimeout(restoreTimer);
      restoreTimer = setTimeout(() => updateRestoreDerived().catch(() => {}), 180);
    });
  }
  if (btnRestoreNext) {
    btnRestoreNext.onclick = async () => {
      const ta = document.getElementById("obRestoreTa");
      const m = document.getElementById("obRestoreMsg");
      const phrase = cleanMnemonic((ta && ta.value) || "");
      const words = phrase ? phrase.split(" ").filter(Boolean) : [];
      if (words.length !== 12) {
        if (m) m.textContent = "Enter exactly 12 words.";
        return;
      }
      try {
        await ensureTetWalletClient();
        if (!window.tetWalletClient.validateMnemonicPhrase(phrase)) {
          if (m) m.textContent = "Invalid BIP39 phrase.";
          return;
        }
      } catch (e) {
        if (m) m.textContent = String(e);
        return;
      }
      __obPendingMnemonic = phrase;
      if (ta) ta.value = "";
      if (m) m.textContent = "";
      if (restoreDerived) restoreDerived.textContent = "—";
      if (restoreDerivedMsg) restoreDerivedMsg.textContent = "";
      showObStep("obStepPin");
    };
  }
  const btnPinFinish = document.getElementById("btnObPinFinish");
  if (btnPinFinish) {
    btnPinFinish.onclick = async () => {
      const p1 =
        (document.getElementById("obPin1") &&
          document.getElementById("obPin1").value) ||
        "";
      const p2 =
        (document.getElementById("obPin2") &&
          document.getElementById("obPin2").value) ||
        "";
      const m = document.getElementById("obPinMsg");
      if (m) m.textContent = "";
      if (p1.length < 6) {
        if (m) m.textContent = "PIN must be at least 6 characters.";
        return;
      }
      if (p1 !== p2) {
        if (m) m.textContent = "PINs do not match.";
        return;
      }
      const phrase = cleanMnemonic(__obPendingMnemonic);
      if (!phrase) {
        if (m) m.textContent = "Missing recovery phrase.";
        return;
      }
      try {
        await ensureTetWalletClient();
        if (!window.tetWalletClient.validateMnemonicPhrase(phrase)) {
          throw new Error("Invalid recovery phrase.");
        }
        const bundle = await encryptMnemonicLocal(phrase, p1);
        localStorage.setItem(TET_ENC_STORAGE_KEY, JSON.stringify(bundle));
        const wid = window.tetWalletClient.tetWalletIdFromMnemonic(phrase);
        setCurrentWalletId(wid);
        __obPendingMnemonic = "";
        const p1e = document.getElementById("obPin1");
        const p2e = document.getElementById("obPin2");
        if (p1e) p1e.value = "";
        if (p2e) p2e.value = "";
        setUxApp();
        startMainAppLoop();
      } catch (e) {
        if (m) m.textContent = String(e);
      }
    };
  }

  // Default view
  if (localStorage.getItem(TET_ENC_STORAGE_KEY)) {
    document.documentElement.setAttribute("data-ux", "lock");
  } else {
    document.documentElement.setAttribute("data-ux", "onboard");
    showObStep("obStepWelcome");
  }
}

// Founder Control Panel (Genesis) for ui.html
(function wireFounderGenesisPanelUi() {
  const panel = document.getElementById("founderPanel");
  const cfgEl = document.getElementById("founderConfiguredWid");
  const ta = document.getElementById("founderMnemonic");
  const derivedEl = document.getElementById("founderDerivedWid");
  const chk = document.getElementById("chkFounderConfirm");
  const btn = document.getElementById("btnExecuteGenesis");
  const msg = document.getElementById("founderGenesisMsg");
  const wdAmt = document.getElementById("treasuryWithdrawAmt");
  const wdBtn = document.getElementById("btnWithdrawTreasury");
  const wdMsg = document.getElementById("treasuryWithdrawMsg");
  if (!panel || !cfgEl || !ta || !derivedEl || !chk || !btn || !msg) return;

  let configuredFounder = "";
  let derived = "";
  let tmr = null;

  const syncBtn = () => {
    const ok =
      chk.checked &&
      configuredFounder &&
      derived &&
      configuredFounder.toLowerCase() === derived.toLowerCase();
    btn.disabled = !ok;
    btn.style.opacity = ok ? "1" : "0.6";
    btn.style.cursor = ok ? "pointer" : "not-allowed";
  };

  const updateDerived = async () => {
    msg.textContent = "";
    msg.className = "msg mono";
    derived = "";
    derivedEl.textContent = "—";
    const phrase = cleanMnemonic(ta.value || "");
    if (!phrase) {
      syncBtn();
      return;
    }
    await ensureTetWalletClient();
    if (!window.tetWalletClient.validateMnemonicPhrase(phrase)) {
      msg.textContent = "Invalid mnemonic phrase.";
      msg.className = "msg mono";
      syncBtn();
      return;
    }
    derived = window.tetWalletClient.tetWalletIdFromMnemonic(phrase);
    derivedEl.textContent = derived;
    if (configuredFounder && derived.toLowerCase() !== configuredFounder.toLowerCase()) {
      msg.textContent = "Derived wallet does not match configured founder wallet.";
    }
    syncBtn();
  };

  ta.addEventListener("input", () => {
    clearTimeout(tmr);
    tmr = setTimeout(() => updateDerived().catch(() => {}), 160);
  });
  chk.onchange = syncBtn;

  (async () => {
    try {
      const s = await fetchJsonLoose(coreApi("/status"));
      configuredFounder = String(s.founder_wallet_id || "").trim();
      cfgEl.textContent = configuredFounder || "—";
      // Hide founder panel from normal users: show only when this browser's wallet_id matches founder.
      const wid = getCurrentWalletId();
      panel.style.display =
        configuredFounder && wid && configuredFounder.toLowerCase() === wid.toLowerCase()
          ? ""
          : "none";
      syncBtn();
    } catch (_) {
      panel.style.display = "none";
    }
  })();

  btn.onclick = async () => {
    msg.textContent = "";
    msg.className = "msg mono";
    try {
      await ensureTetWalletClient();
      const phrase = cleanMnemonic(ta.value || "");
      if (!window.tetWalletClient.validateMnemonicPhrase(phrase)) {
        throw new Error("Invalid recovery phrase.");
      }
      const wid = window.tetWalletClient.tetWalletIdFromMnemonic(phrase);
      if (!configuredFounder || wid.toLowerCase() !== configuredFounder.toLowerCase()) {
        throw new Error("Phrase does not match the configured founder wallet.");
      }
      btn.disabled = true;
      btn.textContent = "EXECUTING…";
      msg.textContent = "Signing locally (Ed25519 + ML-DSA-44)…";

      const sig = await window.tetWalletClient.tetSignFounderGenesisHybrid(phrase, wid);
      const r = await fetch(coreApi("/founder/genesis"), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-tet-founder-ed25519-sig-b64": sig.ed25519_sig_b64,
        },
        body: JSON.stringify({
          founder_wallet_id: wid,
          mldsa_pubkey_b64: sig.mldsa_pubkey_b64,
          mldsa_signature_b64: sig.mldsa_signature_b64,
        }),
      });
      const t = await r.text();
      if (!r.ok) throw new Error(t || String(r.status));
      msg.textContent = "GENESIS EXECUTED. Founder balance updated.";
      await refreshTop();
    } catch (e) {
      msg.textContent = String(e && e.message ? e.message : e);
    } finally {
      btn.textContent = "EXECUTE GENESIS (Mint 2B TET)";
      syncBtn();
    }
  };

  if (wdBtn && wdAmt && wdMsg) {
    wdBtn.onclick = async () => {
      wdMsg.textContent = "";
      wdMsg.className = "msg mono";
      try {
        await ensureTetWalletClient();
        const phrase = cleanMnemonic(ta.value || "");
        if (!window.tetWalletClient.validateMnemonicPhrase(phrase)) {
          throw new Error("Invalid recovery phrase.");
        }
        const wid = window.tetWalletClient.tetWalletIdFromMnemonic(phrase);
        if (!configuredFounder || wid.toLowerCase() !== configuredFounder.toLowerCase()) {
          throw new Error("Phrase does not match the configured founder wallet.");
        }
        const amountTet = Number(String(wdAmt.value || "").trim().replace(/,/g, ""));
        if (!Number.isFinite(amountTet) || amountTet <= 0) throw new Error("Invalid amount.");
        const amountMicro = Math.max(0, Math.round(amountTet * 1e8));
        if (!amountMicro) throw new Error("Amount too small.");
        const nonce = Date.now();

        wdBtn.disabled = true;
        wdBtn.textContent = "WITHDRAWING…";
        wdMsg.textContent = "Signing locally (Ed25519 + ML-DSA-44)…";

        const sig = await window.tetWalletClient.tetSignFounderWithdrawTreasuryHybrid(
          phrase,
          wid,
          amountMicro,
          nonce
        );
        const r = await fetch(coreApi("/founder/withdraw_treasury"), {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-tet-founder-ed25519-sig-b64": sig.ed25519_sig_b64,
          },
          body: JSON.stringify({
            founder_wallet_id: wid,
            amount_tet: amountTet,
            nonce,
            mldsa_pubkey_b64: sig.mldsa_pubkey_b64,
            mldsa_signature_b64: sig.mldsa_signature_b64,
          }),
        });
        const t = await r.text();
        if (!r.ok) throw new Error(t || String(r.status));
        wdMsg.textContent = "Treasury withdrawal executed.";
        await refreshTop();
      } catch (e) {
        wdMsg.textContent = String(e && e.message ? e.message : e);
      } finally {
        wdBtn.disabled = false;
        wdBtn.textContent = "Withdraw from Treasury";
      }
    };
  }
})();

function fmtTet(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return "—";
  return __nf4.format(n);
}
function fmtUsd(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return "—";
  return __nfUsd2.format(n);
}
function fmtInt(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return "—";
  return Math.round(n).toLocaleString("en-US");
}

function clamp01(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

// FinTech-grade display formatting (visual only; math stays unchanged)
const __nf2 = new Intl.NumberFormat("en-US", {
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});
const __nf4 = new Intl.NumberFormat("en-US", {
  minimumFractionDigits: 4,
  maximumFractionDigits: 4,
});
const __nfUsd2 = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});
const __nfCompact = new Intl.NumberFormat("en-US", {
  notation: "compact",
  compactDisplay: "short",
  maximumFractionDigits: 2,
});
function fmtTet2(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return "—";
  return __nf2.format(n);
}
function fmtTet4(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return "—";
  return __nf4.format(n);
}
function fmtCompact(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return "—";
  return String(__nfCompact.format(n)).replace(/([kmb])\b/g, (m) => m.toUpperCase());
}

const CHART_HISTORY_MAX = 36;
const liveChartHist = { tf: [], px: [] };
let liveLastBurnMicro = null;
let liveLastBurnTs = null;

// Pro charts (Bloomberg-style) via lightweight-charts (optional CDN load).
let __proChart = null;
let __proSeries = null;
let __proLastClose = null;
let __proLastCandleTime = 0;

function __nowSec() {
  return Math.floor(Date.now() / 1000);
}

async function ensureLightweightCharts() {
  if (window.LightweightCharts) return window.LightweightCharts;
  // Attempt CDN load; if blocked/offline, we fall back to canvas.
  await new Promise((res) => {
    const s = document.createElement("script");
    s.src =
      "https://unpkg.com/lightweight-charts@4.2.0/dist/lightweight-charts.standalone.production.js";
    s.async = true;
    s.onload = () => res();
    s.onerror = () => res();
    document.head.appendChild(s);
  });
  return window.LightweightCharts;
}

async function ensureProChart() {
  const host = document.getElementById("proChart");
  if (!host) return;
  if (__proChart) return;
  const LW = await ensureLightweightCharts();
  if (!LW || !LW.createChart) return;

  host.style.display = "block";
  const canvas = document.getElementById("chartTflops");
  if (canvas) canvas.style.display = "none";

  __proChart = LW.createChart(host, {
    layout: { background: { color: "#000000" }, textColor: "#ffffff" },
    grid: {
      vertLines: { color: "rgba(255,255,255,0.14)" },
      horzLines: { color: "rgba(255,255,255,0.14)" },
    },
    crosshair: { mode: 1 },
    rightPriceScale: { borderColor: "rgba(255,255,255,0.35)" },
    leftPriceScale: { borderColor: "rgba(255,255,255,0.35)", visible: true },
    timeScale: { borderColor: "rgba(255,255,255,0.35)" },
    handleScroll: { mouseWheel: true, pressedMouseMove: true },
    handleScale: { axisPressedMouseMove: true, mouseWheel: true, pinch: true },
  });

  const candle = __proChart.addCandlestickSeries({
    priceScaleId: "right",
    upColor: "#00ff00",
    downColor: "#ff0000",
    wickUpColor: "#00ff00",
    wickDownColor: "#ff0000",
    borderVisible: false,
  });
  const tflops = __proChart.addAreaSeries({
    priceScaleId: "left",
    lineColor: "#ffffff",
    topColor: "rgba(255,255,255,0.18)",
    bottomColor: "rgba(255,255,255,0.0)",
    lineWidth: 2,
  });
  const burn = __proChart.addHistogramSeries({
    priceScaleId: "burn",
    color: "rgba(255,255,255,0.45)",
    priceFormat: { type: "volume" },
    scaleMargins: { top: 0.85, bottom: 0 },
  });
  __proChart.priceScale("burn").applyOptions({
    visible: false,
    scaleMargins: { top: 0.85, bottom: 0 },
  });
  __proSeries = { candle, tflops, burn };

  // Resize
  const ro = new ResizeObserver(() => {
    try {
      __proChart.applyOptions({ width: host.clientWidth, height: host.clientHeight });
    } catch (_) {}
  });
  ro.observe(host);
}

/** USD index for 1 TET — single source: `tet_price_usd` from `GET /network/stats` (see `syncTetUsdSpot` in `updateLiveChartsFromSnapshot`). */
window.__tetUsdPerTet = window.__tetUsdPerTet || 0;
window.__tetPresaleUsdPerTet = window.__tetPresaleUsdPerTet || 0.05;

function syncTetUsdSpot(usdPerTet) {
  const u = Number(usdPerTet);
  if (!Number.isFinite(u) || u <= 0) return;
  window.__tetUsdPerTet = u;
  const line = `1 TET = $${u.toFixed(4)} USDC`;
  const vp = document.getElementById("valPrice");
  if (vp) vp.textContent = line;
  const rib = document.getElementById("tetPriceRibbon");
  if (rib) rib.textContent = line;
  const mkt = document.getElementById("marketTetUsdLine");
  if (mkt) mkt.textContent = line;
  const termBig = document.getElementById("terminalTetUsdcBig");
  if (termBig) termBig.textContent = line;
}

function drawChartGrid_(ctx, padL, padT, cw, ch, grid) {
  for (let g = 0; g <= 4; g++) {
    const yy = padT + (ch * g) / 4;
    ctx.strokeStyle = grid;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padL, yy);
    ctx.lineTo(padL + cw, yy);
    ctx.stroke();
  }
  for (let gx = 0; gx <= 6; gx++) {
    const xx = padL + (cw * gx) / 6;
    ctx.strokeStyle = grid;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(xx, padT);
    ctx.lineTo(xx, padT + ch);
    ctx.stroke();
  }
}

/**
 * Ledger-backed TFLOPS (cyan) + TET/USDC index (gold) from polled `/network/stats` — no RNG.
 * With zero workers, TFLOPS stays at 0 and the index line is flat at the pre-sale floor.
 */
function drawTradingChart(canvasId, tfSeries, pxSeries) {
  const tf = Array.isArray(tfSeries) ? tfSeries : [];
  const px = Array.isArray(pxSeries) && pxSeries.length === tf.length ? pxSeries : [];
  const c = document.getElementById(canvasId);
  if (!c || !c.getContext) return;
  const ctx = c.getContext("2d");
  const w = c.width;
  const h = c.height;
  const padL = 44;
  const padR = 12;
  const padT = 54;
  const padB = 30;
  const cw = w - padL - padR;
  const ch = h - padT - padB;
  const bg = "#000000";
  const grid = "rgba(212, 196, 168, 0.1)";
  const axis = "#737373";
  const idxUsd = Number(window.__tetUsdPerTet || 0);

  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, w, h);
  ctx.textAlign = "center";
  ctx.fillStyle = "#f5f5f5";
  ctx.font = "700 15px 'Crimson Pro', Georgia, 'Times New Roman', serif";
  ctx.fillText("NETWORK TFLOPS + INDEX", w / 2, 26);
  ctx.fillStyle = "#06b6d4";
  ctx.font = "600 11px ui-monospace, Roboto Mono, monospace";
  const idxLine =
    idxUsd > 0
      ? `TET/USDC INDEX   ${idxUsd.toFixed(4)} USDC`
      : "TET/USDC INDEX   —";
  ctx.fillText(idxLine, w / 2, 44);
  ctx.textAlign = "left";
  drawChartGrid_(ctx, padL, padT, cw, ch, grid);

  if (!tf.length) {
    ctx.fillStyle = "rgba(6, 182, 212, 0.95)";
    ctx.font = "600 13px ui-monospace, Roboto Mono, monospace";
    ctx.textAlign = "center";
    ctx.fillText("AWAITING NETWORK DATA", w / 2, padT + ch / 2 - 6);
    ctx.fillStyle = axis;
    ctx.font = "500 10px ui-monospace, Roboto Mono, monospace";
    ctx.fillText("TFLOPS · time series (poll /network/stats)", w / 2, padT + ch / 2 + 14);
    ctx.textAlign = "left";
    const xLbl = document.getElementById("chartXAxisLabel");
    if (xLbl) xLbl.textContent = "No samples yet · waiting for core";
    return;
  }

  const min = Math.min(...tf);
  const max = Math.max(...tf);
  const span = max - min;
  const padY = span < 1e-9 ? Math.abs(min || 1) * 0.06 : span * 0.1;
  const lo = min - padY;
  const hi = max + padY;
  const rng = hi - lo || 1;

  const yToPix = (v) => padT + ch - ((v - lo) / rng) * ch;
  const xToPix = (i) =>
    padL + (i / Math.max(tf.length - 1, 1)) * cw;

  ctx.fillStyle = axis;
  ctx.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
  ctx.textAlign = "right";
  const yTicks = [hi, (hi + lo) / 2, lo];
  yTicks.forEach((yv) => {
    const yy = yToPix(yv);
    const lab = Number.isFinite(yv) ? yv.toLocaleString(undefined, { maximumFractionDigits: 2 }) : "—";
    ctx.fillText(lab, padL - 6, Math.min(padT + ch, Math.max(padT + 10, yy + 3)));
  });

  const lineColor = "#06b6d4";
  ctx.beginPath();
  tf.forEach((v, i) => {
    const x = xToPix(i);
    const y = yToPix(Number.isFinite(v) ? v : lo);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  const lastX = xToPix(tf.length - 1);
  const firstX = xToPix(0);
  const baseY = padT + ch;
  ctx.lineTo(lastX, baseY);
  ctx.lineTo(firstX, baseY);
  ctx.closePath();
  const grd = ctx.createLinearGradient(0, padT, 0, baseY);
  grd.addColorStop(0, "rgba(6, 182, 212, 0.22)");
  grd.addColorStop(1, "rgba(6, 182, 212, 0)");
  ctx.fillStyle = grd;
  ctx.fill();

  ctx.beginPath();
  tf.forEach((v, i) => {
    const x = xToPix(i);
    const y = yToPix(Number.isFinite(v) ? v : lo);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = lineColor;
  ctx.lineWidth = 2;
  ctx.stroke();

  if (px.length === tf.length && px.length > 0) {
    const pMin = Math.min(...px);
    const pMax = Math.max(...px);
    const pSpan = pMax - pMin;
    const pPad = pSpan < 1e-12 ? Math.abs(pMin || 0.05) * 0.02 : pSpan * 0.12;
    const pLo = pMin - pPad;
    const pHi = pMax + pPad;
    const pRng = pHi - pLo || 1;
    const yPx = (v) => padT + ch - ((Number(v) - pLo) / pRng) * ch;
    ctx.beginPath();
    px.forEach((v, i) => {
      const x = xToPix(i);
      const y = yPx(Number.isFinite(Number(v)) ? Number(v) : pLo);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#d4c4a8";
    ctx.lineWidth = 1.5;
    ctx.setLineDash([4, 3]);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = axis;
    ctx.font = "9px ui-monospace, Roboto Mono, monospace";
    ctx.textAlign = "right";
    ctx.fillText(`idx ${pHi.toFixed(4)}`, padL + cw, padT + 10);
    ctx.fillText(`idx ${pLo.toFixed(4)}`, padL + cw, padT + ch);
  }

  const xLbl = document.getElementById("chartXAxisLabel");
  if (xLbl) {
    xLbl.textContent = `${tf.length} samples · TFLOPS (solid) · USDC index (dashed) · older ← → now`;
  }
}

function updateLiveChartsFromSnapshot(n) {
  const tf = Number(n.total_compute_tflops ?? 0);
  const px = Number(n.tet_price_usd ?? 0);
  const presale = Number(n.tet_presale_usd ?? 0);
  if (Number.isFinite(presale) && presale > 0) {
    window.__tetPresaleUsdPerTet = presale;
  }
  const burn = Number(n.total_burned_micro ?? 0);
  const now = Date.now();
  const vt = document.getElementById("valTflops");
  const vb = document.getElementById("valBurn");
  if (vt) {
    vt.textContent =
      tf.toLocaleString(undefined, { maximumFractionDigits: 2 }) + " TFLOPS";
  }
  if (px > 0) {
    syncTetUsdSpot(px);
  } else if (Number(window.__tetUsdPerTet) <= 0) {
    syncTetUsdSpot(Number(window.__tetPresaleUsdPerTet) || 0.05);
  }
  let rate = 0;
  if (liveLastBurnMicro != null && liveLastBurnTs != null) {
    const dt = (now - liveLastBurnTs) / 1000;
    if (dt > 0.2) {
      rate = ((burn - liveLastBurnMicro) / STEVEMON) / (dt / 3600);
    }
  }
  liveLastBurnMicro = burn;
  liveLastBurnTs = now;
  if (vb) {
    vb.textContent =
      rate > 0 ? rate.toExponential(2) + " TET/h (est.)" : "0 TET/h (no burn delta)";
  }
  liveChartHist.tf.push(tf);
  liveChartHist.px.push(Number.isFinite(px) && px > 0 ? px : Number(window.__tetPresaleUsdPerTet) || 0.05);
  while (liveChartHist.tf.length > CHART_HISTORY_MAX) {
    liveChartHist.tf.shift();
    liveChartHist.px.shift();
  }
  drawTradingChart("chartTflops", liveChartHist.tf, liveChartHist.px);

  // Pro chart streaming update (if available). Candles are built from spot samples:
  // open=prev close, close=current, high/low envelop open/close (degenerate but correct).
  ensureProChart()
    .then(() => {
      if (!__proSeries) return;
      const t = __nowSec();
      const price = Number.isFinite(px) && px > 0 ? px : Number(window.__tetPresaleUsdPerTet) || 0.05;
      const open = __proLastClose != null ? __proLastClose : price;
      const close = price;
      const high = Math.max(open, close);
      const low = Math.min(open, close);
      // 4s polls: only emit a new candle when time moves (always), but keep it stable per second.
      if (t !== __proLastCandleTime) {
        __proSeries.candle.update({ time: t, open, high, low, close });
        __proLastCandleTime = t;
      }
      __proLastClose = close;
      __proSeries.tflops.update({ time: t, value: tf });
      __proSeries.burn.update({ time: t, value: burn / STEVEMON });
    })
    .catch(() => {});
}

async function getStatus() {
  return fetchJsonLoose(coreApi("/status"));
}
async function getMe() {
  const wid = getCurrentWalletId();
  if (!wid) throw new Error("No wallet_id in this browser session.");
  return fetchJsonLoose(coreApi(`/ledger/me?wallet_id=${encodeURIComponent(wid)}`));
}

async function getNetworkStats() {
  return fetchJsonLoose(coreApi("/network/stats"));
}

const VIEW_META = {
  vault: {
    title: "Vault",
    sub: "Balance, recovery phrase, and on-ledger TET transfers.",
  },
  ai: {
    title: "AI Playground",
    sub: "Utility prompts and cost quotes tied to the ledger-backed /network/stats index.",
  },
  worker: {
    title: "Worker Nodes",
    sub: "Ledger-backed pulse, TFLOPS / index chart, and heartbeat earnings.",
  },
  market: {
    title: "Market",
    sub: "Trading terminal: order book, buy/sell, settlement rails.",
  },
  vision: {
    title: "Vision",
    sub: "Pitch deck, manifesto, whitepaper, Genesis Guardian, and developer docs.",
  },
};

function activateDashboardTab(name) {
  if (name === "logout") {
    doLogoutHard();
    return;
  }
  document.querySelectorAll("#mainTabs .nav-item").forEach((x) => {
    const on = x.dataset.tab === name;
    x.classList.toggle("active", on);
    x.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll("#appShell .pane").forEach((p) => {
    p.classList.toggle("active", p.id === "pane-" + name);
  });
  const m = VIEW_META[name];
  if (m) {
    const t = document.getElementById("dashViewTitle");
    const s = document.getElementById("dashViewSub");
    if (t) t.textContent = m.title;
    if (s) s.textContent = m.sub;
  }
}

function setTab(name) {
  activateDashboardTab(name);
}
async function sha256Hex(str) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

let earnIv = null;

async function refreshOrderbook() {
  // Back-compat: if old text element exists, keep filling it.
  const ob = document.getElementById("obSimple");
  const asksEl = document.getElementById("obAsks");
  const bidsEl = document.getElementById("obBids");
  try {
    const rows = await coreGet("/dex/orderbook");
    const list = Array.isArray(rows) ? rows : [];
    window.__tetLastBook = list;

    if (ob) {
      const lines = list
        .map(
          (o) =>
            `${o.side} ${o.price_quote_per_tet} · ${fmtTet4(
              Number(o.tet_micro_remaining || 0) / STEVEMON
            )} TET · ${String(o.order_id).slice(0, 10)}…`
        )
        .join("\n");
      ob.textContent = lines || "(empty)";
    }

    // Pro terminal orderbook (asks/bids) used by ui.html
    if (asksEl) asksEl.innerHTML = "";
    if (bidsEl) bidsEl.innerHTML = "";
    if (asksEl || bidsEl) {
      let maxSz = 0;
      for (const o of list) {
        const sz = Number(o.tet_micro_remaining || 0);
        if (Number.isFinite(sz) && sz > maxSz) maxSz = sz;
      }
      const mkRow = (side, pxQuote, tetMicro) => {
        const row = document.createElement("div");
        row.className = "ob-row " + (side === "sell" ? "ask" : "bid");
        const frac = maxSz > 0 ? Math.min(1, Number(tetMicro || 0) / maxSz) : 0;
        const bar = document.createElement("div");
        bar.className = "bar";
        bar.style.transformOrigin = side === "sell" ? "right center" : "left center";
        bar.style.transform = `scaleX(${frac.toFixed(4)})`;
        row.appendChild(bar);

        const px = document.createElement("div");
        px.className = "px";
        // price_quote_per_tet is USDC micro per 1 TET
        const usdPerTet = Number(pxQuote) / 1_000_000;
        px.textContent = Number.isFinite(usdPerTet) ? `$${usdPerTet.toFixed(4)}` : "—";

        const sz = document.createElement("div");
        sz.className = "sz";
        sz.textContent = `${fmtTet4(Number(tetMicro || 0) / STEVEMON)} TET`;

        row.appendChild(px);
        row.appendChild(sz);
        return row;
      };

      const asks = list
        .filter((o) => String(o.side).toLowerCase() === "sell")
        .sort((a, b) => Number(a.price_quote_per_tet) - Number(b.price_quote_per_tet))
        .slice(0, 18);
      const bids = list
        .filter((o) => String(o.side).toLowerCase() === "buy")
        .sort((a, b) => Number(b.price_quote_per_tet) - Number(a.price_quote_per_tet))
        .slice(0, 18);
      if (asksEl) for (const o of asks) asksEl.appendChild(mkRow("sell", o.price_quote_per_tet, o.tet_micro_remaining));
      if (bidsEl) for (const o of bids) bidsEl.appendChild(mkRow("buy", o.price_quote_per_tet, o.tet_micro_remaining));
    }

    return list;
  } catch (_) {
    if (ob) ob.textContent = "(unavailable)";
    if (asksEl) asksEl.innerHTML = "";
    if (bidsEl) bidsEl.innerHTML = "";
    window.__tetLastBook = [];
    return [];
  }
}

function bestAsk(rows) {
  let best = null;
  for (const o of rows || []) {
    if (String(o.side).toLowerCase() === "sell") {
      const p = Number(o.price_quote_per_tet);
      if (!best || p < best.p) best = { p, o };
    }
  }
  return best;
}

async function updateSwapPreview() {
  const usdEl = document.getElementById("swapUsd");
  const outEl = document.getElementById("swapTetOut");
  const hintEl = document.getElementById("swapHint");
  if (!usdEl || !outEl) return;
  const usd = Number(usdEl.value);
  const rows = window.__tetLastBook || (await refreshOrderbook());
  const a = bestAsk(rows);
  if (!a || !Number.isFinite(usd) || usd <= 0) {
    outEl.textContent = "—";
    if (hintEl) hintEl.textContent = "Enter USDC · needs a sell order in the book.";
    return;
  }
  const usdcMicro = Math.round(usd * 1_000_000);
  const tetMicro = Math.floor((usdcMicro * STEVEMON) / a.p);
  outEl.textContent = `${fmtTet2(tetMicro / STEVEMON)} TET`;
  const bookUsdPerTet = a.p / 1_000_000;
  if (hintEl) {
    hintEl.textContent = `Book ask · 1 TET = $${bookUsdPerTet.toFixed(4)} USDC (then ~${fmtTet2(tetMicro / STEVEMON)} TET for your size)`;
  }
  window.__tetSwapTetMicro = tetMicro;
  window.__tetSwapMaxPx = a.p;
}

function renderMyOrders(me, rows) {
  const el = document.getElementById("myOrders");
  if (!el) return;
  el.innerHTML = "";
  const wid = (me && me.wallet_id) || "";
  if (!wid || !Array.isArray(rows)) return;
  const mine = rows.filter((o) => o.maker_wallet === wid);
  if (mine.length === 0) {
    el.innerHTML = '<p class="msg">No open maker orders.</p>';
    return;
  }
  for (const o of mine) {
    const div = document.createElement("div");
    div.className = "order-row";
    div.innerHTML =
      "<span>" +
      fmtTet4(Number(o.tet_micro_remaining || 0) / STEVEMON) +
      " TET · " +
      String(o.side) +
      "</span>";
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = "Cancel";
    b.className = "danger";
    b.onclick = async () => {
      const msg = document.getElementById("marketMsg");
      if (msg) {
        msg.textContent = "";
        msg.className = "msg";
      }
      try {
        await corePost("/dex/order/cancel", { order_id: o.order_id, maker_wallet: wid }, false);
        if (msg) msg.textContent = "Cancelled.";
        await refreshOrderbook();
        renderMyOrders(await getMe(), window.__tetLastBook || []);
        updateSwapPreview().catch(() => {});
      } catch (e) {
        if (msg) {
          msg.textContent = String(e);
          msg.className = "msg";
        }
      }
    };
    div.appendChild(b);
    el.appendChild(div);
  }
}

async function refreshMarketUi() {
  await refreshOrderbook();
  let me = null;
  try {
    me = await getMe();
  } catch (_) {}
  renderMyOrders(me, window.__tetLastBook || []);
  await updateSwapPreview();
  await refreshBuySolanaAddr();
}

document.querySelectorAll("#mainTabs .nav-item").forEach((t) => {
  t.addEventListener("click", () => {
    const name = t.dataset.tab || "vault";
    setTab(name);
    if (name === "market") refreshMarketUi().catch(() => {});
    if (name === "worker") {
      queueMicrotask(() =>
        drawTradingChart("chartTflops", liveChartHist.tf, liveChartHist.px)
      );
    }
  });
});

const btnGotoVault = document.getElementById("btnGotoVault");
if (btnGotoVault) {
  btnGotoVault.onclick = () => setTab("vault");
}

const btnCopyWalletId = document.getElementById("btnCopyWalletId");
if (btnCopyWalletId) {
  btnCopyWalletId.onclick = async () => {
    const box = document.getElementById("vaultWalletId");
    const feedback = document.getElementById("walletIdCopyMsg");
    const wid = (box && box.textContent && box.textContent.trim() !== "—" && box.textContent.trim()) || "";
    if (!wid) {
      if (feedback) {
        feedback.textContent = "No wallet yet — Activate a recovery phrase first.";
        feedback.className = "msg";
      }
      return;
    }
    try {
      await navigator.clipboard.writeText(wid);
      if (feedback) {
        feedback.textContent = "Copied.";
        feedback.className = "msg success";
      }
    } catch (_) {
      if (feedback) {
        feedback.textContent = "Copy blocked — select the ID and copy manually.";
        feedback.className = "msg";
      }
    }
  };
}

async function refreshTop() {
  const s = await getStatus();
  const me = await getMe();
  const balEl = document.getElementById("bal");
  if (balEl) balEl.textContent = `${fmtTet4(me.balance_tet)} TET`;
  const stakedLine = document.getElementById("stakedLine");
  if (stakedLine) {
    const st = Number(me.staked_balance_tet ?? 0);
    stakedLine.textContent = `Staked: ${fmtTet4(st)} TET`;
  }
  const sessionLine = document.getElementById("sessionEarningsLine");
  if (earnIv != null && window.__earnBaselineTet != null) {
    const cur = Number(me.balance_tet);
    const base = Number(window.__earnBaselineTet);
    const d = cur - base;
    if (sessionLine) {
      const sign = d >= 0 ? "+" : "-";
      sessionLine.textContent = `Session earnings: ${sign}${fmtTet4(Math.abs(d))} TET (ledger)`;
    }
  } else if (sessionLine) {
    sessionLine.textContent = "Session earnings: +0.00 TET";
  }
  const feeEl = document.getElementById("fee");
  if (feeEl) feeEl.textContent = fmtTet4(me.fee_total_tet);
  const supEl = document.getElementById("sup");
  if (supEl) supEl.textContent = fmtCompact(me.total_supply_tet);
  document.getElementById("peer").textContent = me.wallet_id ?? "—";
  const vw = document.getElementById("vaultWalletId");
  if (vw) vw.textContent = me.wallet_id && String(me.wallet_id).trim() ? String(me.wallet_id).trim() : "—";
  const genesisRecipient = document.getElementById("genesisRecipientWallet");
  if (genesisRecipient && !genesisRecipient.value.trim() && me.wallet_id) {
    genesisRecipient.value = String(me.wallet_id).trim();
  }
  const burnTet = Number(me.total_burned_tet ?? 0);
  const burnDiag = document.getElementById("burnDiag");
  if (burnDiag) burnDiag.textContent = `${fmtCompact(burnTet)} TET`;

  // Market/Vision tokenomics tiles (compact; display-only)
  const mktSupply = document.getElementById("mktSupply");
  if (mktSupply) mktSupply.textContent = `${fmtCompact(me.total_supply_tet)} TET`;
  const mktBurn = document.getElementById("mktBurn");
  if (mktBurn) mktBurn.textContent = `${fmtCompact(burnTet)} TET`;

  const pqcDot = document.getElementById("pqcDot");
  pqcDot.className = "dot" + (s.pqc_active ? " ok" : "");
  document.getElementById("quantumShield").textContent = s.pqc_active ? "TET Quantum Shield (PQC ON)" : "TET Quantum Shield (PQC OFF)";

  const attDot = document.getElementById("attDot");
  attDot.className = "dot" + (s.attestation_required ? " ok" : "");
  document.getElementById("hardwareAttested").textContent = s.attestation_required ? "Hardware Attested (REQUIRED)" : "Hardware Attested (OFF)";

  const linkDot = document.getElementById("linkDot");
  linkDot.className = "dot" + (s.signer_linked ? " ok" : "");
  document.getElementById("hardwareSecured").textContent = s.signer_linked ? "Signer (LINKED)" : "Signer (UNLINKED)";

  // Founder-only UI has been removed from the primary 5-tab layout.
  // Founder vesting visualization (Founder Control Panel is only visible for founder).
  if (me && me.is_founder) {
    const fmt8 = (n) =>
      Number(n || 0).toLocaleString(undefined, { maximumFractionDigits: 8 });
    const gb = document.getElementById("fvGenesisBal");
    const gl = document.getElementById("fvGenesisLocked");
    const gu = document.getElementById("fvGenesisUnlocked");
    const ua = document.getElementById("fvUnlockAt");
    const dt = document.getElementById("fvDexTreasury");
    if (gb) gb.textContent = fmt8(me.founder_genesis_balance_tet);
    if (gl) gl.textContent = fmt8(me.founder_genesis_locked_tet);
    if (gu) gu.textContent = fmt8(me.founder_genesis_unlocked_tet);
    if (dt) dt.textContent = fmt8(me.dex_treasury_earnings_tet);
    if (ua) {
      const t = me.founder_genesis_unlocks_at_ms;
      if (typeof t === "number" && t > 0) ua.textContent = new Date(t).toISOString();
      else ua.textContent = "—";
    }
  }

  try {
    const n = await getNetworkStats();
    updateLiveChartsFromSnapshot(n);
    // Genesis Guardians FOMO UI (live counter + progress bar)
    (function syncGenesisFomo() {
      const claimed = Number(n.genesis_1k_claimed ?? 0);
      const total = 10000;
      const line = document.getElementById("genesisCountLine");
      if (line) line.textContent = `Genesis Slots Claimed: [ ${fmtInt(claimed)} / 10,000 ]`;
      const fill = document.getElementById("genesisBarFill");
      if (fill) fill.style.width = `${(clamp01(claimed / total) * 100).toFixed(1)}%`;
      const btn = document.getElementById("btnGenesisClaimUi");
      if (btn) {
        if (claimed >= total) {
          btn.textContent = "❌ SOLD OUT";
          btn.disabled = true;
        }
      }
    })();
    // Worker sector: Genesis Guardians counter
    (function syncGenesisGuardiansWorkerSector() {
      const el = document.getElementById("uiGenesisGuardiansLine");
      if (!el) return;
      const a = Number(n.genesis_guardians_filled ?? 0);
      const b = Number(n.genesis_guardians_total ?? 10000);
      const filled = Number.isFinite(a) ? a : 0;
      const total = Number.isFinite(b) && b > 0 ? b : 10000;
      el.textContent = `${filled} / ${total} SLOTS OCCUPIED`;
    })();
    const nw = document.getElementById("netWorkers");
    if (nw) nw.textContent = fmtInt(n.active_worker_nodes);
    const nc = document.getElementById("netCommunity");
    if (nc) {
      const micro = Number(n.community_stevemon_earned_micro ?? 0);
      nc.textContent = `${fmtCompact(micro / STEVEMON)} TET`;
    }
    const nb = document.getElementById("netBurn");
    if (nb) {
      const bmicro = Number(n.total_burned_micro ?? 0);
      nb.textContent = `${fmtCompact(bmicro / STEVEMON)} TET`;
    }
  } catch (_) {
    const nb = document.getElementById("netBurn");
    if (nb) nb.textContent = `${fmtCompact(burnTet)} TET`;
  }
}

const btnGenesisClaimUi = document.getElementById("btnGenesisClaimUi");
if (btnGenesisClaimUi) {
  btnGenesisClaimUi.onclick = async () => {
    const msgEl = document.getElementById("genesisClaimMsgUi");
    if (msgEl) msgEl.textContent = "";
    try {
      await ensureTetWalletClient();
      // Uses local encrypted mnemonic (PIN) — not sent to server.
      const norm = cleanMnemonic(await promptPinAndDecryptStoredMnemonic());
      const wid = window.tetWalletClient.tetWalletIdFromMnemonic(norm);
      setCurrentWalletId(wid);
      const sig = await window.tetWalletClient.tetSignGenesis1kClaimHybrid(norm, wid);
      await fetchJsonLoose(coreApi("/genesis/1000/claim"), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-tet-wallet-id": wid,
          "x-tet-ed25519-sig-b64": sig.ed25519_sig_b64,
          "x-tet-mldsa-pubkey-b64": sig.mldsa_pubkey_b64,
          "x-tet-mldsa-sig-b64": sig.mldsa_signature_b64,
        },
        body: "{}",
      });
      btnGenesisClaimUi.textContent = "✅ CLAIMED";
      btnGenesisClaimUi.disabled = true;
      if (msgEl) msgEl.textContent = "Airdrop credited.";
      await refreshTop();
    } catch (e) {
      if (msgEl) msgEl.textContent = String(e && e.message ? e.message : e);
    }
  };
}

async function refreshBuySolanaAddr() {
  try {
    const s = await getStatus();
    const a = s.dex_usdc_settlement_solana_address;
    const el = document.getElementById("buySolanaAddr");
    if (el) el.textContent = a && String(a).trim() ? String(a).trim() : "(configure TET_DEX_SOLANA_USDC_ADDRESS on core)";
  } catch (_) {
    const el = document.getElementById("buySolanaAddr");
    if (el) el.textContent = "(unable to load)";
  }
}

function setMarketModeUi(m) {
  const buy = m === "buy";
  const mb = document.getElementById("modeBuy");
  const ms = document.getElementById("modeSell");
  const pb = document.getElementById("panelBuy");
  const ps = document.getElementById("panelSell");
  if (mb) mb.classList.toggle("active", buy);
  if (ms) ms.classList.toggle("active", !buy);
  if (pb) pb.style.display = buy ? "block" : "none";
  if (ps) ps.style.display = buy ? "none" : "block";
}
const modeBuy = document.getElementById("modeBuy");
const modeSell = document.getElementById("modeSell");
if (modeBuy) modeBuy.onclick = () => setMarketModeUi("buy");
if (modeSell) modeSell.onclick = () => setMarketModeUi("sell");

async function signerPost(path, body) {
  return fetchJsonLoose(`${SIGNER}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
}

async function corePost(path, body, requireApiKey) {
  const headers = { "content-type": "application/json" };
  if (requireApiKey) {
    if (!key) throw new Error("API key required (set in localStorage x-api-key for AI).");
    headers["x-api-key"] = key;
  }
  return fetchJsonLoose(coreApi(path), {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

async function coreGet(path, requireApiKey) {
  const headers = {};
  if (requireApiKey) {
    if (!key) throw new Error("API key required.");
    headers["x-api-key"] = key;
  }
  return fetchJsonLoose(coreApi(path), { headers });
}

/** POST /ai/utility — tolerant of JSON or wrapped `{ note, response }`. */
async function postAiUtilityPlayground(prompt) {
  const trimmed = String(prompt ?? "").trim();
  const wid = getCurrentWalletId();
  if (!wid) throw new Error("No wallet_id in this browser session.");
  return fetchJsonLoose(coreApi("/ai/utility"), {
    method: "POST",
    headers: { "content-type": "application/json", "x-tet-wallet-id": wid },
    body: JSON.stringify({ prompt: trimmed }),
  });
}

// Guardian enrollment (guarded — a missing node must not abort the rest of this file)
const secureWalletBtn = document.getElementById("secureWallet");
if (secureWalletBtn) {
  secureWalletBtn.onclick = async () => {
  const el = document.getElementById("gmsg");
  const certBox = document.getElementById("cert");
  const celebrate = document.getElementById("celebrate");
    if (el) el.textContent = "";
    if (celebrate) celebrate.style.display = "none";
  try {
    const env = await signerPost("/envelope/founding-enroll", {});
      await corePost("/founding/enroll", env, false);
    const me = await getMe();
      const cert = await coreGet(`/founding/cert/${encodeURIComponent(me.wallet_id ?? "")}`, false);
      if (certBox) certBox.value = JSON.stringify(cert, null, 2);
      if (celebrate) celebrate.style.display = "block";
      if (el) el.textContent = "Guardian enrollment complete.";
  } catch (e) {
      if (el) el.textContent = String(e);
  }
  await refreshTop();
};
}

const refreshGuardianBtn = document.getElementById("refreshGuardian");
if (refreshGuardianBtn) {
  refreshGuardianBtn.onclick = async () => {
  const el = document.getElementById("gmsg");
  try {
    await refreshTop();
      if (el) el.textContent = "OK.";
    } catch (e) {
      if (el) el.textContent = String(e);
    }
  };
}

async function refreshQuote() {
  const modelEl = document.getElementById("model");
  const promptEl = document.getElementById("prompt");
  const model = ((modelEl && modelEl.value) || "llama3").trim();
  const prompt = ((promptEl && promptEl.value) || "").slice(0, 6000);
  const pricingUrl = coreApi(
    `/ai/pricing?model=${encodeURIComponent(model)}&input=${encodeURIComponent(prompt)}`
  );
  let j = null;
  try {
    j = await fetchJsonLoose(pricingUrl);
  } catch (_) {
    // Consumer UX: pricing is advisory only — never crash the UI.
    j = { required_gross_micro: 10_000_000 };
  }
  const ks = Number(j.required_gross_micro ?? 10_000_000);
  const tetCost = ks / STEVEMON;
  const spotRef =
    Number(window.__tetUsdPerTet) > 0
      ? Number(window.__tetUsdPerTet)
      : Number(window.__tetPresaleUsdPerTet) || 0.05;
  const usdcCost =
    Number.isFinite(tetCost) &&
    Number.isFinite(spotRef) &&
    spotRef > 0
      ? tetCost * spotRef
      : NaN;
  const ck = document.getElementById("costKs");
  const ct = document.getElementById("costTet");
  if (ck) ck.textContent = fmtInt(ks);
  if (ct) ct.textContent = fmtTet(tetCost);
  const line = document.getElementById("costPerPromptLine");
  if (line) {
    line.textContent = `Cost per prompt: ${Number.isFinite(tetCost) ? tetCost.toFixed(2) : "—"} TET`;
  }
  const usdcLine = document.getElementById("costPerPromptUsdc");
  if (usdcLine) {
    usdcLine.textContent =
      Number.isFinite(usdcCost) && usdcCost > 0 && Number.isFinite(spotRef) && spotRef > 0
        ? `≈ $${usdcCost.toFixed(2)} USDC @ network spot $${spotRef.toFixed(4)} / 1 TET (same source as Terminal chart)`
        : `≈ $${(tetCost * (Number(window.__tetPresaleUsdPerTet) || 0.05)).toFixed(2)} USDC @ pre-sale index (awaiting /network/stats)`;
  }
  return j;
}

const btnResetChat = document.getElementById("btnResetChat");
if (btnResetChat) {
  btnResetChat.onclick = () => {
    const chat = document.getElementById("chat");
    const promptEl = document.getElementById("prompt");
    const cmsg = document.getElementById("cmsg");
    if (promptEl) promptEl.value = "";
    if (chat) chat.value = "";
    if (cmsg) cmsg.textContent = "";
  };
}

const quoteCostBtn = document.getElementById("quoteCost");
if (quoteCostBtn) {
  quoteCostBtn.onclick = async () => {
  const el = document.getElementById("cmsg");
    if (el) el.textContent = "Recalculating…";
  try {
    await refreshQuote();
      if (el) el.textContent = "OK.";
    } catch (e) {
      if (el) el.textContent = String(e);
    }
  };
}

const btnStartEarnEl = document.getElementById("btnStartEarn");
if (btnStartEarnEl) {
  btnStartEarnEl.onclick = async () => {
    const el = document.getElementById("earnMsg");
    const btn = document.getElementById("btnStartEarn");
    if (!el || !btn) return;
  el.textContent = "";
    if (earnIv) {
      clearInterval(earnIv);
      earnIv = null;
      window.__earnBaselineTet = null;
      btn.textContent = "Start earning";
      el.textContent = "Stopped.";
      const sl = document.getElementById("sessionEarningsLine");
      if (sl) sl.textContent = "Session earnings: +0.00 TET";
      return;
    }
    try {
      const me = await getMe();
      const w = me.wallet_id;
      if (!w) throw new Error("No active wallet");
      window.__earnBaselineTet = Number(me.balance_tet);
      const hw = (await sha256Hex(w)).slice(0, 64);
      const tick = async () => {
        await corePost("/worker/register", {
          wallet: w,
          hardware_id_hex: hw,
          ed25519_pubkey_hex: w,
          tflops_est: 8,
        }, false);
      };
      await tick();
      earnIv = setInterval(tick, 8000);
      btn.textContent = "Stop";
      el.textContent = "Live · heartbeat every 8s · earnings from ledger balance";
    } catch (e) {
      el.textContent = String(e);
    }
  };
}

const swapUsdEl = document.getElementById("swapUsd");
if (swapUsdEl) {
  swapUsdEl.addEventListener("input", () => updateSwapPreview().catch(() => {}));
}

const btnBuyEl = document.getElementById("btnBuy");
if (btnBuyEl) {
  btnBuyEl.onclick = async () => {
    const el = document.getElementById("marketMsg");
    if (el) {
      el.textContent = "";
      el.className = "msg";
    }
    try {
      await updateSwapPreview();
      const tm = window.__tetSwapTetMicro;
      const px = window.__tetSwapMaxPx;
      if (!tm || tm <= 0) throw new Error("No fillable size");
      const me = await getMe();
      await corePost("/dex/take", {
        taker_wallet: me.wallet_id,
        side: "buy",
        quote_asset: "USDC",
        tet_micro: tm,
        max_price_quote_per_tet: px,
        settlement_ttl_sec: 600,
      }, false);
      if (el) el.textContent = "Trade created. Send USDC on Solana to the address shown above, then complete settlement in your ops flow.";
      await refreshOrderbook();
      renderMyOrders(await getMe(), window.__tetLastBook || []);
      await refreshTop();
      await refreshBuySolanaAddr();
    } catch (e) {
      if (el) {
        el.textContent = String(e);
        el.className = "msg";
      }
    }
  };
}

const btnSellEl = document.getElementById("btnSell");
if (btnSellEl) {
  btnSellEl.onclick = async () => {
    const el = document.getElementById("marketMsg");
    if (el) {
      el.textContent = "";
      el.className = "msg";
    }
    const tet = Number(document.getElementById("sellTet")?.value);
    const usdPer = Number(document.getElementById("sellUsdPerTet")?.value);
    if (!Number.isFinite(tet) || tet <= 0 || !Number.isFinite(usdPer) || usdPer <= 0) {
      if (el) {
        el.textContent = "Enter TET amount and USDC per TET.";
        el.className = "msg";
      }
      return;
    }
    const tetMicro = Math.floor(tet * STEVEMON);
    const price = Math.max(1, Math.round(usdPer * 1_000_000));
    try {
      const me = await getMe();
      const w = (me.wallet_id || "").trim();
      if (!w) throw new Error("No active wallet");
      await corePost("/dex/order/place", {
        maker_wallet: w,
        side: "sell",
        quote_asset: "USDC",
        price_quote_per_tet: price,
        tet_micro_total: tetMicro,
        ttl_sec: 600,
      }, false);
      if (el) el.textContent = "Sell order listed.";
      await refreshOrderbook();
      renderMyOrders(me, window.__tetLastBook || []);
      await refreshTop();
    } catch (e) {
      if (el) {
        el.textContent = String(e);
        el.className = "msg";
      }
    }
  };
}

const btnConfirmPresale = document.getElementById("btnConfirmPresale");
if (btnConfirmPresale) {
  btnConfirmPresale.onclick = async () => {
    const usdc = Number(document.getElementById("presaleUsdc")?.value);
    const msg = document.getElementById("presaleMsg");
    const addr = "6kWEkvZgs1RLthwDfaBPuu1iK5uxSRziWBwYuySWx3rN";
    const px = Number(window.__tetPresaleUsdPerTet) || 0.05;
    if (!Number.isFinite(usdc) || usdc <= 0) {
      if (msg) msg.textContent = "Enter USDC contribution amount.";
      return;
    }
    const tet = usdc / px;
    if (msg) {
      msg.textContent =
        `Intent logged: contribute $${usdc.toFixed(2)} USDC → ~${tet.toFixed(2)} TET @ $${px.toFixed(2)} pre-sale.\n` +
        `Send USDC on Solana to: ${addr}`;
    }
    try {
      await navigator.clipboard.writeText(addr);
      showToast("Address Copied! Send USDC via Phantom to finalize.");
    } catch (_) {
      showToast("Copy blocked — please copy the Solana address manually.");
    }
  };
}

const btnStakeMock = document.getElementById("btnStakeMock");
if (btnStakeMock) {
  btnStakeMock.onclick = async () => {
    const amt = Number(document.getElementById("stakeTet")?.value);
    const msg = document.getElementById("stakeMsg");
    if (!Number.isFinite(amt) || amt <= 0) {
      if (msg) msg.textContent = "Enter amount to lock (TET).";
      return;
    }
    if (msg) msg.textContent = `Stake intent recorded (UI only): lock ${amt.toFixed(4)} TET · Unstaking takes 7 days.`;
    await refreshTop();
  };
}

const btnStakeVault = document.getElementById("btnStakeVault");
if (btnStakeVault) {
  btnStakeVault.onclick = async () => {
    const msg = document.getElementById("stakeVaultMsg");
    const inp = document.getElementById("stakeTetVault");
    if (msg) msg.textContent = "";
    const amt = Number(String((inp && inp.value) || "").replace(/,/g, "").trim());
    if (!Number.isFinite(amt) || amt <= 0) {
      if (msg) msg.textContent = "Enter amount to stake (TET).";
      return;
    }
    try {
      await ensureTetWalletClient();
      const norm = cleanMnemonic(await promptPinAndDecryptStoredMnemonic());
      if (!window.tetWalletClient.validateMnemonicPhrase(norm)) {
        throw new Error("Invalid recovery phrase after decrypt.");
      }
      const wid = window.tetWalletClient.tetWalletIdFromMnemonic(norm);
      const nonceData = await fetchJsonLoose(coreApi("/wallet/nonce/" + encodeURIComponent(wid)));
      const nextNonce = Number(nonceData.next_nonce);
      if (!Number.isFinite(nextNonce) || nextNonce <= 0) {
        throw new Error("Could not read next_nonce from core.");
      }
      const amountMicro = Math.round(amt * STEVEMON);
      const sig = await window.tetWalletClient.tetSignWalletStakeHybrid(
        norm,
        amountMicro,
        nextNonce
      );
      await fetchJsonLoose(coreApi("/wallet/stake"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          wallet_id: sig.wallet_id,
          amount_tet: amt,
          nonce: sig.nonce,
          ed25519_sig_hex: sig.ed25519_sig_hex,
          mldsa_pubkey_b64: sig.mldsa_pubkey_b64,
          mldsa_sig_b64: sig.mldsa_sig_b64,
        }),
      });
      if (inp) inp.value = "";
      if (msg) msg.textContent = "Stake submitted. (Min worker stake: 5,000 TET)";
      await refreshTop();
    } catch (e) {
      if (msg) msg.textContent = String(e && e.message ? e.message : e);
    }
  };
}

const sendMsgBtn = document.getElementById("sendMsg");
if (sendMsgBtn) {
  sendMsgBtn.onclick = async () => {
  const el = document.getElementById("cmsg");
    if (el) el.textContent = "";
    const modelEl = document.getElementById("model");
    const model = ((modelEl && modelEl.value) || "llama3").trim();
    const sysEl = document.getElementById("systemPrompt");
    const system_prompt = ((sysEl && sysEl.value) || "").slice(0, 4000);
    const promptEl = document.getElementById("prompt");
    const prompt = (promptEl && promptEl.value) || "";
  const chat = document.getElementById("chat");
  try {
    const quote = await refreshQuote();
    const amount_micro = Number(quote.required_gross_micro ?? 10_000_000);
    const to = "tet-api-pool";
    const payment = await signerPost("/envelope/transfer", { to_wallet: to, amount_micro, fee_bps: 100 });
      const wpEl = document.getElementById("workerProof");
      const wp = (wpEl && wpEl.value.trim()) || "";
    const body = { payment, model, input: prompt };
    if (system_prompt && system_prompt.trim()) body.system_prompt = system_prompt.trim();
    if (wp) {
      try {
        body.worker_proof = JSON.parse(wp);
      } catch (_) {
          if (el) el.textContent = "invalid worker proof JSON";
        return;
      }
    }
      const resp = await corePost("/ai/proxy", body, true);
    const extra = resp.worker_output ? `\n${resp.worker_output}\n` : "";
      if (chat) {
        chat.value = `${(chat.value || "").trim()}\n> ${prompt}\n`;
        await typewriterAppend(
          chat,
          `${resp.note}\n[route=${resp.route}]${extra}\n`,
          2
        );
      }
      if (el) el.textContent = "OK.";
  } catch (e) {
      if (el) el.textContent = String(e);
  }
  await refreshTop();
};
}

const btnExecuteGenesis = document.getElementById("btnExecuteGenesis");
if (btnExecuteGenesis) {
  // Legacy genesis UI (expects #genesisRecipientWallet + #genesisMsg). If those elements
  // are not present, do not bind and do not override the Founder Control Panel handler.
  const __legacyGenesisMsgEl = document.getElementById("genesisMsg");
  const __legacyGenesisInput = document.getElementById("genesisRecipientWallet");
  if (!__legacyGenesisMsgEl || !__legacyGenesisInput) {
    // No-op: Founder Control Panel binds its own handler earlier.
  } else btnExecuteGenesis.onclick = async () => {
    const msgEl = document.getElementById("genesisMsg");
    const input = document.getElementById("genesisRecipientWallet");
    const wid = (input && input.value.trim()) || "";
    if (!wid) {
      if (msgEl) {
        msgEl.textContent = "Enter genesis recipient wallet ID.";
        msgEl.className = "msg";
      }
      return;
    }
    if (msgEl) {
      msgEl.textContent = "";
      msgEl.className = "msg";
    }
    try {
      await ensureTetWalletClient();
      const phrase = window.prompt(
        "Paste the 12-word recovery phrase for this founder wallet (not sent to the server):"
      );
      if (!phrase || !phrase.trim()) {
        if (msgEl) msgEl.textContent = "Cancelled.";
        return;
      }
      const norm = cleanMnemonic(phrase);
      if (!window.tetWalletClient.validateMnemonicPhrase(norm)) {
        throw new Error("Invalid recovery phrase.");
      }
      const derived = window.tetWalletClient.tetWalletIdFromMnemonic(norm);
      if (derived.toLowerCase() !== wid.trim().toLowerCase()) {
        throw new Error("Phrase does not match the genesis recipient wallet ID.");
      }
      const hybrid = await window.tetWalletClient.tetSignFounderGenesisHybrid(
        norm,
        wid.trim()
      );
      const summary = await fetchJsonLoose(coreApi("/founder/genesis"), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-tet-founder-ed25519-sig-b64": hybrid.ed25519_sig_b64,
        },
        body: JSON.stringify({
          founder_wallet_id: wid.trim(),
          mldsa_pubkey_b64: hybrid.mldsa_pubkey_b64,
          mldsa_signature_b64: hybrid.mldsa_signature_b64,
        }),
      });
      const tet = (micro) =>
        (Number(micro) / STEVEMON).toLocaleString(undefined, {
          maximumFractionDigits: 8,
        });
      if (msgEl) {
        msgEl.className = "msg success";
        msgEl.textContent = `Genesis OK — founder allocation ${tet(summary.founder_allocation_micro)} TET · total supply committed.`;
      }
  await refreshTop();
    } catch (e) {
      if (msgEl) {
        msgEl.className = "msg";
        msgEl.textContent = String(e);
      }
    }
  };
}

const btnSendTetCore = document.getElementById("btnSendTetCore");
if (btnSendTetCore) {
  btnSendTetCore.onclick = async () => {
    const msgEl = document.getElementById("transferMsg");
    const toEl = document.getElementById("transferToAddr");
    const amtEl = document.getElementById("transferAmtTet");
    const to = (toEl && toEl.value.trim()) || "";
    const amt = Number(String((amtEl && amtEl.value) || "").replace(/,/g, ""));
    if (msgEl) {
      msgEl.textContent = "";
      msgEl.className = "msg mono";
    }
    if (!to) {
      if (msgEl) msgEl.textContent = "Enter recipient wallet ID.";
      return;
    }
    if (!Number.isFinite(amt) || amt <= 0) {
      if (msgEl) msgEl.textContent = "Enter a valid amount.";
      return;
    }
    const ok = confirm(
      `Are you sure you want to send ${amt} TET to ${to}? This cannot be undone.`
    );
    if (!ok) return;
    try {
      await ensureTetWalletClient();
      const norm = cleanMnemonic(await promptPinAndDecryptStoredMnemonic());
      if (!window.tetWalletClient.validateMnemonicPhrase(norm)) {
        throw new Error("Invalid recovery phrase after decrypt.");
      }
      const fromAddr = window.tetWalletClient.tetWalletIdFromMnemonic(norm);
      const me = await getMe();
      const active = String(me.wallet_id || "").trim().toLowerCase();
      if (active && active !== fromAddr.toLowerCase()) {
        throw new Error(
          "This wallet does not match the active session on the core. Unlock with the same recovery phrase."
        );
      }
      const amountMicro = Math.round(amt * STEVEMON);
      const nonceData = await fetchJsonLoose(
        coreApi("/wallet/nonce/" + encodeURIComponent(fromAddr))
      );
      const nextNonce = Number(nonceData.next_nonce);
      if (!Number.isFinite(nextNonce) || nextNonce <= 0) {
        throw new Error("Could not read next_nonce from core.");
      }
      const sk32 = window.tetWalletClient.tetSecretKey32FromMnemonic(norm);
      const mldsaPub = window.tetWalletClient.tetMldsa44PubkeyB64FromMnemonic(norm);
      const sigHex = await window.tetWalletClient.tetSignWalletTransferHybrid(
        sk32,
        to,
        amountMicro,
        nextNonce,
        mldsaPub
      );
      const mldsaSig = window.tetWalletClient.tetSignMldsa44HybridTransfer(
        norm,
        to,
        amountMicro,
        nextNonce,
        mldsaPub
      );
      await fetchJsonLoose(coreApi("/wallet/transfer"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          from_address: fromAddr,
          to_address: to,
          amount_tet: amt,
          nonce: nextNonce,
          signature: sigHex,
          mldsa_pubkey_b64: mldsaPub,
          mldsa_signature_b64: mldsaSig,
        }),
      });
      alert("Transfer successful!");
      await refreshTop();
    } catch (e) {
      alert("Transfer failed: " + String(e.message || e));
    }
  };
}

const btnAiUtility = document.getElementById("btnAiUtility");
if (btnAiUtility) {
  btnAiUtility.onclick = async () => {
    const el = document.getElementById("cmsg");
    const promptEl = document.getElementById("prompt");
    const chat = document.getElementById("chat");
    const p = (promptEl && promptEl.value.trim()) || "";
    if (!p) {
      if (el) el.textContent = "Enter a prompt for Utility.";
      return;
    }
    if (el) el.textContent = "Routing…";
    try {
      if (chat) {
        chat.value = `${(chat.value || "").trim()}\n[utility]\n> ${p}\n`;
      }
      const j = await withTimeout(postAiUtilityPlayground(p), 15000);
      const ut = textFromUtilityResponse(j);
      const body = String(ut.body || "").trim();
      if (!body) {
        if (chat) {
          chatAppendInstant(
            chat,
            "[NOTICE] Utility response was empty. Confirm an active worker is registered and try again.\n"
          );
        }
      } else if (chat) {
        const tail = `${body}${ut.note ? `\n(${ut.note})` : ""}\n`;
        await typewriterAppend(chat, tail, 2);
      }
      if (el) el.textContent = "OK.";
    } catch (e) {
      const raw = String(e && e.message ? e.message : e);
      let block = UTILITY_NETWORK_UNAVAILABLE_MSG;
      if (/insufficient|Insufficient/i.test(raw)) {
        block = `[LEDGER / UTILITY]\n${raw}`;
      }
      if (chat) {
        chatAppendInstant(chat, block + "\n");
      }
      if (el) el.textContent = "Unavailable.";
    }
    await refreshTop();
  };
}

wireLockAndOnboarding();

// Developer docs modal (hardcore-only, keeps main UI clean)
(function wireDevDocs() {
  const modal = document.getElementById("devDocsModal");
  const btn = document.getElementById("btnDevDocs");
  const close = document.getElementById("btnDevDocsClose");
  const open = () => {
    if (!modal) return;
    modal.classList.add("active");
    modal.setAttribute("aria-hidden", "false");
  };
  const shut = () => {
    if (!modal) return;
    modal.classList.remove("active");
    modal.setAttribute("aria-hidden", "true");
  };
  if (btn) btn.onclick = () => open();
  if (close) close.onclick = () => shut();
  if (modal) {
    modal.addEventListener("click", (ev) => {
      if (ev && ev.target === modal) shut();
    });
  }
  document.addEventListener("keydown", (ev) => {
    if (ev && ev.key === "Escape") shut();
  });
  const map = {
    "git-clone": document.getElementById("codeGitClone"),
    "api-key": document.getElementById("codeApiKey"),
    "run-core": document.getElementById("codeRunCore"),
  };
  for (const el of Array.from(document.querySelectorAll(".copy-btn"))) {
    el.addEventListener("click", async () => {
      try {
        const k = el.getAttribute("data-copy");
        const pre = map[k];
        const txt = pre ? pre.textContent : "";
        if (!txt) throw new Error("copy source missing");
        await navigator.clipboard.writeText(txt.replace(/\u00a0/g, " "));
        const old = el.textContent;
        el.textContent = "Copied";
        setTimeout(() => (el.textContent = old), 900);
      } catch (_) {}
    });
  }
})();

