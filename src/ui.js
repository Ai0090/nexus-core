const key = localStorage.getItem("x-api-key") || "";
const SIGNER = (localStorage.getItem("tet-signer-base") || "http://localhost:5791")
  .trim()
  .replace(/\/$/, "");
const STEVEMON = 1_000_000;
const LS_WALLET_ID_KEY = "tet-wallet-id";
const LS_LOGGED_IN = "nexus-ui-logged-in";
const LS_LAST_MESH_ADDR = "nexus-ui-mesh-addr";
const WALLET_ID_DISPLAY_PREFIX = 6;
const WALLET_ID_DISPLAY_SUFFIX = 4;

// ─────────────────────────────────────────────────────────────────────────────
// TET Wasm Core (WebRTC + ZK verification) integration (Phase 5.1)
// NOTE: Do not change underlying Wasm logic / REST wiring.
// ─────────────────────────────────────────────────────────────────────────────
const NexusCore = (() => {
  let _mod = null; // { default:init, NexusWebClient }
  let _client = null;
  let _initP = null;
  let _connectP = null;

  function _setMeshUi(ok, msg) {
    const dot = document.getElementById("meshDot");
    const line = document.getElementById("meshStatusLine");
    if (dot) dot.className = "dot" + (ok ? " ok" : "");
    if (line) line.textContent = msg || (ok ? "MESH: ONLINE" : "MESH: OFFLINE");
  }

  async function initSilent() {
    if (_initP) return _initP;
    _initP = (async () => {
      try {
        // Dynamic import works from non-module scripts in modern browsers.
        _mod = await import("/assets/nexus_wasm.js");
        await _mod.default(); // init()
        const origin = String(
          window.location && window.location.origin ? window.location.origin : ""
        ).replace(/\/$/, "");
        _client = new _mod.NexusWebClient(origin);

        // Phase 2.1: attempt identity restore from IndexedDB.
        try {
          const ok = await _client.load_identity();
          if (ok) {
            const wid = String(_client.wallet_id ? _client.wallet_id() : "").trim();
            if (wid) setCurrentWalletId(wid);
            setLoggedIn(true);
            setScreens("dashboard");
          }
        } catch (_) {}
        _setMeshUi(false, "MESH: READY (WASM LOADED)");
        return _client;
      } catch (e) {
        _setMeshUi(false, "MESH: DISABLED (WASM LOAD FAILED)");
        throw e;
      }
    })();
    return _initP;
  }

  async function connect(bootnodeAddr) {
    const addr = String(bootnodeAddr || "").trim();
    if (!addr) throw new Error("Missing bootnode multiaddr.");
    if (_connectP) return _connectP;
    _connectP = (async () => {
      _setMeshUi(false, "MESH: CONNECTING…");
      const c = await initSilent();
      await c.connect_to_network(addr);
      _setMeshUi(true, "MESH: ONLINE");
      return true;
    })().finally(() => {
      // allow reconnect attempts later
      _connectP = null;
    });
    return _connectP;
  }

  async function runInference(prompt) {
    const c = await initSilent();
    if (!c) throw new Error("TET core not initialized.");
    return await c.run_inference(String(prompt || ""));
  }

  return { initSilent, connect, runInference };
})();

function $(id) {
  return document.getElementById(id);
}

function showToast(msg, ms = 2400) {
  const t = $("toast");
  if (!t) return;
  t.textContent = String(msg || "");
  t.classList.add("show");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => t.classList.remove("show"), ms);
}

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

/** TET core HTTP API (Rust). Invalid `tet-core-base` values are ignored. */
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

function fmtWalletIdShort(wid) {
  const w = String(wid || "").trim().toLowerCase();
  if (w.length !== 64) return w || "—";
  return `${w.slice(0, WALLET_ID_DISPLAY_PREFIX)}...${w.slice(64 - WALLET_ID_DISPLAY_SUFFIX)}`;
}

function modalEls() {
  return {
    root: $("modalRoot"),
    close: $("btnModalClose"),
    createWallet: $("modalCreateWallet"),
    tosAgree: $("tosAgree"),
    generateWallet: $("btnGenerateWallet"),
    createCancel: $("btnCreateCancel"),
    newWallet: $("modalNewWallet"),
    importWallet: $("modalImportWallet"),
    seedWords: $("seedWords"),
    seedSaved: $("btnSeedSaved"),
    seedInput: $("seedInput"),
    seedImport: $("btnSeedImport"),
    seedCancel: $("btnSeedCancel"),
  };
}

function showModal(which) {
  const m = modalEls();
  if (!m.root) return;
  m.root.hidden = false;
  if (m.createWallet) m.createWallet.hidden = which !== "create";
  if (m.newWallet) m.newWallet.hidden = which !== "new";
  if (m.importWallet) m.importWallet.hidden = which !== "import";
}

function hideModal() {
  const m = modalEls();
  if (!m.root) return;
  m.root.hidden = true;
  if (m.seedInput) m.seedInput.value = "";
  if (m.tosAgree) m.tosAgree.checked = false;
  if (m.generateWallet) m.generateWallet.disabled = true;
}

/** Read body as text, parse JSON safely. */
async function fetchJsonLoose(url, opts) {
  const r = await fetch(url, opts || {});
  const raw = await r.text();
  let data = {};
  const trimmed = raw.trim();
  if (trimmed) {
    try {
      data = JSON.parse(trimmed);
    } catch {
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${trimmed.slice(0, 400)}`);
      return { _plain: trimmed };
    }
  }
  if (typeof data !== "object" || data === null) {
    if (!r.ok) throw new Error(String(trimmed || r.status));
    return { _plain: String(data) };
  }
  if (!r.ok) {
    const msg =
      data.error !== undefined || data.message !== undefined
        ? String(data.error ?? data.message)
        : trimmed.slice(0, 400) || String(r.status);
    const e = new Error(msg);
    e.status = r.status;
    throw e;
  }
  return data;
}

async function getMe() {
  const wid = getCurrentWalletId();
  if (!wid) throw new Error("No wallet_id in this browser session.");
  return fetchJsonLoose(coreApi(`/ledger/me?wallet_id=${encodeURIComponent(wid)}`));
}

function fmtTet4(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return "0.0000";
  return n.toFixed(4);
}

function setScreens(which) {
  const landing = $("screenLanding");
  const dash = $("screenDashboard");
  const dashBody = $("screenDashboardBody");
  const onDash = which === "dashboard";
  if (landing) landing.hidden = onDash;
  if (dash) dash.hidden = !onDash;
  if (dashBody) dashBody.hidden = !onDash;
}

function setLoggedIn(v) {
  try {
    if (v) localStorage.setItem(LS_LOGGED_IN, "1");
    else localStorage.removeItem(LS_LOGGED_IN);
  } catch (_) {}
}

function isLoggedIn() {
  return (localStorage.getItem(LS_LOGGED_IN) || "") === "1";
}

function appendBubble(kind, text, meta) {
  const log = $("chatHistory") || $("chatLog");
  if (!log) return null;
  const row = document.createElement("div");
  row.className = "bubbleRow";
  const bubble = document.createElement("div");
  bubble.className = "bubble " + (kind === "user" ? "user" : "ai");
  bubble.textContent = String(text || "");

  row.appendChild(bubble);

  if (kind !== "user") {
    const metaRow = document.createElement("div");
    metaRow.className = "bubbleMeta";
    const badge = document.createElement("span");
    badge.className = "badge" + (meta && meta.err ? " err" : "");
    badge.textContent = meta && meta.err ? "ZK VERIFY FAILED" : "🛡️ ZK Verified";
    metaRow.appendChild(badge);

    const cost = document.createElement("span");
    cost.className = "mono";
    cost.style.color = "rgba(10, 37, 64, 0.62)";
    cost.style.fontSize = "12px";
    cost.dataset.role = "cost";
    cost.textContent = `Cost: ${meta && meta.cost_stevemon != null ? String(meta.cost_stevemon) : "—"} stevemon`;
    metaRow.appendChild(cost);

    bubble.appendChild(metaRow);
  }

  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
  return bubble;
}

function estimateCostStevemonFromResponseText(respText) {
  // PoC pricing rule (mirrors guest-side deterministic cost idea): 1 byte ~= 10 "micro units".
  // We label it as stevemon in the UI for economic visibility, not as a guaranteed billing statement.
  const s = String(respText || "");
  const bytes = new TextEncoder().encode(s).length;
  const c = Math.max(1, bytes * 10);
  return c;
}

async function refreshWalletUi() {
  const wid = getCurrentWalletId();
  const widEl = $("vaultWalletId");
  const balEl = $("bal");
  const stakedEl = $("stakedLine");
  const hintEl = $("walletHint");

  if (widEl) {
    widEl.textContent = wid ? fmtWalletIdShort(wid) : "—";
    widEl.title = wid || "";
  }
  if (!wid) {
    if (balEl) balEl.textContent = "0.0000 TET";
    if (stakedEl) stakedEl.textContent = "—";
    if (hintEl) hintEl.textContent = "No wallet detected in this browser. Create or access a wallet to view balances.";
    return;
  }

  try {
    const me = await getMe();
    // Backward/forward compatible fields:
    const balMicro = Number(me.balance_micro_tet ?? me.balance_micro ?? me.balance_microtet ?? 0);
    const stakedMicro = Number(me.staked_micro_tet ?? me.staked_micro ?? 0);
    if (balEl) balEl.textContent = `${fmtTet4(balMicro / STEVEMON)} TET`;
    if (stakedEl) stakedEl.textContent = `${fmtTet4(stakedMicro / STEVEMON)} TET`;
    if (hintEl) hintEl.textContent = "Ledger-backed balance from your connected core.";
  } catch (e) {
    if (hintEl) hintEl.textContent = "Unable to load wallet balance from core.";
  }
}

function wireLanding() {
  const b1 = $("btnCreateWallet");
  const b2 = $("btnAccessWallet");
  if (b1) b1.addEventListener("click", async () => {
    showModal("create");
    const m = modalEls();
    if (m.generateWallet) m.generateWallet.disabled = true;

    const onToggle = () => {
      if (m.generateWallet) m.generateWallet.disabled = !Boolean(m.tosAgree && m.tosAgree.checked);
    };
    if (m.tosAgree) m.tosAgree.addEventListener("change", onToggle);
    onToggle();

    const onCancel = () => {
      if (m.tosAgree) m.tosAgree.removeEventListener("change", onToggle);
      if (m.createCancel) m.createCancel.removeEventListener("click", onCancel);
      if (m.generateWallet) m.generateWallet.removeEventListener("click", onGenerate);
      hideModal();
    };

    const onGenerate = async () => {
      if (!(m.tosAgree && m.tosAgree.checked)) return;
      try {
        if (m.generateWallet) m.generateWallet.disabled = true;
        const c = await NexusCore.initSilent();
        const phrase = await c.generate_new_wallet();

        // Move to "new wallet" phrase display modal.
        if (m.tosAgree) m.tosAgree.removeEventListener("change", onToggle);
        if (m.createCancel) m.createCancel.removeEventListener("click", onCancel);
        if (m.generateWallet) m.generateWallet.removeEventListener("click", onGenerate);

        if (m.seedWords) m.seedWords.textContent = String(phrase || "").trim();
        showModal("new");

        const onDone = async () => {
          try {
            const wid = String(c.wallet_id ? c.wallet_id() : "").trim();
            if (wid) setCurrentWalletId(wid);
            } catch (_) {}
          hideModal();
          setLoggedIn(true);
          setScreens("dashboard");
          await refreshWalletUi();
          showToast("Welcome to TET Network.");
          if (m.seedSaved) m.seedSaved.removeEventListener("click", onDone);
        };
        if (m.seedSaved) m.seedSaved.addEventListener("click", onDone);
      } catch (e) {
        showToast(String(e && e.message ? e.message : e));
      } finally {
        onToggle();
      }
    };

    if (m.createCancel) m.createCancel.addEventListener("click", onCancel, { once: true });
    if (m.generateWallet) m.generateWallet.addEventListener("click", onGenerate);
  });
  if (b2) b2.addEventListener("click", async () => {
    showModal("import");
    const m = modalEls();
    const doImport = async () => {
      try {
        const c = await NexusCore.initSilent();
        const phrase = String(m.seedInput ? m.seedInput.value : "").trim();
        const ok = await c.recover_wallet(phrase);
        if (!ok) {
          showToast("Invalid recovery phrase.");
          return;
        }
        const wid = String(c.wallet_id ? c.wallet_id() : "").trim();
        if (wid) setCurrentWalletId(wid);
        hideModal();
        setLoggedIn(true);
        setScreens("dashboard");
        await refreshWalletUi();
        showToast("Wallet recovered.");
        if (m.seedImport) m.seedImport.removeEventListener("click", doImport);
      } catch (e) {
        showToast(String(e && e.message ? e.message : e));
      }
    };
    if (m.seedImport) m.seedImport.addEventListener("click", doImport);
    if (m.seedCancel) m.seedCancel.addEventListener("click", hideModal, { once: true });
  });
}

function wireLogout() {
  const b = $("btnLogout");
  if (!b) return;
  b.addEventListener("click", () => {
    setLoggedIn(false);
    setScreens("landing");
    showToast("Logged out.");
  });
}

function wireMesh() {
  const addrEl = $("meshAddr");
  const btn = $("btnMeshConnect");
  if (addrEl) {
    const last = (localStorage.getItem(LS_LAST_MESH_ADDR) || "").trim();
    if (last) addrEl.value = last;
  }
  const doConnect = async () => {
    const addr = String(addrEl ? addrEl.value : "").trim();
    if (!addr) {
      showToast("Paste a bootnode WebRTC multiaddr first.");
      return;
    }
    try {
      localStorage.setItem(LS_LAST_MESH_ADDR, addr);
    } catch (_) {}
    try {
      await NexusCore.connect(addr);
      showToast("Mesh connected.");
    } catch (e) {
      showToast(String(e && e.message ? e.message : e));
    }
  };
  if (btn) btn.addEventListener("click", doConnect);
  if (addrEl) {
    addrEl.addEventListener("keydown", (ev) => {
      if (ev && ev.key === "Enter") {
        ev.preventDefault();
        doConnect();
      }
    });
  }
}

function wireWalletButtons() {
  const recv = $("btnReceive");
  const faucet = $("btnFaucet");
  if (recv) {
    recv.addEventListener("click", async () => {
  const wid = getCurrentWalletId();
    if (!wid) {
        showToast("No wallet id in this browser.");
    return;
  }
    try {
      await navigator.clipboard.writeText(wid);
        showToast("Wallet ID copied.");
      } catch {
        showToast("Copy failed.");
      }
    });
  }
  if (faucet) {
    faucet.addEventListener("click", async () => {
      const wid = getCurrentWalletId();
    if (!wid) {
        showToast("No wallet id in this browser.");
      return;
    }
    try {
        await fetchJsonLoose(coreApi("/ledger/faucet"), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          },
          body: JSON.stringify({ wallet_id: wid, amount_tet: 100 }),
        });
        showToast("Faucet sent (local Solana).");
        await refreshWalletUi();
    } catch (e) {
        showToast(String(e && e.message ? e.message : e));
      }
    });
  }
}

function wireChat() {
  const input = $("chatInput");
  const btn = $("btnSendPrompt") || $("btnSend");
  const status = $("chatStatus");

  async function send() {
    const prompt = String(input ? input.value : "").trim();
    if (!prompt) return;
    if (input) input.value = "";

    appendBubble("user", prompt);
    const aiBubble = appendBubble("ai", "Worker computing & generating ZK Proof…", { cost_stevemon: "…" });
    if (status) status.textContent = "Working…";

    try {
  const wid = getCurrentWalletId();
      if (!wid) throw new Error("No wallet id in this browser.");
      const r = await fetchJsonLoose(coreApi("/ai/infer"), {
    method: "POST",
        headers: {
          "content-type": "application/json",
          "x-tet-wallet-id": wid,
        },
        body: JSON.stringify({ wallet_id: wid, prompt }),
      });
      const out = String(r && r.response ? r.response : "");
      const receipt = String(r && r.receipt_b64 ? r.receipt_b64 : "");

      if (aiBubble) {
        const metaEl = aiBubble.querySelector(".bubbleMeta");
        aiBubble.textContent = String(out || "");
        if (metaEl) aiBubble.appendChild(metaEl);
        const costEl = aiBubble.querySelector('[data-role="cost"]');
        if (costEl) {
          const c = estimateCostStevemonFromResponseText(out);
          costEl.textContent = `Cost: ${c} stevemon`;
        }
      }

      appendBubble("ai", `[Verified by ZK Receipt] | Worker Rewarded: 10 TET`, { cost_stevemon: "—" });
      if (receipt) {
        const el = appendBubble("ai", `Receipt: ${receipt.slice(0, 18)}…`, { cost_stevemon: "—" });
        if (el) el.style.opacity = "0.75";
      }
      if (status) status.textContent = "Verified & Settled.";
      await refreshWalletUi();
    } catch (e) {
      const msg = String(e && e.message ? e.message : e);
      if (aiBubble) {
        const metaEl = aiBubble.querySelector(".bubbleMeta");
        aiBubble.textContent = msg || "ZK verification failed.";
        if (metaEl) {
          const badge = metaEl.querySelector(".badge");
          if (badge) {
            badge.classList.add("err");
            badge.textContent = "ZK VERIFY FAILED";
          }
          const costEl = metaEl.querySelector('[data-role="cost"]');
          if (costEl) costEl.textContent = "Cost: — stevemon";
          aiBubble.appendChild(metaEl);
        }
      }
      if (status) status.textContent = "Error.";
      if (msg.includes("TET_ERR_SAFE_MODE")) showToast(msg);
    }
  }

  if (btn) btn.addEventListener("click", send);
  if (input) {
    input.addEventListener("keydown", (ev) => {
      if (!ev) return;
      if (ev.key === "Enter" && !ev.shiftKey) {
        ev.preventDefault();
        send();
      }
    });
  }
}

async function boot() {
  wireLanding();
  wireLogout();
  wireMesh();
  wireWalletButtons();
  wireChat();

  // Modal wiring.
  {
    const m = modalEls();
    if (m.close) m.close.addEventListener("click", hideModal);
    if (m.root) {
      m.root.addEventListener("click", (ev) => {
        const t = ev && ev.target ? ev.target : null;
        if (t && t.classList && t.classList.contains("modalBackdrop")) hideModal();
      });
    }
    window.addEventListener("keydown", (ev) => {
      if (ev && ev.key === "Escape") hideModal();
    });
  }

  // Phase 2.1: initSilent may auto-restore identity and flip UI.
  setScreens(isLoggedIn() ? "dashboard" : "landing");

  try {
    await NexusCore.initSilent();
  } catch (_) {}

  // If identity was restored, we should be on dashboard.
  if (isLoggedIn() || getCurrentWalletId()) {
    setLoggedIn(true);
    setScreens("dashboard");
    await refreshWalletUi();
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => void boot());
} else {
  void boot();
}

