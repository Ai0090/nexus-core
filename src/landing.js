// Landing page session + restore modal (CSP-safe: no inline script needed)
(function () {
  const LS_WALLET_ID_KEY = "tet-wallet-id";

  function cleanMnemonic(rawInput) {
    return String(rawInput ?? "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, " ");
  }

  function getWalletIdLs() {
    return String(localStorage.getItem(LS_WALLET_ID_KEY) || "").trim().toLowerCase();
  }

  function setWalletIdLs(wid) {
    const w = String(wid || "").trim().toLowerCase();
    if (w && w.length === 64) localStorage.setItem(LS_WALLET_ID_KEY, w);
  }

  function hasValidWalletId() {
    const w = getWalletIdLs();
    return w.length === 64 && /^[0-9a-f]+$/.test(w);
  }

  async function loadWalletClient() {
    if (window.tetWalletClient) return;
    await new Promise((res, rej) => {
      const s = document.createElement("script");
      s.src = "/assets/wallet_client_bundled.js?v=genesis_v3";
      s.async = true;
      s.onload = () => res();
      s.onerror = () => rej(new Error("Could not load wallet client bundle."));
      document.head.appendChild(s);
    });
    if (!window.tetWalletClient) throw new Error("wallet client not available");
  }

  function openRestore() {
    const m = document.getElementById("restoreModal");
    const ta = document.getElementById("restoreMnemonic");
    const msg = document.getElementById("restoreMsg");
    if (msg) {
      msg.textContent = "Awaiting mnemonic…";
      msg.className = "msg";
    }
    if (m) m.classList.add("active");
    if (ta) setTimeout(() => ta.focus(), 0);
  }

  function closeRestore() {
    const m = document.getElementById("restoreModal");
    const ta = document.getElementById("restoreMnemonic");
    if (m) m.classList.remove("active");
    if (ta) ta.value = "";
  }

  function syncResumeUi() {
    const main = document.getElementById("btnMainCta");
    const paths = document.getElementById("loginPaths");
    if (!main) return;
    if (hasValidWalletId()) {
      main.textContent = "[ > RESUME_SESSION : GO_TO_DASHBOARD ]";
      main.setAttribute("href", "/app");
      if (paths) paths.style.display = "none";
    } else {
      main.textContent = "[ > LOGIN / CONNECT_WALLET ]";
      main.setAttribute("href", "/app");
      if (paths) paths.style.display = "";
    }
  }

  async function verifyAndLogin() {
    const msg = document.getElementById("restoreMsg");
    const ta = document.getElementById("restoreMnemonic");
    const raw = ta ? ta.value : "";
    const phrase = cleanMnemonic(raw);
    if (msg) {
      msg.textContent = "Verifying…";
      msg.className = "msg";
    }
    try {
      await loadWalletClient();
      if (!phrase) throw new Error("Mnemonic required.");
      const words = phrase.split(" ").filter(Boolean);
      if (words.length !== 12) throw new Error(`Expected 12 words. Got ${words.length}.`);
      if (!window.tetWalletClient.validateMnemonicPhrase(phrase)) {
        throw new Error("Invalid BIP39 mnemonic.");
      }
      const wid = String(window.tetWalletClient.tetWalletIdFromMnemonic(phrase) || "")
        .trim()
        .toLowerCase();
      if (!wid || wid.length !== 64 || !/^[0-9a-f]+$/.test(wid)) {
        throw new Error("Failed to derive Wallet ID.");
      }
      setWalletIdLs(wid);
      if (msg) {
        msg.textContent = `OK. WALLET_ID=${wid}`;
        msg.className = "msg";
      }
      window.location.href = "/app";
    } catch (e) {
      const t = String(e && e.message ? e.message : e);
      if (msg) {
        msg.textContent = `ERROR: ${t}`;
        msg.className = "msg err";
      }
    }
  }

  // Wire UI
  const restoreBtn = document.getElementById("btnRestore");
  if (restoreBtn) {
    restoreBtn.addEventListener("click", (ev) => {
      ev.preventDefault();
      openRestore();
    });
  }
  const cancelBtn = document.getElementById("btnRestoreCancel");
  if (cancelBtn) cancelBtn.addEventListener("click", (ev) => { ev.preventDefault(); closeRestore(); });
  const submitBtn = document.getElementById("btnRestoreSubmit");
  if (submitBtn) submitBtn.addEventListener("click", (ev) => { ev.preventDefault(); verifyAndLogin().catch(() => {}); });

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeRestore();
  });

  if (window.location.hash === "#restore") openRestore();
  syncResumeUi();
})();

