/* Founder terminal — loaded from same origin (CSP-safe). */
function dbg(msg) {
  try {
    var el = document.getElementById("dbg");
    var ts = new Date().toISOString();
    var line = "[" + ts + "] " + String(msg);
    if (el) {
      el.textContent = (el.textContent ? el.textContent + "\n" : "") + line;
    }
  } catch (_) {}
}

async function readBodyTextSafe(resp) {
  try {
    return (await resp.text()) || "";
  } catch (_) {
    return "";
  }
}

async function loadWalletClient() {
  if (window.tetWalletClient) return;
  await new Promise(function (res, rej) {
    var s = document.createElement("script");
    s.src = "/assets/wallet_client_bundled.js";
    s.async = true;
    s.onload = function () {
      return res();
    };
    s.onerror = function () {
      return rej(new Error("Could not load wallet_client_bundled.js"));
    };
    document.head.appendChild(s);
  });
}

/** Wired from DOMContentLoaded (inline onclick is blocked by CSP script-src). */
async function doGenesis() {
  alert("CEO confirmed. Starting Genesis process...");
  dbg("CEO confirmed alert shown");

  var walletEl = document.getElementById("founderWallet");
  var btn = document.getElementById("btnGenesis");

  var wid = walletEl && walletEl.value ? String(walletEl.value).trim() : "";

  dbg("Collected inputs: wallet=" + (wid ? "(present)" : "(missing)"));

  if (!wid) {
    dbg("ABORT: missing wallet id");
    alert("FAILURE REASON: Genesis Recipient Wallet ID is required.");
    return;
  }

  var phrase = window.prompt(
    "Paste the 12-word recovery phrase for this founder wallet (not sent to the server):"
  );
  if (!phrase || !String(phrase).trim()) {
    dbg("ABORT: cancelled or empty phrase");
    return;
  }

  var url = "/founder/genesis";
  dbg("POST " + url);

  try {
    if (btn) btn.disabled = true;
    await loadWalletClient();
    var norm = String(phrase)
      .trim()
      .split(/\s+/)
      .join(" ");
    if (!window.tetWalletClient.validateMnemonicPhrase(norm)) {
      throw new Error("Invalid recovery phrase.");
    }
    var derived = window.tetWalletClient.tetWalletIdFromMnemonic(norm);
    if (derived.toLowerCase() !== wid.toLowerCase()) {
      throw new Error("Phrase does not match the genesis recipient wallet ID.");
    }
    var hybrid = await window.tetWalletClient.tetSignFounderGenesisHybrid(norm, wid);

    var resp = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-tet-founder-ed25519-sig-b64": hybrid.ed25519_sig_b64,
      },
      body: JSON.stringify({
        founder_wallet_id: wid,
        mldsa_pubkey_b64: hybrid.mldsa_pubkey_b64,
        mldsa_signature_b64: hybrid.mldsa_signature_b64,
      }),
    });

    dbg("HTTP status=" + resp.status);
    var bodyText = await readBodyTextSafe(resp);
    dbg("Response body (first 600): " + bodyText.slice(0, 600));

    if (!resp.ok) {
      var errMsg =
        bodyText && bodyText.trim() ? bodyText.trim() : "HTTP " + resp.status;
      throw new Error(errMsg);
    }

    alert("10B TET MINTED. EMPIRE STARTED.");
    dbg("SUCCESS alert shown");
  } catch (e) {
    var m = "";
    try {
      m = String(e && e.message ? e.message : e);
    } catch (_) {
      m = "unknown error";
    }
    dbg("ERROR: " + m);
    alert("FAILURE REASON: " + m);
  } finally {
    if (btn) btn.disabled = false;
    dbg("Button re-enabled");
  }
}

window.doGenesis = doGenesis;

document.addEventListener("DOMContentLoaded", function () {
  dbg("Founder terminal JS loaded (external)");

  var btnGenesis = document.getElementById("btnGenesis");
  if (btnGenesis) {
    btnGenesis.addEventListener("click", function (ev) {
      if (ev) ev.preventDefault();
      void doGenesis();
    });
  }
});
