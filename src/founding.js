const CORE_URL = (localStorage.getItem("tet-core-base") || (window.location && window.location.origin) || "")
  .trim()
  .replace(/\/$/, "");
const LS_WALLET_ID_KEY = "tet-wallet-id";
function coreApi(p) {
  return `${CORE_URL}${p.startsWith("/") ? p : "/" + p}`;
}

function fmtTET(x) {
  const n = Number(x ?? 0);
  if (!Number.isFinite(n)) return "0.00";
  return n.toFixed(2);
}

async function getStatus() {
  const r = await fetch(coreApi("/status"));
  return await r.json();
}

async function getMe() {
  const wid = String(localStorage.getItem(LS_WALLET_ID_KEY) || "").trim().toLowerCase();
  if (!wid) throw new Error("missing wallet_id (localStorage.tet-wallet-id)");
  const r = await fetch(coreApi(`/ledger/me?wallet_id=${encodeURIComponent(wid)}`));
  return await r.json();
}

async function getGuardian(wallet) {
  const r = await fetch(coreApi(`/founding/cert/${encodeURIComponent(wallet)}`));
  if (!r.ok) return null;
  return await r.json();
}

function setSecBadge(ok, text) {
  const dot = document.getElementById("secDot");
  const t = document.getElementById("secText");
  dot.className = "dot" + (ok ? " ok" : " hot");
  t.textContent = text;
}

async function refresh() {
  const s = await getStatus();
  const me = await getMe();
  document.getElementById("bal").textContent = `${fmtTET(me.balance_nxs)} TET`;

  const hwDot = document.getElementById("hwDot");
  const hwText = document.getElementById("hwText");
  const linked = !!s.signer_linked;
  hwDot.className = "dot" + (linked ? " ok" : "");
  hwText.textContent = linked ? "Hardware Secured: LINKED" : "Hardware Secured: UNLINKED";

  const wallet = me.wallet_id ?? "";
  const cert = wallet ? await getGuardian(wallet) : null;
  const gDot = document.getElementById("guardianDot");
  const gText = document.getElementById("guardianText");
  const badge = document.getElementById("guardianBadge");
  if (cert) {
    gDot.className = "dot ok";
    gText.textContent = "GENESIS GUARDIAN: ON";
    badge.style.display = "inline-flex";
  } else {
    gDot.className = "dot";
    gText.textContent = "GENESIS GUARDIAN: OFF";
    badge.style.display = "none";
  }

  const pqc = !!s.pqc_active;
  const att = !!s.attestation_required;
  setSecBadge(pqc && att, `Universal Security: ${pqc ? "PQC" : "PQC OFF"} / ${att ? "HW ATTEST REQUIRED" : "HW ATTEST OFF"}`);
}

function buildCommand() {
  // Use signed binary directly (codesign requirement).
  const signer = "target/debug/tet-signer";
  const cmd =
`"${signer}" founding-enroll \\
| curl -sS \"$TET_CORE_BASE/founding/enroll\" \\
  -H "content-type: application/json" \\
  --data-binary @-`;
  return cmd;
}

document.getElementById("secureBtn").onclick = async () => {
  const cmd = buildCommand();
  document.getElementById("cmd").value = cmd;
  document.getElementById("msg").textContent = "Run the command in Terminal (Touch ID will prompt).";
};

document.getElementById("copyBtn").onclick = async () => {
  const v = document.getElementById("cmd").value.trim();
  if (!v) { document.getElementById("msg").textContent = "No command to copy yet."; return; }
  try {
    await navigator.clipboard.writeText(v);
    document.getElementById("msg").textContent = "Copied.";
  } catch {
    document.getElementById("msg").textContent = "Copy failed. Select and copy manually.";
  }
};

document.getElementById("refreshBtn").onclick = async () => {
  document.getElementById("msg").textContent = "Refreshing…";
  try {
    await refresh();
    document.getElementById("msg").textContent = "OK.";
  } catch (e) {
    document.getElementById("msg").textContent = `Error: ${String(e)}`;
  }
};

(async () => {
  await refresh();
  setInterval(refresh, 3500);
})();

