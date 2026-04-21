import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import * as ed from "@noble/ed25519";
import { argon2id } from "@noble/hashes/argon2";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { sha512 } from "@noble/hashes/sha512";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";

// @noble/ed25519 (newer versions) requires explicit sync SHA-512 injection.
// Different versions expect it on different namespaces (`etc` vs `utils`), so set both.
const __sha512Sync = (...messages) => {
  const concat =
    (ed.etc && typeof ed.etc.concatBytes === "function" && ed.etc.concatBytes) ||
    (ed.utils && typeof ed.utils.concatBytes === "function" && ed.utils.concatBytes);
  const msg = concat ? concat(...messages) : messages[0];
  return sha512(msg);
};
if (ed.etc) ed.etc.sha512Sync = __sha512Sync;
if (ed.utils) ed.utils.sha512Sync = __sha512Sync;

export function tetGenerateMnemonic12() {
  return generateMnemonic(wordlist, 128);
}

export function tetWalletIdFromMnemonic(mnemonic) {
  const norm = String(mnemonic || "")
    .trim()
    .split(/\s+/)
    .join(" ");
  if (!validateMnemonic(norm, wordlist)) {
    throw new Error("invalid mnemonic");
  }
  const seed = mnemonicToSeedSync(norm, "");
  const sk = seed.subarray(0, 32);
  const pub = ed.getPublicKey(sk);
  let hex = "";
  for (let i = 0; i < pub.length; i++) {
    hex += pub[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/** First 32 bytes of BIP39 seed — Ed25519 secret scalar (matches Rust `wallet.rs`). */
export function tetSecretKey32FromMnemonic(mnemonic) {
  const norm = String(mnemonic || "")
    .trim()
    .split(/\s+/)
    .join(" ");
  if (!validateMnemonic(norm, wordlist)) {
    throw new Error("invalid mnemonic");
  }
  const seed = mnemonicToSeedSync(norm, "");
  return seed.subarray(0, 32);
}

/** HKDF seed for ML-DSA-44 (matches Rust `mldsa44_seed32_from_mnemonic`). */
export function tetMldsa44Seed32(mnemonic) {
  const norm = String(mnemonic || "")
    .trim()
    .split(/\s+/)
    .join(" ");
  if (!validateMnemonic(norm, wordlist)) {
    throw new Error("invalid mnemonic");
  }
  const seed = mnemonicToSeedSync(norm, "");
  const info = new TextEncoder().encode("tet:pqc:mldsa44-seed:v1");
  return hkdf(sha256, seed, undefined, info, 32);
}

/** ML-DSA-44 keypair from mnemonic: `{ secretKey, publicKey }` as Uint8Arrays (FIPS 204 raw bytes). */
export function tetMldsa44KeypairFromMnemonic(mnemonic) {
  const seed32 = tetMldsa44Seed32(mnemonic);
  return ml_dsa44.keygen(seed32);
}

/** ML-DSA-44 public key STANDARD base64 (matches `WalletInfo.dilithium_pubkey_b64`). */
export function tetMldsa44PubkeyB64FromMnemonic(mnemonic) {
  const { publicKey } = tetMldsa44KeypairFromMnemonic(mnemonic);
  let bin = "";
  for (let i = 0; i < publicKey.length; i++) bin += String.fromCharCode(publicKey[i]);
  return btoa(bin);
}

/** Deterministic signing randomness (matches Rust `mldsa44_signing_rnd`). */
export function tetMldsa44SigningRnd(msgBytes) {
  return sha256(
    new Uint8Array([
      ...new TextEncoder().encode("tet:mldsa44-signing-rnd:v1"),
      ...msgBytes,
    ])
  );
}

/** UTF-8 hybrid transfer message (matches `wallet::transfer_hybrid_auth_message_bytes`). */
export function tetTransferHybridAuthMessageUtf8(toWallet, amountMicro, nonce, mldsaPubkeyB64) {
  const t = String(toWallet || "")
    .trim()
    .toLowerCase();
  const p = String(mldsaPubkeyB64 || "").trim();
  return `tet xfer hybrid v1|${t}|${amountMicro}|${nonce}|${p}`;
}

/** UTF-8 hybrid stake message (matches `rest.rs` stake_hybrid_auth_message_bytes). */
export function tetStakeHybridAuthMessageUtf8(walletIdHex, amountMicro, nonce, mldsaPubkeyB64) {
  const w = String(walletIdHex || "")
    .trim()
    .toLowerCase();
  const p = String(mldsaPubkeyB64 || "").trim();
  return `tet stake hybrid v1|${w}|${amountMicro}|${nonce}|${p}`;
}

/** Hybrid stake signatures for `POST /wallet/stake` (Ed25519 hex + ML-DSA-44 base64). */
export async function tetSignWalletStakeHybrid(mnemonic, amountMicro, nonce) {
  const wid = tetWalletIdFromMnemonic(mnemonic);
  const mldsaPub = tetMldsa44PubkeyB64FromMnemonic(mnemonic);
  const utf8 = tetStakeHybridAuthMessageUtf8(wid, amountMicro, nonce, mldsaPub);
  const msg = new TextEncoder().encode(utf8);
  const sk32 = tetSecretKey32FromMnemonic(mnemonic);
  const edSig = await ed.sign(msg, sk32);
  let edHex = "";
  for (let i = 0; i < edSig.length; i++) edHex += edSig[i].toString(16).padStart(2, "0");
  const { secretKey } = tetMldsa44KeypairFromMnemonic(mnemonic);
  const rnd = tetMldsa44SigningRnd(msg);
  const pqcSig = ml_dsa44.sign(msg, secretKey, { extraEntropy: rnd });
  let pqcB64 = "";
  for (let i = 0; i < pqcSig.length; i++) pqcB64 += String.fromCharCode(pqcSig[i]);
  pqcB64 = btoa(pqcB64);
  return { wallet_id: wid, nonce, amount_micro: amountMicro, ed25519_sig_hex: edHex, mldsa_pubkey_b64: mldsaPub, mldsa_sig_b64: pqcB64 };
}

/** Ed25519 signature (128 hex chars) over hybrid transfer message. */
export async function tetSignWalletTransferHybrid(sk32, toWallet, amountMicro, nonce, mldsaPubkeyB64) {
  const msg = new TextEncoder().encode(
    tetTransferHybridAuthMessageUtf8(toWallet, amountMicro, nonce, mldsaPubkeyB64)
  );
  const sig = await ed.sign(msg, sk32);
  let hex = "";
  for (let i = 0; i < sig.length; i++) {
    hex += sig[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/** ML-DSA-44 signature STANDARD base64 over the same hybrid message bytes. */
export function tetSignMldsa44HybridTransfer(mnemonic, toWallet, amountMicro, nonce, mldsaPubkeyB64) {
  const msg = new TextEncoder().encode(
    tetTransferHybridAuthMessageUtf8(toWallet, amountMicro, nonce, mldsaPubkeyB64)
  );
  const { secretKey } = tetMldsa44KeypairFromMnemonic(mnemonic);
  const rnd = tetMldsa44SigningRnd(msg);
  const sig = ml_dsa44.sign(msg, secretKey, { extraEntropy: rnd });
  let bin = "";
  for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]);
  return btoa(bin);
}

/** Canonical JSON bytes for DEX trade completion (must match Rust `DexEngine::trade_complete_message_v1`). */
export function tetDexTradeCompleteMessageV1(trade, solanaTxid) {
  const t = trade || {};
  const v = {
    v: 1,
    kind: "dex_trade_complete",
    trade_id: String(t.id ?? t.trade_id ?? ""),
    order_id: String(t.order_id ?? ""),
    maker_wallet: String(t.maker_wallet ?? ""),
    taker_wallet: String(t.taker_wallet ?? ""),
    side: String(t.side ?? ""),
    quote_asset: String(t.quote_asset ?? ""),
    price_quote_per_tet: Number(t.price_quote_per_tet ?? 0),
    tet_micro: Number(t.tet_micro ?? 0),
    created_at_ms: Number(t.created_at_ms ?? 0),
    solana_usdc_txid: String(solanaTxid || ""),
  };
  return new TextEncoder().encode(JSON.stringify(v));
}

/** Build DEX completion hybrid headers for `POST /dex/trade/complete`. */
export async function tetDexTradeCompleteHybridHeaders(mnemonic, trade, solanaTxid, who) {
  const role = String(who || "").trim().toLowerCase(); // maker|taker
  if (role !== "maker" && role !== "taker") throw new Error("who must be maker|taker");
  const msg = tetDexTradeCompleteMessageV1(trade, solanaTxid);
  const sk32 = tetSecretKey32FromMnemonic(mnemonic);
  const edSigB64 = await tetSignUtf8Ed25519B64(sk32, new TextDecoder().decode(msg));
  const mldsaPub = tetMldsa44PubkeyB64FromMnemonic(mnemonic);
  const { secretKey } = tetMldsa44KeypairFromMnemonic(mnemonic);
  const rnd = tetMldsa44SigningRnd(msg);
  const pqcSig = ml_dsa44.sign(msg, secretKey, { extraEntropy: rnd });
  let pqcB64 = "";
  for (let i = 0; i < pqcSig.length; i++) pqcB64 += String.fromCharCode(pqcSig[i]);
  pqcB64 = btoa(pqcB64);
  return {
    [`x-tet-${role}-ed25519-sig-b64`]: edSigB64,
    [`x-tet-${role}-mldsa-pubkey-b64`]: mldsaPub,
    [`x-tet-${role}-mldsa-sig-b64`]: pqcB64,
  };
}

/** Founder genesis hybrid UTF-8 (matches `wallet::founder_genesis_hybrid_auth_message_bytes`). */
export function tetFounderGenesisHybridMessageUtf8(founderWalletId, mldsaPubkeyB64) {
  const w = String(founderWalletId || "")
    .trim()
    .toLowerCase();
  const p = String(mldsaPubkeyB64 || "").trim();
  return `tet founder genesis hybrid v1|${w}|${p}`;
}

/** Founder treasury withdraw hybrid UTF-8 (matches `wallet::founder_withdraw_treasury_hybrid_auth_message_bytes`). */
export function tetFounderWithdrawTreasuryHybridMessageUtf8(founderWalletId, amountMicro, nonce, mldsaPubkeyB64) {
  const w = String(founderWalletId || "")
    .trim()
    .toLowerCase();
  const a = Number(amountMicro || 0);
  const n = Number(nonce || 0);
  const p = String(mldsaPubkeyB64 || "").trim();
  if (!w) throw new Error("founderWalletId required");
  if (!Number.isFinite(a) || a <= 0) throw new Error("amountMicro must be > 0");
  if (!Number.isFinite(n) || n <= 0) throw new Error("nonce must be > 0");
  return `tet founder withdraw treasury hybrid v1|${w}|${Math.trunc(a)}|${Math.trunc(n)}|${p}`;
}

/** Genesis 1K claim hybrid UTF-8 (matches `wallet::genesis_1k_claim_hybrid_auth_message_bytes`). */
export function tetGenesis1kClaimHybridMessageUtf8(walletId, mldsaPubkeyB64) {
  const w = String(walletId || "")
    .trim()
    .toLowerCase();
  const p = String(mldsaPubkeyB64 || "").trim();
  return `tet genesis1k claim hybrid v1|${w}|${p}`;
}

/** Enterprise inference hybrid UTF-8 (matches `wallet::enterprise_inference_hybrid_auth_message_bytes`). */
export function tetEnterpriseInferenceHybridMessageUtf8(
  enterpriseWalletId,
  nonce,
  amountMicro,
  promptSha256Hex,
  model,
  attestationRequired,
  mldsaPubkeyB64
) {
  const w = String(enterpriseWalletId || "")
    .trim()
    .toLowerCase();
  const n = Number(nonce || 0);
  const a = Number(amountMicro || 0);
  const h = String(promptSha256Hex || "")
    .trim()
    .toLowerCase();
  const m = String(model || "").trim();
  const att = attestationRequired ? 1 : 0;
  const p = String(mldsaPubkeyB64 || "").trim();
  if (!w) throw new Error("enterpriseWalletId required");
  if (!Number.isFinite(n) || n <= 0) throw new Error("nonce must be > 0");
  if (!Number.isFinite(a) || a <= 0) throw new Error("amountMicro must be > 0");
  if (!h) throw new Error("promptSha256Hex required");
  if (!m) throw new Error("model required");
  return `tet enterprise inference v1|${w}|${Math.trunc(n)}|${Math.trunc(a)}|${h}|${m}|${att}|${p}`;
}

export async function tetSignEnterpriseInferenceHybrid(
  mnemonic,
  enterpriseWalletId,
  nonce,
  amountMicro,
  promptSha256Hex,
  model,
  attestationRequired
) {
  const mldsaPub = tetMldsa44PubkeyB64FromMnemonic(mnemonic);
  const utf8 = tetEnterpriseInferenceHybridMessageUtf8(
    enterpriseWalletId,
    nonce,
    amountMicro,
    promptSha256Hex,
    model,
    attestationRequired,
    mldsaPub
  );
  const sk32 = tetSecretKey32FromMnemonic(mnemonic);
  const edB64 = await tetSignUtf8Ed25519B64(sk32, utf8);
  const msg = new TextEncoder().encode(utf8);
  const { secretKey } = tetMldsa44KeypairFromMnemonic(mnemonic);
  const rnd = tetMldsa44SigningRnd(msg);
  const pqcSig = ml_dsa44.sign(msg, secretKey, { extraEntropy: rnd });
  let pqcB64 = "";
  for (let i = 0; i < pqcSig.length; i++) pqcB64 += String.fromCharCode(pqcSig[i]);
  pqcB64 = btoa(pqcB64);
  return { mldsa_pubkey_b64: mldsaPub, mldsa_signature_b64: pqcB64, ed25519_sig_b64: edB64 };
}

export async function tetSignFounderGenesisHybrid(mnemonic, founderWalletId) {
  const mldsaPub = tetMldsa44PubkeyB64FromMnemonic(mnemonic);
  const utf8 = tetFounderGenesisHybridMessageUtf8(founderWalletId, mldsaPub);
  const sk32 = tetSecretKey32FromMnemonic(mnemonic);
  const edB64 = await tetSignUtf8Ed25519B64(sk32, utf8);
  const msg = new TextEncoder().encode(utf8);
  const { secretKey } = tetMldsa44KeypairFromMnemonic(mnemonic);
  const rnd = tetMldsa44SigningRnd(msg);
  const pqcSig = ml_dsa44.sign(msg, secretKey, { extraEntropy: rnd });
  let pqcB64 = "";
  for (let i = 0; i < pqcSig.length; i++) pqcB64 += String.fromCharCode(pqcSig[i]);
  pqcB64 = btoa(pqcB64);
  return { mldsa_pubkey_b64: mldsaPub, mldsa_signature_b64: pqcB64, ed25519_sig_b64: edB64 };
}

export async function tetSignFounderWithdrawTreasuryHybrid(mnemonic, founderWalletId, amountMicro, nonce) {
  const mldsaPub = tetMldsa44PubkeyB64FromMnemonic(mnemonic);
  const utf8 = tetFounderWithdrawTreasuryHybridMessageUtf8(founderWalletId, amountMicro, nonce, mldsaPub);
  const sk32 = tetSecretKey32FromMnemonic(mnemonic);
  const edB64 = await tetSignUtf8Ed25519B64(sk32, utf8);
  const msg = new TextEncoder().encode(utf8);
  const { secretKey } = tetMldsa44KeypairFromMnemonic(mnemonic);
  const rnd = tetMldsa44SigningRnd(msg);
  const pqcSig = ml_dsa44.sign(msg, secretKey, { extraEntropy: rnd });
  let pqcB64 = "";
  for (let i = 0; i < pqcSig.length; i++) pqcB64 += String.fromCharCode(pqcSig[i]);
  pqcB64 = btoa(pqcB64);
  return { mldsa_pubkey_b64: mldsaPub, mldsa_signature_b64: pqcB64, ed25519_sig_b64: edB64 };
}

/** Returns `{ ed25519_sig_b64, mldsa_signature_b64 }` for claim headers (message is hybrid UTF-8). */
export async function tetSignGenesis1kClaimHybrid(mnemonic, walletId) {
  const mldsaPub = tetMldsa44PubkeyB64FromMnemonic(mnemonic);
  const utf8 = tetGenesis1kClaimHybridMessageUtf8(walletId, mldsaPub);
  const sk32 = tetSecretKey32FromMnemonic(mnemonic);
  const msg = new TextEncoder().encode(utf8);
  const edSig = await ed.sign(msg, sk32);
  let edB64 = "";
  for (let i = 0; i < edSig.length; i++) edB64 += String.fromCharCode(edSig[i]);
  edB64 = btoa(edB64);
  const { secretKey } = tetMldsa44KeypairFromMnemonic(mnemonic);
  const rnd = tetMldsa44SigningRnd(msg);
  const pqcSig = ml_dsa44.sign(msg, secretKey, { extraEntropy: rnd });
  let pqcB64 = "";
  for (let i = 0; i < pqcSig.length; i++) pqcB64 += String.fromCharCode(pqcSig[i]);
  pqcB64 = btoa(pqcB64);
  return { mldsa_pubkey_b64: mldsaPub, ed25519_sig_b64: edB64, mldsa_signature_b64: pqcB64 };
}

/** Argon2id → 32-byte AES key material (PIN KDF v2; matches UI `tet-enc-wallet-v2`). */
export function tetArgon2idKey32(pinUtf8, salt16) {
  const pw = new TextEncoder().encode(String(pinUtf8 || ""));
  if (!pw.length) throw new Error("empty pin");
  if (!(salt16 instanceof Uint8Array) || salt16.length !== 16) {
    throw new Error("salt16 required");
  }
  return argon2id(pw, salt16, { t: 3, m: 65536, p: 1, dkLen: 32 });
}

/** Base64 Ed25519 signature for `x-tet-*-sig-b64` headers (matches Rust `quantum_shield::verify_ed25519`). */
export async function tetSignUtf8Ed25519B64(sk32, utf8Message) {
  const msg = new TextEncoder().encode(String(utf8Message || ""));
  const sig = await ed.sign(msg, sk32);
  let bin = "";
  for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]);
  return btoa(bin);
}

const __tetWalletClientExports = {
  tetGenerateMnemonic12,
  tetWalletIdFromMnemonic,
  tetSecretKey32FromMnemonic,
  tetMldsa44Seed32,
  tetMldsa44KeypairFromMnemonic,
  tetMldsa44PubkeyB64FromMnemonic,
  tetMldsa44SigningRnd,
  tetTransferHybridAuthMessageUtf8,
  tetStakeHybridAuthMessageUtf8,
  tetSignWalletStakeHybrid,
  tetSignWalletTransferHybrid,
  tetSignMldsa44HybridTransfer,
  tetDexTradeCompleteMessageV1,
  tetDexTradeCompleteHybridHeaders,
  tetFounderGenesisHybridMessageUtf8,
  tetFounderWithdrawTreasuryHybridMessageUtf8,
  tetGenesis1kClaimHybridMessageUtf8,
  tetEnterpriseInferenceHybridMessageUtf8,
  tetSignFounderGenesisHybrid,
  tetSignFounderWithdrawTreasuryHybrid,
  tetSignGenesis1kClaimHybrid,
  tetSignEnterpriseInferenceHybrid,
  tetArgon2idKey32,
  tetSignUtf8Ed25519B64,
  validateMnemonicPhrase(m) {
    const norm = String(m || "")
      .trim()
      .split(/\s+/)
      .join(" ");
    return validateMnemonic(norm, wordlist);
  },
};

// Browser global export (Node.js environments may not define `window`).
if (typeof window !== "undefined") {
  window.tetWalletClient = __tetWalletClientExports;
}
