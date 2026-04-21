//! TET Worker Protocol — lend CPU/GPU for PoC inference (Phase 2).
//!
//! ```text
//! # One-line proof JSON for /ai/proxy worker_proof field:
//! TET_WORKER_SK_HEX=... TET_WORKER_HW_ID=... tet-worker proof tet/poc "hello world"
//!
//! # Heartbeat (register) with core:
//! TET_REST_URL=http://127.0.0.1:5010 TET_API_KEY=... \
//!   TET_WORKER_WALLET=my-worker TET_WORKER_SK_HEX=... TET_WORKER_HW_ID=... \
//!   tet-worker heartbeat
//! ```

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::RngCore as _;
use std::io::Write as _;
use tet_core::tet_worker::{
    WorkerProofV1, hardware_id_sha256_hex_best_effort, poc_infer, poe_execution_stub_b64,
    result_sha256_hex, task_sha256_hex, worker_sign_message,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize as _;

fn infer_from_task_plain(pt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(pt) {
        if let serde_json::Value::Object(ref m) = v {
            let kind = m.get("kind").and_then(|x| x.as_str());
            let looks_structured = kind == Some("tet_b2b_infer_v1")
                || m.contains_key("input")
                || m.contains_key("model");
            if looks_structured {
                let model = m.get("model").and_then(|x| x.as_str()).unwrap_or("default");
                let input = m.get("input").and_then(|x| x.as_str()).unwrap_or("");
                let input = if input.trim().is_empty() {
                    String::from_utf8_lossy(pt).into_owned()
                } else {
                    input.to_string()
                };
                let r = tet_core::ai_local::infer_text(model, &input);
                return Ok(serde_json::to_vec(&r)?);
            }
        }
    }
    let s = String::from_utf8_lossy(pt).into_owned();
    let r = tet_core::ai_local::infer_text("default", &s);
    Ok(serde_json::to_vec(&r)?)
}

fn x25519_static_from_env()
-> Result<(X25519StaticSecret, String), Box<dyn std::error::Error + Send + Sync>> {
    let sk_b64 = std::env::var("TET_WORKER_X25519_SK_B64")?;
    let raw = base64::engine::general_purpose::STANDARD.decode(sk_b64.as_bytes())?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "TET_WORKER_X25519_SK_B64 must be 32 bytes")?;
    let sk = X25519StaticSecret::from(arr);
    let pk = X25519PublicKey::from(&sk);
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pk.as_bytes());
    Ok((sk, pk_b64))
}

fn proof_for_model_input(
    model: &str,
    input: &str,
) -> Result<WorkerProofV1, Box<dyn std::error::Error + Send + Sync>> {
    let sk_hex = std::env::var("TET_WORKER_SK_HEX")?;
    let hw = std::env::var("TET_WORKER_HW_ID")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let hw = match hw {
        Some(v) => v,
        None => hardware_id_sha256_hex_best_effort()?,
    };
    let mut sk_bytes = hex::decode(sk_hex.trim())?;
    if sk_bytes.len() != 32 {
        return Err("TET_WORKER_SK_HEX must be 32 bytes hex".into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&sk_bytes);
    sk_bytes.zeroize();
    let signing_key = SigningKey::from_bytes(&arr);
    let output = poc_infer(input);
    let t = task_sha256_hex(model, input);
    let r = result_sha256_hex(&output);
    let msg = worker_sign_message(&t, &r, hw.trim());
    let sig = signing_key.sign(&msg);
    let ed25519_sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    let poe_stub_b64 = poe_execution_stub_b64(&t, &r);
    Ok(WorkerProofV1 {
        hardware_id_hex: hw,
        task_sha256_hex: t,
        result_sha256_hex: r,
        output_text: output,
        ed25519_sig_b64,
        poe_stub_b64,
    })
}

fn cmd_proof(model: &str, input: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let proof = proof_for_model_input(model, input)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, &proof)?;
    writeln!(out)?;
    Ok(())
}

async fn cmd_heartbeat() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = std::env::var("TET_REST_URL").unwrap_or_else(|_| "http://127.0.0.1:5010".into());
    let key = std::env::var("TET_API_KEY")?;
    let wallet = std::env::var("TET_WORKER_WALLET")?;
    let sk_hex = std::env::var("TET_WORKER_SK_HEX")?;
    let hw = std::env::var("TET_WORKER_HW_ID")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let hw = match hw {
        Some(v) => v,
        None => hardware_id_sha256_hex_best_effort()?,
    };
    let tflops = std::env::var("TET_WORKER_TFLOPS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(8.0);

    let mut sk_bytes = hex::decode(sk_hex.trim())?;
    if sk_bytes.len() != 32 {
        return Err("TET_WORKER_SK_HEX must be 32 bytes hex".into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&sk_bytes);
    sk_bytes.zeroize();
    let signing_key = SigningKey::from_bytes(&arr);
    let vk = signing_key.verifying_key();
    let ed25519_pubkey_hex = hex::encode(vk.as_bytes());
    let x25519_pubkey_b64 = x25519_static_from_env().ok().map(|(_, pk)| pk);

    let client = reqwest::Client::new();
    let url = format!("{}/worker/register", base.trim_end_matches('/'));
    let body = serde_json::json!({
        "wallet": wallet,
        "hardware_id_hex": hw,
        "ed25519_pubkey_hex": ed25519_pubkey_hex,
        "x25519_pubkey_b64": x25519_pubkey_b64,
        "tflops_est": tflops,
    });
    let r = client
        .post(url)
        .header("x-api-key", key)
        .json(&body)
        .send()
        .await?;
    if !r.status().is_success() {
        let t = r.text().await.unwrap_or_default();
        return Err(format!("register failed: {t}").into());
    }
    eprintln!("tet-worker: heartbeat OK");
    Ok(())
}

async fn cmd_x25519_gen() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (sk, pk) = tet_core::e2ee::gen_worker_static_keypair();
    let sk_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
    let pk_b64 = tet_core::e2ee::encode_x25519_pub_b64(&pk);
    println!("TET_WORKER_X25519_SK_B64={sk_b64}");
    println!("TET_WORKER_X25519_PK_B64={pk_b64}");
    Ok(())
}

async fn cmd_e2ee_loop() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = std::env::var("TET_REST_URL").unwrap_or_else(|_| "http://127.0.0.1:5010".into());
    let key = std::env::var("TET_API_KEY")?;
    let wallet = std::env::var("TET_WORKER_WALLET")?;
    let (worker_sk, _) = x25519_static_from_env()?;

    #[derive(serde::Deserialize)]
    struct NextJob {
        job_id: String,
        client_ephemeral_pub_b64: String,
        nonce_b64: String,
        ciphertext_b64: String,
    }

    loop {
        let url = format!("{}/worker/e2ee/next/{}", base.trim_end_matches('/'), wallet);
        let r = reqwest::Client::new()
            .get(url)
            .header("x-api-key", &key)
            .send()
            .await?;
        if r.status() == reqwest::StatusCode::NO_CONTENT {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            continue;
        }
        if !r.status().is_success() {
            return Err(format!("e2ee next failed: {}", r.text().await.unwrap_or_default()).into());
        }
        let j: NextJob = r.json().await?;

        let client_pk = tet_core::e2ee::decode_x25519_pub_b64(&j.client_ephemeral_pub_b64)?;
        let nonce_raw = base64::engine::general_purpose::STANDARD.decode(j.nonce_b64.as_bytes())?;
        let nonce12: [u8; 12] = nonce_raw.try_into().map_err(|_| "bad nonce")?;
        let ct = base64::engine::general_purpose::STANDARD.decode(j.ciphertext_b64.as_bytes())?;
        let pt = tet_core::e2ee::decrypt_on_worker(&worker_sk, &client_pk, nonce12, &ct)?;

        let result_json = infer_from_task_plain(&pt)?;

        let mut out_nonce = [0u8; 12];
        let mut rng = rand_core::OsRng;
        rng.fill_bytes(&mut out_nonce);
        let out_ct = tet_core::e2ee::encrypt_on_worker(
            &worker_sk,
            &client_pk,
            out_nonce,
            &result_json,
        )?;

        let url = format!("{}/worker/e2ee/complete", base.trim_end_matches('/'));
        let body = serde_json::json!({
            "wallet": wallet,
            "job_id": j.job_id,
            "result_nonce_b64": base64::engine::general_purpose::STANDARD.encode(out_nonce),
            "result_ciphertext_b64": base64::engine::general_purpose::STANDARD.encode(out_ct),
        });
        let rr = reqwest::Client::new()
            .post(url)
            .header("x-api-key", &key)
            .json(&body)
            .send()
            .await?;
        if !rr.status().is_success() {
            return Err(format!(
                "e2ee complete failed: {}",
                rr.text().await.unwrap_or_default()
            )
            .into());
        }
    }
}

async fn cmd_update_poll() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = std::env::var("TET_REST_URL").unwrap_or_else(|_| "http://127.0.0.1:5010".into());
    let key = std::env::var("TET_API_KEY")?;
    let current = std::env::var("TET_WORKER_VERSION_HASH").unwrap_or_default();

    #[derive(serde::Deserialize)]
    struct R {
        version_hash: String,
        sig_b64: String,
        signer_pubkey_hex: String,
        note: String,
    }

    let client = reqwest::Client::new();
    let url = format!("{}/system/update", base.trim_end_matches('/'));
    let r = client.get(url).header("x-api-key", key).send().await?;
    if !r.status().is_success() {
        return Err(format!("update poll failed: {}", r.text().await.unwrap_or_default()).into());
    }
    let j: R = r.json().await?;
    let msg = format!("tet-update-v1|{}", j.version_hash);
    tet_core::quantum_shield::verify_ed25519(&j.signer_pubkey_hex, &j.sig_b64, msg.as_bytes())
        .map_err(|e| format!("bad update signature: {e}"))?;

    if current.trim() != j.version_hash.trim() {
        eprintln!(
            "UPDATE_AVAILABLE version_hash={} note={}",
            j.version_hash, j.note
        );
        eprintln!("Self-update stub: download/apply new version, then restart.");
    } else {
        eprintln!("UPDATE_OK already on version {}", j.version_hash);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut it = std::env::args();
    let _ = it.next();
    match it.next().as_deref() {
        Some("proof") => {
            let model = it.next().unwrap_or_else(|| "tet/poc".into());
            let input = it.next().unwrap_or_default();
            if input.is_empty() {
                return Err("usage: tet-worker proof <model> <input>".into());
            }
            cmd_proof(&model, &input)?;
        }
        Some("heartbeat") => {
            cmd_heartbeat().await?;
        }
        Some("update-poll") => {
            cmd_update_poll().await?;
        }
        Some("x25519-gen") => {
            cmd_x25519_gen().await?;
        }
        Some("e2ee-loop") => {
            cmd_e2ee_loop().await?;
        }
        _ => {
            eprintln!(
                "TET Worker Protocol\n\
                 \n\
                 {} proof <model> <input>\n\
                   env: TET_WORKER_SK_HEX, TET_WORKER_HW_ID\n\
                 \n\
                 {} heartbeat\n\
                   env: TET_REST_URL, TET_API_KEY, TET_WORKER_WALLET, TET_WORKER_SK_HEX, TET_WORKER_HW_ID, TET_WORKER_X25519_SK_B64\n\
                 \n\
                 {} update-poll\n\
                   env: TET_REST_URL, TET_API_KEY, TET_WORKER_VERSION_HASH (optional)\n\
                 \n\
                 {} x25519-gen\n\
                 \n\
                 {} e2ee-loop\n\
                   env: TET_REST_URL, TET_API_KEY, TET_WORKER_WALLET, TET_WORKER_X25519_SK_B64\n",
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "tet-worker".into()),
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "tet-worker".into()),
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "tet-worker".into()),
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "tet-worker".into()),
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "tet-worker".into()),
            );
        }
    }
    Ok(())
}
