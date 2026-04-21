use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use tet_core::protocol::{AttestationV1, HybridSigV1, SignedTxEnvelopeV1, TxV1};

const STEVEMON: f64 = 100_000_000.0;

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use rand_core::OsRng;
    use rand_core::RngCore as _;
    use security_framework::access_control::SecAccessControl;
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
    };
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
    use security_framework::passwords::{generic_password, set_generic_password_options};
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroize as _;
    use zeroize::Zeroizing;

    fn svc() -> &'static str {
        "tet-signer"
    }

    fn ensure_secret(
        service: &str,
        account: &str,
        len: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if load_secret(service, account).is_ok() {
            return Ok(());
        }
        let mut opt = PasswordOptions::new_generic_password(service, account);
        opt.use_protected_keychain();
        opt.set_access_control_options(AccessControlOptions::BIOMETRY_CURRENT_SET);
        let mut v = vec![0u8; len];
        OsRng.fill_bytes(&mut v);
        set_generic_password_options(&v, opt)?;
        v.zeroize();
        Ok(())
    }

    fn load_secret(
        service: &str,
        account: &str,
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut opt = PasswordOptions::new_generic_password(service, account);
        opt.use_protected_keychain();
        let v = generic_password(opt)?;
        Ok(Zeroizing::new(v))
    }

    fn ensure_se_attest_key() -> Result<(), Box<dyn std::error::Error>> {
        if find_se_attest_key().is_ok() {
            return Ok(());
        }
        let ac = SecAccessControl::create_with_flags(
            (security_framework_sys::access_control::kSecAccessControlBiometryCurrentSet
                | security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage)
                as _,
        )?;
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_label("tet-se-attest")
            .set_access_control(ac);
        let _ = SecKey::new(&opts)?;
        Ok(())
    }

    fn find_se_attest_key() -> Result<SecKey, Box<dyn std::error::Error>> {
        let mut s = ItemSearchOptions::new();
        s.class(ItemClass::key());
        s.key_class(KeyClass::private());
        s.label("tet-se-attest");
        s.load_refs(true);
        let r = s.search()?;
        for it in r {
            if let SearchResult::Ref(Reference::Key(k)) = it {
                return Ok(k);
            }
        }
        Err("secure enclave attestation key not found".into())
    }

    fn spki_from_x963_uncompressed(x963: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if x963.len() != 65 || x963[0] != 0x04 {
            return Err("unexpected P-256 public key format".into());
        }
        let mut spki = Vec::with_capacity(26 + 65);
        spki.extend_from_slice(&[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ]);
        spki.extend_from_slice(x963);
        Ok(spki)
    }

    pub fn build_envelope_macos(
        tx: TxV1,
    ) -> Result<SignedTxEnvelopeV1, Box<dyn std::error::Error>> {
        ensure_secret(svc(), "ed25519_sk", 32)?;
        let ed = load_secret(svc(), "ed25519_sk")?;
        let ed32: [u8; 32] = ed
            .as_slice()
            .try_into()
            .map_err(|_| "invalid ed25519 key")?;
        let signing = SigningKey::from_bytes(&ed32);
        let default_wallet_id = hex::encode(signing.verifying_key().to_bytes());

        let tx = match tx {
            TxV1::SignerLink { wallet_id } if wallet_id == "auto" => TxV1::SignerLink {
                wallet_id: default_wallet_id.clone(),
            },
            TxV1::FoundingMemberEnroll { member_wallet } if member_wallet == "auto" => {
                TxV1::FoundingMemberEnroll {
                    member_wallet: default_wallet_id.clone(),
                }
            }
            TxV1::Transfer {
                from_wallet,
                to_wallet,
                amount_micro,
                fee_bps,
            } if from_wallet == "auto" => TxV1::Transfer {
                from_wallet: default_wallet_id.clone(),
                to_wallet,
                amount_micro,
                fee_bps,
            },
            other => other,
        };

        if load_secret(svc(), "mldsa44_sk").is_err() {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            let kp = dilithium::MlDsaKeyPair::generate_deterministic(dilithium::ML_DSA_44, &seed);
            let mut opt = PasswordOptions::new_generic_password(svc(), "mldsa44_sk");
            opt.use_protected_keychain();
            opt.set_access_control_options(AccessControlOptions::BIOMETRY_CURRENT_SET);
            security_framework::passwords::set_generic_password_options(kp.private_key(), opt)?;
            let mut opt2 = PasswordOptions::new_generic_password(svc(), "mldsa44_pk");
            opt2.use_protected_keychain();
            opt2.set_access_control_options(AccessControlOptions::BIOMETRY_CURRENT_SET);
            security_framework::passwords::set_generic_password_options(kp.public_key(), opt2)?;
        }
        let mldsa_sk = load_secret(svc(), "mldsa44_sk")?;
        let mldsa_pk = load_secret(svc(), "mldsa44_pk")?;

        let tx_bytes = serde_json::to_vec(&tx)?;
        let ed_sig = signing.sign(&tx_bytes);
        let ed_b64 = base64::engine::general_purpose::STANDARD.encode(ed_sig.to_bytes());

        let kp = dilithium::MlDsaKeyPair::from_keys(
            mldsa_sk.as_slice(),
            mldsa_pk.as_slice(),
            dilithium::ML_DSA_44,
        )
        .map_err(|_| "invalid mldsa44 key bytes")?;
        let sig = tet_core::wallet::mldsa44_sign_deterministic(&kp, &tx_bytes)
            .map_err(|_| "mldsa44 signing failed")?;
        let mldsa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
        let mldsa_pk_b64 = base64::engine::general_purpose::STANDARD.encode(mldsa_pk.as_slice());

        ensure_se_attest_key()?;
        let se = find_se_attest_key()?;
        let pubk = se.public_key().ok_or("secure enclave public key missing")?;
        let x963 = pubk
            .external_representation()
            .ok_or("secure enclave public key export failed")?
            .to_vec();
        let spki = spki_from_x963_uncompressed(&x963)?;

        let digest = Sha256::digest(&tx_bytes);
        let sig_der =
            se.create_signature(Algorithm::ECDSASignatureDigestX962SHA256, digest.as_slice())?;

        let report_payload = serde_json::json!({
            "v": 1,
            "pubkey_spki_der_b64": base64::engine::general_purpose::STANDARD.encode(&spki),
            "sig_der_b64": base64::engine::general_purpose::STANDARD.encode(&sig_der),
        });
        let report_b64 =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&report_payload)?);

        Ok(SignedTxEnvelopeV1 {
            v: 1,
            tx,
            sig: HybridSigV1 {
                ed25519_pubkey_hex: default_wallet_id,
                ed25519_sig_b64: ed_b64,
                mldsa_pubkey_b64: mldsa_pk_b64,
                mldsa_sig_b64: mldsa_sig_b64,
            },
            attestation: AttestationV1 {
                platform: "macos-se".into(),
                report_b64,
            },
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    match cmd.as_str() {
        "serve" => {
            let bind = opt_arg(&mut args, "--bind").unwrap_or_else(|| "127.0.0.1:5791".into());
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async move { serve_signer(&bind).await })?;
            Ok(())
        }
        "link" => {
            let wallet_id = opt_arg(&mut args, "--wallet-id").unwrap_or_else(|| "auto".into());
            let tx = TxV1::SignerLink { wallet_id };
            let env = build_envelope(tx)?;
            println!("{}", serde_json::to_string_pretty(&env)?);
            Ok(())
        }
        "founding-enroll" => {
            let member_wallet =
                opt_arg(&mut args, "--member-wallet").unwrap_or_else(|| "auto".into());
            let tx = TxV1::FoundingMemberEnroll { member_wallet };
            let env = build_envelope(tx)?;
            println!("{}", serde_json::to_string_pretty(&env)?);
            Ok(())
        }
        "transfer" => {
            let to = need_arg(&mut args, "--to")?;
            let amount_tet = need_arg(&mut args, "--amount-tet")?.parse::<f64>()?;
            let fee_bps = opt_arg(&mut args, "--fee-bps")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(50);
            let from_wallet = need_arg(&mut args, "--from-wallet")?;
            let amount_micro = (amount_tet * STEVEMON).round().max(0.0) as u64;
            let tx = TxV1::Transfer {
                from_wallet: from_wallet.clone(),
                to_wallet: to,
                amount_micro,
                fee_bps,
            };
            let env = build_envelope(tx)?;
            println!("{}", serde_json::to_string_pretty(&env)?);
            Ok(())
        }
        "genesis-bridge" => {
            let to = need_arg(&mut args, "--to")?;
            let amount_tet = need_arg(&mut args, "--amount-tet")?.parse::<f64>()?;
            let from_wallet = need_arg(&mut args, "--from-wallet")?;
            let amount_micro = (amount_tet * STEVEMON).round().max(0.0) as u64;
            let tx = TxV1::GenesisBridge {
                founder_wallet: from_wallet.clone(),
                to_wallet: to,
                amount_micro,
            };
            let env = build_envelope(tx)?;
            println!("{}", serde_json::to_string_pretty(&env)?);
            Ok(())
        }
        "help" | "--help" | "-h" => {
            eprintln!(
                "TET-Signer (native signing helper)\n\n\
Commands:\n\
  serve [--bind 127.0.0.1:5791]\n\
  link [--wallet-id <string|auto>]\n\
  founding-enroll [--member-wallet <hex|auto>]\n\
  transfer --from-wallet <hex> --to <hex> --amount-tet <f64> [--fee-bps <u64>]\n\
  genesis-bridge --from-wallet <hex> --to <hex> --amount-tet <f64>\n\n\
This tool prints a SignedTxEnvelope v1 JSON.\n"
            );
            Ok(())
        }
        _ => {
            eprintln!("Unknown command. Use `TET-Signer help`.");
            Ok(())
        }
    }
}

#[derive(serde::Deserialize)]
struct TransferEnvReq {
    to_wallet: String,
    amount_micro: u64,
    fee_bps: u64,
}

async fn serve_signer(bind: &str) -> Result<(), Box<dyn std::error::Error>> {
    use axum::http::StatusCode;
    use axum::{Json, Router, routing::post};

    async fn env_founding() -> (StatusCode, Json<SignedTxEnvelopeV1>) {
        let tx = TxV1::FoundingMemberEnroll {
            member_wallet: "auto".into(),
        };
        match build_envelope(tx) {
            Ok(env) => (StatusCode::OK, Json(env)),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SignedTxEnvelopeV1 {
                    v: 1,
                    tx: TxV1::SignerLink {
                        wallet_id: "error".into(),
                    },
                    sig: HybridSigV1 {
                        ed25519_pubkey_hex: "".into(),
                        ed25519_sig_b64: "".into(),
                        mldsa_pubkey_b64: "".into(),
                        mldsa_sig_b64: "".into(),
                    },
                    attestation: AttestationV1 {
                        platform: "".into(),
                        report_b64: "".into(),
                    },
                }),
            ),
        }
    }

    async fn env_transfer(
        Json(req): Json<TransferEnvReq>,
    ) -> (StatusCode, Json<SignedTxEnvelopeV1>) {
        let tx = TxV1::Transfer {
            from_wallet: "auto".into(),
            to_wallet: req.to_wallet,
            amount_micro: req.amount_micro,
            fee_bps: req.fee_bps,
        };
        match build_envelope(tx) {
            Ok(env) => (StatusCode::OK, Json(env)),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SignedTxEnvelopeV1 {
                    v: 1,
                    tx: TxV1::SignerLink {
                        wallet_id: "error".into(),
                    },
                    sig: HybridSigV1 {
                        ed25519_pubkey_hex: "".into(),
                        ed25519_sig_b64: "".into(),
                        mldsa_pubkey_b64: "".into(),
                        mldsa_sig_b64: "".into(),
                    },
                    attestation: AttestationV1 {
                        platform: "".into(),
                        report_b64: "".into(),
                    },
                }),
            ),
        }
    }

    let app = Router::new()
        .route("/envelope/founding-enroll", post(env_founding))
        .route("/envelope/transfer", post(env_transfer));

    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn need_arg(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    while let Some(a) = args.next() {
        if a == name {
            return args
                .next()
                .ok_or_else(|| format!("missing value for {name}"));
        }
    }
    Err(format!("missing {name}"))
}

fn opt_arg(args: &mut impl Iterator<Item = String>, name: &str) -> Option<String> {
    let mut buf = Vec::new();
    buf.extend(args.by_ref());
    let mut it = buf.into_iter();
    let mut out = None;
    let mut rest = Vec::new();
    while let Some(a) = it.next() {
        if a == name {
            out = it.next();
            break;
        }
        rest.push(a);
    }
    let _ = rest;
    out
}

fn build_envelope(tx: TxV1) -> Result<SignedTxEnvelopeV1, Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        macos::build_envelope_macos(tx)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("hardware enclave signing is not implemented on this OS yet".into())
    }
}
