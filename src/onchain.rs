use clone_solana_rpc_client::rpc_client::RpcClient;
use clone_solana_sdk::commitment_config::CommitmentConfig;
use clone_solana_sdk::instruction::AccountMeta;
use clone_solana_sdk::instruction::Instruction;
use clone_solana_sdk::signature::{Keypair, Signer, read_keypair_file};
use clone_solana_sdk::system_program;
use clone_solana_sdk::transaction::Transaction;
use sha2::Digest as _;

pub const LOCALNET_RPC: &str = "http://127.0.0.1:8899";

pub fn load_worker_keypair_from_env() -> anyhow::Result<Keypair> {
    let p = std::env::var("TET_SOLANA_KEYPAIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            format!("{home}/.config/solana/id.json")
        });
    read_keypair_file(p).map_err(|e| anyhow::anyhow!(e.to_string()))
}

pub fn register_and_stake(
    worker_keypair: &Keypair,
    program_id: &clone_solana_sdk::pubkey::Pubkey,
    stake_amount: u64,
) -> anyhow::Result<()> {
    let rpc =
        RpcClient::new_with_commitment(LOCALNET_RPC.to_string(), CommitmentConfig::confirmed());

    let (worker_record, _record_bump) = clone_solana_sdk::pubkey::Pubkey::find_program_address(
        &[b"record", worker_keypair.pubkey().as_ref()],
        program_id,
    );
    let (vault, _vault_bump) = clone_solana_sdk::pubkey::Pubkey::find_program_address(
        &[b"vault", worker_keypair.pubkey().as_ref()],
        program_id,
    );

    // Anchor instruction format:
    // - data = 8-byte discriminator (sha256("global:register_worker")[..8]) + borsh(u64 stake_amount)
    let mut h = sha2::Sha256::new();
    h.update(b"global:register_worker");
    let hash = h.finalize();
    let mut data = Vec::with_capacity(8 + 8);
    data.extend_from_slice(&hash[..8]);
    data.extend_from_slice(&stake_amount.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(worker_keypair.pubkey(), true),
        AccountMeta::new(worker_record, false),
        AccountMeta::new(vault, false),
        AccountMeta::new_readonly(system_program::ID, false),
    ];

    let ix = Instruction {
        program_id: *program_id,
        accounts,
        data,
    };

    let bh = rpc.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&worker_keypair.pubkey()),
        &[worker_keypair],
        bh,
    );

    let sig = rpc.send_and_confirm_transaction(&tx)?;
    eprintln!(
        "[onchain] register_worker ok program_id={} worker={} stake_lamports={} sig={}",
        program_id,
        worker_keypair.pubkey(),
        stake_amount,
        sig
    );
    Ok(())
}

pub fn default_program_id() -> anyhow::Result<clone_solana_sdk::pubkey::Pubkey> {
    // Local dev default (Phase 3.2 deploy).
    Ok("8fRpiwwjpZPZiiNePhistCfHA2ctCLaxJMSWZRP4C6Bx".parse()?)
}

pub fn slash_bad_worker(
    admin_keypair: &Keypair,
    worker_pubkey: &clone_solana_sdk::pubkey::Pubkey,
    program_id: &clone_solana_sdk::pubkey::Pubkey,
    treasury: &clone_solana_sdk::pubkey::Pubkey,
) -> anyhow::Result<()> {
    let rpc =
        RpcClient::new_with_commitment(LOCALNET_RPC.to_string(), CommitmentConfig::confirmed());

    let (worker_record, _record_bump) = clone_solana_sdk::pubkey::Pubkey::find_program_address(
        &[b"record", worker_pubkey.as_ref()],
        program_id,
    );
    let (vault, _vault_bump) = clone_solana_sdk::pubkey::Pubkey::find_program_address(
        &[b"vault", worker_pubkey.as_ref()],
        program_id,
    );

    // data = discriminator only (sha256("global:slash_worker")[..8])
    let mut h = sha2::Sha256::new();
    h.update(b"global:slash_worker");
    let hash = h.finalize();
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&hash[..8]);

    let accounts = vec![
        AccountMeta::new(admin_keypair.pubkey(), true),
        AccountMeta::new_readonly(*worker_pubkey, false),
        AccountMeta::new(worker_record, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(*treasury, false),
        AccountMeta::new_readonly(system_program::ID, false),
    ];

    let ix = Instruction {
        program_id: *program_id,
        accounts,
        data,
    };

    let bh = rpc.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&admin_keypair.pubkey()),
        &[admin_keypair],
        bh,
    );

    let sig = rpc.send_and_confirm_transaction(&tx)?;
    eprintln!(
        "[onchain] slash_worker ok program_id={} admin={} worker={} treasury={} sig={}",
        program_id,
        admin_keypair.pubkey(),
        worker_pubkey,
        treasury,
        sig
    );
    Ok(())
}

pub fn maybe_register_worker_before_p2p() -> anyhow::Result<()> {
    let enabled = std::env::var("TET_ONCHAIN_STAKE")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        return Ok(());
    }

    let is_worker = std::env::var("TET_IS_WORKER")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !is_worker {
        return Ok(());
    }

    let program_id: clone_solana_sdk::pubkey::Pubkey = std::env::var("TET_ONCHAIN_PROGRAM_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(default_program_id()?);

    let stake_amount = std::env::var("TET_ONCHAIN_STAKE_LAMPORTS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(1_000_000_000);

    let kp = load_worker_keypair_from_env()?;
    eprintln!(
        "[onchain] registering worker before P2P program_id={} stake_lamports={} solana_keypair_pubkey={}",
        program_id,
        stake_amount,
        kp.pubkey()
    );
    register_and_stake(&kp, &program_id, stake_amount)?;
    Ok(())
}
