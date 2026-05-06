use anyhow::{Context as _, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer, read_keypair_file};
use solana_sdk::transaction::Transaction;
use std::str::FromStr as _;
use std::sync::Arc;

use spl_associated_token_account::get_associated_token_address;
use spl_associated_token_account::instruction::create_associated_token_account;
use spl_token::instruction as spl_token_ix;

pub const TET_MINT_ADDRESS: &str = "2WZmTHKZgo5VMKzDnWGpmD28PkjQHYzR2vTS64n76jkU";
pub const REWARD_PER_INFERENCE_TET: u64 = 10;
const MICRO_TET_PER_TET: u64 = 1_000_000_000; // decimals=9

#[derive(Clone)]
pub struct NexusSolanaClient {
    rpc: Arc<RpcClient>,
}

impl NexusSolanaClient {
    pub fn devnet() -> Self {
        let rpc = RpcClient::new_with_commitment(
            "http://127.0.0.1:8899".to_string(),
            CommitmentConfig::confirmed(),
        );
        Self { rpc: Arc::new(rpc) }
    }

    pub fn get_balance(&self, pubkey: &Pubkey) -> Result<u64> {
        self.rpc
            .get_balance(pubkey)
            .context("solana get_balance failed")
    }

    pub fn request_airdrop(&self, pubkey: &Pubkey, lamports: u64) -> Result<String> {
        let sig = self
            .rpc
            .request_airdrop(pubkey, lamports)
            .with_context(|| {
                format!("solana request_airdrop failed pubkey={pubkey} lamports={lamports}")
            })?;
        Ok(sig.to_string())
    }

    fn tet_mint_pubkey() -> Result<Pubkey> {
        Pubkey::from_str(TET_MINT_ADDRESS).context("invalid TET_MINT_ADDRESS")
    }

    pub fn tet_ata(&self, wallet_pubkey: &Pubkey) -> Result<Pubkey> {
        let mint = Self::tet_mint_pubkey()?;
        Ok(get_associated_token_address(wallet_pubkey, &mint))
    }

    pub fn get_tet_balance(&self, wallet_pubkey: &Pubkey) -> Result<u64> {
        let ata = self.tet_ata(wallet_pubkey)?;
        match self.rpc.get_token_account_balance(&ata) {
            Ok(v) => Ok(v.amount.parse::<u64>().unwrap_or(0)),
            Err(e) => {
                // If the ATA doesn't exist yet, balance is zero.
                let s = e.to_string();
                if s.contains("could not find account")
                    || s.contains("AccountNotFound")
                    || s.contains("Invalid param")
                {
                    Ok(0)
                } else {
                    Err(anyhow::anyhow!(e)).context("solana get_token_account_balance failed")
                }
            }
        }
    }

    fn founder_keypair() -> Result<Keypair> {
        let home = std::env::var("HOME").context("HOME not set")?;
        let path = format!("{home}/.config/solana/founder.json");
        read_keypair_file(&path)
            .map_err(|e| anyhow::anyhow!("failed to read founder keypair at {path}: {e}"))
    }

    pub fn founder_pubkey(&self) -> Result<Pubkey> {
        Ok(Self::founder_keypair()?.pubkey())
    }

    pub fn faucet_tet(&self, to_wallet: &Pubkey, amount_micro_tet: u64) -> Result<String> {
        let founder = Self::founder_keypair()?;
        let mint = Self::tet_mint_pubkey()?;

        // NOTE: This assumes the founder's ATA already exists (since Steve minted locally).
        // If it doesn't, we create it too for robustness.
        let founder_ata = get_associated_token_address(&founder.pubkey(), &mint);
        let to_ata = get_associated_token_address(to_wallet, &mint);

        let mut ixs = Vec::new();
        if self.rpc.get_account(&founder_ata).is_err() {
            ixs.push(create_associated_token_account(
                &founder.pubkey(),
                &founder.pubkey(),
                &mint,
                &spl_token::id(),
            ));
        }
        if self.rpc.get_account(&to_ata).is_err() {
            ixs.push(create_associated_token_account(
                &founder.pubkey(),
                to_wallet,
                &mint,
                &spl_token::id(),
            ));
        }
        ixs.push(spl_token_ix::transfer_checked(
            &spl_token::id(),
            &founder_ata,
            &mint,
            &to_ata,
            &founder.pubkey(),
            &[],
            amount_micro_tet,
            9, // TET decimals (micro = 1e-9)
        )?);

        let bh = self
            .rpc
            .get_latest_blockhash()
            .context("get_latest_blockhash failed")?;
        let tx = Transaction::new_signed_with_payer(&ixs, Some(&founder.pubkey()), &[&founder], bh);
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .context("send_and_confirm_transaction failed")?;
        Ok(sig.to_string())
    }

    pub fn pay_worker_reward(&self, worker_pubkey: &Pubkey) -> Result<String> {
        let amount_micro = REWARD_PER_INFERENCE_TET.saturating_mul(MICRO_TET_PER_TET);
        self.faucet_tet(worker_pubkey, amount_micro)
            .context("pay_worker_reward failed")
    }
}
