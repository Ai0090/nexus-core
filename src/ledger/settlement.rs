use super::*;

impl Ledger {
    /// AI utility settlement: user pays `gross_micro` and the protocol routes value deterministically.
    ///
    /// - **80%** → `worker_wallet`
    /// - **20%** → network fee
    ///   - burn **25% of network fee** (i.e. **5% of total**) → reduces total supply + increases burned
    ///   - remaining **75% of network fee** (i.e. **15% of total**) → `dex:treasury`
    ///
    /// This path is atomic and does **not** use `transfer_with_fee_*` to avoid stacking protocol fees
    /// on top of the explicit DePIN split.
    pub fn settle_ai_utility_payment(
        &self,
        payer_wallet: &str,
        worker_wallet: &str,
        gross_micro: u64,
        burn_wallet: &str,
    ) -> Result<(u64, u64, u64), LedgerError> {
        let payer = payer_wallet.trim();
        let worker = worker_wallet.trim();
        let burn = burn_wallet.trim();
        if payer.is_empty() || worker.is_empty() || burn.is_empty() {
            return Err(LedgerError::Invalid("wallet ids required".into()));
        }
        if gross_micro == 0 || gross_micro > MAX_SUPPLY_MICRO {
            return Err(LedgerError::Invalid("invalid gross amount".into()));
        }
        if payer == worker {
            return Err(LedgerError::Invalid("payer and worker must differ".into()));
        }

        let fee_bps = NETWORK_FEE_BPS;
        let fee_micro = gross_micro.saturating_mul(fee_bps) / 10_000;
        let worker_micro = gross_micro.saturating_sub(fee_micro);
        // Burn 25% of network fee (5% of total).
        let burn_micro = fee_micro.saturating_mul(BURN_FRACTION_OF_NETWORK_FEE_BPS) / 10_000;
        let treasury_micro = fee_micro.saturating_sub(burn_micro);

        let payer_k = payer.as_bytes().to_vec();
        let worker_k = worker.as_bytes().to_vec();
        let burn_k = burn.as_bytes().to_vec();
        let treasury_k = WALLET_DEX_TREASURY.as_bytes().to_vec();

        let res: Result<(), TransactionError<sled::Error>> = (&self.meta, &self.balances).transaction(|(m, b)| {
            let total = m
                .get(META_TOTAL_SUPPLY)?
                .as_deref()
                .map(|v| self.decrypt_value(v))
                .transpose()?
                .as_deref()
                .map(bytes_to_u64)
                .unwrap_or(0);

            // Ensure payer has enough (spendable checks happen at a higher layer; this is the raw ledger balance).
            let payer_cur = b
                .get(&payer_k)?
                .as_deref()
                .map(|v| self.decrypt_value(v))
                .transpose()?
                .as_deref()
                .map(bytes_to_u64)
                .unwrap_or(0);
            if payer_cur < gross_micro {
                return Err(ConflictableTransactionError::Abort(sled::Error::Unsupported(
                    "insufficient_funds".into(),
                )));
            }

            // Debit payer.
            b.insert(
                payer_k.clone(),
                self.encrypt_value(&u64_to_bytes(payer_cur.saturating_sub(gross_micro)))?,
            )?;

            // Credit worker (80%).
            let w_cur = b
                .get(&worker_k)?
                .as_deref()
                .map(|v| self.decrypt_value(v))
                .transpose()?
                .as_deref()
                .map(bytes_to_u64)
                .unwrap_or(0);
            b.insert(
                worker_k.clone(),
                self.encrypt_value(&u64_to_bytes(w_cur.saturating_add(worker_micro)))?,
            )?;

            // Credit treasury (15%).
            if treasury_micro > 0 {
                let t_cur = b
                    .get(&treasury_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    treasury_k.clone(),
                    self.encrypt_value(&u64_to_bytes(t_cur.saturating_add(treasury_micro)))?,
                )?;

                // Track founder revenue into fee_total as well (useful aggregate).
                let fee_total = m
                    .get(META_FEE_TOTAL)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    META_FEE_TOTAL,
                    self.encrypt_value(&u64_to_bytes(fee_total.saturating_add(treasury_micro)))?,
                )?;
            }

            // Burn (5%): credit burn wallet (optional sink accounting) and reduce total supply.
            if burn_micro > 0 {
                let b_cur = b
                    .get(&burn_k)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                b.insert(
                    burn_k.clone(),
                    self.encrypt_value(&u64_to_bytes(b_cur.saturating_add(burn_micro)))?,
                )?;

                let burned = m
                    .get(META_TOTAL_BURNED)?
                    .as_deref()
                    .map(|v| self.decrypt_value(v))
                    .transpose()?
                    .as_deref()
                    .map(bytes_to_u64)
                    .unwrap_or(0);
                m.insert(
                    META_TOTAL_BURNED,
                    self.encrypt_value(&u64_to_bytes(burned.saturating_add(burn_micro)))?,
                )?;

                // Reduce total supply.
                m.insert(
                    META_TOTAL_SUPPLY,
                    self.encrypt_value(&u64_to_bytes(total.saturating_sub(burn_micro)))?,
                )?;
            }

            Ok(())
        });

        res.map_err(|e| match e {
            TransactionError::Abort(e) | TransactionError::Storage(e) => {
                if e.to_string().contains("insufficient_funds") {
                    LedgerError::InsufficientFunds
                } else {
                    LedgerError::Sled(e)
                }
            }
        })?;

        let audit = serde_json::json!({
            "v": 1,
            "action": "ai_utility_settlement_v1",
            "payer_wallet": payer,
            "worker_wallet": worker,
            "treasury_wallet": WALLET_DEX_TREASURY,
            "burn_wallet": burn,
            "gross_micro": gross_micro,
            "worker_micro": worker_micro,
            "network_fee_micro": fee_micro,
            "treasury_micro": treasury_micro,
            "burn_micro": burn_micro,
            "network_fee_bps": fee_bps,
            "burn_fraction_of_network_fee_bps": BURN_FRACTION_OF_NETWORK_FEE_BPS,
        });
        let _ = self.audit_write(&serde_json::to_vec(&audit).unwrap_or_default());
        self.persist_snapshot_best_effort();
        Ok((worker_micro, treasury_micro, burn_micro))
    }
}

