#[cfg(test)]
mod tests {
    use super::super::attestation::AttestationReport;
    use super::super::ledger::{Ledger, MAX_SUPPLY_MICRO};
    use proptest::prelude::*;

    // Property: total supply must never exceed hard cap.
    //
    // Keep this bounded so `cargo test` completes deterministically in CI/dev.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 32,
            max_shrink_iters: 0,
            .. ProptestConfig::default()
        })]
        #[test]
        fn hard_cap_never_exceeded(mints in prop::collection::vec(1u64..1_000_000u64, 1..200)) {
            let _g = super::super::test_env::lock();
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("db");
            unsafe { std::env::set_var("TET_FOUNDER_WALLET", "founder"); }
            unsafe { std::env::set_var("TET_REQUIRE_ATTESTATION", "false"); }
            unsafe { std::env::set_var("TET_DB_ENCRYPT", "false"); }
            let ledger = Ledger::open(db.to_str().unwrap()).unwrap();
            ledger.init_genesis_founder_premine_from_env().unwrap();

            for amt in mints {
                let payload = b"energy:dummy";
                let r = ledger.mint_reward_with_proof("peer", amt, payload, None, false);
                // We allow failures once cap is reached, but never allow cap to be exceeded.
                let supply = ledger.total_supply_micro().unwrap();
                prop_assert!(supply <= MAX_SUPPLY_MICRO);
                let _ = r;
            }
        }
    }

    #[test]
    fn founder_fee_is_credited_on_mint_and_transfer() {
        let _g = super::super::test_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db2");
        unsafe {
            std::env::set_var("TET_FOUNDER_WALLET", "founder");
            std::env::set_var("TET_PROTOCOL_FEE_BPS", "100");
            std::env::set_var("TET_DB_ENCRYPT", "false");
            std::env::set_var("TET_REQUIRE_ATTESTATION", "false");
        }
        let ledger = Ledger::open(db.to_str().unwrap()).unwrap();
        ledger.init_genesis_founder_premine_from_env().unwrap();
        ledger.apply_genesis_allocation("founder").unwrap();

        // Fund worker pool so transfers can be tested even when genesis is founder-only.
        ledger
            .mint_reward_with_proof(
                super::super::ledger::WALLET_SYSTEM_WORKER_POOL,
                2_000_000,
                b"energy:test",
                None,
                false,
            )
            .unwrap();

        let founder_before = ledger.balance_micro("founder").unwrap();
        let fee_total_before = ledger.fee_total_micro().unwrap();
        let supply_before = ledger.total_supply_micro().unwrap();
        let burned_before = ledger.total_burned_micro().unwrap();

        ledger
            .transfer_with_fee(
                super::super::ledger::WALLET_SYSTEM_WORKER_POOL,
                "alice",
                1_000_000,
                Some(100),
            )
            .unwrap();
        let fee = 10_000u64;
        let (treasury0, burn0) = Ledger::split_protocol_fee_treasury_and_burn(fee);
        let net = 1_000_000u64 - fee;

        let founder_bal_after_mint = ledger.balance_micro("founder").unwrap();
        assert_eq!(founder_bal_after_mint, founder_before + treasury0);
        assert_eq!(ledger.balance_micro("alice").unwrap(), net);
        assert_eq!(ledger.fee_total_micro().unwrap(), fee_total_before + treasury0);
        assert_eq!(ledger.total_burned_micro().unwrap(), burned_before + burn0);
        assert_eq!(
            ledger.total_supply_micro().unwrap(),
            supply_before.saturating_sub(burn0)
        );

        let founder_before_xfer = ledger.balance_micro("founder").unwrap();
        let supply_mid = ledger.total_supply_micro().unwrap();
        let burned_mid = ledger.total_burned_micro().unwrap();
        let (t_net, t_fee) = ledger
            .transfer_with_fee("alice", "bob", 500_000, Some(100))
            .unwrap();
        assert_eq!(t_fee, 5_000);
        assert_eq!(t_net, 495_000);
        let (treasury1, burn1) = Ledger::split_protocol_fee_treasury_and_burn(t_fee);

        let founder_bal_after_xfer = ledger.balance_micro("founder").unwrap();
        assert_eq!(founder_bal_after_xfer, founder_before_xfer + treasury1);
        assert_eq!(ledger.balance_micro("bob").unwrap(), t_net);
        assert_eq!(
            ledger.total_burned_micro().unwrap(),
            burned_mid.saturating_add(burn1)
        );
        assert_eq!(
            ledger.total_supply_micro().unwrap(),
            supply_mid.saturating_sub(burn1)
        );
    }

    #[test]
    fn attestation_gate_rejects_when_required() {
        let _g = super::super::test_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db3");
        unsafe {
            std::env::set_var("TET_FOUNDER_WALLET", "founder");
            std::env::set_var("TET_PROTOCOL_FEE_BPS", "100");
            std::env::set_var("TET_DB_ENCRYPT", "false");
            std::env::set_var("TET_REQUIRE_ATTESTATION", "true");
        }
        let ledger = Ledger::open(db.to_str().unwrap()).unwrap();
        ledger.init_genesis_founder_premine_from_env().unwrap();

        let r = ledger.mint_reward_with_proof("peer", 100, b"energy:test", None, false);
        assert!(matches!(
            r,
            Err(super::super::ledger::LedgerError::AttestationRequired)
        ));

        let dummy = AttestationReport {
            v: 1,
            platform: "test".into(),
            report_b64: "dGVzdA==".into(),
        };
        let r2 = ledger.mint_reward_with_proof("peer", 100, b"energy:test", Some(&dummy), false);
        assert!(r2.is_ok());
    }
}
