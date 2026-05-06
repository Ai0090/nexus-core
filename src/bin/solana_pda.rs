use clone_solana_sdk::pubkey::Pubkey;

fn main() {
    let program_id: Pubkey = std::env::var("TET_ONCHAIN_PROGRAM_ID")
        .unwrap_or_else(|_| "8fRpiwwjpZPZiiNePhistCfHA2ctCLaxJMSWZRP4C6Bx".to_string())
        .parse()
        .expect("bad program id");
    let worker: Pubkey = std::env::var("TET_ONCHAIN_WORKER_PUBKEY")
        .expect("set TET_ONCHAIN_WORKER_PUBKEY")
        .parse()
        .expect("bad worker pubkey");

    let (record, _rb) = Pubkey::find_program_address(&[b"record", worker.as_ref()], &program_id);
    let (vault, _vb) = Pubkey::find_program_address(&[b"vault", worker.as_ref()], &program_id);

    println!("program_id={}", program_id);
    println!("worker_pubkey={}", worker);
    println!("worker_record_pda={}", record);
    println!("vault_pda={}", vault);
}
