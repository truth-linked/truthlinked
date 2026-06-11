use fips204::traits::SerDes;
use std::env;
use truthlinked_core::DualKeypair;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: keyinfo <keys_file>");
        std::process::exit(1);
    }

    let password = env::var("KEY_PASSWORD").ok();
    let keypair =
        DualKeypair::load_with_password(&args[1], password.as_deref()).unwrap_or_else(|e| {
            eprintln!("Failed to load keys: {}", e);
            std::process::exit(1);
        });

    let pk = keypair.dilithium_pk.into_bytes();
    let account_id = truthlinked_core::pq_identity::account_id_from_pubkey(&pk);

    println!("Account ID: {}", hex::encode(account_id));
    println!("Public Key: {}", hex::encode(&pk));
}
