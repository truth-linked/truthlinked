use clap::Parser;
use fips204::traits::SerDes;
/// Raw tx spammer — pre-signs N batch-transfer txs then fires them concurrently.
/// Usage: spammer --keys validator1_keys.json --rpc http://localhost:19944 --count 500 --workers 20
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use truthlinked_core::pq_execution::{BatchTransferEntry, Transaction, TransactionIntent};
use truthlinked_core::pq_identity::{account_id_from_pubkey, DualKeypair};
use truthlinked_core::ONE_TLKD;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    keys: String,
    #[arg(long, default_value = "http://localhost:19944")]
    rpc: String,
    #[arg(long, default_value = "200")]
    count: usize,
    #[arg(long, default_value = "20")]
    workers: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = reqwest::Client::new();

    // Fetch chain info once
    let info: serde_json::Value = client
        .get(format!("{}/chain_info", args.rpc))
        .send()
        .await?
        .json()
        .await?;
    let genesis_hex = info["genesis_hash"].as_str().unwrap();
    let mut genesis_fingerprint = [0u8; 32];
    hex::decode_to_slice(genesis_hex, &mut genesis_fingerprint)?;

    // Load keypair
    let keypair = DualKeypair::load(&args.keys).map_err(|e| anyhow::anyhow!(e))?;
    let pubkey = keypair.dilithium_pk.clone().into_bytes().to_vec();
    let sender = account_id_from_pubkey(&pubkey);

    // Fetch nonce once
    let acc: serde_json::Value = client
        .get(format!("{}/account/{}", args.rpc, hex::encode(sender)))
        .send()
        .await?
        .json()
        .await?;
    let base_nonce = acc.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);

    // Use local validator accounts as known-good recipients. Include pubkeys so the
    // transfer remains valid even if a recipient account has not been materialized yet.
    let mut transfers: Vec<BatchTransferEntry> = Vec::new();
    for path in [
        "validator1_keys.json",
        "validator2_keys.json",
        "validator3_keys.json",
        "validator4_keys.json",
        "validator5_keys.json",
    ] {
        if let Ok(recipient_keys) = DualKeypair::load(path) {
            let recipient_pubkey = recipient_keys.dilithium_pk.clone().into_bytes().to_vec();
            transfers.push(BatchTransferEntry {
                recipient: account_id_from_pubkey(&recipient_pubkey),
                recipient_pubkey: Some(recipient_pubkey),
                amount: ONE_TLKD / 10,
            });
        }
    }
    if transfers.is_empty() {
        transfers.push(BatchTransferEntry {
            recipient: sender,
            recipient_pubkey: Some(pubkey.clone()),
            amount: ONE_TLKD / 10,
        });
    }

    // Pre-sign all txs
    println!("Pre-signing {} txs...", args.count);
    let t0 = Instant::now();
    let mut signed_txs: Vec<Vec<u8>> = Vec::with_capacity(args.count);
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    for i in 0..args.count {
        let tx = Transaction {
            sender,
            nonce: base_nonce + 1 + i as u64,
            timestamp,
            genesis_fingerprint,
            expiration_height: u64::MAX,
            signature: vec![],
            intent: TransactionIntent::BatchTransfer {
                transfers: transfers.clone(),
            },
        };
        let signed = keypair
            .sign_transaction(&tx)
            .map_err(|e| anyhow::anyhow!(e))?;
        signed_txs.push(postcard::to_allocvec(&signed)?);
    }
    println!(
        "Signed {} txs in {:.1}ms",
        args.count,
        t0.elapsed().as_secs_f64() * 1000.0
    );

    // Fire concurrently
    let client = Arc::new(client);
    let rpc = Arc::new(args.rpc.clone());
    let txs = Arc::new(signed_txs);
    let chunk = (args.count + args.workers - 1) / args.workers;

    println!("Firing {} txs with {} workers...", args.count, args.workers);
    let t1 = Instant::now();

    let mut handles = vec![];
    for w in 0..args.workers {
        let client = Arc::clone(&client);
        let rpc = Arc::clone(&rpc);
        let txs = Arc::clone(&txs);
        let start = w * chunk;
        let end = ((w + 1) * chunk).min(args.count);
        handles.push(tokio::spawn(async move {
            let mut ok = 0usize;
            for i in start..end {
                let res = client
                    .post(format!("{}/submit_raw", rpc))
                    .body(txs[i].clone())
                    .send()
                    .await;
                match res {
                    Ok(r) => {
                        let status = r.status();
                        let body = r.text().await.unwrap_or_default();
                        let accepted = status.is_success()
                            && serde_json::from_str::<serde_json::Value>(&body)
                                .ok()
                                .and_then(|v| v.get("success").and_then(|s| s.as_bool()))
                                .unwrap_or(false);
                        if accepted {
                            ok += 1;
                        } else if i < start + 3 {
                            eprintln!("submit failed: HTTP {} {}", status, body);
                        }
                    }
                    Err(e) => {
                        if i < start + 3 {
                            eprintln!("submit failed: {}", e);
                        }
                    }
                }
            }
            ok
        }));
    }

    let mut total_ok = 0;
    for h in handles {
        total_ok += h.await?;
    }

    let elapsed = t1.elapsed();
    println!(
        "Submitted {}/{} txs in {:.2}s = {:.1} submit TPS",
        total_ok,
        args.count,
        elapsed.as_secs_f64(),
        total_ok as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}
