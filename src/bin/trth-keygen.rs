use fips204::traits::SerDes;
use rand::RngCore;
use truthlinked_core::DualKeypair;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyMode {
    Validator,
    Signer,
    Agent,
    Wallet,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: trth-keygen [mode] <output_file> [--encrypt] [--allow-plaintext] [--force]"
        );
        eprintln!("  mode: validator | signer | agent | wallet");
        eprintln!("  --encrypt: Encrypt keys with a password (recommended)");
        eprintln!("  --allow-plaintext: Permit unencrypted keyfile output");
        eprintln!("  --force: Overwrite existing keyfile");
        std::process::exit(1);
    }

    let (mode, output_file) = match args.get(1).map(|s| s.as_str()) {
        Some("validator") => (KeyMode::Validator, args.get(2)),
        Some("signer") => (KeyMode::Signer, args.get(2)),
        Some("agent") => (KeyMode::Agent, args.get(2)),
        Some("wallet") => (KeyMode::Wallet, args.get(2)),
        Some("tls") => {
            eprintln!("Unknown mode: tls");
            eprintln!("Mode must be one of: validator | signer | agent | wallet");
            std::process::exit(1);
        }
        _ => (KeyMode::Validator, args.get(1)),
    };

    let output_file = match output_file {
        Some(p) => p,
        None => {
            eprintln!("Missing output_file.");
            std::process::exit(1);
        }
    };

    let encrypt = args.iter().any(|s| s == "--encrypt");
    let allow_plaintext = args.iter().any(|s| s == "--allow-plaintext");
    let force = args.iter().any(|s| s == "--force");

    if !force && std::path::Path::new(output_file).exists() {
        eprintln!("Refusing to overwrite existing keyfile: {}", output_file);
        eprintln!("Use --force to overwrite.");
        std::process::exit(1);
    }
    if !encrypt && !allow_plaintext {
        eprintln!("Refusing to write unencrypted keys.");
        eprintln!("Use --encrypt (recommended) or --allow-plaintext (unsafe).");
        std::process::exit(1);
    }

    // Generate keypair from random mnemonic
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).expect("Mnemonic generation failed");
    let keypair = DualKeypair::from_mnemonic(mnemonic.to_string());

    match mode {
        KeyMode::Validator => eprintln!("Generated new validator keypair."),
        KeyMode::Signer => eprintln!("Generated new signing keypair."),
        KeyMode::Agent => eprintln!("Generated new agent keypair."),
        KeyMode::Wallet => eprintln!("Generated new wallet keypair."),
    }
    eprintln!("WRITE THIS DOWN. It is shown only once and cannot be recovered.");
    eprintln!("Mnemonic: {}", mnemonic);
    eprintln!();

    let password = if encrypt {
        let pwd = rpassword::prompt_password("Enter password to encrypt keys: ")
            .expect("Password input failed");
        let pwd2 = rpassword::prompt_password("Confirm password: ").expect("Password input failed");

        if pwd != pwd2 {
            eprintln!("Passwords don't match.");
            std::process::exit(1);
        }

        if pwd.len() < 8 {
            eprintln!("Password must be at least 8 characters.");
            std::process::exit(1);
        }

        Some(pwd)
    } else {
        eprintln!("WARNING: writing keys unencrypted.");
        None
    };

    match mode {
        KeyMode::Validator => {
            keypair
                .save_with_password(output_file, password.as_deref())
                .expect("Failed to save keys");
        }
        KeyMode::Signer | KeyMode::Wallet => {
            save_labeled_keyfile(&keypair, output_file, "signer", password.as_deref())
                .expect("Failed to save keys");
        }
        KeyMode::Agent => {
            save_labeled_keyfile(&keypair, output_file, "agent", password.as_deref())
                .expect("Failed to save keys");
        }
    }

    if encrypt {
        println!("Encrypted keys saved: {}", output_file);
    } else {
        println!("Keys saved (unencrypted): {}", output_file);
    }
}

fn save_labeled_keyfile(
    keypair: &DualKeypair,
    output_file: &str,
    key_type: &str,
    password: Option<&str>,
) -> Result<(), String> {
    use std::fs;
    use std::path::Path;

    let data = serde_json::json!({
        "key_type": key_type,
        "mnemonic": keypair.mnemonic,
        "dilithium_public": hex::encode(keypair.dilithium_pk.clone().into_bytes()),
        "dilithium_secret": hex::encode(keypair.dilithium_sk.clone().into_bytes()),
    });

    let json_str = serde_json::to_string_pretty(&data)
        .map_err(|e| format!("Failed to serialize keypair: {}", e))?;

    let final_data = if let Some(pwd) = password {
        let encrypted = encrypt_keyfile(&json_str, pwd)?;
        serde_json::to_string_pretty(&serde_json::json!({
            "encrypted": true,
            "version": 1,
            "data": encrypted,
        }))
        .map_err(|e| format!("Failed to wrap encrypted keypair: {}", e))?
    } else {
        json_str
    };

    let path_ref = Path::new(output_file);
    fs::write(path_ref, final_data).map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path_ref)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path_ref, perms).map_err(|e| e.to_string())?;
    }

    Ok(())
}

fn encrypt_keyfile(plaintext: &str, password: &str) -> Result<String, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Argon2 failed: {}", e))?;

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher init failed: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encrypt failed: {}", e))?;

    let payload = serde_json::json!({
        "salt": hex::encode(salt),
        "nonce": hex::encode(nonce_bytes),
        "ciphertext": hex::encode(ciphertext),
    });

    Ok(payload.to_string())
}
