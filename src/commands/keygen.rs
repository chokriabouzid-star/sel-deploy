use anyhow::Result;
use std::fs;

use crate::cli::KeygenArgs;
use sel_deploy::attestation::signer::{load_public_key, AttestationSigner};
use sel_deploy::storage::paths::SelPaths;

pub fn execute(args: KeygenArgs) -> Result<i32> {
    let paths = SelPaths::load()?;
    if paths.private_key.exists() && !args.force {
        eprintln!("⚠️   Key already exists: {}", paths.private_key.display());
        eprintln!("    Use --force to overwrite (the current public key will be archived).");
        return Ok(1);
    }

    if args.force && paths.public_key.exists() {
        match load_public_key(&paths.public_key) {
            Ok((kid, _)) => {
                fs::create_dir_all(&paths.keys_archive)?;
                let dest = paths.keys_archive.join(format!("{kid}.pub"));
                fs::copy(&paths.public_key, &dest)?;
                println!("   Archived previous public key → {}", dest.display());
            }
            Err(e) => {
                eprintln!("⚠️   Could not archive previous public key: {e}");
            }
        }
    }

    let signer = AttestationSigner::generate_and_save(&paths.private_key, &paths.public_key)?;
    println!("✔  Keypair generated");
    println!("   Home    : {}", paths.root.display());
    println!("   Keys    : {}", paths.keys_dir.display());
    println!("   Private : {}", paths.private_key.display());
    println!("   Public  : {}", paths.public_key.display());
    println!("   Key ID  : {}", signer.key_id());
    println!("   Format  : PEM (ED25519 PRIVATE/PUBLIC KEY, 32-byte seed)");
    println!("\n⚠️   Never commit your private key to version control.");
    Ok(0)
}
