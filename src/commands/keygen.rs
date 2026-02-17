use anyhow::Result;
use crate::{
    cli::KeygenArgs,
    attestation::signer::AttestationSigner,
    storage::paths::SelPaths,
};

pub fn execute(args: KeygenArgs) -> Result<()> {
    let paths = SelPaths::load()?;
    if paths.private_key.exists() && !args.force {
        println!("⚠️   Key already exists: {}", paths.private_key.display());
        println!("    Use --force to overwrite.");
        return Ok(());
    }
    let signer = AttestationSigner::generate_and_save(
        &paths.private_key,
        &paths.public_key,
    )?;
    println!("✔  Keypair generated");
    println!("   Private : {}", paths.private_key.display());
    println!("   Public  : {}", paths.public_key.display());
    println!("   Key ID  : {}", signer.key_id());
    println!("\n⚠️   Never commit your private key to version control.");
    Ok(())
}
