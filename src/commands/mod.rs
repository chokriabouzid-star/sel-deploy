pub mod export;
pub mod history;
pub mod keygen;
pub mod rebuild;
pub mod run;
pub mod timeline;
pub mod verify;

use anyhow::Result;
use sel_deploy::attestation::signer::load_public_key;
use sel_deploy::storage::paths::SelPaths;
use std::fs;

/// Load default.pub plus every archived public key.
pub fn load_all_public_keys(paths: &SelPaths) -> Result<Vec<(String, Vec<u8>)>> {
    let mut keys = Vec::new();
    if paths.public_key.exists() {
        keys.push(load_public_key(&paths.public_key)?);
    }
    if paths.keys_archive.exists() {
        for entry in fs::read_dir(&paths.keys_archive)? {
            let p = entry?.path();
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.ends_with(".pub") {
                match load_public_key(&p) {
                    Ok(k) => keys.push(k),
                    Err(e) => eprintln!("⚠️  Skipping {}: {}", p.display(), e),
                }
            }
        }
    }
    Ok(keys)
}
