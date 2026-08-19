use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::attestation::model::DeploymentAttestation;
use crate::attestation::signer::verify_sig;
use crate::util::prefix;

/// Verify hash integrity + Ed25519 signature of one attestation against one key.
pub fn verify_attestation(a: &DeploymentAttestation, pubkey: &[u8]) -> Result<()> {
    verify_hash(a)?;
    let payload = a.canonical_payload().context("Cannot build payload")?;
    verify_sig(&payload, &a.signature, pubkey).context("Signature invalid")
}

/// Verify using the key whose `key_id` matches, falling back to every provided key.
pub fn verify_attestation_with_keys(
    a: &DeploymentAttestation,
    keys: &[(String, Vec<u8>)],
) -> Result<()> {
    verify_hash(a)?;
    let payload = a.canonical_payload().context("Cannot build payload")?;

    if let Some((_, pk)) = keys.iter().find(|(id, _)| id == &a.signer.key_id) {
        return verify_sig(&payload, &a.signature, pk)
            .with_context(|| format!("Signature invalid for key_id {}", a.signer.key_id));
    }

    for (id, pk) in keys {
        if verify_sig(&payload, &a.signature, pk).is_ok() {
            return Ok(());
        }
        let _ = id;
    }

    if keys.is_empty() {
        bail!("No public keys available. Run 'sel-deploy keygen' first.");
    }
    bail!(
        "No matching public key for key_id {} ({} key(s) loaded, including archive)",
        a.signer.key_id,
        keys.len()
    );
}

fn verify_hash(a: &DeploymentAttestation) -> Result<()> {
    let expected = a.compute_hash().context("Cannot compute hash")?;
    anyhow::ensure!(
        expected == a.attestation_hash,
        "Hash mismatch — attestation tampered.\n  Expected: {}\n  Got:      {}",
        prefix(&expected, 32),
        prefix(&a.attestation_hash, 32)
    );
    Ok(())
}

/// Load and verify one attestation from a JSON file against one key.
pub fn verify_file(path: &Path, pubkey: &[u8]) -> Result<DeploymentAttestation> {
    let a = load_attestation(path)?;
    verify_attestation(&a, pubkey)?;
    Ok(a)
}

/// Load and verify one attestation trying every known public key.
pub fn verify_file_with_keys(
    path: &Path,
    keys: &[(String, Vec<u8>)],
) -> Result<DeploymentAttestation> {
    let a = load_attestation(path)?;
    verify_attestation_with_keys(&a, keys)?;
    Ok(a)
}

pub fn load_attestation(path: &Path) -> Result<DeploymentAttestation> {
    let txt =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))?;
    serde_json::from_str(&txt).context("Invalid attestation JSON")
}
