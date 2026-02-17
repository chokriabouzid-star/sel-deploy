use anyhow::{Result, Context};
use std::{fs, path::Path};
use crate::attestation::{model::DeploymentAttestation, signer::verify_sig};

/// Verify hash integrity + Ed25519 signature of one attestation
pub fn verify_attestation(a: &DeploymentAttestation, pubkey: &[u8]) -> Result<()> {
    // 1. Recompute hash and compare
    let expected = a.compute_hash().context("Cannot compute hash")?;
    anyhow::ensure!(
        expected == a.attestation_hash,
        "Hash mismatch — attestation tampered.\n  Expected: {}\n  Got:      {}",
        &expected[..32], &a.attestation_hash[..32.min(a.attestation_hash.len())]
    );

    // 2. Verify signature
    let payload = a.canonical_payload().context("Cannot build payload")?;
    verify_sig(&payload, &a.signature, pubkey).context("Signature invalid")
}

/// Load and verify one attestation from a JSON file
pub fn verify_file(path: &Path, pubkey: &[u8]) -> Result<DeploymentAttestation> {
    let txt = fs::read_to_string(path)
        .with_context(|| format!("Cannot read {}", path.display()))?;
    let a: DeploymentAttestation = serde_json::from_str(&txt)
        .context("Invalid attestation JSON")?;
    verify_attestation(&a, pubkey)?;
    Ok(a)
}
