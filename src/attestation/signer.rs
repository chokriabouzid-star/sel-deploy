use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const PRIV_LABEL: &str = "ED25519 PRIVATE KEY";
const PUB_LABEL: &str = "ED25519 PUBLIC KEY";

pub struct AttestationSigner {
    signing_key: SigningKey,
}

impl AttestationSigner {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|_| crate::error::DeployError::NoKey)?;
        let seed = decode_key_bytes(&bytes, 32).context("Invalid private key file")?;
        let arr: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Private key must be 32 bytes"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&arr),
        })
    }

    pub fn generate_and_save(priv_path: &Path, pub_path: &Path) -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        persist_keypair(&signing_key, priv_path, pub_path)?;
        Ok(Self { signing_key })
    }

    pub fn sign(&self, data: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(data);
        hex::encode(sig.to_bytes())
    }

    pub fn key_id(&self) -> String {
        key_id_from_verifying_bytes(&self.signing_key.verifying_key().to_bytes())
    }

    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }
}

pub fn persist_keypair(signing_key: &SigningKey, priv_path: &Path, pub_path: &Path) -> Result<()> {
    if let Some(p) = priv_path.parent() {
        fs::create_dir_all(p)?;
    }
    if let Some(p) = pub_path.parent() {
        fs::create_dir_all(p)?;
    }

    let priv_pem = encode_pem(PRIV_LABEL, &signing_key.to_bytes());
    let pub_pem = encode_pem(PUB_LABEL, &signing_key.verifying_key().to_bytes());
    fs::write(priv_path, priv_pem)?;
    fs::write(pub_path, pub_pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(priv_path, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(pub_path, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

pub fn key_id_from_verifying_bytes(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hex::encode(&hash[..8])
}

/// Load a public key file (PEM or legacy raw 32 bytes) → (key_id, raw 32).
pub fn load_public_key(path: &Path) -> Result<(String, Vec<u8>)> {
    let bytes = fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;
    let raw = decode_key_bytes(&bytes, 32).with_context(|| {
        format!(
            "Public key {} is neither PEM nor a 32-byte raw key",
            path.display()
        )
    })?;
    if raw.len() != 32 {
        bail!("Public key must be 32 bytes, got {}", raw.len());
    }
    let id = key_id_from_verifying_bytes(&raw);
    Ok((id, raw))
}

pub fn verify_sig(data: &[u8], sig_hex: &str, pubkey_bytes: &[u8]) -> Result<()> {
    use ed25519_dalek::Verifier;

    let sig_bytes = hex::decode(sig_hex).context("Invalid signature hex")?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);

    let pk_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_arr)?;

    vk.verify(data, &sig)
        .context("Signature verification failed")
}

/// Accept PEM (`-----BEGIN …-----`) or a legacy raw 32-byte seed / pubkey.
fn decode_key_bytes(raw: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(raw);
    if let Ok(s) = text {
        let trimmed = s.trim();
        if trimmed.contains("BEGIN") {
            return decode_pem(trimmed);
        }
        // Hex-encoded 32 bytes (64 hex chars) — tolerate it.
        let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.len() == expected_len * 2 && compact.chars().all(|c| c.is_ascii_hexdigit()) {
            return hex::decode(compact).context("hex key");
        }
    }
    if raw.len() == expected_len {
        return Ok(raw.to_vec());
    }
    bail!(
        "unrecognized key encoding ({} bytes; expected PEM or {expected_len} raw bytes)",
        raw.len()
    );
}

fn encode_pem(label: &str, bytes: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn decode_pem(s: &str) -> Result<Vec<u8>> {
    let mut b64 = String::new();
    let mut inside = false;
    for line in s.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") {
            inside = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if inside && !line.is_empty() {
            b64.push_str(line);
        }
    }
    if b64.is_empty() {
        bail!("PEM body is empty");
    }
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("PEM base64 decode")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_roundtrip() {
        let raw = [7u8; 32];
        let pem = encode_pem(PUB_LABEL, &raw);
        assert!(pem.starts_with("-----BEGIN ED25519 PUBLIC KEY-----"));
        let out = decode_pem(&pem).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn raw_32_still_loads() {
        let raw = [9u8; 32];
        let decoded = decode_key_bytes(&raw, 32).unwrap();
        assert_eq!(decoded, raw);
    }
}
