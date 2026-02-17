use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature};
use sha2::{Sha256, Digest};
use anyhow::{Result, Context};
use std::path::Path;
use std::fs;

pub struct AttestationSigner {
    signing_key: SigningKey,
}

impl AttestationSigner {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .context("Key file not found. Run 'sel-deploy keygen' first.")?;
        anyhow::ensure!(bytes.len() >= 32, "Key file too short");
        let arr: [u8; 32] = bytes[..32].try_into().unwrap();
        Ok(Self { signing_key: SigningKey::from_bytes(&arr) })
    }

    pub fn generate_and_save(priv_path: &Path, pub_path: &Path) -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);

        if let Some(p) = priv_path.parent() { fs::create_dir_all(p)?; }
        if let Some(p) = pub_path.parent()  { fs::create_dir_all(p)?; }

        fs::write(priv_path, signing_key.to_bytes())?;
        fs::write(pub_path,  signing_key.verifying_key().to_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(priv_path, fs::Permissions::from_mode(0o600))?;
            fs::set_permissions(pub_path,  fs::Permissions::from_mode(0o644))?;
        }

        Ok(Self { signing_key })
    }

    pub fn sign(&self, data: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(data);
        hex::encode(sig.to_bytes())
    }

    pub fn key_id(&self) -> String {
        let vk: VerifyingKey = self.signing_key.verifying_key();
        let hash = Sha256::digest(vk.as_bytes());
        hex::encode(&hash[..8])
    }

    #[allow(dead_code)]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }
}

pub fn verify_sig(data: &[u8], sig_hex: &str, pubkey_bytes: &[u8]) -> Result<()> {
    use ed25519_dalek::Verifier;

    let sig_bytes = hex::decode(sig_hex).context("Invalid signature hex")?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);

    let pk_arr: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_arr)?;

    vk.verify(data, &sig).context("Signature verification failed")
}
