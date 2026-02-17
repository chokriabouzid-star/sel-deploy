use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum DeployError {
    #[error("Signing key not found. Run 'sel-deploy keygen' first.")]
    NoKey,
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Chain broken at: {0}")]
    ChainBroken(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
