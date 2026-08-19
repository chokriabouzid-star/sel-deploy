use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

/// Environment variable that overrides the data directory.
/// When set, attestations, keys, and the SQLite index all live under this path.
pub const HOME_ENV: &str = "SEL_DEPLOY_HOME";

pub struct SelPaths {
    pub root: PathBuf,
    pub attestations: PathBuf,
    pub keys_dir: PathBuf,
    pub keys_archive: PathBuf,
    pub private_key: PathBuf,
    pub public_key: PathBuf,
    pub db: PathBuf,
}

impl SelPaths {
    pub fn load() -> Result<Self> {
        let root = if let Ok(raw) = std::env::var(HOME_ENV) {
            let trimmed = raw.trim();
            anyhow::ensure!(
                !trimmed.is_empty(),
                "{HOME_ENV} is set but empty — unset it or give a directory path"
            );
            PathBuf::from(trimmed)
        } else {
            let proj = ProjectDirs::from("", "", "sel-deploy")
                .context("Cannot determine home directory")?;
            proj.data_dir().to_path_buf()
        };
        Self::from_root(root)
    }

    pub fn from_root(root: PathBuf) -> Result<Self> {
        let att_dir = root.join("attestations");
        let keys_dir = root.join("keys");
        let keys_archive = keys_dir.join("archive");

        fs::create_dir_all(&att_dir)?;
        fs::create_dir_all(&keys_dir)?;
        fs::create_dir_all(&keys_archive)?;

        Ok(Self {
            attestations: att_dir,
            private_key: keys_dir.join("default.pem"),
            public_key: keys_dir.join("default.pub"),
            db: root.join("timeline.db"),
            keys_dir,
            keys_archive,
            root,
        })
    }
}
