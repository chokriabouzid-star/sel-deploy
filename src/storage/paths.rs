use anyhow::{Result, Context};
use directories::ProjectDirs;
use std::{fs, path::PathBuf};

pub struct SelPaths {
    pub attestations: PathBuf,
    pub private_key:  PathBuf,
    pub public_key:   PathBuf,
    pub db:           PathBuf,
}

impl SelPaths {
    pub fn load() -> Result<Self> {
        let proj = ProjectDirs::from("", "", "sel-deploy")
            .context("Cannot determine home directory")?;
        let base     = proj.data_dir().to_path_buf();
        let att_dir  = base.join("attestations");
        let keys_dir = base.join("keys");

        fs::create_dir_all(&att_dir)?;
        fs::create_dir_all(&keys_dir)?;

        Ok(Self {
            attestations: att_dir,
            private_key:  keys_dir.join("default.pem"),
            public_key:   keys_dir.join("default.pub"),
            db:           base.join("timeline.db"),
        })
    }
}
