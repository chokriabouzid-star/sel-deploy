use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use crate::attestation::model::DeploymentAttestation;
use crate::util::prefix;

pub struct AttestationStore {
    dir: PathBuf,
}

impl AttestationStore {
    pub fn new(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Unique filename: `{utc-second}-{id-prefix}.json`.
    /// Two deploys in the same second no longer overwrite each other.
    pub fn filename_for(a: &DeploymentAttestation) -> String {
        format!(
            "{}-{}.json",
            a.timestamp.format("%Y-%m-%dT%H-%M-%S"),
            prefix(&a.id, 8)
        )
    }

    /// Atomic write: temp file in the same directory + rename.
    pub fn save(&self, a: &DeploymentAttestation) -> Result<PathBuf> {
        let name = Self::filename_for(a);
        let path = self.dir.join(&name);
        let tmp = self.dir.join(format!("{name}.tmp"));
        let data = serde_json::to_vec_pretty(a).context("serialize attestation")?;
        fs::write(&tmp, &data).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
        Ok(path)
    }

    pub fn load_all_sorted(&self) -> Result<Vec<DeploymentAttestation>> {
        let mut entries: Vec<(String, String, DeploymentAttestation)> = Vec::new();
        let rd = fs::read_dir(&self.dir)
            .with_context(|| format!("Cannot read {}", self.dir.display()))?;
        for e in rd {
            let p = e?.path();
            let fname = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            if !fname.ends_with(".json") || fname.ends_with(".tmp.json") {
                continue;
            }
            if fname.ends_with(".json.tmp") {
                continue;
            }
            let txt = fs::read_to_string(&p)?;
            match serde_json::from_str::<DeploymentAttestation>(&txt) {
                Ok(a) => entries.push((a.timestamp.to_rfc3339(), a.id.clone(), a)),
                Err(err) => eprintln!("⚠️  Skipping {}: {}", p.display(), err),
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        Ok(entries.into_iter().map(|(_, _, a)| a).collect())
    }
}
