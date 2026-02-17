use anyhow::{Result, Context};
use std::{fs, path::PathBuf};
use crate::attestation::model::DeploymentAttestation;

pub struct AttestationStore { dir: PathBuf }

impl AttestationStore {
    pub fn new(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn save(&self, a: &DeploymentAttestation) -> Result<PathBuf> {
        let name = format!("{}.json", a.timestamp.format("%Y-%m-%dT%H-%M-%S"));
        let path = self.dir.join(&name);
        fs::write(&path, serde_json::to_string_pretty(a)?)?;
        Ok(path)
    }

    pub fn load_all_sorted(&self) -> Result<Vec<DeploymentAttestation>> {
        let mut entries: Vec<(String, DeploymentAttestation)> = Vec::new();
        for e in fs::read_dir(&self.dir)
            .with_context(|| format!("Cannot read {}", self.dir.display()))?
        {
            let p = e?.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
            let txt = fs::read_to_string(&p)?;
            match serde_json::from_str::<DeploymentAttestation>(&txt) {
                Ok(a)  => entries.push((a.timestamp.to_rfc3339(), a)),
                Err(e) => eprintln!("⚠️  Skipping {}: {}", p.display(), e),
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries.into_iter().map(|(_, a)| a).collect())
    }
}
