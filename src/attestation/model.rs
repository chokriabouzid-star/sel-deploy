use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Attestation document version emitted by this build.
pub const ATTESTATION_VERSION: &str = "0.2";

/// Legacy documents produced by sel-deploy 0.1.x.
pub const ATTESTATION_VERSION_V01: &str = "0.1";

// ── Hashing via SEL Core ──────────────────────────────────────────────────
//
// v0.2 hashes the canonical JSON *string* with sel-common::canonical::versioned_hash.
// That function prefixes the input with `sel:v1.0:` before SHA-256, then emits
// `sel:v1.0:sha256:<hex>`.
//
// v0.1 hashed the canonical JSON *bytes* directly (no prefix) and wrapped the
// digest in the same string format. Verification of old files must keep that
// path so existing signatures remain valid.

fn legacy_v01_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    format!("sel:v1.0:sha256:{}", hex::encode(digest))
}

fn sel_versioned_hash_str(canonical: &str) -> String {
    sel_common::canonical::versioned_hash(canonical)
}

fn canonicalize_value(value: serde_json::Value) -> Result<serde_json::Value> {
    sel_common::canonicalize_json_value(&value)
        .map_err(|e| anyhow::anyhow!("canonicalization failed: {e}"))
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let raw = serde_json::to_value(value).context("serialize payload")?;
    let normalized = canonicalize_value(raw)?;
    serde_json::to_vec(&normalized).context("emit canonical bytes")
}

fn canonical_string<T: Serialize>(value: &T) -> Result<String> {
    let raw = serde_json::to_value(value).context("serialize payload")?;
    let normalized = canonicalize_value(raw)?;
    serde_json::to_string(&normalized).context("emit canonical string")
}

/// SHA-256 of the argv as a canonical JSON array (preserves argument boundaries).
pub fn hash_command(command: &[String]) -> Result<String> {
    let canonical = canonical_string(&command)?;
    Ok(sel_versioned_hash_str(&canonical))
}

/// v0.1 hashed `command.join(" ")` bytes. Used only when verifying old files.
pub fn hash_command_v01(command: &[String]) -> String {
    legacy_v01_hash(command.join(" ").as_bytes())
}

// ── Data structures ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentAttestation {
    pub version: String,
    pub id: String,
    pub timestamp: DateTime<Utc>,
    /// Original argv. Empty on v0.1 documents (field did not exist).
    #[serde(default)]
    pub command: Vec<String>,
    /// `sel:v1.0:sha256:<hex>` of the command (argv-canonical in v0.2).
    pub command_hash: String,
    pub git_commit: Option<String>,
    pub exit_code: i32,
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    pub previous_hash: Option<String>,
    pub attestation_hash: String,
    pub signature: String,
    pub signer: SignerInfo,
    /// Explicit claims only. Never inferred. Defaults to all-false.
    #[serde(default)]
    pub compliance_hints: ComplianceHints,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    pub key_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceHints {
    #[serde(default)]
    pub soc2_cc8: bool,
    #[serde(default)]
    pub change_management: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AttestationMeta {
    pub cwd: Option<String>,
    pub actor: Option<String>,
    pub hostname: Option<String>,
    pub duration_ms: Option<u64>,
    pub claims: ComplianceHints,
}

impl DeploymentAttestation {
    pub fn build(
        command: &[String],
        exit_code: i32,
        git_commit: Option<String>,
        environment: Option<String>,
        previous_hash: Option<String>,
        key_id: String,
        meta: AttestationMeta,
    ) -> Result<Self> {
        let command_hash = hash_command(command)?;
        Ok(Self {
            version: ATTESTATION_VERSION.into(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            command: command.to_vec(),
            command_hash,
            git_commit,
            exit_code,
            environment,
            cwd: meta.cwd,
            actor: meta.actor,
            hostname: meta.hostname,
            duration_ms: meta.duration_ms,
            previous_hash,
            attestation_hash: String::new(),
            signature: String::new(),
            signer: SignerInfo { key_id },
            compliance_hints: meta.claims,
        })
    }

    /// Convenience constructor used by tests (no host metadata, no claims).
    pub fn build_simple(
        command: &[String],
        exit_code: i32,
        git_commit: Option<String>,
        environment: Option<String>,
        previous_hash: Option<String>,
        key_id: String,
    ) -> Self {
        Self::build(
            command,
            exit_code,
            git_commit,
            environment,
            previous_hash,
            key_id,
            AttestationMeta::default(),
        )
        .expect("canonical command hash")
    }

    pub fn is_legacy_v01(&self) -> bool {
        self.version == ATTESTATION_VERSION_V01 || self.version.starts_with("0.1")
    }

    /// Bytes that were signed. Field set depends on document version.
    pub fn canonical_payload(&self) -> Result<Vec<u8>> {
        if self.is_legacy_v01() {
            canonical_bytes(&V01Payload::from(self))
        } else {
            Ok(self.canonical_payload_string()?.into_bytes())
        }
    }

    fn canonical_payload_string(&self) -> Result<String> {
        canonical_string(&V02Payload::from(self))
    }

    /// Recompute the attestation hash from the signed payload.
    pub fn compute_hash(&self) -> Result<String> {
        if self.is_legacy_v01() {
            let payload = self.canonical_payload()?;
            Ok(legacy_v01_hash(&payload))
        } else {
            let canonical = self.canonical_payload_string()?;
            Ok(sel_versioned_hash_str(&canonical))
        }
    }
}

/// Exact v0.1 signed field set. New fields must not appear here.
#[derive(Serialize)]
struct V01Payload<'a> {
    version: &'a str,
    id: &'a str,
    timestamp: &'a DateTime<Utc>,
    command_hash: &'a str,
    git_commit: &'a Option<String>,
    exit_code: i32,
    environment: &'a Option<String>,
    previous_hash: &'a Option<String>,
    signer: &'a SignerInfo,
    compliance_hints: &'a ComplianceHints,
}

impl<'a> From<&'a DeploymentAttestation> for V01Payload<'a> {
    fn from(a: &'a DeploymentAttestation) -> Self {
        Self {
            version: &a.version,
            id: &a.id,
            timestamp: &a.timestamp,
            command_hash: &a.command_hash,
            git_commit: &a.git_commit,
            exit_code: a.exit_code,
            environment: &a.environment,
            previous_hash: &a.previous_hash,
            signer: &a.signer,
            compliance_hints: &a.compliance_hints,
        }
    }
}

/// v0.2 signed field set — includes the command itself and host metadata.
#[derive(Serialize)]
struct V02Payload<'a> {
    actor: &'a Option<String>,
    command: &'a Vec<String>,
    command_hash: &'a str,
    compliance_hints: &'a ComplianceHints,
    cwd: &'a Option<String>,
    duration_ms: &'a Option<u64>,
    environment: &'a Option<String>,
    exit_code: i32,
    git_commit: &'a Option<String>,
    hostname: &'a Option<String>,
    id: &'a str,
    previous_hash: &'a Option<String>,
    signer: &'a SignerInfo,
    timestamp: &'a DateTime<Utc>,
    version: &'a str,
}

impl<'a> From<&'a DeploymentAttestation> for V02Payload<'a> {
    fn from(a: &'a DeploymentAttestation) -> Self {
        Self {
            actor: &a.actor,
            command: &a.command,
            command_hash: &a.command_hash,
            compliance_hints: &a.compliance_hints,
            cwd: &a.cwd,
            duration_ms: &a.duration_ms,
            environment: &a.environment,
            exit_code: a.exit_code,
            git_commit: &a.git_commit,
            hostname: &a.hostname,
            id: &a.id,
            previous_hash: &a.previous_hash,
            signer: &a.signer,
            timestamp: &a.timestamp,
            version: &a.version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_boundaries_are_distinct() {
        let a = hash_command(&["echo".into(), "hello world".into()]).unwrap();
        let b = hash_command(&["echo hello".into(), "world".into()]).unwrap();
        assert_ne!(a, b, "joining with spaces must not be used for v0.2 hashes");
        assert!(a.starts_with("sel:v1.0:sha256:"));
        assert_eq!(a.len(), "sel:v1.0:sha256:".len() + 64);
    }

    #[test]
    fn hash_is_stable() {
        let cmd = vec![
            "kubectl".into(),
            "apply".into(),
            "-f".into(),
            "d.yaml".into(),
        ];
        let h1 = hash_command(&cmd).unwrap();
        let h2 = hash_command(&cmd).unwrap();
        assert_eq!(h1, h2);
    }
}
