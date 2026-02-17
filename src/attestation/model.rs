use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use anyhow::Result;
use sha2::{Sha256, Digest};

// ── الـ hash يستخدم تنسيق SEL Core الرسمي ─────────────────────────────────
// "sel:v1.0:sha256:<hex>"
// نحسبه يدوياً هنا لأن sel-common قد لا يصدّر versioned_hash مباشرة.
// TODO: استبدل بـ sel_common::versioned_hash عندما تصبح pub.

fn sel_versioned_hash(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    format!("sel:v1.0:sha256:{}", hex::encode(digest))
}

// ── الـ Canonical JSON ─────────────────────────────────────────────────────
// نستخدم serde_json مع BTreeMap (مثل sel-common تماماً) لضمان key ordering.
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // Step 1: serialize إلى Value
    let raw = serde_json::to_value(value)?;
    // Step 2: normalize (sort object keys recursively)
    let normalized = normalize_value(raw);
    // Step 3: compact JSON
    Ok(serde_json::to_vec(&normalized)?)
}

fn normalize_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            // BTreeMap يرتب المفاتيح أبجدياً تلقائياً — نفس ما يفعله sel-common
            let mut sorted: Vec<(String, serde_json::Value)> = map
                .into_iter()
                .map(|(k, v)| (k, normalize_value(v)))
                .collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(normalize_value).collect())
        }
        other => other,
    }
}

// ── Data Structures ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentAttestation {
    pub version:          String,
    pub id:               String,
    pub timestamp:        DateTime<Utc>,
    /// sel:v1.0:sha256:<hex> of the deployment command
    pub command_hash:     String,
    pub git_commit:       Option<String>,
    pub exit_code:        i32,
    pub environment:      Option<String>,
    /// sel:v1.0:sha256:<hex> — hash of the previous attestation
    pub previous_hash:    Option<String>,
    /// sel:v1.0:sha256:<hex> — hash of canonical payload (without sig/hash fields)
    pub attestation_hash: String,
    /// Ed25519 hex signature over canonical payload bytes
    pub signature:        String,
    pub signer:           SignerInfo,
    pub compliance_hints: ComplianceHints,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceHints {
    pub soc2_cc8:          bool,
    pub change_management: bool,
}

impl DeploymentAttestation {
    pub fn build(
        command:       &[String],
        exit_code:     i32,
        git_commit:    Option<String>,
        environment:   Option<String>,
        previous_hash: Option<String>,
        key_id:        String,
    ) -> Self {
        let command_str  = command.join(" ");
        let command_hash = sel_versioned_hash(command_str.as_bytes());

        Self {
            version: "0.1".into(),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            command_hash,
            git_commit,
            exit_code,
            environment,
            previous_hash,
            attestation_hash: String::new(), // مؤقت — يُحسب بعد البناء
            signature:        String::new(), // مؤقت — يُحسب بعد البناء
            signer: SignerInfo { key_id },
            compliance_hints: ComplianceHints {
                soc2_cc8: true,
                change_management: true,
            },
        }
    }

    /// Canonical payload = الـ attestation بدون attestation_hash و signature
    /// هذا ما يُوقَّع عليه.
    pub fn canonical_payload(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Payload<'a> {
            version:          &'a str,
            id:               &'a str,
            timestamp:        &'a DateTime<Utc>,
            command_hash:     &'a str,
            git_commit:       &'a Option<String>,
            exit_code:        i32,
            environment:      &'a Option<String>,
            previous_hash:    &'a Option<String>,
            signer:           &'a SignerInfo,
            compliance_hints: &'a ComplianceHints,
        }
        canonical_bytes(&Payload {
            version:          &self.version,
            id:               &self.id,
            timestamp:        &self.timestamp,
            command_hash:     &self.command_hash,
            git_commit:       &self.git_commit,
            exit_code:        self.exit_code,
            environment:      &self.environment,
            previous_hash:    &self.previous_hash,
            signer:           &self.signer,
            compliance_hints: &self.compliance_hints,
        })
    }

    /// حساب attestation_hash من canonical payload
    pub fn compute_hash(&self) -> Result<String> {
        let payload = self.canonical_payload()?;
        Ok(sel_versioned_hash(&payload))
    }
}
