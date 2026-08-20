//! Golden hashes: these values were computed against SEL Core v1.0.0
//! (`sel-common::canonical::versioned_hash` + `canonicalize_json_value`).
//!
//! After bumping the git tag to v1.2.1 they MUST stay identical.
//! If this file fails, the canonical spec drifted — do not ship.

use chrono::{DateTime, Utc};
use sel_deploy::attestation::model::{
    hash_command, ComplianceHints, DeploymentAttestation, SignerInfo,
};

/// `versioned_hash(canonicalize(["kubectl","apply","-f","deploy.yaml"]))`
const GOLDEN_KUBECTL: &str =
    "sel:v1.0:sha256:676fa4cc4d82043f016bbc0cd08062ca4313d46c90a374a620b4e82028937fd4";

/// `versioned_hash(canonicalize(["echo","hello"]))`
const GOLDEN_ECHO: &str =
    "sel:v1.0:sha256:1dd863fe7189269266a951b79ce7ceedc13b2662b5b06417d7ee9b869f492091";

/// Frozen v0.2 attestation hash (see `frozen_attestation`).
/// Digest of the canonical payload under spec `sel:v1.0` — independent of
/// the sel-common *crate* version.
const GOLDEN_ATTESTATION: &str =
    "sel:v1.0:sha256:bde8f7131c00647d9631b22f06138234a97d12c1a327daf2f53aebe30c67c337";

fn frozen_attestation() -> DeploymentAttestation {
    let ts = DateTime::parse_from_rfc3339("2026-08-18T16:51:00Z")
        .unwrap()
        .with_timezone(&Utc);
    DeploymentAttestation {
        version: "0.2".into(),
        id: "00000000-0000-4000-8000-000000000001".into(),
        timestamp: ts,
        command: vec!["echo".into(), "hello".into()],
        command_hash: GOLDEN_ECHO.into(),
        git_commit: Some("abc123".into()),
        exit_code: 0,
        environment: Some("production".into()),
        cwd: Some("/srv/app".into()),
        actor: Some("ci-bot".into()),
        hostname: Some("runner-7".into()),
        duration_ms: Some(842),
        previous_hash: None,
        attestation_hash: String::new(),
        signature: String::new(),
        signer: SignerInfo {
            key_id: "5044c0906fe14ed6".into(),
        },
        compliance_hints: ComplianceHints::default(),
    }
}

#[test]
fn command_hash_matches_v1_0_0_golden() {
    let got = hash_command(&[
        "kubectl".into(),
        "apply".into(),
        "-f".into(),
        "deploy.yaml".into(),
    ])
    .unwrap();
    assert_eq!(got, GOLDEN_KUBECTL);
    assert_eq!(
        hash_command(&["echo".into(), "hello".into()]).unwrap(),
        GOLDEN_ECHO
    );
}

#[test]
fn hash_prefix_stays_sel_v1_0_not_crate_version() {
    let got = hash_command(&["true".into()]).unwrap();
    assert!(
        got.starts_with("sel:v1.0:sha256:"),
        "crate SEL_VERSION must not leak into the digest prefix, got {got}"
    );
    assert_eq!(sel_common::canonical::CANONICAL_SPEC_VERSION, "1.0");
}

#[test]
fn frozen_attestation_hash_matches_v1_0_0_golden() {
    let a = frozen_attestation();
    let got = a.compute_hash().unwrap();
    assert_eq!(
        got,
        GOLDEN_ATTESTATION,
        "canonical payload drifted.\n  payload: {}\n  got:     {got}",
        String::from_utf8_lossy(&a.canonical_payload().unwrap())
    );
}
