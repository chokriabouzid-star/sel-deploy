use sel_deploy::attestation::{
    chain::{audit_chain, ChainBuilder},
    model::{AttestationMeta, ComplianceHints, DeploymentAttestation},
    signer::AttestationSigner,
    verify::{verify_attestation, verify_file},
};
use sel_deploy::storage::filesystem::AttestationStore;
use tempfile::TempDir;

fn make_signer(dir: &TempDir) -> AttestationSigner {
    let priv_ = dir.path().join("key.pem");
    let pub_ = dir.path().join("key.pub");
    AttestationSigner::generate_and_save(&priv_, &pub_).unwrap()
}

fn sign_att(a: &mut DeploymentAttestation, s: &AttestationSigner) {
    let payload = a.canonical_payload().unwrap();
    let hash = a.compute_hash().unwrap();
    a.attestation_hash = hash;
    a.signature = s.sign(&payload);
}

#[test]
fn test_sign_and_verify() {
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let vk = signer.verifying_key_bytes();

    let mut a = DeploymentAttestation::build_simple(
        &["kubectl".into(), "apply".into()],
        0,
        Some("abc123".into()),
        Some("production".into()),
        None,
        signer.key_id(),
    );
    sign_att(&mut a, &signer);
    assert!(verify_attestation(&a, &vk).is_ok());
    assert_eq!(a.command, vec!["kubectl", "apply"]);
    assert!(!a.compliance_hints.soc2_cc8);
    assert!(!a.compliance_hints.change_management);
}

#[test]
fn test_tamper_detected() {
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let vk = signer.verifying_key_bytes();

    let mut a = DeploymentAttestation::build_simple(
        &["deploy.sh".into()],
        0,
        None,
        None,
        None,
        signer.key_id(),
    );
    sign_att(&mut a, &signer);
    a.exit_code = 1;
    assert!(verify_attestation(&a, &vk).is_err());
}

#[test]
fn test_tamper_command_detected() {
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let vk = signer.verifying_key_bytes();

    let mut a = DeploymentAttestation::build_simple(
        &["helm".into(), "upgrade".into(), "app".into()],
        0,
        None,
        None,
        None,
        signer.key_id(),
    );
    sign_att(&mut a, &signer);
    a.command = vec!["helm".into(), "upgrade".into(), "evil".into()];
    assert!(verify_attestation(&a, &vk).is_err());
}

#[test]
fn test_chain_of_five() {
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let vk = signer.verifying_key_bytes();

    let mut chain = ChainBuilder::new();
    let mut atts = Vec::new();

    for i in 0..5 {
        let mut a = DeploymentAttestation::build_simple(
            &[format!("deploy_{i}")],
            0,
            None,
            None,
            chain.previous_hash(),
            signer.key_id(),
        );
        sign_att(&mut a, &signer);
        chain.advance(&a);
        atts.push(a);
    }

    for a in &atts {
        assert!(verify_attestation(a, &vk).is_ok());
    }
    let report = audit_chain(&atts);
    assert!(report.broken_at.is_none());
    assert!(report.is_clean());
    assert_eq!(report.total, 5);
}

#[test]
fn test_chain_break_detected() {
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);

    let mut chain = ChainBuilder::new();
    let mut atts = Vec::new();

    for i in 0..3 {
        let mut a = DeploymentAttestation::build_simple(
            &[format!("cmd_{i}")],
            0,
            None,
            None,
            chain.previous_hash(),
            signer.key_id(),
        );
        sign_att(&mut a, &signer);
        chain.advance(&a);
        atts.push(a);
    }

    atts[1].attestation_hash = "sel:v1.0:sha256:tampered000000000000".into();
    let report = audit_chain(&atts);
    assert!(report.broken_at.is_some());
}

#[test]
fn test_filesystem_roundtrip() {
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let store = AttestationStore::new(dir.path().to_path_buf()).unwrap();

    let mut a = DeploymentAttestation::build_simple(
        &["echo".into(), "hello".into()],
        0,
        None,
        None,
        None,
        signer.key_id(),
    );
    sign_att(&mut a, &signer);

    let orig_id = a.id.clone();
    let orig_hash = a.attestation_hash.clone();
    let saved = store.save(&a).unwrap();
    assert!(saved.starts_with(store.dir()));
    assert!(verify_file(&saved, &signer.verifying_key_bytes()).is_ok());

    let all = store.load_all_sorted().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, orig_id);
    assert_eq!(all[0].attestation_hash, orig_hash);
    assert_eq!(all[0].command, vec!["echo", "hello"]);
}

#[test]
fn test_same_second_does_not_overwrite() {
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let store = AttestationStore::new(dir.path().join("atts")).unwrap();

    let mut a = DeploymentAttestation::build_simple(
        &["echo".into(), "one".into()],
        0,
        None,
        None,
        None,
        signer.key_id(),
    );
    let mut b = DeploymentAttestation::build_simple(
        &["echo".into(), "two".into()],
        0,
        None,
        None,
        None,
        signer.key_id(),
    );
    // Force identical second-resolution timestamps.
    b.timestamp = a.timestamp;
    sign_att(&mut a, &signer);
    sign_att(&mut b, &signer);

    store.save(&a).unwrap();
    store.save(&b).unwrap();

    let all = store.load_all_sorted().unwrap();
    assert_eq!(
        all.len(),
        2,
        "same-second deploys must not share a filename"
    );
    let names: Vec<_> = all.iter().map(|x| x.command[1].clone()).collect();
    assert!(names.contains(&"one".to_string()));
    assert!(names.contains(&"two".to_string()));
}

#[test]
fn test_claims_default_false_and_opt_in() {
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let meta = AttestationMeta {
        claims: ComplianceHints {
            soc2_cc8: true,
            change_management: false,
        },
        ..AttestationMeta::default()
    };
    let a =
        DeploymentAttestation::build(&["true".into()], 0, None, None, None, signer.key_id(), meta)
            .unwrap();
    assert!(a.compliance_hints.soc2_cc8);
    assert!(!a.compliance_hints.change_management);
}

#[test]
fn test_legacy_v01_hash_path_still_verifies() {
    // Build a v0.2 attestation, then rewrite it as a v0.1-shaped document
    // signed with the v0.1 payload/hash so old files keep verifying.
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let vk = signer.verifying_key_bytes();

    let mut a = DeploymentAttestation::build_simple(
        &["echo".into(), "legacy".into()],
        0,
        Some("deadbeef".into()),
        Some("staging".into()),
        None,
        signer.key_id(),
    );
    a.version = "0.1".into();
    a.command.clear();
    a.command_hash =
        sel_deploy::attestation::model::hash_command_v01(&["echo".into(), "legacy".into()]);
    a.cwd = None;
    a.actor = None;
    a.hostname = None;
    a.duration_ms = None;
    a.compliance_hints = ComplianceHints {
        soc2_cc8: true,
        change_management: true,
    };
    sign_att(&mut a, &signer);
    assert!(a.is_legacy_v01());
    assert!(verify_attestation(&a, &vk).is_ok());
}

#[test]
fn test_lost_genesis_is_reported() {
    let dir = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let mut genesis = DeploymentAttestation::build_simple(
        &["echo".into(), "a".into()],
        0,
        None,
        None,
        None,
        signer.key_id(),
    );
    sign_att(&mut genesis, &signer);
    let mut second = DeploymentAttestation::build_simple(
        &["echo".into(), "b".into()],
        0,
        None,
        None,
        Some(genesis.attestation_hash.clone()),
        signer.key_id(),
    );
    sign_att(&mut second, &signer);
    let report = audit_chain(&[second]);
    assert!(!report.is_clean());
    assert!(report.missing_predecessors >= 1);
}

#[test]
fn test_pem_key_files_are_pem() {
    let dir = TempDir::new().unwrap();
    let priv_ = dir.path().join("key.pem");
    let pub_ = dir.path().join("key.pub");
    AttestationSigner::generate_and_save(&priv_, &pub_).unwrap();
    let priv_txt = std::fs::read_to_string(&priv_).unwrap();
    let pub_txt = std::fs::read_to_string(&pub_).unwrap();
    assert!(priv_txt.contains("BEGIN ED25519 PRIVATE KEY"));
    assert!(pub_txt.contains("BEGIN ED25519 PUBLIC KEY"));
    // And they still load.
    let s = AttestationSigner::load(&priv_).unwrap();
    assert_eq!(s.key_id().len(), 16);
}

#[test]
fn test_legacy_raw_32_byte_key_still_loads() {
    let dir = TempDir::new().unwrap();
    // v0.1 wrote the 32-byte Ed25519 seed with no PEM header.
    let seed = [42u8; 32];
    let seed_path = dir.path().join("seed.key");
    std::fs::write(&seed_path, seed).unwrap();
    let loaded = AttestationSigner::load(&seed_path).unwrap();
    assert_eq!(loaded.key_id().len(), 16);
    let msg = b"legacy-key";
    let sig = loaded.sign(msg);
    assert!(
        sel_deploy::attestation::signer::verify_sig(msg, &sig, &loaded.verifying_key_bytes())
            .is_ok()
    );
}
