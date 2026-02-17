use tempfile::TempDir;
use sel_deploy::attestation::{
    model::DeploymentAttestation,
    signer::AttestationSigner,
    chain::{ChainBuilder, audit_chain},
    verify::verify_attestation,
};
use sel_deploy::storage::filesystem::AttestationStore;

fn make_signer(dir: &TempDir) -> AttestationSigner {
    let priv_ = dir.path().join("key.pem");
    let pub_  = dir.path().join("key.pub");
    AttestationSigner::generate_and_save(&priv_, &pub_).unwrap()
}

fn sign_att(a: &mut DeploymentAttestation, s: &AttestationSigner) {
    let payload        = a.canonical_payload().unwrap();
    let hash           = a.compute_hash().unwrap();
    a.attestation_hash = hash;
    a.signature        = s.sign(&payload);
}

#[test]
fn test_sign_and_verify() {
    let dir    = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let vk     = signer.verifying_key_bytes();

    let mut a = DeploymentAttestation::build(
        &["kubectl".into(), "apply".into()],
        0, Some("abc123".into()), Some("production".into()),
        None, signer.key_id(),
    );
    sign_att(&mut a, &signer);
    assert!(verify_attestation(&a, &vk).is_ok());
}

#[test]
fn test_tamper_detected() {
    let dir    = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let vk     = signer.verifying_key_bytes();

    let mut a = DeploymentAttestation::build(
        &["deploy.sh".into()], 0, None, None, None, signer.key_id(),
    );
    sign_att(&mut a, &signer);
    a.exit_code = 1; // tamper
    assert!(verify_attestation(&a, &vk).is_err());
}

#[test]
fn test_chain_of_five() {
    let dir    = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let vk     = signer.verifying_key_bytes();

    let mut chain = ChainBuilder::new();
    let mut atts  = Vec::new();

    for i in 0..5 {
        let mut a = DeploymentAttestation::build(
            &[format!("deploy_{}", i)], 0, None, None,
            chain.previous_hash(), signer.key_id(),
        );
        sign_att(&mut a, &signer);
        chain.advance(&a);
        atts.push(a);
    }

    for a in &atts { assert!(verify_attestation(a, &vk).is_ok()); }
    let report = audit_chain(&atts);
    assert!(report.broken_at.is_none());
    assert_eq!(report.total, 5);
}

#[test]
fn test_chain_break_detected() {
    let dir    = TempDir::new().unwrap();
    let signer = make_signer(&dir);

    let mut chain = ChainBuilder::new();
    let mut atts  = Vec::new();

    for i in 0..3 {
        let mut a = DeploymentAttestation::build(
            &[format!("cmd_{}", i)], 0, None, None,
            chain.previous_hash(), signer.key_id(),
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
    let dir    = TempDir::new().unwrap();
    let signer = make_signer(&dir);
    let store  = AttestationStore::new(dir.path().to_path_buf()).unwrap();

    let mut a = DeploymentAttestation::build(
        &["echo".into(), "hello".into()],
        0, None, None, None, signer.key_id(),
    );
    sign_att(&mut a, &signer);

    let orig_id   = a.id.clone();
    let orig_hash = a.attestation_hash.clone();
    store.save(&a).unwrap();

    let all = store.load_all_sorted().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, orig_id);
    assert_eq!(all[0].attestation_hash, orig_hash);
}
