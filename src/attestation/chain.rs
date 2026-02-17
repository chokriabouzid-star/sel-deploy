use crate::attestation::model::DeploymentAttestation;

pub struct ChainBuilder {
    last_hash: Option<String>,
}

impl ChainBuilder {
    pub fn new() -> Self { Self { last_hash: None } }
    pub fn with_tip(hash: String) -> Self { Self { last_hash: Some(hash) } }
    pub fn previous_hash(&self) -> Option<String> { self.last_hash.clone() }
    pub fn advance(&mut self, a: &DeploymentAttestation) {
        self.last_hash = Some(a.attestation_hash.clone());
    }
}

pub struct ChainReport {
    pub broken_at:     Option<String>,
    pub gaps_detected: usize,
    #[allow(dead_code)]
    pub total:         usize,
}

pub fn audit_chain(attestations: &[DeploymentAttestation]) -> ChainReport {
    let total = attestations.len();
    let mut gaps = 0usize;

    for i in 1..total {
        let prev = &attestations[i - 1];
        let curr = &attestations[i];
        match &curr.previous_hash {
            Some(ph) if ph == &prev.attestation_hash => {}
            Some(_) => return ChainReport {
                total,
                broken_at: Some(curr.id.clone()),
                gaps_detected: gaps,
            },
            None => gaps += 1,
        }
    }

    ChainReport { total, broken_at: None, gaps_detected: gaps }
}
