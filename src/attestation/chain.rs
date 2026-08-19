use std::collections::HashSet;

use crate::attestation::model::DeploymentAttestation;

#[derive(Debug, Clone)]
pub struct ChainBuilder {
    last_hash: Option<String>,
}

impl Default for ChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainBuilder {
    pub fn new() -> Self {
        Self { last_hash: None }
    }

    pub fn with_tip(hash: String) -> Self {
        Self {
            last_hash: Some(hash),
        }
    }

    pub fn previous_hash(&self) -> Option<String> {
        self.last_hash.clone()
    }

    pub fn advance(&mut self, a: &DeploymentAttestation) {
        self.last_hash = Some(a.attestation_hash.clone());
    }
}

#[derive(Debug, Clone)]
pub struct ChainReport {
    pub broken_at: Option<String>,
    pub gaps_detected: usize,
    pub missing_predecessors: usize,
    pub total: usize,
}

impl ChainReport {
    pub fn is_clean(&self) -> bool {
        self.broken_at.is_none() && self.gaps_detected == 0 && self.missing_predecessors == 0
    }
}

/// Audit the chain of attestations already sorted by timestamp.
///
/// A document whose `previous_hash` is `Some` but does not match the immediate
/// predecessor is a **break**.
///
/// A document whose `previous_hash` points at a hash that is not present in
/// the set (deleted / overwritten predecessor) is a **missing predecessor**.
///
/// A non-first document with `previous_hash = None` is a **gap**.
///
/// The first document with `previous_hash = Some(...)` that is not in the set
/// is also a missing predecessor (lost genesis). This used to be reported as
/// "chain intact".
pub fn audit_chain(attestations: &[DeploymentAttestation]) -> ChainReport {
    let total = attestations.len();
    let mut gaps = 0usize;
    let mut missing = 0usize;
    let known: HashSet<&str> = attestations
        .iter()
        .map(|a| a.attestation_hash.as_str())
        .collect();

    if total == 0 {
        return ChainReport {
            broken_at: None,
            gaps_detected: 0,
            missing_predecessors: 0,
            total: 0,
        };
    }

    match &attestations[0].previous_hash {
        None => {}
        Some(ph) if known.contains(ph.as_str()) => {
            // First *file* is not genesis but predecessor exists later in the
            // set — ordering problem. Treat as a break.
            return ChainReport {
                broken_at: Some(attestations[0].id.clone()),
                gaps_detected: 0,
                missing_predecessors: 0,
                total,
            };
        }
        Some(_) => missing += 1,
    }

    for i in 1..total {
        let prev = &attestations[i - 1];
        let curr = &attestations[i];
        match &curr.previous_hash {
            Some(ph) if ph == &prev.attestation_hash => {}
            Some(ph) if known.contains(ph.as_str()) => {
                return ChainReport {
                    broken_at: Some(curr.id.clone()),
                    gaps_detected: gaps,
                    missing_predecessors: missing,
                    total,
                };
            }
            Some(_) => {
                // Predecessor hash is claimed but the file is gone.
                missing += 1;
                return ChainReport {
                    broken_at: Some(curr.id.clone()),
                    gaps_detected: gaps,
                    missing_predecessors: missing,
                    total,
                };
            }
            None => gaps += 1,
        }
    }

    ChainReport {
        broken_at: None,
        gaps_detected: gaps,
        missing_predecessors: missing,
        total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::model::DeploymentAttestation;

    fn fake(prev: Option<&str>, hash: &str) -> DeploymentAttestation {
        let mut a = DeploymentAttestation::build_simple(
            &["echo".into()],
            0,
            None,
            None,
            prev.map(|s| s.to_string()),
            "kid".into(),
        );
        a.attestation_hash = hash.to_string();
        a
    }

    #[test]
    fn empty_chain_is_clean() {
        let r = audit_chain(&[]);
        assert!(r.is_clean());
        assert_eq!(r.total, 0);
    }

    #[test]
    fn lost_genesis_is_not_intact() {
        let a = fake(Some("sel:v1.0:sha256:dead"), "sel:v1.0:sha256:beef");
        let r = audit_chain(&[a]);
        assert!(!r.is_clean());
        assert_eq!(r.missing_predecessors, 1);
    }
}
