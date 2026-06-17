use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainAuthorityFingerprint(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainPrincipalFingerprint(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainGroupFingerprint(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPrincipalSnapshot {
    pub principal_fingerprint: DomainPrincipalFingerprint,
    pub authority_fingerprint: DomainAuthorityFingerprint,
    pub provider_kind: String,
    pub created_at: u64,
}

pub fn compute_fingerprint(raw_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_id.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn fingerprint_domain_principal(domain: &str, principal: &str) -> DomainPrincipalFingerprint {
    DomainPrincipalFingerprint(compute_fingerprint(&format!("{}:{}", domain, principal)))
}

pub fn fingerprint_domain_group(domain: &str, group: &str) -> DomainGroupFingerprint {
    DomainGroupFingerprint(compute_fingerprint(&format!("{}:{}", domain, group)))
}
