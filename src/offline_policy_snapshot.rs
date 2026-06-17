use serde::{Deserialize, Serialize};
use crate::domain_principal::DomainAuthorityFingerprint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflinePolicySnapshot {
    pub snapshot_id: String,
    pub domain_policy_id: String,
    pub mapping_id: String,
    pub snapshot_hash: Vec<u8>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issuer_fingerprint: DomainAuthorityFingerprint,
    pub created_at: u64,
}

impl OfflinePolicySnapshot {
    pub fn is_fresh(&self, now: u64) -> bool {
        self.valid_from <= now && now <= self.valid_until
    }
}
