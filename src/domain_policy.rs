use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainPolicySourceKind {
    ImportedGpoSnapshot,
    ReservedLiveDomainController,
    ReservedEnterprisePolicyService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainPolicyEffect {
    Allow,
    Deny,
    RequireLocalApproval,
    RequireDomainApprovalReserved,
    RequireOfflineSnapshot,
    AuditOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainOperationPolicy {
    pub effect: DomainPolicyEffect,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPolicy {
    pub domain_policy_id: String,
    pub domain_authority_fingerprint: crate::domain_principal::DomainAuthorityFingerprint,
    pub source_kind: DomainPolicySourceKind,
    pub created_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum DomainPolicyValidationError {
    #[error("Reserved live domain controller source is not implemented")]
    ReservedSource,
    #[error("Reserved domain approval effect is not implemented")]
    ReservedEffect,
}
