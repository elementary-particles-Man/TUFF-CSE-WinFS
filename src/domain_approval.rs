use crate::domain_principal::{
    DomainAuthorityFingerprint, DomainGroupFingerprint, DomainPrincipalFingerprint,
};
use crate::operations::OperationKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainApprovalStatus {
    Requested,
    Approved,
    Denied,
    Expired,
    Consumed,
    ReservedLiveVerificationRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainApprovalSourceKind {
    ImportedOfflineDecision,
    DevGeneratedOfflineDecision,
    ReservedLiveDomainController,
    ReservedEnterpriseApprovalService,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainApprovalRequest {
    pub request_id: String,
    pub operation_kind: OperationKind,
    pub volume_hash: String,
    pub domain_policy_id: String,
    pub group_policy_mapping_id: String,
    pub offline_snapshot_id: Option<String>,
    pub domain_authority_fingerprint: DomainAuthorityFingerprint,
    pub requester_principal_fingerprint: DomainPrincipalFingerprint,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainApprovalDecision {
    pub request_id: String,
    pub decision_id: String,
    pub operation_kind: OperationKind,
    pub volume_hash: String,
    pub domain_policy_id: String,
    pub group_policy_mapping_id: String,
    pub offline_snapshot_id: Option<String>,
    pub domain_authority_fingerprint: DomainAuthorityFingerprint,
    pub approver_principal_fingerprint: DomainPrincipalFingerprint,
    pub approver_group_fingerprint: Option<DomainGroupFingerprint>,
    pub status: DomainApprovalStatus,
    pub expires_at: u64,
    pub consumed_at: Option<u64>,
    pub decision_hash: Vec<u8>,
    pub source_kind: DomainApprovalSourceKind,
}

impl DomainApprovalDecision {
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }
}
