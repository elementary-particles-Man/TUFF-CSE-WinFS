use crate::domain_principal::DomainAuthorityFingerprint;
use crate::operations::OperationKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainRecoveryWorkflowState {
    Requested,
    AwaitingDomainApproval,
    AwaitingLocalApproval,
    Authorized,
    Planned,
    Completed,
    Aborted,
    Expired,
    ReservedExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainRecoverySourceKind {
    ImportedOfflinePackage,
    DevGeneratedPackage,
    ReservedLiveDomainController,
    ReservedEnterpriseRecoveryService,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecoveryRequest {
    pub request_id: String,
    pub operation_kind: OperationKind,
    pub source_volume_hash: String,
    pub target_volume_hash: Option<String>,
    pub host_fingerprint: Option<String>,
    pub domain_policy_id: String,
    pub group_policy_mapping_id: String,
    pub offline_snapshot_id: Option<String>,
    pub domain_authority_fingerprint: DomainAuthorityFingerprint,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecoveryPackage {
    pub request_id: String,
    pub package_id: String,
    pub package_hash: Vec<u8>,
    pub source_volume_hash: String,
    pub target_volume_hash: Option<String>,
    pub domain_policy_id: String,
    pub group_policy_mapping_id: String,
    pub offline_snapshot_id: Option<String>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecoveryDecision {
    pub request_id: String,
    pub decision_id: String,
    pub package_id: String,
    pub approval_decision_id: Option<String>,
    pub status: DomainRecoveryWorkflowState,
    pub expires_at: u64,
    pub consumed_at: Option<u64>,
    pub decision_hash: Vec<u8>,
}

impl DomainRecoveryDecision {
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }
}
