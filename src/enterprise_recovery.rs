use crate::enterprise_authority::EnterpriseAuthorityPolicyId;
use crate::enterprise_quorum::{EnterpriseQuorumMemberFingerprint, EnterpriseQuorumPolicyId};
use crate::operations::OperationKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseRecoveryStatus {
    Requested,
    Approved,
    Denied,
    Expired,
    Consumed,
    ReservedProviderExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseRecoverySourceKind {
    ImportedOfflineDecision,
    DevGeneratedDecision,
    ReservedKmsProvider,
    ReservedHsmProvider,
    ReservedCloudKms,
    ReservedPkcs11Hsm,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseRecoveryRequestId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseRecoveryDecisionId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseRecoveryDecisionHash(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseRecoveryRequest {
    pub request_id: EnterpriseRecoveryRequestId,
    pub operation_kind: OperationKind,
    pub volume_hash: String,
    pub domain_recovery_request_id: String,
    pub domain_recovery_package_id: String,
    pub domain_recovery_decision_id: String,
    pub enterprise_authority_policy_id: EnterpriseAuthorityPolicyId,
    pub enterprise_quorum_policy_id: EnterpriseQuorumPolicyId,
    pub source_kind: EnterpriseRecoverySourceKind,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseRecoveryDecision {
    pub decision_id: EnterpriseRecoveryDecisionId,
    pub operation_kind: OperationKind,
    pub volume_hash: String,
    pub domain_recovery_request_id: String,
    pub domain_recovery_package_id: String,
    pub domain_recovery_decision_id: String,
    pub enterprise_authority_policy_id: EnterpriseAuthorityPolicyId,
    pub enterprise_quorum_policy_id: EnterpriseQuorumPolicyId,
    pub approver_fingerprints: Vec<EnterpriseQuorumMemberFingerprint>,
    pub decision_hash: EnterpriseRecoveryDecisionHash,
    pub valid_from: u64,
    pub valid_until: u64,
    pub consumed_at: Option<u64>,
    pub status: EnterpriseRecoveryStatus,
    pub source_kind: EnterpriseRecoverySourceKind,
}

#[derive(Debug, Serialize)]
struct EnterpriseRecoveryDecisionCanonical<'a> {
    decision_id: &'a EnterpriseRecoveryDecisionId,
    operation_kind: OperationKind,
    volume_hash: &'a str,
    domain_recovery_request_id: &'a str,
    domain_recovery_package_id: &'a str,
    domain_recovery_decision_id: &'a str,
    enterprise_authority_policy_id: &'a EnterpriseAuthorityPolicyId,
    enterprise_quorum_policy_id: &'a EnterpriseQuorumPolicyId,
    approver_fingerprints: &'a [EnterpriseQuorumMemberFingerprint],
    valid_from: u64,
    valid_until: u64,
    consumed_at: Option<u64>,
    status: EnterpriseRecoveryStatus,
    source_kind: EnterpriseRecoverySourceKind,
}

pub fn canonicalize_enterprise_recovery_decision(decision: &EnterpriseRecoveryDecision) -> Vec<u8> {
    serde_json::to_vec(&EnterpriseRecoveryDecisionCanonical {
        decision_id: &decision.decision_id,
        operation_kind: decision.operation_kind,
        volume_hash: &decision.volume_hash,
        domain_recovery_request_id: &decision.domain_recovery_request_id,
        domain_recovery_package_id: &decision.domain_recovery_package_id,
        domain_recovery_decision_id: &decision.domain_recovery_decision_id,
        enterprise_authority_policy_id: &decision.enterprise_authority_policy_id,
        enterprise_quorum_policy_id: &decision.enterprise_quorum_policy_id,
        approver_fingerprints: &decision.approver_fingerprints,
        valid_from: decision.valid_from,
        valid_until: decision.valid_until,
        consumed_at: decision.consumed_at,
        status: decision.status,
        source_kind: decision.source_kind,
    })
    .unwrap_or_default()
}

pub fn compute_enterprise_recovery_decision_hash(
    decision: &EnterpriseRecoveryDecision,
) -> EnterpriseRecoveryDecisionHash {
    let mut hasher = Sha256::new();
    hasher.update(canonicalize_enterprise_recovery_decision(decision));
    EnterpriseRecoveryDecisionHash(hex::encode(hasher.finalize()))
}

impl EnterpriseRecoveryDecision {
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.valid_until
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    pub fn matches_operation_volume_domain_recovery(
        &self,
        operation_kind: OperationKind,
        volume_hash: &str,
        domain_recovery_request_id: &str,
        domain_recovery_package_id: &str,
        domain_recovery_decision_id: &str,
    ) -> bool {
        self.operation_kind == operation_kind
            && self.volume_hash == volume_hash
            && self.domain_recovery_request_id == domain_recovery_request_id
            && self.domain_recovery_package_id == domain_recovery_package_id
            && self.domain_recovery_decision_id == domain_recovery_decision_id
    }
}

pub fn build_enterprise_recovery_decision(
    decision_id: EnterpriseRecoveryDecisionId,
    operation_kind: OperationKind,
    volume_hash: String,
    domain_recovery_request_id: String,
    domain_recovery_package_id: String,
    domain_recovery_decision_id: String,
    enterprise_authority_policy_id: EnterpriseAuthorityPolicyId,
    enterprise_quorum_policy_id: EnterpriseQuorumPolicyId,
    approver_fingerprints: Vec<EnterpriseQuorumMemberFingerprint>,
    valid_from: u64,
    valid_until: u64,
    status: EnterpriseRecoveryStatus,
    source_kind: EnterpriseRecoverySourceKind,
) -> EnterpriseRecoveryDecision {
    let mut decision = EnterpriseRecoveryDecision {
        decision_id,
        operation_kind,
        volume_hash,
        domain_recovery_request_id,
        domain_recovery_package_id,
        domain_recovery_decision_id,
        enterprise_authority_policy_id,
        enterprise_quorum_policy_id,
        approver_fingerprints,
        decision_hash: EnterpriseRecoveryDecisionHash(String::new()),
        valid_from,
        valid_until,
        consumed_at: None,
        status,
        source_kind,
    };
    decision.decision_hash = compute_enterprise_recovery_decision_hash(&decision);
    decision
}
