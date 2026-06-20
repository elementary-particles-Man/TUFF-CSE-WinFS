use crate::enterprise_authority::EnterpriseAuthorityPolicyId;
use crate::operations::OperationKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseProviderPolicyId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseProviderPolicyHash(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseProviderAttestationId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseProviderAttestationHash(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderKind {
    ImportedOfflineProvider,
    ReservedKmsProvider,
    ReservedHsmProvider,
    ReservedCloudKms,
    ReservedPkcs11Hsm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderCapability {
    AttestationOnly,
    RecoveryApprovalOnly,
    KeyReleaseReserved,
    AuditOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderHealth {
    Unknown,
    OfflineImported,
    HealthyReserved,
    DegradedReserved,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseProviderPolicy {
    pub policy_id: EnterpriseProviderPolicyId,
    pub enterprise_authority_policy_id: EnterpriseAuthorityPolicyId,
    pub provider_kind: EnterpriseProviderKind,
    pub capabilities: Vec<EnterpriseProviderCapability>,
    pub health: EnterpriseProviderHealth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<EnterpriseProviderPolicyHash>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseProviderAttestationSummary {
    pub attestation_id: EnterpriseProviderAttestationId,
    pub enterprise_provider_id: EnterpriseProviderPolicyId,
    pub enterprise_authority_policy_id: EnterpriseAuthorityPolicyId,
    pub provider_kind: EnterpriseProviderKind,
    pub capabilities: Vec<EnterpriseProviderCapability>,
    pub health: EnterpriseProviderHealth,
    pub valid_from: u64,
    pub valid_until: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_hash: Option<EnterpriseProviderAttestationHash>,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
struct EnterpriseProviderPolicyCanonical<'a> {
    policy_id: &'a EnterpriseProviderPolicyId,
    enterprise_authority_policy_id: &'a EnterpriseAuthorityPolicyId,
    provider_kind: &'a EnterpriseProviderKind,
    capabilities: &'a [EnterpriseProviderCapability],
    health: EnterpriseProviderHealth,
    created_at: u64,
}

#[derive(Debug, Serialize)]
struct EnterpriseProviderAttestationCanonical<'a> {
    attestation_id: &'a EnterpriseProviderAttestationId,
    enterprise_provider_id: &'a EnterpriseProviderPolicyId,
    enterprise_authority_policy_id: &'a EnterpriseAuthorityPolicyId,
    provider_kind: &'a EnterpriseProviderKind,
    capabilities: &'a [EnterpriseProviderCapability],
    health: EnterpriseProviderHealth,
    valid_from: u64,
    valid_until: u64,
    revoked_at: Option<u64>,
    created_at: u64,
}

pub fn canonicalize_enterprise_provider_policy(policy: &EnterpriseProviderPolicy) -> Vec<u8> {
    serde_json::to_vec(&EnterpriseProviderPolicyCanonical {
        policy_id: &policy.policy_id,
        enterprise_authority_policy_id: &policy.enterprise_authority_policy_id,
        provider_kind: &policy.provider_kind,
        capabilities: &policy.capabilities,
        health: policy.health,
        created_at: policy.created_at,
    })
    .unwrap_or_default()
}

pub fn compute_enterprise_provider_policy_hash(
    policy: &EnterpriseProviderPolicy,
) -> EnterpriseProviderPolicyHash {
    let mut hasher = Sha256::new();
    hasher.update(canonicalize_enterprise_provider_policy(policy));
    EnterpriseProviderPolicyHash(hex::encode(hasher.finalize()))
}

pub fn normalize_enterprise_provider_policy(
    mut policy: EnterpriseProviderPolicy,
) -> EnterpriseProviderPolicy {
    policy.policy_hash = Some(compute_enterprise_provider_policy_hash(&policy));
    policy
}

pub fn canonicalize_enterprise_provider_attestation(
    attestation: &EnterpriseProviderAttestationSummary,
) -> Vec<u8> {
    serde_json::to_vec(&EnterpriseProviderAttestationCanonical {
        attestation_id: &attestation.attestation_id,
        enterprise_provider_id: &attestation.enterprise_provider_id,
        enterprise_authority_policy_id: &attestation.enterprise_authority_policy_id,
        provider_kind: &attestation.provider_kind,
        capabilities: &attestation.capabilities,
        health: attestation.health,
        valid_from: attestation.valid_from,
        valid_until: attestation.valid_until,
        revoked_at: attestation.revoked_at,
        created_at: attestation.created_at,
    })
    .unwrap_or_default()
}

pub fn compute_enterprise_provider_attestation_hash(
    attestation: &EnterpriseProviderAttestationSummary,
) -> EnterpriseProviderAttestationHash {
    let mut hasher = Sha256::new();
    hasher.update(canonicalize_enterprise_provider_attestation(attestation));
    EnterpriseProviderAttestationHash(hex::encode(hasher.finalize()))
}

pub fn normalize_enterprise_provider_attestation(
    mut attestation: EnterpriseProviderAttestationSummary,
) -> EnterpriseProviderAttestationSummary {
    attestation.attestation_hash = Some(compute_enterprise_provider_attestation_hash(&attestation));
    attestation
}

pub fn required_provider_capability_for_operation(
    operation_kind: OperationKind,
) -> EnterpriseProviderCapability {
    match operation_kind {
        OperationKind::Recover => EnterpriseProviderCapability::RecoveryApprovalOnly,
        OperationKind::Audit => EnterpriseProviderCapability::AuditOnly,
        _ => EnterpriseProviderCapability::AttestationOnly,
    }
}

pub fn is_reserved_live_provider_kind(provider_kind: EnterpriseProviderKind) -> bool {
    !matches!(
        provider_kind,
        EnterpriseProviderKind::ImportedOfflineProvider
    )
}

impl EnterpriseProviderAttestationSummary {
    pub fn is_expired(&self, now: u64) -> bool {
        now < self.valid_from || now > self.valid_until
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some() || self.health == EnterpriseProviderHealth::Revoked
    }
}
