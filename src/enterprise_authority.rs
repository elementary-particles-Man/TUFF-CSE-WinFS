use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseAuthorityFingerprint(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseAuthorityPolicyId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseAuthorityPolicyHash(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseAuthorityProviderKind {
    ImportedOfflineAuthority,
    ReservedKmsProvider,
    ReservedHsmProvider,
    ReservedCloudKms,
    ReservedPkcs11Hsm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseAuthorityPolicy {
    pub policy_id: EnterpriseAuthorityPolicyId,
    pub authority_fingerprint: EnterpriseAuthorityFingerprint,
    pub provider_kind: EnterpriseAuthorityProviderKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<EnterpriseAuthorityPolicyHash>,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
struct EnterpriseAuthorityPolicyCanonical<'a> {
    policy_id: &'a EnterpriseAuthorityPolicyId,
    authority_fingerprint: &'a EnterpriseAuthorityFingerprint,
    provider_kind: &'a EnterpriseAuthorityProviderKind,
    created_at: u64,
}

pub fn canonicalize_enterprise_authority_policy(policy: &EnterpriseAuthorityPolicy) -> Vec<u8> {
    serde_json::to_vec(&EnterpriseAuthorityPolicyCanonical {
        policy_id: &policy.policy_id,
        authority_fingerprint: &policy.authority_fingerprint,
        provider_kind: &policy.provider_kind,
        created_at: policy.created_at,
    })
    .unwrap_or_default()
}

pub fn compute_enterprise_authority_policy_hash(
    policy: &EnterpriseAuthorityPolicy,
) -> EnterpriseAuthorityPolicyHash {
    let mut hasher = Sha256::new();
    hasher.update(canonicalize_enterprise_authority_policy(policy));
    EnterpriseAuthorityPolicyHash(hex::encode(hasher.finalize()))
}

pub fn normalize_enterprise_authority_policy(
    mut policy: EnterpriseAuthorityPolicy,
) -> EnterpriseAuthorityPolicy {
    policy.policy_hash = Some(compute_enterprise_authority_policy_hash(&policy));
    policy
}
