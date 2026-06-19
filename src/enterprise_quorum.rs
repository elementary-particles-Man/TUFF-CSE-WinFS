use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseQuorumPolicyId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseQuorumMemberFingerprint(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseQuorumPolicyHash(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseQuorumThreshold(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuorumRule {
    Threshold,
    ReservedLiveQuorum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseQuorumPolicy {
    pub policy_id: EnterpriseQuorumPolicyId,
    pub enterprise_authority_policy_id: crate::enterprise_authority::EnterpriseAuthorityPolicyId,
    pub rule: QuorumRule,
    pub threshold: EnterpriseQuorumThreshold,
    pub members: Vec<EnterpriseQuorumMemberFingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<EnterpriseQuorumPolicyHash>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseQuorumEvaluation {
    Met,
    NotMet,
}

#[derive(Debug, thiserror::Error)]
pub enum EnterpriseQuorumValidationError {
    #[error("quorum threshold cannot exceed member count")]
    ThresholdTooHigh,
    #[error("quorum member fingerprints must be unique")]
    DuplicateMember,
    #[error("reserved quorum rule is not implemented")]
    ReservedRule,
}

#[derive(Debug, Serialize)]
struct EnterpriseQuorumPolicyCanonical<'a> {
    policy_id: &'a EnterpriseQuorumPolicyId,
    enterprise_authority_policy_id: &'a crate::enterprise_authority::EnterpriseAuthorityPolicyId,
    rule: &'a QuorumRule,
    threshold: EnterpriseQuorumThreshold,
    members: &'a [EnterpriseQuorumMemberFingerprint],
    created_at: u64,
}

pub fn canonicalize_enterprise_quorum_policy(policy: &EnterpriseQuorumPolicy) -> Vec<u8> {
    serde_json::to_vec(&EnterpriseQuorumPolicyCanonical {
        policy_id: &policy.policy_id,
        enterprise_authority_policy_id: &policy.enterprise_authority_policy_id,
        rule: &policy.rule,
        threshold: policy.threshold,
        members: &policy.members,
        created_at: policy.created_at,
    })
    .unwrap_or_default()
}

pub fn compute_enterprise_quorum_policy_hash(
    policy: &EnterpriseQuorumPolicy,
) -> EnterpriseQuorumPolicyHash {
    let mut hasher = Sha256::new();
    hasher.update(canonicalize_enterprise_quorum_policy(policy));
    EnterpriseQuorumPolicyHash(hex::encode(hasher.finalize()))
}

pub fn validate_enterprise_quorum_policy(
    policy: &EnterpriseQuorumPolicy,
) -> Result<(), EnterpriseQuorumValidationError> {
    match policy.rule {
        QuorumRule::Threshold => {}
        QuorumRule::ReservedLiveQuorum => {
            return Err(EnterpriseQuorumValidationError::ReservedRule)
        }
    }

    if policy.threshold.0 == 0 || policy.threshold.0 as usize > policy.members.len() {
        return Err(EnterpriseQuorumValidationError::ThresholdTooHigh);
    }

    let mut seen = HashSet::new();
    for member in &policy.members {
        if !seen.insert(member.0.clone()) {
            return Err(EnterpriseQuorumValidationError::DuplicateMember);
        }
    }

    Ok(())
}

pub fn normalize_enterprise_quorum_policy(
    mut policy: EnterpriseQuorumPolicy,
) -> Result<EnterpriseQuorumPolicy, EnterpriseQuorumValidationError> {
    validate_enterprise_quorum_policy(&policy)?;
    policy.policy_hash = Some(compute_enterprise_quorum_policy_hash(&policy));
    Ok(policy)
}

pub fn evaluate_quorum_decision(
    policy: &EnterpriseQuorumPolicy,
    approver_fingerprints: &[EnterpriseQuorumMemberFingerprint],
) -> Result<EnterpriseQuorumEvaluation, EnterpriseQuorumValidationError> {
    validate_enterprise_quorum_policy(policy)?;
    let member_set: HashSet<&str> = policy.members.iter().map(|fp| fp.0.as_str()).collect();
    let mut approved = HashSet::new();
    for fingerprint in approver_fingerprints {
        if member_set.contains(fingerprint.0.as_str()) {
            approved.insert(fingerprint.0.as_str());
        }
    }
    if approved.len() >= policy.threshold.0 as usize {
        Ok(EnterpriseQuorumEvaluation::Met)
    } else {
        Ok(EnterpriseQuorumEvaluation::NotMet)
    }
}
