use crate::local_policy::{LocalOperationClass, LocalPolicy};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalApprovalStatus {
    Requested,
    Approved,
    Denied,
    Expired,
    Cancelled,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAdminPrincipal {
    pub principal_id: String,
    pub principal_fingerprint: String,
    pub display_label: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalApprovalRequest {
    pub approval_id: String,
    pub policy_id: String,
    pub operation_class: LocalOperationClass,
    pub target_plan_id: String,
    pub target_volume_hash: String,
    pub requested_by_fingerprint: String,
    pub reason_code: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: LocalApprovalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalApprovalDecision {
    pub approval_id: String,
    pub decision_id: String,
    pub status: LocalApprovalStatus,
    pub approved_by_fingerprint: String,
    pub decision_reason: String,
    pub decided_at: u64,
    // Context binding
    pub operation_class: LocalOperationClass,
    pub volume_hash: String,
    pub policy_id: String,
    pub expires_at: u64,
    pub consumed_at: Option<u64>,
}

pub fn build_approval_request(
    policy: &LocalPolicy,
    operation_class: LocalOperationClass,
    target_plan_id: String,
    target_volume_hash: String,
    requested_by_fingerprint: String,
    reason_code: String,
) -> LocalApprovalRequest {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let approval_id = format!("APPR-{}-{}", target_plan_id, now);

    LocalApprovalRequest {
        approval_id,
        policy_id: policy.policy_id.clone(),
        operation_class,
        target_plan_id,
        target_volume_hash,
        requested_by_fingerprint,
        reason_code,
        created_at: now,
        expires_at: now + policy.approval_ttl_seconds,
        status: LocalApprovalStatus::Requested,
    }
}

pub fn approve_request(
    request: &LocalApprovalRequest,
    principal_fingerprint: String,
    reason: String,
) -> (LocalApprovalRequest, LocalApprovalDecision) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut updated_request = request.clone();
    updated_request.status = LocalApprovalStatus::Approved;

    let decision = LocalApprovalDecision {
        approval_id: request.approval_id.clone(),
        decision_id: format!("DEC-{}", now),
        status: LocalApprovalStatus::Approved,
        approved_by_fingerprint: principal_fingerprint,
        decision_reason: reason,
        decided_at: now,
        operation_class: request.operation_class,
        volume_hash: request.target_volume_hash.clone(),
        policy_id: request.policy_id.clone(),
        expires_at: request.expires_at,
        consumed_at: None,
    };

    (updated_request, decision)
}

pub fn deny_request(
    request: &LocalApprovalRequest,
    principal_fingerprint: String,
    reason: String,
) -> (LocalApprovalRequest, LocalApprovalDecision) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut updated_request = request.clone();
    updated_request.status = LocalApprovalStatus::Denied;

    let decision = LocalApprovalDecision {
        approval_id: request.approval_id.clone(),
        decision_id: format!("DEC-{}", now),
        status: LocalApprovalStatus::Denied,
        approved_by_fingerprint: principal_fingerprint,
        decision_reason: reason,
        decided_at: now,
        operation_class: request.operation_class,
        volume_hash: request.target_volume_hash.clone(),
        policy_id: request.policy_id.clone(),
        expires_at: request.expires_at,
        consumed_at: None,
    };

    (updated_request, decision)
}

pub fn is_expired(request: &LocalApprovalRequest, now: u64) -> bool {
    request.expires_at < now
}
