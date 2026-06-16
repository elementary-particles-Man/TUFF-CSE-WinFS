use crate::binding_store::BindingStore;
use crate::local_approval::{LocalApprovalStatus};
use crate::local_policy::{LocalOperationClass, LocalPolicy, operation_requires_approval};
use anyhow::{Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalEnforcementDecision {
    Allowed,
    Rejected,
    NotRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalRejectionReason {
    ApprovalRequiredButMissing,
    ApprovalRecordNotFound,
    ApprovalDenied,
    ApprovalExpired,
    ApprovalVolumeMismatch,
    ApprovalOperationMismatch,
    ApprovalPolicyMismatch,
    ApprovalAlreadyConsumed,
}

pub struct ApprovalEnforcementResult {
    pub decision: ApprovalEnforcementDecision,
    pub reason: Option<ApprovalRejectionReason>,
    pub approval_id: Option<String>,
}

pub struct ApprovalEnforcer<'a> {
    store: &'a BindingStore,
}

impl<'a> ApprovalEnforcer<'a> {
    pub fn new(store: &'a BindingStore) -> Self {
        Self { store }
    }

    pub fn check_required_approval(
        &self,
        policy: &LocalPolicy,
        operation: LocalOperationClass,
        volume_hash: &str,
        supplied_approval_id: Option<String>,
    ) -> Result<ApprovalEnforcementResult> {
        if !operation_requires_approval(policy, operation) {
            return Ok(ApprovalEnforcementResult {
                decision: ApprovalEnforcementDecision::NotRequired,
                reason: None,
                approval_id: None,
            });
        }

        let approval_id = match supplied_approval_id {
            Some(id) => id,
            None => {
                return Ok(ApprovalEnforcementResult {
                    decision: ApprovalEnforcementDecision::Rejected,
                    reason: Some(ApprovalRejectionReason::ApprovalRequiredButMissing),
                    approval_id: None,
                });
            }
        };

        let decision = match self.store.load_approval_decision(&approval_id)? {
            Some(d) => d,
            None => {
                return Ok(ApprovalEnforcementResult {
                    decision: ApprovalEnforcementDecision::Rejected,
                    reason: Some(ApprovalRejectionReason::ApprovalRecordNotFound),
                    approval_id: Some(approval_id),
                });
            }
        };

        // Validate Decision
        if decision.status != LocalApprovalStatus::Approved {
            return Ok(ApprovalEnforcementResult {
                decision: ApprovalEnforcementDecision::Rejected,
                reason: Some(ApprovalRejectionReason::ApprovalDenied),
                approval_id: Some(approval_id),
            });
        }

        if decision.volume_hash != volume_hash {
            return Ok(ApprovalEnforcementResult {
                decision: ApprovalEnforcementDecision::Rejected,
                reason: Some(ApprovalRejectionReason::ApprovalVolumeMismatch),
                approval_id: Some(approval_id),
            });
        }

        if decision.operation_class != operation {
            return Ok(ApprovalEnforcementResult {
                decision: ApprovalEnforcementDecision::Rejected,
                reason: Some(ApprovalRejectionReason::ApprovalOperationMismatch),
                approval_id: Some(approval_id),
            });
        }

        if decision.policy_id != policy.policy_id {
            return Ok(ApprovalEnforcementResult {
                decision: ApprovalEnforcementDecision::Rejected,
                reason: Some(ApprovalRejectionReason::ApprovalPolicyMismatch),
                approval_id: Some(approval_id),
            });
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if decision.expires_at < now {
            return Ok(ApprovalEnforcementResult {
                decision: ApprovalEnforcementDecision::Rejected,
                reason: Some(ApprovalRejectionReason::ApprovalExpired),
                approval_id: Some(approval_id),
            });
        }

        if decision.consumed_at.is_some() && policy.one_time_approval {
            return Ok(ApprovalEnforcementResult {
                decision: ApprovalEnforcementDecision::Rejected,
                reason: Some(ApprovalRejectionReason::ApprovalAlreadyConsumed),
                approval_id: Some(approval_id),
            });
        }

        Ok(ApprovalEnforcementResult {
            decision: ApprovalEnforcementDecision::Allowed,
            reason: None,
            approval_id: Some(approval_id),
        })
    }

    pub fn consume_approval_if_required(
        &self,
        policy: &LocalPolicy,
        approval_id: &str,
    ) -> Result<()> {
        if policy.one_time_approval {
            self.store.mark_approval_consumed(approval_id)?;
        }
        Ok(())
    }
}
