use crate::binding_store::BindingStore;
use crate::domain_approval::{DomainApprovalDecision, DomainApprovalStatus};
use crate::domain_policy::{DomainPolicy, DomainPolicyEffect};
use crate::offline_policy_snapshot::OfflinePolicySnapshot;
use crate::operations::OperationKind;
use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainApprovalEnforcementDecision {
    Allowed,
    Rejected,
    NotRequired,
    ReservedLiveVerificationRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainApprovalRejectionReason {
    MissingDecision,
    MissingSnapshot,
    Denied,
    Expired,
    Consumed,
    OperationMismatch,
    VolumeMismatch,
    PolicyMismatch,
    MappingMismatch,
    SnapshotMismatch,
    DomainAuthorityMismatch,
    SnapshotExpired,
    SnapshotHashMismatch,
    ReservedLiveVerification,
}

pub struct DomainApprovalEnforcer<'a> {
    store: &'a BindingStore,
}

impl<'a> DomainApprovalEnforcer<'a> {
    pub fn new(store: &'a BindingStore) -> Self {
        Self { store }
    }

    pub fn check_required_domain_approval(
        &self,
        decision: Option<&DomainApprovalDecision>,
        operation: OperationKind,
        volume_hash: &str,
        domain_policy: &DomainPolicy,
        snapshot: Option<&OfflinePolicySnapshot>,
    ) -> Result<DomainApprovalEnforcementDecision> {
        // P5B Logic
        // 1. Check if domain approval is actually required by policy (Reserved for P5B)
        // 2. If required, verify decision
        if let Some(d) = decision {
             if d.operation_kind != operation || d.volume_hash != volume_hash || d.domain_policy_id != domain_policy.domain_policy_id {
                 return Ok(DomainApprovalEnforcementDecision::Rejected);
             }
             if d.is_expired(crate::operations::get_now()) || d.is_consumed() {
                 return Ok(DomainApprovalEnforcementDecision::Rejected);
             }
             return Ok(DomainApprovalEnforcementDecision::Allowed);
        }
        Ok(DomainApprovalEnforcementDecision::Rejected)
    }

    pub fn consume_domain_approval_if_required(&self, decision_id: &str) -> Result<()> {
        self.store.mark_domain_approval_consumed(decision_id)
    }
}
