use crate::binding_store::BindingStore;
use crate::domain_recovery::{
    DomainRecoveryDecision, DomainRecoveryRequest, DomainRecoveryWorkflowState,
};
use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainRecoveryEnforcementDecision {
    Allowed,
    Rejected,
    NotRequired,
    ReservedExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainRecoveryRejectionReason {
    MissingRequest,
    MissingPackage,
    MissingDecision,
    Expired,
    Consumed,
    RequestMismatch,
    PackageMismatch,
    VolumeMismatch,
    PolicyMismatch,
    DomainApprovalMissing,
    DomainApprovalRejected,
    OfflineSnapshotInvalid,
    LocalApprovalRequired,
    ManualConfirmationRequired,
    ReservedExecution,
}

pub struct DomainRecoveryEnforcer<'a> {
    store: &'a BindingStore,
}

impl<'a> DomainRecoveryEnforcer<'a> {
    pub fn new(store: &'a BindingStore) -> Self {
        Self { store }
    }

    pub fn check_recovery_workflow(
        &self,
        decision: Option<&DomainRecoveryDecision>,
        request: &DomainRecoveryRequest,
        operation: crate::operations::OperationKind,
    ) -> Result<DomainRecoveryEnforcementDecision> {
        // P5C Logic - Placeholder for actual workflow validation
        if let Some(d) = decision {
            if d.request_id != request.request_id
                || d.status != DomainRecoveryWorkflowState::Authorized
            {
                return Ok(DomainRecoveryEnforcementDecision::Rejected);
            }
            if d.is_expired(crate::operations::get_now()) || d.is_consumed() {
                return Ok(DomainRecoveryEnforcementDecision::Rejected);
            }
            return Ok(DomainRecoveryEnforcementDecision::Allowed);
        }
        Ok(DomainRecoveryEnforcementDecision::Rejected)
    }

    pub fn consume_recovery_decision_if_required(&self, decision_id: &str) -> Result<()> {
        self.store.mark_domain_recovery_consumed(decision_id)
    }
}
