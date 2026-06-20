use crate::binding_store::BindingStore;
use crate::enterprise_authority::EnterpriseAuthorityPolicy;
use crate::enterprise_provider::{EnterpriseProviderAttestationSummary, EnterpriseProviderPolicy};
use crate::enterprise_provider_enforcement::{
    EnterpriseProviderEnforcementDecision, EnterpriseProviderEnforcer,
};
use crate::enterprise_quorum::{
    evaluate_quorum_decision, EnterpriseQuorumEvaluation, EnterpriseQuorumPolicy,
};
use crate::enterprise_recovery::{
    EnterpriseRecoveryDecision, EnterpriseRecoveryRequest, EnterpriseRecoveryStatus,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseRecoveryEnforcementDecision {
    Allowed,
    Rejected,
    NotRequired,
    ReservedProviderExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseRecoveryRejectionReason {
    MissingAuthorityPolicy,
    MissingQuorumPolicy,
    MissingDecision,
    Denied,
    Expired,
    Consumed,
    OperationMismatch,
    VolumeMismatch,
    DomainRecoveryMismatch,
    AuthorityPolicyMismatch,
    QuorumPolicyMismatch,
    QuorumNotMet,
    ReservedProviderExecution,
}

pub struct EnterpriseRecoveryEnforcer<'a> {
    store: &'a BindingStore,
}

impl<'a> EnterpriseRecoveryEnforcer<'a> {
    pub fn new(store: &'a BindingStore) -> Self {
        Self { store }
    }

    pub fn check_enterprise_recovery(
        &self,
        request: &EnterpriseRecoveryRequest,
        decision: Option<&EnterpriseRecoveryDecision>,
        authority_policy: Option<&EnterpriseAuthorityPolicy>,
        quorum_policy: Option<&EnterpriseQuorumPolicy>,
    ) -> Result<EnterpriseRecoveryEnforcementDecision> {
        let authority_policy = match authority_policy {
            Some(policy) => policy,
            None => return Ok(EnterpriseRecoveryEnforcementDecision::Rejected),
        };
        let quorum_policy = match quorum_policy {
            Some(policy) => policy,
            None => return Ok(EnterpriseRecoveryEnforcementDecision::Rejected),
        };
        let decision = match decision {
            Some(decision) => decision,
            None => return Ok(EnterpriseRecoveryEnforcementDecision::Rejected),
        };

        if decision.status == EnterpriseRecoveryStatus::Denied {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }
        if decision.status == EnterpriseRecoveryStatus::ReservedProviderExecution
            || matches!(
                request.source_kind,
                crate::enterprise_recovery::EnterpriseRecoverySourceKind::ReservedCloudKms
                    | crate::enterprise_recovery::EnterpriseRecoverySourceKind::ReservedHsmProvider
                    | crate::enterprise_recovery::EnterpriseRecoverySourceKind::ReservedKmsProvider
                    | crate::enterprise_recovery::EnterpriseRecoverySourceKind::ReservedPkcs11Hsm
            )
        {
            return Ok(EnterpriseRecoveryEnforcementDecision::ReservedProviderExecution);
        }

        if decision.operation_kind != request.operation_kind {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }
        if decision.volume_hash != request.volume_hash {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }
        if decision.domain_recovery_request_id != request.domain_recovery_request_id
            || decision.domain_recovery_package_id != request.domain_recovery_package_id
            || decision.domain_recovery_decision_id != request.domain_recovery_decision_id
        {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }
        if decision.enterprise_authority_policy_id != authority_policy.policy_id {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }
        if decision.enterprise_quorum_policy_id != quorum_policy.policy_id {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }

        let quorum = evaluate_quorum_decision(quorum_policy, &decision.approver_fingerprints)?;
        if quorum != EnterpriseQuorumEvaluation::Met {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }

        if decision.is_expired(crate::operations::get_now()) {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }
        if decision.is_consumed() {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }

        if authority_policy.policy_id != request.enterprise_authority_policy_id {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }
        if quorum_policy.policy_id != request.enterprise_quorum_policy_id {
            return Ok(EnterpriseRecoveryEnforcementDecision::Rejected);
        }

        Ok(EnterpriseRecoveryEnforcementDecision::Allowed)
    }

    pub fn consume_enterprise_recovery_decision_if_required(
        &self,
        decision_id: &str,
    ) -> Result<()> {
        self.store.mark_enterprise_recovery_consumed(decision_id)
    }

    pub fn check_enterprise_provider(
        &self,
        request: &crate::enterprise_recovery::EnterpriseRecoveryRequest,
        decision: Option<&EnterpriseRecoveryDecision>,
        provider_policy: Option<&EnterpriseProviderPolicy>,
        attestation: Option<&EnterpriseProviderAttestationSummary>,
        authority_policy: Option<&EnterpriseAuthorityPolicy>,
    ) -> Result<EnterpriseProviderEnforcementDecision> {
        EnterpriseProviderEnforcer::new(self.store).check_enterprise_provider(
            request,
            decision,
            provider_policy,
            attestation,
            authority_policy,
        )
    }
}
