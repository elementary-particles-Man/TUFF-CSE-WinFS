use crate::binding_store::BindingStore;
use crate::enterprise_authority::EnterpriseAuthorityPolicy;
use crate::enterprise_provider::{
    is_reserved_live_provider_kind, required_provider_capability_for_operation,
    EnterpriseProviderAttestationSummary, EnterpriseProviderHealth, EnterpriseProviderPolicy,
};
use crate::enterprise_recovery::{EnterpriseRecoveryDecision, EnterpriseRecoveryRequest};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderEnforcementDecision {
    Allowed,
    Rejected,
    NotRequired,
    ReservedLiveProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderRejectionReason {
    MissingProviderPolicy,
    MissingAttestation,
    ProviderRevoked,
    ProviderKindMismatch,
    CapabilityMissing,
    AuthorityMismatch,
    AttestationExpired,
    AttestationHashMismatch,
    ReservedLiveProvider,
}

pub struct EnterpriseProviderEnforcer<'a> {
    store: &'a BindingStore,
}

impl<'a> EnterpriseProviderEnforcer<'a> {
    pub fn new(store: &'a BindingStore) -> Self {
        Self { store }
    }

    pub fn check_enterprise_provider(
        &self,
        request: &EnterpriseRecoveryRequest,
        decision: Option<&EnterpriseRecoveryDecision>,
        provider_policy: Option<&EnterpriseProviderPolicy>,
        attestation: Option<&EnterpriseProviderAttestationSummary>,
        authority_policy: Option<&EnterpriseAuthorityPolicy>,
    ) -> Result<EnterpriseProviderEnforcementDecision> {
        let _ = decision;
        let provider_id = match request.enterprise_provider_id.as_ref() {
            Some(provider_id) => provider_id,
            None => return Ok(EnterpriseProviderEnforcementDecision::NotRequired),
        };

        let provider_policy = match provider_policy {
            Some(policy) => policy,
            None => return Ok(EnterpriseProviderEnforcementDecision::Rejected),
        };

        if is_reserved_live_provider_kind(provider_policy.provider_kind) {
            return Ok(EnterpriseProviderEnforcementDecision::ReservedLiveProvider);
        }

        if let Some(decision) = decision {
            if decision.enterprise_provider_id.as_deref() != Some(provider_id.as_str()) {
                return Ok(EnterpriseProviderEnforcementDecision::Rejected);
            }
            if decision.provider_attestation_hash.as_deref()
                != request.provider_attestation_hash.as_deref()
            {
                return Ok(EnterpriseProviderEnforcementDecision::Rejected);
            }
        }

        if provider_policy.policy_id.0 != *provider_id {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }

        if let Some(authority_policy) = authority_policy {
            if provider_policy.enterprise_authority_policy_id != authority_policy.policy_id {
                return Ok(EnterpriseProviderEnforcementDecision::Rejected);
            }
        }
        if provider_policy.enterprise_authority_policy_id != request.enterprise_authority_policy_id
        {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }
        if provider_policy.health == EnterpriseProviderHealth::Revoked {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }

        let attestation = match attestation {
            Some(attestation) => attestation,
            None => return Ok(EnterpriseProviderEnforcementDecision::Rejected),
        };

        if attestation.enterprise_provider_id != provider_policy.policy_id {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }
        if attestation.enterprise_authority_policy_id
            != provider_policy.enterprise_authority_policy_id
            || attestation.enterprise_authority_policy_id != request.enterprise_authority_policy_id
        {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }
        if attestation.provider_kind != provider_policy.provider_kind {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }
        if attestation.is_revoked() || provider_policy.health == EnterpriseProviderHealth::Revoked {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }
        if attestation.is_expired(crate::operations::get_now()) {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }

        let required_capability =
            required_provider_capability_for_operation(request.operation_kind);
        if !provider_policy.capabilities.contains(&required_capability) {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }

        if request
            .provider_attestation_hash
            .as_ref()
            .zip(attestation.attestation_hash.as_ref())
            .map(|(lhs, rhs)| lhs != &rhs.0)
            .unwrap_or(false)
        {
            return Ok(EnterpriseProviderEnforcementDecision::Rejected);
        }

        Ok(EnterpriseProviderEnforcementDecision::Allowed)
    }

    pub fn load_latest_enterprise_provider_attestation(
        &self,
        provider_id: &str,
        attestation_hash: Option<&str>,
    ) -> Result<Option<EnterpriseProviderAttestationSummary>> {
        self.store
            .find_valid_enterprise_provider_attestation_summary(provider_id, attestation_hash)
    }
}
