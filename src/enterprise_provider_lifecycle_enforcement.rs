use crate::binding_store::BindingStore;
use crate::enterprise_provider::{EnterpriseProviderAttestationSummary, EnterpriseProviderPolicy};
use crate::enterprise_provider_lifecycle::{
    EnterpriseProviderLifecycleEvent, EnterpriseProviderLifecycleEventKind,
    EnterpriseProviderLifecycleState, EnterpriseProviderRevocationReason,
};
use crate::enterprise_recovery::{EnterpriseRecoveryDecision, EnterpriseRecoveryRequest};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderLifecycleEnforcementDecision {
    Allowed,
    Rejected(EnterpriseProviderLifecycleRejectionReason),
    NotRequired,
    ReservedLiveRefreshRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderLifecycleRejectionReason {
    MissingLifecycleState,
    ProviderRevoked,
    ProviderSuperseded,
    ProviderExpired,
    GenerationMismatch,
    RotationIncomplete,
    LifecycleHashMismatch,
    AttestationRenewalRequired,
    ReservedLiveRefreshRequired,
}

pub struct EnterpriseProviderLifecycleEnforcer<'a> {
    store: &'a BindingStore,
}

impl<'a> EnterpriseProviderLifecycleEnforcer<'a> {
    pub fn new(store: &'a BindingStore) -> Self {
        Self { store }
    }

    pub fn check_provider_lifecycle(
        &self,
        request: &EnterpriseRecoveryRequest,
        decision: Option<&EnterpriseRecoveryDecision>,
        provider_policy: Option<&EnterpriseProviderPolicy>,
        attestation: Option<&EnterpriseProviderAttestationSummary>,
    ) -> Result<EnterpriseProviderLifecycleEnforcementDecision> {
        let provider_id = match &request.enterprise_provider_id {
            Some(id) => id,
            None => return Ok(EnterpriseProviderLifecycleEnforcementDecision::NotRequired),
        };

        // Load latest lifecycle event for the provider
        let latest_event = match self
            .store
            .find_latest_provider_lifecycle_event(provider_id)?
        {
            Some(event) => event,
            None => {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::MissingLifecycleState,
                ));
            }
        };

        // Validate lifecycle event hash
        let computed_event_hash =
            crate::enterprise_provider_lifecycle::compute_lifecycle_event_hash(&latest_event);
        if latest_event.event_hash.as_deref() != Some(&computed_event_hash) {
            return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                EnterpriseProviderLifecycleRejectionReason::LifecycleHashMismatch,
            ));
        }

        // Validate rotation plans hash integrity if any exist
        let active_plan = self.store.find_latest_rotation_plan(provider_id)?;
        if let Some(ref plan) = active_plan {
            let computed_plan_hash =
                crate::enterprise_provider_lifecycle::compute_rotation_plan_hash(plan);
            if plan.plan_hash.as_deref() != Some(&computed_plan_hash) {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::LifecycleHashMismatch,
                ));
            }
        }

        // Verify lifecycle state
        match latest_event.state {
            EnterpriseProviderLifecycleState::Revoked => {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::ProviderRevoked,
                ));
            }
            EnterpriseProviderLifecycleState::Superseded => {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::ProviderSuperseded,
                ));
            }
            EnterpriseProviderLifecycleState::Expired => {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::ProviderExpired,
                ));
            }
            EnterpriseProviderLifecycleState::ReservedLiveRefreshRequired => {
                return Ok(
                    EnterpriseProviderLifecycleEnforcementDecision::ReservedLiveRefreshRequired,
                );
            }
            _ => {}
        }

        // Active generation is determined by the latest lifecycle event.
        let active_gen = latest_event.generation;

        // Verify provider policy generation and hash integrity if provided
        if let Some(policy) = provider_policy {
            if policy.policy_id.0 != *provider_id {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::GenerationMismatch,
                ));
            }
            // Verify computed policy hash matches stored hash
            let computed_policy_hash =
                crate::enterprise_provider::compute_enterprise_provider_policy_hash(policy);
            if policy.policy_hash.as_ref().map(|h| &h.0) != Some(&computed_policy_hash.0) {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::LifecycleHashMismatch,
                ));
            }

            if let Some(p_gen) = policy.provider_generation {
                if p_gen != active_gen.0 {
                    return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                        EnterpriseProviderLifecycleRejectionReason::GenerationMismatch,
                    ));
                }
            } else if active_gen.0 != 1 {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::GenerationMismatch,
                ));
            }
        }

        // Verify attestation generation and hash integrity if provided
        if let Some(att) = attestation {
            if att.enterprise_provider_id.0 != *provider_id {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::GenerationMismatch,
                ));
            }
            // Verify computed attestation hash matches stored hash
            let computed_att_hash =
                crate::enterprise_provider::compute_enterprise_provider_attestation_hash(att);
            if att.attestation_hash.as_ref().map(|h| &h.0) != Some(&computed_att_hash.0) {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::LifecycleHashMismatch,
                ));
            }

            if let Some(a_gen) = att.provider_generation {
                if a_gen != active_gen.0 {
                    return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                        EnterpriseProviderLifecycleRejectionReason::GenerationMismatch,
                    ));
                }
            } else if active_gen.0 != 1 {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::GenerationMismatch,
                ));
            }

            // If the latest event is ImportedAttestationRenewal, check if attestation matches its hash
            if latest_event.kind == EnterpriseProviderLifecycleEventKind::ImportedAttestationRenewal
            {
                if let Some(ref expected_att_hash) = latest_event.attestation_hash {
                    if att.attestation_hash.as_ref() != Some(expected_att_hash) {
                        return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                            EnterpriseProviderLifecycleRejectionReason::AttestationRenewalRequired,
                        ));
                    }
                }
            }
        }

        // Verify decision generation and hash integrity if provided
        if let Some(dec) = decision {
            if dec.enterprise_provider_id.as_deref() != Some(provider_id.as_str()) {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::GenerationMismatch,
                ));
            }

            // Verify computed decision hash matches stored hash
            let computed_dec_hash =
                crate::enterprise_recovery::compute_enterprise_recovery_decision_hash(dec);
            if dec.decision_hash.0 != computed_dec_hash.0 {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::LifecycleHashMismatch,
                ));
            }

            if let Some(d_gen) = dec.enterprise_provider_generation {
                // If a rotation is pending (state is PendingRotation), the active generation is G.
                // But a rotation plan exists from G to G+1.
                // If the decision uses G+1, check if rotation is complete.
                // If state is PendingRotation and decision has G+1, reject with RotationIncomplete.
                if latest_event.state == EnterpriseProviderLifecycleState::PendingRotation {
                    if let Some(ref plan) = active_plan {
                        if d_gen == plan.next_generation.0 {
                            return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                                EnterpriseProviderLifecycleRejectionReason::RotationIncomplete,
                            ));
                        }
                    }
                }

                // If active generation has been updated (e.g. state is Active and active_gen is G+1),
                // but decision has the old generation G, reject it with GenerationMismatch.
                if d_gen != active_gen.0 {
                    return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                        EnterpriseProviderLifecycleRejectionReason::GenerationMismatch,
                    ));
                }
            } else if active_gen.0 != 1 {
                return Ok(EnterpriseProviderLifecycleEnforcementDecision::Rejected(
                    EnterpriseProviderLifecycleRejectionReason::GenerationMismatch,
                ));
            }
        }

        Ok(EnterpriseProviderLifecycleEnforcementDecision::Allowed)
    }
}
