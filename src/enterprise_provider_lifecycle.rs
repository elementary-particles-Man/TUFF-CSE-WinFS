use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EnterpriseProviderLifecycleEventId(pub String);

impl std::fmt::Debug for EnterpriseProviderLifecycleEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnterpriseProviderGeneration(pub u64);

impl std::fmt::Debug for EnterpriseProviderGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderLifecycleState {
    Active,
    PendingRotation,
    Superseded,
    Revoked,
    Expired,
    ReservedLiveRefreshRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderLifecycleEventKind {
    ImportedActivation,
    ImportedRevocation,
    ImportedRotationPlan,
    ImportedRotationComplete,
    ImportedAttestationRenewal,
    ReservedLiveRefresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderRevocationReason {
    CompromisedReserved,
    PolicySuperseded,
    AuthorityRevoked,
    AttestationExpired,
    AdministrativeRevocation,
    ReservedLiveProviderFailure,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EnterpriseProviderLifecycleEvent {
    pub event_id: EnterpriseProviderLifecycleEventId,
    pub provider_id: crate::enterprise_provider::EnterpriseProviderPolicyId,
    pub generation: EnterpriseProviderGeneration,
    pub kind: EnterpriseProviderLifecycleEventKind,
    pub state: EnterpriseProviderLifecycleState,
    pub revocation_reason: Option<EnterpriseProviderRevocationReason>,
    pub attestation_hash: Option<crate::enterprise_provider::EnterpriseProviderAttestationHash>,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
}

impl std::fmt::Debug for EnterpriseProviderLifecycleEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnterpriseProviderLifecycleEvent")
            .field("id", &self.event_id.0)
            .field("provider_id", &self.provider_id.0)
            .field("generation", &self.generation.0)
            .field("state", &self.state)
            .field("hash", &self.event_hash)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EnterpriseProviderRotationPlanId(pub String);

impl std::fmt::Debug for EnterpriseProviderRotationPlanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EnterpriseProviderRotationPlan {
    pub plan_id: EnterpriseProviderRotationPlanId,
    pub provider_id: crate::enterprise_provider::EnterpriseProviderPolicyId,
    pub current_generation: EnterpriseProviderGeneration,
    pub next_generation: EnterpriseProviderGeneration,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_hash: Option<String>,
}

impl std::fmt::Debug for EnterpriseProviderRotationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnterpriseProviderRotationPlan")
            .field("id", &self.plan_id.0)
            .field("provider_id", &self.provider_id.0)
            .field("generation", &self.next_generation.0)
            .field("hash", &self.plan_hash)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EnterpriseProviderRotationDecisionId(pub String);

impl std::fmt::Debug for EnterpriseProviderRotationDecisionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EnterpriseProviderRotationDecision {
    pub decision_id: EnterpriseProviderRotationDecisionId,
    pub rotation_plan_id: EnterpriseProviderRotationPlanId,
    pub provider_id: crate::enterprise_provider::EnterpriseProviderPolicyId,
    pub next_generation: EnterpriseProviderGeneration,
    pub approver_fingerprints: Vec<crate::enterprise_quorum::EnterpriseQuorumMemberFingerprint>,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_hash: Option<String>,
}

impl std::fmt::Debug for EnterpriseProviderRotationDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnterpriseProviderRotationDecision")
            .field("id", &self.decision_id.0)
            .field("provider_id", &self.provider_id.0)
            .field("generation", &self.next_generation.0)
            .field("hash", &self.decision_hash)
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct EnterpriseProviderLifecycleEventCanonical<'a> {
    event_id: &'a EnterpriseProviderLifecycleEventId,
    provider_id: &'a crate::enterprise_provider::EnterpriseProviderPolicyId,
    generation: EnterpriseProviderGeneration,
    kind: EnterpriseProviderLifecycleEventKind,
    state: EnterpriseProviderLifecycleState,
    revocation_reason: Option<EnterpriseProviderRevocationReason>,
    attestation_hash: Option<&'a crate::enterprise_provider::EnterpriseProviderAttestationHash>,
    created_at: u64,
}

#[derive(Debug, Serialize)]
struct EnterpriseProviderRotationPlanCanonical<'a> {
    plan_id: &'a EnterpriseProviderRotationPlanId,
    provider_id: &'a crate::enterprise_provider::EnterpriseProviderPolicyId,
    current_generation: EnterpriseProviderGeneration,
    next_generation: EnterpriseProviderGeneration,
    created_at: u64,
}

#[derive(Debug, Serialize)]
struct EnterpriseProviderRotationDecisionCanonical<'a> {
    decision_id: &'a EnterpriseProviderRotationDecisionId,
    rotation_plan_id: &'a EnterpriseProviderRotationPlanId,
    provider_id: &'a crate::enterprise_provider::EnterpriseProviderPolicyId,
    next_generation: EnterpriseProviderGeneration,
    approver_fingerprints: &'a [crate::enterprise_quorum::EnterpriseQuorumMemberFingerprint],
    created_at: u64,
}

pub fn compute_lifecycle_event_hash(event: &EnterpriseProviderLifecycleEvent) -> String {
    let canonical = serde_json::to_vec(&EnterpriseProviderLifecycleEventCanonical {
        event_id: &event.event_id,
        provider_id: &event.provider_id,
        generation: event.generation,
        kind: event.kind,
        state: event.state,
        revocation_reason: event.revocation_reason,
        attestation_hash: event.attestation_hash.as_ref(),
        created_at: event.created_at,
    })
    .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    hex::encode(hasher.finalize())
}

pub fn compute_rotation_plan_hash(plan: &EnterpriseProviderRotationPlan) -> String {
    let canonical = serde_json::to_vec(&EnterpriseProviderRotationPlanCanonical {
        plan_id: &plan.plan_id,
        provider_id: &plan.provider_id,
        current_generation: plan.current_generation,
        next_generation: plan.next_generation,
        created_at: plan.created_at,
    })
    .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    hex::encode(hasher.finalize())
}

pub fn compute_rotation_decision_hash(decision: &EnterpriseProviderRotationDecision) -> String {
    let canonical = serde_json::to_vec(&EnterpriseProviderRotationDecisionCanonical {
        decision_id: &decision.decision_id,
        rotation_plan_id: &decision.rotation_plan_id,
        provider_id: &decision.provider_id,
        next_generation: decision.next_generation,
        approver_fingerprints: &decision.approver_fingerprints,
        created_at: decision.created_at,
    })
    .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    hex::encode(hasher.finalize())
}

pub fn normalize_lifecycle_event(
    mut event: EnterpriseProviderLifecycleEvent,
) -> EnterpriseProviderLifecycleEvent {
    event.event_hash = Some(compute_lifecycle_event_hash(&event));
    event
}

pub fn normalize_rotation_plan(
    mut plan: EnterpriseProviderRotationPlan,
) -> EnterpriseProviderRotationPlan {
    plan.plan_hash = Some(compute_rotation_plan_hash(&plan));
    plan
}

pub fn normalize_rotation_decision(
    mut decision: EnterpriseProviderRotationDecision,
) -> EnterpriseProviderRotationDecision {
    decision.decision_hash = Some(compute_rotation_decision_hash(&decision));
    decision
}

impl EnterpriseProviderLifecycleState {
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked)
    }
    pub fn is_superseded(&self) -> bool {
        matches!(self, Self::Superseded)
    }
    pub fn is_expired(&self) -> bool {
        matches!(self, Self::Expired)
    }
}

impl EnterpriseProviderLifecycleEvent {
    pub fn is_revoked(&self) -> bool {
        self.state.is_revoked()
    }
    pub fn is_superseded(&self) -> bool {
        self.state.is_superseded()
    }
    pub fn is_expired(&self) -> bool {
        self.state.is_expired()
    }
    pub fn generation_matches(&self, gen: EnterpriseProviderGeneration) -> bool {
        self.generation == gen
    }
}
