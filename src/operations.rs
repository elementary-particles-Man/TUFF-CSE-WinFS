use crate::approval_enforcement::{
    ApprovalEnforcementDecision, ApprovalEnforcer, ApprovalRejectionReason,
};
use crate::audit_chain::{self, canonicalize_journal_payload, AuditChainState};
use crate::audit_signing::{self, AuditSigner, DevAuditSigner};
use crate::binding::{self, BindingInputSnapshot};
use crate::binding_policy;
use crate::binding_store::BindingStore;
use crate::enterprise_authority;
use crate::enterprise_quorum;
use crate::enterprise_recovery;
use crate::enterprise_recovery::{
    EnterpriseRecoveryDecision, EnterpriseRecoveryRequest, EnterpriseRecoverySourceKind,
};
use crate::enterprise_recovery_enforcement::{
    EnterpriseRecoveryEnforcementDecision, EnterpriseRecoveryEnforcer,
};
use crate::export_manifest::{self, ExportRecipient};
use crate::export_policy;
use crate::key_material;
use crate::local_policy::{LocalOperationClass, LocalPolicy};
use crate::managed_policy::ManagedPolicy;
use crate::manual_flow::{self, ManualFlowKind};
use crate::plan_state::PlanLifecycleStatus;
use crate::rebind_model::{self, RebindPolicy};
use crate::recovery_key::{self, RecoveryPolicy};
use crate::runtime_session::{RuntimeSession, RuntimeSessionStatus};
use crate::volume_state::{VolumeBindingState, VolumeRuntimeState};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationKind {
    Status,
    Bind,
    Unlock,
    Lock,
    Eject,
    Audit,
    Export,
    Rebind,
    Recover,
    ManualComplete,
    ManualCancel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationStatus {
    Accepted,
    Rejected,
    Reserved,
    PendingDriverPhase,
    PendingCryptoPhase,
    PendingBindingPhase,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRequest {
    pub operation_id: String,
    pub kind: OperationKind,
    pub volume: String,
    pub requested_by: String,
    pub policy_id: String,
    pub timestamp: u64,
    pub approval_id: Option<String>,
    pub enterprise_authority_policy_id: Option<String>,
    pub enterprise_quorum_policy_id: Option<String>,
    pub enterprise_recovery_decision_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    pub operation_id: String,
    pub kind: OperationKind,
    pub volume: String,
    pub status: OperationStatus,
    pub previous_state: VolumeBindingState,
    pub next_state: VolumeBindingState,
    pub reason: String,
    pub timestamp: u64,
    pub approval_enforcement_decision: Option<ApprovalEnforcementDecision>,
    pub approval_rejection_reason: Option<ApprovalRejectionReason>,
}

pub fn get_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn execute_operation(
    request: OperationRequest,
    policy: &ManagedPolicy,
    state: &mut VolumeRuntimeState,
) -> Result<OperationResult> {
    let previous_state = state.current;
    let mut next_state = previous_state;
    let mut status = OperationStatus::Rejected;
    let reason;

    // Policy Check
    let allowed = match request.kind {
        OperationKind::Status => policy.allow_status,
        OperationKind::Bind => policy.allow_bind,
        OperationKind::Unlock => policy.allow_unlock,
        OperationKind::Lock => policy.allow_lock,
        OperationKind::Eject => policy.allow_eject,
        OperationKind::Audit => policy.allow_audit,
        OperationKind::Export => policy.allow_export,
        OperationKind::Rebind => policy.allow_rebind,
        OperationKind::Recover => policy.allow_recover,
        OperationKind::ManualComplete | OperationKind::ManualCancel => true,
    };

    if !allowed {
        reason = "Operation denied by policy".to_string();
        return Ok(build_result(
            &request,
            status,
            previous_state,
            next_state,
            reason,
        ));
    }

    match request.kind {
        OperationKind::Status
        | OperationKind::Audit
        | OperationKind::Export
        | OperationKind::Recover
        | OperationKind::Rebind
        | OperationKind::ManualComplete
        | OperationKind::ManualCancel => {
            status = OperationStatus::Accepted;
            reason = "Success".to_string();
        }
        OperationKind::Bind => {
            if previous_state == VolumeBindingState::Unregistered {
                next_state = VolumeBindingState::BoundLocked;
                status = OperationStatus::PendingBindingPhase;
                reason = "Binding phase pending".to_string();
            } else {
                reason = "Invalid state transition for Bind".to_string();
            }
        }
        OperationKind::Unlock => {
            if previous_state == VolumeBindingState::BoundLocked
                || previous_state == VolumeBindingState::Locked
            {
                next_state = VolumeBindingState::Unlocked;
                status = OperationStatus::PendingCryptoPhase;
                reason = "Crypto phase pending".to_string();
            } else {
                reason = "Invalid state transition for Unlock".to_string();
            }
        }
        OperationKind::Lock => {
            if previous_state == VolumeBindingState::Unlocked {
                next_state = VolumeBindingState::Locked;
                status = OperationStatus::PendingDriverPhase;
                reason = "Driver phase pending".to_string();
            } else {
                reason = "Invalid state transition for Lock".to_string();
            }
        }
        OperationKind::Eject => {
            if previous_state == VolumeBindingState::Locked
                || previous_state == VolumeBindingState::BoundLocked
            {
                next_state = VolumeBindingState::CleanRemoved;
                status = OperationStatus::PendingDriverPhase;
                reason = "Driver phase pending".to_string();
            } else {
                reason = "Invalid state transition for Eject".to_string();
            }
        }
    }

    state.current = next_state;

    Ok(build_result(
        &request,
        status,
        previous_state,
        next_state,
        reason,
    ))
}

fn build_result(
    request: &OperationRequest,
    status: OperationStatus,
    prev: VolumeBindingState,
    next: VolumeBindingState,
    reason: String,
) -> OperationResult {
    OperationResult {
        operation_id: request.operation_id.clone(),
        kind: request.kind,
        volume: request.volume.clone(),
        status,
        previous_state: prev,
        next_state: next,
        reason,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        approval_enforcement_decision: None,
        approval_rejection_reason: None,
    }
}

pub fn execute_managed_operation(
    request: OperationRequest,
    policy: &ManagedPolicy,
    store: &BindingStore,
    local_policy: Option<&LocalPolicy>,
) -> Result<OperationResult> {
    let mut state = store.load_volume_state(&request.volume)?;
    let dummy_hash = BindingStore::volume_hash(&request.volume);

    // Optional Enforcement for Unlock/Eject if policy provided
    let mut enf_result = None;
    if let Some(lp) = local_policy {
        let op_class = match request.kind {
            OperationKind::Unlock => Some(LocalOperationClass::Unlock),
            OperationKind::Eject => Some(LocalOperationClass::Eject),
            _ => None,
        };
        if let Some(oc) = op_class {
            let enforcer = ApprovalEnforcer::new(store);
            let res = enforcer.check_required_approval(
                lp,
                oc,
                &dummy_hash,
                request.approval_id.clone(),
            )?;
            if res.decision == ApprovalEnforcementDecision::Rejected {
                let mut op_res = build_result(
                    &request,
                    OperationStatus::Rejected,
                    state.current,
                    state.current,
                    format!("CSE-APPROVAL-REJECTION: {:?}", res.reason.unwrap()),
                );
                op_res.approval_enforcement_decision = Some(res.decision);
                op_res.approval_rejection_reason = res.reason;
                return Ok(op_res);
            }
            enf_result = Some(res);
        }
    }

    // For bind/unlock, we need to ensure binding descriptor exists (except for bind which creates it)
    if request.kind != OperationKind::Bind
        && request.kind != OperationKind::Status
        && request.kind != OperationKind::Audit
    {
        if store.load_binding_descriptor(&request.volume)?.is_none() {
            return Ok(build_result(
                &request,
                OperationStatus::Rejected,
                state.current,
                state.current,
                "Binding not found. Cannot perform operation.".to_string(),
            ));
        }
    }

    let result = execute_operation(request.clone(), policy, &mut state)?;

    if result.status == OperationStatus::Rejected || result.status == OperationStatus::Reserved {
        return Ok(result);
    }

    // Prepare journal record
    let mut record_template = crate::operation_journal::OperationJournalRecord {
        seq: 0,
        phase: crate::operation_journal::OperationJournalPhase::Begin,
        operation_id: result.operation_id.clone(),
        kind: result.kind,
        volume: result.volume.clone(),
        requested_by: request.requested_by.clone(),
        result_status: result.status.clone(),
        previous_state: result.previous_state,
        next_state: result.next_state,
        descriptor_id: None,
        plan_id: None,
        session_id: None,
        manual_flow_id: None,
        approval_id: enf_result.as_ref().and_then(|r| r.approval_id.clone()),
        decision_id: None,
        enterprise_authority_policy_id: None,
        enterprise_quorum_policy_id: None,
        enterprise_recovery_request_id: None,
        enterprise_recovery_decision_id: None,
        enterprise_recovery_status: None,
        enterprise_recovery_enforcement_status: None,
        enterprise_recovery_rejection_reason: None,
        approval_status: enf_result.as_ref().map(|_| "Approved".to_string()),
        recovery_reason: None,
        reason: result.reason.clone(),
        timestamp: result.timestamp,
        record_hash: None,
        previous_record_hash: None,
        chain_hash: None,
        signing_key_id: None,
        signature_algorithm: None,
        signature: None,
        signed_at: None,
    };

    // Append Begin
    if request.kind != OperationKind::Status && request.kind != OperationKind::Audit {
        // P4C: Stub - get signer and chain state, then append_signed_record
        // For now, continue unsigned for Begin
        let _ = crate::operation_journal::append_begin_record(
            store.root_path(),
            &dummy_hash,
            record_template.clone(),
        );
    }

    // Persist state updates and handle specific operation logic
    match result.kind {
        OperationKind::Bind => {
            let input = BindingInputSnapshot {
                raw_tpm_identity: Some("MOCK_TPM_EK_PUB".to_string()),
                raw_host_id: Some("MOCK_HOST_UUID".to_string()),
                raw_device_uuid: Some("MOCK_DEVICE_UUID".to_string()),
                raw_volume_serial: Some("MOCK_VOL_SERIAL".to_string()),
                raw_policy_material: Some("MOCK_POLICY_MATERIAL".to_string()),
                installer_entropy_bytes: Some(vec![1, 2, 3, 4]),
            };
            let binding_policy = binding_policy::default_single_host_local_policy();
            let global_salt = "SYSTEM_UNIQUE_SALT_STUB";
            let descriptor = binding::build_binding_descriptor(
                &binding_policy,
                &input,
                &request.volume,
                global_salt,
            )?;
            let plan = key_material::build_key_derivation_plan(&descriptor, &binding_policy)?;

            store.save_binding_descriptor(&descriptor)?;
            store.save_key_derivation_plan(&request.volume, &plan)?;
            store.save_volume_state(&request.volume, &state)?;
        }
        OperationKind::Unlock => {
            let descriptor = store.load_binding_descriptor(&request.volume)?.unwrap();
            let plan = store.load_key_derivation_plan(&request.volume)?.unwrap();
            let session = RuntimeSession {
                session_id: format!("SESS-{}", result.operation_id),
                volume_hash: dummy_hash.clone(),
                descriptor_id: descriptor.descriptor_id,
                plan_id: plan.plan_id,
                status: RuntimeSessionStatus::UnlockedPlaceholder,
                created_at: result.timestamp,
                last_transition_at: result.timestamp,
                zeroize_required: false,
                zeroized_at: None,
            };
            store.save_runtime_session(&session)?;
            store.save_volume_state(&request.volume, &state)?;
        }
        OperationKind::Lock => {
            if let Some(mut session) = store.load_runtime_session(&dummy_hash)? {
                session.mark_zeroize_required();
                session.mark_zeroized(result.timestamp);
                store.save_runtime_session(&session)?;
            }
            store.save_volume_state(&request.volume, &state)?;
        }
        OperationKind::Eject => {
            store.clear_runtime_session(&dummy_hash)?;
            store.save_volume_state(&request.volume, &state)?;
        }
        _ => {}
    }

    // Mark approval consumed if required
    if let (Some(lp), Some(enf)) = (local_policy, enf_result) {
        if enf.decision == ApprovalEnforcementDecision::Allowed {
            if let Some(aid) = enf.approval_id {
                let enforcer = ApprovalEnforcer::new(store);
                enforcer.consume_approval_if_required(lp, &aid)?;
            }
        }
    }

    // Append Commit
    if request.kind != OperationKind::Status && request.kind != OperationKind::Audit {
        record_template.seq = 1; // Simplistic seq
        let _ = crate::operation_journal::append_commit_record(
            store.root_path(),
            &dummy_hash,
            record_template,
        );
    }

    Ok(result)
}

pub fn execute_export_operation(
    request: OperationRequest,
    _policy: &ManagedPolicy,
    export_policy: &export_policy::ExportPolicy,
    store: &BindingStore,
    recipient: ExportRecipient,
    require_manual_confirmation: bool,
    local_policy: &LocalPolicy,
) -> Result<OperationResult> {
    let state = store.load_volume_state(&request.volume)?;
    let dummy_hash = BindingStore::volume_hash(&request.volume);

    // Enforcement Check
    let enforcer = ApprovalEnforcer::new(store);
    let enf_result = enforcer.check_required_approval(
        local_policy,
        LocalOperationClass::Export,
        &dummy_hash,
        request.approval_id.clone(),
    )?;

    if enf_result.decision == ApprovalEnforcementDecision::Rejected {
        let mut res = build_result(
            &request,
            OperationStatus::Rejected,
            state.current,
            state.current,
            format!("CSE-APPROVAL-REJECTION: {:?}", enf_result.reason.unwrap()),
        );
        res.approval_enforcement_decision = Some(enf_result.decision);
        res.approval_rejection_reason = enf_result.reason;
        return Ok(res);
    }

    if state.current == VolumeBindingState::Unregistered
        || state.current == VolumeBindingState::RecoveryRequired
    {
        return Ok(build_result(
            &request,
            OperationStatus::Rejected,
            state.current,
            state.current,
            "Invalid source state for export".to_string(),
        ));
    }

    if store.load_binding_descriptor(&request.volume)?.is_none() {
        return Ok(build_result(
            &request,
            OperationStatus::Rejected,
            state.current,
            state.current,
            "Binding not found. Cannot perform operation.".to_string(),
        ));
    }

    // Prepare journal record
    let mut record_template = crate::operation_journal::OperationJournalRecord {
        seq: 0,
        phase: crate::operation_journal::OperationJournalPhase::Begin,
        operation_id: request.operation_id.clone(),
        kind: OperationKind::Export,
        volume: request.volume.clone(),
        requested_by: request.requested_by.clone(),
        result_status: OperationStatus::Accepted,
        previous_state: state.current,
        next_state: state.current,
        descriptor_id: None,
        plan_id: None,
        session_id: None,
        manual_flow_id: None,
        approval_id: enf_result.approval_id.clone(),
        decision_id: None,
        enterprise_authority_policy_id: None,
        enterprise_quorum_policy_id: None,
        enterprise_recovery_request_id: None,
        enterprise_recovery_decision_id: None,
        enterprise_recovery_status: None,
        enterprise_recovery_enforcement_status: None,
        enterprise_recovery_rejection_reason: None,
        approval_status: if enf_result.decision == ApprovalEnforcementDecision::Allowed {
            Some("Approved".to_string())
        } else {
            None
        },
        recovery_reason: None,
        reason: "Exporting manifest".to_string(),
        timestamp: request.timestamp,
        record_hash: None,
        previous_record_hash: None,
        chain_hash: None,
        signing_key_id: None,
        signature_algorithm: None,
        signature: None,
        signed_at: None,
    };

    let _ = crate::operation_journal::append_begin_record(
        store.root_path(),
        &dummy_hash,
        record_template.clone(),
    );

    let mut plan =
        export_manifest::build_export_plan(store, &request.volume, export_policy, recipient)?;
    if require_manual_confirmation {
        plan.status = PlanLifecycleStatus::ManualConfirmationRequired;
    }

    let manifest =
        export_manifest::build_export_manifest(&plan, export_policy, request.operation_id.clone());

    store.save_export_plan(&plan)?;
    store.save_export_manifest(&manifest)?;

    record_template.plan_id = Some(plan.plan_id.clone());

    // Consume approval if allowed
    if enf_result.decision == ApprovalEnforcementDecision::Allowed {
        if let Some(aid) = enf_result.approval_id {
            enforcer.consume_approval_if_required(local_policy, &aid)?;
        }
    }

    let _ = crate::operation_journal::append_commit_record(
        store.root_path(),
        &dummy_hash,
        record_template,
    );

    let mut final_res = build_result(
        &request,
        OperationStatus::Accepted,
        state.current,
        state.current,
        format!("Export manifest generated: {}", manifest.manifest_id),
    );
    final_res.approval_enforcement_decision = Some(enf_result.decision);
    Ok(final_res)
}

pub fn execute_recover_operation(
    request: OperationRequest,
    _policy: &ManagedPolicy,
    recovery_policy: &RecoveryPolicy,
    store: &BindingStore,
    recovery_key_fingerprint: String,
    reason_code: String,
    local_policy: &LocalPolicy,
) -> Result<OperationResult> {
    let state = store.load_volume_state(&request.volume)?;
    let dummy_hash = BindingStore::volume_hash(&request.volume);

    if state.current == VolumeBindingState::Unregistered {
        return Ok(build_result(
            &request,
            OperationStatus::Rejected,
            state.current,
            state.current,
            "Invalid source state for recover".to_string(),
        ));
    }

    let enterprise_request = if let Some(enterprise_decision_id) =
        request.enterprise_recovery_decision_id.as_ref()
    {
        let enterprise_decision = store
            .load_enterprise_recovery_decision(enterprise_decision_id)?
            .ok_or_else(|| anyhow::anyhow!("enterprise recovery decision not found"))?;
        let enterprise_request = EnterpriseRecoveryRequest {
            request_id: enterprise_recovery::EnterpriseRecoveryRequestId(format!(
                "ERQ-{}",
                request.operation_id
            )),
            operation_kind: request.kind,
            volume_hash: dummy_hash.clone(),
            domain_recovery_request_id: enterprise_decision.domain_recovery_request_id.clone(),
            domain_recovery_package_id: enterprise_decision.domain_recovery_package_id.clone(),
            domain_recovery_decision_id: enterprise_decision.domain_recovery_decision_id.clone(),
            enterprise_authority_policy_id: enterprise_decision
                .enterprise_authority_policy_id
                .clone(),
            enterprise_quorum_policy_id: enterprise_decision.enterprise_quorum_policy_id.clone(),
            source_kind: enterprise_decision.source_kind,
            created_at: request.timestamp,
        };

        let authority_policy = store
            .load_enterprise_authority_policy(&enterprise_request.enterprise_authority_policy_id.0)?
            .ok_or_else(|| anyhow::anyhow!("enterprise authority policy not found"))?;
        let quorum_policy = store
            .load_enterprise_quorum_policy(&enterprise_request.enterprise_quorum_policy_id.0)?
            .ok_or_else(|| anyhow::anyhow!("enterprise quorum policy not found"))?;
        let enforcer = EnterpriseRecoveryEnforcer::new(store);
        match enforcer.check_enterprise_recovery(
            &enterprise_request,
            Some(&enterprise_decision),
            Some(&authority_policy),
            Some(&quorum_policy),
        )? {
            EnterpriseRecoveryEnforcementDecision::Allowed => {
                Some((enterprise_request, enterprise_decision))
            }
            EnterpriseRecoveryEnforcementDecision::Rejected => {
                return Ok(build_result(
                    &request,
                    OperationStatus::Rejected,
                    state.current,
                    state.current,
                    "Enterprise recovery gate rejected".to_string(),
                ));
            }
            EnterpriseRecoveryEnforcementDecision::ReservedProviderExecution => {
                return Ok(build_result(
                    &request,
                    OperationStatus::Reserved,
                    state.current,
                    state.current,
                    "Enterprise recovery reserved provider execution".to_string(),
                ));
            }
            EnterpriseRecoveryEnforcementDecision::NotRequired => None,
        }
    } else {
        None
    };

    // Enforcement Check
    let enforcer = ApprovalEnforcer::new(store);
    let enf_result = enforcer.check_required_approval(
        local_policy,
        LocalOperationClass::Recover,
        &dummy_hash,
        request.approval_id.clone(),
    )?;

    if enf_result.decision == ApprovalEnforcementDecision::Rejected {
        let mut res = build_result(
            &request,
            OperationStatus::Rejected,
            state.current,
            state.current,
            format!("CSE-APPROVAL-REJECTION: {:?}", enf_result.reason.unwrap()),
        );
        res.approval_enforcement_decision = Some(enf_result.decision);
        res.approval_rejection_reason = enf_result.reason;
        return Ok(res);
    }

    // Prepare journal record
    let record_template = crate::operation_journal::OperationJournalRecord {
        seq: 0,
        phase: crate::operation_journal::OperationJournalPhase::Begin,
        operation_id: request.operation_id.clone(),
        kind: OperationKind::Recover,
        volume: request.volume.clone(),
        requested_by: request.requested_by.clone(),
        result_status: OperationStatus::Accepted,
        previous_state: state.current,
        next_state: state.current,
        descriptor_id: None,
        plan_id: None,
        session_id: None,
        manual_flow_id: None,
        approval_id: enf_result.approval_id.clone(),
        decision_id: None,
        enterprise_authority_policy_id: enterprise_request
            .as_ref()
            .map(|(request, _)| request.enterprise_authority_policy_id.0.clone()),
        enterprise_quorum_policy_id: enterprise_request
            .as_ref()
            .map(|(request, _)| request.enterprise_quorum_policy_id.0.clone()),
        enterprise_recovery_request_id: enterprise_request
            .as_ref()
            .map(|(request, _)| request.request_id.0.clone()),
        enterprise_recovery_decision_id: request.enterprise_recovery_decision_id.clone(),
        enterprise_recovery_status: enterprise_request
            .as_ref()
            .map(|(_, decision)| decision.status),
        enterprise_recovery_enforcement_status: enterprise_request
            .as_ref()
            .map(|_| EnterpriseRecoveryEnforcementDecision::Allowed),
        enterprise_recovery_rejection_reason: None,
        approval_status: if enf_result.decision == ApprovalEnforcementDecision::Allowed {
            Some("Approved".to_string())
        } else {
            None
        },
        recovery_reason: Some(reason_code.clone()),
        reason: "Generating recovery plan".to_string(),
        timestamp: request.timestamp,
        record_hash: None,
        previous_record_hash: None,
        chain_hash: None,
        signing_key_id: None,
        signature_algorithm: None,
        signature: None,
        signed_at: None,
    };

    let _ = crate::operation_journal::append_begin_record(
        store.root_path(),
        &dummy_hash,
        record_template.clone(),
    );

    let descriptor = recovery_key::build_recovery_descriptor(
        store,
        &request.volume,
        recovery_policy,
        recovery_key_fingerprint,
    )?;
    let plan =
        recovery_key::build_recovery_plan(&descriptor, reason_code, request.operation_id.clone());

    store.save_recovery_descriptor(&descriptor)?;
    store.save_recovery_plan(&plan)?;

    if let Some(aid) = enf_result.approval_id {
        enforcer.consume_approval_if_required(local_policy, &aid)?;
    }

    if let Some((_, decision)) = enterprise_request {
        EnterpriseRecoveryEnforcer::new(store)
            .consume_enterprise_recovery_decision_if_required(&decision.decision_id.0)?;
    }

    let _ = crate::operation_journal::append_commit_record(
        store.root_path(),
        &dummy_hash,
        record_template,
    );

    let mut final_res = build_result(
        &request,
        OperationStatus::Accepted,
        state.current,
        state.current,
        format!("Recovery plan generated: {}", plan.recovery_plan_id),
    );
    final_res.approval_enforcement_decision = Some(enf_result.decision);
    Ok(final_res)
}

pub fn execute_rebind_operation(
    request: OperationRequest,
    _policy: &ManagedPolicy,
    rebind_policy: &RebindPolicy,
    store: &BindingStore,
    new_host_fingerprint: String,
    new_host_label: Option<String>,
    reason_code: String,
    local_policy: &LocalPolicy,
) -> Result<OperationResult> {
    let state = store.load_volume_state(&request.volume)?;
    let dummy_hash = BindingStore::volume_hash(&request.volume);

    // Enforcement Check
    let enforcer = ApprovalEnforcer::new(store);
    let enf_result = enforcer.check_required_approval(
        local_policy,
        LocalOperationClass::Rebind,
        &dummy_hash,
        request.approval_id.clone(),
    )?;

    if enf_result.decision == ApprovalEnforcementDecision::Rejected {
        let mut res = build_result(
            &request,
            OperationStatus::Rejected,
            state.current,
            state.current,
            format!("CSE-APPROVAL-REJECTION: {:?}", enf_result.reason.unwrap()),
        );
        res.approval_enforcement_decision = Some(enf_result.decision);
        res.approval_rejection_reason = enf_result.reason;
        return Ok(res);
    }

    if state.current == VolumeBindingState::Unregistered
        || state.current == VolumeBindingState::RecoveryRequired
    {
        return Ok(build_result(
            &request,
            OperationStatus::Rejected,
            state.current,
            state.current,
            "Invalid source state for rebind".to_string(),
        ));
    }

    // Prepare journal record
    let record_template = crate::operation_journal::OperationJournalRecord {
        seq: 0,
        phase: crate::operation_journal::OperationJournalPhase::Begin,
        operation_id: request.operation_id.clone(),
        kind: OperationKind::Rebind,
        volume: request.volume.clone(),
        requested_by: request.requested_by.clone(),
        result_status: OperationStatus::Accepted,
        previous_state: state.current,
        next_state: state.current,
        descriptor_id: None,
        plan_id: None,
        session_id: None,
        manual_flow_id: None,
        approval_id: enf_result.approval_id.clone(),
        decision_id: None,
        enterprise_authority_policy_id: None,
        enterprise_quorum_policy_id: None,
        enterprise_recovery_request_id: None,
        enterprise_recovery_decision_id: None,
        enterprise_recovery_status: None,
        enterprise_recovery_enforcement_status: None,
        enterprise_recovery_rejection_reason: None,
        approval_status: if enf_result.decision == ApprovalEnforcementDecision::Allowed {
            Some("Approved".to_string())
        } else {
            None
        },
        recovery_reason: Some(reason_code.clone()),
        reason: "Generating rebind plan".to_string(),
        timestamp: request.timestamp,
        record_hash: None,
        previous_record_hash: None,
        chain_hash: None,
        signing_key_id: None,
        signature_algorithm: None,
        signature: None,
        signed_at: None,
    };

    let _ = crate::operation_journal::append_begin_record(
        store.root_path(),
        &dummy_hash,
        record_template.clone(),
    );

    let plan = rebind_model::build_rebind_plan(
        store,
        &request.volume,
        rebind_policy,
        new_host_fingerprint,
        new_host_label,
        reason_code,
        request.operation_id.clone(),
    )?;
    let manifest = rebind_model::build_rebind_manifest(&plan);

    store.save_rebind_plan(&plan)?;
    store.save_rebind_manifest(&manifest)?;

    if let Some(aid) = enf_result.approval_id {
        enforcer.consume_approval_if_required(local_policy, &aid)?;
    }

    let _ = crate::operation_journal::append_commit_record(
        store.root_path(),
        &dummy_hash,
        record_template,
    );

    let mut final_res = build_result(
        &request,
        OperationStatus::Accepted,
        state.current,
        state.current,
        format!("Rebind manifest generated: {}", manifest.rebind_id),
    );
    final_res.approval_enforcement_decision = Some(enf_result.decision);
    Ok(final_res)
}

pub fn execute_manual_flow_operation(
    request: OperationRequest,
    store: &BindingStore,
    kind: ManualFlowKind,
    target_plan_id: String,
    confirmation_token: String,
    reason_code: String,
    local_policy: &LocalPolicy,
) -> Result<OperationResult> {
    let state = store.load_volume_state(&request.volume)?;
    let dummy_hash = BindingStore::volume_hash(&request.volume);

    let op_class = match kind {
        ManualFlowKind::ExportComplete
        | ManualFlowKind::RecoverComplete
        | ManualFlowKind::RebindComplete => LocalOperationClass::ManualComplete,
        ManualFlowKind::ExportCancel
        | ManualFlowKind::RecoverCancel
        | ManualFlowKind::RebindCancel => LocalOperationClass::ManualCancel,
    };

    // Enforcement Check
    let enforcer = ApprovalEnforcer::new(store);
    let enf_result = enforcer.check_required_approval(
        local_policy,
        op_class,
        &dummy_hash,
        request.approval_id.clone(),
    )?;

    if enf_result.decision == ApprovalEnforcementDecision::Rejected {
        let mut res = build_result(
            &request,
            OperationStatus::Rejected,
            state.current,
            state.current,
            format!("CSE-APPROVAL-REJECTION: {:?}", enf_result.reason.unwrap()),
        );
        res.approval_enforcement_decision = Some(enf_result.decision);
        res.approval_rejection_reason = enf_result.reason;
        return Ok(res);
    }

    // Prepare journal record
    let record_template = crate::operation_journal::OperationJournalRecord {
        seq: 0,
        phase: crate::operation_journal::OperationJournalPhase::Begin,
        operation_id: request.operation_id.clone(),
        kind: request.kind,
        volume: request.volume.clone(),
        requested_by: request.requested_by.clone(),
        result_status: OperationStatus::Accepted,
        previous_state: state.current,
        next_state: state.current,
        descriptor_id: None,
        plan_id: Some(target_plan_id.clone()),
        session_id: None,
        manual_flow_id: None,
        approval_id: enf_result.approval_id.clone(),
        decision_id: None,
        enterprise_authority_policy_id: None,
        enterprise_quorum_policy_id: None,
        enterprise_recovery_request_id: None,
        enterprise_recovery_decision_id: None,
        enterprise_recovery_status: None,
        enterprise_recovery_enforcement_status: None,
        enterprise_recovery_rejection_reason: None,
        approval_status: if enf_result.decision == ApprovalEnforcementDecision::Allowed {
            Some("Approved".to_string())
        } else {
            None
        },
        recovery_reason: Some(reason_code.clone()),
        reason: format!("Manual flow: {:?}", kind),
        timestamp: request.timestamp,
        record_hash: None,
        previous_record_hash: None,
        chain_hash: None,
        signing_key_id: None,
        signature_algorithm: None,
        signature: None,
        signed_at: None,
    };

    let _ = crate::operation_journal::append_begin_record(
        store.root_path(),
        &dummy_hash,
        record_template.clone(),
    );

    let mflow = manual_flow::prepare_manual_flow(
        kind,
        target_plan_id.clone(),
        None,
        dummy_hash.clone(),
        reason_code.clone(),
        &confirmation_token,
        request.operation_id.clone(),
    );

    if !manual_flow::verify_confirmation_token(&mflow, &confirmation_token) {
        let _ = crate::operation_journal::append_abort_record(
            store.root_path(),
            &dummy_hash,
            record_template,
        );
        return Ok(build_result(
            &request,
            OperationStatus::Rejected,
            state.current,
            state.current,
            "Invalid confirmation token".to_string(),
        ));
    }

    // Handle plan status updates
    match kind {
        ManualFlowKind::ExportComplete => {
            if let Some(mut plan) =
                store.load_export_plan(&target_plan_id.trim_start_matches("PLAN-"))?
            {
                if plan.status == PlanLifecycleStatus::Completed
                    || plan.status == PlanLifecycleStatus::Cancelled
                {
                    return Ok(build_result(
                        &request,
                        OperationStatus::Rejected,
                        state.current,
                        state.current,
                        "Plan already finalized".to_string(),
                    ));
                }
                plan.status = PlanLifecycleStatus::Completed;
                store.save_export_plan(&plan)?;
                if let Some(mut manifest) = store.load_export_manifest(&plan.export_id)? {
                    manifest.status = PlanLifecycleStatus::Completed;
                    store.save_export_manifest(&manifest)?;
                }
            } else {
                return Ok(build_result(
                    &request,
                    OperationStatus::Rejected,
                    state.current,
                    state.current,
                    "Plan not found".to_string(),
                ));
            }
        }
        ManualFlowKind::ExportCancel => {
            if let Some(mut plan) =
                store.load_export_plan(&target_plan_id.trim_start_matches("PLAN-"))?
            {
                plan.status = PlanLifecycleStatus::Cancelled;
                store.save_export_plan(&plan)?;
            }
        }
        ManualFlowKind::RecoverComplete => {
            if let Some(mut plan) = store.load_recovery_plan(&target_plan_id)? {
                plan.status = PlanLifecycleStatus::Completed;
                store.save_recovery_plan(&plan)?;
            }
        }
        ManualFlowKind::RebindComplete => {
            if let Some(mut plan) = store.load_rebind_plan(&target_plan_id)? {
                plan.status = PlanLifecycleStatus::Completed;
                store.save_rebind_plan(&plan)?;
            }
        }
        _ => {}
    }

    store.save_manual_flow_record(&mflow)?;

    if let Some(aid) = enf_result.approval_id {
        enforcer.consume_approval_if_required(local_policy, &aid)?;
    }

    let _ = crate::operation_journal::append_commit_record(
        store.root_path(),
        &dummy_hash,
        record_template,
    );

    let mut final_res = build_result(
        &request,
        OperationStatus::Accepted,
        state.current,
        state.current,
        "Manual flow completed".to_string(),
    );
    final_res.approval_enforcement_decision = Some(enf_result.decision);
    Ok(final_res)
}
