use crate::binding::{self, BindingInputSnapshot};
use crate::binding_policy;
use crate::binding_store::BindingStore;
use crate::export_manifest::{self, ExportRecipient};
use crate::export_policy;
use crate::key_material;
use crate::managed_policy::ManagedPolicy;
use crate::runtime_session::{RuntimeSession, RuntimeSessionStatus};
use crate::volume_state::{VolumeBindingState, VolumeRuntimeState};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        OperationKind::Status | OperationKind::Audit | OperationKind::Export => {
            status = OperationStatus::Accepted;
            reason = "Success".to_string();
        }
        OperationKind::Rebind | OperationKind::Recover => {
            status = OperationStatus::Reserved;
            reason = "RESERVED_NOT_IMPLEMENTED".to_string();
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
    }
}

pub fn execute_managed_operation(
    request: OperationRequest,
    policy: &ManagedPolicy,
    store: &BindingStore,
) -> Result<OperationResult> {
    let mut state = store.load_volume_state(&request.volume)?;

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

    let dummy_hash = BindingStore::volume_hash(&request.volume);

    // Prepare journal record
    let record_template = crate::operation_journal::OperationJournalRecord {
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
        recovery_reason: None,
        reason: result.reason.clone(),
        timestamp: result.timestamp,
    };

    // Append Begin
    if request.kind != OperationKind::Status && request.kind != OperationKind::Audit {
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

    // Append Commit
    if request.kind != OperationKind::Status && request.kind != OperationKind::Audit {
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
) -> Result<OperationResult> {
    let state = store.load_volume_state(&request.volume)?;
    let dummy_hash = BindingStore::volume_hash(&request.volume);

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
    let record_template = crate::operation_journal::OperationJournalRecord {
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
        recovery_reason: None,
        reason: "Exporting manifest".to_string(),
        timestamp: request.timestamp,
    };

    let _ = crate::operation_journal::append_begin_record(
        store.root_path(),
        &dummy_hash,
        record_template.clone(),
    );

    let plan =
        export_manifest::build_export_plan(store, &request.volume, export_policy, recipient)?;
    let manifest =
        export_manifest::build_export_manifest(&plan, export_policy, request.operation_id.clone());

    store.save_export_plan(&plan)?;
    store.save_export_manifest(&manifest)?;

    let _ = crate::operation_journal::append_commit_record(
        store.root_path(),
        &dummy_hash,
        record_template,
    );

    Ok(build_result(
        &request,
        OperationStatus::Accepted,
        state.current,
        state.current,
        format!("Export manifest generated: {}", manifest.manifest_id),
    ))
}
