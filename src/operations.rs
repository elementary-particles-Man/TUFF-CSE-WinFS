use crate::managed_policy::ManagedPolicy;
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
        OperationKind::Status | OperationKind::Audit => {
            status = OperationStatus::Accepted;
            reason = "Success".to_string();
        }
        OperationKind::Export | OperationKind::Rebind | OperationKind::Recover => {
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
