use crate::binding_store::BindingStore;
use crate::operation_journal::{self};
use crate::runtime_session::RuntimeSessionStatus;
use crate::volume_state::VolumeBindingState;
use anyhow::Result;

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryDecision {
    NoAction,
    MarkLocked,
    MarkRecoveryRequired,
    ClearStaleRuntimeSession,
    RejectUnsafeTransition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryReason {
    StaleRuntimeSession,
    BeginWithoutCommit,
    StateJournalMismatch,
    RuntimeSessionWithoutUnlockedState,
    CleanRemovalConfirmed,
}

pub fn recover_store(store: &BindingStore, volume: &str) -> Result<RecoveryDecision> {
    let state = store.load_volume_state(volume)?;
    let vol_hash = BindingStore::volume_hash(volume);
    let session = store.load_runtime_session(&vol_hash)?;
    let records = operation_journal::read_journal_records(store.root_path(), &vol_hash)?;

    // 1. Detect uncommitted Begin
    if let Some(last_begin) = operation_journal::detect_uncommitted_begin(&records) {
        // If we have a Begin without Commit/Abort, it's an interrupted operation.
        // Safety: mark as RecoveryRequired.
        let mut new_state = state.clone();
        new_state.current = VolumeBindingState::RecoveryRequired;
        store.save_volume_state(volume, &new_state)?;

        let rec = crate::operation_journal::OperationJournalRecord {
            seq: 0,
            phase: crate::operation_journal::OperationJournalPhase::Recovery,
            operation_id: format!("RECO-{}", last_begin.operation_id),
            kind: last_begin.kind,
            volume: volume.to_string(),
            requested_by: "System:Recovery".to_string(),
            result_status: crate::operations::OperationStatus::Failed,
            previous_state: state.current,
            next_state: VolumeBindingState::RecoveryRequired,
            descriptor_id: None,
            plan_id: None,
            session_id: None,
            manual_flow_id: None,
            recovery_reason: Some(format!("{:?}", RecoveryReason::BeginWithoutCommit)),
            reason: "Interrupted operation detected".to_string(),
            timestamp: 0,
        };
        operation_journal::append_recovery_record(store.root_path(), &vol_hash, rec)?;
        return Ok(RecoveryDecision::MarkRecoveryRequired);
    }

    // 2. Detect stale session or session/state mismatch
    if let Some(sess) = session {
        if state.current != VolumeBindingState::Unlocked
            && sess.status == RuntimeSessionStatus::UnlockedPlaceholder
        {
            // Session exists but state is not Unlocked.
            store.clear_runtime_session(&vol_hash)?;
            return Ok(RecoveryDecision::ClearStaleRuntimeSession);
        }

        // Check for TTL stale (placeholder TTL: 3600 seconds)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if sess.is_stale(now, 3600) {
            let mut new_state = state.clone();
            new_state.current = VolumeBindingState::RecoveryRequired;
            store.save_volume_state(volume, &new_state)?;
            store.clear_runtime_session(&vol_hash)?;

            let rec = crate::operation_journal::OperationJournalRecord {
                seq: 0,
                phase: crate::operation_journal::OperationJournalPhase::Recovery,
                operation_id: format!("RECO-STALE-{}", sess.session_id),
                kind: crate::operations::OperationKind::Status,
                volume: volume.to_string(),
                requested_by: "System:Recovery".to_string(),
                result_status: crate::operations::OperationStatus::Failed,
                previous_state: state.current,
                next_state: VolumeBindingState::RecoveryRequired,
                descriptor_id: None,
                plan_id: None,
                session_id: Some(sess.session_id),
                manual_flow_id: None,
                recovery_reason: Some(format!("{:?}", RecoveryReason::StaleRuntimeSession)),
                reason: "Stale session detected".to_string(),
                timestamp: 0,
            };
            operation_journal::append_recovery_record(store.root_path(), &vol_hash, rec)?;

            return Ok(RecoveryDecision::MarkRecoveryRequired);
        }
    }

    Ok(RecoveryDecision::NoAction)
}
