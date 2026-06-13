use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManualFlowKind {
    ExportComplete,
    ExportCancel,
    RebindComplete,
    RebindCancel,
    RecoverComplete,
    RecoverCancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManualFlowStatus {
    Prepared,
    Confirmed,
    Committed,
    Cancelled,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualFlowRecord {
    pub manual_flow_id: String,
    pub kind: ManualFlowKind,
    pub status: ManualFlowStatus,
    pub target_plan_id: String,
    pub target_manifest_id: Option<String>,
    pub source_volume_hash: String,
    pub reason_code: String,
    pub confirmation_token_hash: String,
    pub created_at: u64,
    pub completed_at: Option<u64>,
    pub cancelled_at: Option<u64>,
    pub journal_operation_id: String,
}

pub fn compute_token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn prepare_manual_flow(
    kind: ManualFlowKind,
    target_plan_id: String,
    target_manifest_id: Option<String>,
    source_volume_hash: String,
    reason_code: String,
    confirmation_token: &str,
    journal_operation_id: String,
) -> ManualFlowRecord {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    ManualFlowRecord {
        manual_flow_id: format!("MFLOW-{}-{}", target_plan_id, now),
        kind,
        status: ManualFlowStatus::Prepared,
        target_plan_id,
        target_manifest_id,
        source_volume_hash,
        reason_code,
        confirmation_token_hash: compute_token_hash(confirmation_token),
        created_at: now,
        completed_at: None,
        cancelled_at: None,
        journal_operation_id,
    }
}

pub fn verify_confirmation_token(record: &ManualFlowRecord, provided_token: &str) -> bool {
    let provided_hash = compute_token_hash(provided_token);
    record.confirmation_token_hash == provided_hash
}
