use crate::operations::{OperationKind, OperationStatus};
use crate::volume_state::VolumeBindingState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationJournalPhase {
    Begin,
    Commit,
    Abort,
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationJournalRecord {
    pub seq: u64,
    pub phase: OperationJournalPhase,
    pub operation_id: String,
    pub kind: OperationKind,
    pub volume: String,
    pub requested_by: String,
    pub result_status: OperationStatus,
    pub previous_state: VolumeBindingState,
    pub next_state: VolumeBindingState,
    pub descriptor_id: Option<String>,
    pub plan_id: Option<String>,
    pub session_id: Option<String>,
    pub manual_flow_id: Option<String>,
    pub approval_id: Option<String>,
    pub decision_id: Option<String>,
    pub approval_status: Option<String>,
    pub recovery_reason: Option<String>,
    pub reason: String,
    pub timestamp: u64,
}

pub fn append_begin_record(
    store_root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
) -> Result<()> {
    record.phase = OperationJournalPhase::Begin;
    append_record(store_root, volume_hash, record)
}

pub fn append_commit_record(
    store_root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
) -> Result<()> {
    record.phase = OperationJournalPhase::Commit;
    append_record(store_root, volume_hash, record)
}

pub fn append_abort_record(
    store_root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
) -> Result<()> {
    record.phase = OperationJournalPhase::Abort;
    append_record(store_root, volume_hash, record)
}

pub fn append_recovery_record(
    store_root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
) -> Result<()> {
    record.phase = OperationJournalPhase::Recovery;
    append_record(store_root, volume_hash, record)
}

fn append_record(
    store_root: &Path,
    volume_hash: &str,
    record: OperationJournalRecord,
) -> Result<()> {
    let path = store_root.join(format!("JRN/operations-{}.jsonl", volume_hash));
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    let json = serde_json::to_string(&record)?;
    writeln!(file, "{}", json)?;
    Ok(())
}

pub fn read_journal_records(
    store_root: &Path,
    volume_hash: &str,
) -> Result<Vec<OperationJournalRecord>> {
    let path = store_root.join(format!("JRN/operations-{}.jsonl", volume_hash));
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)?;
    let mut records = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let record: OperationJournalRecord = serde_json::from_str(line)?;
        records.push(record);
    }
    Ok(records)
}

pub fn detect_uncommitted_begin(
    records: &[OperationJournalRecord],
) -> Option<&OperationJournalRecord> {
    let mut last_begin = None;
    for rec in records {
        match rec.phase {
            OperationJournalPhase::Begin => last_begin = Some(rec),
            OperationJournalPhase::Commit | OperationJournalPhase::Abort => {
                if let Some(begin) = last_begin {
                    if begin.operation_id == rec.operation_id {
                        last_begin = None;
                    }
                }
            }
            _ => {}
        }
    }
    last_begin
}
