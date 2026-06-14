use crate::operations::{OperationKind, OperationStatus};
use crate::volume_state::VolumeBindingState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

pub fn append_record(
    root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
) -> Result<()> {
    let mut jrn_dir = root.to_path_buf();
    jrn_dir.push("JRN");

    if !jrn_dir.exists() {
        fs::create_dir_all(&jrn_dir)?;
    }

    let file_path = jrn_dir.join(format!("operations-{}.jsonl", volume_hash));

    let mut current_seq = 0;
    if file_path.exists() {
        let file = fs::File::open(&file_path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                if let Ok(r) = serde_json::from_str::<OperationJournalRecord>(&l) {
                    current_seq = r.seq;
                }
            }
        }
    }

    record.seq = current_seq + 1;
    record.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file_path)?;

    let json_line = serde_json::to_string(&record)?;
    writeln!(file, "{}", json_line)?;

    Ok(())
}

pub fn append_begin_record(
    root: &Path,
    volume_hash: &str,
    record: OperationJournalRecord,
) -> Result<()> {
    let mut rec = record;
    rec.phase = OperationJournalPhase::Begin;
    append_record(root, volume_hash, rec)
}

pub fn append_commit_record(
    root: &Path,
    volume_hash: &str,
    record: OperationJournalRecord,
) -> Result<()> {
    let mut rec = record;
    rec.phase = OperationJournalPhase::Commit;
    append_record(root, volume_hash, rec)
}

pub fn append_abort_record(
    root: &Path,
    volume_hash: &str,
    record: OperationJournalRecord,
) -> Result<()> {
    let mut rec = record;
    rec.phase = OperationJournalPhase::Abort;
    append_record(root, volume_hash, rec)
}

pub fn append_recovery_record(
    root: &Path,
    volume_hash: &str,
    record: OperationJournalRecord,
) -> Result<()> {
    let mut rec = record;
    rec.phase = OperationJournalPhase::Recovery;
    append_record(root, volume_hash, rec)
}

pub fn read_journal_records(root: &Path, volume_hash: &str) -> Result<Vec<OperationJournalRecord>> {
    let mut jrn_dir = root.to_path_buf();
    jrn_dir.push("JRN");
    let file_path = jrn_dir.join(format!("operations-{}.jsonl", volume_hash));

    if !file_path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(&file_path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: OperationJournalRecord = serde_json::from_str(&line)?;
        records.push(record);
    }

    Ok(records)
}

pub fn detect_uncommitted_begin(
    records: &[OperationJournalRecord],
) -> Option<&OperationJournalRecord> {
    if let Some(last) = records.last() {
        if last.phase == OperationJournalPhase::Begin {
            return Some(last);
        }
    }
    None
}
