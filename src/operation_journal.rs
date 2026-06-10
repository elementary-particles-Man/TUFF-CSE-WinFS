use crate::operations::{OperationKind, OperationStatus};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationJournalRecord {
    pub operation_id: String,
    pub kind: OperationKind,
    pub volume: String,
    pub requested_by: String,
    pub result_status: OperationStatus,
    pub reason: String,
    pub timestamp: u64,
}

pub fn append_journal_record(
    root: &Path,
    volume_hash: &str,
    record: &OperationJournalRecord,
) -> Result<()> {
    let mut jrn_dir = root.to_path_buf();
    jrn_dir.push("JRN");

    if !jrn_dir.exists() {
        fs::create_dir_all(&jrn_dir)?;
    }

    let file_path = jrn_dir.join(format!("operations-{}.jsonl", volume_hash));

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file_path)?;

    let json_line = serde_json::to_string(record)?;
    writeln!(file, "{}", json_line)?;

    Ok(())
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
