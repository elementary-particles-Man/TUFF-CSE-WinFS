use crate::audit_chain::{canonicalize_journal_payload, compute_chain_hash, compute_record_hash};
use crate::audit_signing::AuditSigner;
use crate::enterprise_recovery::EnterpriseRecoveryStatus;
use crate::enterprise_recovery_enforcement::{
    EnterpriseRecoveryEnforcementDecision, EnterpriseRecoveryRejectionReason,
};
use crate::operations::{OperationKind, OperationStatus};
use crate::volume_state::VolumeBindingState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub enterprise_authority_policy_id: Option<String>,
    pub enterprise_quorum_policy_id: Option<String>,
    pub enterprise_recovery_request_id: Option<String>,
    pub enterprise_recovery_decision_id: Option<String>,
    pub enterprise_recovery_status: Option<EnterpriseRecoveryStatus>,
    pub enterprise_recovery_enforcement_status: Option<EnterpriseRecoveryEnforcementDecision>,
    pub enterprise_recovery_rejection_reason: Option<EnterpriseRecoveryRejectionReason>,
    pub approval_status: Option<String>,
    pub recovery_reason: Option<String>,
    pub reason: String,
    pub timestamp: u64,
    pub record_hash: Option<Vec<u8>>,
    pub previous_record_hash: Option<Vec<u8>>,
    pub chain_hash: Option<Vec<u8>>,
    pub signing_key_id: Option<String>,
    pub signature_algorithm: Option<crate::audit_signing::AuditSignatureAlgorithm>,
    pub signature: Option<Vec<u8>>,
    pub signed_at: Option<u64>,
}

pub fn append_signed_record(
    store_root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
    prev_hash: &[u8],
    signer: &dyn AuditSigner,
) -> Result<()> {
    let payload = canonicalize_journal_payload(&record);
    let record_hash = compute_record_hash(&payload);
    let chain_hash = compute_chain_hash(prev_hash, &record_hash);

    record.record_hash = Some(record_hash);
    record.previous_record_hash = Some(prev_hash.to_vec());
    record.chain_hash = Some(chain_hash);

    let sig_record = signer.sign(&canonicalize_journal_payload(&record))?;
    record.signing_key_id = Some(sig_record.key_id.0);
    record.signature_algorithm = Some(sig_record.algorithm);
    record.signature = Some(sig_record.signature);
    record.signed_at = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );

    let path = store_root.join(format!("JRN/operations-{}.jsonl", volume_hash));
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    let json = serde_json::to_string(&record)?;
    writeln!(file, "{}", json)?;
    Ok(())
}

pub fn append_begin_record(
    store_root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
) -> Result<()> {
    record.phase = OperationJournalPhase::Begin;
    // P4C: Sign Begin (Stub)
    // append_signed_record(store_root, volume_hash, record, prev_hash, signer)
    append_record_unsigned(store_root, volume_hash, record)
}

pub fn append_commit_record(
    store_root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
) -> Result<()> {
    record.phase = OperationJournalPhase::Commit;
    append_record_unsigned(store_root, volume_hash, record)
}

pub fn append_abort_record(
    store_root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
) -> Result<()> {
    record.phase = OperationJournalPhase::Abort;
    append_record_unsigned(store_root, volume_hash, record)
}

pub fn append_recovery_record(
    store_root: &Path,
    volume_hash: &str,
    mut record: OperationJournalRecord,
) -> Result<()> {
    record.phase = OperationJournalPhase::Recovery;
    append_record_unsigned(store_root, volume_hash, record)
}

fn append_record_unsigned(
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
    let file = File::open(path)?;
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
