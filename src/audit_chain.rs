use crate::audit_signing::AuditPublicKeyRecord;
use crate::operation_journal::OperationJournalRecord;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainState {
    pub volume_hash: String,
    pub chain_id: String,
    pub head_hash: Vec<u8>,
    pub last_seq: u64,
    pub last_record_id: String,
    pub last_key_id: String,
    pub created_at: u64,
    pub updated_at: u64,
}

pub fn compute_record_hash(payload: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().to_vec()
}

pub fn compute_chain_hash(prev_hash: &[u8], record_hash: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(record_hash);
    hasher.finalize().to_vec()
}

pub fn canonicalize_journal_payload(record: &OperationJournalRecord) -> Vec<u8> {
    // Exclude signature fields
    let mut rec = record.clone();
    rec.record_hash = None;
    rec.previous_record_hash = None;
    rec.chain_hash = None;
    rec.signing_key_id = None;
    rec.signature_algorithm = None;
    rec.signature = None;
    rec.signed_at = None;
    serde_json::to_vec(&rec).unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditChainViolation {
    MissingSignature,
    InvalidSignature,
    SeqGap,
    PrevHashMismatch,
    RecordHashMismatch,
    UnknownKeyId,
    ChainHeadMismatch,
    MalformedCanonicalPayload,
}

pub type AuditChainVerificationResult = Result<(), AuditChainViolation>;

pub fn verify_journal_chain(
    records: &[OperationJournalRecord],
    public_keys: &std::collections::HashMap<String, AuditPublicKeyRecord>,
) -> AuditChainVerificationResult {
    let mut prev_hash = vec![0u8; 32];
    let mut last_seq = 0;

    for rec in records {
        if rec.seq != last_seq + 1 {
            return Err(AuditChainViolation::SeqGap);
        }

        // Canonical check
        let payload = canonicalize_journal_payload(rec);
        let record_hash = compute_record_hash(&payload);
        if Some(&record_hash) != rec.record_hash.as_ref() {
            return Err(AuditChainViolation::RecordHashMismatch);
        }

        if Some(&prev_hash) != rec.previous_record_hash.as_ref() {
            return Err(AuditChainViolation::PrevHashMismatch);
        }

        // Signature check
        let key_id = rec
            .signing_key_id
            .as_ref()
            .ok_or(AuditChainViolation::MissingSignature)?;
        let pub_key = public_keys
            .get(key_id)
            .ok_or(AuditChainViolation::UnknownKeyId)?;

        if !crate::audit_signing::verify_signature(
            &crate::audit_signing::AuditSignatureRecord {
                key_id: crate::audit_signing::AuditSigningKeyId(key_id.clone()),
                algorithm: rec
                    .signature_algorithm
                    .ok_or(AuditChainViolation::MissingSignature)?,
                signature: rec
                    .signature
                    .clone()
                    .ok_or(AuditChainViolation::MissingSignature)?,
            },
            &pub_key.public_key,
            &payload,
        )
        .map_err(|_| AuditChainViolation::InvalidSignature)?
        {
            return Err(AuditChainViolation::InvalidSignature);
        }

        prev_hash = rec
            .chain_hash
            .clone()
            .ok_or(AuditChainViolation::MissingSignature)?;
        last_seq = rec.seq;
    }

    Ok(())
}
