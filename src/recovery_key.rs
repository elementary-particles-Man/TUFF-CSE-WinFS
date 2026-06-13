use crate::binding_store::BindingStore;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryKeyStatus {
    DescriptorOnly,
    Planned,
    Reserved,
    Rejected,
}

use crate::plan_state::PlanLifecycleStatus;

pub type RecoveryPlanStatus = PlanLifecycleStatus;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RecoveryPolicy {
    pub policy_id: String,
    pub allow_recovery_descriptor: bool,
    pub allow_recovery_plan: bool,
    pub require_recovery_key_fingerprint: bool,
    pub require_reason_code: bool,
    pub allow_raw_recovery_key_persistence: bool,
    pub allow_plaintext_recovery: bool,
    pub persist_raw_identifiers: bool,
    pub audit_recovery_operations: bool,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        RecoveryPolicy {
            policy_id: "DEFAULT-RECOVERY-POLICY".to_string(),
            allow_recovery_descriptor: true,
            allow_recovery_plan: true,
            require_recovery_key_fingerprint: true,
            require_reason_code: true,
            allow_raw_recovery_key_persistence: false,
            allow_plaintext_recovery: false,
            persist_raw_identifiers: false,
            audit_recovery_operations: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKeyDescriptor {
    pub recovery_id: String,
    pub policy_id: String,
    pub source_volume_hash: String,
    pub source_binding_descriptor_id: String,
    pub source_key_derivation_plan_id: String,
    pub recovery_key_fingerprint: String,
    pub status: RecoveryKeyStatus,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPlan {
    pub recovery_plan_id: String,
    pub recovery_id: String,
    pub policy_id: String,
    pub source_volume_hash: String,
    pub source_binding_descriptor_id: String,
    pub source_key_derivation_plan_id: String,
    pub recovery_key_fingerprint: String,
    pub reason_code: String,
    pub status: RecoveryPlanStatus,
    pub created_at: u64,
    pub journal_operation_id: String,
}

pub fn default_recovery_policy() -> RecoveryPolicy {
    RecoveryPolicy::default()
}

pub fn load_recovery_policy<P: AsRef<Path>>(path: P) -> Result<RecoveryPolicy> {
    let content = fs::read_to_string(path)?;
    let policy: RecoveryPolicy = serde_json::from_str(&content)?;
    validate_recovery_policy(&policy)?;
    Ok(policy)
}

pub fn validate_recovery_policy(policy: &RecoveryPolicy) -> Result<()> {
    if policy.allow_raw_recovery_key_persistence {
        return Err(anyhow!(
            "allow_raw_recovery_key_persistence=true is rejected in P3B for security reasons"
        ));
    }
    if policy.allow_plaintext_recovery {
        return Err(anyhow!("allow_plaintext_recovery=true is rejected in P3B"));
    }
    if policy.persist_raw_identifiers {
        return Err(anyhow!("persist_raw_identifiers=true is rejected in P3B"));
    }
    Ok(())
}

pub fn build_recovery_descriptor(
    store: &BindingStore,
    volume: &str,
    policy: &RecoveryPolicy,
    recovery_key_fingerprint: String,
) -> Result<RecoveryKeyDescriptor> {
    let vol_hash = BindingStore::volume_hash(volume);
    let desc = store
        .load_binding_descriptor(volume)?
        .ok_or_else(|| anyhow!("Binding descriptor not found for volume"))?;
    let key_plan = store
        .load_key_derivation_plan(volume)?
        .ok_or_else(|| anyhow!("Key derivation plan not found for volume"))?;

    let recovery_id = format!("RECO-DESC-{}", &vol_hash[..8]);

    Ok(RecoveryKeyDescriptor {
        recovery_id,
        policy_id: policy.policy_id.clone(),
        source_volume_hash: vol_hash,
        source_binding_descriptor_id: desc.descriptor_id,
        source_key_derivation_plan_id: key_plan.plan_id,
        recovery_key_fingerprint,
        status: RecoveryKeyStatus::DescriptorOnly,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

pub fn build_recovery_plan(
    descriptor: &RecoveryKeyDescriptor,
    reason_code: String,
    journal_operation_id: String,
) -> RecoveryPlan {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    RecoveryPlan {
        recovery_plan_id: format!("RECO-PLAN-{}", descriptor.recovery_id),
        recovery_id: descriptor.recovery_id.clone(),
        policy_id: descriptor.policy_id.clone(),
        source_volume_hash: descriptor.source_volume_hash.clone(),
        source_binding_descriptor_id: descriptor.source_binding_descriptor_id.clone(),
        source_key_derivation_plan_id: descriptor.source_key_derivation_plan_id.clone(),
        recovery_key_fingerprint: descriptor.recovery_key_fingerprint.clone(),
        reason_code,
        status: RecoveryPlanStatus::Planned,
        created_at: now,
        journal_operation_id,
    }
}
