use crate::binding_store::BindingStore;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::plan_state::PlanLifecycleStatus;

pub type RebindPlanStatus = PlanLifecycleStatus;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RebindPolicy {
    pub policy_id: String,
    pub allow_rebind_plan: bool,
    pub require_new_host_fingerprint: bool,
    pub require_reason_code: bool,
    pub allow_same_host_rebind: bool,
    pub allow_binding_descriptor_replacement: bool,
    pub persist_raw_identifiers: bool,
    pub audit_rebind_operations: bool,
}

impl Default for RebindPolicy {
    fn default() -> Self {
        RebindPolicy {
            policy_id: "DEFAULT-REBIND-POLICY".to_string(),
            allow_rebind_plan: true,
            require_new_host_fingerprint: true,
            require_reason_code: true,
            allow_same_host_rebind: false,
            allow_binding_descriptor_replacement: false,
            persist_raw_identifiers: false,
            audit_rebind_operations: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebindPlan {
    pub rebind_plan_id: String,
    pub rebind_id: String,
    pub policy_id: String,
    pub source_volume_hash: String,
    pub source_binding_descriptor_id: String,
    pub source_key_derivation_plan_id: String,
    pub old_host_fingerprint: String,
    pub new_host_fingerprint: String,
    pub new_host_label: Option<String>,
    pub reason_code: String,
    pub status: RebindPlanStatus,
    pub created_at: u64,
    pub journal_operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebindManifest {
    pub rebind_id: String,
    pub rebind_plan_id: String,
    pub policy_id: String,
    pub source_volume_hash: String,
    pub source_binding_descriptor_id: String,
    pub old_host_fingerprint: String,
    pub new_host_fingerprint: String,
    pub status: RebindPlanStatus,
    pub created_at: u64,
    pub journal_operation_id: String,
}

pub fn default_rebind_policy() -> RebindPolicy {
    RebindPolicy::default()
}

pub fn load_rebind_policy<P: AsRef<Path>>(path: P) -> Result<RebindPolicy> {
    let content = fs::read_to_string(path)?;
    let policy: RebindPolicy = serde_json::from_str(&content)?;
    validate_rebind_policy(&policy)?;
    Ok(policy)
}

pub fn validate_rebind_policy(policy: &RebindPolicy) -> Result<()> {
    if policy.allow_binding_descriptor_replacement {
        return Err(anyhow!(
            "allow_binding_descriptor_replacement=true is rejected in P3B"
        ));
    }
    if policy.persist_raw_identifiers {
        return Err(anyhow!("persist_raw_identifiers=true is rejected in P3B"));
    }
    Ok(())
}

pub fn build_rebind_plan(
    store: &BindingStore,
    volume: &str,
    policy: &RebindPolicy,
    new_host_fingerprint: String,
    new_host_label: Option<String>,
    reason_code: String,
    journal_operation_id: String,
) -> Result<RebindPlan> {
    let vol_hash = BindingStore::volume_hash(volume);
    let desc = store
        .load_binding_descriptor(volume)?
        .ok_or_else(|| anyhow!("Binding descriptor not found for volume"))?;
    let key_plan = store
        .load_key_derivation_plan(volume)?
        .ok_or_else(|| anyhow!("Key derivation plan not found for volume"))?;

    let rebind_id = format!("REBIND-{}", &vol_hash[..8]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Mock old host fingerprint for P3B boundary
    let old_host_fingerprint = "OLD-HOST-FP-STUB".to_string();

    Ok(RebindPlan {
        rebind_plan_id: format!("REBIND-PLAN-{}", rebind_id),
        rebind_id,
        policy_id: policy.policy_id.clone(),
        source_volume_hash: vol_hash,
        source_binding_descriptor_id: desc.descriptor_id,
        source_key_derivation_plan_id: key_plan.plan_id,
        old_host_fingerprint,
        new_host_fingerprint,
        new_host_label,
        reason_code,
        status: RebindPlanStatus::Planned,
        created_at: now,
        journal_operation_id,
    })
}

pub fn build_rebind_manifest(plan: &RebindPlan) -> RebindManifest {
    RebindManifest {
        rebind_id: plan.rebind_id.clone(),
        rebind_plan_id: plan.rebind_plan_id.clone(),
        policy_id: plan.policy_id.clone(),
        source_volume_hash: plan.source_volume_hash.clone(),
        source_binding_descriptor_id: plan.source_binding_descriptor_id.clone(),
        old_host_fingerprint: plan.old_host_fingerprint.clone(),
        new_host_fingerprint: plan.new_host_fingerprint.clone(),
        status: plan.status.clone(),
        created_at: plan.created_at,
        journal_operation_id: plan.journal_operation_id.clone(),
    }
}
