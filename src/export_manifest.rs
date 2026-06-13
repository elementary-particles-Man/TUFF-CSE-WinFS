use crate::binding_store::BindingStore;
use crate::export_policy::ExportPolicy;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportMode {
    ManifestOnly,
    ManagedRewrapReserved,
    OfflineTransferReserved,
}

use crate::plan_state::PlanLifecycleStatus;

pub type ExportStatus = PlanLifecycleStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecipient {
    pub recipient_id: String,
    pub recipient_key_fingerprint: String,
    pub recipient_org_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportPlan {
    pub plan_id: String,
    pub export_id: String,
    pub source_volume_hash: String,
    pub source_descriptor_id: String,
    pub source_key_plan_id: String,
    pub recipient: ExportRecipient,
    pub mode: ExportMode,
    pub status: ExportStatus,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportManifest {
    pub manifest_id: String,
    pub export_id: String,
    pub policy_id: String,
    pub source_volume_hash: String,
    pub source_binding_descriptor_id: String,
    pub source_key_derivation_plan_id: String,
    pub recipient_id: String,
    pub recipient_key_fingerprint: String,
    pub export_mode: ExportMode,
    pub status: ExportStatus,
    pub created_at: u64,
    pub journal_operation_id: String,
}

pub fn build_export_plan(
    store: &BindingStore,
    volume: &str,
    policy: &ExportPolicy,
    recipient: ExportRecipient,
) -> Result<ExportPlan> {
    let vol_hash = BindingStore::volume_hash(volume);
    let desc = store
        .load_binding_descriptor(volume)?
        .ok_or_else(|| anyhow::anyhow!("Binding descriptor not found for volume"))?;
    let key_plan = store
        .load_key_derivation_plan(volume)?
        .ok_or_else(|| anyhow::anyhow!("Key derivation plan not found for volume"))?;

    let export_id = format!(
        "EXP-{}-{}",
        &vol_hash[..8],
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    Ok(ExportPlan {
        plan_id: format!("PLAN-{}", export_id),
        export_id,
        source_volume_hash: vol_hash,
        source_descriptor_id: desc.descriptor_id,
        source_key_plan_id: key_plan.plan_id,
        recipient,
        mode: if policy.allow_manifest_only {
            ExportMode::ManifestOnly
        } else {
            ExportMode::ManagedRewrapReserved
        },
        status: ExportStatus::Planned,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

pub fn build_export_manifest(
    plan: &ExportPlan,
    policy: &ExportPolicy,
    journal_operation_id: String,
) -> ExportManifest {
    ExportManifest {
        manifest_id: format!("MANIFEST-{}", plan.export_id),
        export_id: plan.export_id.clone(),
        policy_id: policy.policy_id.clone(),
        source_volume_hash: plan.source_volume_hash.clone(),
        source_binding_descriptor_id: plan.source_descriptor_id.clone(),
        source_key_derivation_plan_id: plan.source_key_plan_id.clone(),
        recipient_id: plan.recipient.recipient_id.clone(),
        recipient_key_fingerprint: plan.recipient.recipient_key_fingerprint.clone(),
        export_mode: plan.mode.clone(),
        status: ExportStatus::Planned,
        created_at: plan.created_at,
        journal_operation_id,
    }
}
