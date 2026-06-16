use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalOperationClass {
    Bind,
    Unlock,
    Lock,
    Eject,
    Export,
    Recover,
    Rebind,
    ManualComplete,
    ManualCancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalApprovalRequirement {
    NotRequired,
    Required,
    RequiredForRiskyOperation,
    ReservedFuture,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LocalPolicy {
    pub policy_id: String,
    pub require_local_admin_for_export: bool,
    pub require_local_admin_for_rebind: bool,
    pub require_local_admin_for_recover: bool,
    pub require_local_admin_for_manual_complete: bool,
    pub require_local_admin_for_manual_cancel: bool,
    pub require_local_admin_for_unlock: bool,
    pub require_local_admin_for_eject: bool,
    pub one_time_approval: bool,
    pub approval_ttl_seconds: u64,
    pub allow_self_approval: bool,
    pub persist_raw_admin_identity: bool,
    pub audit_local_approval: bool,
}

impl Default for LocalPolicy {
    fn default() -> Self {
        LocalPolicy {
            policy_id: "DEFAULT-LOCAL-POLICY".to_string(),
            require_local_admin_for_export: true,
            require_local_admin_for_rebind: true,
            require_local_admin_for_recover: true,
            require_local_admin_for_manual_complete: true,
            require_local_admin_for_manual_cancel: true,
            require_local_admin_for_unlock: false,
            require_local_admin_for_eject: false,
            one_time_approval: true,
            approval_ttl_seconds: 900,
            allow_self_approval: false,
            persist_raw_admin_identity: false,
            audit_local_approval: true,
        }
    }
}

pub fn default_local_policy() -> LocalPolicy {
    LocalPolicy::default()
}

pub fn load_local_policy<P: AsRef<Path>>(path: P) -> Result<LocalPolicy> {
    let content = fs::read_to_string(path)?;
    let policy: LocalPolicy = serde_json::from_str(&content)?;
    validate_local_policy(&policy)?;
    Ok(policy)
}

pub fn validate_local_policy(policy: &LocalPolicy) -> Result<()> {
    if policy.persist_raw_admin_identity {
        return Err(anyhow!(
            "persist_raw_admin_identity=true is rejected for security reasons"
        ));
    }
    if policy.approval_ttl_seconds == 0 {
        return Err(anyhow!("approval_ttl_seconds must be greater than 0"));
    }
    Ok(())
}

pub fn operation_requires_approval(policy: &LocalPolicy, op_class: LocalOperationClass) -> bool {
    match op_class {
        LocalOperationClass::Export => policy.require_local_admin_for_export,
        LocalOperationClass::Rebind => policy.require_local_admin_for_rebind,
        LocalOperationClass::Recover => policy.require_local_admin_for_recover,
        LocalOperationClass::ManualComplete => policy.require_local_admin_for_manual_complete,
        LocalOperationClass::ManualCancel => policy.require_local_admin_for_manual_cancel,
        LocalOperationClass::Unlock => policy.require_local_admin_for_unlock,
        LocalOperationClass::Eject => policy.require_local_admin_for_eject,
        _ => false,
    }
}
