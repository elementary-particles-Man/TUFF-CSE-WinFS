use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ManagedPolicy {
    pub policy_id: String,
    pub allow_status: bool,
    pub allow_bind: bool,
    pub allow_unlock: bool,
    pub allow_lock: bool,
    pub allow_eject: bool,
    pub allow_audit: bool,
    pub allow_export: bool,
    pub allow_rebind: bool,
    pub allow_recover: bool,
    pub audit_status_operations: bool,
}

impl Default for ManagedPolicy {
    fn default() -> Self {
        ManagedPolicy {
            policy_id: "DEFAULT-LOCAL-POLICY".to_string(),
            allow_status: true,
            allow_bind: true,
            allow_unlock: true,
            allow_lock: true,
            allow_eject: true,
            allow_audit: true,
            allow_export: false,
            allow_rebind: false,
            allow_recover: false,
            audit_status_operations: true,
        }
    }
}

pub fn load_managed_policy<P: AsRef<Path>>(path: P) -> Result<ManagedPolicy> {
    let content = fs::read_to_string(path)?;
    let policy: ManagedPolicy = serde_json::from_str(&content)?;
    Ok(policy)
}

pub fn default_local_policy() -> ManagedPolicy {
    ManagedPolicy::default()
}
