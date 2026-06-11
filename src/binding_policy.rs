use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingProfile {
    SingleHostLocalV1,
    ManagedExportReservedV1,
    EmergencyRecoveryReservedV1,
}

impl Default for BindingProfile {
    fn default() -> Self {
        BindingProfile::SingleHostLocalV1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingPolicy {
    pub policy_id: String,
    pub profile: BindingProfile,
    pub require_tpm: bool,
    pub require_host_identity: bool,
    pub require_device_identity: bool,
    pub require_volume_identity: bool,
    pub require_policy_material: bool,
    pub allow_installer_entropy: bool,
    pub allow_dev_without_tpm: bool,
    pub persist_raw_identifiers: bool,
    pub allow_export: bool,
    pub allow_rebind: bool,
    pub allow_recover: bool,
}

impl Default for BindingPolicy {
    fn default() -> Self {
        BindingPolicy {
            policy_id: "DEFAULT-BINDING-POLICY".to_string(),
            profile: BindingProfile::default(),
            require_tpm: true,
            require_host_identity: true,
            require_device_identity: true,
            require_volume_identity: true,
            require_policy_material: true,
            allow_installer_entropy: true,
            allow_dev_without_tpm: true,
            persist_raw_identifiers: false,
            allow_export: false,
            allow_rebind: false,
            allow_recover: false,
        }
    }
}

pub fn load_binding_policy<P: AsRef<Path>>(path: P) -> Result<BindingPolicy> {
    let content = fs::read_to_string(path)?;
    let policy: BindingPolicy = serde_json::from_str(&content)?;
    validate_binding_policy(&policy)?;
    Ok(policy)
}

pub fn default_single_host_local_policy() -> BindingPolicy {
    let mut policy = BindingPolicy::default();
    policy.profile = BindingProfile::SingleHostLocalV1;
    policy
}

pub fn validate_binding_policy(policy: &BindingPolicy) -> Result<()> {
    if policy.persist_raw_identifiers {
        return Err(anyhow!(
            "persist_raw_identifiers=true is rejected in P2A for security reasons"
        ));
    }

    if policy.allow_export || policy.allow_rebind || policy.allow_recover {
        return Err(anyhow!(
            "export/rebind/recover operations must remain disabled in P2A"
        ));
    }

    Ok(())
}
