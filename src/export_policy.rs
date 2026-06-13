use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportPolicy {
    pub policy_id: String,
    pub allow_manifest_only: bool,
    pub allow_managed_rewrap: bool,
    pub allow_offline_transfer: bool,
    pub require_recipient_id: bool,
    pub require_recipient_key_fingerprint: bool,
    pub allow_plaintext_export: bool,
    pub persist_raw_identifiers: bool,
    pub audit_export_operations: bool,
}

impl Default for ExportPolicy {
    fn default() -> Self {
        ExportPolicy {
            policy_id: "DEFAULT-EXPORT-POLICY".to_string(),
            allow_manifest_only: true,
            allow_managed_rewrap: false,
            allow_offline_transfer: false,
            require_recipient_id: true,
            require_recipient_key_fingerprint: true,
            allow_plaintext_export: false,
            persist_raw_identifiers: false,
            audit_export_operations: true,
        }
    }
}

pub fn load_export_policy<P: AsRef<Path>>(path: P) -> Result<ExportPolicy> {
    let content = fs::read_to_string(path)?;
    let policy: ExportPolicy = serde_json::from_str(&content)?;
    validate_export_policy(&policy)?;
    Ok(policy)
}

pub fn default_manifest_only_policy() -> ExportPolicy {
    ExportPolicy::default()
}

pub fn validate_export_policy(policy: &ExportPolicy) -> Result<()> {
    if policy.persist_raw_identifiers {
        return Err(anyhow!(
            "persist_raw_identifiers=true is rejected in P3A for security reasons"
        ));
    }

    if policy.allow_plaintext_export {
        return Err(anyhow!("allow_plaintext_export must always be false"));
    }

    if policy.allow_managed_rewrap || policy.allow_offline_transfer {
        return Err(anyhow!(
            "managed rewrap and offline transfer are reserved for future phases"
        ));
    }

    Ok(())
}
