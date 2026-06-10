use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundPriority {
    Lowest,
    Low,
    Normal,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TargetVolume {
    pub volume: String,
    pub role: String,
    pub cse: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InstallPolicy {
    pub policy_id: String,
    pub mode: String,
    pub targets: Vec<TargetVolume>,
    pub supported_filesystems: Vec<String>,
    pub exclude_system_volumes: bool,
    pub background_priority: BackgroundPriority,
    pub meta_flush_minutes: u32,
    pub meta_flush_jitter_minutes: u32,
    pub completion_code: bool,
}

pub fn load_policy<P: AsRef<Path>>(path: P) -> Result<InstallPolicy> {
    let content = fs::read_to_string(path)?;
    let policy: InstallPolicy = serde_json::from_str(&content)?;
    validate_policy(&policy)?;
    Ok(policy)
}

pub fn validate_policy(policy: &InstallPolicy) -> Result<()> {
    if policy.policy_id.is_empty() {
        return Err(anyhow!("policy_id cannot be empty"));
    }

    if policy.targets.is_empty() {
        return Err(anyhow!("targets cannot be empty"));
    }

    let allowed_fs = ["NTFS", "exFAT", "FAT32", "FAT"];
    for fs in &policy.supported_filesystems {
        if !allowed_fs.contains(&fs.as_str()) {
            return Err(anyhow!("Unsupported filesystem in policy: {}", fs));
        }
    }

    // Explicitly reject ReFS and RAW if they somehow sneak into supported_filesystems
    if policy
        .supported_filesystems
        .iter()
        .any(|fs| fs == "ReFS" || fs == "RAW")
    {
        return Err(anyhow!("ReFS and RAW are strictly out of scope"));
    }

    Ok(())
}
