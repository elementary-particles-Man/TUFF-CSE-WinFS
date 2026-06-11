use crate::binding_policy::{BindingPolicy, BindingProfile};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingMaterialKind {
    TpmIdentity,
    HostIdentity,
    DeviceIdentity,
    VolumeIdentity,
    PolicyMaterial,
    InstallerEntropy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingMaterialRequirement {
    Required,
    OptionalForDev,
    ReservedFuture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingMaterialFingerprint {
    pub kind: BindingMaterialKind,
    pub fingerprint: String,
    pub salt_id: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingDescriptor {
    pub descriptor_id: String,
    pub profile: BindingProfile,
    pub policy_id: String,
    pub volume: String,
    pub material_fingerprints: Vec<BindingMaterialFingerprint>,
    pub created_at: u64,
    pub state_hint: String,
}

// In P2A, we don't serialize the raw input. It only exists in memory during binding setup.
pub struct BindingInputSnapshot {
    pub raw_tpm_identity: Option<String>,
    pub raw_host_id: Option<String>,
    pub raw_device_uuid: Option<String>,
    pub raw_volume_serial: Option<String>,
    pub raw_policy_material: Option<String>,
    pub installer_entropy_bytes: Option<Vec<u8>>,
}

fn compute_salted_fingerprint(raw_value: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(raw_value.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn build_binding_descriptor(
    policy: &BindingPolicy,
    input: &BindingInputSnapshot,
    volume: &str,
    global_salt: &str,
) -> Result<BindingDescriptor> {
    let mut fingerprints = Vec::new();

    if policy.require_tpm {
        if let Some(tpm) = &input.raw_tpm_identity {
            fingerprints.push(BindingMaterialFingerprint {
                kind: BindingMaterialKind::TpmIdentity,
                fingerprint: compute_salted_fingerprint(tpm, global_salt),
                salt_id: compute_salted_fingerprint(global_salt, "tpm_salt_id"), // Obfuscate salt id
                algorithm: "SHA256".to_string(),
            });
        } else if !policy.allow_dev_without_tpm {
            return Err(anyhow::anyhow!("TPM identity required but not provided"));
        }
    }

    if policy.require_host_identity {
        if let Some(host) = &input.raw_host_id {
            fingerprints.push(BindingMaterialFingerprint {
                kind: BindingMaterialKind::HostIdentity,
                fingerprint: compute_salted_fingerprint(host, global_salt),
                salt_id: compute_salted_fingerprint(global_salt, "host_salt_id"),
                algorithm: "SHA256".to_string(),
            });
        }
    }

    if policy.require_device_identity {
        if let Some(device) = &input.raw_device_uuid {
            fingerprints.push(BindingMaterialFingerprint {
                kind: BindingMaterialKind::DeviceIdentity,
                fingerprint: compute_salted_fingerprint(device, global_salt),
                salt_id: compute_salted_fingerprint(global_salt, "dev_salt_id"),
                algorithm: "SHA256".to_string(),
            });
        }
    }

    if policy.require_volume_identity {
        if let Some(vol_serial) = &input.raw_volume_serial {
            fingerprints.push(BindingMaterialFingerprint {
                kind: BindingMaterialKind::VolumeIdentity,
                fingerprint: compute_salted_fingerprint(vol_serial, global_salt),
                salt_id: compute_salted_fingerprint(global_salt, "vol_salt_id"),
                algorithm: "SHA256".to_string(),
            });
        }
    }

    if policy.require_policy_material {
        if let Some(pol_mat) = &input.raw_policy_material {
            fingerprints.push(BindingMaterialFingerprint {
                kind: BindingMaterialKind::PolicyMaterial,
                fingerprint: compute_salted_fingerprint(pol_mat, global_salt),
                salt_id: compute_salted_fingerprint(global_salt, "pol_salt_id"),
                algorithm: "SHA256".to_string(),
            });
        }
    }

    // Compute an overall descriptor ID from the fingerprints to ensure stability for same inputs+salt
    let mut id_hasher = Sha256::new();
    for fp in &fingerprints {
        id_hasher.update(fp.fingerprint.as_bytes());
    }
    let descriptor_id = format!(
        "DESC-{}",
        hex::encode(id_hasher.finalize())[..16].to_uppercase()
    );

    Ok(BindingDescriptor {
        descriptor_id,
        profile: policy.profile.clone(),
        policy_id: policy.policy_id.clone(),
        volume: volume.to_string(),
        material_fingerprints: fingerprints,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        state_hint: "BoundLocked".to_string(), // Initial bind target
    })
}
