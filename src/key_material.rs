use crate::binding::{BindingDescriptor, BindingMaterialKind};
use crate::binding_policy::{BindingPolicy, BindingProfile};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyMaterialClass {
    MasterKeyMaterial,
    DeviceBindingKeyMaterial,
    TokenKeyMaterial,
    PairingKeyMaterial,
    RecoveryKeyMaterialReserved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMaterialRef {
    pub class: KeyMaterialClass,
    pub ref_id: String,
    pub binding_descriptor_id: String,
    pub wrapping_state: String,
    pub algorithm_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationPlan {
    pub plan_id: String,
    pub profile: BindingProfile,
    pub required_materials: Vec<BindingMaterialKind>,
    pub target_key_classes: Vec<KeyMaterialClass>,
    pub algorithm_suite: String,
    pub descriptor_id: String,
}

pub fn build_key_derivation_plan(
    descriptor: &BindingDescriptor,
    policy: &BindingPolicy,
) -> Result<KeyDerivationPlan> {
    let mut required = Vec::new();
    if policy.require_tpm {
        required.push(BindingMaterialKind::TpmIdentity);
    }
    if policy.require_host_identity {
        required.push(BindingMaterialKind::HostIdentity);
    }
    if policy.require_device_identity {
        required.push(BindingMaterialKind::DeviceIdentity);
    }
    if policy.require_volume_identity {
        required.push(BindingMaterialKind::VolumeIdentity);
    }
    if policy.require_policy_material {
        required.push(BindingMaterialKind::PolicyMaterial);
    }

    let targets = vec![
        KeyMaterialClass::MasterKeyMaterial,
        KeyMaterialClass::DeviceBindingKeyMaterial,
        KeyMaterialClass::TokenKeyMaterial,
        KeyMaterialClass::PairingKeyMaterial,
    ];

    Ok(KeyDerivationPlan {
        plan_id: format!("PLAN-{}", descriptor.descriptor_id),
        profile: policy.profile.clone(),
        required_materials: required,
        target_key_classes: targets,
        algorithm_suite: "SHA256-KDF".to_string(), // Conceptual
        descriptor_id: descriptor.descriptor_id.clone(),
    })
}
