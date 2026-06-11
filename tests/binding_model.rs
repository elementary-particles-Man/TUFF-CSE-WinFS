#[cfg(test)]
mod tests {
    use tuff_cse_winfs::binding::{
        build_binding_descriptor, BindingInputSnapshot, BindingMaterialKind,
    };
    use tuff_cse_winfs::binding_policy::{
        default_single_host_local_policy, validate_binding_policy, BindingPolicy, BindingProfile,
    };
    use tuff_cse_winfs::key_material::{build_key_derivation_plan, KeyMaterialClass};

    fn get_mock_input() -> BindingInputSnapshot {
        BindingInputSnapshot {
            raw_tpm_identity: Some("RAW_TPM_DATA".to_string()),
            raw_host_id: Some("RAW_HOST_UUID".to_string()),
            raw_device_uuid: Some("RAW_DEVICE_UUID".to_string()),
            raw_volume_serial: Some("RAW_VOL_SERIAL".to_string()),
            raw_policy_material: Some("RAW_POLICY_DATA".to_string()),
            installer_entropy_bytes: Some(vec![0xAA, 0xBB]),
        }
    }

    #[test]
    fn test_default_binding_policy_validates() {
        let policy = default_single_host_local_policy();
        assert!(validate_binding_policy(&policy).is_ok());
    }

    #[test]
    fn test_binding_policy_persist_raw_rejected() {
        let mut policy = default_single_host_local_policy();
        policy.persist_raw_identifiers = true;
        assert!(validate_binding_policy(&policy).is_err());
    }

    #[test]
    fn test_binding_policy_export_rebind_disabled() {
        let mut policy = default_single_host_local_policy();
        policy.allow_export = true;
        assert!(validate_binding_policy(&policy).is_err());

        let mut policy2 = default_single_host_local_policy();
        policy2.allow_rebind = true;
        assert!(validate_binding_policy(&policy2).is_err());
    }

    #[test]
    fn test_descriptor_serializes_without_raw_values() {
        let policy = default_single_host_local_policy();
        let input = get_mock_input();
        let desc = build_binding_descriptor(&policy, &input, "D:", "SALT").unwrap();

        let json = serde_json::to_string(&desc).unwrap();
        assert!(!json.contains("RAW_TPM_DATA"));
        assert!(!json.contains("RAW_HOST_UUID"));
        assert!(!json.contains("RAW_DEVICE_UUID"));
        assert!(!json.contains("RAW_VOL_SERIAL"));
    }

    #[test]
    fn test_descriptor_contains_material_fingerprints() {
        let policy = default_single_host_local_policy();
        let input = get_mock_input();
        let desc = build_binding_descriptor(&policy, &input, "D:", "SALT").unwrap();

        assert_eq!(desc.material_fingerprints.len(), 5);
        let has_tpm = desc
            .material_fingerprints
            .iter()
            .any(|fp| fp.kind == BindingMaterialKind::TpmIdentity);
        assert!(has_tpm);
    }

    #[test]
    fn test_stable_descriptor_id() {
        let policy = default_single_host_local_policy();
        let input1 = get_mock_input();
        let input2 = get_mock_input();

        let desc1 = build_binding_descriptor(&policy, &input1, "D:", "SALT1").unwrap();
        let desc2 = build_binding_descriptor(&policy, &input2, "D:", "SALT1").unwrap();

        assert_eq!(desc1.descriptor_id, desc2.descriptor_id);
    }

    #[test]
    fn test_different_salt_produces_different_fingerprints() {
        let policy = default_single_host_local_policy();
        let input1 = get_mock_input();
        let input2 = get_mock_input();

        let desc1 = build_binding_descriptor(&policy, &input1, "D:", "SALT1").unwrap();
        let desc2 = build_binding_descriptor(&policy, &input2, "D:", "SALT2").unwrap();

        assert_ne!(desc1.descriptor_id, desc2.descriptor_id);
        assert_ne!(
            desc1.material_fingerprints[0].fingerprint,
            desc2.material_fingerprints[0].fingerprint
        );
    }

    #[test]
    fn test_key_derivation_plan_contains_no_key_bytes() {
        let policy = default_single_host_local_policy();
        let input = get_mock_input();
        let desc = build_binding_descriptor(&policy, &input, "D:", "SALT").unwrap();

        let plan = build_key_derivation_plan(&desc, &policy).unwrap();
        let json = serde_json::to_string(&plan).unwrap();

        // Assert absence of typical key material strings in the serialized plan
        assert!(!json.contains("key_bytes"));
        assert!(!json.contains("MK"));
        assert!(!json.contains("TK"));
        assert!(!json.contains("PK"));
        assert!(!json.contains("basekey"));
    }
}
